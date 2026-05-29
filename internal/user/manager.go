package user

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/logger"
)

var validUsername = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// validGroupName matches the POSIX-ish group name rules enforced by
// shadow-utils (same shape as validUsername). It deliberately excludes `,`
// because `usermod -aG` splits on commas inside a single -aG argument —
// a config entry like "sudo,root" would otherwise add the user to BOTH
// groups without any shell involvement.
var validGroupName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

var executor commandExecutor = systemCommandExecutor{}

type commandExecutor interface {
	Run(name string, args ...string) ([]byte, int, error)
	RunWithStdin(stdin string, name string, args ...string) ([]byte, int, error)
}

type systemCommandExecutor struct{}

func (systemCommandExecutor) Run(name string, args ...string) ([]byte, int, error) {
	cmd := exec.Command(findBin(name), args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return out, 0, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return out, exitErr.ExitCode(), err
	}
	return out, -1, err
}

func (systemCommandExecutor) RunWithStdin(stdin string, name string, args ...string) ([]byte, int, error) {
	cmd := exec.Command(findBin(name), args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return out, 0, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return out, exitErr.ExitCode(), err
	}
	return out, -1, err
}

func findBin(name string) string {
	for _, dir := range []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"} {
		path := dir + "/" + name
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return name
}

// Setup creates a Linux user with group memberships if they don't exist.
// If isAdmin is true, uses adminGroups; otherwise uses userGroups.
// When adminGroups is configured and user is NOT admin, actively removes from admin-only groups.
// Returns (created bool, tempPassword string, err error).
// tempPassword is non-empty only when a new user is created with forcePasswd=true.
func Setup(username string, userGroups, adminGroups []string, isAdmin bool, forcePasswd bool, log *logger.Logger) (bool, string, error) {
	if !validUsername.MatchString(username) {
		return false, "", fmt.Errorf("invalid username: %q", username)
	}

	// Validate group names BEFORE touching useradd/usermod. Config is trusted
	// in principle (root-owned /etc/pam-device-auth/config.json) but a typo
	// like "sudo,root" would otherwise elevate the user to root group.
	if err := validateGroups(userGroups); err != nil {
		return false, "", fmt.Errorf("invalid user_groups: %w", err)
	}
	if err := validateGroups(adminGroups); err != nil {
		return false, "", fmt.Errorf("invalid admin_groups: %w", err)
	}

	exists, err := userExists(username)
	if err != nil {
		return false, "", fmt.Errorf("check user exists: %w", err)
	}

	created := false
	if !exists {
		log.Info("Creating user: %s", username)
		if out, _, err := executor.Run("useradd", "-m", "-s", "/bin/bash", username); err != nil {
			return false, "", fmt.Errorf("useradd failed: %s: %w", string(out), err)
		}
		log.Info("User %s created", username)
		created = true
	}

	// Determine groups based on admin status
	if isAdmin && len(adminGroups) > 0 {
		for _, g := range adminGroups {
			if out, _, err := executor.Run("usermod", "-aG", g, username); err != nil {
				log.Warn("Failed to add %s to group %s: %s", username, g, string(out))
			}
		}
		log.Info("Admin groups applied for %s: %v", username, adminGroups)
	} else {
		for _, g := range userGroups {
			if out, _, err := executor.Run("usermod", "-aG", g, username); err != nil {
				log.Warn("Failed to add %s to group %s: %s", username, g, string(out))
			}
		}

		if len(adminGroups) > 0 {
			adminOnly := groupDiff(adminGroups, userGroups)
			for _, g := range adminOnly {
				executor.Run("gpasswd", "-d", username, g)
				log.Info("Removed %s from group %s (admin role revoked)", username, g)
			}
		}
	}

	if created && forcePasswd {
		tempPwd, err := generateTempPassword(12)
		if err != nil {
			return false, "", fmt.Errorf("generate temp password: %w", err)
		}

		// Set temp password via chpasswd (reads user:password from stdin)
		if out, _, err := executor.RunWithStdin(username+":"+tempPwd+"\n", "chpasswd"); err != nil {
			return false, "", fmt.Errorf("set temp password: %s: %w", string(out), err)
		}
		log.Info("Temp password set for %s", username)

		// Force password change on first shell login via .bash_profile
		if err := installPasswordPrompt(username, log); err != nil {
			log.Warn("Failed to install password prompt: %v", err)
		}

		return true, tempPwd, nil
	}

	return created, "", nil
}

// generateTempPassword creates a cryptographically random password.
// Uses an unambiguous charset (no 0/O, 1/l/I).
func generateTempPassword(length int) (string, error) {
	const charset = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	result := make([]byte, length)
	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[n.Int64()]
	}
	return string(result), nil
}

const passwordPromptScript = `# pam-device-auth: force local password setup on first login
if [ ! -f "$HOME/.password_set" ]; then
    echo ""
    echo "------------------------------------"
    echo "  Please set your local password."
    echo "------------------------------------"
    echo ""
    if passwd; then
        touch "$HOME/.password_set"
        echo ""
        echo "Password set successfully."
    else
        echo "Password not set. You will be asked again on next login."
        exit 1
    fi
fi
`

func installPasswordPrompt(username string, log *logger.Logger) error {
	homeDir := "/home/" + username
	profilePath := homeDir + "/.bash_profile"

	created, err := writeFileExcl(profilePath, []byte(passwordPromptScript), 0644)
	if err != nil {
		return fmt.Errorf("write .bash_profile: %w", err)
	}
	if !created {
		// A pre-existing .bash_profile (or a symlink planted by an attacker on
		// a shared-home NFS mount) MUST NOT be silently overwritten — O_EXCL
		// refused to follow it. Skip cleanly on re-runs / manually-provisioned
		// accounts; the user simply won't get the one-shot password prompt.
		log.Warn(".bash_profile already exists for %s, skipping password-prompt install", username)
		return nil
	}

	// Ensure owned by user
	if out, _, err := executor.Run("chown", username+":"+username, profilePath); err != nil {
		return fmt.Errorf("chown .bash_profile: %s: %w", string(out), err)
	}

	log.Info("Password prompt installed for %s", username)
	return nil
}

// writeFileExcl writes content to path atomically if and only if no file
// (including a symlink) already exists at that path. Returns created=false
// and nil error on pre-existing targets so callers can skip cleanly.
// Defends against symlink-plant TOCTOU on shared-home mounts: O_EXCL refuses
// to follow an existing symlink, so an attacker cannot redirect the write.
func writeFileExcl(path string, content []byte, mode os.FileMode) (bool, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()
	if _, err := f.Write(content); err != nil {
		return false, err
	}
	return true, nil
}

// Lock locks the user's local password via usermod --lock.
// Prepends '!' to the shadow hash, preventing password authentication.
func Lock(username string, log *logger.Logger) error {
	if !validUsername.MatchString(username) {
		return fmt.Errorf("invalid username: %q", username)
	}
	if out, _, err := executor.Run("usermod", "--lock", username); err != nil {
		return fmt.Errorf("lock user %s: %s: %w", username, string(out), err)
	}
	log.Info("Locked user account: %s", username)
	return nil
}

// Unlock unlocks the user's local password via usermod --unlock.
// Removes the '!' prefix from the shadow hash.
func Unlock(username string, log *logger.Logger) error {
	if !validUsername.MatchString(username) {
		return fmt.Errorf("invalid username: %q", username)
	}
	if out, _, err := executor.Run("usermod", "--unlock", username); err != nil {
		return fmt.Errorf("unlock user %s: %s: %w", username, string(out), err)
	}
	log.Info("Unlocked user account: %s", username)
	return nil
}

// validateGroups ensures every entry is a well-formed group name. Empty
// lists are allowed (the caller decides whether that's meaningful).
func validateGroups(groups []string) error {
	for _, g := range groups {
		if !validGroupName.MatchString(g) {
			return fmt.Errorf("invalid group name %q", g)
		}
	}
	return nil
}

// groupDiff returns elements in a that are NOT in b.
func groupDiff(a, b []string) []string {
	bSet := make(map[string]bool)
	for _, g := range b {
		bSet[g] = true
	}
	var diff []string
	for _, g := range a {
		if !bSet[g] {
			diff = append(diff, g)
		}
	}
	return diff
}

func userExists(username string) (bool, error) {
	_, exitCode, err := executor.Run("getent", "passwd", username)
	if err == nil {
		return true, nil
	}
	if exitCode == 2 {
		return false, nil
	}
	return false, err
}
