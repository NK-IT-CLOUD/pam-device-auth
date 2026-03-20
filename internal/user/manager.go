package user

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/nk-dev/pam-device-auth/internal/logger"
)

var validUsername = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
var executor commandExecutor = systemCommandExecutor{}

type commandExecutor interface {
	Run(name string, args ...string) ([]byte, int, error)
	RunWithStdin(name string, stdin string, args ...string) ([]byte, int, error)
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

func (systemCommandExecutor) RunWithStdin(name string, stdin string, args ...string) ([]byte, int, error) {
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

	// Set temporary password + force change on first login
	var tempPassword string
	if created && forcePasswd {
		tempPassword, err = setTempPassword(username, log)
		if err != nil {
			log.Warn("Failed to set temp password: %v", err)
		}
	}

	return created, tempPassword, nil
}

// setTempPassword generates a random password, sets it via chpasswd, and expires it.
func setTempPassword(username string, log *logger.Logger) (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random password: %w", err)
	}
	tempPwd := base64.RawURLEncoding.EncodeToString(b)[:16]

	// Set password via chpasswd
	input := fmt.Sprintf("%s:%s", username, tempPwd)
	if out, _, err := executor.RunWithStdin("chpasswd", input); err != nil {
		return "", fmt.Errorf("chpasswd failed: %s: %w", string(out), err)
	}

	// Force password change on next login
	if out, _, err := executor.Run("chage", "-d", "0", username); err != nil {
		log.Warn("chage failed: %s", string(out))
	}

	return tempPwd, nil
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
