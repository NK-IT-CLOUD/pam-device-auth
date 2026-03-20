package user

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"

	"github.com/nk-dev/pam-device-auth/internal/logger"
)

var validUsername = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
var executor commandExecutor = systemCommandExecutor{}

type commandExecutor interface {
	Run(name string, args ...string) ([]byte, int, error)
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
// Returns (true, nil) if the user was newly created.
func Setup(username string, userGroups, adminGroups []string, isAdmin bool, forcePasswd bool, log *logger.Logger) (bool, error) {
	if !validUsername.MatchString(username) {
		return false, fmt.Errorf("invalid username: %q", username)
	}

	exists, err := userExists(username)
	if err != nil {
		return false, fmt.Errorf("check user exists: %w", err)
	}

	created := false
	if !exists {
		log.Info("Creating user: %s", username)
		if out, _, err := executor.Run("useradd", "-m", "-s", "/bin/bash", username); err != nil {
			return false, fmt.Errorf("useradd failed: %s: %w", string(out), err)
		}
		log.Info("User %s created", username)
		created = true
	}

	// Determine groups based on admin status
	if isAdmin && len(adminGroups) > 0 {
		// Admin: add to admin groups
		for _, g := range adminGroups {
			if out, _, err := executor.Run("usermod", "-aG", g, username); err != nil {
				log.Warn("Failed to add %s to group %s: %s", username, g, string(out))
			}
		}
		log.Info("Admin groups applied for %s: %v", username, adminGroups)
	} else {
		// Normal user: add to user groups
		for _, g := range userGroups {
			if out, _, err := executor.Run("usermod", "-aG", g, username); err != nil {
				log.Warn("Failed to add %s to group %s: %s", username, g, string(out))
			}
		}

		// If admin groups configured, remove from admin-only groups (demotion)
		if len(adminGroups) > 0 {
			adminOnly := groupDiff(adminGroups, userGroups)
			for _, g := range adminOnly {
				executor.Run("gpasswd", "-d", username, g) // ignore errors
				log.Info("Removed %s from group %s (admin role revoked)", username, g)
			}
		}
	}

	// Force password change on first login
	if created && forcePasswd {
		if out, _, err := executor.Run("chage", "-d", "0", username); err != nil {
			log.Warn("Failed to force password change: %s", string(out))
		}
	}

	return created, nil
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
