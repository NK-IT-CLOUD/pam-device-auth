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
// Returns (true, nil) if the user was newly created.
func Setup(username string, groups []string, forcePasswd bool, log *logger.Logger) (bool, error) {
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

	// Add to configured groups
	for _, g := range groups {
		if out, _, err := executor.Run("usermod", "-aG", g, username); err != nil {
			log.Warn("Failed to add %s to group %s: %s", username, g, string(out))
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
