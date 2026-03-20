package user

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"

	"github.com/nk-dev/pam-device-auth/internal/logger"
)

var validUsername = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

const sudoersContent = "%sudo ALL=(ALL) NOPASSWD:ALL\n"

var sudoersFile = "/etc/sudoers.d/keycloak-ssh-auth"
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

// findBin resolves a command to its absolute path.
// PAM sets a minimal PATH, so exec.Command("getent") fails.
func findBin(name string) string {
	for _, dir := range []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"} {
		path := dir + "/" + name
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return name // fallback to bare name
}

// Setup creates a Linux user with sudo access if they don't exist.
// Always adds to sudo group and ensures NOPASSWD sudoers drop-in.
// Returns (true, nil) if the user was newly created.
func Setup(username string, log *logger.Logger) (bool, error) {
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
		if out, _, err := executor.Run("useradd", "-m", "-s", "/bin/bash", "-G", "sudo", username); err != nil {
			return false, fmt.Errorf("useradd failed: %s: %w", string(out), err)
		}
		log.Info("User %s created", username)
		created = true
	}

	// Ensure sudo group membership (idempotent)
	if out, _, err := executor.Run("usermod", "-aG", "sudo", username); err != nil {
		return false, fmt.Errorf("add to sudo group: %s: %w", string(out), err)
	}

	// Ensure sudoers drop-in
	if err := ensureSudoers(log); err != nil {
		return false, fmt.Errorf("sudoers setup: %w", err)
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

func ensureSudoers(log *logger.Logger) error {
	if _, err := os.Stat(sudoersFile); err == nil {
		return nil // already exists
	}

	// Write to temp file
	tmpFile := sudoersFile + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(sudoersContent), 0440); err != nil {
		return fmt.Errorf("write temp sudoers: %w", err)
	}

	// Validate syntax
	if out, _, err := executor.Run("visudo", "-cf", tmpFile); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("visudo validation failed: %s: %w", string(out), err)
	}

	// Move into place
	if err := os.Rename(tmpFile, sudoersFile); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("install sudoers: %w", err)
	}

	log.Info("Sudoers drop-in installed: %s", sudoersFile)
	return nil
}
