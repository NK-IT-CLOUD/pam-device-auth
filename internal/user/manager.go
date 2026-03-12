package user

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"

	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/logger"
)

var validUsername = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

const sudoersFile = "/etc/sudoers.d/keycloak-ssh-auth"
const sudoersContent = "%sudo ALL=(ALL) NOPASSWD:ALL\n"

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
func Setup(username string, log *logger.Logger) error {
	if !validUsername.MatchString(username) {
		return fmt.Errorf("invalid username: %q", username)
	}

	exists, err := userExists(username)
	if err != nil {
		return fmt.Errorf("check user exists: %w", err)
	}

	if !exists {
		log.Info("Creating user: %s", username)
		cmd := exec.Command(findBin("useradd"), "-m", "-s", "/bin/bash", "-G", "sudo", username)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("useradd failed: %s: %w", string(out), err)
		}
		log.Info("User %s created", username)
	}

	// Ensure sudo group membership (idempotent)
	cmd := exec.Command(findBin("usermod"), "-aG", "sudo", username)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("add to sudo group: %s: %w", string(out), err)
	}

	// Ensure sudoers drop-in
	if err := ensureSudoers(log); err != nil {
		return fmt.Errorf("sudoers setup: %w", err)
	}

	return nil
}

func userExists(username string) (bool, error) {
	err := exec.Command(findBin("getent"), "passwd", username).Run()
	if err == nil {
		return true, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
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
	cmd := exec.Command(findBin("visudo"), "-cf", tmpFile)
	if out, err := cmd.CombinedOutput(); err != nil {
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
