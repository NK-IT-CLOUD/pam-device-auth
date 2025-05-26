package user

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"keycloak-ssh-auth/internal/logger"
)

// Manager handles user account management
type Manager struct {
	logger *logger.Logger
}

// NewManager creates a new user manager
func NewManager(log *logger.Logger) *Manager {
	return &Manager{
		logger: log,
	}
}

// SetupUser creates or updates a user account with proper permissions
func (m *Manager) SetupUser(username string, createUser, addToSudo bool) error {
	m.logger.Info("Setting up user account: %s", username)

	if !isValidUsername(username) {
		return fmt.Errorf("invalid username format: %s", username)
	}

	// Check if user exists
	exists := m.userExists(username)
	
	if !exists && createUser {
		m.logger.Info("Creating new system user: %s", username)
		if err := m.createUser(username); err != nil {
			return fmt.Errorf("failed to create user: %v", err)
		}
		m.logger.Info("User created successfully: %s", username)
	} else if !exists {
		return fmt.Errorf("user %s does not exist and user creation is disabled", username)
	} else {
		m.logger.Info("User already exists: %s", username)
	}

	// Add to sudo group if requested
	if addToSudo {
		if !m.isUserInGroup(username, "sudo") {
			m.logger.Info("Adding user to sudo group: %s", username)
			if err := m.addUserToGroup(username, "sudo"); err != nil {
				return fmt.Errorf("failed to add user to sudo group: %v", err)
			}
		}

		// Configure NOPASSWD sudo access
		if !m.isNOPASSWDSet("sudo") {
			m.logger.Info("Configuring NOPASSWD sudo access")
			if err := m.setNOPASSWD("sudo"); err != nil {
				return fmt.Errorf("failed to configure NOPASSWD sudo: %v", err)
			}
		}
	}

	m.logger.Info("User setup completed: %s", username)
	return nil
}

// userExists checks if a user exists in the system
func (m *Manager) userExists(username string) bool {
	m.logger.Debug("Checking if user exists: %s", username)
	
	// Try getent first
	if getentPath := findCommand("getent"); getentPath != "" {
		cmd := exec.Command(getentPath, "passwd", username)
		if err := cmd.Run(); err == nil {
			m.logger.Debug("User %s exists (confirmed via getent)", username)
			return true
		}
	}
	
	// Fallback to /etc/passwd
	content, err := os.ReadFile("/etc/passwd")
	if err != nil {
		m.logger.Error("Error reading /etc/passwd: %v", err)
		return false
	}
	
	exists := strings.Contains(string(content), fmt.Sprintf("%s:", username))
	m.logger.Debug("User %s exists: %v (checked via /etc/passwd)", username, exists)
	return exists
}

// createUser creates a new system user
func (m *Manager) createUser(username string) error {
	useraddPath := findCommand("useradd")
	if useraddPath == "" {
		return fmt.Errorf("useradd command not found")
	}
	
	// Create user with home directory and shell
	cmd := exec.Command(useraddPath,
		"-m",                    // Create home directory
		"-s", "/bin/bash",      // Set default shell
		"-G", "sudo",           // Add to sudo group directly
		username)
	
	if output, err := cmd.CombinedOutput(); err != nil {
		m.logger.Error("Failed to add user: %v (output: %s)", err, string(output))
		return fmt.Errorf("failed to add user: %v", err)
	}
	
	// Set permissions for home directory
	homePath := fmt.Sprintf("/home/%s", username)
	if err := os.Chmod(homePath, 0750); err != nil {
		m.logger.Warn("Failed to set home directory permissions: %v", err)
	}
	
	// Ensure proper ownership
	if chownPath := findCommand("chown"); chownPath != "" {
		cmd = exec.Command(chownPath, "-R", fmt.Sprintf("%s:%s", username, username), homePath)
		if output, err := cmd.CombinedOutput(); err != nil {
			m.logger.Warn("Failed to set ownership: %v (output: %s)", err, string(output))
		}
	}
	
	// Sleep briefly to allow system to complete user setup
	time.Sleep(2 * time.Second)
	
	return nil
}

// isUserInGroup checks if a user is in a specified group
func (m *Manager) isUserInGroup(username, groupname string) bool {
	m.logger.Debug("Checking if user %s is in group %s", username, groupname)
	
	// Try getent first
	if getentPath := findCommand("getent"); getentPath != "" {
		cmd := exec.Command(getentPath, "group", groupname)
		output, err := cmd.CombinedOutput()
		if err == nil {
			groupLine := string(output)
			fields := strings.Split(groupLine, ":")
			if len(fields) >= 4 {
				members := strings.Split(fields[3], ",")
				for _, member := range members {
					if strings.TrimSpace(member) == username {
						m.logger.Debug("User %s found in group %s via getent", username, groupname)
						return true
					}
				}
			}
		}
	}
	
	// Fallback to groups command
	if groupsPath := findCommand("groups"); groupsPath != "" {
		cmd := exec.Command(groupsPath, username)
		output, err := cmd.CombinedOutput()
		if err == nil {
			groups := strings.Fields(string(output))
			for _, group := range groups {
				if group == groupname {
					m.logger.Debug("User %s found in group %s via groups command", username, groupname)
					return true
				}
			}
		}
	}
	
	m.logger.Debug("User %s not found in group %s", username, groupname)
	return false
}

// addUserToGroup adds a user to a specified group
func (m *Manager) addUserToGroup(username, groupname string) error {
	if !isValidUsername(username) || !isValidUsername(groupname) {
		return fmt.Errorf("invalid username or groupname format")
	}
	
	usermodPath := findCommand("usermod")
	if usermodPath == "" {
		return fmt.Errorf("usermod command not found")
	}
	
	cmd := exec.Command(usermodPath, "-aG", groupname, username)
	if output, err := cmd.CombinedOutput(); err != nil {
		m.logger.Error("Failed to add user to group: %v (output: %s)", err, string(output))
		return fmt.Errorf("failed to add user to group")
	}
	
	// Verify the change
	if !m.isUserInGroup(username, groupname) {
		return fmt.Errorf("group membership verification failed")
	}
	
	m.logger.Info("Successfully added user %s to group %s", username, groupname)
	return nil
}

// isNOPASSWDSet checks if NOPASSWD is set for a group
func (m *Manager) isNOPASSWDSet(groupname string) bool {
	content, err := os.ReadFile("/etc/sudoers")
	if err != nil {
		m.logger.Error("Error reading /etc/sudoers: %v", err)
		return false
	}
	
	// Check for NOPASSWD rule
	patterns := []string{
		fmt.Sprintf("%%%s\\s+ALL\\s*=\\s*\\(ALL(:ALL)?\\)\\s*NOPASSWD:\\s*ALL", groupname),
		fmt.Sprintf("%s\\s+ALL\\s*=\\s*\\(ALL(:ALL)?\\)\\s*NOPASSWD:\\s*ALL", groupname),
	}
	
	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, string(content)); matched {
			m.logger.Debug("NOPASSWD rule exists for group %s", groupname)
			return true
		}
	}
	
	m.logger.Debug("NOPASSWD rule not found for group %s", groupname)
	return false
}

// setNOPASSWD sets NOPASSWD for a group in /etc/sudoers
func (m *Manager) setNOPASSWD(groupname string) error {
	if !isValidUsername(groupname) {
		return fmt.Errorf("invalid group name format")
	}
	
	visudoPath := findCommand("visudo")
	if visudoPath == "" {
		return fmt.Errorf("visudo command not found")
	}
	
	// Create temporary file
	tmpFile, err := os.CreateTemp("/tmp", "sudoers")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %v", err)
	}
	defer func() {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
	}()
	
	// Set secure permissions
	if err := os.Chmod(tmpFile.Name(), 0440); err != nil {
		return fmt.Errorf("failed to set permissions on temporary file: %v", err)
	}
	
	// Read current sudoers
	content, err := os.ReadFile("/etc/sudoers")
	if err != nil {
		return fmt.Errorf("failed to read sudoers file: %v", err)
	}
	
	// Add new rule
	newContent := string(content)
	newRule := fmt.Sprintf("\n%%%s ALL=(ALL) NOPASSWD:ALL # Added by keycloak-ssh-auth\n", groupname)
	newContent += newRule
	
	// Write to temporary file
	if err := os.WriteFile(tmpFile.Name(), []byte(newContent), 0440); err != nil {
		return fmt.Errorf("failed to write temporary file: %v", err)
	}
	
	// Verify syntax
	cmd := exec.Command(visudoPath, "-cf", tmpFile.Name())
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("invalid sudoers syntax: %v (output: %s)", err, string(output))
	}
	
	// Backup original sudoers
	backupPath := "/etc/sudoers.bak"
	if err := os.WriteFile(backupPath, content, 0440); err != nil {
		return fmt.Errorf("failed to create backup: %v", err)
	}
	
	// Copy new file to sudoers
	if cpPath := findCommand("cp"); cpPath != "" {
		if err := exec.Command(cpPath, tmpFile.Name(), "/etc/sudoers").Run(); err != nil {
			// Attempt to restore backup if update fails
			if restoreErr := os.Rename(backupPath, "/etc/sudoers"); restoreErr != nil {
				m.logger.Error("Failed to restore sudoers backup: %v", restoreErr)
			}
			return fmt.Errorf("failed to update sudoers file: %v", err)
		}
	}
	
	m.logger.Info("Successfully updated sudoers for group %s", groupname)
	return nil
}

// isValidUsername validates username format
func isValidUsername(username string) bool {
	matched, err := regexp.MatchString(`^[a-z_][a-z0-9_-]{0,31}$`, username)
	if err != nil {
		return false
	}
	return matched
}

// findCommand finds a command in common system paths
func findCommand(cmd string) string {
	paths := []string{
		fmt.Sprintf("/usr/sbin/%s", cmd),
		fmt.Sprintf("/sbin/%s", cmd),
		fmt.Sprintf("/usr/bin/%s", cmd),
		fmt.Sprintf("/bin/%s", cmd),
	}
	
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}
