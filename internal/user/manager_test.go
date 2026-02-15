package user

import (
	"os"
	"path/filepath"
	"testing"

	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/logger"
)

func newTestLogger() *logger.Logger {
	log, _ := logger.NewLogger("", true)
	return log
}

func TestNewManager(t *testing.T) {
	log := newTestLogger()
	m := NewManager(log)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.logger == nil {
		t.Error("Manager should have a logger")
	}
}

func TestIsValidUsername(t *testing.T) {
	valid := []string{
		"root", "admin", "norbert", "test_user", "user-name",
		"a", "_service", "_", "a0", "user123",
		"ab-cd-ef", "a_b_c",
	}
	invalid := []string{
		"", "Root", "ADMIN", "user name", "user@name",
		"123user", "-user", ".user",
		"a-very-long-username-that-exceeds-the-limit-of-32-chars",
		"../etc", "user/name", "user\tname",
		"user;cmd", "$(whoami)", "`id`",
	}

	for _, u := range valid {
		if !isValidUsername(u) {
			t.Errorf("'%s' should be valid", u)
		}
	}
	for _, u := range invalid {
		if isValidUsername(u) {
			t.Errorf("'%s' should be invalid", u)
		}
	}
}

func TestIsValidUsername_MaxLength(t *testing.T) {
	// Exactly 32 chars (1 start + 31 following = 32 total)
	maxValid := "a2345678901234567890123456789012"
	if len(maxValid) != 32 {
		t.Fatalf("test string should be 32 chars, got %d", len(maxValid))
	}
	if !isValidUsername(maxValid) {
		t.Errorf("32-char username should be valid")
	}

	// 33 chars should fail
	tooLong := maxValid + "x"
	if isValidUsername(tooLong) {
		t.Errorf("33-char username should be invalid")
	}
}

func TestFindCommand(t *testing.T) {
	// These should exist on any Linux system
	found := false
	for _, cmd := range []string{"ls", "cat", "bash", "sh"} {
		if path := findCommand(cmd); path != "" {
			found = true
			// Verify the path actually exists
			if _, err := os.Stat(path); err != nil {
				t.Errorf("findCommand returned '%s' but file doesn't exist", path)
			}
			break
		}
	}
	if !found {
		t.Error("at least one of ls/cat/bash/sh should be found")
	}

	// This should not exist
	if path := findCommand("nonexistent_command_xyz_abc_123"); path != "" {
		t.Errorf("nonexistent command found at '%s'", path)
	}
}

func TestFindCommand_KnownPaths(t *testing.T) {
	// Test that findCommand checks standard paths
	// On most systems, 'ls' is in /usr/bin or /bin
	path := findCommand("ls")
	if path == "" {
		t.Skip("ls not found in standard paths")
	}

	dir := filepath.Dir(path)
	validDirs := map[string]bool{
		"/usr/sbin": true, "/sbin": true,
		"/usr/bin": true, "/bin": true,
	}
	if !validDirs[dir] {
		t.Errorf("findCommand returned unexpected directory: %s", dir)
	}
}

func TestSetupUser_InvalidUsername(t *testing.T) {
	log := newTestLogger()
	m := NewManager(log)

	invalidUsernames := []string{
		"", "Root", "ADMIN", "user name",
		"../etc", "$(whoami)", "123start",
	}

	for _, u := range invalidUsernames {
		err := m.SetupUser(u, false, false)
		if err == nil {
			t.Errorf("SetupUser should fail for invalid username '%s'", u)
		}
	}
}

func TestSetupUser_UserNotExistsNoCreate(t *testing.T) {
	log := newTestLogger()
	m := NewManager(log)

	// This user should not exist on the test system
	err := m.SetupUser("nonexistent_test_user_xyz", false, false)
	if err == nil {
		t.Error("SetupUser should fail when user doesn't exist and createUser is false")
	}
}

func TestUserExists_CurrentUser(t *testing.T) {
	log := newTestLogger()
	m := NewManager(log)

	// root should always exist
	if !m.userExists("root") {
		t.Error("root user should exist")
	}
}

func TestUserExists_NonexistentUser(t *testing.T) {
	log := newTestLogger()
	m := NewManager(log)

	if m.userExists("nonexistent_user_abc_xyz_12345") {
		t.Error("nonexistent user should not exist")
	}
}

func TestIsUserInGroup_Root(t *testing.T) {
	log := newTestLogger()
	m := NewManager(log)

	// root should be in the root group on most systems
	// This test may be system-dependent
	if m.isUserInGroup("nonexistent_user_xyz", "root") {
		t.Error("nonexistent user should not be in root group")
	}
}

func TestIsUserInGroup_NonexistentGroup(t *testing.T) {
	log := newTestLogger()
	m := NewManager(log)

	if m.isUserInGroup("root", "nonexistent_group_abc_xyz") {
		t.Error("user should not be in nonexistent group")
	}
}

func TestIsNOPASSWDSet(t *testing.T) {
	log := newTestLogger()
	m := NewManager(log)

	// Test with a group that likely doesn't have NOPASSWD set
	result := m.isNOPASSWDSet("nonexistent_group_xyz")
	if result {
		t.Error("nonexistent group should not have NOPASSWD set")
	}
}

func TestAddUserToGroup_InvalidInputs(t *testing.T) {
	log := newTestLogger()
	m := NewManager(log)

	// Invalid username
	err := m.addUserToGroup("INVALID_USER", "sudo")
	if err == nil {
		t.Error("should fail for invalid username")
	}

	// Invalid group name
	err = m.addUserToGroup("root", "INVALID_GROUP")
	if err == nil {
		t.Error("should fail for invalid group name")
	}
}

func TestSetNOPASSWD_InvalidGroupName(t *testing.T) {
	log := newTestLogger()
	m := NewManager(log)

	err := m.setNOPASSWD("INVALID_GROUP_NAME")
	if err == nil {
		t.Error("should fail for invalid group name format")
	}
}
