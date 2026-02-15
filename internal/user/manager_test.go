package user

import (
	"testing"
)

func TestIsValidUsername(t *testing.T) {
	valid := []string{"root", "admin", "norbert", "test_user", "user-name", "a", "_service"}
	invalid := []string{"", "Root", "ADMIN", "user name", "user@name", "123user", "a-very-long-username-that-exceeds-the-limit-of-32-chars", "../etc"}

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

func TestFindCommand(t *testing.T) {
	// These should exist on any Linux system
	if path := findCommand("ls"); path == "" {
		t.Error("ls should be found")
	}

	// This should not exist
	if path := findCommand("nonexistent_command_xyz"); path != "" {
		t.Errorf("nonexistent command found at '%s'", path)
	}
}
