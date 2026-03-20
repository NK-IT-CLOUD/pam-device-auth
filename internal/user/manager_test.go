package user

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nk-dev/pam-device-auth/internal/logger"
)

type mockResult struct {
	out      []byte
	exitCode int
	err      error
}

type mockExecutor struct {
	results map[string][]mockResult
	calls   []string
}

func (m *mockExecutor) Run(name string, args ...string) ([]byte, int, error) {
	call := strings.Join(append([]string{name}, args...), " ")
	m.calls = append(m.calls, call)

	if len(m.results[call]) == 0 {
		return nil, 0, nil
	}

	result := m.results[call][0]
	m.results[call] = m.results[call][1:]
	return result.out, result.exitCode, result.err
}

func testLogger(t *testing.T) *logger.Logger {
	t.Helper()

	log, err := logger.NewLogger("", false)
	if err != nil {
		t.Fatalf("NewLogger() error: %v", err)
	}
	return log
}

func setupTestEnvironment(t *testing.T, exec commandExecutor) string {
	t.Helper()

	dir := t.TempDir()
	origExecutor := executor
	origSudoersFile := sudoersFile

	executor = exec
	sudoersFile = filepath.Join(dir, "keycloak-ssh-auth")

	t.Cleanup(func() {
		executor = origExecutor
		sudoersFile = origSudoersFile
	})

	return dir
}

func TestIsValidUsername(t *testing.T) {
	valid := []string{"admin", "testuser", "a", "user-name", "user_name", "_hidden"}
	invalid := []string{"", "Root", "123start", "has space", "way-too-long-username-that-exceeds-the-maximum", "special!char", "-start"}

	for _, u := range valid {
		if !validUsername.MatchString(u) {
			t.Errorf("%q should be valid", u)
		}
	}
	for _, u := range invalid {
		if validUsername.MatchString(u) {
			t.Errorf("%q should be invalid", u)
		}
	}
}

func TestSetupExistingUserWithExistingSudoers(t *testing.T) {
	mock := &mockExecutor{
		results: map[string][]mockResult{
			"getent passwd testuser":    {{exitCode: 0}},
			"usermod -aG sudo testuser": {{exitCode: 0}},
		},
	}
	setupTestEnvironment(t, mock)

	if err := os.WriteFile(sudoersFile, []byte(sudoersContent), 0440); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	created, err := Setup("testuser", testLogger(t))
	if err != nil {
		t.Fatalf("Setup() error: %v", err)
	}
	if created {
		t.Fatal("Setup() should return created=false for existing user")
	}

	for _, call := range mock.calls {
		if strings.HasPrefix(call, "useradd ") {
			t.Fatalf("useradd should not be called for existing users, calls = %v", mock.calls)
		}
	}
}

func TestSetupCreatesUserAndSudoers(t *testing.T) {
	mock := &mockExecutor{
		results: map[string][]mockResult{
			"getent passwd testuser":                   {{exitCode: 2, err: errors.New("not found")}},
			"useradd -m -s /bin/bash -G sudo testuser": {{exitCode: 0}},
			"usermod -aG sudo testuser":                {{exitCode: 0}},
		},
	}

	setupTestEnvironment(t, mock)
	mock.results["visudo -cf "+sudoersFile+".tmp"] = []mockResult{{exitCode: 0}}

	created, err := Setup("testuser", testLogger(t))
	if err != nil {
		t.Fatalf("Setup() error: %v", err)
	}
	if !created {
		t.Fatal("Setup() should return created=true for new user")
	}

	content, err := os.ReadFile(sudoersFile)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	if string(content) != sudoersContent {
		t.Errorf("sudoers content = %q, want %q", string(content), sudoersContent)
	}
}

func TestSetupUserAddFailure(t *testing.T) {
	mock := &mockExecutor{
		results: map[string][]mockResult{
			"getent passwd testuser": {{exitCode: 2, err: errors.New("not found")}},
			"useradd -m -s /bin/bash -G sudo testuser": {{
				out:      []byte("useradd failed"),
				exitCode: 1,
				err:      errors.New("exit status 1"),
			}},
		},
	}
	setupTestEnvironment(t, mock)

	_, err := Setup("testuser", testLogger(t))
	if err == nil {
		t.Fatal("Setup() should fail when useradd fails")
	}
	if !strings.Contains(err.Error(), "useradd failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetupVisudoFailureCleansTempFile(t *testing.T) {
	mock := &mockExecutor{
		results: map[string][]mockResult{
			"getent passwd testuser":    {{exitCode: 0}},
			"usermod -aG sudo testuser": {{exitCode: 0}},
		},
	}
	setupTestEnvironment(t, mock)
	mock.results["visudo -cf "+sudoersFile+".tmp"] = []mockResult{{
		out:      []byte("syntax error"),
		exitCode: 1,
		err:      errors.New("exit status 1"),
	}}

	_, err := Setup("testuser", testLogger(t))
	if err == nil {
		t.Fatal("Setup() should fail when visudo validation fails")
	}
	if _, statErr := os.Stat(sudoersFile); !os.IsNotExist(statErr) {
		t.Fatalf("sudoers file should not exist after validation failure, statErr = %v", statErr)
	}
	if _, statErr := os.Stat(sudoersFile + ".tmp"); !os.IsNotExist(statErr) {
		t.Fatalf("temporary sudoers file should be cleaned up, statErr = %v", statErr)
	}
}
