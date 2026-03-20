package user

import (
	"errors"
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

func setupTestEnvironment(t *testing.T, exec commandExecutor) {
	t.Helper()

	origExecutor := executor
	executor = exec

	t.Cleanup(func() {
		executor = origExecutor
	})
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

func TestSetupExistingUser(t *testing.T) {
	mock := &mockExecutor{
		results: map[string][]mockResult{
			"getent passwd testuser":    {{exitCode: 0}},
			"usermod -aG sudo testuser": {{exitCode: 0}},
		},
	}
	setupTestEnvironment(t, mock)

	created, err := Setup("testuser", []string{"sudo"}, true, testLogger(t))
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
		if strings.HasPrefix(call, "chage ") {
			t.Fatalf("chage should not be called for existing users, calls = %v", mock.calls)
		}
	}
}

func TestSetupCreatesUser(t *testing.T) {
	mock := &mockExecutor{
		results: map[string][]mockResult{
			"getent passwd testuser":        {{exitCode: 2, err: errors.New("not found")}},
			"useradd -m -s /bin/bash testuser": {{exitCode: 0}},
			"usermod -aG sudo testuser":     {{exitCode: 0}},
			"chage -d 0 testuser":           {{exitCode: 0}},
		},
	}

	setupTestEnvironment(t, mock)

	created, err := Setup("testuser", []string{"sudo"}, true, testLogger(t))
	if err != nil {
		t.Fatalf("Setup() error: %v", err)
	}
	if !created {
		t.Fatal("Setup() should return created=true for new user")
	}

	hasUseradd := false
	hasChage := false
	for _, call := range mock.calls {
		if call == "useradd -m -s /bin/bash testuser" {
			hasUseradd = true
		}
		if call == "chage -d 0 testuser" {
			hasChage = true
		}
	}
	if !hasUseradd {
		t.Fatalf("useradd should be called for new user, calls = %v", mock.calls)
	}
	if !hasChage {
		t.Fatalf("chage should be called for new user with forcePasswd=true, calls = %v", mock.calls)
	}
}

func TestSetupUserAddFailure(t *testing.T) {
	mock := &mockExecutor{
		results: map[string][]mockResult{
			"getent passwd testuser": {{exitCode: 2, err: errors.New("not found")}},
			"useradd -m -s /bin/bash testuser": {{
				out:      []byte("useradd failed"),
				exitCode: 1,
				err:      errors.New("exit status 1"),
			}},
		},
	}
	setupTestEnvironment(t, mock)

	_, err := Setup("testuser", []string{"sudo"}, true, testLogger(t))
	if err == nil {
		t.Fatal("Setup() should fail when useradd fails")
	}
	if !strings.Contains(err.Error(), "useradd failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetup_CustomGroups(t *testing.T) {
	mock := &mockExecutor{
		results: map[string][]mockResult{
			"getent passwd testuser":           {{exitCode: 2, err: errors.New("not found")}},
			"useradd -m -s /bin/bash testuser": {{exitCode: 0}},
			"usermod -aG docker testuser":      {{exitCode: 0}},
			"usermod -aG adm testuser":         {{exitCode: 0}},
			"chage -d 0 testuser":              {{exitCode: 0}},
		},
	}
	setupTestEnvironment(t, mock)

	created, err := Setup("testuser", []string{"docker", "adm"}, true, testLogger(t))
	if err != nil {
		t.Fatalf("Setup() error: %v", err)
	}
	if !created {
		t.Fatal("Setup() should return created=true for new user")
	}

	hasDocker := false
	hasAdm := false
	for _, call := range mock.calls {
		if call == "usermod -aG docker testuser" {
			hasDocker = true
		}
		if call == "usermod -aG adm testuser" {
			hasAdm = true
		}
	}
	if !hasDocker {
		t.Fatalf("usermod for docker group should be called, calls = %v", mock.calls)
	}
	if !hasAdm {
		t.Fatalf("usermod for adm group should be called, calls = %v", mock.calls)
	}
}

func TestSetup_NoForcePasswd(t *testing.T) {
	mock := &mockExecutor{
		results: map[string][]mockResult{
			"getent passwd testuser":           {{exitCode: 2, err: errors.New("not found")}},
			"useradd -m -s /bin/bash testuser": {{exitCode: 0}},
			"usermod -aG sudo testuser":        {{exitCode: 0}},
		},
	}
	setupTestEnvironment(t, mock)

	created, err := Setup("testuser", []string{"sudo"}, false, testLogger(t))
	if err != nil {
		t.Fatalf("Setup() error: %v", err)
	}
	if !created {
		t.Fatal("Setup() should return created=true for new user")
	}

	for _, call := range mock.calls {
		if strings.HasPrefix(call, "chage ") {
			t.Fatalf("chage should not be called when forcePasswd=false, calls = %v", mock.calls)
		}
	}
}

func TestSetup_ForcePasswd(t *testing.T) {
	mock := &mockExecutor{
		results: map[string][]mockResult{
			"getent passwd testuser":           {{exitCode: 2, err: errors.New("not found")}},
			"useradd -m -s /bin/bash testuser": {{exitCode: 0}},
			"usermod -aG sudo testuser":        {{exitCode: 0}},
			"chage -d 0 testuser":              {{exitCode: 0}},
		},
	}
	setupTestEnvironment(t, mock)

	created, err := Setup("testuser", []string{"sudo"}, true, testLogger(t))
	if err != nil {
		t.Fatalf("Setup() error: %v", err)
	}
	if !created {
		t.Fatal("Setup() should return created=true for new user")
	}

	hasChage := false
	for _, call := range mock.calls {
		if call == "chage -d 0 testuser" {
			hasChage = true
		}
	}
	if !hasChage {
		t.Fatalf("chage -d 0 should be called for new user with forcePasswd=true, calls = %v", mock.calls)
	}
}

func TestSetup_ExistingUser_NoChage(t *testing.T) {
	mock := &mockExecutor{
		results: map[string][]mockResult{
			"getent passwd testuser":    {{exitCode: 0}},
			"usermod -aG sudo testuser": {{exitCode: 0}},
		},
	}
	setupTestEnvironment(t, mock)

	created, err := Setup("testuser", []string{"sudo"}, true, testLogger(t))
	if err != nil {
		t.Fatalf("Setup() error: %v", err)
	}
	if created {
		t.Fatal("Setup() should return created=false for existing user")
	}

	for _, call := range mock.calls {
		if strings.HasPrefix(call, "chage ") {
			t.Fatalf("chage should not be called for existing user even with forcePasswd=true, calls = %v", mock.calls)
		}
	}
}
