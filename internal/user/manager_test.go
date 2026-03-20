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

func (m *mockExecutor) RunWithStdin(name string, stdin string, args ...string) ([]byte, int, error) {
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

	created, _, err := Setup("testuser", []string{"sudo"}, nil, true, true, testLogger(t))
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
			"getent passwd testuser":           {{exitCode: 2, err: errors.New("not found")}},
			"useradd -m -s /bin/bash testuser": {{exitCode: 0}},
			"usermod -aG sudo testuser":        {{exitCode: 0}},
			"chage -d 0 testuser":              {{exitCode: 0}},
		},
	}

	setupTestEnvironment(t, mock)

	created, _, err := Setup("testuser", []string{"sudo"}, nil, true, true, testLogger(t))
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

	_, _, err := Setup("testuser", []string{"sudo"}, nil, true, true, testLogger(t))
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

	created, _, err := Setup("testuser", []string{"docker", "adm"}, nil, true, true, testLogger(t))
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

	created, _, err := Setup("testuser", []string{"sudo"}, nil, true, false, testLogger(t))
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

	created, _, err := Setup("testuser", []string{"sudo"}, nil, true, true, testLogger(t))
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

	created, _, err := Setup("testuser", []string{"sudo"}, nil, true, true, testLogger(t))
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

// --- New tests for role-based group assignment ---

func TestSetup_AdminUser(t *testing.T) {
	mock := &mockExecutor{
		results: map[string][]mockResult{
			"getent passwd newuser":           {{exitCode: 2, err: errors.New("not found")}},
			"useradd -m -s /bin/bash newuser": {{exitCode: 0}},
			"usermod -aG sudo newuser":        {{exitCode: 0}},
			"usermod -aG users newuser":       {{exitCode: 0}},
			"chage -d 0 newuser":              {{exitCode: 0}},
		},
	}
	setupTestEnvironment(t, mock)

	created, _, err := Setup("newuser", []string{"users"}, []string{"sudo", "users"}, true, true, testLogger(t))
	if err != nil {
		t.Fatalf("Setup() error: %v", err)
	}
	if !created {
		t.Fatal("Setup() should return created=true for new user")
	}

	hasSudo := false
	hasUsers := false
	hasChage := false
	for _, call := range mock.calls {
		if call == "usermod -aG sudo newuser" {
			hasSudo = true
		}
		if call == "usermod -aG users newuser" {
			hasUsers = true
		}
		if call == "chage -d 0 newuser" {
			hasChage = true
		}
	}
	if !hasSudo {
		t.Fatalf("admin user should be added to sudo group, calls = %v", mock.calls)
	}
	if !hasUsers {
		t.Fatalf("admin user should be added to users group, calls = %v", mock.calls)
	}
	if !hasChage {
		t.Fatalf("chage should be called for new user, calls = %v", mock.calls)
	}
}

func TestSetup_NormalUser(t *testing.T) {
	mock := &mockExecutor{
		results: map[string][]mockResult{
			"getent passwd newuser":           {{exitCode: 2, err: errors.New("not found")}},
			"useradd -m -s /bin/bash newuser": {{exitCode: 0}},
			"usermod -aG users newuser":       {{exitCode: 0}},
			"gpasswd -d newuser sudo":         {{exitCode: 0}},
			"chage -d 0 newuser":              {{exitCode: 0}},
		},
	}
	setupTestEnvironment(t, mock)

	created, _, err := Setup("newuser", []string{"users"}, []string{"sudo", "users"}, false, true, testLogger(t))
	if err != nil {
		t.Fatalf("Setup() error: %v", err)
	}
	if !created {
		t.Fatal("Setup() should return created=true for new user")
	}

	hasUsersGroup := false
	hasGpasswd := false
	for _, call := range mock.calls {
		if call == "usermod -aG users newuser" {
			hasUsersGroup = true
		}
		if call == "gpasswd -d newuser sudo" {
			hasGpasswd = true
		}
		// Normal user should NOT get sudo via usermod
		if call == "usermod -aG sudo newuser" {
			t.Fatalf("normal user should NOT be added to sudo group, calls = %v", mock.calls)
		}
	}
	if !hasUsersGroup {
		t.Fatalf("normal user should be added to users group, calls = %v", mock.calls)
	}
	if !hasGpasswd {
		t.Fatalf("normal user should be removed from sudo (admin-only) group, calls = %v", mock.calls)
	}
}

func TestSetup_Demotion(t *testing.T) {
	// Existing user, isAdmin=false, adminGroups=["sudo","users"], userGroups=["users"]
	// Expect: usermod -aG users, gpasswd -d username sudo
	mock := &mockExecutor{
		results: map[string][]mockResult{
			"getent passwd existuser":       {{exitCode: 0}},
			"usermod -aG users existuser":   {{exitCode: 0}},
			"gpasswd -d existuser sudo":     {{exitCode: 0}},
		},
	}
	setupTestEnvironment(t, mock)

	created, _, err := Setup("existuser", []string{"users"}, []string{"sudo", "users"}, false, true, testLogger(t))
	if err != nil {
		t.Fatalf("Setup() error: %v", err)
	}
	if created {
		t.Fatal("Setup() should return created=false for existing user")
	}

	hasUsersGroup := false
	hasGpasswd := false
	for _, call := range mock.calls {
		if call == "usermod -aG users existuser" {
			hasUsersGroup = true
		}
		if call == "gpasswd -d existuser sudo" {
			hasGpasswd = true
		}
	}
	if !hasUsersGroup {
		t.Fatalf("demoted user should be added to users group, calls = %v", mock.calls)
	}
	if !hasGpasswd {
		t.Fatalf("demoted user should be removed from sudo group, calls = %v", mock.calls)
	}

	// Ensure no chage for existing user
	for _, call := range mock.calls {
		if strings.HasPrefix(call, "chage ") {
			t.Fatalf("chage should not be called for existing user, calls = %v", mock.calls)
		}
	}
}

func TestSetup_NoSudoRole(t *testing.T) {
	// isAdmin=true, adminGroups=[] (empty) — backward compatible behavior
	// Expect: usermod -aG for userGroups only
	mock := &mockExecutor{
		results: map[string][]mockResult{
			"getent passwd testuser":           {{exitCode: 2, err: errors.New("not found")}},
			"useradd -m -s /bin/bash testuser": {{exitCode: 0}},
			"usermod -aG users testuser":       {{exitCode: 0}},
			"chage -d 0 testuser":              {{exitCode: 0}},
		},
	}
	setupTestEnvironment(t, mock)

	created, _, err := Setup("testuser", []string{"users"}, nil, true, true, testLogger(t))
	if err != nil {
		t.Fatalf("Setup() error: %v", err)
	}
	if !created {
		t.Fatal("Setup() should return created=true for new user")
	}

	hasUsersGroup := false
	for _, call := range mock.calls {
		if call == "usermod -aG users testuser" {
			hasUsersGroup = true
		}
		// No gpasswd calls should be made
		if strings.HasPrefix(call, "gpasswd ") {
			t.Fatalf("gpasswd should not be called when adminGroups is empty, calls = %v", mock.calls)
		}
	}
	if !hasUsersGroup {
		t.Fatalf("user should be added to users group, calls = %v", mock.calls)
	}
}

func TestGroupDiff(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want []string
	}{
		{"admin-only groups", []string{"sudo", "users"}, []string{"users"}, []string{"sudo"}},
		{"no diff", []string{"users"}, []string{"users"}, nil},
		{"all different", []string{"sudo", "docker"}, []string{"users"}, []string{"sudo", "docker"}},
		{"empty a", nil, []string{"users"}, nil},
		{"empty b", []string{"sudo"}, nil, []string{"sudo"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := groupDiff(tt.a, tt.b)
			if len(got) != len(tt.want) {
				t.Fatalf("groupDiff(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
			for i, g := range got {
				if g != tt.want[i] {
					t.Fatalf("groupDiff(%v, %v)[%d] = %q, want %q", tt.a, tt.b, i, g, tt.want[i])
				}
			}
		})
	}
}
