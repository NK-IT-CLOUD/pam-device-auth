package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.AuthTimeout != 180 {
		t.Errorf("default AuthTimeout = %d, want 180", cfg.AuthTimeout)
	}
	if cfg.CreateUser != true {
		t.Errorf("default CreateUser = %v, want true", cfg.CreateUser)
	}
	if len(cfg.UserGroups) != 1 || cfg.UserGroups[0] != "sudo" {
		t.Errorf("default UserGroups = %v, want [sudo]", cfg.UserGroups)
	}
	if cfg.ForcePasswordChange != true {
		t.Errorf("default ForcePasswordChange = %v, want true", cfg.ForcePasswordChange)
	}
}

func TestLoadValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{
		"issuer_url": "https://sso.example.com/realms/test",
		"client_id": "ssh-server",
		"required_role": "ssh-access"
	}`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.IssuerURL != "https://sso.example.com/realms/test" {
		t.Errorf("IssuerURL = %q", cfg.IssuerURL)
	}
	if cfg.ClientID != "ssh-server" {
		t.Errorf("ClientID = %q", cfg.ClientID)
	}
	if cfg.RequiredRole != "ssh-access" {
		t.Errorf("RequiredRole = %q", cfg.RequiredRole)
	}
	if cfg.AuthTimeout != 180 {
		t.Errorf("AuthTimeout = %d, want 180 (default)", cfg.AuthTimeout)
	}
}

func TestLoadWithAuthTimeout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{
		"issuer_url": "https://sso.example.com/realms/test",
		"client_id": "ssh-server",
		"required_role": "ssh-access",
		"auth_timeout": 300
	}`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.AuthTimeout != 300 {
		t.Errorf("AuthTimeout = %d, want 300", cfg.AuthTimeout)
	}
}

func TestLoadRoleClaim(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{
		"issuer_url": "https://sso.example.com/realms/test",
		"client_id": "ssh-server",
		"required_role": "ssh-access",
		"role_claim": "resource_access.ssh.roles"
	}`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.RoleClaim != "resource_access.ssh.roles" {
		t.Errorf("RoleClaim = %q, want resource_access.ssh.roles", cfg.RoleClaim)
	}
}

func TestTrailingSlashStripped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{
		"issuer_url": "https://sso.example.com/realms/test/",
		"client_id": "ssh-server",
		"required_role": "ssh-access"
	}`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.IssuerURL != "https://sso.example.com/realms/test" {
		t.Errorf("IssuerURL = %q, trailing slash should be stripped", cfg.IssuerURL)
	}
}

func TestDefaultUserManagementFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	// Minimal config — user management fields should get defaults
	os.WriteFile(path, []byte(`{
		"issuer_url": "https://sso.example.com/realms/test",
		"client_id": "ssh-server",
		"required_role": "ssh-access"
	}`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.CreateUser != true {
		t.Errorf("CreateUser = %v, want true (default)", cfg.CreateUser)
	}
	if len(cfg.UserGroups) != 1 || cfg.UserGroups[0] != "sudo" {
		t.Errorf("UserGroups = %v, want [sudo] (default)", cfg.UserGroups)
	}
	if cfg.ForcePasswordChange != true {
		t.Errorf("ForcePasswordChange = %v, want true (default)", cfg.ForcePasswordChange)
	}
}

func TestUserManagementFieldsOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{
		"issuer_url": "https://sso.example.com/realms/test",
		"client_id": "ssh-server",
		"required_role": "ssh-access",
		"create_user": false,
		"user_groups": ["wheel", "docker"],
		"force_password_change": false
	}`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.CreateUser != false {
		t.Errorf("CreateUser = %v, want false", cfg.CreateUser)
	}
	if len(cfg.UserGroups) != 2 || cfg.UserGroups[0] != "wheel" || cfg.UserGroups[1] != "docker" {
		t.Errorf("UserGroups = %v, want [wheel docker]", cfg.UserGroups)
	}
	if cfg.ForcePasswordChange != false {
		t.Errorf("ForcePasswordChange = %v, want false", cfg.ForcePasswordChange)
	}
}

func TestValidateMissingFields(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"missing issuer_url", Config{ClientID: "c", RequiredRole: "r", AuthTimeout: 180}},
		{"missing client_id", Config{IssuerURL: "https://x", RequiredRole: "r", AuthTimeout: 180}},
		{"missing required_role", Config{IssuerURL: "https://x", ClientID: "c", AuthTimeout: 180}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.Validate(); err == nil {
				t.Error("Validate() should have returned error")
			}
		})
	}
}

func TestValidateErrorMessages(t *testing.T) {
	cfg := Config{AuthTimeout: 180}
	err := cfg.Validate()
	if err == nil || err.Error() != "issuer_url is required" {
		t.Errorf("expected 'issuer_url is required', got %v", err)
	}
}

func TestValidateTimeoutRange(t *testing.T) {
	base := Config{
		IssuerURL:    "https://sso.example.com/realms/test",
		ClientID:     "ssh-server",
		RequiredRole: "ssh-access",
	}

	base.AuthTimeout = 29
	if err := base.Validate(); err == nil {
		t.Error("timeout 29 should fail")
	}

	base.AuthTimeout = 601
	if err := base.Validate(); err == nil {
		t.Error("timeout 601 should fail")
	}

	base.AuthTimeout = 30
	if err := base.Validate(); err != nil {
		t.Errorf("timeout 30 should pass: %v", err)
	}

	base.AuthTimeout = 600
	if err := base.Validate(); err != nil {
		t.Errorf("timeout 600 should pass: %v", err)
	}
}

func TestEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{
		"issuer_url": "https://original.com/realms/test",
		"client_id": "original",
		"required_role": "original"
	}`), 0644)

	os.Setenv("PAM_DEVICE_AUTH_ISSUER", "https://override.com/realms/prod")
	os.Setenv("PAM_DEVICE_AUTH_CLIENT_ID", "override-client")
	os.Setenv("PAM_DEVICE_AUTH_REQUIRED_ROLE", "override-role")
	os.Setenv("PAM_DEVICE_AUTH_TIMEOUT", "60")
	defer func() {
		os.Unsetenv("PAM_DEVICE_AUTH_ISSUER")
		os.Unsetenv("PAM_DEVICE_AUTH_CLIENT_ID")
		os.Unsetenv("PAM_DEVICE_AUTH_REQUIRED_ROLE")
		os.Unsetenv("PAM_DEVICE_AUTH_TIMEOUT")
	}()

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.IssuerURL != "https://override.com/realms/prod" {
		t.Errorf("IssuerURL = %q, want override", cfg.IssuerURL)
	}
	if cfg.ClientID != "override-client" {
		t.Errorf("ClientID = %q", cfg.ClientID)
	}
	if cfg.RequiredRole != "override-role" {
		t.Errorf("RequiredRole = %q", cfg.RequiredRole)
	}
	if cfg.AuthTimeout != 60 {
		t.Errorf("AuthTimeout = %d, want 60", cfg.AuthTimeout)
	}
}

func TestEnvOverrideRoleClaim(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{
		"issuer_url": "https://sso.example.com/realms/test",
		"client_id": "ssh-server",
		"required_role": "ssh-access"
	}`), 0644)

	os.Setenv("PAM_DEVICE_AUTH_ROLE_CLAIM", "realm_access.roles")
	defer os.Unsetenv("PAM_DEVICE_AUTH_ROLE_CLAIM")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.RoleClaim != "realm_access.roles" {
		t.Errorf("RoleClaim = %q, want realm_access.roles", cfg.RoleClaim)
	}
}

func TestDefaultSudoRoleAndAdminGroups(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.SudoRole != "" {
		t.Errorf("default SudoRole = %q, want empty", cfg.SudoRole)
	}
	if cfg.AdminGroups != nil {
		t.Errorf("default AdminGroups = %v, want nil", cfg.AdminGroups)
	}
}

func TestLoadSudoRoleAndAdminGroups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{
		"issuer_url": "https://sso.example.com/realms/test",
		"client_id": "ssh-server",
		"required_role": "ssh-access",
		"sudo_role": "ssh-admin",
		"admin_groups": ["sudo", "users"]
	}`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.SudoRole != "ssh-admin" {
		t.Errorf("SudoRole = %q, want ssh-admin", cfg.SudoRole)
	}
	if len(cfg.AdminGroups) != 2 || cfg.AdminGroups[0] != "sudo" || cfg.AdminGroups[1] != "users" {
		t.Errorf("AdminGroups = %v, want [sudo users]", cfg.AdminGroups)
	}
}

func TestEnvOverrideSudoRole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{
		"issuer_url": "https://sso.example.com/realms/test",
		"client_id": "ssh-server",
		"required_role": "ssh-access",
		"sudo_role": "original-role"
	}`), 0644)

	os.Setenv("PAM_DEVICE_AUTH_SUDO_ROLE", "override-admin")
	defer os.Unsetenv("PAM_DEVICE_AUTH_SUDO_ROLE")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.SudoRole != "override-admin" {
		t.Errorf("SudoRole = %q, want override-admin", cfg.SudoRole)
	}
}

func TestLoadIPClaim(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{
		"issuer_url": "https://sso.example.com/realms/test",
		"client_id": "ssh-server",
		"required_role": "ssh-access",
		"ip_claim": "clients"
	}`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.IPClaim != "clients" {
		t.Errorf("IPClaim = %q, want clients", cfg.IPClaim)
	}
}

func TestEnvOverrideIPClaim(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{
		"issuer_url": "https://sso.example.com/realms/test",
		"client_id": "ssh-server",
		"required_role": "ssh-access"
	}`), 0644)

	os.Setenv("PAM_DEVICE_AUTH_IP_CLAIM", "allowed_ips")
	defer os.Unsetenv("PAM_DEVICE_AUTH_IP_CLAIM")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.IPClaim != "allowed_ips" {
		t.Errorf("IPClaim = %q, want allowed_ips", cfg.IPClaim)
	}
}

func TestDefaultIPClaimEmpty(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.IPClaim != "" {
		t.Errorf("default IPClaim = %q, want empty", cfg.IPClaim)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.json")
	if err == nil {
		t.Error("Load() should fail for missing file")
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`not json`), 0644)

	_, err := Load(path)
	if err == nil {
		t.Error("Load() should fail for invalid JSON")
	}
}
