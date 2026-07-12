package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.AuthTimeout != 180 {
		t.Errorf("default AuthTimeout = %d, want 180", cfg.AuthTimeout)
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
		"auth_timeout": 240
	}`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.AuthTimeout != 240 {
		t.Errorf("AuthTimeout = %d, want 240", cfg.AuthTimeout)
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

	base.AuthTimeout = 241
	if err := base.Validate(); err == nil {
		t.Error("timeout 241 should fail (above C wrapper 300s SIGKILL headroom)")
	}

	base.AuthTimeout = 30
	if err := base.Validate(); err != nil {
		t.Errorf("timeout 30 should pass: %v", err)
	}

	base.AuthTimeout = 240
	if err := base.Validate(); err != nil {
		t.Errorf("timeout 240 should pass: %v", err)
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

func TestDefaultSudoRole(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.SudoRole != "" {
		t.Errorf("default SudoRole = %q, want empty", cfg.SudoRole)
	}
}

func TestLoadSudoRole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{
		"issuer_url": "https://sso.example.com/realms/test",
		"client_id": "ssh-server",
		"required_role": "ssh-access",
		"sudo_role": "ssh-admin"
	}`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.SudoRole != "ssh-admin" {
		t.Errorf("SudoRole = %q, want ssh-admin", cfg.SudoRole)
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

func TestLoadAllowedAlgorithms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{
		"issuer_url": "https://sso.example.com/realms/test",
		"client_id": "ssh-server",
		"required_role": "ssh-access",
		"allowed_algorithms": ["RS256"]
	}`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(cfg.AllowedAlgorithms) != 1 || cfg.AllowedAlgorithms[0] != "RS256" {
		t.Errorf("AllowedAlgorithms = %v, want [RS256]", cfg.AllowedAlgorithms)
	}
}

func TestDefaultAllowedAlgorithmsNil(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.AllowedAlgorithms != nil {
		t.Errorf("default AllowedAlgorithms = %v, want nil (accept all)", cfg.AllowedAlgorithms)
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

// A non-numeric PAM_DEVICE_AUTH_TIMEOUT is an explicit operator override that
// cannot be honored — silently falling back to the JSON value would hide the
// misconfiguration. Load must fail closed.
func TestLoadRejectsNonNumericTimeoutEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{
		"issuer_url": "https://sso.example.com/realms/test",
		"client_id": "c",
		"required_role": "r"
	}`), 0644)

	os.Setenv("PAM_DEVICE_AUTH_TIMEOUT", "300s")
	defer os.Unsetenv("PAM_DEVICE_AUTH_TIMEOUT")

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() should fail for non-numeric PAM_DEVICE_AUTH_TIMEOUT")
	}
	if !strings.Contains(err.Error(), "PAM_DEVICE_AUTH_TIMEOUT") {
		t.Errorf("error should name the env var, got: %v", err)
	}
}

func TestValidateAllowsIPv6LoopbackHTTPIssuer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.IssuerURL = "http://[::1]:8080/realms/test"
	cfg.ClientID = "c"
	cfg.RequiredRole = "r"
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() should allow http://[::1] issuer for development: %v", err)
	}
}

func TestLDAPConfigParsesTierGroups(t *testing.T) {
	js := `{"issuer_url":"https://i","client_id":"c","ldap":{"uri":"ldaps://x","base_dn":"dc=x","bind_dn":"cn=x","bind_password":"p","access_group":"ssh-access","admin_group":"ssh-admin","service_account_groups":["ssh-service"],"nopasswd_sudo_groups":["ssh-admin-nopasswd"]}}`
	var c Config
	if err := json.Unmarshal([]byte(js), &c); err != nil {
		t.Fatal(err)
	}
	if len(c.LDAP.ServiceAccountGroups) != 1 || c.LDAP.ServiceAccountGroups[0] != "ssh-service" {
		t.Errorf("ServiceAccountGroups = %v", c.LDAP.ServiceAccountGroups)
	}
	if len(c.LDAP.NopasswdSudoGroups) != 1 || c.LDAP.NopasswdSudoGroups[0] != "ssh-admin-nopasswd" {
		t.Errorf("NopasswdSudoGroups = %v", c.LDAP.NopasswdSudoGroups)
	}
}
