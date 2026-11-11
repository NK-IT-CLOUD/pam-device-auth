package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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

// ip_claim was removed in 0.5.7 (the OIDC-token IP check is retired; the
// `clients` allowlist is enforced solely in the PAM account phase). A config
// that still carries the obsolete field must load without error: the field is
// silently ignored, so existing deployments do not break on upgrade.
func TestLoadToleratesObsoleteIPClaim(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{
		"issuer_url": "https://sso.example.com/realms/test",
		"client_id": "ssh-server",
		"required_role": "ssh-access",
		"ip_claim": "clients"
	}`), 0644)

	if _, err := Load(path); err != nil {
		t.Fatalf("Load() with obsolete ip_claim should succeed, got error: %v", err)
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

func TestLoad_NewFieldsParse(t *testing.T) {
	path := writeConfig(t, `{
  "issuer_url": "https://sso.example.com/realms/r", "client_id": "ssh-server", "required_role": "ssh-access",
  "required_acr": ["3"], "root_login_sources": ["192.0.2.10", "2001:db8::1"],
  "ldap": {"profile": "ad", "uri": "ldaps://dc1.example.com", "ca_file": "/etc/ssl/ad-ca.pem",
    "bind_password_file": "/etc/pam-device-auth/ldap.secret",
    "attributes": {"username": "sAMAccountName", "ssh_key": "sshPublicKey", "clients": "extensionAttribute1"},
    "id_mapping": true, "id_range": {"min": 10000, "max": 60000}, "home": "/home/%u", "shell": "/bin/bash",
    "kerberos": {"realm": "EXAMPLE.COM", "kdc": "dc1.example.com", "kpasswd": "dc1.example.com", "keytab": "/etc/krb5.sssd.keytab"}}
}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.RequiredACR; len(got) != 1 || got[0] != "3" {
		t.Errorf("RequiredACR = %v", got)
	}
	if got := cfg.RootLoginSources; len(got) != 2 {
		t.Errorf("RootLoginSources = %v", got)
	}
	l := cfg.LDAP
	if l.Profile != LDAPProfileAD || l.CAFile != "/etc/ssl/ad-ca.pem" || l.BindPasswordFile == "" {
		t.Errorf("ldap basics = %+v", l)
	}
	if l.Attributes.Clients != "extensionAttribute1" || l.IDMapping == nil || !*l.IDMapping || l.IDRange.Max != 60000 {
		t.Errorf("ldap ad fields = %+v", l)
	}
	if l.Kerberos == nil || l.Kerberos.Realm != "EXAMPLE.COM" || l.Kerberos.Keytab != "/etc/krb5.sssd.keytab" {
		t.Errorf("kerberos = %+v", l.Kerberos)
	}
}

func TestValidate_RequiredACR(t *testing.T) {
	for _, c := range []struct {
		name string
		acr  []string
		ok   bool
	}{
		{"absent", nil, true},
		{"numeric level", []string{"3"}, true},
		{"several names", []string{"gold", "platinum"}, true},
		{"empty entry", []string{""}, false},
		{"whitespace", []string{"3 "}, false},
		{"control character", []string{"3\n"}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := validBase()
			cfg.RequiredACR = c.acr
			if err := cfg.Validate(); (err == nil) != c.ok {
				t.Fatalf("Validate() err = %v, want ok=%v", err, c.ok)
			}
		})
	}
}

func TestValidate_RootLoginSources(t *testing.T) {
	for _, c := range []struct {
		name    string
		sources []string
		ok      bool
	}{
		{"absent", nil, true},
		{"ipv4 and ipv6", []string{"192.0.2.10", "2001:db8::1"}, true},
		{"cidr rejected", []string{"192.0.2.0/24"}, false},
		{"host name rejected", []string{"admin.example.com"}, false},
		{"empty rejected", []string{""}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := validBase()
			cfg.RootLoginSources = c.sources
			if err := cfg.Validate(); (err == nil) != c.ok {
				t.Fatalf("Validate() err = %v, want ok=%v", err, c.ok)
			}
		})
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

// loadString loads a config from a JSON string through Load.
func loadString(t *testing.T, body string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

const supportedList = "RS256, RS384, RS512, ES256, ES384, ES512"

// A misspelled key must not switch a protection off without a word: every
// key the loader does not know is reported with its path. Keys match without
// regard to case, as encoding/json reads them, and keys of earlier versions
// stay silent.
func TestLoad_UnknownKeys(t *testing.T) {
	cfg, err := loadString(t, `{
		"Issuer_URL": "https://sso.example.com/realms/test",
		"client_id": "ssh-server",
		"required_role": "ssh-access",
		"requried_acr": ["gold"],
		"create_user": true, "directory_mode": true, "ip_claim": "ips",
		"ldap": {
			"profile": "lldap", "uri": "ldaps://ldap.example.com:636",
			"acess_group": "ssh-access",
			"kerberos": {"realm": "EXAMPLE.COM", "kdc": "kdc.example.com", "relm": "X"},
			"attributes": {"ssh_key": "sshPublicKey", "sshkey": "x"},
			"id_range": {"min": 1000, "max": 2000, "maximum": 3}
		}
	}`)
	if err != nil {
		t.Fatalf("Load() error: %v (unknown keys must never fail a load)", err)
	}
	if cfg.IssuerURL != "https://sso.example.com/realms/test" {
		t.Errorf("IssuerURL = %q: the key Issuer_URL must be read as issuer_url", cfg.IssuerURL)
	}
	want := []string{
		`unknown key "ldap.acess_group" is ignored`,
		`unknown key "ldap.attributes.sshkey" is ignored`,
		`unknown key "ldap.id_range.maximum" is ignored`,
		`unknown key "ldap.kerberos.relm" is ignored`,
		`unknown key "requried_acr" is ignored`,
	}
	if got := cfg.Warnings(); !reflect.DeepEqual(got, want) {
		t.Errorf("Warnings() = %q\nwant %q", got, want)
	}
}

func TestLoad_UnsupportedAlgorithm(t *testing.T) {
	cfg, err := loadString(t, `{
		"issuer_url": "https://sso.example.com/realms/test", "client_id": "ssh-server",
		"required_role": "ssh-access", "allowed_algorithms": ["RS256", "rs256", "none"]
	}`)
	if err != nil {
		t.Fatalf("Load() error: %v (one supported entry is enough to load)", err)
	}
	want := []string{
		`allowed_algorithms: "rs256" is not supported (supported: ` + supportedList + `)`,
		`allowed_algorithms: "none" is not supported (supported: ` + supportedList + `)`,
	}
	if got := cfg.Warnings(); !reflect.DeepEqual(got, want) {
		t.Errorf("Warnings() = %q\nwant %q", got, want)
	}
}

// With no supported entry no token can ever validate: that is a config error.
func TestLoad_NoSupportedAlgorithm(t *testing.T) {
	_, err := loadString(t, `{
		"issuer_url": "https://sso.example.com/realms/test", "client_id": "ssh-server",
		"required_role": "ssh-access", "allowed_algorithms": ["rs256"]
	}`)
	want := "allowed_algorithms has no supported entry (supported: " + supportedList + ")"
	if err == nil || err.Error() != want {
		t.Fatalf("Load() error = %v, want %q", err, want)
	}
}

func TestLoad_CleanConfigHasNoWarnings(t *testing.T) {
	cfg, err := loadString(t, `{
		"issuer_url": "https://sso.example.com/realms/test", "client_id": "ssh-server",
		"required_role": "ssh-access", "allowed_algorithms": ["ES256"], "ldap": null
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if w := cfg.Warnings(); len(w) != 0 {
		t.Errorf("Warnings() = %q, want none", w)
	}
}
