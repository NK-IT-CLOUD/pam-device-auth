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
}

func TestLoadValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{
		"keycloak_url": "https://sso.example.com",
		"realm": "test",
		"client_id": "ssh-server",
		"required_role": "ssh-access"
	}`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.KeycloakURL != "https://sso.example.com" {
		t.Errorf("KeycloakURL = %q", cfg.KeycloakURL)
	}
	if cfg.Realm != "test" {
		t.Errorf("Realm = %q", cfg.Realm)
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
		"keycloak_url": "https://sso.example.com",
		"realm": "test",
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

func TestValidateMissingFields(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"missing keycloak_url", Config{Realm: "r", ClientID: "c", RequiredRole: "r", AuthTimeout: 180}},
		{"missing realm", Config{KeycloakURL: "https://x", ClientID: "c", RequiredRole: "r", AuthTimeout: 180}},
		{"missing client_id", Config{KeycloakURL: "https://x", Realm: "r", RequiredRole: "r", AuthTimeout: 180}},
		{"missing required_role", Config{KeycloakURL: "https://x", Realm: "r", ClientID: "c", AuthTimeout: 180}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.Validate(); err == nil {
				t.Error("Validate() should have returned error")
			}
		})
	}
}

func TestValidateTimeoutRange(t *testing.T) {
	base := Config{
		KeycloakURL:  "https://sso.example.com",
		Realm:        "test",
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
		"keycloak_url": "https://original.com",
		"realm": "original",
		"client_id": "original",
		"required_role": "original"
	}`), 0644)

	os.Setenv("KEYCLOAK_URL", "https://override.com")
	os.Setenv("KEYCLOAK_REALM", "override-realm")
	os.Setenv("KEYCLOAK_CLIENT_ID", "override-client")
	os.Setenv("KEYCLOAK_REQUIRED_ROLE", "override-role")
	os.Setenv("KEYCLOAK_AUTH_TIMEOUT", "60")
	defer func() {
		os.Unsetenv("KEYCLOAK_URL")
		os.Unsetenv("KEYCLOAK_REALM")
		os.Unsetenv("KEYCLOAK_CLIENT_ID")
		os.Unsetenv("KEYCLOAK_REQUIRED_ROLE")
		os.Unsetenv("KEYCLOAK_AUTH_TIMEOUT")
	}()

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.KeycloakURL != "https://override.com" {
		t.Errorf("KeycloakURL = %q, want override", cfg.KeycloakURL)
	}
	if cfg.Realm != "override-realm" {
		t.Errorf("Realm = %q", cfg.Realm)
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
