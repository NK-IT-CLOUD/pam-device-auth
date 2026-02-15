package config

import (
	"os"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.AuthTimeout != 180 {
		t.Errorf("expected AuthTimeout 180, got %d", cfg.AuthTimeout)
	}
	if !cfg.CreateUsers {
		t.Error("expected CreateUsers true by default")
	}
	if !cfg.AddToSudo {
		t.Error("expected AddToSudo true by default")
	}
}

func TestValidate_Valid(t *testing.T) {
	cfg := &Config{
		KeycloakURL:  "https://sso.example.com",
		Realm:        "test",
		ClientID:     "client",
		ClientSecret: "secret",
		RequiredRole: "ssh-access",
		CallbackIP:   "10.0.0.1",
		CallbackPort: "33499",
		AuthTimeout:  180,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid config should pass: %v", err)
	}
}

func TestValidate_MissingFields(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"no url", Config{Realm: "r", ClientID: "c", ClientSecret: "s", RequiredRole: "r", CallbackIP: "1.1.1.1", CallbackPort: "80", AuthTimeout: 60}},
		{"no realm", Config{KeycloakURL: "https://x", ClientID: "c", ClientSecret: "s", RequiredRole: "r", CallbackIP: "1.1.1.1", CallbackPort: "80", AuthTimeout: 60}},
		{"no client_id", Config{KeycloakURL: "https://x", Realm: "r", ClientSecret: "s", RequiredRole: "r", CallbackIP: "1.1.1.1", CallbackPort: "80", AuthTimeout: 60}},
		{"no secret", Config{KeycloakURL: "https://x", Realm: "r", ClientID: "c", RequiredRole: "r", CallbackIP: "1.1.1.1", CallbackPort: "80", AuthTimeout: 60}},
		{"no role", Config{KeycloakURL: "https://x", Realm: "r", ClientID: "c", ClientSecret: "s", CallbackIP: "1.1.1.1", CallbackPort: "80", AuthTimeout: 60}},
	}
	for _, tc := range cases {
		if err := tc.cfg.Validate(); err == nil {
			t.Errorf("%s: expected validation error", tc.name)
		}
	}
}

func TestValidate_InvalidPort(t *testing.T) {
	cfg := &Config{
		KeycloakURL: "https://x", Realm: "r", ClientID: "c", ClientSecret: "s",
		RequiredRole: "r", CallbackIP: "1.1.1.1", CallbackPort: "99999", AuthTimeout: 60,
	}
	if err := cfg.Validate(); err == nil {
		t.Error("should fail for invalid port")
	}
}

func TestValidate_InvalidTimeout(t *testing.T) {
	cfg := &Config{
		KeycloakURL: "https://x", Realm: "r", ClientID: "c", ClientSecret: "s",
		RequiredRole: "r", CallbackIP: "1.1.1.1", CallbackPort: "8080", AuthTimeout: 10,
	}
	if err := cfg.Validate(); err == nil {
		t.Error("should fail for timeout < 30")
	}
}

func TestGetCallbackURL(t *testing.T) {
	cfg := &Config{CallbackIP: "10.0.88.70", CallbackPort: "33499"}
	expected := "http://10.0.88.70:33499/callback"
	if got := cfg.GetCallbackURL(); got != expected {
		t.Errorf("expected '%s', got '%s'", expected, got)
	}
}

func TestGetKeycloakAuthURL(t *testing.T) {
	cfg := &Config{KeycloakURL: "https://sso.nk-it.cloud", Realm: "nk-it.cloud"}
	expected := "https://sso.nk-it.cloud/realms/nk-it.cloud/protocol/openid-connect/auth"
	if got := cfg.GetKeycloakAuthURL(); got != expected {
		t.Errorf("expected '%s', got '%s'", expected, got)
	}
}

func TestGetKeycloakTokenURL(t *testing.T) {
	cfg := &Config{KeycloakURL: "https://sso.nk-it.cloud", Realm: "nk-it.cloud"}
	expected := "https://sso.nk-it.cloud/realms/nk-it.cloud/protocol/openid-connect/token"
	if got := cfg.GetKeycloakTokenURL(); got != expected {
		t.Errorf("expected '%s', got '%s'", expected, got)
	}
}

func TestLoadFromEnvironment(t *testing.T) {
	cfg := DefaultConfig()
	cfg.KeycloakURL = "default"

	os.Setenv("KEYCLOAK_URL", "https://env.example.com")
	defer os.Unsetenv("KEYCLOAK_URL")

	cfg.loadFromEnvironment()

	if cfg.KeycloakURL != "https://env.example.com" {
		t.Errorf("env override failed, got '%s'", cfg.KeycloakURL)
	}
}

func TestString_NoSecrets(t *testing.T) {
	cfg := &Config{
		KeycloakURL:  "https://sso.example.com",
		Realm:        "test",
		ClientID:     "client",
		ClientSecret: "super-secret-value",
		RequiredRole: "ssh-access",
		CallbackIP:   "10.0.0.1",
		CallbackPort: "33499",
	}
	s := cfg.String()
	if containsString(s, "super-secret-value") {
		t.Error("String() should not contain client secret")
	}
	if !containsString(s, "sso.example.com") {
		t.Error("String() should contain Keycloak URL")
	}
}

func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
