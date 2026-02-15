package config

import (
	"encoding/json"
	"os"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.AuthTimeout != 180 {
		t.Errorf("expected AuthTimeout 180, got %d", cfg.AuthTimeout)
	}
	if cfg.DebugMode {
		t.Error("expected DebugMode false by default")
	}
	if !cfg.CreateUsers {
		t.Error("expected CreateUsers true by default")
	}
	if !cfg.AddToSudo {
		t.Error("expected AddToSudo true by default")
	}
}

func validConfig() *Config {
	return &Config{
		KeycloakURL:  "https://sso.example.com",
		Realm:        "test",
		ClientID:     "client",
		ClientSecret: "secret",
		RequiredRole: "ssh-access",
		CallbackIP:   "10.0.0.1",
		CallbackPort: "33499",
		AuthTimeout:  180,
	}
}

func TestValidate_Valid(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid config should pass: %v", err)
	}
}

func TestValidate_MissingFields(t *testing.T) {
	cases := []struct {
		name   string
		modify func(*Config)
	}{
		{"no url", func(c *Config) { c.KeycloakURL = "" }},
		{"no realm", func(c *Config) { c.Realm = "" }},
		{"no client_id", func(c *Config) { c.ClientID = "" }},
		{"no secret", func(c *Config) { c.ClientSecret = "" }},
		{"no role", func(c *Config) { c.RequiredRole = "" }},
		{"no callback_ip", func(c *Config) { c.CallbackIP = "" }},
		{"no callback_port", func(c *Config) { c.CallbackPort = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.modify(cfg)
			if err := cfg.Validate(); err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestValidate_InvalidPort(t *testing.T) {
	cases := []struct {
		name string
		port string
	}{
		{"too high", "99999"},
		{"zero", "0"},
		{"negative", "-1"},
		{"not a number", "abc"},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.CallbackPort = tc.port
			if err := cfg.Validate(); err == nil {
				t.Errorf("should fail for port '%s'", tc.port)
			}
		})
	}
}

func TestValidate_ValidPorts(t *testing.T) {
	for _, port := range []string{"1", "80", "443", "8080", "33499", "65535"} {
		cfg := validConfig()
		cfg.CallbackPort = port
		if err := cfg.Validate(); err != nil {
			t.Errorf("port '%s' should be valid: %v", port, err)
		}
	}
}

func TestValidate_InvalidTimeout(t *testing.T) {
	cases := []struct {
		name    string
		timeout int
	}{
		{"too low", 10},
		{"zero", 0},
		{"negative", -1},
		{"just under minimum", 29},
		{"too high", 601},
		{"way too high", 9999},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.AuthTimeout = tc.timeout
			if err := cfg.Validate(); err == nil {
				t.Errorf("should fail for timeout %d", tc.timeout)
			}
		})
	}
}

func TestValidate_ValidTimeouts(t *testing.T) {
	for _, timeout := range []int{30, 60, 180, 300, 600} {
		cfg := validConfig()
		cfg.AuthTimeout = timeout
		if err := cfg.Validate(); err != nil {
			t.Errorf("timeout %d should be valid: %v", timeout, err)
		}
	}
}

func TestGetCallbackURL(t *testing.T) {
	cfg := &Config{CallbackIP: "10.0.88.70", CallbackPort: "33499"}
	expected := "http://10.0.88.70:33499/callback"
	if got := cfg.GetCallbackURL(); got != expected {
		t.Errorf("expected '%s', got '%s'", expected, got)
	}
}

func TestGetCallbackURL_Localhost(t *testing.T) {
	cfg := &Config{CallbackIP: "127.0.0.1", CallbackPort: "8080"}
	expected := "http://127.0.0.1:8080/callback"
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

func TestGetKeycloakURLs_DifferentRealms(t *testing.T) {
	cases := []struct {
		url      string
		realm    string
		authURL  string
		tokenURL string
	}{
		{
			"https://sso.example.com", "master",
			"https://sso.example.com/realms/master/protocol/openid-connect/auth",
			"https://sso.example.com/realms/master/protocol/openid-connect/token",
		},
		{
			"http://localhost:8080", "test-realm",
			"http://localhost:8080/realms/test-realm/protocol/openid-connect/auth",
			"http://localhost:8080/realms/test-realm/protocol/openid-connect/token",
		},
	}
	for _, tc := range cases {
		cfg := &Config{KeycloakURL: tc.url, Realm: tc.realm}
		if got := cfg.GetKeycloakAuthURL(); got != tc.authURL {
			t.Errorf("auth URL: expected '%s', got '%s'", tc.authURL, got)
		}
		if got := cfg.GetKeycloakTokenURL(); got != tc.tokenURL {
			t.Errorf("token URL: expected '%s', got '%s'", tc.tokenURL, got)
		}
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

func TestLoadFromEnvironment_AllVars(t *testing.T) {
	cfg := DefaultConfig()

	envVars := map[string]string{
		"KEYCLOAK_URL":           "https://env-sso.test.com",
		"KEYCLOAK_REALM":        "env-realm",
		"KEYCLOAK_CLIENT_ID":    "env-client",
		"KEYCLOAK_CLIENT_SECRET": "env-secret",
		"KEYCLOAK_REQUIRED_ROLE": "env-role",
		"CALLBACK_IP":           "10.10.10.10",
		"CALLBACK_PORT":         "12345",
		"AUTH_TIMEOUT":          "120",
		"DEBUG_MODE":            "true",
		"CREATE_USERS":          "false",
		"ADD_TO_SUDO":           "false",
	}

	for k, v := range envVars {
		os.Setenv(k, v)
		defer os.Unsetenv(k)
	}

	cfg.loadFromEnvironment()

	if cfg.KeycloakURL != "https://env-sso.test.com" {
		t.Errorf("KeycloakURL: expected 'https://env-sso.test.com', got '%s'", cfg.KeycloakURL)
	}
	if cfg.Realm != "env-realm" {
		t.Errorf("Realm: expected 'env-realm', got '%s'", cfg.Realm)
	}
	if cfg.ClientID != "env-client" {
		t.Errorf("ClientID: expected 'env-client', got '%s'", cfg.ClientID)
	}
	if cfg.ClientSecret != "env-secret" {
		t.Errorf("ClientSecret: expected 'env-secret', got '%s'", cfg.ClientSecret)
	}
	if cfg.RequiredRole != "env-role" {
		t.Errorf("RequiredRole: expected 'env-role', got '%s'", cfg.RequiredRole)
	}
	if cfg.CallbackIP != "10.10.10.10" {
		t.Errorf("CallbackIP: expected '10.10.10.10', got '%s'", cfg.CallbackIP)
	}
	if cfg.CallbackPort != "12345" {
		t.Errorf("CallbackPort: expected '12345', got '%s'", cfg.CallbackPort)
	}
	if cfg.AuthTimeout != 120 {
		t.Errorf("AuthTimeout: expected 120, got %d", cfg.AuthTimeout)
	}
	if !cfg.DebugMode {
		t.Error("DebugMode should be true")
	}
	if cfg.CreateUsers {
		t.Error("CreateUsers should be false")
	}
	if cfg.AddToSudo {
		t.Error("AddToSudo should be false")
	}
}

func TestLoadFromEnvironment_InvalidTimeout(t *testing.T) {
	cfg := DefaultConfig()
	originalTimeout := cfg.AuthTimeout

	os.Setenv("AUTH_TIMEOUT", "not-a-number")
	defer os.Unsetenv("AUTH_TIMEOUT")

	cfg.loadFromEnvironment()

	if cfg.AuthTimeout != originalTimeout {
		t.Errorf("invalid timeout should not change value, got %d", cfg.AuthTimeout)
	}
}

func TestLoadFromEnvironment_BooleanParsing(t *testing.T) {
	cases := []struct {
		value    string
		expected bool
	}{
		{"true", true},
		{"True", true},
		{"TRUE", true},
		{"false", false},
		{"anything", false},
		{"", false},
	}

	for _, tc := range cases {
		cfg := DefaultConfig()
		os.Setenv("DEBUG_MODE", tc.value)
		cfg.loadFromEnvironment()
		os.Unsetenv("DEBUG_MODE")

		if cfg.DebugMode != tc.expected {
			t.Errorf("DEBUG_MODE='%s': expected %v, got %v", tc.value, tc.expected, cfg.DebugMode)
		}
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
	if !containsString(s, "test") {
		t.Error("String() should contain realm")
	}
	if !containsString(s, "client") {
		t.Error("String() should contain client ID")
	}
	if !containsString(s, "ssh-access") {
		t.Error("String() should contain required role")
	}
	if !containsString(s, "10.0.0.1") {
		t.Error("String() should contain callback IP")
	}
	if !containsString(s, "33499") {
		t.Error("String() should contain callback port")
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.json")
	if err == nil {
		t.Error("LoadConfig should fail for nonexistent file")
	}
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	tmpFile := "/tmp/test-ksa-invalid-config.json"
	defer os.Remove(tmpFile)

	err := os.WriteFile(tmpFile, []byte("not json"), 0644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err = LoadConfig(tmpFile)
	if err == nil {
		t.Error("LoadConfig should fail for invalid JSON")
	}
}

func TestLoadConfig_ValidFile(t *testing.T) {
	tmpFile := "/tmp/test-ksa-valid-config.json"
	defer os.Remove(tmpFile)

	cfg := validConfig()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	err = os.WriteFile(tmpFile, data, 0644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	loaded, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if loaded.KeycloakURL != cfg.KeycloakURL {
		t.Errorf("KeycloakURL: expected '%s', got '%s'", cfg.KeycloakURL, loaded.KeycloakURL)
	}
	if loaded.Realm != cfg.Realm {
		t.Errorf("Realm: expected '%s', got '%s'", cfg.Realm, loaded.Realm)
	}
	if loaded.ClientID != cfg.ClientID {
		t.Errorf("ClientID: expected '%s', got '%s'", cfg.ClientID, loaded.ClientID)
	}
}

func TestLoadConfig_MergesDefaults(t *testing.T) {
	tmpFile := "/tmp/test-ksa-defaults-config.json"
	defer os.Remove(tmpFile)

	// Write a config without optional fields
	partial := map[string]interface{}{
		"keycloak_url":  "https://sso.test.com",
		"realm":         "test",
		"client_id":     "client",
		"client_secret": "secret",
		"required_role": "role",
		"callback_ip":   "127.0.0.1",
		"callback_port": "8080",
	}
	data, _ := json.Marshal(partial)
	os.WriteFile(tmpFile, data, 0644)

	loaded, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Should have defaults for optional fields
	if loaded.AuthTimeout != 180 {
		t.Errorf("AuthTimeout should default to 180, got %d", loaded.AuthTimeout)
	}
	if !loaded.CreateUsers {
		t.Error("CreateUsers should default to true")
	}
	if !loaded.AddToSudo {
		t.Error("AddToSudo should default to true")
	}
}

func TestLoadConfig_ValidationFails(t *testing.T) {
	tmpFile := "/tmp/test-ksa-invalid-vals-config.json"
	defer os.Remove(tmpFile)

	// Valid JSON but invalid config (missing required fields)
	cfg := map[string]interface{}{
		"keycloak_url": "https://sso.test.com",
		// Missing other required fields
	}
	data, _ := json.Marshal(cfg)
	os.WriteFile(tmpFile, data, 0644)

	_, err := LoadConfig(tmpFile)
	if err == nil {
		t.Error("LoadConfig should fail validation for incomplete config")
	}
}

func TestLoadConfig_EnvOverrides(t *testing.T) {
	tmpFile := "/tmp/test-ksa-env-override-config.json"
	defer os.Remove(tmpFile)

	cfg := validConfig()
	data, _ := json.Marshal(cfg)
	os.WriteFile(tmpFile, data, 0644)

	// Override a value via env
	os.Setenv("KEYCLOAK_URL", "https://env-override.test.com")
	defer os.Unsetenv("KEYCLOAK_URL")

	loaded, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if loaded.KeycloakURL != "https://env-override.test.com" {
		t.Errorf("env should override file value, got '%s'", loaded.KeycloakURL)
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
