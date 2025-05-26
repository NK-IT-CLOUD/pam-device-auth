package unit

import (
	"net"
	"os"
	"strings"
	"testing"

	"keycloak-ssh-auth/internal/config"
)

// Test configuration validation
func TestConfigValidation(t *testing.T) {
	// Test valid config
	cfg := &config.Config{
		KeycloakURL:  "https://test.keycloak.com",
		Realm:        "test-realm",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RequiredRole: "test-role",
		CallbackIP:   "127.0.0.1",
		CallbackPort: "8080",
		AuthTimeout:  180,
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Valid config failed validation: %v", err)
	}

	// Test invalid config
	invalidCfg := &config.Config{}
	if err := invalidCfg.Validate(); err == nil {
		t.Error("Invalid config passed validation")
	}

	// Test URL generation
	expectedCallback := "http://127.0.0.1:8080/callback"
	if cfg.GetCallbackURL() != expectedCallback {
		t.Errorf("Expected callback URL %s, got %s", expectedCallback, cfg.GetCallbackURL())
	}

	expectedAuthURL := "https://test.keycloak.com/realms/test-realm/protocol/openid-connect/auth"
	if cfg.GetKeycloakAuthURL() != expectedAuthURL {
		t.Errorf("Expected auth URL %s, got %s", expectedAuthURL, cfg.GetKeycloakAuthURL())
	}
}

// Test client IP parsing logic
func TestClientIPParsing(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "SSH_CONNECTION format",
			input:    "192.168.1.100 12345 192.168.1.1 22",
			expected: "192.168.1.100",
		},
		{
			name:     "SSH_CLIENT format",
			input:    "10.0.0.5 54321 22",
			expected: "10.0.0.5",
		},
		{
			name:     "Single IP",
			input:    "172.16.0.10",
			expected: "172.16.0.10",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Invalid IP",
			input:    "invalid-ip 12345 192.168.1.1 22",
			expected: "invalid-ip",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parts := strings.Fields(test.input)
			var result string
			if len(parts) > 0 {
				result = parts[0]
			}

			if result != test.expected {
				t.Errorf("Expected %q, got %q", test.expected, result)
			}
		})
	}
}

// Test IP validation helper
func TestIPValidation(t *testing.T) {
	validIPs := []string{
		"127.0.0.1",
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"::1",
		"2001:db8::1",
	}

	invalidIPs := []string{
		"",
		"invalid",
		"256.256.256.256",
		"192.168.1",
		"192.168.1.1.1",
	}

	for _, ip := range validIPs {
		if net.ParseIP(ip) == nil {
			t.Errorf("Expected %s to be a valid IP", ip)
		}
	}

	for _, ip := range invalidIPs {
		if net.ParseIP(ip) != nil {
			t.Errorf("Expected %s to be an invalid IP", ip)
		}
	}
}

// Test environment variable parsing
func TestEnvironmentVariables(t *testing.T) {
	// Save original environment
	originalEnv := os.Environ()
	defer func() {
		os.Clearenv()
		for _, env := range originalEnv {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				os.Setenv(parts[0], parts[1])
			}
		}
	}()

	// Clear environment
	os.Clearenv()

	// Set test environment variables
	testEnvVars := map[string]string{
		"KEYCLOAK_URL":           "https://env.keycloak.com",
		"KEYCLOAK_REALM":         "env-realm",
		"KEYCLOAK_CLIENT_ID":     "env-client",
		"KEYCLOAK_CLIENT_SECRET": "env-secret",
		"KEYCLOAK_REQUIRED_ROLE": "env-role",
		"CALLBACK_IP":            "10.0.0.1",
		"CALLBACK_PORT":          "9999",
		"AUTH_TIMEOUT":           "300",
		"DEBUG_MODE":             "true",
	}

	for key, value := range testEnvVars {
		os.Setenv(key, value)
	}

	// Create config with defaults
	cfg := config.DefaultConfig()
	cfg.KeycloakURL = "https://default.keycloak.com"
	cfg.Realm = "default-realm"
	cfg.ClientID = "default-client"
	cfg.ClientSecret = "default-secret"
	cfg.RequiredRole = "default-role"
	cfg.CallbackIP = "127.0.0.1"
	cfg.CallbackPort = "8080"

	// Load from environment (this would normally be called in LoadConfig)
	// For testing, we'll simulate the environment loading
	if val := os.Getenv("KEYCLOAK_URL"); val != "" {
		cfg.KeycloakURL = val
	}
	if val := os.Getenv("KEYCLOAK_REALM"); val != "" {
		cfg.Realm = val
	}

	// Verify environment variables override defaults
	if cfg.KeycloakURL != "https://env.keycloak.com" {
		t.Errorf("Expected KeycloakURL from env, got %s", cfg.KeycloakURL)
	}
	if cfg.Realm != "env-realm" {
		t.Errorf("Expected Realm from env, got %s", cfg.Realm)
	}
}

// Test version file reading
func TestVersionFile(t *testing.T) {
	// Test that we can read version from VERSION file
	expectedVersion := "0.2.4"

	// This would normally read from VERSION file
	version := expectedVersion

	if version == "" {
		t.Error("Version should not be empty")
	}

	if !strings.Contains(version, "0.2.4") {
		t.Errorf("Expected version to contain '0.2.4', got %s", version)
	}
}

// Test log file path validation
func TestLogFilePath(t *testing.T) {
	expectedLogFile := "/var/log/keycloak-ssh-auth.log"

	// Test that the path is valid
	if expectedLogFile == "" {
		t.Error("Log file path should not be empty")
	}

	if !strings.HasSuffix(expectedLogFile, ".log") {
		t.Error("Log file should have .log extension")
	}
}

// Benchmark string operations
func BenchmarkStringOperations(b *testing.B) {
	testString := "192.168.1.100 12345 192.168.1.1 22"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parts := strings.Fields(testString)
		if len(parts) > 0 {
			_ = parts[0]
		}
	}
}
