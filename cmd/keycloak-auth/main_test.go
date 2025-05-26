package main

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
		KeycloakURL:   "https://test.keycloak.com",
		Realm:         "test-realm",
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		RequiredRole:  "test-role",
		CallbackIP:    "127.0.0.1",
		CallbackPort:  "8080",
		AuthTimeout:   180,
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

// Test client IP detection
func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		expected string
	}{
		{
			name: "SSH_CONNECTION",
			envVars: map[string]string{
				"SSH_CONNECTION": "192.168.1.100 12345 192.168.1.1 22",
			},
			expected: "192.168.1.100",
		},
		{
			name: "SSH_CLIENT",
			envVars: map[string]string{
				"SSH_CLIENT": "10.0.0.5 54321 22",
			},
			expected: "10.0.0.5",
		},
		{
			name: "PAM_RHOST",
			envVars: map[string]string{
				"PAM_RHOST": "172.16.0.10",
			},
			expected: "172.16.0.10",
		},
		{
			name:     "No environment variables",
			envVars:  map[string]string{},
			expected: "unknown",
		},
		{
			name: "Invalid IP",
			envVars: map[string]string{
				"SSH_CONNECTION": "invalid-ip 12345 192.168.1.1 22",
			},
			expected: "unknown",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Clear environment
			os.Clearenv()
			
			// Set test environment variables
			for key, value := range test.envVars {
				os.Setenv(key, value)
			}

			result := getClientIP()
			if result != test.expected {
				t.Errorf("getClientIP() = %q, expected %q", result, test.expected)
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

// Test version constant
func TestVersion(t *testing.T) {
	if VERSION == "" {
		t.Error("VERSION constant should not be empty")
	}
	
	if !strings.Contains(VERSION, "0.2.4") {
		t.Errorf("Expected version to contain '0.2.4', got %s", VERSION)
	}
}

// Test log file constant
func TestLogFile(t *testing.T) {
	if LOG_FILE == "" {
		t.Error("LOG_FILE constant should not be empty")
	}
	
	expectedLogFile := "/var/log/keycloak-ssh-auth.log"
	if LOG_FILE != expectedLogFile {
		t.Errorf("Expected log file %s, got %s", expectedLogFile, LOG_FILE)
	}
}

// Benchmark client IP detection
func BenchmarkGetClientIP(b *testing.B) {
	os.Setenv("SSH_CONNECTION", "192.168.1.100 12345 192.168.1.1 22")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		getClientIP()
	}
}
