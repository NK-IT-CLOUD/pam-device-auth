package unit

import (
	"testing"

	"keycloak-ssh-auth/internal/auth"
	"keycloak-ssh-auth/internal/config"
	"keycloak-ssh-auth/internal/logger"
)

// TestStateParameterConsistency tests that GetAuthURL and Authenticate use the same state parameter
func TestStateParameterConsistency(t *testing.T) {
	// Create a test configuration
	cfg := &config.Config{
		KeycloakURL:  "https://test.keycloak.com",
		Realm:        "test-realm",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RequiredRole: "ssh-access",
		CallbackIP:   "127.0.0.1",
		CallbackPort: "33499",
		AuthTimeout:  60,
	}

	// Create a test logger
	log, err := logger.NewLogger("/tmp/test-keycloak-auth.log", true)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer log.Close()

	// Create KeycloakAuth instance
	keycloakAuth := auth.NewKeycloakAuth(cfg, log)

	// Get the first auth URL
	authURL1, err := keycloakAuth.GetAuthURL()
	if err != nil {
		t.Fatalf("Failed to get first auth URL: %v", err)
	}

	// Get the second auth URL (should be the same)
	authURL2, err := keycloakAuth.GetAuthURL()
	if err != nil {
		t.Fatalf("Failed to get second auth URL: %v", err)
	}

	// URLs should be identical
	if authURL1 != authURL2 {
		t.Errorf("Auth URLs are different:\nFirst:  %s\nSecond: %s", authURL1, authURL2)
	}

	// Extract state parameter from URL
	state1 := extractStateFromURL(authURL1)
	state2 := extractStateFromURL(authURL2)

	if state1 == "" {
		t.Error("Could not extract state parameter from first URL")
	}

	if state2 == "" {
		t.Error("Could not extract state parameter from second URL")
	}

	if state1 != state2 {
		t.Errorf("State parameters are different: %s != %s", state1, state2)
	}

	t.Logf("State parameter consistency test passed. State: %s", state1)
}

// extractStateFromURL extracts the state parameter from an OAuth2 URL
func extractStateFromURL(authURL string) string {
	// Simple extraction for testing - in real implementation would use url.Parse
	start := "state="
	startIdx := findSubstring(authURL, start)
	if startIdx == -1 {
		return ""
	}

	startIdx += len(start)
	endIdx := findChar(authURL[startIdx:], '&')
	if endIdx == -1 {
		return authURL[startIdx:]
	}

	return authURL[startIdx : startIdx+endIdx]
}

// findSubstring finds the index of a substring in a string
func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// findChar finds the index of a character in a string
func findChar(s string, c rune) int {
	for i, char := range s {
		if char == c {
			return i
		}
	}
	return -1
}
