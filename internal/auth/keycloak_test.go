package auth

import (
	"testing"

	"keycloak-ssh-auth/internal/config"
	"keycloak-ssh-auth/internal/logger"
)

func testLogger() *logger.Logger {
	log, _ := logger.NewLogger("", true)
	return log
}

func testConfig() *config.Config {
	return &config.Config{
		KeycloakURL:  "https://sso.example.com",
		Realm:        "test-realm",
		ClientID:     "ssh-auth",
		ClientSecret: "secret",
		RequiredRole: "ssh-access",
		CallbackIP:   "127.0.0.1",
		CallbackPort: "33499",
		AuthTimeout:  60,
	}
}

func TestNewKeycloakAuth(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())
	if ka == nil {
		t.Fatal("NewKeycloakAuth returned nil")
	}
	if ka.config.ClientID != "ssh-auth" {
		t.Errorf("expected ClientID 'ssh-auth', got '%s'", ka.config.ClientID)
	}
}

func TestGetAuthURL(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	url, err := ka.GetAuthURL()
	if err != nil {
		t.Fatalf("GetAuthURL failed: %v", err)
	}

	// URL should contain expected components
	checks := []string{
		"sso.example.com",
		"test-realm",
		"client_id=ssh-auth",
		"response_type=code",
		"state=",
		"code_challenge=",
		"code_challenge_method=S256",
	}
	for _, check := range checks {
		if !containsString(url, check) {
			t.Errorf("auth URL missing '%s': %s", check, url)
		}
	}
}

func TestGetAuthURL_Idempotent(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	url1, _ := ka.GetAuthURL()
	url2, _ := ka.GetAuthURL()

	if url1 != url2 {
		t.Error("GetAuthURL should return same URL on repeated calls")
	}
}

func TestGenerateSecureString(t *testing.T) {
	s1 := generateSecureString(32)
	s2 := generateSecureString(32)

	if len(s1) != 32 {
		t.Errorf("expected length 32, got %d", len(s1))
	}
	if s1 == s2 {
		t.Error("two generated strings should not be equal")
	}
}

func TestGenerateShortCode(t *testing.T) {
	code := generateShortCode(8)
	if len(code) != 8 {
		t.Errorf("expected length 8, got %d", len(code))
	}
	// Should be uppercase hex
	for _, c := range code {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
			t.Errorf("unexpected character in code: %c", c)
		}
	}
}

func TestExtractRoles(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	claims := map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"ssh-access", "admin", "default-roles"},
		},
		"resource_access": map[string]interface{}{
			"ssh-auth": map[string]interface{}{
				"roles": []interface{}{"client-role"},
			},
		},
	}

	roles := ka.extractRoles(claims)

	expected := map[string]bool{"ssh-access": false, "admin": false, "default-roles": false, "client-role": false}
	for _, r := range roles {
		expected[r] = true
	}
	for role, found := range expected {
		if !found {
			t.Errorf("expected role '%s' not found in extracted roles", role)
		}
	}
}

func TestExtractRoles_Empty(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())
	roles := ka.extractRoles(map[string]interface{}{})
	if len(roles) != 0 {
		t.Errorf("expected empty roles, got %v", roles)
	}
}

func TestHasRequiredRole(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	if !ka.hasRequiredRole([]string{"admin", "ssh-access", "user"}) {
		t.Error("should find ssh-access in roles")
	}
	if ka.hasRequiredRole([]string{"admin", "user"}) {
		t.Error("should not find ssh-access in roles")
	}
	if ka.hasRequiredRole([]string{}) {
		t.Error("should not find role in empty list")
	}
}

func TestGetTokenClaims_ValidToken(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	// Build a fake JWT (header.payload.signature) with matching issuer
	// Payload: {"iss":"https://sso.example.com/realms/test-realm","preferred_username":"testuser","exp":9999999999,"azp":"ssh-auth"}
	payload := "eyJpc3MiOiJodHRwczovL3Nzby5leGFtcGxlLmNvbS9yZWFsbXMvdGVzdC1yZWFsbSIsInByZWZlcnJlZF91c2VybmFtZSI6InRlc3R1c2VyIiwiZXhwIjo5OTk5OTk5OTk5LCJhenAiOiJzc2gtYXV0aCJ9"
	fakeToken := map[string]interface{}{
		"access_token": "eyJhbGciOiJSUzI1NiJ9." + payload + ".fake-signature",
	}

	claims, ok := ka.getTokenClaims(fakeToken)
	if !ok {
		t.Fatal("getTokenClaims failed for valid token")
	}
	if claims["preferred_username"] != "testuser" {
		t.Errorf("expected username 'testuser', got '%v'", claims["preferred_username"])
	}
}

func TestGetTokenClaims_ExpiredToken(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	// Payload with exp in the past: {"iss":"https://sso.example.com/realms/test-realm","exp":1000000000,"azp":"ssh-auth"}
	payload := "eyJpc3MiOiJodHRwczovL3Nzby5leGFtcGxlLmNvbS9yZWFsbXMvdGVzdC1yZWFsbSIsImV4cCI6MTAwMDAwMDAwMCwiYXpwIjoic3NoLWF1dGgifQ"
	fakeToken := map[string]interface{}{
		"access_token": "eyJhbGciOiJSUzI1NiJ9." + payload + ".fake",
	}

	_, ok := ka.getTokenClaims(fakeToken)
	if ok {
		t.Error("getTokenClaims should fail for expired token")
	}
}

func TestGetTokenClaims_WrongIssuer(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	// Payload with wrong issuer: {"iss":"https://evil.com/realms/hack","exp":9999999999}
	payload := "eyJpc3MiOiJodHRwczovL2V2aWwuY29tL3JlYWxtcy9oYWNrIiwiZXhwIjo5OTk5OTk5OTk5fQ"
	fakeToken := map[string]interface{}{
		"access_token": "eyJhbGciOiJSUzI1NiJ9." + payload + ".fake",
	}

	_, ok := ka.getTokenClaims(fakeToken)
	if ok {
		t.Error("getTokenClaims should fail for wrong issuer")
	}
}

func TestGetTokenClaims_InvalidJWT(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	cases := []map[string]interface{}{
		{},                                    // no access_token
		{"access_token": "not-a-jwt"},         // invalid format
		{"access_token": "a.b"},               // only 2 parts
		{"access_token": "a.!!!invalid.c"},    // invalid base64
	}

	for i, token := range cases {
		_, ok := ka.getTokenClaims(token)
		if ok {
			t.Errorf("case %d: getTokenClaims should fail for invalid token", i)
		}
	}
}

// Helper
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
