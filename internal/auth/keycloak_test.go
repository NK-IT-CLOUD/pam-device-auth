package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/config"
	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/logger"
)

var testRSAKey *rsa.PrivateKey

func init() {
	testRSAKey, _ = rsa.GenerateKey(rand.Reader, 2048)
}

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

// createSignedJWT builds a complete signed JWT from claims
func createSignedJWT(claims map[string]interface{}, kid string) string {
	headerMap := map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"}
	headerBytes, _ := json.Marshal(headerMap)
	header := base64.RawURLEncoding.EncodeToString(headerBytes)

	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signedContent := header + "." + payload
	h := sha256.Sum256([]byte(signedContent))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, testRSAKey, crypto.SHA256, h[:])
	return signedContent + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// startJWKSServer starts a mock JWKS endpoint
func startJWKSServer(kid string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(testRSAKey.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(testRSAKey.PublicKey.E)).Bytes())
		jwks := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"%s","use":"sig","alg":"RS256","n":"%s","e":"%s"}]}`, kid, n, e)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwks))
	}))
}

// testConfigWithJWKS creates a config pointing to a mock JWKS server, returns config + cleanup
func testKeycloakAuthWithJWKS(kid string) (*KeycloakAuth, *httptest.Server) {
	jwksServer := startJWKSServer(kid)
	cfg := testConfig()
	cfg.KeycloakURL = jwksServer.URL
	cfg.Realm = "test-realm"

	ka := &KeycloakAuth{
		config:    cfg,
		logger:    testLogger(),
		jwksCache: NewJWKSCache(jwksServer.URL+"/realms/test-realm/protocol/openid-connect/certs", 1*time.Hour),
	}
	// Override JWKS URL to point to our test server root
	ka.jwksCache.jwksURL = jwksServer.URL

	return ka, jwksServer
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
	kid := "test-key-1"
	ka, jwksServer := testKeycloakAuthWithJWKS(kid)
	defer jwksServer.Close()

	claims := map[string]interface{}{
		"iss":                jwksServer.URL + "/realms/test-realm",
		"preferred_username": "testuser",
		"exp":                float64(9999999999),
		"azp":                "ssh-auth",
	}
	jwt := createSignedJWT(claims, kid)
	token := map[string]interface{}{"access_token": jwt}

	// Update config to match issuer
	ka.config.KeycloakURL = jwksServer.URL

	result, ok := ka.getTokenClaims(token)
	if !ok {
		t.Fatal("getTokenClaims failed for valid signed token")
	}
	if result["preferred_username"] != "testuser" {
		t.Errorf("expected username 'testuser', got '%v'", result["preferred_username"])
	}
}

func TestGetTokenClaims_ExpiredToken(t *testing.T) {
	kid := "test-key-2"
	ka, jwksServer := testKeycloakAuthWithJWKS(kid)
	defer jwksServer.Close()

	claims := map[string]interface{}{
		"iss": jwksServer.URL + "/realms/test-realm",
		"exp": float64(1000000000), // expired
		"azp": "ssh-auth",
	}
	jwt := createSignedJWT(claims, kid)
	token := map[string]interface{}{"access_token": jwt}

	ka.config.KeycloakURL = jwksServer.URL

	_, ok := ka.getTokenClaims(token)
	if ok {
		t.Error("getTokenClaims should fail for expired token")
	}
}

func TestGetTokenClaims_WrongIssuer(t *testing.T) {
	kid := "test-key-3"
	ka, jwksServer := testKeycloakAuthWithJWKS(kid)
	defer jwksServer.Close()

	claims := map[string]interface{}{
		"iss": "https://evil.com/realms/hack",
		"exp": float64(9999999999),
	}
	jwt := createSignedJWT(claims, kid)
	token := map[string]interface{}{"access_token": jwt}

	ka.config.KeycloakURL = jwksServer.URL

	_, ok := ka.getTokenClaims(token)
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

func TestGetTokenClaims_TamperedPayload(t *testing.T) {
	kid := "test-key-4"
	ka, jwksServer := testKeycloakAuthWithJWKS(kid)
	defer jwksServer.Close()

	claims := map[string]interface{}{
		"iss":                jwksServer.URL + "/realms/test-realm",
		"preferred_username": "admin",
		"exp":                float64(9999999999),
		"azp":                "ssh-auth",
	}
	jwt := createSignedJWT(claims, kid)

	// Tamper with the payload (change username)
	parts := splitJWT(jwt)
	tamperedClaims := map[string]interface{}{
		"iss":                jwksServer.URL + "/realms/test-realm",
		"preferred_username": "evil-admin",
		"exp":                float64(9999999999),
		"azp":                "ssh-auth",
	}
	tamperedPayload, _ := json.Marshal(tamperedClaims)
	parts[1] = base64.RawURLEncoding.EncodeToString(tamperedPayload)
	tamperedJWT := parts[0] + "." + parts[1] + "." + parts[2]

	token := map[string]interface{}{"access_token": tamperedJWT}
	ka.config.KeycloakURL = jwksServer.URL

	_, ok := ka.getTokenClaims(token)
	if ok {
		t.Error("getTokenClaims should fail for tampered token")
	}
}

func splitJWT(jwt string) []string {
	parts := make([]string, 0, 3)
	start := 0
	for i := 0; i < len(jwt); i++ {
		if jwt[i] == '.' {
			parts = append(parts, jwt[start:i])
			start = i + 1
		}
	}
	parts = append(parts, jwt[start:])
	return parts
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
