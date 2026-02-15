package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/config"
	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/logger"
)

// mockKeycloak simulates a full Keycloak server for integration tests
type mockKeycloak struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey
	kid        string
	realm      string
	clientID   string
}

func newMockKeycloak(realm, clientID string) *mockKeycloak {
	mk := &mockKeycloak{
		privateKey: testRSAKey,
		kid:        "mock-kid-1",
		realm:      realm,
		clientID:   clientID,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/realms/"+realm+"/protocol/openid-connect/certs", mk.handleJWKS)
	mux.HandleFunc("/realms/"+realm+"/protocol/openid-connect/token", mk.handleToken)
	mux.HandleFunc("/realms/"+realm+"/protocol/openid-connect/auth", mk.handleAuth)

	mk.server = httptest.NewServer(mux)
	return mk
}

func (mk *mockKeycloak) Close() {
	mk.server.Close()
}

func (mk *mockKeycloak) URL() string {
	return mk.server.URL
}

func (mk *mockKeycloak) handleJWKS(w http.ResponseWriter, r *http.Request) {
	n := base64.RawURLEncoding.EncodeToString(mk.privateKey.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(mk.privateKey.PublicKey.E)).Bytes())
	jwks := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"%s","use":"sig","alg":"RS256","n":"%s","e":"%s"}]}`,
		mk.kid, n, e)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(jwks))
}

func (mk *mockKeycloak) handleAuth(w http.ResponseWriter, r *http.Request) {
	// Simulate redirect back to callback with auth code
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	if redirectURI == "" || state == "" {
		http.Error(w, "missing params", http.StatusBadRequest)
		return
	}
	// In real flow, user would authenticate here
	http.Redirect(w, r, fmt.Sprintf("%s?code=mock-auth-code&state=%s", redirectURI, state), http.StatusFound)
}

func (mk *mockKeycloak) handleToken(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	values, _ := url.ParseQuery(string(body))

	grantType := values.Get("grant_type")
	if grantType != "authorization_code" {
		http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
		return
	}

	code := values.Get("code")
	if code != "mock-auth-code" {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}

	// Create a signed JWT
	claims := map[string]interface{}{
		"iss":                mk.server.URL + "/realms/" + mk.realm,
		"sub":                "user-uuid-123",
		"preferred_username": "nk",
		"email":              "nk@nk-it.cloud",
		"name":               "Norbert",
		"azp":                mk.clientID,
		"exp":                float64(time.Now().Add(5 * time.Minute).Unix()),
		"iat":                float64(time.Now().Unix()),
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"ssh-access", "default-roles"},
		},
	}

	jwt := mk.signJWT(claims)

	tokenResp := map[string]interface{}{
		"access_token":  jwt,
		"token_type":    "Bearer",
		"expires_in":    300,
		"refresh_token": "mock-refresh-token",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResp)
}

func (mk *mockKeycloak) signJWT(claims map[string]interface{}) string {
	headerMap := map[string]string{"alg": "RS256", "kid": mk.kid, "typ": "JWT"}
	headerBytes, _ := json.Marshal(headerMap)
	header := base64.RawURLEncoding.EncodeToString(headerBytes)

	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signedContent := header + "." + payload
	h := sha256.Sum256([]byte(signedContent))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, mk.privateKey, crypto.SHA256, h[:])
	return signedContent + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// TestFullAuthFlowWithMockKeycloak tests the complete OAuth2 flow
func TestFullAuthFlowWithMockKeycloak(t *testing.T) {
	mockKC := newMockKeycloak("test-realm", "ssh-auth")
	defer mockKC.Close()

	log, _ := logger.NewLogger("", true)

	cfg := &config.Config{
		KeycloakURL:  mockKC.URL(),
		Realm:        "test-realm",
		ClientID:     "ssh-auth",
		ClientSecret: "test-secret",
		RequiredRole: "ssh-access",
		CallbackIP:   "127.0.0.1",
		CallbackPort: "0", // Will pick random port
		AuthTimeout:  30,
		CreateUsers:  false,
		AddToSudo:    false,
	}

	ka := NewKeycloakAuth(cfg, log)

	// Get auth URL
	authURL, err := ka.GetAuthURL()
	if err != nil {
		t.Fatalf("GetAuthURL failed: %v", err)
	}

	if !strings.Contains(authURL, mockKC.URL()) {
		t.Errorf("auth URL should contain mock KC URL: %s", authURL)
	}
	if !strings.Contains(authURL, "code_challenge_method=S256") {
		t.Error("auth URL should contain PKCE S256")
	}

	t.Logf("Auth URL generated: %s", authURL[:80]+"...")
}

// TestTokenExchangeWithMockKeycloak tests the token exchange step
func TestTokenExchangeWithMockKeycloak(t *testing.T) {
	mockKC := newMockKeycloak("test-realm", "ssh-auth")
	defer mockKC.Close()

	log, _ := logger.NewLogger("", true)

	cfg := &config.Config{
		KeycloakURL:  mockKC.URL(),
		Realm:        "test-realm",
		ClientID:     "ssh-auth",
		ClientSecret: "test-secret",
		RequiredRole: "ssh-access",
		CallbackIP:   "127.0.0.1",
		CallbackPort: "33499",
		AuthTimeout:  30,
	}

	ka := NewKeycloakAuth(cfg, log)
	ka.codeVerifier = "test-verifier"
	ka.state = "test-state"
	ka.authCode = "mock-auth-code"

	token, err := ka.exchangeToken()
	if err != nil {
		t.Fatalf("Token exchange failed: %v", err)
	}

	if token["access_token"] == nil {
		t.Fatal("No access_token in response")
	}

	// Verify claims
	claims, ok := ka.getTokenClaims(token)
	if !ok {
		t.Fatal("Failed to extract verified claims")
	}

	if claims["preferred_username"] != "nk" {
		t.Errorf("expected username 'nk', got '%v'", claims["preferred_username"])
	}
	if claims["email"] != "nk@nk-it.cloud" {
		t.Errorf("expected email 'nk@nk-it.cloud', got '%v'", claims["email"])
	}

	// Verify roles
	roles := ka.extractRoles(claims)
	if !ka.hasRequiredRole(roles) {
		t.Errorf("user should have ssh-access role, got: %v", roles)
	}
}

// TestTokenExchangeInvalidCode tests rejection of invalid auth codes
func TestTokenExchangeInvalidCode(t *testing.T) {
	mockKC := newMockKeycloak("test-realm", "ssh-auth")
	defer mockKC.Close()

	log, _ := logger.NewLogger("", true)

	cfg := &config.Config{
		KeycloakURL:  mockKC.URL(),
		Realm:        "test-realm",
		ClientID:     "ssh-auth",
		ClientSecret: "test-secret",
		RequiredRole: "ssh-access",
		CallbackIP:   "127.0.0.1",
		CallbackPort: "33499",
		AuthTimeout:  30,
	}

	ka := NewKeycloakAuth(cfg, log)
	ka.codeVerifier = "test-verifier"
	ka.authCode = "wrong-code"

	_, err := ka.exchangeToken()
	if err == nil {
		t.Error("should fail with invalid auth code")
	}
}

// TestCallbackHandlerStateMismatch tests CSRF protection
func TestCallbackHandlerStateMismatch(t *testing.T) {
	mockKC := newMockKeycloak("test-realm", "ssh-auth")
	defer mockKC.Close()

	log, _ := logger.NewLogger("", true)

	cfg := &config.Config{
		KeycloakURL:  mockKC.URL(),
		Realm:        "test-realm",
		ClientID:     "ssh-auth",
		ClientSecret: "test-secret",
		RequiredRole: "ssh-access",
		CallbackIP:   "127.0.0.1",
		CallbackPort: "0",
		AuthTimeout:  5,
	}

	ka := NewKeycloakAuth(cfg, log)
	ka.state = "correct-state"
	ka.codeVerifier = "test-verifier"

	// Simulate callback with wrong state
	doneChan := make(chan error, 1)
	var processed atomic.Bool
	handler := ka.createCallbackHandler(&processed, doneChan)

	// Create request with mismatched state
	req := httptest.NewRequest("GET", "/callback?code=test&state=wrong-state", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	select {
	case err := <-doneChan:
		if err == nil {
			t.Error("should return error for state mismatch")
		}
		if !strings.Contains(err.Error(), "invalid state") {
			t.Errorf("error should mention invalid state, got: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("handler should have returned error")
	}
}

// TestCallbackHandlerNonCallbackPath tests that non-callback paths are rejected
func TestCallbackHandlerNonCallbackPath(t *testing.T) {
	log, _ := logger.NewLogger("", true)
	cfg := testConfig()
	ka := NewKeycloakAuth(cfg, log)
	ka.state = "test-state"

	doneChan := make(chan error, 1)
	var processed atomic.Bool
	handler := ka.createCallbackHandler(&processed, doneChan)

	req := httptest.NewRequest("GET", "/not-callback", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// TestAuthenticateUsernameMismatch tests that username verification works
func TestAuthenticateUsernameMismatch(t *testing.T) {
	mockKC := newMockKeycloak("test-realm", "ssh-auth")
	defer mockKC.Close()

	log, _ := logger.NewLogger("", true)

	cfg := &config.Config{
		KeycloakURL:  mockKC.URL(),
		Realm:        "test-realm",
		ClientID:     "ssh-auth",
		ClientSecret: "test-secret",
		RequiredRole: "ssh-access",
		CallbackIP:   "127.0.0.1",
		CallbackPort: "33499",
		AuthTimeout:  30,
	}

	ka := NewKeycloakAuth(cfg, log)
	ka.codeVerifier = "test-verifier"
	ka.state = "test-state"
	ka.authCode = "mock-auth-code"

	token, err := ka.exchangeToken()
	if err != nil {
		t.Fatalf("Token exchange failed: %v", err)
	}
	ka.token = token

	// verifyAndBuildResult should fail because mock KC returns username "nk"
	// but we're requesting SSH user "root"
	result, err := ka.verifyAndBuildResult("root")
	if err == nil {
		t.Error("should fail for username mismatch")
	}
	if result != nil && result.Success {
		t.Error("result should not be successful")
	}
	if err != nil && !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("error should mention mismatch, got: %v", err)
	}
}

// TestAuthenticateTimeout verifies timeout handling
func TestAuthenticateTimeout(t *testing.T) {
	log, _ := logger.NewLogger("", true)

	cfg := &config.Config{
		KeycloakURL:  "https://unused.example.com",
		Realm:        "test",
		ClientID:     "test",
		ClientSecret: "test",
		RequiredRole: "test",
		CallbackIP:   "127.0.0.1",
		CallbackPort: "0",
		AuthTimeout:  31, // minimum valid
	}

	ka := NewKeycloakAuth(cfg, log)
	ka.state = "test"
	ka.codeVerifier = "test"

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err := ka.waitForCallback(ctx)
	if err == nil {
		t.Error("should timeout")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("error should mention timeout, got: %v", err)
	}
}

// (uses sync/atomic.Bool from stdlib)
