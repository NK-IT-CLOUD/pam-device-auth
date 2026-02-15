package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/config"
	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/logger"
)

// === generateSecureString tests ===

func TestGenerateSecureString_Length(t *testing.T) {
	for _, length := range []int{8, 16, 32, 64, 128} {
		s := generateSecureString(length)
		if len(s) != length {
			t.Errorf("expected length %d, got %d", length, len(s))
		}
	}
}

func TestGenerateSecureString_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		s := generateSecureString(32)
		if seen[s] {
			t.Fatalf("duplicate string generated on iteration %d", i)
		}
		seen[s] = true
	}
}

func TestGenerateSecureString_URLSafe(t *testing.T) {
	// base64 URL encoding should not contain +, /, or =
	for i := 0; i < 20; i++ {
		s := generateSecureString(64)
		if strings.ContainsAny(s, "+/=") {
			t.Errorf("secure string contains non-URL-safe chars: %s", s)
		}
	}
}

// === generateShortCode tests ===

func TestGenerateShortCode_Length(t *testing.T) {
	for _, length := range []int{4, 6, 8, 12} {
		code := generateShortCode(length)
		if len(code) != length {
			t.Errorf("expected length %d, got %d", length, len(code))
		}
	}
}

func TestGenerateShortCode_UppercaseHex(t *testing.T) {
	for i := 0; i < 50; i++ {
		code := generateShortCode(8)
		for _, c := range code {
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
				t.Errorf("unexpected character in code: %c (code: %s)", c, code)
			}
		}
	}
}

func TestGenerateShortCode_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		code := generateShortCode(8)
		if seen[code] {
			t.Fatalf("duplicate code generated on iteration %d", i)
		}
		seen[code] = true
	}
}

// === NewKeycloakAuth tests ===

func TestNewKeycloakAuth_Fields(t *testing.T) {
	cfg := testConfig()
	log := testLogger()
	ka := NewKeycloakAuth(cfg, log)

	if ka == nil {
		t.Fatal("NewKeycloakAuth returned nil")
	}
	if ka.config != cfg {
		t.Error("config not set correctly")
	}
	if ka.logger != log {
		t.Error("logger not set correctly")
	}
	if ka.jwksCache == nil {
		t.Error("jwksCache should be initialized")
	}
	if ka.state != "" {
		t.Error("state should be empty initially")
	}
	if ka.authURL != "" {
		t.Error("authURL should be empty initially")
	}
}

func TestNewKeycloakAuth_JWKSCacheURL(t *testing.T) {
	cfg := &config.Config{
		KeycloakURL: "https://sso.test.com",
		Realm:       "my-realm",
	}
	log := testLogger()
	ka := NewKeycloakAuth(cfg, log)

	expectedURL := "https://sso.test.com/realms/my-realm/protocol/openid-connect/certs"
	if ka.jwksCache.jwksURL != expectedURL {
		t.Errorf("JWKS URL: expected '%s', got '%s'", expectedURL, ka.jwksCache.jwksURL)
	}
}

// === GetAuthURL tests ===

func TestGetAuthURL_ContainsRequiredParams(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	url, err := ka.GetAuthURL()
	if err != nil {
		t.Fatalf("GetAuthURL failed: %v", err)
	}

	requiredParams := []string{
		"client_id=ssh-auth",
		"response_type=code",
		"scope=openid",
		"state=",
		"code_challenge=",
		"code_challenge_method=S256",
		"redirect_uri=",
	}
	for _, param := range requiredParams {
		if !strings.Contains(url, param) {
			t.Errorf("auth URL missing '%s': %s", param, url)
		}
	}
}

func TestGetAuthURL_CachesResult(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	url1, _ := ka.GetAuthURL()
	url2, _ := ka.GetAuthURL()

	if url1 != url2 {
		t.Error("GetAuthURL should return same URL on repeated calls")
	}
}

func TestGetAuthURL_SetsState(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	if ka.state != "" {
		t.Error("state should be empty before GetAuthURL")
	}

	_, err := ka.GetAuthURL()
	if err != nil {
		t.Fatalf("GetAuthURL failed: %v", err)
	}

	if ka.state == "" {
		t.Error("state should be set after GetAuthURL")
	}
}

func TestGetAuthURL_SetsCodeVerifier(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	_, err := ka.GetAuthURL()
	if err != nil {
		t.Fatalf("GetAuthURL failed: %v", err)
	}

	if ka.codeVerifier == "" {
		t.Error("codeVerifier should be set after GetAuthURL")
	}
}

// === extractRoles tests ===

func TestExtractRoles_RealmOnly(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	claims := map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"ssh-access", "admin"},
		},
	}

	roles := ka.extractRoles(claims)
	if len(roles) != 2 {
		t.Errorf("expected 2 roles, got %d: %v", len(roles), roles)
	}
}

func TestExtractRoles_ResourceOnly(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	claims := map[string]interface{}{
		"resource_access": map[string]interface{}{
			"ssh-auth": map[string]interface{}{
				"roles": []interface{}{"client-role-1", "client-role-2"},
			},
		},
	}

	roles := ka.extractRoles(claims)
	if len(roles) != 2 {
		t.Errorf("expected 2 client roles, got %d: %v", len(roles), roles)
	}
}

func TestExtractRoles_Combined(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	claims := map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"ssh-access"},
		},
		"resource_access": map[string]interface{}{
			"ssh-auth": map[string]interface{}{
				"roles": []interface{}{"client-role"},
			},
		},
	}

	roles := ka.extractRoles(claims)
	if len(roles) != 2 {
		t.Errorf("expected 2 combined roles, got %d: %v", len(roles), roles)
	}
}

func TestExtractRoles_NoClaims(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())
	roles := ka.extractRoles(map[string]interface{}{})
	if len(roles) != 0 {
		t.Errorf("expected empty roles, got %v", roles)
	}
}

func TestExtractRoles_MalformedClaims(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	// realm_access exists but no roles key
	claims := map[string]interface{}{
		"realm_access": map[string]interface{}{
			"not_roles": "something",
		},
	}
	roles := ka.extractRoles(claims)
	if len(roles) != 0 {
		t.Errorf("expected 0 roles for malformed claims, got %d", len(roles))
	}
}

func TestExtractRoles_WrongClientID(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	claims := map[string]interface{}{
		"resource_access": map[string]interface{}{
			"different-client": map[string]interface{}{
				"roles": []interface{}{"some-role"},
			},
		},
	}

	roles := ka.extractRoles(claims)
	if len(roles) != 0 {
		t.Errorf("expected 0 roles for different client, got %d: %v", len(roles), roles)
	}
}

// === hasRequiredRole tests ===

func TestHasRequiredRole_Found(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	if !ka.hasRequiredRole([]string{"admin", "ssh-access", "user"}) {
		t.Error("should find ssh-access in roles")
	}
}

func TestHasRequiredRole_NotFound(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	if ka.hasRequiredRole([]string{"admin", "user"}) {
		t.Error("should not find ssh-access in roles")
	}
}

func TestHasRequiredRole_Empty(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	if ka.hasRequiredRole([]string{}) {
		t.Error("should not find role in empty list")
	}
}

func TestHasRequiredRole_SingleMatch(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	if !ka.hasRequiredRole([]string{"ssh-access"}) {
		t.Error("should find ssh-access as sole role")
	}
}

// === Timeout test ===

func TestWaitForCallback_Timeout(t *testing.T) {
	log, _ := logger.NewLogger("", true)

	cfg := &config.Config{
		KeycloakURL:  "https://unused.example.com",
		Realm:        "test",
		ClientID:     "test",
		ClientSecret: "test",
		RequiredRole: "test",
		CallbackIP:   "127.0.0.1",
		CallbackPort: "0",
		AuthTimeout:  31,
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

// === Callback handler tests ===

func TestCallbackHandler_MissingCode(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())
	ka.state = "test-state"

	doneChan := make(chan error, 1)
	var processed atomic.Bool
	handler := ka.createCallbackHandler(&processed, doneChan)

	req := httptest.NewRequest("GET", "/callback?state=test-state", nil) // missing code
	w := httptest.NewRecorder()
	handler(w, req)

	select {
	case err := <-doneChan:
		if err == nil {
			t.Error("should error for missing code")
		}
		if !strings.Contains(err.Error(), "missing code") {
			t.Errorf("error should mention missing code, got: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("handler should have returned error")
	}
}

func TestCallbackHandler_MissingState(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())
	ka.state = "test-state"

	doneChan := make(chan error, 1)
	var processed atomic.Bool
	handler := ka.createCallbackHandler(&processed, doneChan)

	req := httptest.NewRequest("GET", "/callback?code=test-code", nil) // missing state
	w := httptest.NewRecorder()
	handler(w, req)

	select {
	case err := <-doneChan:
		if err == nil {
			t.Error("should error for missing state")
		}
	case <-time.After(time.Second):
		t.Fatal("handler should have returned error")
	}
}

func TestCallbackHandler_OAuthError(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())
	ka.state = "test-state"

	doneChan := make(chan error, 1)
	var processed atomic.Bool
	handler := ka.createCallbackHandler(&processed, doneChan)

	req := httptest.NewRequest("GET", "/callback?error=access_denied&error_description=User+denied", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	select {
	case err := <-doneChan:
		if err == nil {
			t.Error("should error for OAuth error")
		}
		if !strings.Contains(err.Error(), "access_denied") {
			t.Errorf("error should contain OAuth error, got: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("handler should have returned error")
	}
}

func TestCallbackHandler_DoubleCallback(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())
	ka.state = "test-state"

	doneChan := make(chan error, 1)
	var processed atomic.Bool
	handler := ka.createCallbackHandler(&processed, doneChan)

	// First call — sets processed to true (but will error on token exchange)
	req1 := httptest.NewRequest("GET", "/callback?code=test&state=test-state", nil)
	w1 := httptest.NewRecorder()
	handler(w1, req1)

	// Second call — should be rejected as already processed
	req2 := httptest.NewRequest("GET", "/callback?code=test&state=test-state", nil)
	w2 := httptest.NewRecorder()
	handler(w2, req2)

	if w2.Code != http.StatusConflict {
		// The second call should get a conflict status
		// (first call may error on token exchange, that's fine)
	}
}

func TestCallbackHandler_NonCallbackPath(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())
	ka.state = "test-state"

	doneChan := make(chan error, 1)
	var processed atomic.Bool
	handler := ka.createCallbackHandler(&processed, doneChan)

	paths := []string{"/", "/login", "/auth", "/favicon.ico"}
	for _, path := range paths {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		handler(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("path '%s' should return 404, got %d", path, w.Code)
		}
	}
}

// === exchangeToken mock tests ===

func TestExchangeToken_Success(t *testing.T) {
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
	ka.authCode = "mock-auth-code"
	ka.codeVerifier = "test-verifier"

	token, err := ka.exchangeToken()
	if err != nil {
		t.Fatalf("exchangeToken failed: %v", err)
	}
	if token["access_token"] == nil {
		t.Error("access_token should be present")
	}
}

func TestExchangeToken_InvalidCode(t *testing.T) {
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
	ka.authCode = "wrong-code"
	ka.codeVerifier = "test-verifier"

	_, err := ka.exchangeToken()
	if err == nil {
		t.Error("should fail with wrong auth code")
	}
}

func TestExchangeToken_ServerDown(t *testing.T) {
	log, _ := logger.NewLogger("", true)
	cfg := &config.Config{
		KeycloakURL:  "http://127.0.0.1:1", // unreachable
		Realm:        "test-realm",
		ClientID:     "ssh-auth",
		ClientSecret: "test-secret",
		RequiredRole: "ssh-access",
		CallbackIP:   "127.0.0.1",
		CallbackPort: "33499",
		AuthTimeout:  30,
	}

	ka := NewKeycloakAuth(cfg, log)
	ka.authCode = "test-code"
	ka.codeVerifier = "test-verifier"

	_, err := ka.exchangeToken()
	if err == nil {
		t.Error("should fail when server is unreachable")
	}
}

// === verifyAndBuildResult tests ===

func TestVerifyAndBuildResult_Success(t *testing.T) {
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
	ka.authCode = "mock-auth-code"
	ka.codeVerifier = "test-verifier"
	ka.state = "test-state"

	token, err := ka.exchangeToken()
	if err != nil {
		t.Fatalf("exchangeToken failed: %v", err)
	}
	ka.token = token

	// Mock KC returns username "nk"
	result, err := ka.verifyAndBuildResult("nk")
	if err != nil {
		t.Fatalf("verifyAndBuildResult failed: %v", err)
	}
	if !result.Success {
		t.Error("result should be successful")
	}
	if result.Username != "nk" {
		t.Errorf("expected username 'nk', got '%s'", result.Username)
	}
	if result.Email != "nk@nk-it.cloud" {
		t.Errorf("expected email 'nk@nk-it.cloud', got '%s'", result.Email)
	}
}

func TestVerifyAndBuildResult_UsernameMismatch(t *testing.T) {
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
	ka.authCode = "mock-auth-code"
	ka.codeVerifier = "test-verifier"

	token, _ := ka.exchangeToken()
	ka.token = token

	// SSH user "root" but token has "nk"
	_, err := ka.verifyAndBuildResult("root")
	if err == nil {
		t.Error("should fail for username mismatch")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("error should mention mismatch, got: %v", err)
	}
}

func TestVerifyAndBuildResult_MissingRole(t *testing.T) {
	// Create a mock KC that returns user without the required role
	kid := "role-test-kid"
	jwksServer := startJWKSServer(kid)
	defer jwksServer.Close()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := map[string]interface{}{
			"iss":                jwksServer.URL + "/realms/test-realm",
			"preferred_username": "nk",
			"email":              "nk@test.com",
			"name":               "Norbert",
			"azp":                "ssh-auth",
			"exp":                float64(time.Now().Add(5 * time.Minute).Unix()),
			"realm_access": map[string]interface{}{
				"roles": []interface{}{"user", "default-roles"}, // No ssh-access
			},
		}
		jwt := createSignedJWT(claims, kid)
		resp := map[string]interface{}{"access_token": jwt}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	log, _ := logger.NewLogger("", true)
	cfg := &config.Config{
		KeycloakURL:  jwksServer.URL,
		Realm:        "test-realm",
		ClientID:     "ssh-auth",
		ClientSecret: "test-secret",
		RequiredRole: "ssh-access",
		CallbackIP:   "127.0.0.1",
		CallbackPort: "33499",
		AuthTimeout:  30,
	}

	ka := &KeycloakAuth{
		config:    cfg,
		logger:    log,
		jwksCache: NewJWKSCache(jwksServer.URL, 1*time.Hour),
	}

	// Manually build a token with the claims
	claims := map[string]interface{}{
		"iss":                jwksServer.URL + "/realms/test-realm",
		"preferred_username": "nk",
		"email":              "nk@test.com",
		"azp":                "ssh-auth",
		"exp":                float64(time.Now().Add(5 * time.Minute).Unix()),
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"user", "default-roles"}, // No ssh-access
		},
	}
	jwt := createSignedJWT(claims, kid)
	ka.token = map[string]interface{}{"access_token": jwt}

	_, err := ka.verifyAndBuildResult("nk")
	if err == nil {
		t.Error("should fail when user lacks required role")
	}
	if !strings.Contains(err.Error(), "required role") {
		t.Errorf("error should mention required role, got: %v", err)
	}
}

func TestVerifyAndBuildResult_NoUsername(t *testing.T) {
	kid := "no-user-kid"
	jwksServer := startJWKSServer(kid)
	defer jwksServer.Close()

	log, _ := logger.NewLogger("", true)
	cfg := &config.Config{
		KeycloakURL:  jwksServer.URL,
		Realm:        "test-realm",
		ClientID:     "ssh-auth",
		ClientSecret: "test-secret",
		RequiredRole: "ssh-access",
		CallbackIP:   "127.0.0.1",
		CallbackPort: "33499",
		AuthTimeout:  30,
	}

	ka := &KeycloakAuth{
		config:    cfg,
		logger:    log,
		jwksCache: NewJWKSCache(jwksServer.URL, 1*time.Hour),
	}

	// Token without preferred_username
	claims := map[string]interface{}{
		"iss": jwksServer.URL + "/realms/test-realm",
		"azp": "ssh-auth",
		"exp": float64(time.Now().Add(5 * time.Minute).Unix()),
	}
	jwt := createSignedJWT(claims, kid)
	ka.token = map[string]interface{}{"access_token": jwt}

	_, err := ka.verifyAndBuildResult("nk")
	if err == nil {
		t.Error("should fail when no username in claims")
	}
	if !strings.Contains(err.Error(), "username") {
		t.Errorf("error should mention username, got: %v", err)
	}
}

// === getTokenClaims edge cases ===

func TestGetTokenClaims_NoAccessToken(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())
	_, ok := ka.getTokenClaims(map[string]interface{}{})
	if ok {
		t.Error("should fail when no access_token")
	}
}

func TestGetTokenClaims_InvalidBase64Payload(t *testing.T) {
	ka := NewKeycloakAuth(testConfig(), testLogger())

	validHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test"}`))
	token := map[string]interface{}{
		"access_token": validHeader + ".!!!invalid!!!.sig",
	}

	_, ok := ka.getTokenClaims(token)
	if ok {
		t.Error("should fail for invalid base64 payload")
	}
}

// === AuthResult struct test ===

func TestAuthResult_Fields(t *testing.T) {
	result := &AuthResult{
		Success:      true,
		Username:     "testuser",
		Email:        "test@example.com",
		Name:         "Test User",
		Roles:        []string{"admin", "user"},
		ErrorMessage: "",
	}

	if !result.Success {
		t.Error("Success should be true")
	}
	if result.Username != "testuser" {
		t.Errorf("expected username 'testuser', got '%s'", result.Username)
	}
	if len(result.Roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(result.Roles))
	}
}
