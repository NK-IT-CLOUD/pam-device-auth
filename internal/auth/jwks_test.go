package auth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestJWKSCache_GetKey(t *testing.T) {
	kid := "jwks-test-1"
	server := startJWKSServer(kid)
	defer server.Close()

	cache := NewJWKSCache(server.URL, 1*time.Hour)
	key, err := cache.GetKey(kid)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	if key == nil {
		t.Fatal("key should not be nil")
	}
}

func TestJWKSCache_UnknownKid(t *testing.T) {
	server := startJWKSServer("known-kid")
	defer server.Close()

	cache := NewJWKSCache(server.URL, 1*time.Hour)
	_, err := cache.GetKey("unknown-kid")
	if err == nil {
		t.Error("should fail for unknown kid")
	}
}

func TestJWKSCache_ServerDown(t *testing.T) {
	cache := NewJWKSCache("http://127.0.0.1:1", 1*time.Hour)
	_, err := cache.GetKey("any")
	if err == nil {
		t.Error("should fail when JWKS server is unreachable")
	}
}

func TestJWKSCache_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	cache := NewJWKSCache(server.URL, 1*time.Hour)
	_, err := cache.GetKey("any")
	if err == nil {
		t.Error("should fail for invalid JSON response")
	}
}

func TestVerifyJWT_ValidSignature(t *testing.T) {
	kid := "verify-test-1"
	server := startJWKSServer(kid)
	defer server.Close()

	cache := NewJWKSCache(server.URL, 1*time.Hour)
	claims := map[string]interface{}{"sub": "testuser"}
	jwt := createSignedJWT(claims, kid)

	if err := VerifyJWT(jwt, cache); err != nil {
		t.Errorf("valid JWT verification failed: %v", err)
	}
}

func TestVerifyJWT_InvalidFormat(t *testing.T) {
	cache := NewJWKSCache("http://unused", 1*time.Hour)

	cases := []string{"", "a", "a.b", "a.b.c.d"}
	for _, jwt := range cases {
		if err := VerifyJWT(jwt, cache); err == nil {
			t.Errorf("should fail for '%s'", jwt)
		}
	}
}

func TestParseJWK_UnsupportedType(t *testing.T) {
	jwk := JWK{Kty: "oct", Kid: "test"}
	_, err := parseJWK(jwk)
	if err == nil {
		t.Error("should fail for unsupported key type")
	}
}

func TestParseECKey_UnsupportedCurve(t *testing.T) {
	jwk := JWK{Kty: "EC", Crv: "P-192", X: "AA", Y: "AA"}
	_, err := parseECKey(jwk)
	if err == nil {
		t.Error("should fail for unsupported curve")
	}
}

func TestVerifyJWT_MissingKid(t *testing.T) {
	headerMap := map[string]string{"alg": "RS256", "typ": "JWT"}
	headerBytes, _ := json.Marshal(headerMap)
	header := base64.RawURLEncoding.EncodeToString(headerBytes)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
	jwt := header + "." + payload + ".fakesig"

	cache := NewJWKSCache("http://unused", 1*time.Hour)
	if err := VerifyJWT(jwt, cache); err == nil {
		t.Error("should fail for missing kid")
	}
}
