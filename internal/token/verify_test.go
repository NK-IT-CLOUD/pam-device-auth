package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// Helper: create a signed JWT with RSA
func createTestJWT(t *testing.T, privKey *rsa.PublicKey, signingKey *rsa.PrivateKey, kid string, claims map[string]interface{}) string {
	t.Helper()

	header := map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signedContent := headerB64 + "." + claimsB64
	h := sha256.Sum256([]byte(signedContent))
	sig, err := rsa.SignPKCS1v15(rand.Reader, signingKey, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}

	return signedContent + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestValidate_Success(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"

	keys := map[string]crypto.PublicKey{
		kid: &privKey.PublicKey,
	}

	claims := map[string]interface{}{
		"iss":                "https://sso.example.com/realms/test",
		"exp":                float64(time.Now().Add(1 * time.Hour).Unix()),
		"nbf":                float64(time.Now().Add(-1 * time.Minute).Unix()),
		"azp":                "ssh-server",
		"preferred_username": "testuser",
		"email":              "test@example.com",
		"name":               "Test User",
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"ssh-access"},
		},
	}

	jwt := createTestJWT(t, &privKey.PublicKey, privKey, kid, claims)

	result, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server")
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}

	if result.Username != "testuser" {
		t.Errorf("Username = %q", result.Username)
	}
	if result.Email != "test@example.com" {
		t.Errorf("Email = %q", result.Email)
	}
	if result.Name != "Test User" {
		t.Errorf("Name = %q", result.Name)
	}
	if !HasRole(result.Roles, "ssh-access") {
		t.Errorf("Roles = %v, missing ssh-access", result.Roles)
	}
}

func TestValidate_ExpiredToken(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	claims := map[string]interface{}{
		"iss":                "https://sso.example.com/realms/test",
		"exp":                float64(time.Now().Add(-1 * time.Hour).Unix()),
		"preferred_username": "testuser",
	}

	jwt := createTestJWT(t, &privKey.PublicKey, privKey, kid, claims)
	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server")
	if err == nil {
		t.Error("should fail for expired token")
	}
}

func TestValidate_WrongIssuer(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	claims := map[string]interface{}{
		"iss":                "https://wrong-issuer.com",
		"exp":                float64(time.Now().Add(1 * time.Hour).Unix()),
		"preferred_username": "testuser",
	}

	jwt := createTestJWT(t, &privKey.PublicKey, privKey, kid, claims)
	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server")
	if err == nil {
		t.Error("should fail for wrong issuer")
	}
}

func TestValidate_NBFInFuture(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	claims := map[string]interface{}{
		"iss":                "https://sso.example.com/realms/test",
		"exp":                float64(time.Now().Add(1 * time.Hour).Unix()),
		"nbf":                float64(time.Now().Add(1 * time.Hour).Unix()),
		"preferred_username": "testuser",
	}

	jwt := createTestJWT(t, &privKey.PublicKey, privKey, kid, claims)
	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server")
	if err == nil {
		t.Error("should fail for nbf in future")
	}
}

func TestValidate_MissingUsername(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	claims := map[string]interface{}{
		"iss": "https://sso.example.com/realms/test",
		"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	jwt := createTestJWT(t, &privKey.PublicKey, privKey, kid, claims)
	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server")
	if err == nil {
		t.Error("should fail for missing preferred_username")
	}
}

func TestValidate_UnknownKid(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keys := map[string]crypto.PublicKey{
		"other-key": &privKey.PublicKey,
	}

	claims := map[string]interface{}{
		"iss":                "https://sso.example.com/realms/test",
		"exp":                float64(time.Now().Add(1 * time.Hour).Unix()),
		"preferred_username": "testuser",
	}

	jwt := createTestJWT(t, &privKey.PublicKey, privKey, "wrong-kid", claims)
	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server")
	if err == nil {
		t.Error("should fail for unknown kid")
	}
}

func TestValidate_WrongSignature(t *testing.T) {
	privKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
	privKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"

	keys := map[string]crypto.PublicKey{kid: &privKey1.PublicKey}

	claims := map[string]interface{}{
		"iss":                "https://sso.example.com/realms/test",
		"exp":                float64(time.Now().Add(1 * time.Hour).Unix()),
		"preferred_username": "testuser",
	}

	jwt := createTestJWT(t, &privKey2.PublicKey, privKey2, kid, claims)
	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server")
	if err == nil {
		t.Error("should fail for wrong signature")
	}
}

func TestValidate_InvalidJWTFormat(t *testing.T) {
	keys := map[string]crypto.PublicKey{}

	_, err := Validate("not.a.jwt.token.at.all", keys, "x", "x")
	if err == nil {
		t.Error("should fail for invalid JWT format")
	}

	_, err = Validate("only-one-part", keys, "x", "x")
	if err == nil {
		t.Error("should fail for single-part token")
	}
}

func TestValidate_ECDSA(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid := "test-ec-key"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	claims := map[string]interface{}{
		"iss":                "https://sso.example.com/realms/test",
		"exp":                float64(time.Now().Add(1 * time.Hour).Unix()),
		"preferred_username": "testuser",
		"realm_access":       map[string]interface{}{"roles": []interface{}{"ssh-access"}},
	}

	header := map[string]string{"alg": "ES256", "kid": kid, "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signedContent := headerB64 + "." + claimsB64
	h := sha256.Sum256([]byte(signedContent))
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, h[:])
	if err != nil {
		t.Fatal(err)
	}
	jwt := signedContent + "." + base64.RawURLEncoding.EncodeToString(sig)

	result, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server")
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if result.Username != "testuser" {
		t.Errorf("Username = %q", result.Username)
	}
}
