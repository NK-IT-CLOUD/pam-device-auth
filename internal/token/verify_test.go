package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func createRSATestJWT(t *testing.T, signingKey *rsa.PrivateKey, kid string, claims map[string]interface{}) string {
	t.Helper()

	return buildJWT(t, map[string]string{
		"alg": "RS256",
		"kid": kid,
		"typ": "JWT",
	}, claims, func(signedContent string) []byte {
		hashed := hashSignedContent(t, "RS256", signedContent)
		sig, err := rsa.SignPKCS1v15(rand.Reader, signingKey, crypto.SHA256, hashed)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	})
}

func createECDSATestJWT(t *testing.T, signingKey *ecdsa.PrivateKey, alg, kid string, claims map[string]interface{}) string {
	t.Helper()

	return buildJWT(t, map[string]string{
		"alg": alg,
		"kid": kid,
		"typ": "JWT",
	}, claims, func(signedContent string) []byte {
		hashed := hashSignedContent(t, alg, signedContent)
		partSize, err := ecdsaCoordinateSize(alg)
		if err != nil {
			t.Fatal(err)
		}

		r, s, err := ecdsa.Sign(rand.Reader, signingKey, hashed)
		if err != nil {
			t.Fatal(err)
		}

		sig := make([]byte, partSize*2)
		rBytes := r.Bytes()
		sBytes := s.Bytes()
		copy(sig[partSize-len(rBytes):partSize], rBytes)
		copy(sig[len(sig)-len(sBytes):], sBytes)
		return sig
	})
}

func createECDSAASN1JWT(t *testing.T, signingKey *ecdsa.PrivateKey, alg, kid string, claims map[string]interface{}) string {
	t.Helper()

	return buildJWT(t, map[string]string{
		"alg": alg,
		"kid": kid,
		"typ": "JWT",
	}, claims, func(signedContent string) []byte {
		hashed := hashSignedContent(t, alg, signedContent)
		sig, err := ecdsa.SignASN1(rand.Reader, signingKey, hashed)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	})
}

func buildJWT(t *testing.T, header map[string]string, claims map[string]interface{}, sign func(string) []byte) string {
	t.Helper()

	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signedContent := headerB64 + "." + claimsB64

	return signedContent + "." + base64.RawURLEncoding.EncodeToString(sign(signedContent))
}

func hashSignedContent(t *testing.T, alg, signedContent string) []byte {
	t.Helper()

	hashFunc, err := hashForAlgorithm(alg)
	if err != nil {
		t.Fatal(err)
	}

	h := hashFunc.New()
	if _, err := h.Write([]byte(signedContent)); err != nil {
		t.Fatal(err)
	}

	return h.Sum(nil)
}

func validClaims() map[string]interface{} {
	return map[string]interface{}{
		"iss":                "https://sso.example.com/realms/test",
		"exp":                float64(time.Now().Add(1 * time.Hour).Unix()),
		"azp":                "ssh-server",
		"preferred_username": "testuser",
	}
}

func TestValidate_Success(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"

	keys := map[string]crypto.PublicKey{
		kid: &privKey.PublicKey,
	}

	claims := validClaims()
	claims["nbf"] = float64(time.Now().Add(-1 * time.Minute).Unix())
	claims["email"] = "test@example.com"
	claims["name"] = "Test User"
	claims["realm_access"] = map[string]interface{}{
		"roles": []interface{}{"ssh-access"},
	}

	jwt := createRSATestJWT(t, privKey, kid, claims)

	result, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", "")
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

	claims := validClaims()
	claims["exp"] = float64(time.Now().Add(-1 * time.Hour).Unix())

	jwt := createRSATestJWT(t, privKey, kid, claims)
	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", "")
	if err == nil {
		t.Error("should fail for expired token")
	}
}

func TestValidate_WrongIssuer(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	claims := validClaims()
	claims["iss"] = "https://wrong-issuer.com"

	jwt := createRSATestJWT(t, privKey, kid, claims)
	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", "")
	if err == nil {
		t.Error("should fail for wrong issuer")
	}
}

func TestValidate_NBFInFuture(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	claims := validClaims()
	claims["nbf"] = float64(time.Now().Add(1 * time.Hour).Unix())

	jwt := createRSATestJWT(t, privKey, kid, claims)
	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", "")
	if err == nil {
		t.Error("should fail for nbf in future")
	}
}

func TestValidate_MissingUsername(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	claims := validClaims()
	delete(claims, "preferred_username")

	jwt := createRSATestJWT(t, privKey, kid, claims)
	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", "")
	if err == nil {
		t.Error("should fail for missing preferred_username")
	}
}

func TestValidate_UnknownKid(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keys := map[string]crypto.PublicKey{
		"other-key": &privKey.PublicKey,
	}

	jwt := createRSATestJWT(t, privKey, "wrong-kid", validClaims())
	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", "")
	if err == nil {
		t.Error("should fail for unknown kid")
	}
}

func TestValidate_WrongSignature(t *testing.T) {
	privKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
	privKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"

	keys := map[string]crypto.PublicKey{kid: &privKey1.PublicKey}
	jwt := createRSATestJWT(t, privKey2, kid, validClaims())

	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", "")
	if err == nil {
		t.Error("should fail for wrong signature")
	}
}

func TestValidate_InvalidJWTFormat(t *testing.T) {
	keys := map[string]crypto.PublicKey{}

	_, err := Validate("not.a.jwt.token.at.all", keys, "x", "x", "", "")
	if err == nil {
		t.Error("should fail for invalid JWT format")
	}

	_, err = Validate("only-one-part", keys, "x", "x", "", "")
	if err == nil {
		t.Error("should fail for single-part token")
	}
}

func TestValidate_AudienceFallback_String(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	claims := validClaims()
	delete(claims, "azp")
	claims["aud"] = "ssh-server"

	jwt := createRSATestJWT(t, privKey, kid, claims)
	if _, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", ""); err != nil {
		t.Fatalf("Validate() with string aud failed: %v", err)
	}
}

func TestValidate_AudienceFallback_Array(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	claims := validClaims()
	delete(claims, "azp")
	claims["aud"] = []interface{}{"account", "ssh-server"}

	jwt := createRSATestJWT(t, privKey, kid, claims)
	if _, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", ""); err != nil {
		t.Fatalf("Validate() with array aud failed: %v", err)
	}
}

func TestValidate_WrongAuthorizedParty(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	claims := validClaims()
	claims["azp"] = "other-client"
	claims["aud"] = []interface{}{"ssh-server"}

	jwt := createRSATestJWT(t, privKey, kid, claims)
	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", "")
	if err == nil {
		t.Error("should fail for wrong azp even when aud contains client")
	}
}

func TestValidate_WrongAudience(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	claims := validClaims()
	delete(claims, "azp")
	claims["aud"] = []interface{}{"account", "other-client"}

	jwt := createRSATestJWT(t, privKey, kid, claims)
	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", "")
	if err == nil {
		t.Error("should fail for wrong aud")
	}
}

func TestValidate_MissingClientBinding(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	claims := validClaims()
	delete(claims, "azp")

	jwt := createRSATestJWT(t, privKey, kid, claims)
	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", "")
	if err == nil {
		t.Error("should fail when azp and aud are missing")
	}
}

func TestValidate_ECDSAJWS(t *testing.T) {
	tests := []struct {
		name  string
		alg   string
		curve elliptic.Curve
	}{
		{name: "ES256", alg: "ES256", curve: elliptic.P256()},
		{name: "ES384", alg: "ES384", curve: elliptic.P384()},
		{name: "ES512", alg: "ES512", curve: elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privKey, _ := ecdsa.GenerateKey(tt.curve, rand.Reader)
			kid := "test-ec-key"
			keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

			claims := validClaims()
			claims["realm_access"] = map[string]interface{}{"roles": []interface{}{"ssh-access"}}

			jwt := createECDSATestJWT(t, privKey, tt.alg, kid, claims)

			result, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", "")
			if err != nil {
				t.Fatalf("Validate() error: %v", err)
			}
			if result.Username != "testuser" {
				t.Errorf("Username = %q", result.Username)
			}
		})
	}
}

func TestValidate_RejectsAlgorithmKeyMismatch_RSAKeyWithESAlg(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid := "test-key"
	keys := map[string]crypto.PublicKey{kid: &rsaKey.PublicKey}
	claims := validClaims()
	jwt := createECDSATestJWT(t, ecKey, "ES256", kid, claims)
	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", "")
	if err == nil {
		t.Error("should reject ES256 algorithm with RSA key")
	}
}

func TestValidate_RejectsAlgorithmKeyMismatch_ECKeyWithRSAlg(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid := "test-key"
	keys := map[string]crypto.PublicKey{kid: &ecKey.PublicKey}
	claims := validClaims()
	jwt := createRSATestJWT(t, rsaKey, kid, claims)
	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", "")
	if err == nil {
		t.Error("should reject RS256 algorithm with EC key")
	}
}

func TestValidate_RejectsUnsupportedAlgorithm(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key"
	keys := map[string]crypto.PublicKey{kid: &rsaKey.PublicKey}
	jwt := buildJWT(t, map[string]string{"alg": "none", "kid": kid}, validClaims(), func(signedContent string) []byte { return []byte{} })
	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", "")
	if err == nil {
		t.Error("should reject 'none' algorithm")
	}
}

func TestValidate_ExtractsIPClaim(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	claims := validClaims()
	claims["clients"] = []interface{}{"10.0.20.2", "10.0.99.202"}

	jwt := createRSATestJWT(t, privKey, kid, claims)
	result, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", "clients")
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if len(result.AllowedIPs) != 2 {
		t.Fatalf("AllowedIPs = %v, want 2 entries", result.AllowedIPs)
	}
	if result.AllowedIPs[0] != "10.0.20.2" {
		t.Errorf("AllowedIPs[0] = %q", result.AllowedIPs[0])
	}
}

func TestValidate_NoIPClaimConfigured(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	claims := validClaims()
	claims["clients"] = []interface{}{"10.0.20.2"}

	jwt := createRSATestJWT(t, privKey, kid, claims)
	result, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", "")
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if result.AllowedIPs != nil {
		t.Errorf("AllowedIPs should be nil when ipClaim is empty, got %v", result.AllowedIPs)
	}
}

func TestValidate_IPClaimMissingInToken(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	jwt := createRSATestJWT(t, privKey, kid, validClaims())
	result, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", "clients")
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if result.AllowedIPs != nil {
		t.Errorf("AllowedIPs should be nil when claim missing from token, got %v", result.AllowedIPs)
	}
}

func TestValidate_RejectsEmptyKidInJWTHeader(t *testing.T) {
	// Even when JWKS has a key under "" (which we also reject at fetch time),
	// a JWT whose header kid is empty must fail before any key lookup.
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keys := map[string]crypto.PublicKey{
		"":         &privKey.PublicKey, // defensively: should never be in the map
		"valid-id": &privKey.PublicKey,
	}

	jwt := createRSATestJWT(t, privKey, "", validClaims())
	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", "")
	if err == nil {
		t.Fatal("should reject JWT with empty kid header")
	}
	if !strings.Contains(err.Error(), "kid") {
		t.Errorf("error should mention kid, got: %v", err)
	}
}

func TestValidate_IssuedAtInFutureRejected(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	claims := validClaims()
	// iat 5 min in the future — outside our 60s skew tolerance
	claims["iat"] = float64(time.Now().Add(5 * time.Minute).Unix())

	jwt := createRSATestJWT(t, privKey, kid, claims)
	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", "")
	if err == nil {
		t.Error("should reject token with iat too far in the future")
	}
}

func TestValidate_IssuedAtWithinSkewAccepted(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	claims := validClaims()
	// iat 30s in the future — within skew tolerance
	claims["iat"] = float64(time.Now().Add(30 * time.Second).Unix())

	jwt := createRSATestJWT(t, privKey, kid, claims)
	if _, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", ""); err != nil {
		t.Fatalf("token with iat within skew should be accepted: %v", err)
	}
}

func TestValidate_ECDSARejectsASN1JWTSignature(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid := "test-ec-key"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	jwt := createECDSAASN1JWT(t, privKey, "ES256", kid, validClaims())
	_, err := Validate(jwt, keys, "https://sso.example.com/realms/test", "ssh-server", "", "")
	if err == nil {
		t.Error("ASN.1 ECDSA signature should not be accepted as a JWS signature")
	}
}
