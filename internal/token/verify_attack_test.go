package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

const attackIssuer = "https://sso.example.com/realms/test"

func TestValidate_AlgNoneVariantsRejected(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key"
	keys := map[string]crypto.PublicKey{kid: &rsaKey.PublicKey}

	for _, alg := range []string{"none", "None", "NONE", ""} {
		for _, allowed := range [][]string{nil, {"none"}, {"RS256"}} {
			jwt := buildJWT(t, map[string]string{"alg": alg, "kid": kid}, validClaims(), func(string) []byte { return nil })
			// The unsigned form ends in a trailing dot with an empty signature.
			if !strings.HasSuffix(jwt, ".") {
				t.Fatalf("expected empty signature segment, got %q", jwt)
			}
			if _, err := Validate(jwt, keys, attackIssuer, "ssh-server", "", allowed); err == nil {
				t.Errorf("alg %q with allowedAlgs %v must be rejected", alg, allowed)
			}
		}
	}
}

// hmacJWT signs with HS256 using secret as the HMAC key.
func hmacJWT(t *testing.T, kid string, secret []byte, claims map[string]interface{}) string {
	t.Helper()
	return buildJWT(t, map[string]string{"alg": "HS256", "kid": kid}, claims, func(signed string) []byte {
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(signed))
		return m.Sum(nil)
	})
}

func TestValidate_HS256WithPublicKeyAsSecretRejected(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]crypto.PublicKey{"rsa": &rsaKey.PublicKey, "ec": &ecKey.PublicKey}

	for _, c := range []struct {
		kid    string
		secret []byte
	}{
		{"rsa", rsaDER},
		{"rsa", x509PEMLike(rsaDER)},
		{"ec", ecDER},
		{"ec", x509PEMLike(ecDER)},
	} {
		jwt := hmacJWT(t, c.kid, c.secret, validClaims())
		for _, allowed := range [][]string{nil, {"HS256"}} {
			if _, err := Validate(jwt, keys, attackIssuer, "ssh-server", "", allowed); err == nil {
				t.Errorf("HS256 token forged with %s public key bytes must be rejected (allowed=%v)", c.kid, allowed)
			}
		}
	}
}

// x509PEMLike returns a PEM-ish byte form some attackers use as HMAC secret.
func x509PEMLike(der []byte) []byte {
	return []byte("-----BEGIN PUBLIC KEY-----\n" + string(der) + "\n-----END PUBLIC KEY-----\n")
}

func TestValidate_MissingExpRejected(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	claims := validClaims()
	delete(claims, "exp")
	jwt := createRSATestJWT(t, privKey, kid, claims)
	_, err := Validate(jwt, keys, attackIssuer, "ssh-server", "", nil)
	if err == nil {
		t.Fatal("should reject token with no exp claim")
	}
	if !strings.Contains(err.Error(), "exp") {
		t.Errorf("error should mention exp, got: %v", err)
	}

	// A non-numeric exp must not be accepted as "no expiry" either.
	claims["exp"] = "never"
	jwt = createRSATestJWT(t, privKey, kid, claims)
	if _, err := Validate(jwt, keys, attackIssuer, "ssh-server", "", nil); err == nil {
		t.Error("should reject token with non-numeric exp")
	}
}

// alignToSecondStart sleeps until the wall clock is just past a second
// boundary, so time.Now().Unix() stays constant for the next ~900 ms and the
// exact-boundary assertions below cannot straddle a tick (Validate reads the
// clock itself; there is no injectable clock).
func alignToSecondStart() {
	if ns := time.Now().Nanosecond(); ns > 50_000_000 {
		time.Sleep(time.Second - time.Duration(ns) + 5*time.Millisecond)
	}
}

func TestValidate_ClockSkewExactBoundaries(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"
	keys := map[string]crypto.PublicKey{kid: &privKey.PublicKey}

	// The window is 60 s: exp = now-60 / nbf = now+60 / iat = now+60 pass,
	// one second further is rejected.
	cases := []struct {
		claim  string
		offset int64
		ok     bool
	}{
		{"exp", -60, true},
		{"exp", -61, false},
		{"nbf", 60, true},
		{"nbf", 61, false},
		{"iat", 60, true},
		{"iat", 61, false},
	}
	for _, c := range cases {
		t.Run(c.claim, func(t *testing.T) {
			alignToSecondStart()
			now := time.Now().Unix()
			claims := validClaims()
			claims[c.claim] = float64(now + c.offset)
			jwt := createRSATestJWT(t, privKey, kid, claims)
			_, err := Validate(jwt, keys, attackIssuer, "ssh-server", "", nil)
			if c.ok && err != nil {
				t.Errorf("%s = now%+d should be accepted: %v", c.claim, c.offset, err)
			}
			if !c.ok && err == nil {
				t.Errorf("%s = now%+d should be rejected", c.claim, c.offset)
			}
		})
	}
}
