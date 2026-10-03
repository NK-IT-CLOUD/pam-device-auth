package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
)

func rsaJWK(n *big.Int, e int) jwk {
	return jwk{
		Kty: "RSA",
		Kid: "k",
		N:   base64.RawURLEncoding.EncodeToString(n.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(e)).Bytes()),
	}
}

func TestParseRSAKey_AcceptsStrongKey(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := parseRSAKey(rsaJWK(priv.N, priv.E)); err != nil {
		t.Fatalf("strong RSA key rejected: %v", err)
	}
}

// A short modulus is cryptographically weak; an attacker who can influence the
// JWKS response could factor it and forge signatures.
func TestParseRSAKey_RejectsShortModulus(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := parseRSAKey(rsaJWK(priv.N, priv.E)); err == nil {
		t.Error("RSA key with a 1024-bit modulus should be rejected")
	}
}

// e=1 makes RSA "signatures" trivially forgeable (m^1 == m); reject it.
func TestParseRSAKey_RejectsTinyExponent(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	for _, e := range []int{0, 1, 2} {
		if _, err := parseRSAKey(rsaJWK(priv.N, e)); err == nil {
			t.Errorf("RSA key with exponent %d should be rejected", e)
		}
	}
}

func ecJWK(curve elliptic.Curve, x, y *big.Int) jwk {
	byteLen := (curve.Params().BitSize + 7) / 8
	xb, yb := make([]byte, byteLen), make([]byte, byteLen)
	x.FillBytes(xb)
	y.FillBytes(yb)
	crv := "P-256"
	switch curve {
	case elliptic.P384():
		crv = "P-384"
	case elliptic.P521():
		crv = "P-521"
	}
	return jwk{
		Kty: "EC",
		Kid: "k",
		Crv: crv,
		X:   base64.RawURLEncoding.EncodeToString(xb),
		Y:   base64.RawURLEncoding.EncodeToString(yb),
	}
}

func TestParseECKey_AcceptsOnCurvePoint(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := parseECKey(ecJWK(elliptic.P256(), priv.X, priv.Y)); err != nil {
		t.Fatalf("valid on-curve EC point rejected: %v", err)
	}
}

// An off-curve point can enable invalid-curve attacks; reject points that do
// not satisfy the curve equation.
func TestParseECKey_RejectsOffCurvePoint(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	offY := new(big.Int).Add(priv.Y, big.NewInt(1)) // perturb Y -> off curve
	if _, err := parseECKey(ecJWK(elliptic.P256(), priv.X, offY)); err == nil {
		t.Error("off-curve EC point should be rejected")
	}
}
