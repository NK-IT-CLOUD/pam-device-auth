package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strings"
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

// A JWK coordinate is the unsigned big-endian value. Leading zero bytes do not
// change it: a coordinate with one left out and one with an extra one give the
// same key. A value that does not fit the curve size is refused.
func TestParseECKey_CoordinateLength(t *testing.T) {
	// A key whose X starts with a zero byte, so the short form is 31 bytes.
	var priv *ecdsa.PrivateKey
	for i := 0; ; i++ {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if k.X.BitLen() <= 248 {
			priv = k
			break
		}
		if i > 100000 {
			t.Fatal("no key with a short X coordinate found")
		}
	}
	full := ecJWK(elliptic.P256(), priv.X, priv.Y)
	if _, err := parseECKey(full); err != nil {
		t.Fatalf("full-length coordinates rejected: %v", err)
	}

	short := full
	short.X = base64.RawURLEncoding.EncodeToString(priv.X.Bytes()) // 31 bytes or fewer
	key, err := parseECKey(short)
	if err != nil {
		t.Fatalf("a coordinate without its leading zero byte was rejected: %v", err)
	}
	if !key.Equal(&priv.PublicKey) {
		t.Error("the padded key differs from the original")
	}

	padded := full
	xb := make([]byte, 33) // one zero byte in front
	priv.X.FillBytes(xb)
	padded.X = base64.RawURLEncoding.EncodeToString(xb)
	key, err = parseECKey(padded)
	if err != nil {
		t.Fatalf("a coordinate with an extra leading zero byte was rejected: %v", err)
	}
	if !key.Equal(&priv.PublicKey) {
		t.Error("the key from the zero-padded coordinate differs from the original")
	}

	tooLarge := full
	xb[0] = 1 // 33 significant bytes: no P-256 field element
	tooLarge.X = base64.RawURLEncoding.EncodeToString(xb)
	_, err = parseECKey(tooLarge)
	if err == nil || !strings.Contains(err.Error(), "longer than 32 bytes") {
		t.Errorf("a coordinate of 33 significant bytes for P-256: err = %v, want the length error", err)
	}
}
