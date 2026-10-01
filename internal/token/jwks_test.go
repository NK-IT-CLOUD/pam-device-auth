package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchJWKS_RSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	nBytes := privKey.N.Bytes()
	eBytes := big.NewInt(int64(privKey.E)).Bytes()

	jwksResp := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": "test-rsa-key",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(nBytes),
				"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwksResp)
	}))
	defer srv.Close()

	keys, err := FetchJWKS(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("FetchJWKS() error: %v", err)
	}

	key, ok := keys["test-rsa-key"]
	if !ok {
		t.Fatal("key 'test-rsa-key' not found")
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", key)
	}

	if rsaKey.N.Cmp(privKey.N) != 0 {
		t.Error("RSA N mismatch")
	}
}

func TestFetchJWKS_EC(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	byteLen := (privKey.Params().BitSize + 7) / 8
	xBytes := privKey.X.Bytes()
	yBytes := privKey.Y.Bytes()
	xPadded := make([]byte, byteLen)
	yPadded := make([]byte, byteLen)
	copy(xPadded[byteLen-len(xBytes):], xBytes)
	copy(yPadded[byteLen-len(yBytes):], yBytes)

	jwksResp := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "EC",
				"kid": "test-ec-key",
				"use": "sig",
				"crv": "P-256",
				"x":   base64.RawURLEncoding.EncodeToString(xPadded),
				"y":   base64.RawURLEncoding.EncodeToString(yPadded),
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwksResp)
	}))
	defer srv.Close()

	keys, err := FetchJWKS(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("FetchJWKS() error: %v", err)
	}

	key, ok := keys["test-ec-key"]
	if !ok {
		t.Fatal("key 'test-ec-key' not found")
	}

	_, ok = key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", key)
	}
}

func TestFetchJWKS_SkipsNonSigKeys(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	jwksResp := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": "enc-key",
				"use": "enc",
				"n":   base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
			},
			{
				"kty": "RSA",
				"kid": "sig-key",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwksResp)
	}))
	defer srv.Close()

	keys, err := FetchJWKS(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("FetchJWKS() error: %v", err)
	}

	if _, ok := keys["enc-key"]; ok {
		t.Error("encryption key should have been skipped")
	}
	if _, ok := keys["sig-key"]; !ok {
		t.Error("signing key should be present")
	}
}

func TestFetchJWKS_EmptyKeys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{}})
	}))
	defer srv.Close()

	_, err := FetchJWKS(context.Background(), srv.Client(), srv.URL)
	if err == nil {
		t.Error("FetchJWKS() should fail with no signing keys")
	}
}

func TestFetchJWKS_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	_, err := FetchJWKS(context.Background(), srv.Client(), srv.URL)
	if err == nil {
		t.Error("FetchJWKS() should fail on 500")
	}
}

func TestFetchJWKS_Unreachable(t *testing.T) {
	_, err := FetchJWKS(context.Background(), &http.Client{Timeout: 100 * time.Millisecond}, "http://127.0.0.1:1")
	if err == nil {
		t.Error("FetchJWKS() should fail for an unreachable server")
	}
}

func TestFetchJWKS_SkipsEmptyKid(t *testing.T) {
	// Empty kid in JWK must be rejected — otherwise a JWT with no kid header
	// (which JSON-decodes to "") silently matches this key.
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	jwksResp := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": "",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
			},
			{
				"kty": "RSA",
				"kid": "valid-key",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwksResp)
	}))
	defer srv.Close()

	keys, err := FetchJWKS(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("FetchJWKS() error: %v", err)
	}
	if _, ok := keys[""]; ok {
		t.Error("empty-kid key should be skipped")
	}
	if _, ok := keys["valid-key"]; !ok {
		t.Error("valid key should be present")
	}
}

func TestFetchJWKS_AllEmptyKid(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	jwksResp := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": "",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwksResp)
	}))
	defer srv.Close()

	_, err := FetchJWKS(context.Background(), srv.Client(), srv.URL)
	if err == nil {
		t.Error("FetchJWKS() should fail when all keys have empty kid")
	}
}

// The exponent accumulator is a plain int; an over-long e from a poisoned JWKS
// must be rejected up front rather than silently overflowing.
func TestParseRSAKey_ExponentLength(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Standard 65537 encodes as 3 bytes (0x01 0x00 0x01) and must still parse.
	k := rsaJWK(priv.N, 65537)
	if got, _ := base64.RawURLEncoding.DecodeString(k.E); len(got) != 3 {
		t.Fatalf("test setup: 65537 should encode as 3 bytes, got %d", len(got))
	}
	pub, err := parseRSAKey(k)
	if err != nil {
		t.Fatalf("3-byte exponent 65537 rejected: %v", err)
	}
	if pub.E != 65537 {
		t.Errorf("E = %d, want 65537", pub.E)
	}

	for _, c := range []struct {
		name string
		e    []byte
	}{
		{"5-byte exponent", []byte{1, 0, 0, 0, 1}},
		{"empty exponent", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			k := rsaJWK(priv.N, 65537)
			k.E = base64.RawURLEncoding.EncodeToString(c.e)
			_, err := parseRSAKey(k)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), "out of range") {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
