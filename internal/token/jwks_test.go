package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
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

	keys, err := FetchJWKS(srv.URL)
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

	keys, err := FetchJWKS(srv.URL)
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

	keys, err := FetchJWKS(srv.URL)
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

	_, err := FetchJWKS(srv.URL)
	if err == nil {
		t.Error("FetchJWKS() should fail with no signing keys")
	}
}

func TestFetchJWKS_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	_, err := FetchJWKS(srv.URL)
	if err == nil {
		t.Error("FetchJWKS() should fail on 500")
	}
}
