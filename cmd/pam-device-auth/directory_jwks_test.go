package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/discovery"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/logger"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/oidccache"
)

const (
	jwksTestIssuer = "https://sso.example.com/realms/test"
	jwksTestClient = "ssh-server"
	jwksTestUser   = "testuser"
)

// Local RS256 signer: the token package's test helpers are not importable
// from another package, so this mirrors createRSATestJWT in miniature.
func signRS256(t *testing.T, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	claims, _ := json.Marshal(map[string]interface{}{
		"iss":                jwksTestIssuer,
		"exp":                time.Now().Add(time.Hour).Unix(),
		"iat":                time.Now().Add(-time.Minute).Unix(),
		"azp":                jwksTestClient,
		"preferred_username": jwksTestUser,
	})
	signed := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	h := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func jwksDoc(keys map[string]*rsa.PrivateKey) []byte {
	var list []map[string]interface{}
	for kid, k := range keys {
		list = append(list, map[string]interface{}{
			"kty": "RSA",
			"kid": kid,
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		})
	}
	body, _ := json.Marshal(map[string]interface{}{"keys": list})
	return body
}

type jwksFixture struct {
	log       *logger.Logger
	client    *http.Client
	endpoints *discovery.Endpoints
	cfg       *config.Config
	hits      *int32
}

// newJWKSFixture redirects the metadata cache to a temp dir, optionally plants
// a fresh cached key set, and serves the live key set from an httptest server.
func newJWKSFixture(t *testing.T, cached, live map[string]*rsa.PrivateKey) *jwksFixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "oidc")
	orig := oidccache.Dir
	oidccache.Dir = dir
	t.Cleanup(func() { oidccache.Dir = orig })

	if cached != nil {
		if err := oidccache.Save(oidccache.JWKSFile, jwksTestIssuer, jwksDoc(cached)); err != nil {
			t.Fatal(err)
		}
	}

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write(jwksDoc(live))
	}))
	t.Cleanup(srv.Close)

	log, err := logger.NewLogger("", false)
	if err != nil {
		t.Fatal(err)
	}
	return &jwksFixture{
		log:       log,
		client:    srv.Client(),
		endpoints: &discovery.Endpoints{Issuer: jwksTestIssuer, JwksURI: srv.URL},
		cfg:       &config.Config{IssuerURL: jwksTestIssuer, ClientID: jwksTestClient},
		hits:      &hits,
	}
}

func (f *jwksFixture) validate(t *testing.T, accessToken string) error {
	t.Helper()
	_, err := validateDirectoryToken(f.log, f.client, f.endpoints, f.cfg, accessToken, jwksTestUser)
	return err
}

func genKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestValidateDirectoryToken_CacheHitNoHTTP(t *testing.T) {
	a := genKey(t)
	f := newJWKSFixture(t, map[string]*rsa.PrivateKey{"a": a}, map[string]*rsa.PrivateKey{"a": a})

	if err := f.validate(t, signRS256(t, a, "a")); err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if *f.hits != 0 {
		t.Errorf("warm cache must need no JWKS request, got %d", *f.hits)
	}
}

// Key rotation: the cache holds only the old key, the token is signed with a
// new one. Exactly one live refetch must happen, the cache must be replaced
// and validation must succeed.
func TestValidateDirectoryToken_KidMissRefetchesOnce(t *testing.T) {
	a, b := genKey(t), genKey(t)
	f := newJWKSFixture(t, map[string]*rsa.PrivateKey{"a": a}, map[string]*rsa.PrivateKey{"a": a, "b": b})

	tok := signRS256(t, b, "b")
	if err := f.validate(t, tok); err != nil {
		t.Fatalf("validation after rotation failed: %v", err)
	}
	if *f.hits != 1 {
		t.Errorf("expected exactly 1 JWKS refetch, got %d", *f.hits)
	}

	// The refreshed set is now cached: the same token validates with no HTTP.
	if err := f.validate(t, tok); err != nil {
		t.Fatalf("second validation failed: %v", err)
	}
	if *f.hits != 1 {
		t.Errorf("refetched set must be cached, got %d requests total", *f.hits)
	}
	fi, err := os.Stat(filepath.Join(oidccache.Dir, oidccache.JWKSFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("cache file mode = %o, want 0600", fi.Mode().Perm())
	}
}

// The kid is still unknown after the live refetch: one request, then a final
// error with no further retries.
func TestValidateDirectoryToken_KidMissRefetchStillUnknownFails(t *testing.T) {
	a, b := genKey(t), genKey(t)
	f := newJWKSFixture(t, map[string]*rsa.PrivateKey{"a": a}, map[string]*rsa.PrivateKey{"a": a})

	if err := f.validate(t, signRS256(t, b, "b")); err == nil {
		t.Fatal("expected validation error for unknown kid")
	}
	if *f.hits != 1 {
		t.Errorf("expected exactly 1 JWKS refetch, got %d", *f.hits)
	}
}

// Keys that were just fetched live cannot be stale: an unknown kid must not
// trigger a second fetch.
func TestValidateDirectoryToken_KidMissAfterLiveFetchNoRetry(t *testing.T) {
	a, b := genKey(t), genKey(t)
	f := newJWKSFixture(t, nil, map[string]*rsa.PrivateKey{"a": a})

	if err := f.validate(t, signRS256(t, b, "b")); err == nil {
		t.Fatal("expected validation error for unknown kid")
	}
	if *f.hits != 1 {
		t.Errorf("live fetch must not be repeated on kid miss, got %d requests", *f.hits)
	}
}

// A bad signature under a KNOWN kid is a final error and must never cause a
// network round trip (no refetch on arbitrary validation failures).
func TestValidateDirectoryToken_BadSignatureKnownKidNoRefetch(t *testing.T) {
	a, forged := genKey(t), genKey(t)
	f := newJWKSFixture(t, map[string]*rsa.PrivateKey{"a": a}, map[string]*rsa.PrivateKey{"a": a})

	if err := f.validate(t, signRS256(t, forged, "a")); err == nil {
		t.Fatal("expected signature failure")
	}
	if *f.hits != 0 {
		t.Errorf("signature failure must not refetch JWKS, got %d requests", *f.hits)
	}
}

// A JWKS cache entry written for another issuer must be ignored:
// the fixture's server is hit once and the foreign key never validates.
func TestValidateDirectoryToken_ForeignIssuerCacheIgnored(t *testing.T) {
	a, foreign := genKey(t), genKey(t)
	f := newJWKSFixture(t, nil, map[string]*rsa.PrivateKey{"a": a})
	if err := oidccache.Save(oidccache.JWKSFile, "https://other.example.com/realms/x", jwksDoc(map[string]*rsa.PrivateKey{"a": foreign})); err != nil {
		t.Fatal(err)
	}

	if err := f.validate(t, signRS256(t, a, "a")); err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if *f.hits != 1 {
		t.Errorf("foreign-issuer cache must be bypassed with one live fetch, got %d", *f.hits)
	}
}
