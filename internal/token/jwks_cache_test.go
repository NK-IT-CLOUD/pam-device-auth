package token

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/oidccache"
)

const cacheTestIssuer = "https://sso.example.com/realms/test"

func setupCacheDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "oidc")
	orig := oidccache.Dir
	oidccache.Dir = dir
	t.Cleanup(func() { oidccache.Dir = orig })
	return dir
}

// rsaJWKSDoc builds a JWKS document containing the given kid -> key pairs.
func rsaJWKSDoc(keys map[string]*rsa.PrivateKey) map[string]interface{} {
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
	return map[string]interface{}{"keys": list}
}

func jwksServer(t *testing.T, doc map[string]interface{}) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func plantJWKSCache(t *testing.T, fetchedAt int64, issuer string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(oidccache.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	iss, _ := json.Marshal(issuer)
	env := `{"fetched_at":` + big.NewInt(fetchedAt).String() + `,"issuer":` + string(iss) + `,"body":` + string(body) + `}`
	if err := os.WriteFile(filepath.Join(oidccache.Dir, oidccache.JWKSFile), []byte(env), 0600); err != nil {
		t.Fatal(err)
	}
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestFetchJWKSCachedMissFetchesAndWrites(t *testing.T) {
	dir := setupCacheDir(t)
	srv, hits := jwksServer(t, rsaJWKSDoc(map[string]*rsa.PrivateKey{"k1": newRSAKey(t)}))

	keys, cached, err := FetchJWKSCached(context.Background(), srv.Client(), srv.URL, cacheTestIssuer, nil)
	if err != nil {
		t.Fatalf("FetchJWKSCached() error: %v", err)
	}
	if cached {
		t.Error("first call must not report cached")
	}
	if _, ok := keys["k1"]; !ok {
		t.Error("key k1 missing")
	}
	if *hits != 1 {
		t.Errorf("expected 1 HTTP request, got %d", *hits)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0700 {
		t.Errorf("cache dir mode = %o, want 0700", di.Mode().Perm())
	}
	fi, err := os.Stat(filepath.Join(dir, oidccache.JWKSFile))
	if err != nil {
		t.Fatalf("cache file not written: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("cache file mode = %o, want 0600", fi.Mode().Perm())
	}
}

func TestFetchJWKSCachedHitSkipsHTTP(t *testing.T) {
	setupCacheDir(t)
	srv, hits := jwksServer(t, rsaJWKSDoc(map[string]*rsa.PrivateKey{"k1": newRSAKey(t)}))

	if _, _, err := FetchJWKSCached(context.Background(), srv.Client(), srv.URL, cacheTestIssuer, nil); err != nil {
		t.Fatal(err)
	}
	keys, cached, err := FetchJWKSCached(context.Background(), srv.Client(), srv.URL, cacheTestIssuer, nil)
	if err != nil {
		t.Fatalf("second FetchJWKSCached() error: %v", err)
	}
	if !cached {
		t.Error("second call must report cached")
	}
	if _, ok := keys["k1"]; !ok {
		t.Error("key k1 missing from cached set")
	}
	if *hits != 1 {
		t.Errorf("expected 1 HTTP request across two calls, got %d", *hits)
	}
}

func TestFetchJWKSCachedExpiredRefetches(t *testing.T) {
	setupCacheDir(t)
	srv, hits := jwksServer(t, rsaJWKSDoc(map[string]*rsa.PrivateKey{"k1": newRSAKey(t)}))
	body, _ := json.Marshal(rsaJWKSDoc(map[string]*rsa.PrivateKey{"stale": newRSAKey(t)}))
	plantJWKSCache(t, time.Now().Add(-oidccache.TTL-time.Minute).Unix(), cacheTestIssuer, body)

	keys, cached, err := FetchJWKSCached(context.Background(), srv.Client(), srv.URL, cacheTestIssuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cached || *hits != 1 {
		t.Errorf("expired entry must trigger a live fetch (cached=%v, hits=%d)", cached, *hits)
	}
	if _, ok := keys["stale"]; ok {
		t.Error("stale cached key must not be served")
	}
}

func TestFetchJWKSCachedCorruptRefetches(t *testing.T) {
	setupCacheDir(t)
	srv, hits := jwksServer(t, rsaJWKSDoc(map[string]*rsa.PrivateKey{"k1": newRSAKey(t)}))
	if err := os.MkdirAll(oidccache.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oidccache.Dir, oidccache.JWKSFile), []byte("{nope"), 0600); err != nil {
		t.Fatal(err)
	}

	_, cached, err := FetchJWKSCached(context.Background(), srv.Client(), srv.URL, cacheTestIssuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cached || *hits != 1 {
		t.Errorf("corrupt entry must trigger a live fetch (cached=%v, hits=%d)", cached, *hits)
	}
}

func TestFetchJWKSCachedIssuerMismatchRefetches(t *testing.T) {
	setupCacheDir(t)
	srv, hits := jwksServer(t, rsaJWKSDoc(map[string]*rsa.PrivateKey{"k1": newRSAKey(t)}))
	body, _ := json.Marshal(rsaJWKSDoc(map[string]*rsa.PrivateKey{"foreign": newRSAKey(t)}))
	plantJWKSCache(t, time.Now().Unix(), "https://other.example.com/realms/x", body)

	keys, cached, err := FetchJWKSCached(context.Background(), srv.Client(), srv.URL, cacheTestIssuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cached || *hits != 1 {
		t.Errorf("foreign-issuer entry must trigger a live fetch (cached=%v, hits=%d)", cached, *hits)
	}
	if _, ok := keys["foreign"]; ok {
		t.Error("foreign-issuer key must not be served")
	}
}

// A cached body with no usable signing keys fails ParseJWKS and must fall
// through to a live fetch instead of being served.
func TestFetchJWKSCachedInvalidBodyRefetches(t *testing.T) {
	setupCacheDir(t)
	srv, hits := jwksServer(t, rsaJWKSDoc(map[string]*rsa.PrivateKey{"k1": newRSAKey(t)}))
	plantJWKSCache(t, time.Now().Unix(), cacheTestIssuer, []byte(`{"keys":[{"kty":"RSA","kid":"","n":"AQAB","e":"AQAB"}]}`))

	keys, cached, err := FetchJWKSCached(context.Background(), srv.Client(), srv.URL, cacheTestIssuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cached || *hits != 1 {
		t.Errorf("invalid cached body must trigger a live fetch (cached=%v, hits=%d)", cached, *hits)
	}
	if _, ok := keys["k1"]; !ok {
		t.Error("live key k1 missing")
	}
}

func TestRefreshJWKSOverwritesCache(t *testing.T) {
	setupCacheDir(t)
	oldKey, newKey := newRSAKey(t), newRSAKey(t)
	body, _ := json.Marshal(rsaJWKSDoc(map[string]*rsa.PrivateKey{"old": oldKey}))
	plantJWKSCache(t, time.Now().Unix(), cacheTestIssuer, body)
	srv, hits := jwksServer(t, rsaJWKSDoc(map[string]*rsa.PrivateKey{"new": newKey}))

	keys, err := RefreshJWKS(context.Background(), srv.Client(), srv.URL, cacheTestIssuer, nil)
	if err != nil {
		t.Fatalf("RefreshJWKS() error: %v", err)
	}
	if _, ok := keys["new"]; !ok || *hits != 1 {
		t.Errorf("RefreshJWKS must fetch live (hits=%d)", *hits)
	}

	// The cache now holds the new set, so a cached load serves "new" not "old".
	keys, cached, err := FetchJWKSCached(context.Background(), srv.Client(), srv.URL, cacheTestIssuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cached || *hits != 1 {
		t.Errorf("refreshed entry should be served from cache (cached=%v, hits=%d)", cached, *hits)
	}
	if _, ok := keys["old"]; ok {
		t.Error("old key still served after refresh")
	}
	if _, ok := keys["new"]; !ok {
		t.Error("new key missing after refresh")
	}
}

func TestRefreshJWKSFailedFetchNotCached(t *testing.T) {
	dir := setupCacheDir(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := RefreshJWKS(context.Background(), srv.Client(), srv.URL, cacheTestIssuer, nil); err == nil {
		t.Fatal("RefreshJWKS() should fail on 500")
	}
	if _, err := os.Stat(filepath.Join(dir, oidccache.JWKSFile)); !os.IsNotExist(err) {
		t.Error("a failed fetch must not leave a cache file")
	}
}

func TestRefreshJWKSEmptyKeySetNotCached(t *testing.T) {
	dir := setupCacheDir(t)
	srv, _ := jwksServer(t, map[string]interface{}{"keys": []interface{}{}})

	if _, err := RefreshJWKS(context.Background(), srv.Client(), srv.URL, cacheTestIssuer, nil); err == nil {
		t.Fatal("RefreshJWKS() should reject an empty key set")
	}
	if _, err := os.Stat(filepath.Join(dir, oidccache.JWKSFile)); !os.IsNotExist(err) {
		t.Error("a key set failing validation must not be cached")
	}
}

func TestValidateUnknownKidIsSentinel(t *testing.T) {
	privKey := newRSAKey(t)
	jwt := createRSATestJWT(t, privKey, "rotated", validClaims())
	_, err := Validate(jwt, map[string]crypto.PublicKey{"other": &privKey.PublicKey}, "https://sso.example.com/realms/test", "ssh-server", "", nil)
	if !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("expected ErrUnknownKeyID, got %v", err)
	}
	if got := err.Error(); got != "unknown key ID: rotated" {
		t.Errorf("error text changed: %q", got)
	}
}

// A server that flushes a valid key set but never closes the response must
// not hang FetchJWKSRaw when the caller passes neither a context deadline nor
// a client timeout.
func TestFetchJWKSRaw_NoDeadlineFallback(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[`))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-release
	}))
	// Unblock the handler before the server closes (cleanups run LIFO).
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })

	old := defaultFetchTimeout
	defaultFetchTimeout = 200 * time.Millisecond
	t.Cleanup(func() { defaultFetchTimeout = old })

	done := make(chan error, 1)
	go func() {
		_, err := FetchJWKSRaw(context.Background(), &http.Client{}, srv.URL)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error from the deadline fallback, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FetchJWKSRaw blocked without a deadline")
	}
}
