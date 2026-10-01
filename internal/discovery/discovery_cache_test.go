package discovery

import (
	"context"
	"encoding/json"
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

func validDiscoveryDoc() map[string]interface{} {
	return map[string]interface{}{
		"issuer":                        cacheTestIssuer,
		"token_endpoint":                cacheTestIssuer + "/protocol/openid-connect/token",
		"device_authorization_endpoint": cacheTestIssuer + "/protocol/openid-connect/auth/device",
		"jwks_uri":                      cacheTestIssuer + "/protocol/openid-connect/certs",
	}
}

func setupCacheDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "oidc")
	orig := oidccache.Dir
	oidccache.Dir = dir
	t.Cleanup(func() { oidccache.Dir = orig })
	return dir
}

// discoveryServer serves doc and counts requests.
func discoveryServer(t *testing.T, doc map[string]interface{}) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// plantCache writes a raw envelope so tests control age, issuer and body.
func plantCache(t *testing.T, fetchedAt int64, issuer string, body string) {
	t.Helper()
	if err := os.MkdirAll(oidccache.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	env := `{"fetched_at":` + jsonNum(fetchedAt) + `,"issuer":` + jsonStr(issuer) + `,"body":` + body + `}`
	if err := os.WriteFile(filepath.Join(oidccache.Dir, oidccache.DiscoveryFile), []byte(env), 0600); err != nil {
		t.Fatal(err)
	}
}

func jsonNum(n int64) string  { b, _ := json.Marshal(n); return string(b) }
func jsonStr(s string) string { b, _ := json.Marshal(s); return string(b) }

func TestFetchCachedMissFetchesAndWrites(t *testing.T) {
	dir := setupCacheDir(t)
	srv, hits := discoveryServer(t, validDiscoveryDoc())

	ep, err := FetchCached(context.Background(), srv.Client(), srv.URL, nil)
	if err != nil {
		t.Fatalf("FetchCached() error: %v", err)
	}
	if ep.Issuer != cacheTestIssuer {
		t.Errorf("Issuer = %q", ep.Issuer)
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
	fi, err := os.Stat(filepath.Join(dir, oidccache.DiscoveryFile))
	if err != nil {
		t.Fatalf("cache file not written: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("cache file mode = %o, want 0600", fi.Mode().Perm())
	}

	// The envelope must be keyed to the configured issuer passed to FetchCached.
	data, _ := os.ReadFile(filepath.Join(dir, oidccache.DiscoveryFile))
	var env struct {
		Issuer string          `json:"issuer"`
		Body   json.RawMessage `json:"body"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	if env.Issuer != srv.URL {
		t.Errorf("envelope issuer = %q, want %q", env.Issuer, srv.URL)
	}
	if len(env.Body) == 0 {
		t.Error("envelope body is empty")
	}
}

func TestFetchCachedHitSkipsHTTP(t *testing.T) {
	setupCacheDir(t)
	srv, hits := discoveryServer(t, validDiscoveryDoc())

	if _, err := FetchCached(context.Background(), srv.Client(), srv.URL, nil); err != nil {
		t.Fatal(err)
	}
	ep, err := FetchCached(context.Background(), srv.Client(), srv.URL, nil)
	if err != nil {
		t.Fatalf("second FetchCached() error: %v", err)
	}
	if ep.JwksURI != cacheTestIssuer+"/protocol/openid-connect/certs" {
		t.Errorf("JwksURI = %q", ep.JwksURI)
	}
	if *hits != 1 {
		t.Errorf("expected 1 HTTP request across two calls, got %d", *hits)
	}
}

func TestFetchCachedExpiredRefetches(t *testing.T) {
	setupCacheDir(t)
	srv, hits := discoveryServer(t, validDiscoveryDoc())
	body, _ := json.Marshal(validDiscoveryDoc())
	plantCache(t, time.Now().Add(-oidccache.TTL-time.Minute).Unix(), srv.URL, string(body))

	if _, err := FetchCached(context.Background(), srv.Client(), srv.URL, nil); err != nil {
		t.Fatal(err)
	}
	if *hits != 1 {
		t.Errorf("expired entry must trigger a live fetch, got %d requests", *hits)
	}
}

func TestFetchCachedCorruptRefetches(t *testing.T) {
	setupCacheDir(t)
	srv, hits := discoveryServer(t, validDiscoveryDoc())
	if err := os.MkdirAll(oidccache.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oidccache.Dir, oidccache.DiscoveryFile), []byte("{nope"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := FetchCached(context.Background(), srv.Client(), srv.URL, nil); err != nil {
		t.Fatal(err)
	}
	if *hits != 1 {
		t.Errorf("corrupt entry must trigger a live fetch, got %d requests", *hits)
	}
}

func TestFetchCachedIssuerMismatchRefetches(t *testing.T) {
	setupCacheDir(t)
	srv, hits := discoveryServer(t, validDiscoveryDoc())
	body, _ := json.Marshal(validDiscoveryDoc())
	plantCache(t, time.Now().Unix(), "https://other.example.com/realms/x", string(body))

	if _, err := FetchCached(context.Background(), srv.Client(), srv.URL, nil); err != nil {
		t.Fatal(err)
	}
	if *hits != 1 {
		t.Errorf("foreign-issuer entry must trigger a live fetch, got %d requests", *hits)
	}
}

// A cached body that would not pass Parse (here: jwks_uri on a different
// host) must never be served; the live document is fetched instead.
func TestFetchCachedInvalidBodyRefetches(t *testing.T) {
	setupCacheDir(t)
	srv, hits := discoveryServer(t, validDiscoveryDoc())
	bad := validDiscoveryDoc()
	bad["jwks_uri"] = "https://evil.attacker.example/certs"
	body, _ := json.Marshal(bad)
	plantCache(t, time.Now().Unix(), srv.URL, string(body))

	ep, err := FetchCached(context.Background(), srv.Client(), srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ep.JwksURI != cacheTestIssuer+"/protocol/openid-connect/certs" {
		t.Errorf("served tampered cached jwks_uri %q", ep.JwksURI)
	}
	if *hits != 1 {
		t.Errorf("invalid cached body must trigger a live fetch, got %d requests", *hits)
	}
}

func TestFetchCachedFailedFetchNotCached(t *testing.T) {
	dir := setupCacheDir(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := FetchCached(context.Background(), srv.Client(), srv.URL, nil); err == nil {
		t.Fatal("FetchCached() should fail on 500")
	}
	if _, err := os.Stat(filepath.Join(dir, oidccache.DiscoveryFile)); !os.IsNotExist(err) {
		t.Error("a failed fetch must not leave a cache file")
	}
}

func TestFetchCachedInvalidLiveDocNotCached(t *testing.T) {
	dir := setupCacheDir(t)
	bad := validDiscoveryDoc()
	bad["jwks_uri"] = "https://evil.attacker.example/certs"
	srv, _ := discoveryServer(t, bad)

	if _, err := FetchCached(context.Background(), srv.Client(), srv.URL, nil); err == nil {
		t.Fatal("FetchCached() should reject off-issuer jwks_uri")
	}
	if _, err := os.Stat(filepath.Join(dir, oidccache.DiscoveryFile)); !os.IsNotExist(err) {
		t.Error("a document failing validation must not be cached")
	}
}

func TestFetchCachedWriteFailureIsNonFatal(t *testing.T) {
	// Point the cache at a path under a regular file so MkdirAll fails.
	base := t.TempDir()
	blocker := filepath.Join(base, "file")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	orig := oidccache.Dir
	oidccache.Dir = filepath.Join(blocker, "oidc")
	t.Cleanup(func() { oidccache.Dir = orig })

	srv, hits := discoveryServer(t, validDiscoveryDoc())
	logged := false
	debugf := func(string, ...interface{}) { logged = true }
	ep, err := FetchCached(context.Background(), srv.Client(), srv.URL, debugf)
	if err != nil {
		t.Fatalf("cache write failure must not fail the fetch: %v", err)
	}
	if ep == nil || *hits != 1 {
		t.Errorf("expected live result with 1 request, got %v / %d", ep, *hits)
	}
	if !logged {
		t.Error("cache write failure should be reported through debugf")
	}
}

// A server that flushes a valid document but never closes the response must
// not hang FetchRaw when the caller passes neither a context deadline nor a
// client timeout.
func TestFetchRaw_NoDeadlineFallback(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"x"`))
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
		_, err := FetchRaw(context.Background(), &http.Client{}, srv.URL)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error from the deadline fallback, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FetchRaw blocked without a deadline")
	}
}
