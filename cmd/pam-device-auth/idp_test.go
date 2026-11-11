package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/cache"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/device"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/discovery"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/logger"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/oidccache"
)

// Test identities of the login flow tests.
const (
	flowUser = "alice"
	flowAddr = "192.0.2.10"
	flowRole = "ssh-access"
)

// tokenStep is one answer of the fake token endpoint; body is sent as JSON.
type tokenStep struct {
	status int
	body   any
}

// pending is the answer while the user has not approved the device code yet.
func pending() tokenStep { return oauthError("authorization_pending") }

// oauthError is an OAuth error document with HTTP 400.
func oauthError(code string) tokenStep {
	return tokenStep{status: http.StatusBadRequest, body: map[string]string{"error": code}}
}

// fakeIdP is an identity provider on httptest: device authorization
// endpoint, token endpoint (device grant and refresh grant) and JWKS.
type fakeIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey

	mu          sync.Mutex
	grant       []tokenStep
	refresh     tokenStep
	deviceHits  int
	tokenHits   int
	refreshHits int
}

// newFakeIdP starts the provider. Until deviceGrant is called the device grant
// stays pending; until refreshGrant is called every refresh is rejected.
func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	i := &fakeIdP{key: genKey(t), refresh: oauthError("invalid_grant")}
	mux := http.NewServeMux()
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		i.mu.Lock()
		i.deviceHits++
		i.mu.Unlock()
		writeStep(w, tokenStep{status: http.StatusOK, body: map[string]any{
			"device_code":               "device-code-1",
			"user_code":                 "ABCD-EFGH",
			"verification_uri":          "https://sso.example.com/device",
			"verification_uri_complete": "https://sso.example.com/device?user_code=ABCD-EFGH",
			"expires_in":                600,
			"interval":                  0,
		}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") == "refresh_token" {
			i.mu.Lock()
			i.refreshHits++
			step := i.refresh
			i.mu.Unlock()
			writeStep(w, step)
			return
		}
		i.mu.Lock()
		n := i.tokenHits
		i.tokenHits++
		steps := i.grant
		i.mu.Unlock()
		step := pending()
		if len(steps) > 0 {
			step = steps[min(n, len(steps)-1)]
		}
		if step.status != http.StatusOK {
			// A pending answer must not turn the poll loop into a busy loop:
			// the tests run with a poll interval of 0.
			time.Sleep(10 * time.Millisecond)
		}
		writeStep(w, step)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Write(jwksDoc(map[string]*rsa.PrivateKey{"k1": i.key}))
	})
	i.srv = httptest.NewServer(mux)
	t.Cleanup(i.srv.Close)
	return i
}

func writeStep(w http.ResponseWriter, s tokenStep) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(s.status)
	json.NewEncoder(w).Encode(s.body)
}

// deviceGrant sets the answers of the device grant in order; the last repeats.
func (i *fakeIdP) deviceGrant(steps ...tokenStep) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.grant = steps
}

// refreshGrant sets the answer of grant_type=refresh_token.
func (i *fakeIdP) refreshGrant(step tokenStep) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.refresh = step
}

// hits returns how often each endpoint was called.
func (i *fakeIdP) hits() (deviceRequests, tokenRequests, refreshRequests int) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.deviceHits, i.tokenHits, i.refreshHits
}

// token signs an access token (RS256, kid "k1") for user with the role
// flowRole; mod may change the claims before signing.
func (i *fakeIdP) token(t *testing.T, user string, mod func(claims map[string]any)) string {
	t.Helper()
	claims := map[string]any{
		"iss":                jwksTestIssuer,
		"exp":                time.Now().Add(time.Hour).Unix(),
		"iat":                time.Now().Add(-time.Minute).Unix(),
		"azp":                jwksTestClient,
		"preferred_username": user,
		"realm_access":       map[string]any{"roles": []string{flowRole}},
	}
	if mod != nil {
		mod(claims)
	}
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	h := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// tokens is a successful token response carrying accessToken and refresh.
func tokens(accessToken, refresh string) tokenStep {
	return tokenStep{status: http.StatusOK, body: map[string]string{
		"access_token": accessToken, "refresh_token": refresh, "token_type": "Bearer",
	}}
}

// ok is a successful token response for user with the role flowRole.
func (i *fakeIdP) ok(t *testing.T, user, refresh string) tokenStep {
	t.Helper()
	return tokens(i.token(t, user, nil), refresh)
}

// newFlow builds the login flow against i with stdin as the answers of the
// PAM module. The session cache and the metadata cache live in a temp dir,
// the poll interval is 0, the QR is off, the required role is flowRole, the
// device flow times out after 2 s and every user has a directory identity.
func newFlow(t *testing.T, i *fakeIdP, stdin string) (f *authFlow, out *bytes.Buffer, logPath string) {
	t.Helper()
	tmp := t.TempDir()
	origCache, origOIDC, origInterval := cache.CacheDir, oidccache.Dir, device.MinPollInterval
	cache.CacheDir = filepath.Join(tmp, "session")
	oidccache.Dir = filepath.Join(tmp, "oidc")
	device.MinPollInterval = 0
	t.Cleanup(func() { cache.CacheDir, oidccache.Dir, device.MinPollInterval = origCache, origOIDC, origInterval })

	logPath = filepath.Join(tmp, "auth.log")
	log, err := logger.NewLogger(logPath, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })

	noQR := false
	out = &bytes.Buffer{}
	f = &authFlow{
		log: log,
		cfg: &config.Config{
			IssuerURL: jwksTestIssuer, ClientID: jwksTestClient,
			RequiredRole: flowRole, AuthTimeout: 2, ShowQR: &noQR,
		},
		client: i.srv.Client(),
		endpoints: &discovery.Endpoints{
			Issuer:                      jwksTestIssuer,
			TokenEndpoint:               i.srv.URL + "/token",
			DeviceAuthorizationEndpoint: i.srv.URL + "/device",
			JwksURI:                     i.srv.URL + "/jwks",
		},
		io:  &authIO{in: bufio.NewReader(strings.NewReader(stdin)), out: out},
		nss: func(string) (bool, error) { return true, nil },
	}
	return f, out, logPath
}

// seedCache stores a session as an earlier login would have left it.
func seedCache(t *testing.T, user, refresh string, addrs ...string) {
	t.Helper()
	if err := cache.Save(&cache.CachedSession{Username: user, RefreshToken: refresh, KnownIPs: addrs}); err != nil {
		t.Fatal(err)
	}
}

// cachedSession returns the stored session of user, nil when there is none.
func cachedSession(t *testing.T, user string) *cache.CachedSession {
	t.Helper()
	s, err := cache.Load(user)
	if err != nil {
		t.Fatalf("load session cache: %v", err)
	}
	return s
}

func logText(t *testing.T, logPath string) string {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
