package device

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// Lower minimum poll interval for fast tests.
	MinPollInterval = 1
	os.Exit(m.Run())
}

func newTestClient(srv *httptest.Server) *http.Client {
	client := srv.Client()
	client.Timeout = 2 * time.Second
	return client
}

func TestReadResponse_RejectsOversizedBody(t *testing.T) {
	small := []byte(`{"ok":true}`)
	if got, err := readResponse(bytes.NewReader(small)); err != nil || string(got) != string(small) {
		t.Fatalf("readResponse(small) = %q, %v; want %q, nil", got, err, small)
	}

	oversized := make([]byte, maxResponseBytes+1)
	if _, err := readResponse(bytes.NewReader(oversized)); err == nil {
		t.Errorf("readResponse(oversized) = nil error; want fail-closed error")
	}
}

func TestPostForm_NilClientDoesNotFollowRedirects(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			// Redirect the token POST elsewhere; following it would re-send the
			// device_code/refresh_token body to the redirect target.
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := postForm(context.Background(), nil, srv.URL, nil)
	if err != nil {
		t.Fatalf("postForm: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("nil-client followed redirect (status %d); want 302 not followed", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("server hit %d times; redirect was followed", got)
	}
}

func TestRequestCode_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("content-type = %s", ct)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error: %v", err)
		}
		if r.Form.Get("client_id") != "ssh-server" {
			t.Errorf("client_id = %s", r.Form.Get("client_id"))
		}
		if r.Form.Get("scope") != "openid profile email" {
			t.Errorf("scope = %s", r.Form.Get("scope"))
		}

		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":               "dev-code-123",
			"user_code":                 "ABCD-EFGH",
			"verification_uri":          "https://sso.example.com/device",
			"verification_uri_complete": "https://sso.example.com/device?user_code=ABCD-EFGH",
			"expires_in":                600,
			"interval":                  5,
		}); err != nil {
			t.Fatalf("Encode() error: %v", err)
		}
	}))
	defer srv.Close()

	dc, err := RequestCode(context.Background(), newTestClient(srv), srv.URL, "ssh-server")
	if err != nil {
		t.Fatalf("RequestCode() error: %v", err)
	}
	if dc.DeviceCode != "dev-code-123" {
		t.Errorf("DeviceCode = %q", dc.DeviceCode)
	}
	if dc.UserCode != "ABCD-EFGH" {
		t.Errorf("UserCode = %q", dc.UserCode)
	}
	if dc.VerificationURI != "https://sso.example.com/device" {
		t.Errorf("VerificationURI = %q", dc.VerificationURI)
	}
	if dc.VerificationURIComplete != "https://sso.example.com/device?user_code=ABCD-EFGH" {
		t.Errorf("VerificationURIComplete = %q", dc.VerificationURIComplete)
	}
	if dc.Interval != 5 {
		t.Errorf("Interval = %d", dc.Interval)
	}
}

func TestRequestCode_MinInterval(t *testing.T) {
	old := MinPollInterval
	MinPollInterval = 5
	defer func() { MinPollInterval = old }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":      "x",
			"user_code":        "Y",
			"verification_uri": "https://sso.example.com/device",
			"interval":         1,
		}); err != nil {
			t.Fatalf("Encode() error: %v", err)
		}
	}))
	defer srv.Close()

	dc, err := RequestCode(context.Background(), newTestClient(srv), srv.URL, "test")
	if err != nil {
		t.Fatalf("RequestCode() error: %v", err)
	}
	if dc.Interval < 5 {
		t.Errorf("Interval = %d, should be clamped to >= 5", dc.Interval)
	}
}

func TestRequestCode_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		if _, err := w.Write([]byte(`{"error": "invalid_client"}`)); err != nil {
			t.Fatalf("Write() error: %v", err)
		}
	}))
	defer srv.Close()

	_, err := RequestCode(context.Background(), newTestClient(srv), srv.URL, "bad-client")
	if err == nil {
		t.Error("should fail on 400")
	}
}

func TestRequestCode_MissingFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code": "x",
		}); err != nil {
			t.Fatalf("Encode() error: %v", err)
		}
	}))
	defer srv.Close()

	_, err := RequestCode(context.Background(), newTestClient(srv), srv.URL, "test")
	if err == nil {
		t.Error("should fail with missing required fields")
	}
}

func TestRequestCode_ContextTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := RequestCode(ctx, newTestClient(srv), srv.URL, "ssh-server")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("RequestCode() should fail when the request context times out")
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("request should have been cancelled quickly, elapsed = %v", elapsed)
	}
}

func TestPollToken_ImmediateSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "test-token-xyz",
			"refresh_token": "test-rt-xyz",
			"token_type":    "Bearer",
			"expires_in":    300,
		}); err != nil {
			t.Fatalf("Encode() error: %v", err)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token, err := PollToken(ctx, newTestClient(srv), srv.URL, "ssh-server", "dev-code", 1)
	if err != nil {
		t.Fatalf("PollToken() error: %v", err)
	}
	if token.AccessToken != "test-token-xyz" {
		t.Errorf("AccessToken = %q", token.AccessToken)
	}
	if token.RefreshToken != "test-rt-xyz" {
		t.Errorf("RefreshToken = %q, want %q", token.RefreshToken, "test-rt-xyz")
	}
}

func TestPollToken_PendingThenSuccess(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := callCount.Add(1)
		if count < 3 {
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "authorization_pending",
			}); err != nil {
				t.Fatalf("Encode() error: %v", err)
			}
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "success-token",
			"refresh_token": "rt-success",
			"token_type":    "Bearer",
		}); err != nil {
			t.Fatalf("Encode() error: %v", err)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token, err := PollToken(ctx, newTestClient(srv), srv.URL, "ssh-server", "dev-code", 1)
	if err != nil {
		t.Fatalf("PollToken() error: %v", err)
	}
	if token.AccessToken != "success-token" {
		t.Errorf("AccessToken = %q", token.AccessToken)
	}
}

func TestPollToken_AccessDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "access_denied",
		}); err != nil {
			t.Fatalf("Encode() error: %v", err)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := PollToken(ctx, newTestClient(srv), srv.URL, "ssh-server", "dev-code", 1)
	if err == nil {
		t.Error("should fail on access_denied")
	}
}

func TestPollToken_ExpiredToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "expired_token",
		}); err != nil {
			t.Fatalf("Encode() error: %v", err)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := PollToken(ctx, newTestClient(srv), srv.URL, "ssh-server", "dev-code", 1)
	if err == nil {
		t.Error("should fail on expired_token")
	}
}

func TestPollToken_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "authorization_pending",
		}); err != nil {
			t.Fatalf("Encode() error: %v", err)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := PollToken(ctx, newTestClient(srv), srv.URL, "ssh-server", "dev-code", 1)
	if err == nil {
		t.Error("should fail on timeout")
	}
}

func TestPollToken_ContextTimeoutDuringRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1500 * time.Millisecond)
	}))
	defer srv.Close()

	// The first request goes out at once and is still in flight when the
	// context ends.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := PollToken(ctx, newTestClient(srv), srv.URL, "ssh-server", "dev-code", 1)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "device authorization timed out") {
		t.Fatalf("PollToken() error = %v, want the timeout when the context ends during a request", err)
	}
	if elapsed > time.Second {
		t.Fatalf("poll request should have been cancelled, elapsed = %v", elapsed)
	}
}

func TestPollToken_SlowDown(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := callCount.Add(1)
		if count == 1 {
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "slow_down",
			}); err != nil {
				t.Fatalf("Encode() error: %v", err)
			}
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "token",
			"refresh_token": "rt-slow",
			"token_type":    "Bearer",
		}); err != nil {
			t.Fatalf("Encode() error: %v", err)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	_, err := PollToken(ctx, newTestClient(srv), srv.URL, "ssh-server", "dev-code", 1)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("PollToken() error: %v", err)
	}
	if elapsed < 5*time.Second {
		t.Errorf("slow_down should have increased interval, but elapsed = %v", elapsed)
	}
}

func TestRefreshToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error: %v", err)
		}
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("grant_type = %s", r.Form.Get("grant_type"))
		}
		if r.Form.Get("refresh_token") != "old-rt" {
			t.Errorf("refresh_token = %s", r.Form.Get("refresh_token"))
		}
		if r.Form.Get("client_id") != "ssh-server" {
			t.Errorf("client_id = %s", r.Form.Get("client_id"))
		}

		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "new-at",
			"refresh_token": "new-rt",
			"token_type":    "Bearer",
			"expires_in":    300,
		}); err != nil {
			t.Fatalf("Encode() error: %v", err)
		}
	}))
	defer srv.Close()

	token, err := RefreshToken(context.Background(), newTestClient(srv), srv.URL, "ssh-server", "old-rt")
	if err != nil {
		t.Fatalf("RefreshToken() error: %v", err)
	}
	if token.AccessToken != "new-at" {
		t.Errorf("AccessToken = %q", token.AccessToken)
	}
	if token.RefreshToken != "new-rt" {
		t.Errorf("RefreshToken = %q", token.RefreshToken)
	}
}

func TestRefreshToken_Rejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "invalid_grant",
			"error_description": "Token is not active",
		}); err != nil {
			t.Fatalf("Encode() error: %v", err)
		}
	}))
	defer srv.Close()

	_, err := RefreshToken(context.Background(), newTestClient(srv), srv.URL, "ssh-server", "expired-rt")
	if err == nil {
		t.Error("should fail on rejected refresh")
	}
}

func TestRefreshToken_ServerDown(t *testing.T) {
	client := &http.Client{Timeout: 100 * time.Millisecond}
	_, err := RefreshToken(context.Background(), client, "http://127.0.0.1:1", "ssh-server", "rt")
	if err == nil {
		t.Error("should fail on unreachable server")
	}
}

// tokenSuccess answers a token request with a fixed token pair.
func tokenSuccess(t *testing.T, w http.ResponseWriter, accessToken string) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": accessToken, "refresh_token": "rt", "token_type": "Bearer",
	}); err != nil {
		t.Errorf("Encode() error: %v", err)
	}
}

// The user presses Enter after approving in the browser: the first token
// request must go out at once, not after a full poll interval.
func TestPollToken_FirstRequestAtOnce(t *testing.T) {
	old := MinPollInterval
	MinPollInterval = 2
	defer func() { MinPollInterval = old }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenSuccess(t, w, "at-once")
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	token, err := PollToken(ctx, newTestClient(srv), srv.URL, "ssh-server", "dev-code", 2)
	if err != nil {
		t.Fatalf("PollToken() error: %v", err)
	}
	if token.AccessToken != "at-once" {
		t.Errorf("AccessToken = %q", token.AccessToken)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("the token arrived after %s; the first request must not wait for the poll interval (2 s)", d)
	}
}

// fastRetries removes the waits between token requests for one test.
func fastRetries(t *testing.T) {
	t.Helper()
	oldInterval, oldBackoff := MinPollInterval, minRetryBackoff
	MinPollInterval, minRetryBackoff = 0, 10*time.Millisecond
	t.Cleanup(func() { MinPollInterval, minRetryBackoff = oldInterval, oldBackoff })
}

// A proxy error page, a rate limit and a dropped connection say nothing about
// the device code: polling goes on and the login completes.
func TestPollToken_RetriesTransientErrors(t *testing.T) {
	fastRetries(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1:
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte("<html><body>502 Bad Gateway</body></html>"))
		case 2:
			w.WriteHeader(http.StatusTooManyRequests)
		case 3:
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("Hijack() error: %v", err)
				return
			}
			conn.Close()
		default:
			tokenSuccess(t, w, "after-retries")
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	token, err := PollToken(ctx, newTestClient(srv), srv.URL, "ssh-server", "dev-code", 0)
	if err != nil {
		t.Fatalf("PollToken() error: %v", err)
	}
	if token.AccessToken != "after-retries" {
		t.Errorf("AccessToken = %q", token.AccessToken)
	}
	if n := calls.Load(); n != 4 {
		t.Errorf("token requests = %d, want 4 (three transient failures, then the token)", n)
	}
}

// While the provider keeps failing, polling goes on until the deadline and
// the error names the last failure.
func TestPollToken_TransientUntilDeadline(t *testing.T) {
	fastRetries(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	_, err := PollToken(ctx, newTestClient(srv), srv.URL, "ssh-server", "dev-code", 0)
	if err == nil {
		t.Fatal("PollToken() must fail at the deadline")
	}
	if !strings.Contains(err.Error(), "device authorization timed out") || !strings.Contains(err.Error(), "503") {
		t.Errorf("error = %q, want the timeout and the last failure (status 503)", err)
	}
	if n := calls.Load(); n < 2 {
		t.Errorf("token requests = %d, want more than one before the deadline", n)
	}
}

// The wait after a transient failure starts at the poll interval, doubles and
// is capped; an answer of the provider resets it.
func TestNextBackoff(t *testing.T) {
	const interval = 5 * time.Second
	var got []time.Duration
	b := time.Duration(0)
	for i := 0; i < 5; i++ {
		b = nextBackoff(b, interval)
		got = append(got, b)
	}
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 30 * time.Second, 30 * time.Second}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("backoff sequence = %v, want %v", got, want)
		}
	}
	if b := nextBackoff(0, 0); b != minRetryBackoff {
		t.Errorf("nextBackoff(0, 0) = %s, want the minimum %s", b, minRetryBackoff)
	}
}

// The poll interval is the floor: RFC 8628 does not allow polling faster, so
// the wait after repeated failures must not fall below it, also when the
// interval (from the provider, or after slow_down answers) is above the cap.
func TestNextBackoff_NeverBelowTheInterval(t *testing.T) {
	const interval = 45 * time.Second
	b := time.Duration(0)
	for i := 1; i <= 4; i++ {
		b = nextBackoff(b, interval)
		if b < interval {
			t.Fatalf("failure %d in a row: wait %s is below the poll interval %s", i, b, interval)
		}
	}
}

// An error page of the provider goes into the helper's log line; it must not
// carry the whole body there.
func TestErrorBodiesAreTruncated(t *testing.T) {
	huge := strings.Repeat("x", 64<<10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(huge))
	}))
	defer srv.Close()

	_, err := RequestCode(context.Background(), newTestClient(srv), srv.URL, "ssh-server")
	if err == nil || len(err.Error()) > 600 {
		t.Errorf("RequestCode() error has %d bytes, want an error of at most 600", len(fmt.Sprint(err)))
	}
	if err != nil && !strings.Contains(err.Error(), "status 500") {
		t.Errorf("RequestCode() error %.80q lacks the status", err.Error())
	}

	_, err = RefreshToken(context.Background(), newTestClient(srv), srv.URL, "ssh-server", "rt")
	if err == nil || len(err.Error()) > 600 {
		t.Errorf("RefreshToken() error has %d bytes, want an error of at most 600", len(fmt.Sprint(err)))
	}
}
