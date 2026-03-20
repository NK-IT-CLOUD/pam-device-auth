package device

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := PollToken(ctx, newTestClient(srv), srv.URL, "ssh-server", "dev-code", 1)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("PollToken() should fail when the request context times out")
	}
	if elapsed > 2*time.Second {
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
