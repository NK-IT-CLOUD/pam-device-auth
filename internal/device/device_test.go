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
	// Lower minimum poll interval for fast tests
	MinPollInterval = 1
	os.Exit(m.Run())
}

func TestRequestCode_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("content-type = %s", ct)
		}
		r.ParseForm()
		if r.Form.Get("client_id") != "ssh-server" {
			t.Errorf("client_id = %s", r.Form.Get("client_id"))
		}
		if r.Form.Get("scope") != "openid profile email" {
			t.Errorf("scope = %s", r.Form.Get("scope"))
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":               "dev-code-123",
			"user_code":                 "ABCD-EFGH",
			"verification_uri":          "https://sso.example.com/device",
			"verification_uri_complete": "https://sso.example.com/device?user_code=ABCD-EFGH",
			"expires_in":                600,
			"interval":                  5,
		})
	}))
	defer srv.Close()

	dc, err := RequestCode(srv.URL, "ssh-server")
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
	// Temporarily restore real minimum for this test
	old := MinPollInterval
	MinPollInterval = 5
	defer func() { MinPollInterval = old }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":      "x",
			"user_code":        "Y",
			"verification_uri": "https://sso.example.com/device",
			"interval":         1, // too low
		})
	}))
	defer srv.Close()

	dc, err := RequestCode(srv.URL, "test")
	if err != nil {
		t.Fatalf("RequestCode() error: %v", err)
	}
	if dc.Interval < 5 {
		t.Errorf("Interval = %d, should be clamped to >= 5", dc.Interval)
	}
}

func TestRequestCode_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"error": "invalid_client"}`))
	}))
	defer srv.Close()

	_, err := RequestCode(srv.URL, "bad-client")
	if err == nil {
		t.Error("should fail on 400")
	}
}

func TestRequestCode_MissingFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code": "x",
			// missing user_code and verification_uri
		})
	}))
	defer srv.Close()

	_, err := RequestCode(srv.URL, "test")
	if err == nil {
		t.Error("should fail with missing required fields")
	}
}

func TestPollToken_ImmediateSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token-xyz",
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token, err := PollToken(ctx, srv.URL, "ssh-server", "dev-code", 1)
	if err != nil {
		t.Fatalf("PollToken() error: %v", err)
	}
	if token.AccessToken != "test-token-xyz" {
		t.Errorf("AccessToken = %q", token.AccessToken)
	}
}

func TestPollToken_PendingThenSuccess(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := callCount.Add(1)
		if count < 3 {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "authorization_pending",
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "success-token",
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token, err := PollToken(ctx, srv.URL, "ssh-server", "dev-code", 1)
	if err != nil {
		t.Fatalf("PollToken() error: %v", err)
	}
	if token.AccessToken != "success-token" {
		t.Errorf("AccessToken = %q", token.AccessToken)
	}
}

func TestPollToken_AccessDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "access_denied",
		})
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := PollToken(ctx, srv.URL, "ssh-server", "dev-code", 1)
	if err == nil {
		t.Error("should fail on access_denied")
	}
}

func TestPollToken_ExpiredToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "expired_token",
		})
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := PollToken(ctx, srv.URL, "ssh-server", "dev-code", 1)
	if err == nil {
		t.Error("should fail on expired_token")
	}
}

func TestPollToken_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "authorization_pending",
		})
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := PollToken(ctx, srv.URL, "ssh-server", "dev-code", 1)
	if err == nil {
		t.Error("should fail on timeout")
	}
}

func TestPollToken_SlowDown(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := callCount.Add(1)
		if count == 1 {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "slow_down",
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "token",
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	_, err := PollToken(ctx, srv.URL, "ssh-server", "dev-code", 1)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("PollToken() error: %v", err)
	}
	// After slow_down, interval should increase by 5s (MinPollInterval=1 in tests, so 1+5=6s).
	if elapsed < 5*time.Second {
		t.Errorf("slow_down should have increased interval, but elapsed = %v", elapsed)
	}
}
