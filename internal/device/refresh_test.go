package device

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func refreshAgainst(t *testing.T, status int, body string) error {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	_, err := RefreshToken(context.Background(), newTestClient(srv), srv.URL, "ssh-server", "rt")
	return err
}

// Only an IdP rejection (HTTP 4xx) may be treated as "the cached refresh token
// is dead"; 5xx and transport errors must not match ErrRefreshRejected.
func TestRefreshToken_ErrorClassification(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		rejected bool
	}{
		{"invalid_grant 400", 400, `{"error":"invalid_grant","error_description":"Session not active"}`, true},
		{"401 without json", 401, `nope`, true},
		{"408 timeout is transient", 408, `slow`, false},
		{"429 rate limit is transient", 429, `{"error":"too_many_requests"}`, false},
		{"500 outage", 500, `{"error":"server_error"}`, false},
		{"503 plain", 503, `unavailable`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := refreshAgainst(t, c.status, c.body)
			if err == nil {
				t.Fatal("RefreshToken() = nil error")
			}
			if got := errors.Is(err, ErrRefreshRejected); got != c.rejected {
				t.Fatalf("errors.Is(ErrRefreshRejected) = %v, want %v (err: %v)", got, c.rejected, err)
			}
		})
	}
}

func TestRefreshToken_TransportErrorIsNotRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	client := newTestClient(srv)
	url := srv.URL
	srv.Close() // connection refused
	_, err := RefreshToken(context.Background(), client, url, "ssh-server", "rt")
	if err == nil || errors.Is(err, ErrRefreshRejected) {
		t.Fatalf("RefreshToken() = %v; want a non-rejection transport error", err)
	}
}
