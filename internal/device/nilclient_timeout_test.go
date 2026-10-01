package device

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// With a nil client postForm builds its own client bounded by
// DefaultHTTPTimeout; a server that never answers must be cut off.
func TestRequestCode_NilClientHangingServerTimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })

	old := DefaultHTTPTimeout
	DefaultHTTPTimeout = 200 * time.Millisecond
	t.Cleanup(func() { DefaultHTTPTimeout = old })

	done := make(chan error, 1)
	go func() {
		_, err := RequestCode(context.Background(), nil, srv.URL, "ssh-server")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a timeout error, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RequestCode with nil client blocked past DefaultHTTPTimeout")
	}
}
