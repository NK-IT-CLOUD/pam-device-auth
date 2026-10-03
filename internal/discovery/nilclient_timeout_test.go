package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// With a nil client FetchRaw builds its own client bounded by
// defaultFetchTimeout; a server that stalls mid-body must be cut off. Without
// that Timeout (and with a deadline-free context) the read would block until
// the 5 s guard below fires.
func TestFetchRaw_NilClientStalledBodyIsCutOff(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"x"`))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-release
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })

	old := defaultFetchTimeout
	defaultFetchTimeout = 200 * time.Millisecond
	t.Cleanup(func() { defaultFetchTimeout = old })

	done := make(chan error, 1)
	go func() {
		_, err := FetchRaw(context.Background(), nil, srv.URL)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a timeout error, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FetchRaw with nil client blocked past the default timeout")
	}
}
