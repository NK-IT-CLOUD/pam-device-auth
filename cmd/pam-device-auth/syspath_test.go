package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/logger"
)

// The CLI commands run sshd, visudo, sss_cache and userdel by name. A root
// shell that came from `su` has no sbin directory in its PATH on Debian.
func TestSetSystemPath(t *testing.T) {
	t.Setenv("PATH", "/home/someone/bin:/usr/local/bin")
	setSystemPath()
	if got := os.Getenv("PATH"); got != "/usr/sbin:/usr/bin:/sbin:/bin" {
		t.Errorf("PATH = %q, want the fixed system path", got)
	}
}

// A request above the limit is repeated once over a new connection. Only two
// slow requests in a row mean that every login waits; one slow request can be
// a cold cache on the way (a name server that had to ask upstream first).
func TestDiscoveryTiming(t *testing.T) {
	never := func() (time.Duration, error) {
		t.Error("a fast first request must not be repeated")
		return 0, nil
	}
	ok, okMsg, _ := discoveryTiming(1900*time.Millisecond, never)
	if !ok || !strings.Contains(okMsg, "discovery answered in 1.9s") {
		t.Errorf("discoveryTiming(1.9s) = %v, %q; want ok with the duration", ok, okMsg)
	}

	calls := 0
	fastAgain := func() (time.Duration, error) { calls++; return 180 * time.Millisecond, nil }
	ok, okMsg, _ = discoveryTiming(3760*time.Millisecond, fastAgain)
	if !ok || calls != 1 {
		t.Errorf("discoveryTiming(3.76s, then 180ms) = %v after %d repeat(s); want ok after one repeat", ok, calls)
	}
	for _, want := range []string{"discovery answered in 180ms", "first request took 3.76s"} {
		if !strings.Contains(okMsg, want) {
			t.Errorf("message %q lacks %q", okMsg, want)
		}
	}

	slowAgain := func() (time.Duration, error) { return 5010 * time.Millisecond, nil }
	ok, _, badMsg := discoveryTiming(5020*time.Millisecond, slowAgain)
	if ok {
		t.Error("discoveryTiming(5.02s, then 5.01s) = ok, want a finding: two slow requests in a row")
	}
	for _, want := range []string{"5.02s", "5.01s", "two requests in a row", "every login waits", "DNS", "name server"} {
		if !strings.Contains(badMsg, want) {
			t.Errorf("message %q lacks %q", badMsg, want)
		}
	}

	failAgain := func() (time.Duration, error) { return 0, errors.New("dial tcp: i/o timeout") }
	ok, _, badMsg = discoveryTiming(2100*time.Millisecond, failAgain)
	if ok {
		t.Error("discoveryTiming(2.1s, then an error) = ok, want a finding")
	}
	for _, want := range []string{"2.1s", "second request failed", "dial tcp: i/o timeout"} {
		if !strings.Contains(badMsg, want) {
			t.Errorf("message %q lacks %q", badMsg, want)
		}
	}
}

// Each timedDiscovery call opens its own connection: the second request of
// --check has to pay for the name lookup and the handshakes again, or it could
// not show that every login waits. Through the connection pool that
// newOIDCClient shares, the second request would reuse the open connection.
func TestTimedDiscovery_OpensAConnectionPerCall(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		json.NewEncoder(w).Encode(map[string]string{
			"issuer": base, "token_endpoint": base + "/token",
			"device_authorization_endpoint": base + "/device", "jwks_uri": base + "/jwks",
		})
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)

	for i := 1; i <= 2; i++ {
		endpoints, took, err := timedDiscovery(srv.URL)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if endpoints.Issuer != srv.URL || took <= 0 {
			t.Errorf("request %d: issuer %q, duration %v", i, endpoints.Issuer, took)
		}
	}
	if got := conns.Load(); got != 2 {
		t.Errorf("two requests used %d connection(s), want 2", got)
	}
}

// With --debug the log says how long each request to the identity provider
// took, so a slow login can be traced to the step that was slow.
func TestFlow_LogsRequestDurationsAtDebug(t *testing.T) {
	idp := newFakeIdP(t)
	idp.deviceGrant(idp.ok(t, flowUser, "rt-1"))
	f, _, logPath := newFlow(t, idp, "\n")
	debugLog, err := logger.NewLogger(logPath, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { debugLog.Close() })
	f.log = debugLog

	requireOutcome(t, f.run(flowUser, flowAddr), allow)

	requireContains(t, "log", logText(t, logPath), "Device code request took ", "JWKS fetch took ")

	// A cached login: the refresh is timed too.
	idp.refreshGrant(idp.ok(t, flowUser, "rt-2"))
	requireOutcome(t, f.run(flowUser, flowAddr), allow)
	requireContains(t, "log", logText(t, logPath), "Token refresh took ")
}
