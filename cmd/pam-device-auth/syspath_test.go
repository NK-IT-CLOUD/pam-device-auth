package main

import (
	"os"
	"strings"
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

func TestDiscoveryTiming(t *testing.T) {
	ok, okMsg, _ := discoveryTiming(1900 * time.Millisecond)
	if !ok || !strings.Contains(okMsg, "1.9s") {
		t.Errorf("discoveryTiming(1.9s) = %v, %q; want ok with the duration", ok, okMsg)
	}
	ok, _, badMsg := discoveryTiming(2100 * time.Millisecond)
	if ok {
		t.Error("discoveryTiming(2.1s) = ok, want a finding above 2 s")
	}
	for _, want := range []string{"2.1s", "DNS", "name server"} {
		if !strings.Contains(badMsg, want) {
			t.Errorf("discoveryTiming(2.1s) message %q lacks %q", badMsg, want)
		}
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
