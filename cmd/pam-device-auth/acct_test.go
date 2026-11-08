package main

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/logger"
)

var errRead = errors.New("read failed")

func TestDecideIPGate(t *testing.T) {
	cases := []struct {
		name    string
		dir     bool
		clients []string
		readErr error
		rhost   string
		allow   bool
	}{
		{"local user exempt", false, nil, nil, "1.2.3.4", true},
		{"dir no clients -> allow", true, nil, nil, "1.2.3.4", true},
		{"dir clients match -> allow", true, []string{"198.51.100.0/24"}, nil, "198.51.100.15", true},
		{"dir clients no match -> deny", true, []string{"198.51.100.0/24"}, nil, "203.0.113.1", false},
		{"dir clients read error -> fail-closed deny", true, nil, errRead, "198.51.100.15", false},
		{"dir clients empty rhost -> fail-closed deny", true, []string{"198.51.100.0/24"}, nil, "", false},
		{"local user exempt even with read error", false, nil, errRead, "1.2.3.4", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := decideIPGate(c.dir, c.clients, c.readErr, c.rhost); got != c.allow {
				t.Fatalf("decideIPGate = %v, want %v", got, c.allow)
			}
		})
	}
}

func TestRequiresIPGate(t *testing.T) {
	cases := []struct {
		name string
		user string
		want bool
	}{
		{"root is the only exemption", "root", false},
		{"directory user is gated", "nk", true},
		{"local non-root name is gated", "daemon", true},
		{"empty user is gated defensively", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := requiresIPGate(c.user); got != c.want {
				t.Fatalf("requiresIPGate(%q) = %v, want %v", c.user, got, c.want)
			}
		})
	}
}

func TestParseBusctlClients(t *testing.T) {
	// busctl --json=short GetUserAttr output shape (a{sv} clients -> string array)
	js := []byte(`{"type":"a{sv}","data":[{"clients":{"type":"as","data":["198.51.100.11","192.0.2.128/25"]}}]}`)
	got, err := parseBusctlClients(js)
	if err != nil || len(got) != 2 || got[0] != "198.51.100.11" || got[1] != "192.0.2.128/25" {
		t.Fatalf("parseBusctlClients = %v, %v", got, err)
	}

	// no clients attr -> empty, no error (live-verified shape for a directory
	// user with no "clients" attribute set)
	if g, err := parseBusctlClients([]byte(`{"type":"a{sv}","data":[{}]}`)); err != nil || len(g) != 0 {
		t.Fatalf("empty attrs = %v, %v", g, err)
	}

	// live-verified full multi-entry shape
	full := []byte(`{"type":"a{sv}","data":[{"clients":{"type":"as","data":["192.0.2.203","192.0.2.204","192.0.2.12","198.51.100.2","192.0.2.64/26"]}}]}`)
	if g, err := parseBusctlClients(full); err != nil || len(g) != 5 || g[4] != "192.0.2.64/26" {
		t.Fatalf("full clients = %v, %v", g, err)
	}

	// malformed JSON -> error
	if _, err := parseBusctlClients([]byte(`not json`)); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if _, err := parseBusctlClients([]byte(`{"type":"a{sv}","data":[]}`)); err == nil {
		t.Fatal("expected error for missing result entry")
	}
	if _, err := parseBusctlClients([]byte(`{"type":"a{sv}","data":[{"clients":{"type":"s","data":[]}}]}`)); err == nil {
		t.Fatal("expected error for unexpected clients attribute type")
	}
}

// runPamAcctWithBrokenLog runs runPamAcct for user with a logger that cannot be
// opened, a reader that fails the test if called and a captured syslog; it
// returns the exit code, everything written to stderr and the syslog messages.
func runPamAcctWithBrokenLog(t *testing.T, user string) (code int, stderr string, syslogged []string) {
	t.Helper()
	origLogger, origRead, origSyslog := newAcctLogger, readClients, syslogAuthErr
	t.Cleanup(func() { newAcctLogger, readClients, syslogAuthErr = origLogger, origRead, origSyslog })
	newAcctLogger = func(string, bool) (*logger.Logger, error) {
		return nil, errors.New("failed to open log file: read-only file system")
	}
	readClients = func(string) ([]string, error) {
		t.Error("allowlist read without an audit log")
		return nil, nil
	}
	syslogAuthErr = func(msg string) { syslogged = append(syslogged, msg) }
	t.Setenv("PAM_USER", user)
	t.Setenv("PAM_RHOST", "198.51.100.11")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStderr := os.Stderr
	t.Cleanup(func() { os.Stderr = origStderr })
	os.Stderr = w
	code = runPamAcct()
	os.Stderr = origStderr
	w.Close()
	out, _ := io.ReadAll(r)
	r.Close()
	return code, string(out), syslogged
}

// The C module (pam_device_auth.c acct_mgmt) maps 0 to allow, 1 to a per-user
// deny and every other exit code to an infrastructure failure that denies. 2 is
// Go's panic exit and the auth phase's hard deny, 127 a failed execl.
func TestAcctExitInfraFailureIsDistinct(t *testing.T) {
	switch acctExitInfraFailure {
	case 0, 1, 2, 127:
		t.Fatalf("acctExitInfraFailure = %d collides with a code that has another meaning", acctExitInfraFailure)
	}
}

func TestRunPamAcctLoggerFailureDeniesUser(t *testing.T) {
	code, stderr, syslogged := runPamAcctWithBrokenLog(t, "alice")
	if code != acctExitInfraFailure {
		t.Errorf("runPamAcct() = %d, want %d (infrastructure failure, fail closed)", code, acctExitInfraFailure)
	}
	want := "pam-device-auth: cannot open " + logFile + ": failed to open log file: read-only file system; denying"
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr, want)
	}
	if len(syslogged) != 1 || syslogged[0] != want {
		t.Errorf("syslog = %q, want exactly %q (sshd discards stderr)", syslogged, want)
	}
}

func TestRunPamAcctLoggerFailureDeniesUnsetUser(t *testing.T) {
	code, stderr, syslogged := runPamAcctWithBrokenLog(t, "")
	if code != acctExitInfraFailure || !strings.Contains(stderr, "denying") {
		t.Errorf("runPamAcct() = %d, stderr %q; want %d and a denying message", code, stderr, acctExitInfraFailure)
	}
	if len(syslogged) != 1 || !strings.Contains(syslogged[0], "denying") {
		t.Errorf("syslog = %q, want one denying message", syslogged)
	}
}

func TestRunPamAcctLoggerFailureRootAllowed(t *testing.T) {
	code, stderr, syslogged := runPamAcctWithBrokenLog(t, "root")
	if code != 0 {
		t.Errorf("runPamAcct() = %d, want 0 (root is exempt)", code)
	}
	if strings.Contains(stderr, "denying") || len(syslogged) != 1 || strings.Contains(syslogged[0], "denying") {
		t.Errorf("stderr %q / syslog %q: want one non-deny report for root", stderr, syslogged)
	}
}
