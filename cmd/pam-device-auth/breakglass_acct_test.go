package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/logger"
)

const bgPasswd = "root:x:0:0:root:/root:/bin/bash\n" +
	"breakglass:x:1001:1002::/home/breakglass:/bin/bash\n" +
	"broken:x\n"

func lookupYes(string) (bool, error)  { return true, nil }
func lookupNo(string) (bool, error)   { return false, nil }
func lookupFail(string) (bool, error) { return false, errors.New("signal: killed") }

// A listed account is allowed on local facts alone: it has a local entry, it
// comes from an allowed address, and the directory does not know the name.
// Only a positive answer of the directory denies; no answer does not.
func TestBreakGlassVerdict(t *testing.T) {
	bg := config.BreakGlass{Users: []string{"breakglass"}}
	src := config.BreakGlass{Users: []string{"breakglass"}, Sources: []string{"192.0.2.0/24", "2001:db8:1::/48"}}
	for _, c := range []struct {
		name       string
		bg         config.BreakGlass
		rhost      string
		local, sss func(string) (bool, error)
		allow      bool
		level, msg string // msg: a part of the log line
	}{
		{"local only", bg, "203.0.113.9", lookupYes, lookupNo, true, "info", "local break-glass account; exempt, allow"},
		{"directory does not answer", bg, "203.0.113.9", lookupYes, lookupFail, true, "warn", "directory lookup failed (signal: killed), treated as not in the directory"},
		{"name also in the directory", bg, "203.0.113.9", lookupYes, lookupYes, false, "error", "the name also resolves in the directory"},
		{"no local entry", bg, "203.0.113.9", lookupNo, lookupNo, false, "error", "has no entry in /etc/passwd"},
		{"passwd unreadable", bg, "203.0.113.9", lookupFail, lookupNo, false, "error", "cannot read /etc/passwd"},
		{"inside a source", src, "192.0.2.77", lookupYes, lookupNo, true, "info", "exempt, allow"},
		{"inside the IPv6 source", src, "2001:db8:1::5", lookupYes, lookupNo, true, "info", "exempt, allow"},
		{"IPv4 client reported as mapped IPv6", src, "::ffff:192.0.2.77", lookupYes, lookupNo, true, "info", "exempt, allow"},
		{"outside the sources", src, "203.0.113.9", lookupYes, lookupNo, false, "warn", "not in break_glass_sources"},
		{"no client address", src, "", lookupYes, lookupNo, false, "warn", "not in break_glass_sources"},
		{"host name instead of an address", src, "client.example.com", lookupYes, lookupNo, false, "warn", "not in break_glass_sources"},
	} {
		v := breakGlassVerdict("breakglass", c.rhost, c.bg, c.local, c.sss)
		if v.allow != c.allow || v.level != c.level || !strings.Contains(v.msg, c.msg) {
			t.Errorf("%s: verdict = %+v, want allow=%v level=%s msg containing %q", c.name, v, c.allow, c.level, c.msg)
		}
	}
}

func TestPasswdEntry(t *testing.T) {
	uid, gid, home, ok := passwdEntry([]byte(bgPasswd), "breakglass")
	if !ok || uid != 1001 || gid != 1002 || home != "/home/breakglass" {
		t.Errorf("passwdEntry(breakglass) = %d, %d, %q, %v; want 1001, 1002, /home/breakglass, true", uid, gid, home, ok)
	}
	for _, name := range []string{"break", "broken", "", "alice"} {
		if _, _, _, ok := passwdEntry([]byte(bgPasswd), name); ok {
			t.Errorf("passwdEntry(%q) found an entry", name)
		}
	}
}

func TestLocalAccount(t *testing.T) {
	orig := passwdFile
	t.Cleanup(func() { passwdFile = orig })
	passwdFile = filepath.Join(t.TempDir(), "passwd")
	if _, err := localAccount("breakglass"); err == nil {
		t.Error("a missing passwd file must be an error, not 'no such account'")
	}
	if err := os.WriteFile(passwdFile, []byte(bgPasswd), 0644); err != nil {
		t.Fatal(err)
	}
	if ok, err := localAccount("breakglass"); err != nil || !ok {
		t.Errorf("localAccount(breakglass) = %v, %v; want true", ok, err)
	}
	if ok, err := localAccount("alice"); err != nil || ok {
		t.Errorf("localAccount(alice) = %v, %v; want false", ok, err)
	}
}

// The exemption is for the listed accounts only: every other user, local or
// from the directory, takes the path of 0.7.2.
func TestPamAccount_BreakGlass(t *testing.T) {
	bg := config.BreakGlass{Users: []string{"breakglass"}}
	boom := errors.New("ifp down")
	for _, c := range []struct {
		name     string
		user     string
		sss      func(string) (bool, error)
		readErr  error
		want     int
		wantRead bool
		wantLog  string
	}{
		// rescue was taken out of the config, but its block is still in the
		// drop-in: sshd accepts its local key without OIDC. The login is denied
		// before clients is read, also when the directory knows the name (the
		// clients read then succeeds and would allow).
		{"block left in the drop-in for an unlisted name: denied", "rescue", lookupYes, nil, 1, false, "ERROR pam-acct: user=rescue has a break-glass block in the sshd drop-in but is not in break_glass_users; deny (run 'pam-device-auth --enable')"},
		{"listed, local, not in the directory: exempt", "breakglass", lookupNo, boom, 0, false, "INFO pam-acct: user=breakglass local break-glass account; exempt, allow"},
		{"listed, name also in the directory: denied", "breakglass", lookupYes, nil, 1, false, "ERROR pam-acct: user=breakglass is a break-glass account but the name also resolves in the directory"},
		{"listed, directory does not answer: exempt with a warning", "breakglass", lookupFail, boom, 0, false, "WARN pam-acct: user=breakglass local break-glass account; directory lookup failed"},
		{"unlisted local account stays gated", "daemon", lookupNo, boom, 1, true, "clients read failed, fail-closed deny"},
		{"directory user is gated as before", "alice", lookupNo, nil, 0, true, "no clients allowlist set"},
		{"root stays exempt", "root", lookupNo, boom, 0, false, "user=root; exempt"},
	} {
		log, done := testLog(t)
		called := false
		got := pamAccount(log, c.user, "203.0.113.9", acctInputs{
			read:  func(string) ([]string, error) { called = true; return nil, c.readErr },
			bg:    bg,
			local: lookupYes,
			sss:   c.sss,
			block: func() []string { return []string{"breakglass", "rescue"} },
		})
		text := done()
		if got != c.want || called != c.wantRead {
			t.Errorf("%s: pamAccount = %d (clients read: %v), want %d (%v)", c.name, got, called, c.want, c.wantRead)
		}
		if !strings.Contains(strings.Join(strings.Fields(text), " "), c.wantLog) {
			t.Errorf("%s: log lacks %q:\n%s", c.name, c.wantLog, text)
		}
	}
}

// SSSD that is running but does not answer must not hold the login: the
// lookup ends at its limit with an error, which the verdict turns into an
// allow. The C module would end the helper after 7 s and deny.
func TestSSSLookupTimesOut(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "getent"), []byte("#!/bin/sh\nexec sleep 30\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	start := time.Now()
	found, err := sssLookup("breakglass", 200*time.Millisecond)
	if found || err == nil {
		t.Errorf("sssLookup = %v, %v; want not found and an error", found, err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("sssLookup took %s with a limit of 200ms", took)
	}
	if breakGlassLookupTimeout > 3*time.Second {
		t.Errorf("breakGlassLookupTimeout = %s; it must stay well below the 7 s of the PAM module", breakGlassLookupTimeout)
	}
}

// stubBreakGlassHost makes breakglass a local account and answers the
// directory lookup with inDirectory.
func stubBreakGlassHost(t *testing.T, inDirectory bool) {
	t.Helper()
	origPasswd, origSSS, origDropin := passwdFile, breakGlassSSS, sshdDropinPath
	t.Cleanup(func() { passwdFile, breakGlassSSS, sshdDropinPath = origPasswd, origSSS, origDropin })
	// Never the drop-in of the host the tests run on.
	sshdDropinPath = filepath.Join(t.TempDir(), "10-pam-device-auth.conf")
	passwdFile = filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(passwdFile, []byte(bgPasswd), 0644); err != nil {
		t.Fatal(err)
	}
	breakGlassSSS = func(string) (bool, error) { return inDirectory, nil }
}

// A log that cannot be opened must not lock the emergency account out: like
// root it is decided without the audit log, and syslog gets the report.
func TestRunPamAcctLoggerFailureBreakGlassAllowed(t *testing.T) {
	stubBreakGlassHost(t, false)
	code, _, syslogged := runPamAcctWithBrokenLog(t, "breakglass", config.BreakGlass{Users: []string{"breakglass"}})
	if code != 0 {
		t.Errorf("runPamAcct() = %d, want 0 (break-glass account)", code)
	}
	if len(syslogged) != 1 || !strings.Contains(syslogged[0], "break-glass account breakglass is exempt, allowing") {
		t.Errorf("syslog = %q, want one line that allows the break-glass account", syslogged)
	}
}

func TestRunPamAcctLoggerFailureBreakGlassDenied(t *testing.T) {
	stubBreakGlassHost(t, true)
	code, _, syslogged := runPamAcctWithBrokenLog(t, "breakglass", config.BreakGlass{Users: []string{"breakglass"}})
	if code != acctExitInfraFailure {
		t.Errorf("runPamAcct() = %d, want %d", code, acctExitInfraFailure)
	}
	all := strings.Join(syslogged, "\n")
	if !strings.Contains(all, "the name also resolves in the directory") || !strings.Contains(all, "denying") {
		t.Errorf("syslog = %q, want the reason and a denying line", syslogged)
	}
}

// A config that cannot be read gives nobody the exemption, and the log says so.
func TestRunPamAcctBreakGlassLoadError(t *testing.T) {
	stubBreakGlassHost(t, false)
	origLogger, origRead, origLoad := newAcctLogger, readClients, loadBreakGlass
	t.Cleanup(func() { newAcctLogger, readClients, loadBreakGlass = origLogger, origRead, origLoad })
	logPath := filepath.Join(t.TempDir(), "pda.log")
	newAcctLogger = func(string, bool) (*logger.Logger, error) { return logger.NewLogger(logPath, false) }
	readClients = func(string) ([]string, error) { return nil, errors.New("ifp down") }
	loadBreakGlass = func(string) (config.BreakGlass, error) {
		return config.BreakGlass{}, errors.New("parse config: unexpected end of JSON input")
	}
	t.Setenv("PAM_USER", "breakglass")
	t.Setenv("PAM_RHOST", "198.51.100.11")

	if code := runPamAcct(); code != 1 {
		t.Errorf("runPamAcct() = %d, want 1: without the list the account is a local account like any other", code)
	}
	text, _ := os.ReadFile(logPath)
	for _, want := range []string{"break_glass_users not read, no break-glass exemption: parse config", "clients read failed, fail-closed deny"} {
		if !strings.Contains(string(text), want) {
			t.Errorf("log lacks %q:\n%s", want, text)
		}
	}
}
