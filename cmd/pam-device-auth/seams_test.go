package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/logger"
)

// testLog returns a file-backed logger and a func that closes it and returns
// everything logged, so tests can assert on log lines.
func testLog(t *testing.T) (*logger.Logger, func() string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pda.log")
	log, err := logger.NewLogger(path, false)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	return log, func() string {
		log.Close()
		b, _ := os.ReadFile(path)
		return string(b)
	}
}

func TestPamAccount_DecisionTable(t *testing.T) {
	boom := errors.New("ifp down")
	cases := []struct {
		name        string
		user, rhost string
		clients     []string
		readErr     error
		want        int
		wantRead    bool
	}{
		{"PAM_USER unset denies", "", "10.0.0.1", nil, nil, 1, false},
		{"root is exempt and never reads", "root", "203.0.113.9", nil, nil, 0, false},
		{"read error fails closed", "nk", "10.0.0.1", nil, boom, 1, true},
		{"empty allowlist is unrestricted", "nk", "10.0.0.1", nil, nil, 0, true},
		{"ip match allows", "nk", "10.0.20.2", []string{"10.0.20.2"}, nil, 0, true},
		{"cidr match allows", "nk", "10.0.20.77", []string{"10.0.20.0/24"}, nil, 0, true},
		{"no match denies", "nk", "192.168.1.5", []string{"10.0.20.0/24"}, nil, 1, true},
		{"empty rhost denies when an allowlist is set", "nk", "", []string{"10.0.20.2"}, nil, 1, true},
		{"service account is gated too", "svc-backup", "192.0.2.99", []string{"192.0.2.70"}, nil, 1, true},
		{"local non-root user is gated, not exempt", "daemon", "10.0.0.1", nil, boom, 1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			log, done := testLog(t)
			called := false
			got := pamAccount(log, c.user, c.rhost, func(string) ([]string, error) {
				called = true
				return c.clients, c.readErr
			})
			done()
			if got != c.want {
				t.Errorf("pamAccount() = %d, want %d", got, c.want)
			}
			if called != c.wantRead {
				t.Errorf("allowlist read called = %v, want %v", called, c.wantRead)
			}
		})
	}
}

// A typo in the directory attribute must be visible in the log, and a valid
// entry next to it must still be honoured.
func TestPamAccount_LogsInvalidAllowlistEntries(t *testing.T) {
	log, done := testLog(t)
	got := pamAccount(log, "nk", "10.0.20.2", func(string) ([]string, error) {
		return []string{"10.0.20.0/33", "not-an-ip", "10.0.20.2"}, nil
	})
	out := done()
	if got != 0 {
		t.Errorf("valid entry next to invalid ones must still allow, got %d", got)
	}
	if !strings.Contains(out, "10.0.20.0/33") || !strings.Contains(out, "not-an-ip") || !strings.Contains(out, "invalid") {
		t.Errorf("log does not name the invalid entries:\n%s", out)
	}

	// With only invalid entries the user is denied, and the log says why.
	log, done = testLog(t)
	if got := pamAccount(log, "nk", "10.0.20.2", func(string) ([]string, error) {
		return []string{"10.0.20.0/33"}, nil
	}); got != 1 {
		t.Errorf("only invalid entries must deny, got %d", got)
	}
	if out := done(); !strings.Contains(out, "10.0.20.0/33") {
		t.Errorf("deny log does not name the invalid entry:\n%s", out)
	}
}

func TestInvalidAllowlistEntries(t *testing.T) {
	in := []string{"10.0.0.1", "10.0.0.0/24", "::1", "fd00::/8", "10.0.0.0/33", "10.0.0", "host.example", "", "10.0.0.1/abc"}
	want := []string{"10.0.0.0/33", "10.0.0", "host.example", "", "10.0.0.1/abc"}
	if got := invalidAllowlistEntries(in); !reflect.DeepEqual(got, want) {
		t.Errorf("invalidAllowlistEntries() = %q, want %q", got, want)
	}
	if got := invalidAllowlistEntries(nil); len(got) != 0 {
		t.Errorf("nil allowlist = %q, want none", got)
	}
}

func TestIdentityGate(t *testing.T) {
	boom := errors.New("signal: killed")
	cases := []struct {
		name      string
		found     bool
		err       error
		allow     bool
		logHas    string
		bannerHas string
	}{
		{"resolves", true, nil, true, "", ""},
		{"unknown user", false, nil, false, "does not resolve via NSS", "no directory identity"},
		{"SSSD outage is not 'unknown user'", false, boom, false, "SSSD unavailable", "directory lookup failed"},
		{"error wins over found", true, boom, false, "SSSD unavailable", "directory lookup failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			allow, logMsg, banner := identityGate("nk", c.found, c.err)
			if allow != c.allow {
				t.Fatalf("allow = %v, want %v", allow, c.allow)
			}
			if !strings.Contains(logMsg, c.logHas) || !strings.Contains(banner, c.bannerHas) {
				t.Errorf("logMsg=%q banner=%q, want %q / %q", logMsg, banner, c.logHas, c.bannerHas)
			}
			if c.err != nil && strings.Contains(logMsg, "does not resolve") {
				t.Errorf("an outage must not be reported as a missing account: %q", logMsg)
			}
		})
	}
}

func TestClassifyMembers(t *testing.T) {
	status := map[string]string{"a": "ok", "b": "none", "c": "invalid", "d": "error", "e": "none", "f": "error"}
	noKey, badKey, errKey := classifyMembers([]string{"a", "b", "c", "d", "e", "f"}, func(m string) string { return status[m] })
	if !reflect.DeepEqual(noKey, []string{"b", "e"}) || !reflect.DeepEqual(badKey, []string{"c"}) || !reflect.DeepEqual(errKey, []string{"d", "f"}) {
		t.Errorf("classifyMembers() = %q %q %q", noKey, badKey, errKey)
	}
}

func fakeRunner(results map[string]error, out map[string]string, log *[]string) commandRunner {
	return func(name string, args ...string) ([]byte, error) {
		key := name + " " + strings.Join(args, " ")
		*log = append(*log, key)
		return []byte(out[key]), results[key]
	}
}

func TestRestartSSH(t *testing.T) {
	const ssh, sshd = "systemctl restart ssh.service", "systemctl restart sshd.service"
	fail := errors.New("exit status 5")

	var calls []string
	if err := restartSSH(fakeRunner(nil, nil, &calls)); err != nil {
		t.Fatalf("ssh.service ok: %v", err)
	}
	if !reflect.DeepEqual(calls, []string{ssh}) {
		t.Errorf("calls = %q, want only ssh.service", calls)
	}

	calls = nil
	if err := restartSSH(fakeRunner(map[string]error{ssh: fail}, map[string]string{ssh: "Unit ssh.service not found."}, &calls)); err != nil {
		t.Fatalf("RHEL fallback to sshd.service: %v", err)
	}
	if !reflect.DeepEqual(calls, []string{ssh, sshd}) {
		t.Errorf("calls = %q, want ssh then sshd", calls)
	}

	calls = nil
	err := restartSSH(fakeRunner(map[string]error{ssh: fail, sshd: fail},
		map[string]string{ssh: "not found", sshd: "config invalid"}, &calls))
	if !errors.Is(err, errSSHRestart) {
		t.Fatalf("both fail: err = %v, want errSSHRestart", err)
	}
	if !strings.Contains(err.Error(), "not found") || !strings.Contains(err.Error(), "config invalid") {
		t.Errorf("error lacks the units' output: %v", err)
	}
}

func TestActivatePAM(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "sshd")
	backup := filepath.Join(dir, "sshd.original")
	tmpl := filepath.Join(dir, "template")
	mustWrite := func(p, s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(conf, "auth required pam_unix.so\n")
	mustWrite(tmpl, "auth required pam_device_auth.so\n")

	var warn bytes.Buffer
	if err := activatePAM(conf, backup, tmpl, &warn); err != nil {
		t.Fatalf("activatePAM: %v", err)
	}
	if got, _ := os.ReadFile(conf); string(got) != "auth required pam_device_auth.so\n" {
		t.Errorf("PAM stack not switched: %q", got)
	}
	if got, _ := os.ReadFile(backup); string(got) != "auth required pam_unix.so\n" {
		t.Errorf("backup is not the pristine original: %q", got)
	}
	if st, _ := os.Stat(conf); st.Mode().Perm() != 0644 {
		t.Errorf("PAM stack mode = %v, want 0644", st.Mode().Perm())
	}
	if warn.Len() != 0 {
		t.Errorf("unexpected warning: %s", warn.String())
	}
	// No temp files may be left behind by the atomic write.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}

	// Re-run on the already wired stack: the pristine backup must survive and
	// activation must still succeed.
	if err := activatePAM(conf, backup, tmpl, &warn); err != nil {
		t.Fatalf("re-activate: %v", err)
	}
	if got, _ := os.ReadFile(backup); string(got) != "auth required pam_unix.so\n" {
		t.Errorf("backup overwritten on re-run: %q", got)
	}

	// Unreadable template: error, and the live PAM stack is untouched.
	before, _ := os.ReadFile(conf)
	if err := activatePAM(conf, backup, filepath.Join(dir, "missing-template"), &warn); err == nil {
		t.Fatal("activatePAM with a missing template = nil error")
	}
	if after, _ := os.ReadFile(conf); !bytes.Equal(before, after) {
		t.Error("PAM stack modified although the template was unreadable")
	}
}

// With no backup and an already wired source the operator is warned, activation
// still proceeds.
func TestActivatePAM_WarnsWhenNoPristineBackup(t *testing.T) {
	dir := t.TempDir()
	conf, backup, tmpl := filepath.Join(dir, "sshd"), filepath.Join(dir, "sshd.original"), filepath.Join(dir, "template")
	for p, s := range map[string]string{conf: "auth required pam_device_auth.so\n", tmpl: "auth required pam_device_auth.so\n# new\n"} {
		if err := os.WriteFile(p, []byte(s), 0644); err != nil {
			t.Fatal(err)
		}
	}
	var warn bytes.Buffer
	if err := activatePAM(conf, backup, tmpl, &warn); err != nil {
		t.Fatalf("activatePAM: %v", err)
	}
	if !strings.Contains(warn.String(), "could not back up") {
		t.Errorf("no backup warning: %q", warn.String())
	}
	if _, err := os.Stat(backup); err == nil {
		t.Error("a backup of the already modified stack was written")
	}
}

func TestRunEnableSteps_Order(t *testing.T) {
	var order []string
	step := func(name string, err error) func() error {
		return func() error { order = append(order, name); return err }
	}
	boom := errors.New("boom")

	order = nil
	if err := runEnableSteps(enableSteps{step("dropin", nil), step("pam", nil), step("restart", nil)}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"dropin", "pam", "restart"}) {
		t.Errorf("order = %q", order)
	}

	// A rejected drop-in must not be followed by a PAM switch or an sshd restart.
	order = nil
	err := runEnableSteps(enableSteps{step("dropin", boom), step("pam", nil), step("restart", nil)})
	if !errors.Is(err, boom) || !reflect.DeepEqual(order, []string{"dropin"}) {
		t.Errorf("drop-in failure: err=%v order=%q; want boom and only the drop-in step", err, order)
	}

	// A failed PAM write must not restart sshd.
	order = nil
	err = runEnableSteps(enableSteps{step("dropin", nil), step("pam", boom), step("restart", nil)})
	if !errors.Is(err, boom) || !reflect.DeepEqual(order, []string{"dropin", "pam"}) {
		t.Errorf("pam failure: err=%v order=%q", err, order)
	}

	// A failed restart is reported to the caller as such.
	order = nil
	restartErr := errors.Join(errSSHRestart, boom)
	err = runEnableSteps(enableSteps{step("dropin", nil), step("pam", nil), step("restart", restartErr)})
	if !errors.Is(err, errSSHRestart) {
		t.Errorf("restart failure not surfaced: %v", err)
	}
}

func TestLogInitFailureMessage(t *testing.T) {
	msg := logInitFailureMessage(errors.New("permission denied"))
	for _, want := range []string{logFile, "permission denied", "fail closed"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q lacks %q", msg, want)
		}
	}
}

func TestSetupWarnf_CollectsForSummary(t *testing.T) {
	old := setupWarnings
	setupWarnings = nil
	t.Cleanup(func() { setupWarnings = old })
	setupWarnf("mkhomedir failed: %v", errors.New("x"))
	setupWarnf("second")
	if len(setupWarnings) != 2 || !strings.Contains(setupWarnings[0], "mkhomedir failed: x") {
		t.Errorf("setupWarnings = %q", setupWarnings)
	}
}
