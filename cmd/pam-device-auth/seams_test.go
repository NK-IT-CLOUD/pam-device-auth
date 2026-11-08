package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/distro"
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
		{"PAM_USER unset denies", "", "198.51.100.11", nil, nil, 1, false},
		{"root is exempt and never reads", "root", "203.0.113.9", nil, nil, 0, false},
		{"read error fails closed", "nk", "198.51.100.11", nil, boom, 1, true},
		{"empty allowlist is unrestricted", "nk", "198.51.100.11", nil, nil, 0, true},
		{"ip match allows", "nk", "198.51.100.2", []string{"198.51.100.2"}, nil, 0, true},
		{"cidr match allows", "nk", "198.51.100.77", []string{"198.51.100.0/24"}, nil, 0, true},
		{"no match denies", "nk", "203.0.113.5", []string{"198.51.100.0/24"}, nil, 1, true},
		{"empty rhost denies when an allowlist is set", "nk", "", []string{"198.51.100.2"}, nil, 1, true},
		{"service account is gated too", "svc-backup", "192.0.2.99", []string{"192.0.2.70"}, nil, 1, true},
		{"local non-root user is gated, not exempt", "daemon", "198.51.100.11", nil, boom, 1, true},
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
	got := pamAccount(log, "nk", "198.51.100.2", func(string) ([]string, error) {
		return []string{"198.51.100.0/33", "not-an-ip", "198.51.100.2"}, nil
	})
	out := done()
	if got != 0 {
		t.Errorf("valid entry next to invalid ones must still allow, got %d", got)
	}
	if !strings.Contains(out, "198.51.100.0/33") || !strings.Contains(out, "not-an-ip") || !strings.Contains(out, "invalid") {
		t.Errorf("log does not name the invalid entries:\n%s", out)
	}

	// With only invalid entries the user is denied, and the log says why.
	log, done = testLog(t)
	if got := pamAccount(log, "nk", "198.51.100.2", func(string) ([]string, error) {
		return []string{"198.51.100.0/33"}, nil
	}); got != 1 {
		t.Errorf("only invalid entries must deny, got %d", got)
	}
	if out := done(); !strings.Contains(out, "198.51.100.0/33") {
		t.Errorf("deny log does not name the invalid entry:\n%s", out)
	}
}

func TestInvalidAllowlistEntries(t *testing.T) {
	in := []string{"198.51.100.11", "198.51.100.0/24", "::1", "fd00::/8", "198.51.100.0/33", "198.51.100", "host.example", "", "198.51.100.11/abc"}
	want := []string{"198.51.100.0/33", "198.51.100", "host.example", "", "198.51.100.11/abc"}
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
	fail := errors.New("exit status 5")
	for _, unit := range []string{"ssh.service", "sshd.service"} {
		t.Run(unit, func(t *testing.T) {
			cmd := "systemctl restart " + unit

			var calls []string
			if err := restartSSH(fakeRunner(nil, nil, &calls), unit); err != nil {
				t.Fatalf("restart ok: %v", err)
			}
			if !reflect.DeepEqual(calls, []string{cmd}) {
				t.Errorf("calls = %q, want only %q", calls, cmd)
			}

			// A failed restart is an error; no other unit is tried.
			calls = nil
			err := restartSSH(fakeRunner(map[string]error{cmd: fail}, map[string]string{cmd: "config invalid"}, &calls), unit)
			if !errors.Is(err, errSSHRestart) {
				t.Fatalf("restart fails: err = %v, want errSSHRestart", err)
			}
			if !strings.Contains(err.Error(), unit) || !strings.Contains(err.Error(), "config invalid") {
				t.Errorf("error lacks the unit or its output: %v", err)
			}
			if !reflect.DeepEqual(calls, []string{cmd}) {
				t.Errorf("calls = %q, want only %q", calls, cmd)
			}
		})
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

	if err := activatePAM(conf, tmpl); err != nil {
		t.Fatalf("activatePAM: %v", err)
	}
	if got, _ := os.ReadFile(conf); string(got) != "auth required pam_device_auth.so\n" {
		t.Errorf("PAM stack not switched: %q", got)
	}
	if st, _ := os.Stat(conf); st.Mode().Perm() != 0644 {
		t.Errorf("PAM stack mode = %v, want 0644", st.Mode().Perm())
	}
	// activatePAM only installs the template; the backup is backupPAM's step.
	if _, err := os.Lstat(backup); !os.IsNotExist(err) {
		t.Errorf("activatePAM wrote a backup (err=%v)", err)
	}
	// No temp files may be left behind by the atomic write.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}

	// Unreadable template: error, and the live PAM stack is untouched.
	before, _ := os.ReadFile(conf)
	if err := activatePAM(conf, filepath.Join(dir, "missing-template")); err == nil {
		t.Fatal("activatePAM with a missing template = nil error")
	}
	if after, _ := os.ReadFile(conf); !bytes.Equal(before, after) {
		t.Error("PAM stack modified although the template was unreadable")
	}
}

// backupPAM saves the pristine /etc/pam.d/sshd once; a re-run of --enable on
// the wired stack keeps the existing valid backup as it is.
func TestBackupPAM(t *testing.T) {
	dir := t.TempDir()
	conf, backup := filepath.Join(dir, "sshd"), filepath.Join(dir, "sshd.original")
	if err := os.WriteFile(conf, []byte("@include common-auth\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := backupPAM(conf, backup); err != nil {
		t.Fatalf("backupPAM: %v", err)
	}
	if got, _ := os.ReadFile(backup); string(got) != "@include common-auth\n" {
		t.Errorf("backup is not the pristine original: %q", got)
	}
	// Re-run after activation: the stack is wired, the backup stays.
	if err := os.WriteFile(conf, []byte("auth required pam_device_auth.so\n"), 0644); err != nil {
		t.Fatal(err)
	}
	mt := mtimeOf(t, backup)
	if err := backupPAM(conf, backup); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if got, _ := os.ReadFile(backup); string(got) != "@include common-auth\n" || !mtimeOf(t, backup).Equal(mt) {
		t.Errorf("backup touched on re-run: %q", got)
	}
}

// Without a valid rollback copy --enable must not start: every case is an
// error that names the manual step, and nothing is written.
func TestBackupPAM_RefusesWithoutValidBackup(t *testing.T) {
	const restoreHint = "restore <conf> from your distribution's openssh-server package"
	const absent = "<absent>"
	for _, c := range []struct {
		name, conf, backup string
		want               []string
	}{
		{"missing source", absent, absent, []string{"does not exist", restoreHint, "nothing was changed"}},
		{"wired source, no backup", "auth required pam_device_auth.so\n", absent, []string{"contains pam_device_auth.so", restoreHint}},
		{"empty source", "", absent, []string{"is empty", restoreHint}},
		{"source without auth line", "# comment\n", absent, []string{"no line starting with auth or @include", restoreHint}},
		{"polluted backup", "@include common-auth\n", "auth required pam_device_auth.so\n", []string{"existing backup", "contains pam_device_auth.so", restoreHint}},
		{"empty backup", "auth required pam_device_auth.so\n", "", []string{"existing backup", "is empty", restoreHint}},
		{"backup without auth line", "@include common-auth\n", "# nothing\n", []string{"existing backup", "no line starting with auth or @include"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			conf, backup := filepath.Join(dir, "sshd"), filepath.Join(dir, "sshd.original")
			for p, s := range map[string]string{conf: c.conf, backup: c.backup} {
				if s == absent {
					continue
				}
				if err := os.WriteFile(p, []byte(s), 0644); err != nil {
					t.Fatal(err)
				}
			}
			err := backupPAM(conf, backup)
			if err == nil {
				t.Fatal("backupPAM = nil, want an error")
			}
			for _, w := range append(c.want, "cannot back up "+conf+" to "+backup) {
				if w = strings.ReplaceAll(w, "<conf>", conf); !strings.Contains(err.Error(), w) {
					t.Errorf("error %q lacks %q", err, w)
				}
			}
			for p, s := range map[string]string{conf: c.conf, backup: c.backup} {
				got, rerr := os.ReadFile(p)
				if s == absent && !os.IsNotExist(rerr) || s != absent && string(got) != s {
					t.Errorf("%s changed: %q (err=%v)", p, got, rerr)
				}
			}
		})
	}

	// An I/O failure is no content problem: the message carries the cause, not
	// the restore hint.
	dir := t.TempDir()
	conf := filepath.Join(dir, "sshd")
	if err := os.WriteFile(conf, []byte("@include common-auth\n"), 0644); err != nil {
		t.Fatal(err)
	}
	err := backupPAM(conf, filepath.Join(dir, "missing-subdir", "sshd.original"))
	if err == nil || strings.Contains(err.Error(), "openssh-server") || !strings.Contains(err.Error(), "nothing was changed") {
		t.Errorf("unwritable backup: err = %v, want the cause without the restore hint", err)
	}
}

// A backup that is in place but whose directory sync failed is a valid copy:
// the error says so instead of "nothing was changed".
func TestBackupPAM_DirSyncFailure(t *testing.T) {
	stubSyncDir(t, func(dir string) error { return &os.PathError{Op: "sync", Path: dir, Err: syscall.EIO} })
	dir := t.TempDir()
	conf, backup := filepath.Join(dir, "sshd"), filepath.Join(dir, "sshd.original")
	if err := os.WriteFile(conf, []byte("@include common-auth\n"), 0644); err != nil {
		t.Fatal(err)
	}
	err := backupPAM(conf, backup)
	if err == nil || strings.Contains(err.Error(), "nothing was changed") ||
		!strings.Contains(err.Error(), backup+" is in place as a valid copy of "+conf+"; nothing else was changed") {
		t.Fatalf("err = %v, want the in-place backup named", err)
	}
	if got, _ := os.ReadFile(backup); string(got) != "@include common-auth\n" {
		t.Errorf("backup = %q, want the copy in place", got)
	}
}

func TestRunEnableSteps_Order(t *testing.T) {
	var order []string
	step := func(name string, err error) func() error {
		return func() error { order = append(order, name); return err }
	}
	boom := errors.New("boom")

	order = nil
	if err := runEnableSteps(enableSteps{step("backup", nil), step("dropin", nil), step("pam", nil), step("restart", nil)}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"backup", "dropin", "pam", "restart"}) {
		t.Errorf("order = %q", order)
	}

	// Without a valid PAM backup nothing is written: no drop-in, no PAM
	// switch, no restart.
	order = nil
	err := runEnableSteps(enableSteps{step("backup", boom), step("dropin", nil), step("pam", nil), step("restart", nil)})
	if !errors.Is(err, boom) || !reflect.DeepEqual(order, []string{"backup"}) {
		t.Errorf("backup failure: err=%v order=%q; want boom and only the backup step", err, order)
	}

	// A rejected drop-in must not be followed by a PAM switch or an sshd restart.
	order = nil
	err = runEnableSteps(enableSteps{step("backup", nil), step("dropin", boom), step("pam", nil), step("restart", nil)})
	if !errors.Is(err, boom) || !reflect.DeepEqual(order, []string{"backup", "dropin"}) {
		t.Errorf("drop-in failure: err=%v order=%q; want boom and no step after the drop-in", err, order)
	}

	// A failed PAM write must not restart sshd.
	order = nil
	err = runEnableSteps(enableSteps{step("backup", nil), step("dropin", nil), step("pam", boom), step("restart", nil)})
	if !errors.Is(err, boom) || !reflect.DeepEqual(order, []string{"backup", "dropin", "pam"}) {
		t.Errorf("pam failure: err=%v order=%q", err, order)
	}

	// A failed restart is reported to the caller as such.
	order = nil
	restartErr := errors.Join(errSSHRestart, boom)
	err = runEnableSteps(enableSteps{step("backup", nil), step("dropin", nil), step("pam", nil), step("restart", restartErr)})
	if !errors.Is(err, errSSHRestart) {
		t.Errorf("restart failure not surfaced: %v", err)
	}
}

func TestLogFailureMessage(t *testing.T) {
	msg := logFailureMessage(errors.New("permission denied"), "denying login (fail closed)")
	want := "pam-device-auth: cannot open " + logFile + ": permission denied; denying login (fail closed)"
	if msg != want {
		t.Errorf("message = %q, want %q", msg, want)
	}
}

// A chmod failure is not an open failure: the message says chmod and names the
// path once (the *os.PathError already carries it).
func TestLogFailureMessageChmod(t *testing.T) {
	err := fmt.Errorf("%w: %w", logger.ErrLogMode, &os.PathError{Op: "chmod", Path: logFile, Err: errors.New("operation not permitted")})
	msg := logFailureMessage(err, "denying login (fail closed)")
	want := "pam-device-auth: cannot set log file mode 0640: chmod " + logFile + ": operation not permitted; denying login (fail closed)"
	if msg != want {
		t.Errorf("message = %q, want %q", msg, want)
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

// On an unsupported platform --enable, --check and --setup-ldap must refuse
// as their first step, before the config is loaded and before any write. The
// commands exit the process, so each runs in a child test binary. The child is
// fail-safe: every side-effecting stage reachable from the commands is stubbed
// to abort with exit code 99 and a marker line, and loadConfig (the first stage
// after the platform check in all three) aborts too, so a regression that
// moves the platform check stops there instead of touching the host. The
// "guard" mode lets detection succeed and proves the child hits a stub.
func TestCommands_RefuseUnsupportedPlatformFirst(t *testing.T) {
	const abortMarker = "PDA_TEST_ABORT:"
	if mode := os.Getenv("PDA_TEST_PLATFORM_CHILD"); mode != "" {
		abort := func(stage string) {
			fmt.Fprintln(os.Stderr, abortMarker, stage)
			os.Exit(99)
		}
		loadConfig = func(string) (*config.Config, error) { abort("config"); return nil, nil }
		runPreflightFn = func(distro.Profile) (int, int) { abort("preflight"); return 0, 0 }
		runEnableStepsFn = func(enableSteps) error { abort("enable steps"); return nil }
		systemctl = func(...string) (string, error) { abort("systemctl"); return "", nil }
		sshdTOutput = func(...string) ([]byte, error) { abort("sshd -T"); return nil, nil }
		sshdTest = func() ([]byte, error) { abort("sshd -t"); return nil, nil }
		readClients = func(string) ([]string, error) { abort("readClients"); return nil, nil }
		sshdDropinPath = filepath.Join(t.TempDir(), "10-pam-device-auth.conf")
		cmdName, platform, _ := strings.Cut(mode, ":")
		detectPlatform = func() (distro.Profile, error) {
			if platform == "guard" {
				return distro.Profile{Family: "debian"}, nil
			}
			return distro.Profile{}, fmt.Errorf("%w %q", distro.ErrUnsupported, "alpine 3.24.4")
		}
		switch cmdName {
		case "enable":
			runEnable()
		case "check":
			runCheck()
		case "setup-ldap":
			runSetupLDAP()
		}
		abort(cmdName + " returned")
	}
	runChild := func(t *testing.T, mode string) (code int, stdout, stderr string) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestCommands_RefuseUnsupportedPlatformFirst$")
		cmd.Env = append(os.Environ(), "PDA_TEST_PLATFORM_CHILD="+mode)
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err := cmd.Run()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("child (%s): err=%v, want a non-zero exit; stderr=%q", mode, err, errOut.String())
		}
		return exitErr.ExitCode(), out.String(), errOut.String()
	}

	for _, c := range []struct{ cmd, guardStage string }{
		{"enable", "preflight"},
		{"check", "config"},
		{"setup-ldap", "config"},
	} {
		t.Run(c.cmd+": unsupported platform refuses first", func(t *testing.T) {
			code, stdout, stderr := runChild(t, c.cmd+":unsupported")
			if strings.Contains(stderr, abortMarker) {
				t.Fatalf("--%s reached a side-effecting stage before refusing: %q", c.cmd, stderr)
			}
			if code != 1 {
				t.Fatalf("exit code = %d, want 1; stderr=%q", code, stderr)
			}
			if !strings.Contains(stderr, `FAIL: unsupported distribution "alpine 3.24.4"`) {
				t.Errorf("stderr = %q, want the unsupported-platform FAIL line", stderr)
			}
			// Nothing ran: no config, no preflight output, no write, no restart.
			if stdout != "" {
				t.Errorf("--%s printed %q before refusing; want no output", c.cmd, stdout)
			}
		})
		t.Run(c.cmd+": guard stubs are in place", func(t *testing.T) {
			code, _, stderr := runChild(t, c.cmd+":guard")
			if code != 99 || !strings.Contains(stderr, abortMarker+" "+c.guardStage) {
				t.Fatalf("supported platform: exit %d, stderr=%q; want exit 99 at the %s stub", code, stderr, c.guardStage)
			}
		})
	}
}

// scriptRunner is fakeRunner with per-call results: each call of a command
// takes the next error from script[cmd] (nil once the list is used up).
func scriptRunner(script map[string][]error, out map[string]string, log *[]string) commandRunner {
	return func(name string, args ...string) ([]byte, error) {
		key := name + " " + strings.Join(args, " ")
		*log = append(*log, key)
		var err error
		if errs := script[key]; len(errs) > 0 {
			err, script[key] = errs[0], errs[1:]
		}
		return []byte(out[key]), err
	}
}

const (
	sssdEnable  = "systemctl enable --now sssd"
	sssdCache   = "sss_cache -E"
	sssdRestart = "systemctl restart sssd"
)

// countingRestore returns a restore func that counts its calls and returns
// what it did (restoring a previous sssd.conf) or err.
func countingRestore(err error) (func() (string, error), *int) {
	n := 0
	return func() (string, error) {
		n++
		if err != nil {
			return "", err
		}
		return "restored previous sssd.conf", nil
	}, &n
}

const sssdIsEnabled = "systemctl is-enabled sssd"

// exitErr returns a real *exec.ExitError with the given exit code (sh exits
// with it; nothing else runs).
func exitErr(t *testing.T, code int) error {
	t.Helper()
	err := exec.Command("sh", "-c", fmt.Sprintf("exit %d", code)).Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != code {
		t.Fatalf("sh exit %d: %v", code, err)
	}
	return err
}

func TestStartSSSDOK(t *testing.T) {
	var calls []string
	restore, n := countingRestore(nil)
	enabled, err := startSSSD(scriptRunner(nil, nil, &calls), restore)
	if err != nil || enabled != sssdEnabledNote {
		t.Fatalf("startSSSD = %q, %v; want %q, nil", enabled, err, sssdEnabledNote)
	}
	if want := []string{sssdEnable, sssdCache, sssdRestart}; !reflect.DeepEqual(calls, want) {
		t.Errorf("calls = %q, want %q", calls, want)
	}
	if *n != 0 {
		t.Errorf("restore called %d times on success", *n)
	}
}

// After a failed `enable --now`, `systemctl is-enabled sssd` decides what the
// abort message says: exit 1 with "disabled" is not enabled, exit 0 with
// "enabled" is enabled, every other answer leaves the state unknown.
func TestStartSSSDEnableFails(t *testing.T) {
	for _, c := range []struct {
		name         string
		isEnabled    error  // result of systemctl is-enabled after the failed enable --now
		isEnabledOut string // its output
		wantEnabled  string
	}{
		{"unit not enabled", exitErr(t, 1), "disabled\n", ""},
		{"enabled, start failed", nil, "enabled\n", sssdEnabledNote},
		{"masked", exitErr(t, 1), "masked\n", sssdMaskedNote},
		{"masked with another exit code", exitErr(t, 4), "masked\n", sssdEnableUnknownNote},
		{"other exit code", exitErr(t, 4), "", sssdEnableUnknownNote},
		{"not an exit status", errors.New("exec: \"systemctl\": executable file not found in $PATH"), "", sssdEnableUnknownNote},
		{"exit 0, other state", nil, "enabled-runtime\n", sssdEnableUnknownNote},
		{"exit 1 with output that is not disabled", exitErr(t, 1), "Failed to get unit file state for sssd.service: Access denied\n", sssdEnableUnknownNote},
	} {
		t.Run(c.name, func(t *testing.T) {
			var calls []string
			restore, n := countingRestore(nil)
			enabled, err := startSSSD(scriptRunner(map[string][]error{sssdEnable: {errors.New("exit status 1")}, sssdIsEnabled: {c.isEnabled}},
				map[string]string{sssdEnable: "Unit sssd.service is masked.", sssdIsEnabled: c.isEnabledOut}, &calls), restore)
			if err == nil {
				t.Fatal("startSSSD = nil although enable failed")
			}
			if enabled != c.wantEnabled {
				t.Errorf("enabled = %q, want %q", enabled, c.wantEnabled)
			}
			for _, want := range []string{sssdEnable, "Unit sssd.service is masked.", "restored previous sssd.conf and restarted sssd"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q lacks %q", err, want)
				}
			}
			if *n != 1 {
				t.Errorf("restore called %d times, want 1", *n)
			}
			// No sss_cache and no restart on the new config; one restart on the restored one.
			if want := []string{sssdEnable, sssdIsEnabled, sssdRestart}; !reflect.DeepEqual(calls, want) {
				t.Errorf("calls = %q, want %q", calls, want)
			}
		})
	}
}

func TestStartSSSDCacheFails(t *testing.T) {
	var calls []string
	restore, n := countingRestore(nil)
	enabled, err := startSSSD(scriptRunner(map[string][]error{sssdCache: {errors.New("exit status 2")}}, nil, &calls), restore)
	if err == nil || !strings.Contains(err.Error(), sssdCache) || !strings.Contains(err.Error(), "restored previous sssd.conf") {
		t.Fatalf("err = %v, want the sss_cache step and the restore state", err)
	}
	if enabled != sssdEnabledNote {
		t.Errorf("enabled = %q although enable --now succeeded", enabled)
	}
	if *n != 1 {
		t.Errorf("restore called %d times, want 1", *n)
	}
	if want := []string{sssdEnable, sssdCache, sssdRestart}; !reflect.DeepEqual(calls, want) {
		t.Errorf("calls = %q, want %q", calls, want)
	}
}

func TestStartSSSDRestartFailsRestoreOK(t *testing.T) {
	boom := errors.New("exit status 1")
	t.Run("restart on the restored config succeeds", func(t *testing.T) {
		var calls []string
		restore, n := countingRestore(nil)
		enabled, err := startSSSD(scriptRunner(map[string][]error{sssdRestart: {boom}},
			map[string]string{sssdRestart: "Job for sssd.service failed."}, &calls), restore)
		if err == nil {
			t.Fatal("startSSSD = nil although the restart failed")
		}
		if enabled != sssdEnabledNote {
			t.Errorf("enabled = %q although enable --now succeeded", enabled)
		}
		for _, want := range []string{sssdRestart, "Job for sssd.service failed.", "restored previous sssd.conf and restarted sssd"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q lacks %q", err, want)
			}
		}
		if *n != 1 {
			t.Errorf("restore called %d times, want 1", *n)
		}
		if want := []string{sssdEnable, sssdCache, sssdRestart, sssdRestart}; !reflect.DeepEqual(calls, want) {
			t.Errorf("calls = %q, want %q", calls, want)
		}
	})
	t.Run("restart on the restored config fails too", func(t *testing.T) {
		var calls []string
		restore, n := countingRestore(nil)
		_, err := startSSSD(scriptRunner(map[string][]error{sssdRestart: {boom, boom}}, nil, &calls), restore)
		if err == nil || !strings.Contains(err.Error(), "restored previous sssd.conf, but sssd did not restart") {
			t.Fatalf("err = %v, want the failed second restart named", err)
		}
		if *n != 1 {
			t.Errorf("restore called %d times, want 1", *n)
		}
	})
}

func TestStartSSSDRestartFailsRestoreFails(t *testing.T) {
	var calls []string
	restore, n := countingRestore(errors.New("read-only file system"))
	_, err := startSSSD(scriptRunner(map[string][]error{sssdRestart: {errors.New("exit status 1")}}, nil, &calls), restore)
	if err == nil {
		t.Fatal("startSSSD = nil although the restart failed")
	}
	for _, want := range []string{sssdRestart, "could NOT roll back sssd.conf", "read-only file system", "fix /etc/sssd/sssd.conf manually"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if *n != 1 {
		t.Errorf("restore called %d times, want 1", *n)
	}
	// Without a restored config there is nothing to restart sssd on.
	if want := []string{sssdEnable, sssdCache, sssdRestart}; !reflect.DeepEqual(calls, want) {
		t.Errorf("calls = %q, want %q", calls, want)
	}
}

// startSSSDStep is the abort wiring of step 7: an enabled sssd is named among
// the remaining host changes whenever a later step fails, and only then.
func TestStartSSSDStep(t *testing.T) {
	boom := errors.New("exit status 1")
	before := []string{"sshd drop-in /x"}
	cases := []struct {
		name          string
		script        map[string][]error
		isEnabledOut  string // output of systemctl is-enabled sssd
		resetFails    bool
		wantErr       []string // substrings; nil = success
		wantRemaining []string
		wantRestores  int
	}{
		{"all steps ok", nil, "", false, nil, []string{"sshd drop-in /x", "sssd enabled"}, 0},
		{"cache fails after enable", map[string][]error{sssdCache: {boom}}, "", false,
			[]string{"start sssd: " + sssdCache, "restored previous sssd.conf and restarted sssd", "still in place on the host: sshd drop-in /x, sssd enabled"},
			[]string{"sshd drop-in /x", "sssd enabled"}, 1},
		{"restart fails after enable", map[string][]error{sssdRestart: {boom}}, "", false,
			[]string{"start sssd: " + sssdRestart, "sssd enabled"},
			[]string{"sshd drop-in /x", "sssd enabled"}, 1},
		{"enable --now fails, unit not enabled", map[string][]error{sssdEnable: {boom}, sssdIsEnabled: {exitErr(t, 1)}}, "disabled\n", false,
			[]string{"start sssd: " + sssdEnable, "still in place on the host: sshd drop-in /x"},
			[]string{"sshd drop-in /x"}, 1},
		{"enable --now fails after enabling the unit", map[string][]error{sssdEnable: {boom}}, "enabled\n", false,
			[]string{"start sssd: " + sssdEnable, "sshd drop-in /x, sssd enabled"},
			[]string{"sshd drop-in /x", "sssd enabled"}, 1},
		{"enable --now fails, enable state unknown", map[string][]error{sssdEnable: {boom}, sssdIsEnabled: {boom}}, "", false,
			[]string{"start sssd: " + sssdEnable, "sshd drop-in /x, enable state of sssd unknown (check `systemctl is-enabled sssd`)"},
			[]string{"sshd drop-in /x", sssdEnableUnknownNote}, 1},
		{"reset-failed fails", nil, "", true,
			[]string{"systemctl reset-failed sssd-*", "restored previous sssd.conf and restarted sssd", "sshd drop-in /x, sssd enabled"},
			[]string{"sshd drop-in /x", "sssd enabled"}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// reset-failed goes through the systemctl seam: never the real one.
			orig := systemctl
			t.Cleanup(func() { systemctl = orig })
			var sysCalls []string
			systemctl = func(args ...string) (string, error) {
				sysCalls = append(sysCalls, strings.Join(args, " "))
				if c.resetFails {
					return "Access denied", boom
				}
				return "", nil
			}
			var calls []string
			restore, n := countingRestore(nil)
			remaining, err := startSSSDStep(scriptRunner(c.script, map[string]string{sssdIsEnabled: c.isEnabledOut}, &calls), restore, append([]string{}, before...))
			if !reflect.DeepEqual(remaining, c.wantRemaining) {
				t.Errorf("remaining = %q, want %q", remaining, c.wantRemaining)
			}
			if c.wantErr == nil && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			for _, want := range c.wantErr {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Errorf("error %v lacks %q", err, want)
				}
			}
			if c.name == "enable --now fails, unit not enabled" && err != nil && strings.Contains(err.Error(), "sssd enabled") {
				t.Errorf("error claims sssd enabled although it is not: %v", err)
			}
			if *n != c.wantRestores {
				t.Errorf("restore called %d times, want %d", *n, c.wantRestores)
			}
			// reset-failed runs only after a successful start.
			if wantReset := c.wantErr == nil || c.resetFails; wantReset != (len(sysCalls) > 0) {
				t.Errorf("systemctl seam calls = %q, reset-failed expected: %v", sysCalls, wantReset)
			}
		})
	}
}

func TestAptUpdateFailureAborts(t *testing.T) {
	prof := distro.Profile{InstallCmd: "apt-get", MarkManualCmd: []string{"apt-mark", "manual"}, SSSDPackages: []string{"sssd-ldap"}}
	var calls []string
	err := ensureSSSDPackages(prof, false, fakeRunner(map[string]error{"apt-get update": errors.New("exit status 100")},
		map[string]string{"apt-get update": "Temporary failure resolving 'deb.debian.org'"}, &calls))
	if err == nil || !strings.Contains(err.Error(), "apt-get update") || !strings.Contains(err.Error(), "Temporary failure resolving") {
		t.Fatalf("err = %v, want the apt-get update failure with its output", err)
	}
	if want := []string{"apt-get update"}; !reflect.DeepEqual(calls, want) {
		t.Errorf("calls = %q, want %q (no install against a stale index)", calls, want)
	}
}

func TestEnsureSSSDPackagesCommands(t *testing.T) {
	deb := distro.Profile{InstallCmd: "apt-get", MarkManualCmd: []string{"apt-mark", "manual"},
		SSSDPackages: []string{"sssd-ldap"}, KrbPackages: []string{"sssd-krb5"}}
	rhel := distro.Profile{InstallCmd: "dnf", MarkManualCmd: []string{"dnf", "mark", "install"},
		SSSDPackages: []string{"sssd"}, MkhomedirPackages: []string{"oddjob-mkhomedir"}}
	boom := errors.New("exit status 1")
	cases := []struct {
		name      string
		prof      distro.Profile
		kerberos  bool
		results   map[string]error
		wantCalls []string
		wantErr   string
	}{
		{"debian", deb, true, nil, []string{"apt-get update",
			"env DEBIAN_FRONTEND=noninteractive apt-get install -y sssd-ldap sssd-krb5", "apt-mark manual sssd-ldap sssd-krb5"}, ""},
		{"rhel", rhel, false, nil, []string{"dnf install -y sssd oddjob-mkhomedir", "dnf mark install sssd oddjob-mkhomedir"}, ""},
		{"install fails", rhel, false, map[string]error{"dnf install -y sssd oddjob-mkhomedir": boom},
			[]string{"dnf install -y sssd oddjob-mkhomedir"}, "dnf install -y sssd oddjob-mkhomedir"},
		{"mark manual fails", rhel, false, map[string]error{"dnf mark install sssd oddjob-mkhomedir": boom},
			[]string{"dnf install -y sssd oddjob-mkhomedir", "dnf mark install sssd oddjob-mkhomedir"}, "dnf mark install sssd oddjob-mkhomedir"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			err := ensureSSSDPackages(tc.prof, tc.kerberos, fakeRunner(tc.results, nil, &calls))
			if tc.wantErr == "" && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want an error naming %q", err, tc.wantErr)
			}
			if !reflect.DeepEqual(calls, tc.wantCalls) {
				t.Errorf("calls = %q, want %q", calls, tc.wantCalls)
			}
		})
	}
}
