package logger

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A malicious SSH username/host reaches this logger unsanitized (the C module
// only sanitizes its own log copies). ESC and other control bytes must not pass
// through into the root-owned log, where they could forge entries or drive a
// viewing terminal via ANSI/OSC escapes.
func TestLog_StripsControlAndEscapeBytes(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "ctl.log")
	log, err := NewLogger(tmp, false)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer log.Close()

	log.Info("user=%s", "ev\x1b[31ml\x07il\ninjected\x9b2K")

	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	s := string(data)
	for _, bad := range []rune{0x1b, 0x07, 0x9b} {
		if strings.ContainsRune(s, bad) {
			t.Errorf("control byte %#x leaked into log: %q", bad, s)
		}
	}
	// The embedded newline must be escaped, not produce a second log line.
	if strings.Count(s, "\n") != 1 {
		t.Errorf("embedded newline forged a log line: %d newlines in %q", strings.Count(s, "\n"), s)
	}
	// Legitimate text is preserved.
	if !strings.Contains(s, "user=ev") || !strings.Contains(s, "injected") {
		t.Errorf("legitimate text was mangled: %q", s)
	}
}

func TestNewLogger_Stderr(t *testing.T) {
	log, err := NewLogger("", false)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	if log.level != INFO {
		t.Errorf("expected INFO level, got %v", log.level)
	}
}

func TestNewLogger_Debug(t *testing.T) {
	log, err := NewLogger("", true)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	if log.level != DEBUG {
		t.Errorf("expected DEBUG level, got %v", log.level)
	}
}

func TestNewLogger_File(t *testing.T) {
	tmpFile := "/tmp/test-ksa-logger.log"
	defer os.Remove(tmpFile)

	log, err := NewLogger(tmpFile, false)
	if err != nil {
		t.Fatalf("NewLogger with file failed: %v", err)
	}
	defer log.Close()

	log.Info("test message")

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	if len(content) == 0 {
		t.Error("log file should not be empty")
	}
	if !strings.Contains(string(content), "[AUTH]") {
		t.Error("log should contain [AUTH] prefix")
	}
	if !strings.Contains(string(content), "test message") {
		t.Error("log should contain the test message")
	}
}

func TestNewLogger_InvalidFile(t *testing.T) {
	_, err := NewLogger("/nonexistent/path/to/log.log", false)
	if err == nil {
		t.Error("NewLogger should fail for invalid file path")
	}
}

// NewLogger removes the mode bits beyond 0640 and nothing else. A log whose
// mode is 0640 or stricter is never chmod-ed: an append-only log (chattr +a,
// where chmod fails) keeps working, and a mode an admin tightened on purpose
// stays. Excess bits that cannot be removed are a misconfiguration, not
// something to log PII into anyway.
func TestNewLoggerRemovesOnlyExcessModeBits(t *testing.T) {
	// The error os.File.Chmod returns for an append-only file.
	eperm := func(f *os.File, _ os.FileMode) error {
		return &os.PathError{Op: "chmod", Path: f.Name(), Err: syscall.EPERM}
	}
	realChmod := func(f *os.File, mode os.FileMode) error { return f.Chmod(mode) }
	for _, c := range []struct {
		name      string
		mode      os.FileMode
		chmod     func(*os.File, os.FileMode) error
		wantCalls int
		wantMode  os.FileMode
		wantErr   bool
	}{
		{"0640, chmod would fail", 0640, eperm, 0, 0640, false},
		{"0600 is stricter and stays", 0600, eperm, 0, 0600, false},
		{"0644, chmod fails", 0644, eperm, 1, 0, true},
		{"0644 loses the read bit of others", 0644, realChmod, 1, 0640, false},
		{"0666 loses every excess bit", 0666, realChmod, 1, 0640, false},
		{"0604 gains nothing for the group", 0604, realChmod, 1, 0600, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			orig := chmodLog
			t.Cleanup(func() { chmodLog = orig })
			calls := 0
			chmodLog = func(f *os.File, mode os.FileMode) error { calls++; return c.chmod(f, mode) }

			path := filepath.Join(t.TempDir(), "mode.log")
			if err := os.WriteFile(path, nil, c.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, c.mode); err != nil { // umask
				t.Fatal(err)
			}
			log, err := NewLogger(path, false)
			if calls != c.wantCalls {
				t.Errorf("chmod calls = %d, want %d", calls, c.wantCalls)
			}
			if !c.wantErr {
				if err != nil {
					t.Fatalf("NewLogger: %v", err)
				}
				log.Close()
				if fi, _ := os.Stat(path); fi.Mode().Perm() != c.wantMode {
					t.Errorf("mode = %v, want %v", fi.Mode().Perm(), c.wantMode)
				}
				return
			}
			if err == nil {
				log.Close()
				t.Fatal("NewLogger succeeded although the excess mode bits could not be removed")
			}
			if !errors.Is(err, ErrLogMode) || !errors.Is(err, syscall.EPERM) {
				t.Errorf("error %q is not ErrLogMode wrapping EPERM", err)
			}
			if msg := err.Error(); !strings.Contains(msg, "chmod") || strings.Count(msg, path) != 1 {
				t.Errorf("error %q must name chmod and the path exactly once", msg)
			}
		})
	}
}

// openWithin runs open and fails the test when it does not return within a
// second: opening a FIFO for writing blocks until someone reads it.
func openWithin(t *testing.T, what string, open func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- open() }()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		t.Fatalf("opening the log blocks on a %s", what)
		return nil
	}
}

// oddLogPaths returns log paths that are no regular file: a symlink to target,
// a FIFO without a reader, a FIFO with a reader, and a directory.
func oddLogPaths(t *testing.T, target string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	paths := map[string]string{
		"symlink":            filepath.Join(dir, "link.log"),
		"FIFO":               filepath.Join(dir, "fifo.log"),
		"FIFO with a reader": filepath.Join(dir, "fifo-read.log"),
		"directory":          filepath.Join(dir, "dir.log"),
	}
	if err := os.Symlink(target, paths["symlink"]); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"FIFO", "FIFO with a reader"} {
		if err := syscall.Mkfifo(paths[name], 0640); err != nil {
			t.Skipf("mkfifo not possible here: %v", err)
		}
	}
	reader, err := os.OpenFile(paths["FIFO with a reader"], os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close() })
	if err := os.Mkdir(paths["directory"], 0750); err != nil {
		t.Fatal(err)
	}
	return paths
}

// The log path must be a regular file. A symlink would redirect a root-written
// log, and a FIFO would block every login in open(2): both, and a directory,
// are refused at once, and what a symlink points to stays untouched.
func TestNewLogger_RefusesSymlinkFIFOAndDirectory(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, path := range oddLogPaths(t, target) {
		t.Run(name, func(t *testing.T) {
			err := openWithin(t, name, func() error {
				l, err := NewLogger(path, false)
				if err == nil {
					l.Close()
				}
				return err
			})
			if !errors.Is(err, ErrLogNotRegular) {
				t.Errorf("NewLogger() error = %v, want ErrLogNotRegular", err)
			}
		})
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(target); fi.Mode().Perm() != 0600 || string(data) != "keep" {
		t.Errorf("the symlink target changed: mode %v, content %q", fi.Mode().Perm(), data)
	}
}

// PrepareLog is what the package's post-install script runs instead of
// touch/chmod/chown, which follow a symlink.
func TestPrepareLog(t *testing.T) {
	dir := t.TempDir()

	created := filepath.Join(dir, "new.log")
	if err := PrepareLog(created, os.Getgid()); err != nil {
		t.Fatalf("PrepareLog(missing file): %v", err)
	}
	fi, err := os.Stat(created)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0640 {
		t.Errorf("a new log has mode %v, want 0640", fi.Mode().Perm())
	}
	if st := fi.Sys().(*syscall.Stat_t); int(st.Gid) != os.Getgid() {
		t.Errorf("a new log has gid %d, want %d", st.Gid, os.Getgid())
	}

	loose := filepath.Join(dir, "loose.log")
	if err := os.WriteFile(loose, []byte("old line\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0644); err != nil {
		t.Fatal(err)
	}
	if err := PrepareLog(loose, -1); err != nil {
		t.Fatalf("PrepareLog(0644 file): %v", err)
	}
	if fi, _ := os.Stat(loose); fi.Mode().Perm() != 0640 {
		t.Errorf("an existing 0644 log has mode %v after PrepareLog, want 0640", fi.Mode().Perm())
	}
	if data, _ := os.ReadFile(loose); string(data) != "old line\n" {
		t.Errorf("PrepareLog changed the content of an existing log: %q", data)
	}

	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, path := range oddLogPaths(t, target) {
		err := openWithin(t, name, func() error { return PrepareLog(path, os.Getgid()) })
		if !errors.Is(err, ErrLogNotRegular) {
			t.Errorf("PrepareLog(%s) error = %v, want ErrLogNotRegular", name, err)
		}
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0600 {
		t.Errorf("the symlink target has mode %v after PrepareLog, want 0600 untouched", fi.Mode().Perm())
	}
}

// chown fails on an append-only file even when it would change nothing. A log
// that already belongs to the wanted owner and group is therefore left alone,
// so a package upgrade works on a host that keeps its log append-only.
func TestPrepareLog_ChownsOnlyWhenTheOwnerDiffers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(path, nil, 0640); err != nil {
		t.Fatal(err)
	}
	type call struct{ uid, gid int }
	var calls []call
	orig := chownLog
	chownLog = func(_ *os.File, uid, gid int) error {
		calls = append(calls, call{uid, gid})
		return syscall.EPERM // what an append-only file answers
	}
	t.Cleanup(func() { chownLog = orig })

	// The file was just created by this process: owner and group fit.
	if err := PrepareLog(path, os.Getegid()); err != nil {
		t.Fatalf("PrepareLog on a log with the wanted owner and group: %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("chown was called for a log that already fits: %+v", calls)
	}

	// Another group must be set, and a failure to do so is an error.
	other := os.Getegid() + 1
	err := PrepareLog(path, other)
	if err == nil || !errors.Is(err, syscall.EPERM) {
		t.Fatalf("PrepareLog with another group: err = %v, want the chown error", err)
	}
	if len(calls) != 1 || calls[0] != (call{os.Geteuid(), other}) {
		t.Fatalf("chown calls = %+v, want one call with (%d, %d)", calls, os.Geteuid(), other)
	}
}

func TestLogLevel_String(t *testing.T) {
	cases := map[LogLevel]string{
		DEBUG: "DEBUG",
		INFO:  "INFO",
		WARN:  "WARN",
		ERROR: "ERROR",
	}
	for level, expected := range cases {
		if got := level.String(); got != expected {
			t.Errorf("expected %q, got %q", expected, got)
		}
	}
}

func TestLogLevel_String_Unknown(t *testing.T) {
	unknown := LogLevel(99)
	if got := unknown.String(); got != "UNKNOWN" {
		t.Errorf("expected UNKNOWN, got %q", got)
	}
}

func TestDebugSuppression(t *testing.T) {
	tmpFile := "/tmp/test-ksa-debug-suppress.log"
	defer os.Remove(tmpFile)

	log, err := NewLogger(tmpFile, false)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	defer log.Close()

	log.Debug("this debug message should be suppressed")
	log.Info("this info message should appear")

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	s := string(content)
	if strings.Contains(s, "suppressed") {
		t.Error("debug message should be suppressed at INFO level")
	}
	if !strings.Contains(s, "this info message should appear") {
		t.Error("info message should appear")
	}
}

func TestAllLogLevels_Output(t *testing.T) {
	tmpFile := "/tmp/test-ksa-all-levels.log"
	defer os.Remove(tmpFile)

	log, err := NewLogger(tmpFile, true)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	defer log.Close()

	log.Debug("debug msg")
	log.Info("info msg")
	log.Warn("warn msg")
	log.Error("error msg")

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	s := string(content)
	for _, expected := range []string{"debug msg", "info msg", "warn msg", "error msg"} {
		if !strings.Contains(s, expected) {
			t.Errorf("log should contain %q", expected)
		}
	}
}

func TestLogLevelFiltering(t *testing.T) {
	tmpFile := "/tmp/test-ksa-level-filter.log"
	defer os.Remove(tmpFile)

	log, err := NewLogger(tmpFile, false)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	defer log.Close()

	log.level = WARN
	log.Debug("debug-hidden")
	log.Info("info-hidden")
	log.Warn("warn-visible")
	log.Error("error-visible")

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	s := string(content)
	if strings.Contains(s, "debug-hidden") {
		t.Error("debug should be hidden at WARN level")
	}
	if strings.Contains(s, "info-hidden") {
		t.Error("info should be hidden at WARN level")
	}
	if !strings.Contains(s, "warn-visible") {
		t.Error("warn should be visible at WARN level")
	}
	if !strings.Contains(s, "error-visible") {
		t.Error("error should be visible at WARN level")
	}
}

func TestClose_NoFile(t *testing.T) {
	log, _ := NewLogger("", false)
	if err := log.Close(); err != nil {
		t.Errorf("Close on stderr logger should not error: %v", err)
	}
}

func TestClose_WithFile(t *testing.T) {
	tmpFile := "/tmp/test-ksa-close.log"
	defer os.Remove(tmpFile)

	log, err := NewLogger(tmpFile, false)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}

	if err := log.Close(); err != nil {
		t.Errorf("Close should not error: %v", err)
	}
}
