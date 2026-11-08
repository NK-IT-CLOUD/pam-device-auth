package logger

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
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
	if log.debug {
		t.Error("debug should be false")
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
	if !log.debug {
		t.Error("debug should be true")
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

// NewLogger sets the log to 0640 only when its mode is wrong. A log with the
// right mode is never chmod-ed, so an append-only log (chattr +a, where chmod
// fails) with the right mode keeps working. A wrong mode that cannot be
// corrected is a misconfiguration, not something to log PII into anyway.
func TestNewLoggerChmodOnlyWhenModeWrong(t *testing.T) {
	// The error os.File.Chmod returns for an append-only file.
	eperm := func(f *os.File) error { return &os.PathError{Op: "chmod", Path: f.Name(), Err: syscall.EPERM} }
	realChmod := func(f *os.File) error { return f.Chmod(0640) }
	for _, c := range []struct {
		name      string
		mode      os.FileMode
		chmod     func(*os.File) error
		wantCalls int
		wantErr   bool
	}{
		{"right mode, chmod would fail", 0640, eperm, 0, false},
		{"wrong mode, chmod fails", 0644, eperm, 1, true},
		{"wrong mode, chmod ok", 0644, realChmod, 1, false},
		{"stricter mode is corrected too", 0600, realChmod, 1, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			orig := chmodLog
			t.Cleanup(func() { chmodLog = orig })
			calls := 0
			chmodLog = func(f *os.File) error { calls++; return c.chmod(f) }

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
				if fi, _ := os.Stat(path); fi.Mode().Perm() != 0640 {
					t.Errorf("mode = %v, want 0640", fi.Mode().Perm())
				}
				return
			}
			if err == nil {
				log.Close()
				t.Fatal("NewLogger succeeded although the wrong mode could not be corrected")
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

func TestSetLevel(t *testing.T) {
	log, _ := NewLogger("", false)

	log.SetLevel(DEBUG)
	if log.level != DEBUG {
		t.Errorf("expected DEBUG, got %v", log.level)
	}

	log.SetLevel(ERROR)
	if log.level != ERROR {
		t.Errorf("expected ERROR, got %v", log.level)
	}

	log.SetLevel(WARN)
	if log.level != WARN {
		t.Errorf("expected WARN, got %v", log.level)
	}
}

func TestIsDebugEnabled(t *testing.T) {
	log, _ := NewLogger("", true)
	if !log.IsDebugEnabled() {
		t.Error("should be debug enabled")
	}
	log2, _ := NewLogger("", false)
	if log2.IsDebugEnabled() {
		t.Error("should not be debug enabled")
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

	log.SetLevel(WARN)
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

func TestLogPhase(t *testing.T) {
	tmpFile := "/tmp/test-ksa-phase.log"
	defer os.Remove(tmpFile)

	log, err := NewLogger(tmpFile, false)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	defer log.Close()

	log.LogPhase("AUTHENTICATION")

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	if !strings.Contains(string(content), "=== PHASE: AUTHENTICATION ===") {
		t.Error("LogPhase output should contain phase markers")
	}
}

func TestLogSummary(t *testing.T) {
	tmpFile := "/tmp/test-ksa-summary.log"
	defer os.Remove(tmpFile)

	log, err := NewLogger(tmpFile, false)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	defer log.Close()

	log.LogSummary("Auth Result", map[string]string{
		"User":   "nk",
		"Status": "authenticated",
	})

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	s := string(content)
	if !strings.Contains(s, "=== Auth Result ===") {
		t.Error("LogSummary should contain title")
	}
	if !strings.Contains(s, "User: nk") && !strings.Contains(s, "Status: authenticated") {
		t.Error("LogSummary should contain summary items")
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
