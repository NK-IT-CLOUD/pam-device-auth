package logger

import (
	"os"
	"strings"
	"testing"
)

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
