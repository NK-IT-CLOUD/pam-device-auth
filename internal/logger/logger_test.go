package logger

import (
	"os"
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

	log.Info("test message")

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	if len(content) == 0 {
		t.Error("log file should not be empty")
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
			t.Errorf("expected '%s', got '%s'", expected, got)
		}
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

func TestDefaultLogger(t *testing.T) {
	log := GetDefaultLogger()
	if log == nil {
		t.Fatal("GetDefaultLogger returned nil")
	}
}
