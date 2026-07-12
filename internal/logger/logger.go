package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"syscall"
	"time"
)

// sanitizeLog neutralizes a fully-formatted log line before it is written.
// Newlines are escaped so a crafted username/IP cannot forge additional log
// lines; ESC and every other C0/C1 control byte (and DEL) are replaced with '?'
// so an unauthenticated value cannot inject ANSI/OSC escape sequences that
// execute when an operator later views the root-owned log in a terminal. This
// mirrors the C module's sanitize_for_log, which only covers the C module's own
// log copies — the SSH username/host reach this Go logger unsanitized.
func sanitizeLog(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString("\\n")
		case r == '\r':
			b.WriteString("\\r")
		case r == '\t':
			b.WriteByte('\t') // tab is harmless and aids readability
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			b.WriteByte('?')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// LogLevel represents the logging level
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

// String returns the string representation of the log level
func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Logger provides structured logging functionality
type Logger struct {
	level  LogLevel
	logger *log.Logger
	debug  bool
	file   *os.File // track file handle for cleanup
}

// NewLogger creates a new logger instance
func NewLogger(logFile string, debug bool) (*Logger, error) {
	var writer io.Writer = os.Stderr
	var logFileHandle *os.File

	if logFile != "" {
		// 0640 (owner rw, group r) matches the C PAM module which writes to the
		// same log file. Log contains PII (usernames, emails, IPs, roles) and
		// must not be world-readable. The `adm` group can read via logrotate.
		// O_NOFOLLOW: refuse to open the log if its final path component is a
		// symlink (defeats a pre-created-symlink redirect of a root-written log).
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, 0640)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %v", err)
		}
		// Defensive tightening for upgrades: existing log files created with
		// earlier versions may have 0644. O_CREATE's mode only applies on
		// creation, so re-chmod here to guarantee the invariant at runtime.
		// Ignore EPERM (non-owner): postinst or logrotate will settle it.
		_ = f.Chmod(0640)
		writer = f
		logFileHandle = f
	}

	logger := log.New(writer, "", 0) // No default prefix or flags

	level := INFO
	if debug {
		level = DEBUG
	}

	return &Logger{
		level:  level,
		logger: logger,
		debug:  debug,
		file:   logFileHandle,
	}, nil
}

// SetLevel sets the minimum log level
func (l *Logger) SetLevel(level LogLevel) {
	l.level = level
}

// Debug logs a debug message
func (l *Logger) Debug(format string, v ...interface{}) {
	if l.level <= DEBUG {
		l.log(DEBUG, format, v...)
	}
}

// Info logs an info message
func (l *Logger) Info(format string, v ...interface{}) {
	if l.level <= INFO {
		l.log(INFO, format, v...)
	}
}

// Warn logs a warning message
func (l *Logger) Warn(format string, v ...interface{}) {
	if l.level <= WARN {
		l.log(WARN, format, v...)
	}
}

// Error logs an error message
func (l *Logger) Error(format string, v ...interface{}) {
	if l.level <= ERROR {
		l.log(ERROR, format, v...)
	}
}

// log writes a log message with timestamp and level
func (l *Logger) log(level LogLevel, format string, v ...interface{}) {
	timestamp := time.Now().Format("2006/01/02 15:04:05")
	message := sanitizeLog(fmt.Sprintf(format, v...))
	logLine := fmt.Sprintf("%s [AUTH]   %-5s %s", timestamp, level.String(), message)
	l.logger.Println(logLine)
}

// LogPhase logs a phase marker for easier log parsing
func (l *Logger) LogPhase(phase string) {
	l.Info("=== PHASE: %s ===", phase)
}

// LogSummary logs a summary section
func (l *Logger) LogSummary(title string, items map[string]string) {
	l.Info("=== %s ===", title)
	for key, value := range items {
		l.Info("- %s: %s", key, value)
	}
}

// IsDebugEnabled returns true if debug logging is enabled
func (l *Logger) IsDebugEnabled() bool {
	return l.debug
}

// Close closes the logger's file handle if one was opened
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
