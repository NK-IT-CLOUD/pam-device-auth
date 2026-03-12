package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

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
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %v", err)
		}
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
	message := fmt.Sprintf(format, v...)
	logLine := fmt.Sprintf("%s [SSO-GO] %-5s %s", timestamp, level.String(), message)
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
