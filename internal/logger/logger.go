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
}

// NewLogger creates a new logger instance
func NewLogger(logFile string, debug bool) (*Logger, error) {
	var writer io.Writer = os.Stderr
	
	if logFile != "" {
		file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %v", err)
		}
		writer = file
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
	
	var prefix string
	if level == DEBUG {
		prefix = "[SSO-GO][DEBUG]"
	} else {
		prefix = "[SSO-GO]"
	}
	
	logLine := fmt.Sprintf("%s %s %s", timestamp, prefix, message)
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

// Close closes the logger (if it uses a file)
func (l *Logger) Close() error {
	// If the logger uses a file, we should close it
	// For now, we don't track the file handle, so this is a no-op
	return nil
}

// Default logger instance
var defaultLogger *Logger

// InitDefaultLogger initializes the default logger
func InitDefaultLogger(logFile string, debug bool) error {
	var err error
	defaultLogger, err = NewLogger(logFile, debug)
	return err
}

// GetDefaultLogger returns the default logger instance
func GetDefaultLogger() *Logger {
	if defaultLogger == nil {
		// Fallback to stderr logger
		defaultLogger, _ = NewLogger("", false)
	}
	return defaultLogger
}

// Convenience functions using the default logger
func Debug(format string, v ...interface{}) {
	GetDefaultLogger().Debug(format, v...)
}

func Info(format string, v ...interface{}) {
	GetDefaultLogger().Info(format, v...)
}

func Warn(format string, v ...interface{}) {
	GetDefaultLogger().Warn(format, v...)
}

func Error(format string, v ...interface{}) {
	GetDefaultLogger().Error(format, v...)
}

func LogPhase(phase string) {
	GetDefaultLogger().LogPhase(phase)
}

func LogSummary(title string, items map[string]string) {
	GetDefaultLogger().LogSummary(title, items)
}
