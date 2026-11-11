package logger

import (
	"errors"
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
	file   *os.File // track file handle for cleanup
}

// logFileMode is the widest mode of the log file: owner rw, group r. The log
// contains PII (usernames, emails, IPs, roles) and must not be world-readable;
// the C PAM module creates it with the same mode.
const logFileMode os.FileMode = 0640

// chmodLog sets the mode of the opened log file; a variable so tests can make
// it fail.
var chmodLog = func(f *os.File, mode os.FileMode) error { return f.Chmod(mode) }

// chownLog sets owner and group of the opened log file; a variable so tests
// can watch it and make it fail.
var chownLog = func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }

// ErrLogMode marks a failure where the log file opened but its mode could not
// be read, or had bits beyond 0640 that could not be removed. The wrapped
// *os.PathError names the operation and the path.
var ErrLogMode = errors.New("cannot set log file mode 0640")

// ErrLogNotRegular marks a log path that is no regular file: a symbolic link,
// a FIFO, a directory or a device.
var ErrLogNotRegular = errors.New("log path is not a regular file")

// openLog opens the log file for appending, creating it with logFileMode, and
// returns it only when it is a regular file without mode bits beyond
// logFileMode.
//
// O_NOFOLLOW refuses a symlink at the path, which would redirect a
// root-written log. O_NONBLOCK makes opening a FIFO fail at once instead of
// blocking the login until someone reads it; it changes nothing for a regular
// file. Whatever opens nevertheless (a FIFO that has a reader, a device) is
// refused after fstat.
//
// Mode bits beyond logFileMode are removed (a log of an earlier version may
// have 0644). A stricter mode stays, and a log with a fitting mode is never
// chmod-ed, so an append-only log keeps working. Excess bits that cannot be
// removed are a misconfiguration: fail instead of writing PII into the file.
func openLog(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, logFileMode)
	switch {
	case errors.Is(err, syscall.ELOOP):
		return nil, fmt.Errorf("%w: %s is a symbolic link", ErrLogNotRegular, path)
	case errors.Is(err, syscall.ENXIO):
		return nil, fmt.Errorf("%w: %s is a FIFO or a device", ErrLogNotRegular, path)
	case errors.Is(err, syscall.EISDIR):
		return nil, fmt.Errorf("%w: %s is a directory", ErrLogNotRegular, path)
	case err != nil:
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%w: %w", ErrLogMode, err)
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%w: %s is a %s", ErrLogNotRegular, path, fi.Mode().Type())
	}
	if perm := fi.Mode().Perm(); perm&^logFileMode != 0 {
		if err := chmodLog(f, perm&logFileMode); err != nil {
			f.Close()
			return nil, fmt.Errorf("%w: %w", ErrLogMode, err)
		}
	}
	return f, nil
}

// PrepareLog creates the log file, or brings an existing one under the rules
// of openLog, and with gid >= 0 gives it to the current user and that group.
// The package's post-install script runs it through `--prepare-log`: every
// step works on the open file, where touch, chmod and chown would follow a
// symlink planted at the path.
//
// A log that already has that owner and group is not chown-ed: like chmod,
// chown fails on an append-only file even when it changes nothing, and such a
// log must not break a package upgrade.
func PrepareLog(path string, gid int) error {
	f, err := openLog(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if gid >= 0 {
		uid := os.Geteuid()
		fi, err := f.Stat()
		if err != nil {
			return fmt.Errorf("cannot read the owner of the log file: %w", err)
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != uid || int(st.Gid) != gid {
			if err := chownLog(f, uid, gid); err != nil {
				return fmt.Errorf("cannot set the owner of the log file: %w", err)
			}
		}
	}
	return nil
}

// NewLogger creates a new logger instance
func NewLogger(logFile string, debug bool) (*Logger, error) {
	var writer io.Writer = os.Stderr
	var logFileHandle *os.File

	if logFile != "" {
		f, err := openLog(logFile)
		if err != nil {
			return nil, err
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
		file:   logFileHandle,
	}, nil
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

// Close closes the logger's file handle if one was opened
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
