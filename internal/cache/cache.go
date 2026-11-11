package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// CacheDir is the directory for cached sessions.
// Exported as a variable so tests can override it.
var CacheDir = "/run/pam-device-auth"

// maxUsernameBytes is the longest user name that gets cache files. Encoded by
// fileStem it stays far below the 255 bytes a file name may have.
const maxUsernameBytes = 64

// fileStem returns the stem of a user's cache file names: the user name with
// every byte outside [A-Za-z0-9_-] written as %XX. A name of those characters
// alone keeps the file name it always had; a name with a dot, an "@" or a
// path separator gets files too, and no name can leave CacheDir or collide
// with another one ("%" itself is encoded). The files of a user are
// <stem>.json, <stem>.lock and the temporary <stem>.json.*: a stem holds no
// dot, so none of them can be the file of another user.
func fileStem(username string) (string, error) {
	if len(username) == 0 || len(username) > maxUsernameBytes {
		return "", fmt.Errorf("invalid username for cache: %q (1 to %d bytes)", username, maxUsernameBytes)
	}
	var b strings.Builder
	for i := 0; i < len(username); i++ {
		c := username[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String(), nil
}

// CachedSession holds a cached Refresh Token and known IPs for a user.
type CachedSession struct {
	RefreshToken string   `json:"refresh_token"`
	Username     string   `json:"username"`
	KnownIPs     []string `json:"known_ips,omitempty"`
}

// HasIP returns true if the given IP is in the session's known IPs list.
func (s *CachedSession) HasIP(ip string) bool {
	for _, known := range s.KnownIPs {
		if known == ip {
			return true
		}
	}
	return false
}

// MaxIPs is the maximum number of known IPs stored per user session.
const MaxIPs = 20

// AddIP adds an IP to the session's known IPs list.
// If the IP already exists, it is moved to the end (refreshed).
// If the list exceeds MaxIPs, the oldest entries are evicted.
func (s *CachedSession) AddIP(ip string) {
	// Skip sentinels: "unknown" (IP undetectable) and "" are never matched by
	// the cached-refresh path, so storing them would only waste a FIFO slot.
	if ip == "" || ip == "unknown" {
		return
	}
	for i, known := range s.KnownIPs {
		if known == ip {
			s.KnownIPs = append(s.KnownIPs[:i], s.KnownIPs[i+1:]...)
			break
		}
	}
	s.KnownIPs = append(s.KnownIPs, ip)
	if len(s.KnownIPs) > MaxIPs {
		s.KnownIPs = s.KnownIPs[len(s.KnownIPs)-MaxIPs:]
	}
}

// cachePath is the session file of the user with this file stem (fileStem).
func cachePath(stem string) string {
	return filepath.Join(CacheDir, stem+".json")
}

// ErrCorrupt marks a cache file that exists but cannot be parsed. Callers may
// discard such a file; it can never become valid again on its own.
var ErrCorrupt = errors.New("corrupt session cache")

// Load reads a cached session for the given username.
// Returns nil, nil if no cache file exists.
func Load(username string) (*CachedSession, error) {
	stem, err := fileStem(username)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(cachePath(stem))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read cache: %w", err)
	}

	var session CachedSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("%w: parse cache: %v", ErrCorrupt, err)
	}

	return &session, nil
}

// Save writes a cached session atomically (unique temp file + rename). Each
// process gets its own temp file, so two concurrent PAM logins for the same
// user can no longer truncate each other's half-written temp (PDA-BUG-003);
// last rename wins. Creates the cache directory if it doesn't exist.
func Save(session *CachedSession) error {
	stem, err := fileStem(session.Username)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(CacheDir, 0700); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal cache: %w", err)
	}

	// A stem holds no dot, so "<stem>.json.*" temp names can never collide
	// with another user's cache file and Load never picks them up.
	tmp, err := os.CreateTemp(CacheDir, stem+".json.*")
	if err != nil {
		return fmt.Errorf("create cache temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { tmp.Close(); os.Remove(tmpName) }
	if err := tmp.Chmod(0600); err != nil {
		cleanup()
		return fmt.Errorf("chmod cache temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write cache temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync cache temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close cache temp: %w", err)
	}
	if err := os.Rename(tmpName, cachePath(stem)); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename cache: %w", err)
	}
	return nil
}

// WithUserLock serializes an arbitrary per-user cache transaction. Callers that
// rotate refresh tokens use it to cover the complete load/network/save cycle.
// The lock is advisory and Linux-only, which matches the PAM module's platform.
func WithUserLock(username string, fn func() error) error {
	stem, err := fileStem(username)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(CacheDir, 0700); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	// A stem holds no dot, so "<stem>.lock" cannot collide with a cache file
	// of another user.
	lock, err := os.OpenFile(filepath.Join(CacheDir, stem+".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open cache lock: %w", err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire cache lock: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return fn()
}

// Update serializes a load-modify-save cycle against concurrent PAM processes.
// mutate receives the existing session, or a fresh one if no cache exists yet.
func Update(username string, mutate func(*CachedSession)) error {
	return WithUserLock(username, func() error {
		session, err := Load(username)
		if err != nil && !errors.Is(err, ErrCorrupt) {
			return err
		}
		// A missing or corrupt file starts a fresh session; Save replaces the
		// corrupt one atomically, so one bad file cannot disable the cached
		// login for this user forever.
		if err != nil || session == nil {
			session = &CachedSession{Username: username}
		}
		mutate(session)
		return Save(session)
	})
}

// Delete removes the cached session for the given username.
// Does not return an error if the file doesn't exist.
func Delete(username string) error {
	stem, err := fileStem(username)
	if err != nil {
		return err
	}

	err = os.Remove(cachePath(stem))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete cache: %w", err)
	}
	return nil
}
