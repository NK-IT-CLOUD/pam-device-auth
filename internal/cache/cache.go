package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
)

// CacheDir is the directory for cached sessions.
// Exported as a variable so tests can override it.
var CacheDir = "/run/pam-device-auth"

// validUsername guards the cache filename derived from the username. It allows
// mixed case so case-preserving LDAP/preferred_username values keep a working
// silent-refresh cache, while still excluding path separators, dots and other
// metacharacters that could escape CacheDir.
var validUsername = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`)

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

func validateUsername(username string) error {
	if !validUsername.MatchString(username) {
		return fmt.Errorf("invalid username for cache: %q", username)
	}
	return nil
}

func cachePath(username string) string {
	return filepath.Join(CacheDir, username+".json")
}

// Load reads a cached session for the given username.
// Returns nil, nil if no cache file exists.
func Load(username string) (*CachedSession, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(cachePath(username))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read cache: %w", err)
	}

	var session CachedSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("parse cache: %w", err)
	}

	return &session, nil
}

// Save writes a cached session atomically (unique temp file + rename). Each
// process gets its own temp file, so two concurrent PAM logins for the same
// user can no longer truncate each other's half-written temp (PDA-BUG-003);
// last rename wins. Creates the cache directory if it doesn't exist.
func Save(session *CachedSession) error {
	if err := validateUsername(session.Username); err != nil {
		return err
	}

	if err := os.MkdirAll(CacheDir, 0700); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal cache: %w", err)
	}

	// validUsername forbids dots, so "<user>.json.*" temp names can never
	// collide with another user's cache file and Load never picks them up.
	tmp, err := os.CreateTemp(CacheDir, session.Username+".json.*")
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
	if err := os.Rename(tmpName, cachePath(session.Username)); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename cache: %w", err)
	}
	return nil
}

// WithUserLock serializes an arbitrary per-user cache transaction. Callers that
// rotate refresh tokens use it to cover the complete load/network/save cycle.
// The lock is advisory and Linux-only, which matches the PAM module's platform.
func WithUserLock(username string, fn func() error) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	if err := os.MkdirAll(CacheDir, 0700); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	// validUsername forbids dots, so "<user>.lock" cannot collide with a
	// cache file of another user.
	lock, err := os.OpenFile(filepath.Join(CacheDir, username+".lock"), os.O_CREATE|os.O_RDWR, 0600)
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
		if err != nil {
			return err
		}
		if session == nil {
			session = &CachedSession{Username: username}
		}
		mutate(session)
		return Save(session)
	})
}

// Delete removes the cached session for the given username.
// Does not return an error if the file doesn't exist.
func Delete(username string) error {
	if err := validateUsername(username); err != nil {
		return err
	}

	err := os.Remove(cachePath(username))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete cache: %w", err)
	}
	return nil
}
