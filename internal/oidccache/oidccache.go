// Package oidccache keeps the OIDC discovery document and the JWKS on disk so
// a login normally needs no metadata round trips. Entries are opaque bodies in
// a small envelope; callers decode a cached body through exactly the same
// parse and validation path as a live response, so the cache can never widen
// what is accepted. Any problem reading an entry is a cache miss (live fetch),
// never a denial.
package oidccache

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Dir is the directory for cached OIDC metadata. It lives under the tmpfs
// session cache (root-only, cleared on reboot). Exported as a variable so
// tests can override it.
var Dir = "/run/pam-device-auth/oidc"

// TTL bounds how long a cached entry is served before a live refetch.
const TTL = 10 * time.Minute

// File names of the two cached documents.
const (
	DiscoveryFile = "discovery.json"
	JWKSFile      = "jwks.json"
)

type envelope struct {
	FetchedAt int64           `json:"fetched_at"`
	Issuer    string          `json:"issuer"`
	Body      json.RawMessage `json:"body"`
}

// checkDir verifies that Dir is a real directory (a symlink is never followed)
// owned by the current user. With fix set, group/other permission bits are
// removed (Dir is meant to be 0700); without it a group/other WRITABLE
// directory is an error, since anyone who can write there can plant entries.
func checkDir(fix bool) error {
	fi, err := os.Lstat(Dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory (symlinks are not followed)", Dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is owned by uid %d, expected %d", Dir, st.Uid, os.Geteuid())
	}
	if fix && fi.Mode().Perm()&0077 != 0 {
		return os.Chmod(Dir, 0700)
	}
	if !fix && fi.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("%s is group/other writable (%v)", Dir, fi.Mode().Perm())
	}
	return nil
}

// readEntry reads a cache file without following a symlink and only when it is
// a regular file owned by the current user that nobody else can write to.
// O_NONBLOCK keeps the open from waiting on a FIFO that has no writer; it has no
// effect on reading a regular file.
func readEntry(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("%s is owned by uid %d, expected %d", path, st.Uid, os.Geteuid())
	}
	if fi.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("%s is group/other writable (%v)", path, fi.Mode().Perm())
	}
	return io.ReadAll(f)
}

// Load returns the cached body of name if the entry exists, was written for
// the configured issuer and is younger than TTL. A missing or expired entry
// returns nil, nil; an unreadable, malformed or foreign-issuer entry returns
// an error. Callers treat both as a cache miss.
func Load(name, issuer string) ([]byte, error) {
	if err := checkDir(false); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("%s cache: %w", name, err)
	}
	data, err := readEntry(filepath.Join(Dir, name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s cache: %w", name, err)
	}

	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse %s cache: %w", name, err)
	}
	if env.Issuer != issuer {
		return nil, fmt.Errorf("%s cache issuer mismatch: cache=%q config=%q", name, env.Issuer, issuer)
	}
	if len(env.Body) == 0 {
		return nil, fmt.Errorf("%s cache has empty body", name)
	}

	// A negative age (fetched_at in the future) counts as expired so a clock
	// step can never pin an entry indefinitely.
	age := time.Now().Unix() - env.FetchedAt
	if age < 0 || age > int64(TTL.Seconds()) {
		return nil, nil
	}
	return env.Body, nil
}

// Save writes body for issuer atomically (unique temp file, 0600, fsync,
// rename), mirroring internal/cache. Creates Dir (0700) if it does not exist
// and tightens an existing Dir to 0700; a symlinked or foreign-owned Dir is an
// error.
// Concurrent writers are safe: last rename wins and both hold valid data.
func Save(name, issuer string, body []byte) error {
	if err := os.MkdirAll(Dir, 0700); err != nil {
		return fmt.Errorf("create oidc cache dir: %w", err)
	}
	if err := checkDir(true); err != nil {
		return fmt.Errorf("oidc cache dir: %w", err)
	}

	data, err := json.Marshal(envelope{
		FetchedAt: time.Now().Unix(),
		Issuer:    issuer,
		Body:      body,
	})
	if err != nil {
		return fmt.Errorf("marshal %s cache: %w", name, err)
	}

	tmp, err := os.CreateTemp(Dir, name+".*")
	if err != nil {
		return fmt.Errorf("create %s cache temp: %w", name, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { tmp.Close(); os.Remove(tmpName) }
	if err := tmp.Chmod(0600); err != nil {
		cleanup()
		return fmt.Errorf("chmod %s cache temp: %w", name, err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write %s cache temp: %w", name, err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync %s cache temp: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close %s cache temp: %w", name, err)
	}
	if err := os.Rename(tmpName, filepath.Join(Dir, name)); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename %s cache: %w", name, err)
	}
	return nil
}
