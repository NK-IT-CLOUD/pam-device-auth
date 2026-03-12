package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// CacheDir is the directory for cached sessions.
// Exported as a variable so tests can override it.
var CacheDir = "/run/keycloak-ssh-auth"

var validUsername = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// CachedSession holds a cached Refresh Token for a user.
type CachedSession struct {
	RefreshToken string `json:"refresh_token"`
	Username     string `json:"username"`
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

// Save writes a cached session for the given username.
// Creates the cache directory if it doesn't exist.
// Uses atomic write (temp file + rename).
func Save(username, refreshToken string) error {
	if err := validateUsername(username); err != nil {
		return err
	}

	if err := os.MkdirAll(CacheDir, 0700); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}

	session := CachedSession{
		RefreshToken: refreshToken,
		Username:     username,
	}

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal cache: %w", err)
	}

	tmpFile := cachePath(username) + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return fmt.Errorf("write cache temp: %w", err)
	}

	if err := os.Rename(tmpFile, cachePath(username)); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("rename cache: %w", err)
	}

	return nil
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
