package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/cache"
)

func withCacheDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := cache.CacheDir
	cache.CacheDir = dir
	t.Cleanup(func() { cache.CacheDir = orig })
	return dir
}

func TestRememberDeviceLogin_StoresRefreshTokenAndIP(t *testing.T) {
	withCacheDir(t)
	log, _ := testLog(t)
	rememberDeviceLogin(log, "alice", "rt-1", "192.0.2.10")

	s, err := cache.Load("alice")
	if err != nil || s == nil {
		t.Fatalf("Load: %v, %v", s, err)
	}
	if s.RefreshToken != "rt-1" || !reflect.DeepEqual(s.KnownIPs, []string{"192.0.2.10"}) {
		t.Fatalf("session = %+v, want refresh token rt-1 and IP 192.0.2.10", s)
	}
}

// Without a refresh token a cached login cannot succeed, so the IP must not be
// remembered: the next login from it would only spend an IdP round trip.
func TestRememberDeviceLogin_NoRefreshTokenCreatesNoSession(t *testing.T) {
	dir := withCacheDir(t)
	log, _ := testLog(t)
	rememberDeviceLogin(log, "alice", "", "192.0.2.10")

	if _, err := os.Stat(filepath.Join(dir, "alice.json")); !os.IsNotExist(err) {
		t.Fatalf("cache file written without a refresh token (stat err = %v)", err)
	}
}

// The cached login must follow the latest device login: a login without a
// refresh token removes the session of an earlier one, so its old token and
// known IPs cannot skip the device flow any longer.
func TestRememberDeviceLogin_NoRefreshTokenRemovesEarlierSession(t *testing.T) {
	dir := withCacheDir(t)
	log, _ := testLog(t)
	rememberDeviceLogin(log, "alice", "rt-1", "192.0.2.10")
	rememberDeviceLogin(log, "alice", "", "198.51.100.20")

	if _, err := os.Stat(filepath.Join(dir, "alice.json")); !os.IsNotExist(err) {
		t.Fatalf("earlier session still cached after a login without refresh token (stat err = %v)", err)
	}
}
