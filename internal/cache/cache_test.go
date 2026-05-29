package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func setupTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	origDir := CacheDir
	CacheDir = dir
	t.Cleanup(func() { CacheDir = origDir })
	return dir
}

func TestSaveAndLoad(t *testing.T) {
	setupTestDir(t)

	if err := Save(&CachedSession{Username: "nk", RefreshToken: "refresh-token-abc"}); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	session, err := Load("nk")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if session == nil {
		t.Fatal("Load() returned nil")
	}
	if session.RefreshToken != "refresh-token-abc" {
		t.Errorf("RefreshToken = %q, want %q", session.RefreshToken, "refresh-token-abc")
	}
	if session.Username != "nk" {
		t.Errorf("Username = %q, want %q", session.Username, "nk")
	}
}

func TestLoad_NotFound(t *testing.T) {
	setupTestDir(t)

	session, err := Load("nonexistent")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if session != nil {
		t.Errorf("Load() = %v, want nil", session)
	}
}

func TestDelete(t *testing.T) {
	setupTestDir(t)

	Save(&CachedSession{Username: "nk", RefreshToken: "token"})
	if err := Delete("nk"); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	session, _ := Load("nk")
	if session != nil {
		t.Error("Load() should return nil after Delete()")
	}
}

func TestDelete_NotFound(t *testing.T) {
	setupTestDir(t)

	// Should not error on missing file
	if err := Delete("nonexistent"); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}
}

func TestSave_OverwritesExisting(t *testing.T) {
	setupTestDir(t)

	Save(&CachedSession{Username: "nk", RefreshToken: "old-token"})
	Save(&CachedSession{Username: "nk", RefreshToken: "new-token"})

	session, _ := Load("nk")
	if session.RefreshToken != "new-token" {
		t.Errorf("RefreshToken = %q, want %q", session.RefreshToken, "new-token")
	}
}

func TestSave_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "subdir")
	origDir := CacheDir
	CacheDir = subdir
	defer func() { CacheDir = origDir }()

	if err := Save(&CachedSession{Username: "nk", RefreshToken: "token"}); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	info, err := os.Stat(subdir)
	if err != nil {
		t.Fatalf("Stat() error: %v", err)
	}
	if info.Mode().Perm() != 0700 {
		t.Errorf("dir perm = %o, want 0700", info.Mode().Perm())
	}
}

func TestSave_FilePermissions(t *testing.T) {
	setupTestDir(t)

	Save(&CachedSession{Username: "nk", RefreshToken: "token"})

	info, err := os.Stat(filepath.Join(CacheDir, "nk.json"))
	if err != nil {
		t.Fatalf("Stat() error: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("file perm = %o, want 0600", info.Mode().Perm())
	}
}

func TestInvalidUsername(t *testing.T) {
	setupTestDir(t)

	for _, name := range []string{"../etc/passwd", "root@domain", "UPPER", "", "a b"} {
		if err := Save(&CachedSession{Username: name, RefreshToken: "token"}); err == nil {
			t.Errorf("Save(%q) should fail", name)
		}
		if _, err := Load(name); err == nil {
			t.Errorf("Load(%q) should fail", name)
		}
		if err := Delete(name); err == nil {
			t.Errorf("Delete(%q) should fail", name)
		}
	}
}

// --- IP tracking tests ---

func TestHasIP(t *testing.T) {
	s := &CachedSession{
		Username:     "nk",
		RefreshToken: "token",
		KnownIPs:     []string{"10.0.1.50", "192.168.1.1"},
	}

	if !s.HasIP("10.0.1.50") {
		t.Error("HasIP should return true for known IP")
	}
	if !s.HasIP("192.168.1.1") {
		t.Error("HasIP should return true for known IP")
	}
	if s.HasIP("10.0.2.99") {
		t.Error("HasIP should return false for unknown IP")
	}
	if s.HasIP("") {
		t.Error("HasIP should return false for empty IP")
	}
}

func TestAddIP(t *testing.T) {
	s := &CachedSession{Username: "nk", RefreshToken: "token"}

	s.AddIP("10.0.1.50")
	if len(s.KnownIPs) != 1 || s.KnownIPs[0] != "10.0.1.50" {
		t.Errorf("KnownIPs = %v, want [10.0.1.50]", s.KnownIPs)
	}

	// Adding same IP again should not duplicate
	s.AddIP("10.0.1.50")
	if len(s.KnownIPs) != 1 {
		t.Errorf("KnownIPs should not duplicate, got %v", s.KnownIPs)
	}

	// Adding a new IP
	s.AddIP("192.168.1.1")
	if len(s.KnownIPs) != 2 {
		t.Errorf("KnownIPs should have 2 entries, got %v", s.KnownIPs)
	}
}

func TestSaveAndLoad_WithKnownIPs(t *testing.T) {
	setupTestDir(t)

	session := &CachedSession{
		Username:     "nk",
		RefreshToken: "token",
		KnownIPs:     []string{"10.0.1.50", "192.168.1.1"},
	}
	if err := Save(session); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	loaded, err := Load("nk")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(loaded.KnownIPs) != 2 {
		t.Fatalf("KnownIPs length = %d, want 2", len(loaded.KnownIPs))
	}
	if !loaded.HasIP("10.0.1.50") || !loaded.HasIP("192.168.1.1") {
		t.Errorf("Loaded KnownIPs = %v, missing expected IPs", loaded.KnownIPs)
	}
}

func TestSave_PreservesKnownIPs(t *testing.T) {
	setupTestDir(t)

	// Save with IPs
	session := &CachedSession{
		Username:     "nk",
		RefreshToken: "old-token",
		KnownIPs:     []string{"10.0.1.50"},
	}
	Save(session)

	// Update token, add IP, save again
	session.RefreshToken = "new-token"
	session.AddIP("192.168.1.1")
	Save(session)

	loaded, _ := Load("nk")
	if loaded.RefreshToken != "new-token" {
		t.Errorf("RefreshToken = %q, want %q", loaded.RefreshToken, "new-token")
	}
	if len(loaded.KnownIPs) != 2 {
		t.Errorf("KnownIPs = %v, want 2 entries", loaded.KnownIPs)
	}
}

func TestLoad_BackwardCompatible(t *testing.T) {
	setupTestDir(t)

	// Simulate old cache format without known_ips
	old := `{"refresh_token":"old-token","username":"nk"}`
	os.WriteFile(filepath.Join(CacheDir, "nk.json"), []byte(old), 0600)

	session, err := Load("nk")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if session.RefreshToken != "old-token" {
		t.Errorf("RefreshToken = %q, want %q", session.RefreshToken, "old-token")
	}
	if len(session.KnownIPs) != 0 {
		t.Errorf("KnownIPs should be empty for old format, got %v", session.KnownIPs)
	}
	// Old format = no known IPs = every IP is "new" = device auth required
	if session.HasIP("10.0.1.50") {
		t.Error("HasIP should return false for old cache format")
	}
}

func TestAddIP_CapsAtMaxIPs(t *testing.T) {
	s := &CachedSession{Username: "nk", RefreshToken: "token"}
	for i := 0; i < MaxIPs+5; i++ {
		s.AddIP(fmt.Sprintf("10.0.0.%d", i))
	}
	if len(s.KnownIPs) != MaxIPs {
		t.Errorf("KnownIPs length = %d, want %d (MaxIPs)", len(s.KnownIPs), MaxIPs)
	}
	if s.HasIP("10.0.0.0") {
		t.Error("oldest IP should have been evicted")
	}
	if !s.HasIP(fmt.Sprintf("10.0.0.%d", MaxIPs+4)) {
		t.Error("newest IP should be present")
	}
}

func TestAddIP_ExistingIPMovesToEnd(t *testing.T) {
	s := &CachedSession{
		Username:     "nk",
		RefreshToken: "token",
		KnownIPs:     []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
	}
	s.AddIP("10.0.0.1")
	if len(s.KnownIPs) != 3 {
		t.Errorf("KnownIPs length = %d, want 3", len(s.KnownIPs))
	}
	if s.KnownIPs[len(s.KnownIPs)-1] != "10.0.0.1" {
		t.Errorf("re-added IP should be at end, got %v", s.KnownIPs)
	}
}
