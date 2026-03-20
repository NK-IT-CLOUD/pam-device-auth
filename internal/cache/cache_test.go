package cache

import (
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

	if err := Save("nk", "refresh-token-abc"); err != nil {
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

	Save("nk", "token")
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

	Save("nk", "old-token")
	Save("nk", "new-token")

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

	if err := Save("nk", "token"); err != nil {
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

	Save("nk", "token")

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
		if err := Save(name, "token"); err == nil {
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
