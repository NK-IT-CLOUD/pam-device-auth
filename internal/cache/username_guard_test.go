package cache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// badUsernames covers traversal, separators, dot names, empty and over-long
// values (the pattern allows 1..32 characters).
var badUsernames = []string{
	"../x", "..", ".", "a/b", "/abs", "x/../y", "", strings.Repeat("a", 33), "a\x00b", "a\nb",
}

func TestValidateUsername_BoundaryLength(t *testing.T) {
	if err := validateUsername(strings.Repeat("a", 32)); err != nil {
		t.Errorf("32 chars should be valid: %v", err)
	}
	if err := validateUsername(strings.Repeat("a", 33)); err == nil {
		t.Error("33 chars should be rejected")
	}
}

func TestUsernameGuard_AllEntryPoints(t *testing.T) {
	setupTestDir(t)
	// A sentinel next to CacheDir proves traversal names never touch the
	// parent directory.
	parent := filepath.Dir(CacheDir)
	sentinel := filepath.Join(parent, "x.json")
	if err := os.WriteFile(sentinel, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}

	for _, name := range badUsernames {
		if err := Save(&CachedSession{Username: name, RefreshToken: "t"}); err == nil {
			t.Errorf("Save(%q) should fail", name)
		}
		if _, err := Load(name); err == nil {
			t.Errorf("Load(%q) should fail", name)
		}
		if err := Delete(name); err == nil {
			t.Errorf("Delete(%q) should fail", name)
		}
		called := false
		if err := WithUserLock(name, func() error { called = true; return nil }); err == nil || called {
			t.Errorf("WithUserLock(%q) should fail without running fn (err=%v called=%v)", name, err, called)
		}
		if err := Update(name, func(*CachedSession) {}); err == nil {
			t.Errorf("Update(%q) should fail", name)
		}
	}

	if _, err := os.Stat(sentinel); err != nil {
		t.Errorf("sentinel outside CacheDir was touched: %v", err)
	}
	if entries, _ := os.ReadDir(CacheDir); len(entries) != 0 {
		t.Errorf("rejected usernames created %d files in CacheDir", len(entries))
	}
}
