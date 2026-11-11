package cache

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The file name of a session is the user name with every byte outside
// [A-Za-z0-9_-] written as %XX: every name gets a cache, and no name can
// leave CacheDir. Names that were valid before keep their file name.
func TestFileStem(t *testing.T) {
	for name, want := range map[string]string{
		"alice":                 "alice",
		"svc_backup-2":          "svc_backup-2",
		"john.doe":              "john%2Edoe",
		"a/b":                   "a%2Fb",
		"..":                    "%2E%2E",
		"a%2Eb":                 "a%252Eb",
		"user@example.com":      "user%40example%2Ecom",
		"a\x00b":                "a%00b",
		"j\xc3\xbcrgen":         "j%C3%BCrgen",
		strings.Repeat("a", 64): strings.Repeat("a", 64),
	} {
		got, err := fileStem(name)
		if err != nil || got != want {
			t.Errorf("fileStem(%q) = %q, %v; want %q", name, got, err, want)
		}
	}
	for _, name := range []string{"", strings.Repeat("a", 65)} {
		if stem, err := fileStem(name); err == nil {
			t.Errorf("fileStem(%q) = %q, want an error (1 to 64 bytes)", name, stem)
		}
	}
}

// Two different names never share a file.
func TestFileStem_Injective(t *testing.T) {
	names := []string{"john.doe", "john%2Edoe", "john%252Edoe", "john_doe", "john-doe", "JOHN.DOE"}
	seen := map[string]string{}
	for _, n := range names {
		stem, err := fileStem(n)
		if err != nil {
			t.Fatal(err)
		}
		if other, dup := seen[stem]; dup {
			t.Errorf("%q and %q share the file stem %q", n, other, stem)
		}
		seen[stem] = n
	}
}

// rejectedUsernames have no file name: empty and longer than 64 bytes.
var rejectedUsernames = []string{"", strings.Repeat("a", 65)}

func TestUsernameGuard_AllEntryPoints(t *testing.T) {
	setupTestDir(t)
	for _, name := range rejectedUsernames {
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
	if entries, _ := os.ReadDir(CacheDir); len(entries) != 0 {
		t.Errorf("rejected usernames created %d files in CacheDir", len(entries))
	}
}

// Names that look like a path stay inside CacheDir: every file the cache
// creates for them lies directly in it, and nothing next to it is touched.
func TestCacheStaysInsideCacheDir(t *testing.T) {
	root := t.TempDir()
	orig := CacheDir
	CacheDir = filepath.Join(root, "cache")
	t.Cleanup(func() { CacheDir = orig })
	// What a traversal would hit one level up.
	sentinel := filepath.Join(root, "x.json")
	if err := os.WriteFile(sentinel, []byte(`{"refresh_token":"untouched"}`), 0600); err != nil {
		t.Fatal(err)
	}

	names := []string{"../x", "a/../../b", ".", "..", "/abs", "x/../y", "a\nb"}
	for _, name := range names {
		if err := Update(name, func(s *CachedSession) { s.RefreshToken = "rt-" + name }); err != nil {
			t.Errorf("Update(%q): %v", name, err)
			continue
		}
		s, err := Load(name)
		if err != nil || s == nil || s.RefreshToken != "rt-"+name {
			t.Errorf("Load(%q) = %+v, %v; want the session stored under that name", name, s, err)
		}
	}

	if data, _ := os.ReadFile(sentinel); string(data) != `{"refresh_token":"untouched"}` {
		t.Errorf("a file outside CacheDir was changed: %q", data)
	}
	if entries, _ := os.ReadDir(root); len(entries) != 2 { // cache/ and x.json
		t.Errorf("the parent of CacheDir has %d entries, want 2", len(entries))
	}
	entries, err := os.ReadDir(CacheDir)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() || strings.ContainsAny(e.Name(), "/") {
			t.Errorf("unexpected entry %q in CacheDir", e.Name())
		}
		files = append(files, e.Name())
	}
	slices.Sort(files)
	if len(files) != 2*len(names) { // <stem>.json and <stem>.lock per name
		t.Errorf("CacheDir holds %d files for %d names, want a .json and a .lock each: %v", len(files), len(names), files)
	}
	if err := Delete("../x"); err != nil {
		t.Errorf("Delete(\"../x\"): %v", err)
	}
	if s, _ := Load("../x"); s != nil {
		t.Error("Delete(\"../x\") left the session")
	}
}

// A session written by 0.7.0 for a name that was valid then is found again:
// same file name, same JSON.
func TestCacheFileOf070StillLoads(t *testing.T) {
	setupTestDir(t)
	old := `{"refresh_token":"rt-070","username":"alice","known_ips":["192.0.2.10"]}`
	path := filepath.Join(CacheDir, "alice.json")
	if err := os.WriteFile(path, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := Load("alice")
	if err != nil || s == nil || s.RefreshToken != "rt-070" || !s.HasIP("192.0.2.10") {
		t.Fatalf("Load(\"alice\") = %+v, %v; want the 0.7.0 session", s, err)
	}
	if err := Update("alice", func(s *CachedSession) { s.RefreshToken = "rt-071" }); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "rt-071") || !strings.Contains(string(data), "192.0.2.10") {
		t.Errorf("the update did not rewrite %s in place: %q, %v", path, data, err)
	}
}
