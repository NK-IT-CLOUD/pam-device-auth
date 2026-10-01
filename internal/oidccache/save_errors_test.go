package oidccache

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSaveFailsWhenDirIsAFile(t *testing.T) {
	orig := Dir
	t.Cleanup(func() { Dir = orig })
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	// MkdirAll cannot create a directory below a regular file.
	Dir = filepath.Join(blocker, "oidc")
	if err := Save(JWKSFile, testIssuer, []byte(`{}`)); err == nil {
		t.Fatal("Save() should fail when Dir cannot be created")
	}
}

func TestSaveCreateTempFailure(t *testing.T) {
	dir := setupTestDir(t)
	// A name with a path separator makes os.CreateTemp reject the pattern
	// (works for root too, unlike a read-only directory).
	if err := Save("a/b.json", testIssuer, []byte(`{}`)); err == nil {
		t.Fatal("Save() should fail when the temp file cannot be created")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("failed Save left %d entries behind", len(entries))
	}
}

func TestSaveCreateTempFailureReadOnlyDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	dir := setupTestDir(t)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })
	if err := Save(JWKSFile, testIssuer, []byte(`{}`)); err == nil {
		t.Fatal("Save() should fail in a read-only Dir")
	}
}

func TestSaveRenameFailureCleansTemp(t *testing.T) {
	dir := setupTestDir(t)
	// A non-empty directory at the destination makes rename(2) fail.
	dest := filepath.Join(dir, JWKSFile)
	if err := os.MkdirAll(filepath.Join(dest, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	err := Save(JWKSFile, testIssuer, []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), "rename") {
		t.Fatalf("Save() error = %v, want rename failure", err)
	}
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(entries) != 1 || entries[0].Name() != JWKSFile {
		t.Errorf("temp file left behind after rename failure: %v", entries)
	}
}

func TestConcurrentSaveAndLoad(t *testing.T) {
	setupTestDir(t)
	if err := Save(JWKSFile, testIssuer, []byte(`{"keys":[0]}`)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 200)
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				if err := Save(JWKSFile, testIssuer, []byte(fmt.Sprintf(`{"keys":[%d]}`, w*100+i))); err != nil {
					errs <- fmt.Errorf("Save: %w", err)
				}
			}
		}(w)
	}
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				// Atomic rename: a reader sees a complete entry, never a
				// torn one, so Load must never report a parse error.
				got, err := Load(JWKSFile, testIssuer)
				if err != nil || got == nil {
					errs <- fmt.Errorf("Load = (%s, %v)", got, err)
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	entries, _ := os.ReadDir(Dir)
	if len(entries) != 1 {
		t.Errorf("expected one cache file after concurrent saves, got %d", len(entries))
	}
}

func TestLoadBoundaryAges(t *testing.T) {
	setupTestDir(t)
	// Just inside the TTL is served; clearly past it is a miss.
	writeEnvelope(t, JWKSFile, time.Now().Add(-TTL+30*time.Second).Unix(), testIssuer, `{"k":1}`)
	if got, err := Load(JWKSFile, testIssuer); err != nil || got == nil {
		t.Errorf("entry inside TTL = (%s, %v), want hit", got, err)
	}
	writeEnvelope(t, JWKSFile, time.Now().Add(-TTL-2*time.Second).Unix(), testIssuer, `{"k":1}`)
	if got, err := Load(JWKSFile, testIssuer); err != nil || got != nil {
		t.Errorf("entry past TTL = (%s, %v), want miss", got, err)
	}
}

func TestLoadFollowsNoGuardOnSymlinkDocumented(t *testing.T) {
	// Load does not claim any symlink/ownership/mode guard (the dir is root-only
	// tmpfs); this test only pins that a dangling symlink is a plain read error,
	// i.e. a cache miss for the caller, never a panic or a denial.
	dir := setupTestDir(t)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, JWKSFile)); err != nil {
		t.Fatal(err)
	}
	got, err := Load(JWKSFile, testIssuer)
	if got != nil {
		t.Errorf("Load() through dangling symlink returned a body: %s", got)
	}
	_ = err // nil (not-exist) or error are both a miss
}
