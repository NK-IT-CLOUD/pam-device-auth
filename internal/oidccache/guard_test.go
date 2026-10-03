package oidccache

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func saved(t *testing.T) string {
	t.Helper()
	dir := setupTestDir(t)
	if err := Save(JWKSFile, testIssuer, []byte(`{"keys":[]}`)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return dir
}

// A symlink planted at the cache path must never be followed, even when it
// points at a perfectly valid entry.
func TestLoadRefusesSymlinkedEntry(t *testing.T) {
	dir := saved(t)
	elsewhere := filepath.Join(t.TempDir(), "valid.json")
	data, _ := os.ReadFile(filepath.Join(dir, JWKSFile))
	if err := os.WriteFile(elsewhere, data, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, DiscoveryFile)
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}
	got, err := Load(DiscoveryFile, testIssuer)
	if got != nil || err == nil {
		t.Fatalf("Load() through a symlink = %q, %v; want nil body and an error", got, err)
	}
	// Dangling symlink: also a refusal, never a panic.
	os.Remove(link)
	if err := os.Symlink(filepath.Join(dir, "nowhere"), link); err != nil {
		t.Fatal(err)
	}
	if got, _ := Load(DiscoveryFile, testIssuer); got != nil {
		t.Fatalf("Load() through a dangling symlink returned a body: %q", got)
	}
}

func TestLoadRefusesGroupOrOtherWritableEntry(t *testing.T) {
	dir := saved(t)
	for _, mode := range []os.FileMode{0660, 0606, 0666} {
		if err := os.Chmod(filepath.Join(dir, JWKSFile), mode); err != nil {
			t.Fatal(err)
		}
		if got, err := Load(JWKSFile, testIssuer); got != nil || err == nil {
			t.Errorf("mode %v: Load() = %q, %v; want nil body and an error", mode, got, err)
		}
	}
	// Read-only for others is fine.
	if err := os.Chmod(filepath.Join(dir, JWKSFile), 0644); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(JWKSFile, testIssuer); got == nil || err != nil {
		t.Errorf("mode 0644: Load() = %q, %v; want the body", got, err)
	}
}

func TestLoadRefusesForeignOwnedEntry(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown to another uid needs root")
	}
	dir := saved(t)
	if err := os.Chown(filepath.Join(dir, JWKSFile), 65534, 65534); err != nil {
		t.Skipf("chown not possible here: %v", err)
	}
	if got, err := Load(JWKSFile, testIssuer); got != nil || err == nil {
		t.Fatalf("Load() of a foreign-owned entry = %q, %v; want nil body and an error", got, err)
	}
}

func TestLoadRefusesWritableDirAndSaveTightensIt(t *testing.T) {
	dir := saved(t)
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(JWKSFile, testIssuer); got != nil || err == nil {
		t.Fatalf("Load() from a world-writable dir = %q, %v; want nil body and an error", got, err)
	}
	if err := Save(JWKSFile, testIssuer, []byte(`{"keys":[]}`)); err != nil {
		t.Fatalf("Save into a loose dir: %v", err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0700 {
		t.Errorf("Save left the dir at %v, want 0700", fi.Mode().Perm())
	}
	if got, err := Load(JWKSFile, testIssuer); got == nil || err != nil {
		t.Errorf("Load after tightening = %q, %v; want the body", got, err)
	}
}

func TestSaveTightensReadableDir(t *testing.T) {
	dir := setupTestDir(t)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := Save(JWKSFile, testIssuer, []byte(`{"keys":[]}`)); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0700 {
		t.Errorf("dir mode = %v, want 0700", fi.Mode().Perm())
	}
}

// Dir itself must not be a symlink: Save would otherwise write into whatever
// the link points at.
func TestSaveAndLoadRefuseSymlinkedDir(t *testing.T) {
	dir := setupTestDir(t)
	target := t.TempDir()
	os.Remove(dir)
	if err := os.Symlink(target, dir); err != nil {
		t.Fatal(err)
	}
	if err := Save(JWKSFile, testIssuer, []byte(`{"keys":[]}`)); err == nil {
		t.Fatal("Save through a symlinked dir succeeded")
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Errorf("Save wrote into the symlink target: %v", entries)
	}
	if got, err := Load(JWKSFile, testIssuer); got != nil || err == nil {
		t.Errorf("Load() through a symlinked dir = %q, %v; want nil body and an error", got, err)
	}
}

func TestSaveRefusesForeignOwnedDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown to another uid needs root")
	}
	dir := setupTestDir(t)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Skipf("chown not possible here: %v", err)
	}
	if err := Save(JWKSFile, testIssuer, []byte(`{"keys":[]}`)); err == nil {
		t.Fatal("Save into a foreign-owned dir succeeded")
	}
}

// A FIFO planted at the cache path must be refused without blocking the login:
// opening a FIFO that has no writer would otherwise wait forever.
func TestLoadRefusesFIFOWithoutBlocking(t *testing.T) {
	dir := saved(t)
	fifo := filepath.Join(dir, DiscoveryFile)
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Skipf("mkfifo not possible here: %v", err)
	}
	done := make(chan struct{})
	var got []byte
	var err error
	go func() {
		got, err = Load(DiscoveryFile, testIssuer)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Load() blocked on a FIFO")
	}
	if got != nil || err == nil {
		t.Fatalf("Load() of a FIFO = %q, %v; want nil body and an error", got, err)
	}
}
