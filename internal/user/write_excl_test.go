package user

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileExcl_CreatesNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile")

	created, err := writeFileExcl(path, []byte("hello"), 0644)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !created {
		t.Fatal("expected created=true for new file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("content = %q, want \"hello\"", string(data))
	}
}

func TestWriteFileExcl_SkipsExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile")
	if err := os.WriteFile(path, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}

	created, err := writeFileExcl(path, []byte("replacement"), 0644)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created {
		t.Error("expected created=false for existing file")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "original" {
		t.Errorf("existing file overwritten: got %q", string(data))
	}
}

func TestWriteFileExcl_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	link := filepath.Join(dir, "profile")
	if err := os.WriteFile(target, []byte("attacker-controlled"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	created, err := writeFileExcl(link, []byte("trusted content"), 0644)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created {
		t.Fatal("O_EXCL should refuse to follow symlink")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "attacker-controlled" {
		t.Errorf("symlink target was written through: got %q", string(data))
	}
}

func TestWriteFileExcl_RefusesDanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "profile")
	if err := os.Symlink(filepath.Join(dir, "nonexistent"), link); err != nil {
		t.Fatal(err)
	}

	created, err := writeFileExcl(link, []byte("trusted content"), 0644)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created {
		t.Error("O_EXCL should refuse dangling symlink too")
	}
}
