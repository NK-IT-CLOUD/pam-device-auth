package cache

import (
	"errors"
	"os"
	"testing"
)

func TestLoadCorruptFileReturnsErrCorrupt(t *testing.T) {
	setupTestDir(t)
	if err := os.WriteFile(cachePath("nk"), []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := Load("nk")
	if s != nil || !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Load() = %v, %v; want nil, ErrCorrupt", s, err)
	}
}

// A corrupt file must not disable the cached login forever: Update starts a
// fresh session and replaces the file.
func TestUpdateRepairsCorruptFile(t *testing.T) {
	setupTestDir(t)
	if err := os.WriteFile(cachePath("nk"), []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	err := Update("nk", func(s *CachedSession) { s.RefreshToken = "rt"; s.AddIP("198.51.100.11") })
	if err != nil {
		t.Fatalf("Update on corrupt file: %v", err)
	}
	s, err := Load("nk")
	if err != nil || s == nil || s.RefreshToken != "rt" || !s.HasIP("198.51.100.11") {
		t.Fatalf("Load after repair = %+v, %v", s, err)
	}
}

// Read errors that are not corruption (here: the path is a directory) must
// still be returned, never papered over by a fresh session.
func TestUpdateKeepsNonCorruptErrors(t *testing.T) {
	setupTestDir(t)
	if err := os.Mkdir(cachePath("nk"), 0700); err != nil {
		t.Fatal(err)
	}
	err := Update("nk", func(s *CachedSession) {})
	if err == nil || errors.Is(err, ErrCorrupt) {
		t.Fatalf("Update() = %v; want a non-corrupt read error", err)
	}
}
