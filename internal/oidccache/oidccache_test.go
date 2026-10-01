package oidccache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testIssuer = "https://sso.example.com/realms/test"

func setupTestDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "oidc")
	orig := Dir
	Dir = dir
	t.Cleanup(func() { Dir = orig })
	return dir
}

// writeEnvelope bypasses Save so tests can plant stale or foreign entries.
func writeEnvelope(t *testing.T, name string, fetchedAt int64, issuer string, body string) {
	t.Helper()
	if err := os.MkdirAll(Dir, 0700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(envelope{FetchedAt: fetchedAt, Issuer: issuer, Body: json.RawMessage(body)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(Dir, name), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSaveAndLoad(t *testing.T) {
	setupTestDir(t)
	body := []byte(`{"keys":[{"kid":"a"}]}`)
	if err := Save(JWKSFile, testIssuer, body); err != nil {
		t.Fatalf("Save() error: %v", err)
	}
	got, err := Load(JWKSFile, testIssuer)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("Load() = %s, want %s", got, body)
	}
}

func TestSaveCreatesDirAndFileModes(t *testing.T) {
	dir := setupTestDir(t)
	if err := Save(DiscoveryFile, testIssuer, []byte(`{}`)); err != nil {
		t.Fatalf("Save() error: %v", err)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !di.IsDir() || di.Mode().Perm() != 0700 {
		t.Errorf("cache dir mode = %o, want 0700", di.Mode().Perm())
	}
	fi, err := os.Stat(filepath.Join(dir, DiscoveryFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("cache file mode = %o, want 0600", fi.Mode().Perm())
	}
}

func TestSaveLeavesNoTempFiles(t *testing.T) {
	dir := setupTestDir(t)
	if err := Save(JWKSFile, testIssuer, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := Save(JWKSFile, testIssuer, []byte(`{"keys":[]}`)); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".json.") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Errorf("expected exactly one cache file, got %d", len(entries))
	}
}

func TestSaveRejectsInvalidJSONBody(t *testing.T) {
	dir := setupTestDir(t)
	if err := Save(JWKSFile, testIssuer, []byte(`not json`)); err == nil {
		t.Fatal("Save() should reject a body that is not valid JSON")
	}
	if _, err := os.Stat(filepath.Join(dir, JWKSFile)); !os.IsNotExist(err) {
		t.Error("no cache file must be written for an invalid body")
	}
}

func TestLoadMissing(t *testing.T) {
	setupTestDir(t)
	got, err := Load(JWKSFile, testIssuer)
	if err != nil || got != nil {
		t.Errorf("Load() on missing entry = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestLoadExpired(t *testing.T) {
	setupTestDir(t)
	old := time.Now().Add(-TTL - time.Minute).Unix()
	writeEnvelope(t, JWKSFile, old, testIssuer, `{"keys":[]}`)
	got, err := Load(JWKSFile, testIssuer)
	if err != nil || got != nil {
		t.Errorf("Load() on expired entry = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestLoadFutureFetchedAtIsExpired(t *testing.T) {
	setupTestDir(t)
	future := time.Now().Add(24 * time.Hour).Unix()
	writeEnvelope(t, JWKSFile, future, testIssuer, `{"keys":[]}`)
	got, err := Load(JWKSFile, testIssuer)
	if err != nil || got != nil {
		t.Errorf("Load() on future entry = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestLoadCorrupt(t *testing.T) {
	setupTestDir(t)
	if err := os.MkdirAll(Dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(Dir, JWKSFile), []byte("{garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(JWKSFile, testIssuer)
	if err == nil || got != nil {
		t.Errorf("Load() on corrupt entry = (%v, %v), want error", got, err)
	}
}

func TestLoadEmptyBody(t *testing.T) {
	setupTestDir(t)
	if err := os.MkdirAll(Dir, 0700); err != nil {
		t.Fatal(err)
	}
	data := `{"fetched_at":` + itoa(time.Now().Unix()) + `,"issuer":"` + testIssuer + `"}`
	if err := os.WriteFile(filepath.Join(Dir, JWKSFile), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(JWKSFile, testIssuer)
	if err == nil || got != nil {
		t.Errorf("Load() on empty body = (%v, %v), want error", got, err)
	}
}

func TestLoadIssuerMismatch(t *testing.T) {
	setupTestDir(t)
	writeEnvelope(t, JWKSFile, time.Now().Unix(), "https://other.example.com/realms/x", `{"keys":[]}`)
	got, err := Load(JWKSFile, testIssuer)
	if err == nil || got != nil {
		t.Errorf("Load() with foreign issuer = (%v, %v), want error", got, err)
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
