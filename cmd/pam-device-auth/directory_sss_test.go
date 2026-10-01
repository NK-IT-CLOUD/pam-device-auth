package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubGetent installs a fake getent on PATH that records its args and prints
// the given output with the given exit code.
func stubGetent(t *testing.T, output string, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	script := fmt.Sprintf("#!/bin/sh\necho \"$@\" > %s\nprintf '%%s' '%s'\nexit %d\n",
		argsFile, output, exitCode)
	if err := os.WriteFile(filepath.Join(dir, "getent"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return argsFile
}

func TestNSSUserExistsQueriesSSSOnly(t *testing.T) {
	argsFile := stubGetent(t, "alice:*:10000:10000::/home/alice:/bin/bash\n", 0)
	if !nssUserExists("alice") {
		t.Fatal("expected true for user present in sss")
	}
	got, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	want := "-s sss passwd -- alice"
	if strings.TrimSpace(string(got)) != want {
		t.Fatalf("getent args = %q, want %q", strings.TrimSpace(string(got)), want)
	}
}

func TestNSSUserExistsRejectsLocalOnlyUser(t *testing.T) {
	// getent -s sss exits 2 with no output when the user is not in sss —
	// even if the user exists in /etc/passwd.
	stubGetent(t, "", 2)
	if nssUserExists("localonly") {
		t.Fatal("expected false for user absent from sss")
	}
}
