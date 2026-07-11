package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "sshd")
	if err := os.WriteFile(src, []byte("original config"), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// First backup: dst does not exist yet → copy made.
	dst := filepath.Join(dir, "sshd.original")
	didBackup, err := backupFile(src, dst)
	if err != nil {
		t.Fatalf("backupFile() error: %v", err)
	}
	if !didBackup {
		t.Error("backupFile() didBackup = false, want true on first backup")
	}
	got, _ := os.ReadFile(dst)
	if string(got) != "original config" {
		t.Errorf("backup content = %q, want %q", got, "original config")
	}

	// Second call: dst already exists → must not overwrite, no error.
	if err := os.WriteFile(src, []byte("MODIFIED"), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	didBackup, err = backupFile(src, dst)
	if err != nil {
		t.Fatalf("backupFile() error on existing dst: %v", err)
	}
	if didBackup {
		t.Error("backupFile() didBackup = true, want false when backup exists")
	}
	got, _ = os.ReadFile(dst)
	if string(got) != "original config" {
		t.Errorf("backup overwritten: %q, want preserved %q", got, "original config")
	}

	// Write failure: parent dir of dst does not exist → error surfaced.
	badDst := filepath.Join(dir, "missing-subdir", "sshd.original")
	didBackup, err = backupFile(src, badDst)
	if err == nil {
		t.Error("backupFile() error = nil, want error on unwritable dst")
	}
	if didBackup {
		t.Error("backupFile() didBackup = true, want false on write failure")
	}
}

// --debug must work regardless of position: the dispatch loop in main exits
// on the first subcommand flag, so debug detection needs a pre-pass.
func TestHasFlag(t *testing.T) {
	if !hasFlag([]string{"--check", "--debug"}, "--debug") {
		t.Error("--debug after subcommand should be found")
	}
	if hasFlag([]string{"--check"}, "--debug") {
		t.Error("absent flag should not be found")
	}
}

// stubSshd installs a fake `sshd` on PATH that answers `-T` (and `-T -C
// user=...`) with the given effective-config lines, mimicking `sshd -T`
// output well enough for sshdParam.
func stubSshd(t *testing.T, config string) {
	t.Helper()
	dir := t.TempDir()
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' '%s'\n", config)
	if err := os.WriteFile(filepath.Join(dir, "sshd"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestSshdParam_AuthorizedKeysFile(t *testing.T) {
	tests := []struct {
		name   string
		config string
		want   string
	}{
		{
			name:   "old drop-in leaves default authorizedkeysfile",
			config: "authorizedkeyscommand /usr/bin/sss_ssh_authorizedkeys\nauthorizedkeysfile .ssh/authorized_keys\n",
			want:   ".ssh/authorized_keys",
		},
		{
			name:   "hardened drop-in disables local keys",
			config: "authorizedkeyscommand /usr/bin/sss_ssh_authorizedkeys\nauthorizedkeysfile none\n",
			want:   "none",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubSshd(t, tt.config)
			got, ok := sshdParam("authorizedkeysfile", "nobody")
			if !ok {
				t.Fatal("sshdParam() ok = false, want true")
			}
			if got != tt.want {
				t.Errorf("sshdParam(authorizedkeysfile) = %q, want %q", got, tt.want)
			}
		})
	}
}
