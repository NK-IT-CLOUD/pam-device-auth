package main

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/distro"
)

func TestSudoersAdminOnly(t *testing.T) {
	got := renderSudoers("ssh-admin", nil)
	if !strings.Contains(got, "%ssh-admin ALL=(ALL:ALL) ALL\n") {
		t.Fatalf("admin rule missing:\n%s", got)
	}
	if strings.Contains(got, "NOPASSWD") {
		t.Fatalf("unexpected NOPASSWD:\n%s", got)
	}
}

func TestSudoersWithNopasswdGroups(t *testing.T) {
	got := renderSudoers("ssh-admin", []string{"ssh-admin-nopasswd"})
	// admin (password) rule present, AND a NOPASSWD rule AFTER it (last match wins for dual members)
	iAdmin := strings.Index(got, "%ssh-admin ALL=(ALL:ALL) ALL")
	iNP := strings.Index(got, "%ssh-admin-nopasswd ALL=(ALL:ALL) NOPASSWD:ALL")
	if iAdmin < 0 || iNP < 0 || iNP < iAdmin {
		t.Fatalf("nopasswd rule missing or not after admin rule:\n%s", got)
	}
}

// stubChownRoot replaces the chownRoot seam for the test; nil makes it succeed
// without touching the file (tests also run as non-root).
func stubChownRoot(t *testing.T, fn func(string) error) {
	t.Helper()
	orig := chownRoot
	t.Cleanup(func() { chownRoot = orig })
	if fn == nil {
		fn = func(string) error { return nil }
	}
	chownRoot = fn
}

func TestWriteSSSDConfChownFails(t *testing.T) {
	eperm := &os.PathError{Op: "chown", Err: syscall.EPERM}
	t.Run("new file is removed", func(t *testing.T) {
		stubChownRoot(t, func(p string) error { eperm.Path = p; return eperm })
		path := filepath.Join(t.TempDir(), "sssd.conf")
		restore, err := writeSSSDConfAt(path, "[new]\n")
		if err == nil || !strings.Contains(err.Error(), "operation not permitted") ||
			!strings.Contains(err.Error(), "removed the new sssd.conf (none existed before)") {
			t.Fatalf("err = %v, want the chown EPERM and the removal of the new file", err)
		}
		if restore != nil {
			t.Error("restore func returned with an error")
		}
		if _, serr := os.Stat(path); !os.IsNotExist(serr) {
			t.Errorf("sssd.conf left behind after the chown failure: stat err = %v", serr)
		}
	})
	t.Run("previous file is restored", func(t *testing.T) {
		calls := 0
		stubChownRoot(t, func(p string) error {
			calls++
			if calls == 1 {
				return eperm
			}
			return nil
		})
		path := filepath.Join(t.TempDir(), "sssd.conf")
		if err := os.WriteFile(path, []byte("[old]\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := writeSSSDConfAt(path, "[new]\n"); err == nil || !strings.Contains(err.Error(), "restored previous sssd.conf") {
			t.Fatalf("err = %v, want the chown failure and the restore state", err)
		}
		if got, _ := os.ReadFile(path); string(got) != "[old]\n" {
			t.Errorf("content after the chown failure = %q, want the previous file", got)
		}
		if calls != 2 {
			t.Errorf("chownRoot called %d times, want 2 (write and restore)", calls)
		}
	})
	t.Run("restore reports its chown failure", func(t *testing.T) {
		stubChownRoot(t, nil)
		path := filepath.Join(t.TempDir(), "sssd.conf")
		if err := os.WriteFile(path, []byte("[old]\n"), 0600); err != nil {
			t.Fatal(err)
		}
		restore, err := writeSSSDConfAt(path, "[new]\n")
		if err != nil {
			t.Fatal(err)
		}
		chownRoot = func(string) error { return eperm }
		if _, err := restore(); err == nil {
			t.Fatal("restore() = nil although its chown failed")
		}
	})
}

// stubSyncDir makes the directory fsync after the rename fail with fn's error.
func stubSyncDir(t *testing.T, fn func(string) error) {
	t.Helper()
	orig := syncDir
	t.Cleanup(func() { syncDir = orig })
	syncDir = fn
}

// A failed directory fsync comes after the rename: the new content is at the
// path, and the error says so.
func TestAtomicWriteFileDirSyncFailsAfterRename(t *testing.T) {
	stubSyncDir(t, func(dir string) error { return &os.PathError{Op: "sync", Path: dir, Err: syscall.EIO} })
	dir := t.TempDir()
	path := filepath.Join(dir, "sssd.conf")
	err := atomicWriteFile(path, []byte("[new]\n"), 0600)
	if !errors.Is(err, errWrittenNotSynced) || !errors.Is(err, syscall.EIO) || !strings.Contains(err.Error(), path) {
		t.Fatalf("err = %v, want errWrittenNotSynced with EIO naming %s", err, path)
	}
	if got, _ := os.ReadFile(path); string(got) != "[new]\n" {
		t.Errorf("content = %q, want the new file", got)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("temp file left behind: %v", entries)
	}
}

// writeSSSDConfAt still hands back a working restore when the new sssd.conf
// is in place but its directory sync failed; the abort message says the new
// file was written and what the rollback did.
func TestWriteSSSDConfDirSyncFails(t *testing.T) {
	stubChownRoot(t, nil)
	eio := func(dir string) error { return &os.PathError{Op: "sync", Path: dir, Err: syscall.EIO} }
	t.Run("previous file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "sssd.conf")
		if err := os.WriteFile(path, []byte("[old]\n"), 0600); err != nil {
			t.Fatal(err)
		}
		stubSyncDir(t, eio)
		restore, err := writeSSSDConfAt(path, "[new]\n")
		if err == nil || restore == nil {
			t.Fatalf("writeSSSDConfAt = %v, restore nil=%v; want an error and a restore", err, restore == nil)
		}
		if got, _ := os.ReadFile(path); string(got) != "[new]\n" {
			t.Fatalf("content = %q, want the new file in place", got)
		}
		syncDir = func(string) error { return nil }
		msg := sssdConfWriteAbort(err, restore)
		for _, want := range []string{"write /etc/sssd/sssd.conf: ", "the new file is in place", "input/output error", "(restored previous sssd.conf)"} {
			if !strings.Contains(msg, want) {
				t.Errorf("abort message %q lacks %q", msg, want)
			}
		}
		if got, _ := os.ReadFile(path); string(got) != "[old]\n" {
			t.Errorf("content after the rollback = %q, want the previous file", got)
		}
	})
	t.Run("no previous file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "sssd.conf")
		stubSyncDir(t, eio)
		restore, err := writeSSSDConfAt(path, "[new]\n")
		if err == nil || restore == nil {
			t.Fatalf("writeSSSDConfAt = %v, restore nil=%v; want an error and a restore", err, restore == nil)
		}
		if msg := sssdConfWriteAbort(err, restore); !strings.Contains(msg, "(removed the new sssd.conf (none existed before))") {
			t.Errorf("abort message %q lacks the removal", msg)
		}
		if _, serr := os.Stat(path); !os.IsNotExist(serr) {
			t.Errorf("new sssd.conf left behind: stat err = %v", serr)
		}
	})
	t.Run("failure before the rename", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing-subdir", "sssd.conf")
		restore, err := writeSSSDConfAt(path, "[new]\n")
		if err == nil || restore != nil {
			t.Fatalf("writeSSSDConfAt = %v, restore nil=%v; want an error and no restore", err, restore == nil)
		}
		if msg := sssdConfWriteAbort(err, nil); strings.Contains(msg, "(") || !strings.HasPrefix(msg, "write /etc/sssd/sssd.conf: ") {
			t.Errorf("abort message %q, want the write error without a rollback note", msg)
		}
	})
}

// An existing file that cannot be read (here: a directory at the path, EISDIR)
// is not "none existed": each writer refuses before it writes anything, so a
// rollback can never delete what it could not save.
func TestWritersRefuseUnreadableExistingFile(t *testing.T) {
	stubChownRoot(t, nil)
	oldPath, oldTest := sshdDropinPath, sshdTest
	t.Cleanup(func() { sshdDropinPath, sshdTest = oldPath, oldTest })
	sshdTest = func() ([]byte, error) { t.Error("sshd -t ran although nothing was written"); return nil, nil }
	noCheck := func() ([]byte, error) { t.Error("visudo -c ran although nothing was written"); return nil, nil }
	for name, write := range map[string]func(path string) error{
		"sssd.conf": func(path string) error { _, err := writeSSSDConfAt(path, "[new]\n"); return err },
		"sshd drop-in": func(path string) error {
			sshdDropinPath = path
			return writeSshdDropin("/usr/bin/sss_ssh_authorizedkeys", nil, "")
		},
		"sudoers": func(path string) error { return writeSudoersAt(path, "%ssh-admin ALL=(ALL:ALL) ALL\n", noCheck) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "conf")
			if err := os.Mkdir(path, 0755); err != nil {
				t.Fatal(err)
			}
			err := write(path)
			if err == nil || !strings.Contains(err.Error(), "cannot read the existing "+path) || !strings.Contains(err.Error(), "nothing was written") {
				t.Fatalf("err = %v, want a read error before the write", err)
			}
			if fi, serr := os.Stat(path); serr != nil || !fi.IsDir() {
				t.Errorf("existing path changed: %v", serr)
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 1 {
				t.Errorf("temp file left behind: %v", entries)
			}
		})
	}
}

// After a write that is in place but whose directory sync failed, the drop-in
// and sudoers writers still validate: accepted means the error says the
// validated file is in place; rejected means the previous file is back.
func TestValidatedWritersAfterDirSyncFailure(t *testing.T) {
	oldPath, oldTest := sshdDropinPath, sshdTest
	t.Cleanup(func() { sshdDropinPath, sshdTest = oldPath, oldTest })
	failFirstSync := func() {
		n := 0
		stubSyncDir(t, func(dir string) error {
			if n++; n == 1 {
				return &os.PathError{Op: "sync", Path: dir, Err: syscall.EIO}
			}
			return nil
		})
	}
	ok := func() ([]byte, error) { return nil, nil }
	reject := func() ([]byte, error) { return []byte("bad config"), errors.New("exit status 1") }
	type writer struct {
		check string
		run   func(path string, validate func() ([]byte, error)) error
	}
	for name, w := range map[string]writer{
		"sshd drop-in": {"sshd -t", func(path string, validate func() ([]byte, error)) error {
			sshdDropinPath, sshdTest = path, validate
			return writeSshdDropin("/usr/bin/sss_ssh_authorizedkeys", nil, "")
		}},
		"sudoers": {"visudo -c", func(path string, validate func() ([]byte, error)) error {
			return writeSudoersAt(path, "%ssh-admin ALL=(ALL:ALL) ALL\n", validate)
		}},
	} {
		t.Run(name+" accepted", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "conf")
			failFirstSync()
			validated := false
			err := w.run(path, func() ([]byte, error) { validated = true; return ok() })
			if !validated {
				t.Fatalf("%s did not run after the sync failure", w.check)
			}
			if !errors.Is(err, errWrittenNotSynced) || !strings.Contains(err.Error(), "passed "+w.check) {
				t.Fatalf("err = %v, want errWrittenNotSynced saying the file passed %s", err, w.check)
			}
			if _, serr := os.Stat(path); serr != nil {
				t.Errorf("validated file not in place: %v", serr)
			}
		})
		t.Run(name+" rejected", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "conf")
			if err := os.WriteFile(path, []byte("# previous\n"), 0644); err != nil {
				t.Fatal(err)
			}
			failFirstSync()
			err := w.run(path, reject)
			if err == nil || !strings.Contains(err.Error(), w.check+" rejected") || !strings.Contains(err.Error(), "bad config") {
				t.Fatalf("err = %v, want the %s rejection", err, w.check)
			}
			if got, _ := os.ReadFile(path); string(got) != "# previous\n" {
				t.Errorf("previous file not restored: %q", got)
			}
		})
	}
}

func TestSetupAbortMessage(t *testing.T) {
	got := setupAbortMessage("sshd config: sshd -t rejected", "restored previous sssd.conf",
		[]string{"mkhomedir PAM wiring (authselect)", "sudoers drop-in /etc/sudoers.d/pam-device-auth"})
	want := "sshd config: sshd -t rejected (restored previous sssd.conf); still in place on the host: " +
		"mkhomedir PAM wiring (authselect), sudoers drop-in /etc/sudoers.d/pam-device-auth"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	if got := setupAbortMessage("x", "restored previous sssd.conf", nil); got != "x (restored previous sssd.conf)" {
		t.Errorf("no remaining changes: got %q", got)
	}
}

func TestRollbackSSSD(t *testing.T) {
	boom := fmt.Errorf("exit status 1")
	cases := []struct {
		name       string
		did        string // what restore reports
		restoreErr error
		restart    bool
		restartErr error
		want       string
		wantCalls  int
	}{
		{"restore only", "restored previous sssd.conf", nil, false, nil, "restored previous sssd.conf", 0},
		{"no previous file", "removed the new sssd.conf (none existed before)", nil, false, nil,
			"removed the new sssd.conf (none existed before)", 0},
		{"restore and restart", "restored previous sssd.conf", nil, true, nil, "restored previous sssd.conf and restarted sssd", 1},
		{"restart fails", "restored previous sssd.conf", nil, true, boom, "restored previous sssd.conf, but sssd did not restart", 1},
		{"restore fails", "", fmt.Errorf("EROFS"), true, nil, "could NOT roll back sssd.conf: EROFS", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var calls []string
			run := fakeRunner(map[string]error{"systemctl restart sssd": c.restartErr}, nil, &calls)
			got := rollbackSSSD(run, func() (string, error) { return c.did, c.restoreErr }, c.restart)
			if !strings.HasPrefix(got, c.want) {
				t.Errorf("got %q, want prefix %q", got, c.want)
			}
			if len(calls) != c.wantCalls {
				t.Errorf("calls = %q, want %d restart(s)", calls, c.wantCalls)
			}
		})
	}
}

// The authselect profile stays selected when oddjobd cannot be enabled; the
// abort message must say so (the restore covers sssd.conf only).
func TestWireMkhomedirOddjobdFailureNamesAuthselectProfile(t *testing.T) {
	const oddjobd = "systemctl enable --now oddjobd"
	var calls []string
	err := wireMkhomedir(distro.Profile{PamWiring: "authselect"},
		fakeRunner(map[string]error{oddjobd: fmt.Errorf("exit status 1")}, nil, &calls))
	if err == nil || !strings.Contains(err.Error(), `authselect profile "sssd with-mkhomedir" stays selected`) {
		t.Fatalf("err = %v, want the remaining authselect profile named", err)
	}
}

func TestCheckSSSDIfp(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "sssd_ifp")
	if err := os.WriteFile(present, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := checkSSSDIfp(present); err != nil {
		t.Errorf("present binary: %v", err)
	}
	missing := filepath.Join(dir, "missing", "sssd_ifp")
	err := checkSSSDIfp(missing)
	if err == nil || !strings.Contains(err.Error(), missing) || !strings.Contains(err.Error(), "sssd-dbus") {
		t.Errorf("missing binary: err = %v, want the path and the sssd-dbus package", err)
	}
}

func TestWriteSSSDConfAt_AtomicAndRestores(t *testing.T) {
	stubChownRoot(t, nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "sssd.conf")

	// Pre-existing known-good config that must be recoverable.
	if err := os.WriteFile(path, []byte("[old]\nknown-good\n"), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	restore, err := writeSSSDConfAt(path, "[new]\nfresh\n")
	if err != nil {
		t.Fatalf("writeSSSDConfAt: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "[new]\nfresh\n" {
		t.Errorf("after write, content = %q, want new content", got)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0600 {
		t.Errorf("perm = %o, want 0600", fi.Mode().Perm())
	}
	// No stray temp files left behind in the directory.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("expected only sssd.conf, got %d entries (temp leak?)", len(entries))
	}

	// Restore must reinstate the prior known-good config (simulating a failed
	// sssd restart on the new config).
	if did, err := restore(); err != nil || did != "restored previous sssd.conf" {
		t.Errorf("restore() = %q, %v; want the previous file reported as restored", did, err)
	}
	got, _ = os.ReadFile(path)
	if string(got) != "[old]\nknown-good\n" {
		t.Errorf("after restore, content = %q, want prior known-good", got)
	}
}

func TestWriteSSSDConfAt_RestoreRemovesWhenNoPrior(t *testing.T) {
	stubChownRoot(t, nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "sssd.conf")

	restore, err := writeSSSDConfAt(path, "[new]\nfresh\n")
	if err != nil {
		t.Fatalf("writeSSSDConfAt: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file should exist after write: %v", err)
	}
	// No prior config existed, so restore removes the file entirely and says so.
	if did, err := restore(); err != nil || did != "removed the new sssd.conf (none existed before)" {
		t.Errorf("restore() = %q, %v; want the removal reported", did, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("restore should remove file when no prior existed; stat err = %v", err)
	}
}

// validLDAP returns a directory config that must pass validation; tests mutate
// one field at a time to assert a specific rejection.
func validLDAP() *config.LDAPConfig {
	return &config.LDAPConfig{
		Profile:      config.LDAPProfileLLDAP,
		URI:          "ldaps://ldap.example.com:636",
		BaseDN:       "dc=example,dc=com",
		BindDN:       "cn=admin,ou=people,dc=example,dc=com",
		BindPassword: "s3cr3t-with-symbols!@#",
		AccessGroup:  "ssh-access",
		AdminGroup:   "ssh-admin",
	}
}

func TestValidateLDAPConfig_AcceptsValid(t *testing.T) {
	if err := validateLDAPConfig(validLDAP()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestValidateLDAPConfig_AcceptsExplicitSearchBases(t *testing.T) {
	l := validLDAP()
	l.UserSearchBase = "ou=people,dc=example,dc=com"
	l.GroupSearchBase = "ou=groups,dc=example,dc=com"
	if err := validateLDAPConfig(l); err != nil {
		t.Fatalf("valid explicit search bases rejected: %v", err)
	}
}

func TestValidateLDAPConfig_RejectsIncomplete(t *testing.T) {
	l := validLDAP()
	l.URI = ""
	if err := validateLDAPConfig(l); err == nil {
		t.Error("incomplete config (missing uri) should be rejected")
	}
}

// Finding 1: newline in user_search_base / group_search_base injects sssd.conf
// directives — these fields previously bypassed the newline guard entirely.
func TestValidateLDAPConfig_RejectsNewlineInUserSearchBase(t *testing.T) {
	l := validLDAP()
	l.UserSearchBase = "ou=people,dc=x\nldap_tls_reqcert = never"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("newline in user_search_base should be rejected (sssd.conf injection)")
	}
}

func TestValidateLDAPConfig_RejectsNewlineInGroupSearchBase(t *testing.T) {
	l := validLDAP()
	l.GroupSearchBase = "ou=groups,dc=x\nldap_access_filter = (objectClass=*)"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("newline in group_search_base should be rejected (access-filter override)")
	}
}

func TestValidateLDAPConfig_RejectsNewlineInBaseDN(t *testing.T) {
	l := validLDAP()
	l.BaseDN = "dc=x\nldap_tls_reqcert = never"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("newline in base_dn should be rejected")
	}
}

// Finding 2: LDAP-filter metacharacters in a search base break out of the
// (memberOf=cn=<group>,<base>) access filter, widening who may log in.
func TestValidateLDAPConfig_RejectsFilterMetacharsInGroupSearchBase(t *testing.T) {
	l := validLDAP()
	l.GroupSearchBase = "ou=g,dc=x)(uid=*"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("LDAP-filter metacharacters in group_search_base should be rejected")
	}
}

func TestValidateLDAPConfig_RejectsFilterMetacharsInBaseDN(t *testing.T) {
	l := validLDAP()
	l.BaseDN = "dc=x)(uid=*"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("LDAP-filter metacharacters in base_dn should be rejected")
	}
}

// Finding 3: group names land in sudoers (%group) and the access filter; a
// value carrying sudoers grammar can silently grant passwordless root.
func TestValidateLDAPConfig_RejectsSudoersPayloadInAdminGroup(t *testing.T) {
	l := validLDAP()
	l.AdminGroup = "ssh-admin ALL=(ALL:ALL) NOPASSWD:ALL #"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("sudoers-significant characters in admin_group should be rejected")
	}
}

func TestValidateLDAPConfig_RejectsMetacharsInAccessGroup(t *testing.T) {
	for _, bad := range []string{"ssh access", "ssh=access", "ssh,access", "ssh)access", "ssh*"} {
		l := validLDAP()
		l.AccessGroup = bad
		if err := validateLDAPConfig(l); err == nil {
			t.Errorf("access_group %q should be rejected", bad)
		}
	}
}

func TestValidateLDAPConfig_AcceptsHyphenAndUnderscoreGroups(t *testing.T) {
	l := validLDAP()
	l.AccessGroup = "ssh-access_2"
	l.AdminGroup = "ssh_admins"
	if err := validateLDAPConfig(l); err != nil {
		t.Fatalf("hyphen/underscore group names rejected: %v", err)
	}
}

// Guard against the injection error message leaking the (secret) bind password:
// the error must name the field, not echo the value, for password fields.
func TestValidateLDAPConfig_RejectsNewlineInBindPassword(t *testing.T) {
	l := validLDAP()
	l.BindPassword = "pw\nldap_tls_reqcert = never"
	err := validateLDAPConfig(l)
	if err == nil {
		t.Fatal("newline in bind_password should be rejected")
	}
	if strings.Contains(err.Error(), "ldap_tls_reqcert") {
		t.Error("error message must not echo the bind_password value")
	}
}

// The restore closure is the emergency path after a failed `systemctl restart
// sssd` — it must use the same temp-file+rename pattern as the forward write.
// atomicWriteFile is that shared primitive.
func TestAtomicWriteFile_WritesContentModeAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/sssd.conf"
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := atomicWriteFile(path, []byte("[restored]\n"), 0600); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "[restored]\n" {
		t.Errorf("content = %q", got)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temp file left behind: %v", entries)
	}
}

func TestAtomicWriteFile_ErrorLeavesTargetUntouched(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/sub/does-not-exist/sssd.conf"
	if err := atomicWriteFile(path, []byte("x"), 0600); err == nil {
		t.Error("expected error for unwritable directory")
	}
}

func TestSshdDropinDisablesLocalKeysForNonRoot(t *testing.T) {
	content := renderSshdDropin("/usr/bin/sss_ssh_authorizedkeys", nil, "")
	matchIdx := strings.Index(content, "Match User root")
	if matchIdx < 0 {
		t.Fatal("drop-in must contain a 'Match User root' block")
	}
	global := content[:matchIdx]
	rootBlock := content[matchIdx:]
	if !strings.Contains(global, "AuthorizedKeysFile none") {
		t.Error("global section must set 'AuthorizedKeysFile none' (PDA-SEC-001)")
	}
	if !strings.Contains(rootBlock, "AuthorizedKeysFile .ssh/authorized_keys") {
		t.Error("root Match block must restore 'AuthorizedKeysFile .ssh/authorized_keys' (break-glass)")
	}
}

func TestSshdDropinLogsOnlyClientVersion(t *testing.T) {
	content := renderSshdDropin("/usr/bin/sss_ssh_authorizedkeys", nil, "")
	global := content[:strings.Index(content, "Match ")]
	if !strings.Contains(global, "\nLogLevel VERBOSE\n") || strings.Contains(content, "DEBUG") {
		t.Errorf("drop-in must set LogLevel VERBOSE and no debug level:\n%s", content)
	}
	if !strings.Contains(global, "\n"+sshdLogVerbose+"\n") {
		t.Errorf("global section must force the client version line (%q):\n%s", sshdLogVerbose, content)
	}
}

func TestSshdDropinNoServiceGroupsUnchanged(t *testing.T) {
	got := renderSshdDropin("/usr/bin/sss_ssh_authorizedkeys", nil, "")
	if strings.Contains(got, "Match Group") {
		t.Fatalf("no service groups but Match Group present:\n%s", got)
	}
}

func TestSshdDropinServiceGroupKeyOnly(t *testing.T) {
	got := renderSshdDropin("/usr/bin/sss_ssh_authorizedkeys", []string{"ssh-service", "ci"}, "")
	if !strings.Contains(got, "Match Group ssh-service,ci\n    AuthenticationMethods publickey\n") {
		t.Fatalf("service Match block wrong:\n%s", got)
	}
	// Root block must still be present and after (or independent of) the service block.
	if !strings.Contains(got, "Match User root") {
		t.Fatalf("root break-glass block lost:\n%s", got)
	}
}

func TestNsswitchWithSSS(t *testing.T) {
	in := []byte("passwd: files systemd\ngroup: files\nshadow: files\nhosts: files dns\n")
	out, changed := nsswitchWithSSS(in)
	if !changed {
		t.Fatal("expected changed=true")
	}
	got := string(out)
	for _, want := range []string{"passwd: files systemd sss", "group: files sss", "shadow: files sss"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "hosts: files dns") || strings.Contains(got, "hosts: files dns sss") {
		t.Error("hosts line must be untouched")
	}
	if _, changed := nsswitchWithSSS(out); changed {
		t.Error("second pass must be a no-op")
	}
}

func TestSshdDropinUsesProfileSSSPath(t *testing.T) {
	got := renderSshdDropin("/usr/libexec/sssd/sss_ssh_authorizedkeys", nil, "")
	if !strings.Contains(got, "AuthorizedKeysCommand /usr/libexec/sssd/sss_ssh_authorizedkeys") {
		t.Fatalf("sshd drop-in missing RHEL SSS path:\n%s", got)
	}
}

func TestSSSDConfUsesProfileCAPath(t *testing.T) {
	d := ldapRenderData{
		URI:          "ldaps://ldap.example.com:636",
		BaseDN:       "dc=example,dc=com",
		UserBase:     "ou=people,dc=example,dc=com",
		GroupBase:    "ou=groups,dc=example,dc=com",
		BindDN:       "cn=admin,ou=people,dc=example,dc=com",
		BindPassword: "s3cr3t-with-symbols!@#",
		AccessGroup:  "ssh-access",
	}
	got := renderSSSDConf(d, "/etc/pki/tls/certs/ca-bundle.crt")
	if !strings.Contains(got, "ldap_tls_cacert = /etc/pki/tls/certs/ca-bundle.crt") {
		t.Fatalf("sssd.conf missing RHEL CA path:\n%s", got)
	}
}

// Debian-family regression: the same renderers must still produce the
// historical Debian values when given the Debian profile's paths.
func TestSSSDConfUsesDebianCAPathByDefault(t *testing.T) {
	d := ldapRenderData{
		URI:          "ldaps://ldap.example.com:636",
		BaseDN:       "dc=example,dc=com",
		UserBase:     "ou=people,dc=example,dc=com",
		GroupBase:    "ou=groups,dc=example,dc=com",
		BindDN:       "cn=admin,ou=people,dc=example,dc=com",
		BindPassword: "s3cr3t-with-symbols!@#",
		AccessGroup:  "ssh-access",
	}
	got := renderSSSDConf(d, "/etc/ssl/certs/ca-certificates.crt")
	if !strings.Contains(got, "ldap_tls_cacert = /etc/ssl/certs/ca-certificates.crt") {
		t.Fatalf("sssd.conf missing Debian CA path:\n%s", got)
	}
}

func TestSshdDropinUsesDebianSSSPathByDefault(t *testing.T) {
	got := renderSshdDropin("/usr/bin/sss_ssh_authorizedkeys", nil, "")
	if !strings.Contains(got, "AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys") {
		t.Fatalf("sshd drop-in missing Debian SSS path:\n%s", got)
	}
}

func TestSSSDConfSingleGroupUnchanged(t *testing.T) {
	got := renderSSSDConf(ldapRenderData{URI: "u", BaseDN: "b", UserBase: "ub", GroupBase: "gb", BindDN: "bd", BindPassword: "pw", AccessGroup: "ssh-access"}, "/ca")
	if !strings.Contains(got, "ldap_access_filter = (memberOf=cn=ssh-access,gb)\n") {
		t.Fatalf("single-group filter changed:\n%s", got)
	}
	for _, want := range []string{
		"services = nss, pam, ssh, ifp\n",
		"ldap_user_extra_attrs = clients:clients\n",
		"[ifp]\nuser_attributes = +clients\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("sssd.conf missing %q:\n%s", want, got)
		}
	}
}

func TestSSSDConfWidenedFilterWithServiceGroups(t *testing.T) {
	got := renderSSSDConf(ldapRenderData{URI: "u", BaseDN: "b", UserBase: "ub", GroupBase: "gb", BindDN: "bd", BindPassword: "pw", AccessGroup: "ssh-access", ServiceGroups: []string{"ssh-service"}}, "/ca")
	want := "ldap_access_filter = (|(memberOf=cn=ssh-access,gb)(memberOf=cn=ssh-service,gb))\n"
	if !strings.Contains(got, want) {
		t.Fatalf("widened filter wrong:\n%s", got)
	}
	for _, want := range []string{
		"services = nss, pam, ssh, ifp\n",
		"ldap_user_extra_attrs = clients:clients\n",
		"[ifp]\nuser_attributes = +clients\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("sssd.conf missing %q:\n%s", want, got)
		}
	}
}

func TestSSSDConfHasInfoPipeForClients(t *testing.T) {
	got := renderSSSDConf(ldapRenderData{URI: "u", BaseDN: "b", UserBase: "ub", GroupBase: "gb", BindDN: "bd", BindPassword: "pw", AccessGroup: "ssh-access"}, "/ca")
	for _, want := range []string{
		"services = nss, pam, ssh, ifp\n",
		"ldap_user_extra_attrs = clients:clients\n",
		"[ifp]\nuser_attributes = +clients\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("sssd.conf missing %q:\n%s", want, got)
		}
	}
}

// The lldap profile must render what 0.5.15 rendered, minus config_file_version
// (SSSD 2.12 reports it; 2.x defaults to version 2). Any other diff is a
// behaviour change on every LLDAP host at the next --setup-ldap.
func TestRenderSSSDConf_LLDAPGolden(t *testing.T) {
	want := lldapGolden(t)
	got := renderSSSDConf(ldapRenderData{
		URI: "ldaps://ldap.example.com:6360", BaseDN: "dc=example,dc=com",
		UserBase: "ou=people,dc=example,dc=com", GroupBase: "ou=groups,dc=example,dc=com",
		BindDN: "uid=ro,ou=people,dc=example,dc=com", BindPassword: "pw",
		AccessGroup: "ssh-access", ServiceGroups: []string{"ssh-service"},
	}, "/etc/ssl/certs/ca-certificates.crt")
	if got != want {
		t.Fatalf("lldap sssd.conf differs from the golden file:\n--- got\n%s\n--- want\n%s", got, want)
	}
}

func TestRenderSSSDConf_LLDAPExplicitDefaultsEqualGolden(t *testing.T) {
	want := lldapGolden(t)
	got := renderSSSDConf(ldapRenderData{
		Profile: config.LDAPProfileLLDAP, URI: "ldaps://ldap.example.com:6360", BaseDN: "dc=example,dc=com",
		UserBase: "ou=people,dc=example,dc=com", GroupBase: "ou=groups,dc=example,dc=com",
		BindDN: "uid=ro,ou=people,dc=example,dc=com", BindPassword: "pw",
		AccessGroup: "ssh-access", ServiceGroups: []string{"ssh-service"},
		UserNameAttr: "uid", SSHKeyAttr: "sshPublicKey", ClientsAttr: "clients", Home: "/home/%u", Shell: "/bin/bash",
	}, "/etc/ssl/certs/ca-certificates.crt")
	if got != want {
		t.Fatalf("explicit lldap defaults change the output:\n%s", got)
	}
}

func TestRenderSSSDConf_LLDAPStartTLSAndKerberos(t *testing.T) {
	got := renderSSSDConf(ldapRenderData{
		URI: "ldap://ldap.example.com:389", BaseDN: "dc=example,dc=com",
		UserBase: "ou=people,dc=example,dc=com", GroupBase: "ou=groups,dc=example,dc=com",
		BindDN: "uid=ro,ou=people,dc=example,dc=com", BindPassword: "pw", AccessGroup: "ssh-access",
		KrbRealm: "EXAMPLE.COM", KrbKDC: "kdc.example.com", KrbKpasswd: "kdc.example.com",
	}, "/etc/ssl/certs/ca-certificates.crt")
	for _, line := range []string{
		"auth_provider = krb5\n", "chpass_provider = krb5\n", "ldap_id_use_start_tls = true\n",
		"krb5_realm = EXAMPLE.COM\n", "krb5_server = kdc.example.com\n", "krb5_kpasswd = kdc.example.com\n",
		"ldap_tls_reqcert = hard\n",
	} {
		if !strings.Contains(got, line) {
			t.Errorf("missing %q in:\n%s", line, got)
		}
	}
}

// No option may produce a cleartext bind: the renderer itself decides StartTLS
// from the URI, for both profiles. url.Parse lowercases the scheme, so
// validateLDAPURI also lets LDAP:// through; it must get StartTLS as well.
func TestRenderSSSDConf_StartTLSDerivedFromURI(t *testing.T) {
	for _, profile := range []string{config.LDAPProfileLLDAP, config.LDAPProfileAD} {
		for _, c := range []struct {
			uri      string
			startTLS bool
		}{
			{"ldap://ldap.example.com:389", true},
			{"ldap://ldap.example.com", true},
			{"LDAP://ldap.example.com", true},
			{"ldaps://ldap.example.com:636", false},
			{"LDAPS://ldap.example.com", false},
		} {
			got := renderSSSDConf(ldapRenderData{
				Profile: profile, URI: c.uri, BaseDN: "dc=example,dc=com",
				UserBase: "ou=people,dc=example,dc=com", GroupBase: "ou=groups,dc=example,dc=com",
				BindDN: "uid=ro,ou=people,dc=example,dc=com", BindPassword: "pw", AccessGroup: "ssh-access",
			}, "/etc/ssl/certs/ca-certificates.crt")
			if has := strings.Contains(got, "ldap_id_use_start_tls = true\n"); has != c.startTLS {
				t.Errorf("profile %s, uri %s: ldap_id_use_start_tls present = %v, want %v:\n%s", profile, c.uri, has, c.startTLS, got)
			}
		}
	}
}

// A keytab replaces the simple bind: no bind DN/authtok lines, GSSAPI with the
// principal and SASL sealing (minssf 56). StartTLS is switched off explicitly,
// because SSSD 2.10 and later default ldap_id_use_start_tls to true and AD and
// Samba refuse GSSAPI sealing inside TLS.
func TestRenderSSSDConf_KeytabBind(t *testing.T) {
	for _, profile := range []string{config.LDAPProfileLLDAP, config.LDAPProfileAD} {
		for _, uri := range []string{"ldap://dc1.example.com", "LDAP://dc1.example.com"} {
			got := renderSSSDConf(ldapRenderData{
				Profile: profile, URI: uri, BaseDN: "DC=example,DC=com",
				UserBase: "DC=example,DC=com", GroupBase: "DC=example,DC=com",
				BindDN: "host/client1.example.com@EXAMPLE.COM", Keytab: "/etc/krb5.sssd.keytab", AccessGroup: "ssh-access",
				KrbRealm: "EXAMPLE.COM", KrbKDC: "dc1.example.com",
			}, "/etc/ssl/certs/ca-certificates.crt")
			for _, line := range []string{
				"ldap_sasl_mech = GSSAPI\n", "ldap_sasl_authid = host/client1.example.com@EXAMPLE.COM\n",
				"ldap_krb5_keytab = /etc/krb5.sssd.keytab\n", "ldap_krb5_init_creds = true\n",
				"ldap_uri = " + uri + "\nldap_id_use_start_tls = false\n", "ldap_sasl_minssf = 56\n",
			} {
				if !strings.Contains(got, line) {
					t.Errorf("profile %s, uri %s: missing %q:\n%s", profile, uri, line, got)
				}
			}
			for _, absent := range []string{"ldap_default_bind_dn", "ldap_default_authtok", "ldap_id_use_start_tls = true", "ldap_sasl_maxssf"} {
				if strings.Contains(got, absent) {
					t.Errorf("profile %s, uri %s: unexpected %s with a keytab:\n%s", profile, uri, absent, got)
				}
			}
		}
	}
}

func TestValidateRejectsBadServiceGroup(t *testing.T) {
	l := validLDAP()
	l.ServiceAccountGroups = []string{"ok", "bad group"}
	if err := validateLDAPConfig(l); err == nil {
		t.Fatal("expected rejection of 'bad group'")
	}
}

// ldap:// is accepted because the renderer then enforces StartTLS (or SASL
// sealing with a keytab); every other scheme and every list stays rejected.
func TestValidateLDAPConfig_URIScheme(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		ok   bool
	}{
		{"ldaps with port accepted", "ldaps://ldap.example.com:6360", true},
		{"ldaps without port accepted", "ldaps://ldap.example.com", true},
		{"ldap accepted (StartTLS)", "ldap://ldap.example.com:389", true},
		{"ldapi rejected", "ldapi:///var/run/slapd.sock", false},
		{"http rejected", "http://ldap.example.com", false},
		{"garbage rejected", "not a uri", false},
		{"ldaps with empty host rejected", "ldaps://", false},
		{"failover list rejected", "ldaps://a.example.com,ldap://b.example.com", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := validLDAP()
			l.URI = c.uri
			err := validateLDAPConfig(l)
			if c.ok && err != nil {
				t.Fatalf("uri %q rejected: %v", c.uri, err)
			}
			if !c.ok && err == nil {
				t.Fatalf("uri %q should be rejected", c.uri)
			}
		})
	}
}

func validADLDAP() *config.LDAPConfig {
	l := validLDAP()
	l.Profile = config.LDAPProfileAD
	l.URI = "ldaps://dc1.example.com"
	l.BaseDN = "DC=example,DC=com"
	l.BindDN = "svc-sssd@example.com"
	l.Attributes = config.LDAPAttributes{SSHKey: "sshPublicKey", Clients: "extensionAttribute1"}
	return l
}

func TestValidateLDAPConfig_Profiles(t *testing.T) {
	if err := validateLDAPConfig(validADLDAP()); err != nil {
		t.Fatalf("valid ad config rejected: %v", err)
	}
	l := validLDAP()
	l.Profile = "openldap"
	if err := validateLDAPConfig(l); err == nil || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("unknown profile: err = %v", err)
	}
}

// ldap.profile has no implicit value: empty is the verbatim required error,
// lldap and ad pass, anything else names the value.
func TestValidateLDAPProfileRequired(t *testing.T) {
	for _, c := range []struct{ profile, want string }{
		{"", `config: ldap.profile is required ("lldap" or "ad")`},
		{"lldap", ""},
		{"ad", ""},
		{"openldap", `ldap.profile must be "lldap" or "ad", got "openldap"`},
	} {
		err := validateLDAPProfile(&config.LDAPConfig{Profile: c.profile})
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != c.want {
			t.Errorf("profile %q: err = %q, want %q", c.profile, got, c.want)
		}
	}
	l := validLDAP()
	l.Profile = ""
	if err := validateLDAPConfig(l); err == nil || err.Error() != `config: ldap.profile is required ("lldap" or "ad")` {
		t.Errorf("validateLDAPConfig without profile: err = %v", err)
	}
}

// The login shell sssd.conf hands to directory users must exist, be a regular
// file and be executable by them (other users). ldapShell supplies the
// documented default when ldap.shell is empty.
func TestCheckLDAPShell(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ok := mk("ok", 0755)
	ownerOnly := mk("owner-only", 0700)
	noExec := mk("noexec", 0644)
	missing := filepath.Join(dir, "missing")
	for _, c := range []struct{ path, want string }{
		{ok, ""},
		{missing, "login shell " + missing + " (ldap.shell): "},
		{dir, "login shell " + dir + " (ldap.shell) is not a regular file"},
		{noExec, "login shell " + noExec + " (ldap.shell) is not executable by directory users (mode -rw-r--r--)"},
		{ownerOnly, "login shell " + ownerOnly + " (ldap.shell) is not executable by directory users (mode -rwx------)"},
	} {
		err := checkLDAPShell(c.path)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: unexpected error %v", c.path, err)
		case c.want != "" && (err == nil || !strings.HasPrefix(err.Error(), c.want)):
			t.Errorf("%s: err = %v, want prefix %q", c.path, err, c.want)
		}
	}
	if got := ldapShell(&config.LDAPConfig{}); got != "/bin/bash" {
		t.Errorf("ldapShell(unset) = %q, want /bin/bash", got)
	}
	if got := ldapShell(&config.LDAPConfig{Shell: "/bin/zsh"}); got != "/bin/zsh" {
		t.Errorf("ldapShell(/bin/zsh) = %q", got)
	}
	// The renderer writes the same default into sssd.conf.
	if !strings.Contains(renderSSSDConf(ldapRenderData{Profile: config.LDAPProfileLLDAP}, "/ca"), "default_shell = "+defaultLDAPShell+"\n") {
		t.Errorf("renderer default shell differs from defaultLDAPShell")
	}
}

// --setup-ldap refuses a missing ldap.shell before its first host write (the
// package install). The command exits the process, so it runs in a child test
// binary. The child is fail-safe: PATH is an empty directory, so no package
// manager or systemctl can run; the sshd/systemctl seams abort with exit 99;
// the drop-in path is a temp file. The "guard" mode gives a valid shell and
// proves the next stage is the package install, which the empty PATH stops.
func TestSetupLDAP_ShellCheckedBeforeHostWrites(t *testing.T) {
	const abortMarker = "PDA_TEST_ABORT:"
	if shell := os.Getenv("PDA_TEST_SHELL_CHILD"); shell != "" {
		abort := func(stage string) {
			fmt.Fprintln(os.Stderr, abortMarker, stage)
			os.Exit(99)
		}
		systemctl = func(...string) (string, error) { abort("systemctl"); return "", nil }
		sshdTOutput = func(...string) ([]byte, error) { abort("sshd -T"); return nil, nil }
		sshdTest = func() ([]byte, error) { abort("sshd -t"); return nil, nil }
		readClients = func(string) ([]string, error) { abort("readClients"); return nil, nil }
		sshdDropinPath = filepath.Join(t.TempDir(), "10-pam-device-auth.conf")
		detectPlatform = func() (distro.Profile, error) {
			return distro.Profile{Family: "debian", InstallCmd: "apt-get", SSSDPackages: []string{"sssd-ldap"}}, nil
		}
		loadConfig = func(string) (*config.Config, error) {
			l := validLDAP()
			l.Shell = shell
			return &config.Config{IssuerURL: "https://sso.example.org/realms/r", LDAP: l}, nil
		}
		runSetupLDAP()
		abort("setup-ldap returned")
	}
	run := func(t *testing.T, shell string) (code int, stdout, stderr string) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestSetupLDAP_ShellCheckedBeforeHostWrites$")
		cmd.Env = append(os.Environ(), "PDA_TEST_SHELL_CHILD="+shell, "PATH="+t.TempDir())
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err := cmd.Run()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("child: err=%v, want a non-zero exit; stderr=%q", err, errOut.String())
		}
		return exitErr.ExitCode(), out.String(), errOut.String()
	}
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	t.Run("missing shell refuses first", func(t *testing.T) {
		code, stdout, stderr := run(t, missing)
		if code != 1 || !strings.Contains(stderr, "FAIL: login shell "+missing+" (ldap.shell)") {
			t.Fatalf("exit %d, stderr %q; want exit 1 with the shell FAIL", code, stderr)
		}
		if stdout != "" || strings.Contains(stderr, abortMarker) {
			t.Errorf("setup ran past the shell check: stdout %q stderr %q", stdout, stderr)
		}
	})
	t.Run("guard: next stage is the package install", func(t *testing.T) {
		ok := filepath.Join(dir, "sh")
		if err := os.WriteFile(ok, []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := run(t, ok)
		if code != 1 || !strings.Contains(stdout, "Installing sssd-ldap") || !strings.Contains(stderr, "FAIL: apt-get update") {
			t.Fatalf("exit %d stdout %q stderr %q; want the package install stopped by the empty PATH", code, stdout, stderr)
		}
	})
}

func TestValidateLDAPConfig_ADNeedsKeyAndClientsAttributes(t *testing.T) {
	for _, mut := range []func(*config.LDAPConfig){
		func(l *config.LDAPConfig) { l.Attributes.SSHKey = "" },
		func(l *config.LDAPConfig) { l.Attributes.Clients = "" },
	} {
		l := validADLDAP()
		mut(l)
		if err := validateLDAPConfig(l); err == nil {
			t.Fatalf("ad config without key/clients attribute accepted: %+v", l.Attributes)
		}
	}
}

func TestValidateLDAPConfig_AttributeNames(t *testing.T) {
	for _, c := range []struct {
		attr string
		ok   bool
	}{
		{"sshPublicKey", true}, {"msDS-cloudExtensionAttribute1", true}, {"extensionAttribute1", true},
		{"1bad", false}, {"bad attr", false}, {"bad:attr", false}, {"bad\nattr", false}, {"bad,attr", false},
	} {
		l := validADLDAP()
		l.Attributes.Clients = c.attr
		if err := validateLDAPConfig(l); (err == nil) != c.ok {
			t.Errorf("clients attribute %q: err = %v, want ok=%v", c.attr, err, c.ok)
		}
	}
}

func TestValidateLDAPConfig_GroupNamesExplainBareNames(t *testing.T) {
	for _, g := range []string{"SSH Access", `EXAMPLE\ssh-access`} {
		l := validADLDAP()
		l.AccessGroup = g
		err := validateLDAPConfig(l)
		if err == nil || !strings.Contains(err.Error(), "bare group name") {
			t.Errorf("access_group %q: err = %v, want a bare-group-name error", g, err)
		}
	}
}

func TestValidateLDAPConfig_PasswordSources(t *testing.T) {
	l := validLDAP()
	l.BindPasswordFile = "/etc/pam-device-auth/ldap.secret"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("bind_password and bind_password_file together accepted")
	}
	l.BindPassword = ""
	if err := validateLDAPConfig(l); err != nil {
		t.Errorf("bind_password_file alone rejected: %v", err)
	}
	l.BindPasswordFile = "relative/ldap.secret"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("relative bind_password_file accepted")
	}
	l = validLDAP()
	l.BindPassword = ""
	if err := validateLDAPConfig(l); err == nil {
		t.Error("no password and no keytab accepted")
	}
}

func TestValidateLDAPConfig_KerberosAndKeytab(t *testing.T) {
	l := validADLDAP()
	l.Kerberos = &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com", Kpasswd: "dc1.example.com"}
	if err := validateLDAPConfig(l); err != nil {
		t.Fatalf("valid kerberos rejected: %v", err)
	}
	l.Kerberos.Keytab = "/etc/krb5.sssd.keytab"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("keytab together with bind_password accepted")
	}
	l.BindPassword = ""
	l.BindDN = "svc-sssd@EXAMPLE.COM"
	l.URI = "ldap://dc1.example.com"
	if err := validateLDAPConfig(l); err != nil {
		t.Errorf("keytab bind over ldap:// rejected: %v", err)
	}
	for _, bad := range []config.KerberosConfig{
		{Realm: "example.com", KDC: "dc1.example.com"},                        // lower-case realm
		{Realm: "EXAMPLE.COM", KDC: ""},                                       // no kdc
		{Realm: "EXAMPLE.COM", KDC: "dc1.example.com\nx = y"},                 // injection
		{Realm: "EXAMPLE.COM", KDC: "dc1.example.com", Keytab: "krb5.keytab"}, // relative keytab
	} {
		l := validADLDAP()
		k := bad
		l.Kerberos = &k
		if k.Keytab != "" {
			l.BindPassword = ""
			l.BindDN = "svc-sssd@EXAMPLE.COM"
			l.URI = "ldap://dc1.example.com"
		}
		if err := validateLDAPConfig(l); err == nil {
			t.Errorf("bad kerberos %+v accepted", bad)
		}
	}
}

func TestKeytabTransportError(t *testing.T) {
	const want = "ldap.kerberos.keytab requires an ldap:// URI: the GSSAPI bind is protected by SASL sealing, not TLS"
	krb := &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com", Keytab: "/etc/krb5.sssd.keytab"}
	for _, c := range []struct {
		name string
		l    *config.LDAPConfig
		bad  bool
	}{
		{"keytab+ldaps", &config.LDAPConfig{URI: "ldaps://dc1.example.com", Kerberos: krb}, true},
		{"keytab+LDAPS", &config.LDAPConfig{URI: "LDAPS://dc1.example.com", Kerberos: krb}, true},
		{"keytab+ldap", &config.LDAPConfig{URI: "ldap://dc1.example.com", Kerberos: krb}, false},
		{"no keytab+ldaps", &config.LDAPConfig{URI: "ldaps://dc1.example.com",
			Kerberos: &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com"}}, false},
		{"no kerberos+ldaps", &config.LDAPConfig{URI: "ldaps://dc1.example.com"}, false},
	} {
		err := keytabTransportError(c.l)
		if c.bad && (err == nil || err.Error() != want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, want)
		}
		if !c.bad && err != nil {
			t.Errorf("%s: err = %v, want nil", c.name, err)
		}
	}
}

// The keytab bind is protected by SASL sealing, and AD and Samba refuse
// GSSAPI sealing inside TLS, so a keytab needs ldap://; ldaps:// is rejected
// in any letter case.
func TestValidateLDAPConfig_KeytabRequiresLDAPURI(t *testing.T) {
	const want = "ldap.kerberos.keytab requires an ldap:// URI: the GSSAPI bind is protected by SASL sealing, not TLS"
	for _, c := range []struct {
		uri string
		ok  bool
	}{
		{"ldap://dc1.example.com", true},
		{"LDAP://dc1.example.com", true},
		{"ldaps://dc1.example.com", false},
		{"LDAPS://dc1.example.com:636", false},
		{"LdApS://dc1.example.com", false},
	} {
		l := validADLDAP()
		l.URI = c.uri
		l.BindPassword = ""
		l.BindDN = "svc-sssd@EXAMPLE.COM"
		l.Kerberos = &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com", Keytab: "/etc/krb5.sssd.keytab"}
		err := validateLDAPConfig(l)
		if c.ok && err != nil {
			t.Errorf("keytab with %s rejected: %v", c.uri, err)
		}
		if !c.ok && (err == nil || err.Error() != want) {
			t.Errorf("keytab with %s: err = %v, want %q", c.uri, err, want)
		}
	}
	// A simple bind over ldaps:// stays valid.
	if err := validateLDAPConfig(validADLDAP()); err != nil {
		t.Errorf("password bind over ldaps:// rejected: %v", err)
	}
}

// With a keytab, bind_dn is the SASL authid, a Kerberos principal: it needs
// '/' and '$' (host/..., HOST$), which the bind DN charset rejects, and a DN
// makes no sense there.
func TestValidateLDAPConfig_KeytabBindDNIsPrincipal(t *testing.T) {
	for _, c := range []struct {
		dn string
		ok bool
	}{
		{"svc-sssd@EXAMPLE.COM", true},
		{"host/dc1.example.com@EXAMPLE.COM", true},
		{"HOST$@EXAMPLE.COM", true},
		{"CN=svc,DC=example,DC=com", false},
		{"svc-sssd@example.com", false},
		{"svc sssd@EXAMPLE.COM", false},
	} {
		l := validADLDAP()
		l.URI = "ldap://dc1.example.com"
		l.BindPassword = ""
		l.Kerberos = &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com", Keytab: "/etc/krb5.sssd.keytab"}
		l.BindDN = c.dn
		err := validateLDAPConfig(l)
		if c.ok && err != nil {
			t.Errorf("principal %q rejected: %v", c.dn, err)
		}
		if !c.ok && (err == nil || !strings.Contains(err.Error(), "Kerberos principal")) {
			t.Errorf("bind_dn %q with keytab: err = %v, want a Kerberos principal error", c.dn, err)
		}
	}
	l := validADLDAP()
	l.BindPassword = ""
	l.Kerberos = &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com", Keytab: "/etc/krb5.sssd.keytab"}
	l.BindDN = "svc-sssd@EXAMPLE.COM\nldap_tls_reqcert = never"
	if err := validateLDAPConfig(l); err == nil || !strings.Contains(err.Error(), "control character") {
		t.Errorf("principal with a newline: err = %v, want the control character error", err)
	}
	// Without a keytab the DN charset still applies: a DN stays valid.
	l = validADLDAP()
	l.BindDN = "CN=svc,DC=example,DC=com"
	if err := validateLDAPConfig(l); err != nil {
		t.Errorf("DN bind_dn without keytab rejected: %v", err)
	}
}

func TestValidateLDAPConfig_IDRangeHomeShell(t *testing.T) {
	l := validADLDAP()
	l.IDRange = &config.IDRange{Min: 10000, Max: 60000}
	l.Home, l.Shell = "/home/%d/%u", "/bin/zsh"
	if err := validateLDAPConfig(l); err != nil {
		t.Fatalf("valid id_range/home/shell rejected: %v", err)
	}
	for _, r := range []config.IDRange{{Min: 60000, Max: 10000}, {Min: 0, Max: 60000}, {Min: 10000, Max: 10000}} {
		l := validADLDAP()
		rr := r
		l.IDRange = &rr
		if err := validateLDAPConfig(l); err == nil {
			t.Errorf("bad id_range %+v accepted", r)
		}
	}
	off := false
	l = validADLDAP()
	l.IDMapping = &off
	l.IDRange = &config.IDRange{Min: 10000, Max: 60000}
	if err := validateLDAPConfig(l); err == nil || !strings.Contains(err.Error(), "ldap.id_range needs id_mapping") {
		t.Errorf("id_range with id_mapping=false: err = %v, want the id_mapping error", err)
	}
	l = validLDAP()
	l.IDRange = &config.IDRange{Min: 10000, Max: 60000}
	if err := validateLDAPConfig(l); err == nil {
		t.Error("id_range accepted for the lldap profile")
	}
	for _, p := range []string{"home/%u", "/home/%u x", "/home/%u\nx"} {
		l := validLDAP()
		l.Home = p
		if err := validateLDAPConfig(l); err == nil {
			t.Errorf("bad home %q accepted", p)
		}
	}
}

// Every value bound for sssd.conf rejects ASCII control characters, not only
// line breaks; the error names the field and never echoes a secret.
func TestValidateLDAPConfig_RejectsControlCharacters(t *testing.T) {
	for _, c := range []struct {
		name  string
		mut   func(*config.LDAPConfig)
		field string
	}{
		{"nul in bind_password", func(l *config.LDAPConfig) { l.BindPassword = "s3cret\x00x" }, "bind_password"},
		{"esc in bind_password", func(l *config.LDAPConfig) { l.BindPassword = "s3cret\x1b[0m" }, "bind_password"},
		{"bel in base_dn", func(l *config.LDAPConfig) { l.BaseDN = "dc=example\x07,dc=com" }, "base_dn"},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := validLDAP()
			c.mut(l)
			err := validateLDAPConfig(l)
			if err == nil || !strings.Contains(err.Error(), "ldap."+c.field+" contains a control character") {
				t.Fatalf("err = %v, want a control-character error for ldap.%s", err, c.field)
			}
			if strings.Contains(err.Error(), "s3cret") {
				t.Fatalf("error echoes the secret: %v", err)
			}
		})
	}
}

// bind_dn may be a DN, a UPN or a down-level logon name, but never carries
// LDAP filter metacharacters.
func TestValidateLDAPConfig_BindDNCharset(t *testing.T) {
	for _, c := range []struct {
		dn string
		ok bool
	}{
		{"CN=svc,OU=x,DC=example,DC=com", true},
		{"svc-sssd@example.com", true},
		{`EXAMPLE\svc-sssd`, true},
		{"svc(sssd)", false},
		{"svc*", false},
	} {
		l := validADLDAP()
		l.BindDN = c.dn
		err := validateLDAPConfig(l)
		if c.ok && err != nil {
			t.Errorf("bind_dn %q rejected: %v", c.dn, err)
		}
		if !c.ok && (err == nil || !strings.Contains(err.Error(), "ldap.bind_dn")) {
			t.Errorf("bind_dn %q: err = %v, want a bind_dn charset error", c.dn, err)
		}
	}
}

func TestCheckSecretFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	os.WriteFile(good, []byte("x\n"), 0600)
	if err := checkSecretFile(good); err != nil {
		t.Fatalf("0600 file rejected: %v", err)
	}
	loose := filepath.Join(dir, "loose")
	os.WriteFile(loose, []byte("x\n"), 0640)
	if err := checkSecretFile(loose); err == nil {
		t.Error("0640 file accepted")
	}
	link := filepath.Join(dir, "link")
	os.Symlink(good, link)
	if err := checkSecretFile(link); err == nil {
		t.Error("symlink accepted")
	}
	if err := checkSecretFile(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file accepted")
	}
}

// A symlink to a valid 0600 file is refused for the keytab and for
// bind_password_file, by name, and the error never carries the secret.
func TestSecretFile_SymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "ldap.secret")
	if err := os.WriteFile(target, []byte("s3cret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.secret")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := checkSecretFile(link); err == nil || err.Error() != link+" is a symlink" {
		t.Errorf("checkSecretFile(symlink) = %v, want %q", err, link+" is a symlink")
	}
	l := validLDAP()
	l.BindPassword = ""
	l.BindPasswordFile = link
	pw, err := resolveBindPassword(l)
	if err == nil || pw != "" {
		t.Fatalf("resolveBindPassword(symlink) = %q, %v; want an error", pw, err)
	}
	if want := "ldap.bind_password_file: " + link + " is a symlink"; err.Error() != want {
		t.Errorf("err = %q, want %q", err, want)
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("error echoes the secret: %v", err)
	}
}

// A FIFO is refused as not a regular file instead of blocking the open until
// a writer appears.
func TestCheckSecretFile_FIFORejected(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- checkSecretFile(fifo) }()
	select {
	case err := <-done:
		if err == nil || err.Error() != fifo+" is not a regular file" {
			t.Fatalf("checkSecretFile(fifo) = %v, want %q", err, fifo+" is not a regular file")
		}
	case <-time.After(2 * time.Second):
		// Release the blocked open so the goroutine ends.
		if w, err := os.OpenFile(fifo, os.O_WRONLY, 0); err == nil {
			w.Close()
		}
		t.Fatal("checkSecretFile blocks on a FIFO")
	}
}

type fakeFileInfo struct {
	mode os.FileMode
	sys  any
}

func (f fakeFileInfo) Name() string       { return "secret" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return f.sys }

// Without a syscall.Stat_t the owner is unknown, so the file is refused.
func TestCheckSecretFileInfo_NoOwnerFailsClosed(t *testing.T) {
	if err := checkSecretFileInfo("/etc/x.secret", fakeFileInfo{mode: 0600}); err == nil {
		t.Fatal("file without owner information accepted")
	}
	own := &syscall.Stat_t{Uid: uint32(os.Geteuid())}
	if err := checkSecretFileInfo("/etc/x.secret", fakeFileInfo{mode: 0600, sys: own}); err != nil {
		t.Fatalf("0600 file of the effective user rejected: %v", err)
	}
}

func TestCAFileError(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, []byte("-----BEGIN CERTIFICATE-----\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := caFileError(ca); err != nil {
		t.Errorf("regular file rejected: %v", err)
	}
	link := filepath.Join(dir, "ca-link.pem")
	if err := os.Symlink(ca, link); err != nil {
		t.Fatal(err)
	}
	if err := caFileError(link); err != nil {
		t.Errorf("symlink to a regular file rejected: %v", err)
	}
	if err := caFileError(dir); err == nil || err.Error() != "ldap.ca_file "+dir+" is not a regular file" {
		t.Errorf("directory: err = %v, want \"ldap.ca_file %s is not a regular file\"", err, dir)
	}
	missing := filepath.Join(dir, "missing.pem")
	if err := caFileError(missing); err == nil || !strings.Contains(err.Error(), "ldap.ca_file") || !strings.Contains(err.Error(), missing) {
		t.Errorf("missing file: err = %v, want an ldap.ca_file error naming %s", err, missing)
	}
}

func TestResolveBindPassword(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(content), 0600)
		return p
	}
	for _, c := range []struct {
		name, content, want string
		ok                  bool
	}{
		{"lf", "s3cret\n", "s3cret", true},
		{"crlf", "s3cret\r\n", "s3cret", true},
		{"no newline", "s3cret", "s3cret", true},
		{"two lines", "s3cret\nldap_tls_reqcert = never\n", "", false},
		{"empty", "\n", "", false},
		{"nul", "s3cret\x00x\n", "", false},
		{"esc", "s3cret\x1b[0m\n", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := validLDAP()
			l.BindPassword = ""
			l.BindPasswordFile = write(c.name, c.content)
			got, err := resolveBindPassword(l)
			if c.ok && (err != nil || got != c.want) {
				t.Fatalf("got %q, %v; want %q", got, err, c.want)
			}
			if !c.ok {
				if err == nil {
					t.Fatal("bad password file accepted")
				}
				if strings.Contains(err.Error(), "s3cret") {
					t.Fatalf("error echoes the secret: %v", err)
				}
			}
		})
	}
	// At most 4096 bytes are read; a longer file fails closed instead of
	// yielding a truncated password.
	l := validLDAP()
	l.BindPassword = ""
	l.BindPasswordFile = write("max", "s3cret"+strings.Repeat("x", 4096-6))
	if got, err := resolveBindPassword(l); err != nil || len(got) != 4096 {
		t.Errorf("4096-byte password file: len %d, %v; want accepted", len(got), err)
	}
	l.BindPasswordFile = write("long", "s3cret"+strings.Repeat("x", 5000-6))
	if got, err := resolveBindPassword(l); err == nil || got != "" || err.Error() != "ldap.bind_password_file is longer than 4096 bytes" {
		t.Errorf("5000-byte password file: %d bytes, %v; want \"ldap.bind_password_file is longer than 4096 bytes\"", len(got), err)
	}
	l = validLDAP()
	if got, err := resolveBindPassword(l); err != nil || got != l.BindPassword {
		t.Fatalf("inline password: %q, %v", got, err)
	}
}

func adRender(t *testing.T, mut func(*config.LDAPConfig)) string {
	t.Helper()
	l := validADLDAP()
	if mut != nil {
		mut(l)
	}
	if err := validateLDAPConfig(l); err != nil {
		t.Fatalf("test config invalid: %v", err)
	}
	pw, _ := resolveBindPassword(l)
	return renderSSSDConf(renderDataFor(l, pw), "/etc/ssl/certs/ca-certificates.crt")
}

func TestRenderSSSDConf_ADDefaults(t *testing.T) {
	got := adRender(t, nil)
	for _, line := range []string{
		"access_provider = simple\n", "simple_allow_groups = ssh-access\n", "ldap_schema = ad\n",
		"ldap_referrals = false\n", "case_sensitive = false\n", "ldap_user_name = sAMAccountName\n",
		"ldap_user_ssh_public_key = sshPublicKey\n", "ldap_user_extra_attrs = clients:extensionAttribute1\n",
		"ldap_id_mapping = true\n", "chpass_provider = none\n", "ldap_user_search_base = DC=example,DC=com\n",
		"ldap_group_search_base = DC=example,DC=com\n", "ldap_tls_reqcert = hard\n", "user_attributes = +clients\n",
	} {
		if !strings.Contains(got, line) {
			t.Errorf("missing %q in:\n%s", line, got)
		}
	}
	for _, absent := range []string{"ldap_access_filter", "posixAccount", "ldap_id_use_start_tls", "config_file_version"} {
		if strings.Contains(got, absent) {
			t.Errorf("unexpected %q in:\n%s", absent, got)
		}
	}
	extra, ifp := sssdClientsExposure(got)
	if !extra || !ifp {
		t.Errorf("--check would reject the rendered ad config (extra=%v ifp=%v)", extra, ifp)
	}
}

func TestRenderSSSDConf_ADServiceGroupsAndIDRange(t *testing.T) {
	got := adRender(t, func(l *config.LDAPConfig) {
		l.ServiceAccountGroups = []string{"ssh-service"}
		l.IDRange = &config.IDRange{Min: 10000, Max: 60000}
	})
	for _, line := range []string{
		"simple_allow_groups = ssh-access, ssh-service\n", "ldap_idmap_range_min = 10000\n",
		"ldap_idmap_range_max = 60000\n", "ldap_idmap_range_size = 50000\n",
	} {
		if !strings.Contains(got, line) {
			t.Errorf("missing %q in:\n%s", line, got)
		}
	}
}

func TestRenderSSSDConf_ADStartTLS(t *testing.T) {
	got := adRender(t, func(l *config.LDAPConfig) { l.URI = "ldap://dc1.example.com" })
	if !strings.Contains(got, "ldap_id_use_start_tls = true\n") {
		t.Fatalf("ldap:// without StartTLS:\n%s", got)
	}
}

func TestRenderSSSDConf_ADGSSAPIOverLDAP(t *testing.T) {
	got := adRender(t, func(l *config.LDAPConfig) {
		l.URI = "ldap://dc1.example.com"
		l.BindPassword = ""
		l.BindDN = "svc-sssd@EXAMPLE.COM"
		l.Kerberos = &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com", Keytab: "/etc/krb5.sssd.keytab"}
	})
	for _, line := range []string{
		"ldap_sasl_mech = GSSAPI\n", "ldap_sasl_authid = svc-sssd@EXAMPLE.COM\n",
		"ldap_krb5_keytab = /etc/krb5.sssd.keytab\n", "ldap_sasl_minssf = 56\n", "auth_provider = krb5\n",
		"ldap_id_use_start_tls = false\n",
	} {
		if !strings.Contains(got, line) {
			t.Errorf("missing %q in:\n%s", line, got)
		}
	}
	for _, absent := range []string{"ldap_default_authtok", "ldap_default_bind_dn", "ldap_id_use_start_tls = true"} {
		if strings.Contains(got, absent) {
			t.Errorf("GSSAPI bind still renders %q:\n%s", absent, got)
		}
	}
}

func TestRenderSSSDConf_ADIDMappingOff(t *testing.T) {
	off := false
	got := adRender(t, func(l *config.LDAPConfig) { l.IDMapping = &off })
	if !strings.Contains(got, "ldap_id_mapping = false\n") || strings.Contains(got, "ldap_idmap_range") {
		t.Fatalf("id_mapping=false:\n%s", got)
	}
}

func TestRenderDataFor_LLDAPDefaultsMatchGolden(t *testing.T) {
	l := validLDAP()
	l.BaseDN = "dc=example,dc=com"
	l.URI = "ldaps://ldap.example.com:6360"
	l.BindDN = "uid=ro,ou=people,dc=example,dc=com"
	l.BindPassword = "pw"
	l.ServiceAccountGroups = []string{"ssh-service"}
	want := lldapGolden(t)
	if got := renderSSSDConf(renderDataFor(l, "pw"), "/etc/ssl/certs/ca-certificates.crt"); got != want {
		t.Fatalf("renderDataFor changes the lldap output:\n%s", got)
	}
}

// The password from bind_password_file must reach sssd.conf, not only pass
// validation.
func TestRenderDataFor_BindPasswordFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ldap.secret")
	if err := os.WriteFile(p, []byte("s3cret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	l := validLDAP()
	l.BindPassword = ""
	l.BindPasswordFile = p
	if err := validateLDAPConfig(l); err != nil {
		t.Fatalf("test config invalid: %v", err)
	}
	pw, err := resolveBindPassword(l)
	if err != nil {
		t.Fatalf("resolveBindPassword: %v", err)
	}
	got := renderSSSDConf(renderDataFor(l, pw), "/etc/ssl/certs/ca-certificates.crt")
	if !strings.Contains(got, "ldap_default_authtok = s3cret\n") {
		t.Fatalf("bind_password_file content missing from sssd.conf:\n%s", got)
	}
}

func TestCACertFor(t *testing.T) {
	prof := distro.Profile{CACertPath: "/etc/ssl/certs/ca-certificates.crt"}
	l := validLDAP()
	if got := caCertFor(l, prof); got != prof.CACertPath {
		t.Errorf("default CA = %q", got)
	}
	l.CAFile = "/usr/local/share/ca-certificates/dir-ca.crt"
	if got := caCertFor(l, prof); got != l.CAFile {
		t.Errorf("ca_file ignored: %q", got)
	}
}

// SSSD's ldap provider takes the Kerberos principal from userPrincipalName,
// whose realm part AD delivers as the lower-case DNS domain. With profile ad
// and kerberos the renderer sets what SSSD's ad provider defaults to, right
// after the krb5_* lines; lldap and ad without kerberos stay as they are.
func TestRenderSSSDConf_ADKerberosPrincipal(t *testing.T) {
	const lines = "krb5_use_enterprise_principal = true\nldap_force_upper_case_realm = true\n"
	for _, c := range []struct {
		name string
		mut  func(*config.LDAPConfig)
		want string // the krb5_* line the two lines must follow
	}{
		{"password bind", func(l *config.LDAPConfig) {
			l.Kerberos = &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com"}
		}, "krb5_server = dc1.example.com\n"},
		{"password bind with kpasswd", func(l *config.LDAPConfig) {
			l.Kerberos = &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com", Kpasswd: "dc2.example.com"}
		}, "krb5_kpasswd = dc2.example.com\n"},
		{"keytab bind", func(l *config.LDAPConfig) {
			l.URI = "ldap://dc1.example.com"
			l.BindPassword = ""
			l.BindDN = "svc-sssd@EXAMPLE.COM"
			l.Kerberos = &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com", Keytab: "/etc/krb5.sssd.keytab"}
		}, "krb5_server = dc1.example.com\n"},
	} {
		got := adRender(t, c.mut)
		if !strings.Contains(got, c.want+lines) {
			t.Errorf("ad, %s: want %q after %q:\n%s", c.name, lines, c.want, got)
		}
	}

	noKrb := adRender(t, nil)
	lldapKrb := renderSSSDConf(ldapRenderData{
		URI: "ldap://ldap.example.com:389", BaseDN: "dc=example,dc=com",
		UserBase: "ou=people,dc=example,dc=com", GroupBase: "ou=groups,dc=example,dc=com",
		BindDN: "uid=ro,ou=people,dc=example,dc=com", BindPassword: "pw", AccessGroup: "ssh-access",
		KrbRealm: "EXAMPLE.COM", KrbKDC: "kdc.example.com", KrbKpasswd: "kdc.example.com",
	}, "/etc/ssl/certs/ca-certificates.crt")
	lldapKeytab := renderSSSDConf(ldapRenderData{
		URI: "ldap://ldap.example.com", BaseDN: "dc=example,dc=com",
		UserBase: "ou=people,dc=example,dc=com", GroupBase: "ou=groups,dc=example,dc=com",
		BindDN: "svc-sssd@EXAMPLE.COM", Keytab: "/etc/krb5.sssd.keytab", AccessGroup: "ssh-access",
		KrbRealm: "EXAMPLE.COM", KrbKDC: "kdc.example.com",
	}, "/etc/ssl/certs/ca-certificates.crt")
	for name, got := range map[string]string{"ad without kerberos": noKrb, "lldap with kerberos": lldapKrb, "lldap with keytab": lldapKeytab} {
		for _, absent := range []string{"krb5_use_enterprise_principal", "ldap_force_upper_case_realm"} {
			if strings.Contains(got, absent) {
				t.Errorf("%s: unexpected %s:\n%s", name, absent, got)
			}
		}
	}
}

// GSSAPI builds the service principal ldap/<host> from the URI host, so a
// keytab bind needs the DC's host name; an IP literal in any form is refused
// by validateLDAPConfig. Without a keytab an IP address stays allowed.
func TestValidateLDAPConfig_KeytabNeedsHostName(t *testing.T) {
	const want = "ldap.kerberos.keytab needs the DC's host name in ldap.uri, not an IP address: GSSAPI uses the ldap/<host> service principal"
	for _, c := range []struct {
		uri string
		ok  bool
	}{
		{"ldap://192.0.2.10", false},
		{"ldap://192.0.2.10:389", false},
		{"LDAP://192.0.2.10", false},
		{"ldap://[2001:db8::1]", false},
		{"ldap://[2001:db8::1]:389", false},
		{"ldap://2001:db8::1", false},
		{"ldap://dc1.example.com", true},
		{"ldap://dc1.example.com:389", true},
		{"ldap://dc1", true},
	} {
		l := validADLDAP()
		l.URI = c.uri
		l.BindPassword = ""
		l.BindDN = "svc-sssd@EXAMPLE.COM"
		l.Kerberos = &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com", Keytab: "/etc/krb5.sssd.keytab"}
		err := validateLDAPConfig(l)
		if c.ok && err != nil {
			t.Errorf("keytab with %s rejected: %v", c.uri, err)
		}
		if !c.ok && (err == nil || err.Error() != want) {
			t.Errorf("keytab with %s: err = %v, want %q", c.uri, err, want)
		}
	}
	// No keytab: an IP address in the URI is the operator's choice.
	for _, c := range []struct {
		uri string
		krb *config.KerberosConfig
	}{
		{"ldaps://192.0.2.10", nil},
		{"ldap://192.0.2.10:389", nil},
		{"ldaps://[2001:db8::1]:636", nil},
		{"ldaps://192.0.2.10", &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "192.0.2.10"}},
	} {
		l := validADLDAP()
		l.URI = c.uri
		l.Kerberos = c.krb
		if err := validateLDAPConfig(l); err != nil {
			t.Errorf("no keytab, %s rejected: %v", c.uri, err)
		}
	}
}

// The 0.6.0 renderings in testdata, as written by --setup-ldap 0.6.0.
//
//go:embed testdata/sshd-dropin-0.6.0-*.conf
var sshdDropin060 embed.FS

// The sshd drop-in is written for every profile, so its comments name no
// directory product. Against 0.6.0 only comment lines may differ: every
// directive, its position and every blank line stay identical.
func TestSshdDropin_ProfileNeutralCommentsOnly(t *testing.T) {
	for _, c := range []struct {
		file      string
		sssCmd    string
		groups    []string
		rootLogin string
	}{
		{"testdata/sshd-dropin-0.6.0-default.conf", "/usr/bin/sss_ssh_authorizedkeys", nil, ""},
		{"testdata/sshd-dropin-0.6.0-service-key.conf", "/usr/libexec/sssd/sss_ssh_authorizedkeys", []string{"ssh-service", "ci"}, config.RootLoginKey},
		{"testdata/sshd-dropin-0.6.0-service-disabled.conf", "/usr/bin/sss_ssh_authorizedkeys", []string{"ssh-service"}, config.RootLoginDisabled},
	} {
		old, err := sshdDropin060.ReadFile(c.file)
		if err != nil || len(old) == 0 {
			t.Fatalf("%s: embedded fixture missing or empty: %v", c.file, err)
		}
		got := renderSshdDropin(c.sssCmd, c.groups, c.rootLogin)
		if strings.Contains(strings.ToLower(got), "lldap") {
			t.Errorf("%s: drop-in names LLDAP:\n%s", c.file, got)
		}
		if !strings.Contains(got, "\n# Non-root: SSH key (from the directory via SSSD) AND OIDC (keyboard-interactive/PAM).\n") {
			t.Errorf("%s: non-root comment not profile-neutral:\n%s", c.file, got)
		}
		gl, ol := strings.Split(got, "\n"), strings.Split(string(old), "\n")
		if len(gl) != len(ol) {
			t.Fatalf("%s: %d lines, 0.6.0 had %d:\n%s", c.file, len(gl), len(ol), got)
		}
		for i := range gl {
			if gl[i] != ol[i] && !(strings.HasPrefix(gl[i], "#") && strings.HasPrefix(ol[i], "#")) {
				t.Errorf("%s line %d: non-comment change %q -> %q", c.file, i+1, ol[i], gl[i])
			}
		}
	}
}

func TestWireMkhomedirUnknownWiring(t *testing.T) {
	var calls []string
	err := wireMkhomedir(distro.Profile{PamWiring: "x"}, fakeRunner(nil, nil, &calls))
	if err == nil || !strings.Contains(err.Error(), `unknown PamWiring "x"`) {
		t.Fatalf("err = %v, want the unknown PamWiring error", err)
	}
	if len(calls) != 0 {
		t.Errorf("runner called for an unknown wiring: %q", calls)
	}
}

func TestWireMkhomedirFailureIsError(t *testing.T) {
	const pamAuthUpdate = "pam-auth-update --enable mkhomedir"
	var calls []string
	err := wireMkhomedir(distro.Profile{PamWiring: "pam-auth-update"},
		fakeRunner(map[string]error{pamAuthUpdate: fmt.Errorf("exit status 1")},
			map[string]string{pamAuthUpdate: "no profile mkhomedir"}, &calls))
	if err == nil || !strings.Contains(err.Error(), "no profile mkhomedir") {
		t.Fatalf("err = %v, want the pam-auth-update failure with its output", err)
	}
}

// authselectPlan reads the active profile from `authselect current --raw`. An
// sssd profile keeps the features it has (with-faillock, with-sudo): they are
// selected again, with with-mkhomedir added once. Everything else is replaced,
// and the replaced profile is named so the setup can print it.
//
// Every plan carries --force. The setup writes /etc/nsswitch.conf itself where
// the profile leaves sss out of a line, which replaces authselect's symlink;
// authselect 1.2 (RHEL 9) then refuses every command without --force
// ("[/etc/nsswitch.conf] was not created by authselect!"), `enable-feature`
// included, so the second --setup-ldap of a host failed.
func TestAuthselectPlan(t *testing.T) {
	selectSSSD := "select sssd with-mkhomedir --force"
	for _, c := range []struct{ current, wantArgs, wantReplaced string }{
		{"sssd with-faillock with-sudo\n", "select sssd with-faillock with-sudo with-mkhomedir --force", ""},
		{"sssd with-mkhomedir with-faillock\n", "select sssd with-mkhomedir with-faillock --force", ""},
		{"sssd with-mkhomedir\n", selectSSSD, ""},
		{"sssd\n", selectSSSD, ""},
		{"winbind with-mkhomedir\n", selectSSSD, "winbind with-mkhomedir"},
		{"custom/corp with-faillock\n", selectSSSD, "custom/corp with-faillock"},
		{"", selectSSSD, ""},
	} {
		args, replaced := authselectPlan(c.current)
		if strings.Join(args, " ") != c.wantArgs || replaced != c.wantReplaced {
			t.Errorf("authselectPlan(%q) = %q, %q; want %q, %q", c.current, args, replaced, c.wantArgs, c.wantReplaced)
		}
	}
}

func TestWireMkhomedirCommands(t *testing.T) {
	const current = "authselect current --raw"
	const selectCmd = "authselect select sssd with-mkhomedir --force"
	const keepCmd = "authselect select sssd with-faillock with-mkhomedir --force"
	const oddjobd = "systemctl enable --now oddjobd"
	boom := fmt.Errorf("exit status 1")
	cases := []struct {
		name      string
		wiring    string
		results   map[string]error
		outputs   map[string]string
		wantCalls []string
		wantErr   string
	}{
		{"debian ok", "pam-auth-update", nil, nil, []string{"pam-auth-update --enable mkhomedir"}, ""},
		{"rhel, no profile yet", "authselect", map[string]error{current: boom}, nil, []string{current, selectCmd, oddjobd}, ""},
		{"rhel, an sssd profile keeps its features", "authselect", nil, map[string]string{current: "sssd with-faillock\n"}, []string{current, keepCmd, oddjobd}, ""},
		{"rhel, another profile is replaced", "authselect", nil, map[string]string{current: "winbind\n"}, []string{current, selectCmd, oddjobd}, ""},
		{"rhel select fails, oddjobd not started", "authselect", map[string]error{selectCmd: boom}, nil, []string{current, selectCmd}, "authselect select"},
		{"rhel select with the kept features fails, oddjobd not started", "authselect", map[string]error{keepCmd: boom}, map[string]string{current: "sssd with-faillock\n"}, []string{current, keepCmd}, keepCmd},
		{"rhel oddjobd fails", "authselect", map[string]error{oddjobd: boom}, nil, []string{current, selectCmd, oddjobd}, `the authselect profile "sssd with-mkhomedir" stays selected`},
		{"rhel oddjobd fails with kept features", "authselect", map[string]error{oddjobd: boom}, map[string]string{current: "sssd with-faillock\n"}, []string{current, keepCmd, oddjobd}, `the authselect profile "sssd with-faillock with-mkhomedir" stays selected`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			err := wireMkhomedir(distro.Profile{PamWiring: tc.wiring}, fakeRunner(tc.results, tc.outputs, &calls))
			if tc.wantErr == "" && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want an error naming %q", err, tc.wantErr)
			}
			if strings.Join(calls, "|") != strings.Join(tc.wantCalls, "|") {
				t.Errorf("calls = %q, want %q", calls, tc.wantCalls)
			}
		})
	}
}

// `authselect current` fails on a host without a selected profile and prints
// why; that text is no profile name.
func TestAuthselectCurrent_FailureMeansNoProfile(t *testing.T) {
	const current = "authselect current --raw"
	var calls []string
	run := fakeRunner(map[string]error{current: fmt.Errorf("exit status 2")},
		map[string]string{current: "No existing configuration detected.\n"}, &calls)
	if got := authselectCurrent(run); got != "" {
		t.Errorf("authselectCurrent() = %q, want \"\" when the command fails", got)
	}
	run = fakeRunner(nil, map[string]string{current: "sssd with-faillock\n"}, &calls)
	if got := authselectCurrent(run); got != "sssd with-faillock" {
		t.Errorf("authselectCurrent() = %q, want the active profile", got)
	}
}
