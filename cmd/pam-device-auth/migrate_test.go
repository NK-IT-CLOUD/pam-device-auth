package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const testPasswd = `root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/bash
bob:x:1001:1001:Bob:/srv/bob:/bin/bash
carol:x:1002:1002:Carol:/home/carol:/bin/bash
svc:x:999:999::/var/lib/svc:/usr/sbin/nologin
`

const testGroup = `sudo:x:27:alice
docker:x:998:alice,carol
alice:x:1000:
video:x:44:alice
wheel:x:10:alice
`

func dirLookup(name string) (int, int, bool) {
	switch name {
	case "alice":
		return 10001, 6000, true
	case "bob":
		return 10002, 6000, true
	case "carol":
		return 1002, 1002, true // same uid: no collision
	}
	return 0, 0, false
}

func TestFindShadowedAccounts(t *testing.T) {
	got := findShadowedAccounts([]byte(testPasswd), []byte(testGroup), dirLookup)
	want := []shadowedAccount{
		{Name: "alice", Home: "/home/alice", LocalUID: 1000, LocalGID: 1000, DirUID: 10001, DirGID: 6000,
			Groups: []string{"video"}, Dropped: []string{"sudo", "docker", "wheel"}},
		{Name: "bob", Home: "/srv/bob", LocalUID: 1001, LocalGID: 1001, DirUID: 10002, DirGID: 6000},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

// Groups that give root or near-root rights are not carried over to the
// directory user: those rights come from the directory. They are returned
// apart so the admin sees what the migration leaves out. The primary group
// is in neither list.
func TestLocalSupplementaryGroups_DropsPrivileged(t *testing.T) {
	kept, dropped := localSupplementaryGroups([]byte(testGroup), "alice", 1000)
	if !reflect.DeepEqual(kept, []string{"video"}) {
		t.Errorf("kept = %v, want [video]", kept)
	}
	if !reflect.DeepEqual(dropped, []string{"sudo", "docker", "wheel"}) {
		t.Errorf("dropped = %v, want [sudo docker wheel]", dropped)
	}

	const hostGroups = `root:x:0:alice
adm:x:4:alice,syslog
disk:x:6:alice
shadow:x:42:alice
staff:x:50:alice
lxd:x:110:alice
incus:x:111:alice
libvirt:x:112:alice
admin:x:113:alice
audio:x:29:alice
plugdev:x:46:alice
`
	kept, dropped = localSupplementaryGroups([]byte(hostGroups), "alice", 1000)
	if !reflect.DeepEqual(kept, []string{"audio", "plugdev"}) {
		t.Errorf("kept = %v, want [audio plugdev]", kept)
	}
	if want := []string{"root", "adm", "disk", "shadow", "staff", "lxd", "incus", "libvirt", "admin"}; !reflect.DeepEqual(dropped, want) {
		t.Errorf("dropped = %v, want %v", dropped, want)
	}
}

func TestProcessCount(t *testing.T) {
	root := t.TempDir()
	write := func(pid, uidLine string) {
		os.MkdirAll(filepath.Join(root, pid), 0755)
		os.WriteFile(filepath.Join(root, pid, "status"), []byte("Name:\tx\n"+uidLine+"\n"), 0644)
	}
	write("100", "Uid:\t1000\t1000\t1000\t1000")
	write("101", "Uid:\t0\t1000\t1000\t1000") // real uid root, effective 1000: counted
	write("102", "Uid:\t1001\t1001\t1001\t1001")
	os.MkdirAll(filepath.Join(root, "self"), 0755)
	if got := processCount(root, 1000); got != 2 {
		t.Fatalf("processCount = %d, want 2", got)
	}
}

func TestMigrateShadowedAccount_Commands(t *testing.T) {
	var calls []string
	run := func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	exists := func(p string) bool { return p == "/home/alice" || p == "/var/spool/cron/crontabs/alice" }
	a := shadowedAccount{Name: "alice", Home: "/home/alice", LocalUID: 1000, LocalGID: 1000, DirUID: 10001, DirGID: 6000, Groups: []string{"docker"}}
	if err := migrateShadowedAccount(a, run, exists); err != nil {
		t.Fatalf("migrateShadowedAccount: %v", err)
	}
	want := []string{
		"userdel alice",
		"gpasswd -a alice docker",
		"chown -R --from=1000 10001 /home/alice",
		"chown -R --from=:1000 :6000 /home/alice",
		"chown -R --from=1000 10001 /var/spool/cron/crontabs/alice",
		"chown -R --from=:1000 :6000 /var/spool/cron/crontabs/alice",
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
	}
	for _, c := range calls {
		if strings.HasPrefix(c, "pkill") || strings.HasPrefix(c, "kill") {
			t.Fatalf("migration sends signals: %s", c)
		}
	}
}

func TestMigrateShadowedAccount_HomeOutsideHomeIsNotChowned(t *testing.T) {
	var calls []string
	run := func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	a := shadowedAccount{Name: "bob", Home: "/srv/bob", LocalUID: 1001, LocalGID: 1001, DirUID: 10002, DirGID: 6000}
	migrateShadowedAccount(a, run, func(string) bool { return false })
	for _, c := range calls {
		if strings.Contains(c, "/srv/bob") {
			t.Fatalf("home outside /home touched: %s", c)
		}
	}
}

// The /home guard compares the cleaned path: dot-dot cannot leave /home, and a
// trailing slash does not hide a home below it.
func TestMigrateShadowedAccount_HomeGuardCleansPath(t *testing.T) {
	for _, c := range []struct {
		home, want string // want "" = home never chowned
	}{
		{"/home/../srv/bob", ""},
		{"/home/alice/", "/home/alice"},
	} {
		var calls []string
		run := func(name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			return nil, nil
		}
		a := shadowedAccount{Name: "bob", Home: c.home, LocalUID: 1001, LocalGID: 1001, DirUID: 10002, DirGID: 6000}
		// Like stat(2): the kernel resolves dot-dot and trailing slashes.
		exists := func(p string) bool { p = filepath.Clean(p); return p == "/srv/bob" || p == "/home/alice" }
		migrateShadowedAccount(a, run, exists)
		var chowned []string
		for _, call := range calls {
			if strings.HasPrefix(call, "chown ") {
				f := strings.Fields(call)
				chowned = append(chowned, f[len(f)-1])
			}
		}
		var want []string
		if c.want != "" {
			want = []string{c.want, c.want}
		}
		if !reflect.DeepEqual(chowned, want) {
			t.Errorf("Home %q: chowned %q, want %q", c.home, chowned, want)
		}
	}
}

func TestMigrateShadowedAccount_UserdelFailureStops(t *testing.T) {
	var calls []string
	run := func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name)
		if name == "userdel" {
			return []byte("userdel: user alice is currently used by process 4711"), os.ErrPermission
		}
		return nil, nil
	}
	a := shadowedAccount{Name: "alice", Home: "/home/alice", LocalUID: 1000, LocalGID: 1000, DirUID: 10001, DirGID: 6000, Groups: []string{"docker"}}
	err := migrateShadowedAccount(a, run, func(string) bool { return false })
	if err == nil || !strings.Contains(err.Error(), "userdel alice") || !strings.Contains(err.Error(), "currently used by process 4711") ||
		!strings.Contains(err.Error(), "not migrated") || len(calls) != 1 {
		t.Fatalf("err=%v calls=%v", err, calls)
	}
}

// After userdel the local entry is gone: every re-own step still runs, and each
// failure is part of the error, which says that the local entry is removed.
func TestMigrateShadowedAccount_FailureAfterUserdelIsError(t *testing.T) {
	var calls []string
	run := func(name string, args ...string) ([]byte, error) {
		call := name + " " + strings.Join(args, " ")
		calls = append(calls, call)
		if call == "gpasswd -a alice docker" {
			return []byte("gpasswd: group 'docker' does not exist"), os.ErrNotExist
		}
		return nil, nil
	}
	a := shadowedAccount{Name: "alice", Home: "/home/alice", LocalUID: 1000, LocalGID: 1000, DirUID: 10001, DirGID: 6000, Groups: []string{"docker"}}
	err := migrateShadowedAccount(a, run, func(p string) bool { return p == "/home/alice" })
	if err == nil {
		t.Fatal("migrateShadowedAccount = nil although gpasswd failed")
	}
	for _, want := range []string{"gpasswd -a alice docker", "does not exist", "local entry of alice is already removed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if want := []string{"userdel alice", "gpasswd -a alice docker",
		"chown -R --from=1000 10001 /home/alice", "chown -R --from=:1000 :6000 /home/alice"}; !reflect.DeepEqual(calls, want) {
		t.Errorf("calls = %q, want %q", calls, want)
	}
}

func TestMigrateShadowedAccounts_RunningProcessSkipsAccount(t *testing.T) {
	old := setupWarnings
	setupWarnings = nil
	t.Cleanup(func() { setupWarnings = old })
	proc := t.TempDir()
	os.MkdirAll(filepath.Join(proc, "4711"), 0755)
	os.WriteFile(filepath.Join(proc, "4711", "status"), []byte("Name:\tsleep\nUid:\t1000\t1000\t1000\t1000\n"), 0644)
	var calls []string
	run := func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "userdel" && args[0] == "carol" {
			return []byte("userdel: cannot lock /etc/passwd"), os.ErrPermission
		}
		return nil, nil
	}
	accounts := []shadowedAccount{
		{Name: "alice", Home: "/home/alice", LocalUID: 1000, LocalGID: 1000, DirUID: 10001, DirGID: 6000, Groups: []string{"docker"}},
		{Name: "bob", Home: "/srv/bob", LocalUID: 1001, LocalGID: 1001, DirUID: 10002, DirGID: 6000},
		{Name: "carol", Home: "/home/carol", LocalUID: 1002, LocalGID: 1002, DirUID: 10003, DirGID: 6000},
		{Name: "dave", Home: "/home/dave", LocalUID: 1003, LocalGID: 1003, DirUID: 10004, DirGID: 6000},
	}
	got, err := migrateShadowedAccounts(accounts, proc, run, func(string) bool { return false })
	if got != 1 {
		t.Fatalf("migrated = %d, want 1 (only bob)", got)
	}
	// A failed migration is an error, not a warning.
	if err == nil || !strings.Contains(err.Error(), "userdel carol") {
		t.Fatalf("err = %v, want the failed userdel of carol", err)
	}
	if want := []string{"userdel bob", "userdel carol"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %q, want %q (nothing for alice, who has a running process, nothing after carol's failure)", calls, want)
	}
	if len(setupWarnings) != 1 || !strings.Contains(setupWarnings[0], "alice") || !strings.Contains(setupWarnings[0], "1 running process") {
		t.Fatalf("setupWarnings = %q, want only the skipped alice", setupWarnings)
	}
}

// Whether a local entry was removed decides the abort message: only then does
// an account resolve through the new sssd.conf alone.
func TestLocalEntryRemoved(t *testing.T) {
	failAt := func(cmd string) commandRunner {
		return func(name string, args ...string) ([]byte, error) {
			if name+" "+strings.Join(args, " ") == cmd {
				return nil, os.ErrPermission
			}
			return nil, nil
		}
	}
	alice := shadowedAccount{Name: "alice", Home: "/home/alice", LocalUID: 1000, LocalGID: 1000, DirUID: 10001, DirGID: 6000, Groups: []string{"docker"}}
	bob := shadowedAccount{Name: "bob", Home: "/home/bob", LocalUID: 1001, LocalGID: 1001, DirUID: 10002, DirGID: 6000}
	none := func(string) bool { return false }
	proc := t.TempDir()
	for _, c := range []struct {
		name     string
		accounts []shadowedAccount
		run      commandRunner
		want     bool
	}{
		{"first userdel fails: nothing removed", []shadowedAccount{alice, bob}, failAt("userdel alice"), false},
		{"failure after userdel: entry removed", []shadowedAccount{alice}, failAt("gpasswd -a alice docker"), true},
		{"one migrated, next userdel fails", []shadowedAccount{bob, alice}, failAt("userdel alice"), true},
		{"all migrated", []shadowedAccount{alice}, failAt(""), true},
		{"nothing to migrate", nil, failAt(""), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			migrated, err := migrateShadowedAccounts(c.accounts, proc, c.run, none)
			if got := localEntryRemoved(migrated, err); got != c.want {
				t.Errorf("localEntryRemoved(%d, %v) = %v, want %v", migrated, err, got, c.want)
			}
		})
	}
}

func TestKeptSSSDConf(t *testing.T) {
	if got := keptSSSDConf(false); strings.Contains(got, "resolve only through") || !strings.Contains(got, "kept the new sssd.conf") {
		t.Errorf("nothing removed: %q must keep sssd.conf without claiming migrated accounts", got)
	}
	if got := keptSSSDConf(true); !strings.Contains(got, "resolve only through the directory") {
		t.Errorf("entry removed: %q must say why sssd.conf stays", got)
	}
}

func TestMigrationPreview(t *testing.T) {
	accounts := []shadowedAccount{
		{Name: "alice", Home: "/home/alice", LocalUID: 1000, LocalGID: 1000, DirUID: 10001, DirGID: 6000,
			Groups: []string{"video"}, Dropped: []string{"sudo", "docker"}},
		{Name: "bob", Home: "/srv/bob", LocalUID: 1001, LocalGID: 1001, DirUID: 10002, DirGID: 6000},
		{Name: "carol", Home: "/home/carol", LocalUID: 1002, LocalGID: 1002, DirUID: 10003, DirGID: 6000, Groups: []string{"video"}},
		{Name: "dave", Home: "/home/../srv/dave", LocalUID: 1003, LocalGID: 1003, DirUID: 10004, DirGID: 6000},
		{Name: "erin", Home: "/home/erin/", LocalUID: 1004, LocalGID: 1004, DirUID: 10005, DirGID: 6000},
	}
	// homeExists is keyed by account name: alice's home exists, erin's is
	// missing; bob's and dave's lie outside /home, so it does not matter.
	got := migrationPreview(accounts, map[string]int{"carol": 2, "bob": 0}, map[string]bool{"alice": true})
	want := []string{
		"local account alice (uid 1000) shadows the directory user (uid 10001); --setup-ldap will migrate it, keep groups [video], not carry over the privileged groups [sudo, docker], re-own /home/alice",
		"local account bob (uid 1001) shadows the directory user (uid 10002); --setup-ldap will migrate it, keep groups [], leave /srv/bob as it is (outside /home)",
		"local account carol (uid 1002) shadows the directory user (uid 10003) but has 2 running process(es); --setup-ldap will skip it",
		"local account dave (uid 1003) shadows the directory user (uid 10004); --setup-ldap will migrate it, keep groups [], leave /home/../srv/dave as it is (outside /home)",
		"local account erin (uid 1004) shadows the directory user (uid 10005); --setup-ldap will migrate it, keep groups [], nothing to re-own (/home/erin missing)",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if migrationPreview(nil, nil, nil) != nil {
		t.Error("no shadowing account must give no line")
	}
}
