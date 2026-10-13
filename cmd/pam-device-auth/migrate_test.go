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
		{Name: "alice", Home: "/home/alice", LocalUID: 1000, LocalGID: 1000, DirUID: 10001, DirGID: 6000, Groups: []string{"docker", "video"}},
		{Name: "bob", Home: "/srv/bob", LocalUID: 1001, LocalGID: 1001, DirUID: 10002, DirGID: 6000},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

func TestLocalSupplementaryGroupsSkipsPrivilegedAndPrimary(t *testing.T) {
	got := localSupplementaryGroups([]byte(testGroup), "alice", 1000)
	if !reflect.DeepEqual(got, []string{"docker", "video"}) {
		t.Fatalf("got %v", got)
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
	if problems := migrateShadowedAccount(a, run, exists); len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
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
	problems := migrateShadowedAccount(a, run, func(string) bool { return false })
	if len(problems) != 1 || len(calls) != 1 {
		t.Fatalf("problems=%v calls=%v", problems, calls)
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
	}
	if got := migrateShadowedAccounts(accounts, proc, run, func(string) bool { return false }); got != 1 {
		t.Fatalf("migrated = %d, want 1 (only bob)", got)
	}
	if want := []string{"userdel bob", "userdel carol"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %q, want %q (nothing for alice, who has a running process)", calls, want)
	}
	if len(setupWarnings) != 2 || !strings.Contains(setupWarnings[0], "alice") || !strings.Contains(setupWarnings[0], "1 running process") ||
		!strings.HasPrefix(setupWarnings[1], "userdel carol failed") {
		t.Fatalf("setupWarnings = %q", setupWarnings)
	}
}
