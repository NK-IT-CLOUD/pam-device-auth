package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// shadowedAccount is a local account whose name also resolves via SSSD with
// another UID. nsswitch reads files before sss, so the local entry would
// shadow the directory identity.
type shadowedAccount struct {
	Name, Home         string
	LocalUID, LocalGID int
	DirUID, DirGID     int
	Groups             []string // local supplementary groups to keep
}

// privilegedGroups never carry over: sudo comes from the directory.
var privilegedGroups = map[string]bool{"sudo": true, "admin": true, "wheel": true}

// findShadowedAccounts returns local accounts in the human UID range whose name
// resolves in the directory with a different UID. Pure; lookup wraps getent.
func findShadowedAccounts(passwd, group []byte, lookup func(name string) (uid, gid int, ok bool)) []shadowedAccount {
	var out []shadowedAccount
	for _, line := range strings.Split(string(passwd), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil || uid < 1000 || uid >= 65000 {
			continue
		}
		dUID, dGID, ok := lookup(f[0])
		if !ok || dUID == uid {
			continue
		}
		out = append(out, shadowedAccount{
			Name: f[0], Home: f[5], LocalUID: uid, LocalGID: gid, DirUID: dUID, DirGID: dGID,
			Groups: localSupplementaryGroups(group, f[0], gid),
		})
	}
	return out
}

// localSupplementaryGroups lists the /etc/group groups that name user as a
// member, without privileged groups and without the primary group.
func localSupplementaryGroups(group []byte, user string, primaryGID int) []string {
	var out []string
	for _, line := range strings.Split(string(group), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 4 || privilegedGroups[f[0]] {
			continue
		}
		if gid, err := strconv.Atoi(f[2]); err != nil || gid == primaryGID {
			continue
		}
		for _, m := range strings.Split(f[3], ",") {
			if m == user {
				out = append(out, f[0])
				break
			}
		}
	}
	return out
}

// processCount counts processes whose real or effective UID is uid, from the
// Uid: line of procRoot/<pid>/status.
func processCount(procRoot string, uid int) int {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return 0
	}
	want := strconv.Itoa(uid)
	n := 0
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "status"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if f := strings.Fields(line); len(f) >= 3 && f[0] == "Uid:" && (f[1] == want || f[2] == want) {
				n++
				break
			}
		}
	}
	return n
}

// migrateShadowedAccount removes the local entry (home kept), puts the
// directory user back into the recorded local groups and re-owns only the
// files that belonged to the old IDs: the home below /home, the mail spool and
// the crontab. It sends no signal. It returns the problems for the summary.
func migrateShadowedAccount(a shadowedAccount, run commandRunner, exists func(string) bool) []string {
	if out, err := run("userdel", a.Name); err != nil {
		return []string{fmt.Sprintf("userdel %s failed, not migrated: %s", a.Name, strings.TrimSpace(string(out)))}
	}
	var problems []string
	for _, g := range a.Groups {
		if out, err := run("gpasswd", "-a", a.Name, g); err != nil {
			problems = append(problems, fmt.Sprintf("re-adding %s to group %s failed: %s", a.Name, g, strings.TrimSpace(string(out))))
		}
	}
	var paths []string
	if h := filepath.Clean(a.Home); strings.HasPrefix(h, "/home/") && exists(h) {
		paths = append(paths, h)
	}
	for _, p := range []string{"/var/mail/" + a.Name, "/var/spool/cron/crontabs/" + a.Name} {
		if exists(p) {
			paths = append(paths, p)
		}
	}
	for _, p := range paths {
		for _, args := range [][]string{
			{"-R", "--from=" + strconv.Itoa(a.LocalUID), strconv.Itoa(a.DirUID), p},
			{"-R", "--from=:" + strconv.Itoa(a.LocalGID), ":" + strconv.Itoa(a.DirGID), p},
		} {
			if out, err := run("chown", args...); err != nil {
				problems = append(problems, fmt.Sprintf("chown %s failed: %s", strings.Join(args, " "), strings.TrimSpace(string(out))))
			}
		}
	}
	return problems
}

// migrateLocalShadowing migrates every shadowing local account that has no
// running process; the others stay untouched and are reported as warnings.
func migrateLocalShadowing() {
	passwd, err := os.ReadFile("/etc/passwd")
	if err != nil {
		setupWarnf("cannot read /etc/passwd, local accounts that shadow directory users were NOT checked: %v", err)
		return
	}
	group, err := os.ReadFile("/etc/group")
	if err != nil {
		setupWarnf("cannot read /etc/group, local accounts that shadow directory users were NOT migrated: %v", err)
		return
	}
	lookup := func(name string) (int, int, bool) {
		out, err := exec.Command("getent", "-s", "sss", "passwd", "--", name).Output()
		if err != nil {
			return 0, 0, false
		}
		f := strings.Split(strings.TrimSpace(string(out)), ":")
		if len(f) < 4 {
			return 0, 0, false
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		return uid, gid, err1 == nil && err2 == nil
	}
	accounts := findShadowedAccounts(passwd, group, lookup)
	if len(accounts) == 0 {
		return
	}
	fmt.Println("------------------------------------------------------------")
	fmt.Printf("%d local account(s) shadow a directory user:\n", len(accounts))
	for _, a := range accounts {
		fmt.Printf("  - %s: local uid %d -> directory uid %d, keeps groups %v, home %s\n", a.Name, a.LocalUID, a.DirUID, a.Groups, a.Home)
	}
	fmt.Println("------------------------------------------------------------")
	exists := func(p string) bool { _, err := os.Lstat(p); return err == nil }
	migrated := migrateShadowedAccounts(accounts, "/proc", execRunner, exists)
	fmt.Printf("Migrated %d of %d local account(s).\n", migrated, len(accounts))
}

// migrateShadowedAccounts migrates each account that has no process under
// procRoot and returns how many lost their local entry. An account with a
// running process is left untouched (no signal, no userdel) and becomes a
// setup warning, as does every problem of a migration.
func migrateShadowedAccounts(accounts []shadowedAccount, procRoot string, run commandRunner, exists func(string) bool) int {
	migrated := 0
	for _, a := range accounts {
		if n := processCount(procRoot, a.LocalUID); n > 0 {
			setupWarnf("local account %s shadows the directory user but has %d running process(es); stop them and re-run --setup-ldap", a.Name, n)
			continue
		}
		problems := migrateShadowedAccount(a, run, exists)
		for _, p := range problems {
			setupWarnf("%s", p)
		}
		if len(problems) == 0 || !strings.HasPrefix(problems[0], "userdel") {
			migrated++
			fmt.Printf("Migrated %s to directory uid %d\n", a.Name, a.DirUID)
		}
	}
	return migrated
}
