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

// reownedHome returns the cleaned home path and whether the migration may
// re-own it: only a home below /home is touched.
func reownedHome(home string) (string, bool) {
	h := filepath.Clean(home)
	return h, strings.HasPrefix(h, "/home/")
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
	if h, ok := reownedHome(a.Home); ok && exists(h) {
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

// sssPasswdLookup resolves name through SSSD only (getent -s sss), the
// directory side of findShadowedAccounts.
func sssPasswdLookup(name string) (uid, gid int, ok bool) {
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
	accounts := findShadowedAccounts(passwd, group, sssPasswdLookup)
	if len(accounts) == 0 {
		return
	}
	fmt.Println("------------------------------------------------------------")
	fmt.Printf("%d local account(s) shadow a directory user:\n", len(accounts))
	for _, a := range accounts {
		fmt.Printf("  - %s: local uid %d -> directory uid %d, keeps groups %v, home %s\n", a.Name, a.LocalUID, a.DirUID, a.Groups, a.Home)
	}
	fmt.Println("------------------------------------------------------------")
	migrated := migrateShadowedAccounts(accounts, "/proc", execRunner, pathExists)
	fmt.Printf("Migrated %d of %d local account(s).\n", migrated, len(accounts))
}

// pathExists reports whether p exists without following a final symlink; the
// migration and its preview decide with it what they re-own.
func pathExists(p string) bool { _, err := os.Lstat(p); return err == nil }

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

// migrationPreview describes, one line per account, what --setup-ldap would do
// with each local account that shadows a directory user (the decisions of
// migrateShadowedAccounts and migrateShadowedAccount); running holds the
// number of running processes and homeExists whether the home below /home
// exists, both per account name. Pure.
func migrationPreview(accounts []shadowedAccount, running map[string]int, homeExists map[string]bool) []string {
	var out []string
	for _, a := range accounts {
		head := fmt.Sprintf("local account %s (uid %d) shadows the directory user (uid %d)", a.Name, a.LocalUID, a.DirUID)
		if n := running[a.Name]; n > 0 {
			out = append(out, fmt.Sprintf("%s but has %d running process(es); --setup-ldap will skip it", head, n))
			continue
		}
		home := "leave " + a.Home + " as it is (outside /home)"
		if h, ok := reownedHome(a.Home); ok {
			home = "re-own " + h
			if !homeExists[a.Name] {
				home = "nothing to re-own (" + h + " missing)"
			}
		}
		out = append(out, fmt.Sprintf("%s; --setup-ldap will migrate it, keep groups [%s], %s", head, strings.Join(a.Groups, ", "), home))
	}
	return out
}

// shadowingPreview is migrationPreview for this host: the local accounts from
// /etc/passwd and /etc/group, the directory users via SSSD, the process counts
// from procRoot and the homes that exist (checked like the migration does).
func shadowingPreview(procRoot string) ([]string, error) {
	passwd, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}
	group, err := os.ReadFile("/etc/group")
	if err != nil {
		return nil, err
	}
	accounts := findShadowedAccounts(passwd, group, sssPasswdLookup)
	running := make(map[string]int, len(accounts))
	homeExists := make(map[string]bool, len(accounts))
	for _, a := range accounts {
		running[a.Name] = processCount(procRoot, a.LocalUID)
		if h, ok := reownedHome(a.Home); ok {
			homeExists[a.Name] = pathExists(h)
		}
	}
	return migrationPreview(accounts, running, homeExists), nil
}
