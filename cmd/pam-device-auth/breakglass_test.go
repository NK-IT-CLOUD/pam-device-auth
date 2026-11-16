package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// checkLevel names the level --check prints for a line.
func checkLevel(l checkLine) string {
	switch {
	case l.ok:
		return "OK"
	case l.fatal:
		return "FAIL"
	}
	return "WARN"
}

// requireCheckLines compares lines with want: one entry per line, the level
// ("OK", "WARN" or "FAIL"), a space and a part of the message.
func requireCheckLines(t *testing.T, name string, lines []checkLine, want []string) {
	t.Helper()
	if len(lines) != len(want) {
		t.Errorf("%s: %d line(s) %+v, want %d", name, len(lines), lines, len(want))
		return
	}
	for i, w := range want {
		level, part, _ := strings.Cut(w, " ")
		if got := checkLevel(lines[i]); got != level || !strings.Contains(lines[i].msg, part) {
			t.Errorf("%s line %d: %s %q, want %s containing %q", name, i, got, lines[i].msg, level, part)
		}
	}
}

// One verdict per break-glass account: a name the directory knows is a
// blocker, everything that keeps the emergency path from working is a
// warning, and only an account without such a finding counts as usable.
func TestBreakGlassVerdicts(t *testing.T) {
	good := sshdPolicy{Methods: "publickey", KeysFile: ".ssh/authorized_keys", KeysCommand: "none"}
	in := good
	in.Source = "192.0.2.0/24"
	closed := &sshdPolicy{Methods: "publickey,keyboard-interactive:pam", KeysFile: "none", KeysCommand: "none"}
	open := &sshdPolicy{Methods: "publickey,keyboard-interactive:pam", KeysFile: "none", KeysCommand: "/usr/bin/sss_ssh_authorizedkeys"}
	stale := sshdPolicy{Methods: "publickey,keyboard-interactive:pam", KeysFile: "none", KeysCommand: "/usr/bin/sss_ssh_authorizedkeys"}
	base := breakGlassFacts{Local: true, UID: 1001, Home: "/home/breakglass", Keys: 1, Inside: []sshdPolicy{good}}
	with := func(change func(*breakGlassFacts)) breakGlassFacts { f := base; change(&f); return f }
	for _, c := range []struct {
		name   string
		f      breakGlassFacts
		usable bool
		want   []string
	}{
		{"works", base, true, []string{"OK break-glass breakglass: local account (uid 1001), not in the directory, 1 key(s) in /home/breakglass/.ssh/authorized_keys, sshd: publickey only"}},
		{"works with sources", with(func(f *breakGlassFacts) { f.Inside, f.Outside = []sshdPolicy{in}, closed }), true,
			[]string{"OK sshd: publickey only from 192.0.2.0/24, no key source from any other address"}},
		{"command line missing counts as none", with(func(f *breakGlassFacts) {
			f.Inside = []sshdPolicy{{Methods: "publickey", KeysFile: ".ssh/authorized_keys"}}
		}), true,
			[]string{"OK sshd: publickey only"}},
		// Another sshd file names another key file: the keys counted in
		// .ssh/authorized_keys say nothing about what sshd reads.
		{"another key file in effect", with(func(f *breakGlassFacts) {
			f.Inside = []sshdPolicy{{Methods: "publickey", KeysFile: ".ssh/other_keys", KeysCommand: "none"}}
		}), false, []string{"WARN sshd does not apply the break-glass policy from any address (AuthenticationMethods publickey, AuthorizedKeysFile .ssh/other_keys, AuthorizedKeysCommand none)"}},
		{"user CA configured", with(func(f *breakGlassFacts) {
			f.Inside = []sshdPolicy{{Methods: "publickey", KeysFile: ".ssh/authorized_keys", KeysCommand: "none", UserCA: "/etc/ssh/user_ca.pub"}}
		}), true, []string{"OK sshd: publickey only; certificates of the user CA /etc/ssh/user_ca.pub are accepted as well (TrustedUserCAKeys)"}},
		{"name in the directory", with(func(f *breakGlassFacts) { f.InDirectory = true; f.Keys = 0 }), false, []string{"FAIL the name also resolves in the directory"}},
		// A directory user listed by mistake: the name is then no login on this
		// host at all, and the line has to say so.
		{"directory user listed", breakGlassFacts{InDirectory: true}, false,
			[]string{"FAIL break-glass breakglass: the name is a directory user and has no entry in /etc/passwd; a listed name never logs in through the directory on this host. Take the name out of break_glass_users"}},
		{"no local account", breakGlassFacts{}, false, []string{"WARN no entry in /etc/passwd"}},
		{"no key", with(func(f *breakGlassFacts) { f.Keys = 0 }), false, []string{"WARN no valid key in /home/breakglass/.ssh/authorized_keys"}},
		{"key file refused", with(func(f *breakGlassFacts) {
			f.KeyProblem = "/home/breakglass is writable by group or others (mode -rwxrwxr-x)"
		}), false,
			[]string{"WARN sshd will not use /home/breakglass/.ssh/authorized_keys: /home/breakglass is writable"}},
		{"block not rendered", with(func(f *breakGlassFacts) { f.Inside = []sshdPolicy{stale} }), false,
			[]string{"WARN sshd does not apply the break-glass policy from any address (AuthenticationMethods publickey,keyboard-interactive:pam, AuthorizedKeysFile none, AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys); run 'pam-device-auth --enable', and if this line stays look for a file in /etc/ssh/sshd_config.d that sorts before 10-pam-device-auth.conf"}},
		{"directory key still accepted", with(func(f *breakGlassFacts) {
			f.Inside = []sshdPolicy{{Source: "192.0.2.0/24", Methods: "publickey", KeysFile: ".ssh/authorized_keys", KeysCommand: "/usr/bin/sss_ssh_authorizedkeys"}}
			f.Outside = closed
		}), false, []string{"WARN sshd does not apply the break-glass policy from 192.0.2.0/24 (AuthenticationMethods publickey, AuthorizedKeysFile .ssh/authorized_keys, AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys)"}},
		{"open from outside", with(func(f *breakGlassFacts) { f.Inside, f.Outside = []sshdPolicy{in}, open }), true,
			[]string{"WARN sshd leaves a key source open from addresses outside break_glass_sources (AuthorizedKeysFile none, AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys); run 'pam-device-auth --enable', and if this line stays look for a file in /etc/ssh/sshd_config.d that sorts before 10-pam-device-auth.conf"}},
		{"drop-in section is stale", with(func(f *breakGlassFacts) { f.Inside, f.Outside, f.DropinStale = []sshdPolicy{in}, closed, true }), true,
			[]string{"WARN break-glass breakglass: the sshd drop-in holds another break-glass section than the config asks for; run 'pam-device-auth --enable'"}},
		{"aging ahead", with(func(f *breakGlassFacts) { f.Aging = "the password reaches its maximum age of 365 days on 2027-08-18" }), true,
			[]string{"WARN break-glass breakglass: the password reaches its maximum age"}},
		{"expired, no key", with(func(f *breakGlassFacts) { f.Keys, f.Aging, f.Expired = 0, "the account expired on 2026-01-01", true }), false,
			[]string{"WARN no valid key", "WARN the account expired on 2026-01-01"}},
		{"expired only", with(func(f *breakGlassFacts) { f.Aging, f.Expired = "the account expired on 2026-01-01", true }), false,
			[]string{"WARN the account expired on 2026-01-01"}},
	} {
		lines, usable := breakGlassVerdicts("breakglass", c.f)
		if usable != c.usable {
			t.Errorf("%s: usable = %v, want %v", c.name, usable, c.usable)
		}
		requireCheckLines(t, c.name, lines, c.want)
	}
}

// With root_login disabled a host whose break-glass accounts are all unusable
// has no emergency path over SSH. A host that disabled root without
// configuring break-glass accounts never gets here.
func TestBreakGlassSection(t *testing.T) {
	verdicts := map[string]bool{"breakglass": true, "rescue": false}
	facts := func(user string) ([]checkLine, bool) {
		if verdicts[user] {
			return []checkLine{{ok: true, msg: "break-glass " + user + ": local account"}}, true
		}
		return []checkLine{{msg: "break-glass " + user + ": no entry in /etc/passwd"}}, false
	}
	noPath := "WARN root_login is 'disabled' and no break-glass account is usable; there is no emergency path over SSH if LDAP, SSSD or the identity provider fail"
	for _, c := range []struct {
		name         string
		users        []string
		rootDisabled bool
		want         []string
	}{
		{"one usable, root disabled", []string{"breakglass", "rescue"}, true, []string{"OK break-glass breakglass", "WARN break-glass rescue"}},
		{"none usable, root disabled", []string{"rescue"}, true, []string{"WARN break-glass rescue", noPath}},
		{"none usable, root has its key", []string{"rescue"}, false, []string{"WARN break-glass rescue"}},
		{"no accounts", nil, true, nil},
	} {
		requireCheckLines(t, c.name, breakGlassSection(c.users, c.rootDisabled, false, facts), c.want)
	}
	// The last account was taken out of the config, but its block is still in
	// the drop-in: sshd accepts the key and the account phase denies the login.
	left := []string{"WARN the sshd drop-in still holds a break-glass section although break_glass_users is empty; run 'pam-device-auth --enable' to remove it"}
	requireCheckLines(t, "no accounts, section left in the drop-in", breakGlassSection(nil, false, true, facts), left)
	requireCheckLines(t, "accounts configured: the stale section is reported per account", breakGlassSection([]string{"breakglass"}, false, true, facts), []string{"OK break-glass breakglass"})
}

// pam_unix stops a key-only login over account expiry and password aging; a
// rarely used account runs into exactly this.
func TestShadowAging(t *testing.T) {
	const today = 20773 // 2026-11-16
	for _, c := range []struct {
		entry, want string
		expired     bool
	}{
		{"breakglass:!:20683:0:99999:7:::", "", false},
		{"breakglass:!:20683:0:30:7:::", "reached its maximum age of 30 days on 2026-09-17", true},
		{"breakglass:!:20683:0:365:7:::", "reaches its maximum age of 365 days on 2027-08-18", false},
		{"breakglass:!:0:0:99999:7:::", "must be changed at the next login", true},
		{"breakglass:!:20683:0:99999:7::20454:", "the account expired on 2026-01-01", true},
		{"breakglass:!:20683:0:99999:7::20773:", "the account expired on 2026-11-16", true},
		{"breakglass:!:20683:0:99999:7::20863:", "the account expires on 2027-02-14", false},
		{"breakglass:!:20683::::::", "", false},
		{"alice:!:0:0:30:7:::", "", false}, // another account's entry
	} {
		got, expired := shadowAging([]byte("root:*:20000:0:99999:7:::\n"+c.entry+"\n"), "breakglass", today)
		if expired != c.expired || (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, expired=%v; want %q, %v", c.entry, got, expired, c.want, c.expired)
		}
		if got != "" && !strings.Contains(got, "breakglass)") {
			t.Errorf("%s: finding %q does not end with the chage command for the account", c.entry, got)
		}
	}
}

// testKeyLines returns n public key lines made by ssh-keygen; the test is
// skipped on a host without it.
func testKeyLines(t *testing.T, n int) []string {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not installed")
	}
	var lines []string
	for i := 0; i < n; i++ {
		key := filepath.Join(t.TempDir(), "key")
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", key).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen: %v: %s", err, out)
		}
		pub, err := os.ReadFile(key + ".pub")
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, strings.TrimSpace(string(pub)))
	}
	return lines
}

func TestCountSSHKeys(t *testing.T) {
	keys := testKeyLines(t, 2)
	for _, c := range []struct {
		name  string
		input string
		want  int
	}{
		{"two keys", keys[0] + "\n" + keys[1] + "\n", 2},
		{"a key, a comment, garbage and a key with options", keys[0] + "\n# comment\ngarbage\nfrom=\"192.0.2.1\",no-pty " + keys[1] + "\n", 2},
		{"empty", "", 0},
		{"garbage", "garbage\n", 0},
	} {
		if got := countSSHKeys([]byte(c.input)); got != c.want {
			t.Errorf("%s: countSSHKeys = %d, want %d", c.name, got, c.want)
		}
		if got := hasValidSSHKey([]byte(c.input)); got != (c.want > 0) {
			t.Errorf("%s: hasValidSSHKey = %v, want %v", c.name, got, c.want > 0)
		}
	}
}

// sshd reads a key file only when the home, .ssh and the file belong to the
// account or to root and are not writable by group or others (StrictModes).
func TestKeyFileFacts(t *testing.T) {
	key := testKeyLines(t, 1)[0]
	uid := os.Getuid()
	home := filepath.Join(t.TempDir(), "home")
	sshDir := filepath.Join(home, ".ssh")
	file := filepath.Join(sshDir, "authorized_keys")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	gid := os.Getgid()
	if keys, problem := keyFileFacts(home, uid, gid); keys != 0 || problem != "" {
		t.Errorf("no .ssh: %d key(s), problem %q; want 0 and none", keys, problem)
	}
	if err := os.Mkdir(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(key+"\ngarbage\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if keys, problem := keyFileFacts(home, uid, gid); keys != 1 || problem != "" {
		t.Errorf("good key file: %d key(s), problem %q; want 1 and none", keys, problem)
	}
	// sshd reads the file as the account: a file or a directory the account
	// cannot use is no key source, whatever root can read.
	for _, c := range []struct {
		path string
		mode os.FileMode
		back os.FileMode
		want string
	}{
		{file, 0200, 0600, file + " cannot be read by the account (mode "},
		{sshDir, 0600, 0700, sshDir + " cannot be entered by the account (mode "},
	} {
		if err := os.Chmod(c.path, c.mode); err != nil {
			t.Fatal(err)
		}
		if _, problem := keyFileFacts(home, uid, gid); !strings.Contains(problem, c.want) {
			t.Errorf("%s with mode %o: problem %q, want %q", c.path, c.mode, problem, c.want)
		}
		if err := os.Chmod(c.path, c.back); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		path string
		mode os.FileMode
		back os.FileMode
	}{
		{home, 0775, 0755},
		{sshDir, 0777, 0700},
		{file, 0664, 0600},
	} {
		if err := os.Chmod(c.path, c.mode); err != nil {
			t.Fatal(err)
		}
		_, problem := keyFileFacts(home, uid, gid)
		if !strings.Contains(problem, c.path+" is writable by group or others (mode ") {
			t.Errorf("%s with mode %o: problem %q, want it to name the path as writable", c.path, c.mode, problem)
		}
		if err := os.Chmod(c.path, c.back); err != nil {
			t.Fatal(err)
		}
	}
	// Another owner than the account or root: as root, hand the home to a
	// third uid; otherwise ask about an account that is not the owner.
	account := uid + 1
	if uid == 0 {
		account = 1001
		if err := os.Chown(home, 12345, 12345); err != nil {
			t.Fatal(err)
		}
	}
	if _, problem := keyFileFacts(home, account, gid); !strings.Contains(problem, home+" belongs to uid ") || !strings.Contains(problem, "not to the account or root") {
		t.Errorf("foreign owner: problem %q, want it to name the owner of %s", problem, home)
	}
}

// A FIFO where the key file should be must not hold --check (or --enable,
// which runs the same checks): sshd reads regular files only.
func TestKeyFileFacts_NotARegularFile(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(home, ".ssh", "authorized_keys")
	if err := syscall.Mkfifo(file, 0600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan string, 1)
	go func() {
		_, problem := keyFileFacts(home, os.Getuid(), os.Getgid())
		done <- problem
	}()
	select {
	case problem := <-done:
		if !strings.Contains(problem, file+" is not a regular file") {
			t.Errorf("problem = %q, want it to say that %s is not a regular file", problem, file)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("keyFileFacts blocks on a FIFO")
	}
}

func TestSourceProbeAddr(t *testing.T) {
	for source, want := range map[string]string{
		"192.0.2.10":      "192.0.2.10",
		"198.51.100.0/24": "198.51.100.0",
		"2001:db8:1::/48": "2001:db8:1::",
		"2001:db8::1":     "2001:db8::1",
	} {
		if got := sourceProbeAddr(source); got != want {
			t.Errorf("sourceProbeAddr(%q) = %q, want %q", source, got, want)
		}
	}
}

// With UseDNS yes PAM gets a host name, which break_glass_sources cannot
// match: the warning names that consequence only when sources are set.
func TestUseDNSWarning(t *testing.T) {
	plain := "sshd has UseDNS yes; PAM receives the client host name instead of its IP and the account-phase IP gate denies every user with a clients allowlist; set UseDNS no"
	if got := useDNSWarning(false); got != plain {
		t.Errorf("without sources: %q, want the 0.7.2 text %q", got, plain)
	}
	want := "sshd has UseDNS yes; PAM receives the client host name instead of its IP and the account-phase IP gate denies every user with a clients allowlist and every break-glass account (break_glass_sources is set); set UseDNS no"
	if got := useDNSWarning(true); got != want {
		t.Errorf("with sources: %q, want %q", got, want)
	}
}
