package main

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
)

// checkLine is one line of --check: [OK] when ok, [FAIL] when fatal, [WARN]
// otherwise.
type checkLine struct {
	ok, fatal bool
	msg       string
}

// sshdPolicy is what sshd applies to a break-glass account from one address:
// the effective AuthenticationMethods, AuthorizedKeysFile and
// AuthorizedKeysCommand, and TrustedUserCAKeys (UserCA). Source is the
// break_glass_sources entry the policy was evaluated for, "" when no address
// was given.
type sshdPolicy struct{ Source, Methods, KeysFile, KeysCommand, UserCA string }

// breakGlassKeyFile is the key file of a break-glass account as the drop-in
// names it.
const breakGlassKeyFile = ".ssh/authorized_keys"

// breakGlassFacts is what --check knows about one break-glass account.
type breakGlassFacts struct {
	Local       bool   // has an entry in /etc/passwd
	UID         int    // of the local entry
	Home        string // of the local entry
	InDirectory bool   // the name resolves through SSSD
	Keys        int    // keys ssh-keygen accepts in <Home>/.ssh/authorized_keys
	KeyProblem  string // why sshd will not read the key file, "" when it will
	Aging       string // finding from /etc/shadow, "" for none
	Expired     bool   // Aging stops the login today
	// Inside holds sshd's policy for every break_glass_sources entry, or the
	// policy without an address when no sources are set. Outside is the policy
	// without an address when sources are set (any other address), nil otherwise.
	Inside  []sshdPolicy
	Outside *sshdPolicy
	// DropinStale says that the drop-in on disk holds another break-glass
	// section than the config asks for (breakGlassDropinStale).
	DropinStale bool
}

// overriddenAdvice ends the two warnings about a policy sshd does not apply.
// --enable renders the drop-in again when its break-glass section is not the
// one the config asks for; what stays after that comes from another file.
const overriddenAdvice = "run 'pam-device-auth --enable', and if this line stays look for a file in /etc/ssh/sshd_config.d that sorts before 10-pam-device-auth.conf"

// commandNone reports whether an effective AuthorizedKeysCommand value means
// that sshd runs no command: "none", or no line at all.
func commandNone(v string) bool {
	v = strings.TrimSpace(v)
	return v == "" || strings.EqualFold(v, "none")
}

// breakGlassVerdicts turns the facts about one break-glass account into the
// lines of --check and says whether the account is a working emergency path.
// A name the directory knows is the one blocker: its logins are denied
// (breakGlassVerdict), and a local entry must never stand in for a directory
// identity. Everything that only keeps the path from working is a warning.
func breakGlassVerdicts(user string, f breakGlassFacts) (lines []checkLine, usable bool) {
	prefix := "break-glass " + user + ": "
	switch {
	case f.InDirectory && !f.Local:
		return []checkLine{{fatal: true, msg: prefix + "the name is a directory user and has no entry in /etc/passwd; a listed name never logs in through the directory on this host. Take the name out of break_glass_users"}}, false
	case f.InDirectory:
		return []checkLine{{fatal: true, msg: prefix + "the name also resolves in the directory; logins of this account are denied until the local account or the directory user is renamed"}}, false
	case !f.Local:
		return []checkLine{{msg: prefix + "no entry in /etc/passwd; the package does not create the account"}}, false
	}
	warn := func(format string, a ...any) {
		lines = append(lines, checkLine{msg: prefix + fmt.Sprintf(format, a...)})
	}
	usable = !f.Expired
	keyFile := f.Home + "/.ssh/authorized_keys"
	switch {
	case f.KeyProblem != "":
		warn("sshd will not use %s: %s", keyFile, f.KeyProblem)
		usable = false
	case f.Keys == 0:
		warn("no valid key in %s", keyFile)
		usable = false
	}
	if f.Aging != "" {
		warn("%s", f.Aging)
	}
	var sources []string
	policyApplied := true
	for _, p := range f.Inside {
		from := "any address"
		if p.Source != "" {
			from = p.Source
			sources = append(sources, p.Source)
		}
		// Another key file than the block's means that another sshd file is in
		// effect: the keys counted in the account's authorized_keys say
		// nothing about what sshd reads.
		if !methodsKeyOnly(p.Methods) || p.KeysFile != breakGlassKeyFile || !commandNone(p.KeysCommand) {
			warn("sshd does not apply the break-glass policy from %s (AuthenticationMethods %s, AuthorizedKeysFile %s, AuthorizedKeysCommand %s); "+
				overriddenAdvice, from, p.Methods, p.KeysFile, p.KeysCommand)
			usable = false
			policyApplied = false
		}
	}
	// The path works in this case; it is wider than the config asks for.
	if o := f.Outside; o != nil && (!noKeysFile(o.KeysFile) || !commandNone(o.KeysCommand)) {
		warn("sshd leaves a key source open from addresses outside break_glass_sources (AuthorizedKeysFile %s, AuthorizedKeysCommand %s); "+
			overriddenAdvice, o.KeysFile, o.KeysCommand)
		policyApplied = false
	}
	// sshd answered as the config asks for every address that was tried, but
	// the section in the drop-in is another one: accounts or sources were
	// changed since it was rendered, and sshd may still accept an address the
	// config no longer lists. The account phase denies such a login.
	if f.DropinStale && policyApplied {
		warn("the sshd drop-in holds another break-glass section than the config asks for; run 'pam-device-auth --enable' (until then the account phase denies what the config no longer allows)")
	}
	if len(lines) == 0 {
		msg := fmt.Sprintf("%slocal account (uid %d), not in the directory, %d key(s) in %s, sshd: publickey only", prefix, f.UID, f.Keys, keyFile)
		if len(sources) > 0 {
			msg += " from " + strings.Join(sources, ", ") + ", no key source from any other address"
		}
		// A user CA is the admin's own sshd setting and applies to every
		// account; it is named so that "publickey only" is not read as "this
		// key file only".
		for _, p := range f.Inside {
			if !commandNone(p.UserCA) {
				msg += "; certificates of the user CA " + p.UserCA + " are accepted as well (TrustedUserCAKeys)"
				break
			}
		}
		lines = append(lines, checkLine{ok: true, msg: msg})
	}
	return lines, usable
}

// breakGlassSection returns the lines of the "Break-glass accounts" section of
// --check: the verdicts of every account and, with root_login disabled, a
// warning when none of them is usable. A host that disabled root without
// configuring break-glass accounts has no such section: its admin chose the
// console. Without accounts the section has one line at most: the drop-in
// still holds a section for accounts that were taken out of the config
// (staleDropin).
func breakGlassSection(users []string, rootDisabled, staleDropin bool, verdicts func(user string) ([]checkLine, bool)) []checkLine {
	if len(users) == 0 {
		if staleDropin {
			return []checkLine{{msg: "the sshd drop-in still holds a break-glass section although break_glass_users is empty; run 'pam-device-auth --enable' to remove it (until then sshd accepts the keys of those accounts and the account phase denies their logins)"}}
		}
		return nil
	}
	var lines []checkLine
	usable := 0
	for _, u := range users {
		l, ok := verdicts(u)
		lines = append(lines, l...)
		if ok {
			usable++
		}
	}
	if rootDisabled && usable == 0 {
		lines = append(lines, checkLine{msg: "root_login is 'disabled' and no break-glass account is usable; there is no emergency path over SSH if LDAP, SSSD or the identity provider fail"})
	}
	return lines
}

// keyFileFacts counts the keys in home/.ssh/authorized_keys and says why sshd
// will not read the file, "" when it will. With StrictModes (the default) the
// home, .ssh and the file must belong to the account or to root and must not
// be writable by group or others. sshd opens the file as the account (uid,
// primary group gid; further groups are not looked at), so the account must
// be able to enter both directories and to read the file, and the file must
// be a regular file. A missing path means no key and no problem.
func keyFileFacts(home string, uid, gid int) (keys int, problem string) {
	file := filepath.Join(home, ".ssh", "authorized_keys")
	for _, p := range []string{home, filepath.Dir(file), file} {
		fi, err := os.Stat(p)
		if err != nil {
			return 0, ""
		}
		perm := fi.Mode().Perm()
		st, ok := fi.Sys().(*syscall.Stat_t)
		if ok && int(st.Uid) != uid && st.Uid != 0 {
			return 0, fmt.Sprintf("%s belongs to uid %d, not to the account or root", p, st.Uid)
		}
		if perm&0022 != 0 {
			return 0, fmt.Sprintf("%s is writable by group or others (mode %s)", p, perm)
		}
		if !ok {
			continue
		}
		// The bit the account needs, in the class the kernel picks for it.
		need, what := os.FileMode(0001), "entered"
		if p == file {
			need, what = 0004, "read"
		}
		switch {
		case int(st.Uid) == uid:
			need <<= 6
		case int(st.Gid) == gid:
			need <<= 3
		}
		if perm&need == 0 {
			return 0, fmt.Sprintf("%s cannot be %s by the account (mode %s, owner uid %d)", p, what, perm, st.Uid)
		}
	}
	// Opened without blocking and looked at again as an open file: a FIFO that
	// takes the place of the file between the two looks must not hold --check.
	f, err := os.OpenFile(file, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0, ""
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return 0, file + " is not a regular file"
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return 0, ""
	}
	return countSSHKeys(data), ""
}

// countSSHKeys returns the number of keys in an authorized_keys blob that
// ssh-keygen -l accepts (the parser family of sshd); 0 when it accepts none.
func countSSHKeys(authKeys []byte) int {
	c := exec.Command("ssh-keygen", "-l", "-f", "/dev/stdin")
	c.Stdin = bytes.NewReader(authKeys)
	out, err := c.Output()
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// shadowAging reads the entry of name from data in shadow format and returns
// what pam_unix makes of it at a login on day today (days since 1970-01-01):
// an expired account is denied, and a password that must be changed or has
// reached its maximum age makes pam_unix demand a password change, which a
// key-only login cannot complete. expired says that the finding stops a login
// today; a finding with expired false lies ahead. An empty field switches its
// rule off (shadow(5)).
func shadowAging(shadow []byte, name string, today int) (finding string, expired bool) {
	num := func(s string) int {
		n, err := strconv.Atoi(s)
		if err != nil {
			return -1
		}
		return n
	}
	date := func(day int) string { return time.Unix(int64(day)*86400, 0).UTC().Format("2006-01-02") }
	for _, line := range strings.Split(string(shadow), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 8 || f[0] != name {
			continue
		}
		lstchg, maxAge, expire := num(f[2]), num(f[4]), num(f[7])
		switch {
		case expire >= 0 && today >= expire:
			return fmt.Sprintf("the account expired on %s; pam_unix denies the login (chage -E -1 %s)", date(expire), name), true
		case lstchg == 0:
			return fmt.Sprintf("the password must be changed at the next login, which a key-only login cannot complete (chage -d <date> %s)", name), true
		case lstchg > 0 && maxAge >= 0 && today-lstchg > maxAge:
			return fmt.Sprintf("the password reached its maximum age of %d days on %s; pam_unix demands a password change at login, which a key-only login cannot complete (chage -M -1 %s)", maxAge, date(lstchg+maxAge), name), true
		case expire > today:
			return fmt.Sprintf("the account expires on %s; from then on pam_unix denies the login (chage -E -1 %s)", date(expire), name), false
		case lstchg > 0 && maxAge >= 0 && maxAge < 99999:
			return fmt.Sprintf("the password reaches its maximum age of %d days on %s; from then on pam_unix demands a password change at login (chage -M -1 %s)", maxAge, date(lstchg+maxAge), name), false
		}
		return "", false
	}
	return "", false
}

// sourceProbeAddr returns the address --check hands to `sshd -T -C addr=` for
// a break_glass_sources entry: the address itself, or the first address of a
// range.
func sourceProbeAddr(source string) string {
	if p, err := netip.ParsePrefix(source); err == nil {
		return p.Addr().String()
	}
	return source
}

// gatherBreakGlassFacts collects the facts about one break-glass account from
// this host: the local entry, the directory, the key file, /etc/shadow and
// sshd's effective policy for every source and for any other address. A
// directory lookup that fails counts as "not in the directory", as it does at
// login (breakGlassVerdict).
func gatherBreakGlassFacts(user string, sources []string) breakGlassFacts {
	var f breakGlassFacts
	gid := 0
	if passwd, err := os.ReadFile(passwdFile); err == nil {
		f.UID, gid, f.Home, f.Local = passwdEntry(passwd, user)
	}
	f.InDirectory, _ = sssLookup(user, breakGlassLookupTimeout)
	if f.Local {
		f.Keys, f.KeyProblem = keyFileFacts(f.Home, f.UID, gid)
		if shadow, err := os.ReadFile("/etc/shadow"); err == nil {
			f.Aging, f.Expired = shadowAging(shadow, user, int(time.Now().Unix()/86400))
		}
	}
	policy := func(source, spec string) sshdPolicy {
		methods, _ := sshdParamFor("authenticationmethods", spec)
		keysFile, _ := sshdKeysFileFor(spec)
		command, _ := sshdParamFor("authorizedkeyscommand", spec)
		userCA, _ := sshdParamFor("trustedusercakeys", spec)
		return sshdPolicy{Source: source, Methods: methods, KeysFile: keysFile, KeysCommand: command, UserCA: userCA}
	}
	if len(sources) == 0 {
		f.Inside = []sshdPolicy{policy("", "user="+user)}
		return f
	}
	for _, s := range sources {
		f.Inside = append(f.Inside, policy(s, "user="+user+",addr="+sourceProbeAddr(s)))
	}
	outside := policy("", "user="+user)
	f.Outside = &outside
	return f
}

// breakGlassDropinStaleOnDisk reports whether the sshd drop-in on disk holds
// another break-glass section than bg asks for. A drop-in that cannot be read
// is not stale: the policy check of every account reports the missing blocks.
func breakGlassDropinStaleOnDisk(bg config.BreakGlass) bool {
	data, err := os.ReadFile(sshdDropinPath)
	return err == nil && breakGlassDropinStale(string(data), bg)
}

// useDNSWarning is the --check warning for UseDNS yes. With
// break_glass_sources the account phase compares the client address of a
// break-glass account too, so the warning names that consequence.
func useDNSWarning(breakGlassSources bool) string {
	gate := "every user with a clients allowlist"
	if breakGlassSources {
		gate += " and every break-glass account (break_glass_sources is set)"
	}
	return "sshd has UseDNS yes; PAM receives the client host name instead of its IP and the account-phase IP gate denies " + gate + "; set UseDNS no"
}
