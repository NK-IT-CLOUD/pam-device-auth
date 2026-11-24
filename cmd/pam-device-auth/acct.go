package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/logger"
)

// busctlTimeout bounds the busctl/D-Bus round-trip so a wedged SSSD cannot
// hang the login. Errors from a timeout are treated identically to any other
// read failure: fail-closed deny (see decideIPGate).
const busctlTimeout = 5 * time.Second

// decideIPGate is the pure IP-allowlist decision. It never touches the
// network, SSSD, or busctl — every input is already resolved by the caller.
//
//   - !requiresGate     -> allow (root is the sole break-glass exemption)
//   - readErr != nil     -> deny (fail-closed: we know the user IS a directory
//     user but could not read their allowlist — never fail open on a read error)
//   - len(clients) == 0  -> allow (directory user with no "clients" attribute
//     set is unrestricted by design)
//   - otherwise          -> allow iff rhost matches one of clients
//     (matchesAllowedIP also denies on an empty/unparseable rhost, which
//     covers "PAM_RHOST unset for a directory user with clients" -> deny)
func decideIPGate(requiresGate bool, clients []string, readErr error, rhost string) bool {
	switch {
	case !requiresGate:
		return true
	case readErr != nil:
		return false
	case len(clients) == 0:
		return true
	default:
		return matchesAllowedIP(rhost, clients)
	}
}

// parseBusctlClients parses the stdout of:
//
//	busctl --json=short call org.freedesktop.sssd.infopipe \
//	  /org/freedesktop/sssd/infopipe org.freedesktop.sssd.infopipe \
//	  GetUserAttr sas <user> 1 clients
//
// Live-verified shapes:
//   - has clients:    {"type":"a{sv}","data":[{"clients":{"type":"as","data":["192.0.2.203",...]}}]}
//   - no clients attr: {"type":"a{sv}","data":[{}]}
//
// The second shape is NOT an error — it means the directory user has no
// "clients" attribute set, i.e. unrestricted. Returns (nil, nil) for it.
func parseBusctlClients(jsonOut []byte) ([]string, error) {
	attrs, err := parseBusctlAttrs(jsonOut)
	if err != nil {
		return nil, err
	}
	return attrs["clients"], nil
}

// parseBusctlAttrs parses the stdout of a busctl GetUserAttr call into the
// values per attribute. An attribute the user does not have, or one the
// InfoPipe does not hand out, is absent from the answer and from the map.
func parseBusctlAttrs(jsonOut []byte) (map[string][]string, error) {
	var resp struct {
		Type string `json:"type"`
		Data []map[string]struct {
			Type string   `json:"type"`
			Data []string `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(jsonOut, &resp); err != nil {
		return nil, fmt.Errorf("parse busctl GetUserAttr output: %w", err)
	}
	if resp.Type != "a{sv}" || len(resp.Data) != 1 {
		return nil, fmt.Errorf("unexpected busctl GetUserAttr response shape: type=%q data entries=%d", resp.Type, len(resp.Data))
	}
	attrs := make(map[string][]string, len(resp.Data[0]))
	for name, attr := range resp.Data[0] {
		if attr.Type != "as" {
			return nil, fmt.Errorf("unexpected %s attribute type %q", name, attr.Type)
		}
		attrs[name] = attr.Data
	}
	return attrs, nil
}

// requiresIPGate keeps the break-glass boundary deliberately narrow: only
// root is exempt without a further look. Treating every name found in
// /etc/passwd as local/exempt is unsafe because a same-named SSSD identity can
// still supply the SSH key and groups while the local passwd entry shadows
// identity lookup. The accounts an admin lists in break_glass_users are
// decided by breakGlassVerdict; every other local account is no login tier
// (AuthorizedKeysFile is disabled for it), so an attempted account check for
// one safely fails closed in busctl.
func requiresIPGate(user string) bool {
	return user != "root"
}

// breakGlassLookupTimeout bounds the directory lookup of a break-glass login.
// The PAM module ends the account helper after ACCT_TOTAL_TIMEOUT_S (7 s,
// pam_device_auth.c) and denies. This limit stays well below that: a lookup
// that gets no answer must end as an allow here, not as that deny.
const breakGlassLookupTimeout = 3 * time.Second

// passwdFile is the database of local accounts; a variable so tests can point
// it at a file of their own.
var passwdFile = "/etc/passwd"

// passwdEntry returns the UID, the primary GID and the home directory of name
// from data in passwd format; ok is false when name has no entry.
func passwdEntry(passwd []byte, name string) (uid, gid int, home string, ok bool) {
	if name == "" {
		return 0, 0, "", false
	}
	for _, line := range strings.Split(string(passwd), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 || f[0] != name {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil {
			return 0, 0, "", false
		}
		return uid, gid, f[5], true
	}
	return 0, 0, "", false
}

// localAccount reports whether name has an entry in passwdFile. The file is
// read directly, not through NSS: the question is whether the account is
// local, and NSS would answer for a directory user as well.
func localAccount(name string) (bool, error) {
	data, err := os.ReadFile(passwdFile)
	if err != nil {
		return false, err
	}
	_, _, _, ok := passwdEntry(data, name)
	return ok, nil
}

// loadBreakGlass reads the break-glass settings for the account phase, and
// breakGlassSSS asks the directory about a break-glass account; variables so
// tests can stand in for the config file and for SSSD.
var (
	loadBreakGlass = config.LoadBreakGlass
	breakGlassSSS  = func(user string) (bool, error) { return sssLookup(user, breakGlassLookupTimeout) }
)

// acctVerdict is the account decision for a break-glass account with the line
// to log and its level ("info", "warn" or "error").
type acctVerdict struct {
	allow bool
	level string
	msg   string
}

// breakGlassVerdict decides the login of user, an account listed in
// break_glass_users. Such an account is exempt from the clients gate like
// root, but only on local facts: it must have an entry in /etc/passwd (local),
// come from break_glass_sources when sources are set, and its name must not
// resolve in the directory (sss). A local entry never stands in for a
// directory identity: when the directory knows the name, the login is denied.
// Only that positive answer denies. A lookup that fails or gets no answer in
// time (SSSD stopped or hanging) allows: that is the situation the account
// exists for, and sshd accepts no key from the directory for these accounts.
func breakGlassVerdict(user, rhost string, bg config.BreakGlass, local, sss func(string) (bool, error)) acctVerdict {
	isLocal, err := local(user)
	switch {
	case err != nil:
		return acctVerdict{false, "error", fmt.Sprintf("pam-acct: user=%s break-glass account: cannot read /etc/passwd: %v; deny", user, err)}
	case !isLocal:
		return acctVerdict{false, "error", fmt.Sprintf("pam-acct: user=%s is listed in break_glass_users but has no entry in /etc/passwd; deny", user)}
	case len(bg.Sources) > 0 && !matchesAllowedIP(rhost, bg.Sources):
		return acctVerdict{false, "warn", fmt.Sprintf("pam-acct: user=%s rhost=%s break-glass account, address not in break_glass_sources %v; deny", user, rhost, bg.Sources)}
	}
	found, err := sss(user)
	switch {
	case found:
		return acctVerdict{false, "error", fmt.Sprintf("pam-acct: user=%s is a break-glass account but the name also resolves in the directory; deny (rename the local account or the directory user)", user)}
	case err != nil:
		return acctVerdict{true, "warn", fmt.Sprintf("pam-acct: user=%s local break-glass account; directory lookup failed (%v), treated as not in the directory; exempt, allow", user, err)}
	}
	return acctVerdict{true, "info", fmt.Sprintf("pam-acct: user=%s local break-glass account; exempt, allow", user)}
}

// logVerdict writes the verdict's line at its level.
func logVerdict(log *logger.Logger, v acctVerdict) {
	switch v.level {
	case "error":
		log.Error("%s", v.msg)
	case "warn":
		log.Warn("%s", v.msg)
	default:
		log.Info("%s", v.msg)
	}
}

// acctInputs are the lookups and settings of one account decision.
type acctInputs struct {
	read  func(user string) ([]string, error) // clients allowlist of a directory user
	bg    config.BreakGlass
	local func(user string) (bool, error) // localAccount
	sss   func(user string) (bool, error) // directory lookup of a break-glass account
	// block returns the accounts the break-glass section of the sshd drop-in
	// names (breakGlassBlockUsersOnDisk); nil means no drop-in is looked at.
	block func() []string
	// ad reports whether the config declares an Active Directory
	// (directoryIsAD); there state reads the account state of a directory
	// user. A nil ad means no account state is looked at.
	ad    func() (bool, error)
	state func(user string) (adAccountState, error)
}

// busctlClientsArgs is the busctl command line that asks the SSSD InfoPipe for
// the "clients" attribute of user. busctl parses options anywhere on its
// command line, so "--" comes before the verb: everything after it, the user
// name included, is data.
func busctlClientsArgs(user string) []string {
	return busctlUserAttrArgs(user, "clients")
}

// busctlUserAttrArgs is the busctl command line that asks the SSSD InfoPipe
// for attrs of user.
func busctlUserAttrArgs(user string, attrs ...string) []string {
	return append([]string{"--json=short", "--", "call",
		"org.freedesktop.sssd.infopipe",
		"/org/freedesktop/sssd/infopipe",
		"org.freedesktop.sssd.infopipe",
		"GetUserAttr", "sas", user, strconv.Itoa(len(attrs)),
	}, attrs...)
}

// busctlClients reads the "clients" IP allowlist attribute for a directory
// user via sssd-infopipe over D-Bus. Callers MUST only invoke this for a user
// subject to the non-root gate. Any non-zero exit here is a read failure (ifp
// down, D-Bus unavailable, unknown/local-only user, etc.) and must fail closed.
//
// Bounded by busctlTimeout: a wedged SSSD/D-Bus must not hang the login —
// a timeout surfaces as an error here, which the caller (decideIPGate) turns
// into a bounded, fail-closed deny.
func busctlClients(user string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), busctlTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "busctl", busctlClientsArgs(user)...).Output()
	if err != nil {
		return nil, fmt.Errorf("busctl GetUserAttr clients failed for %q: %s", user, busctlFailure(ctx, err))
	}
	return parseBusctlClients(out)
}

// busctlFailure describes a failed busctl call so the log can tell an InfoPipe
// outage, an unknown user and a timeout apart: it appends busctl's stderr and
// reports the deadline explicitly instead of "signal: killed".
func busctlFailure(ctx context.Context, err error) string {
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Sprintf("timed out after %s: %v", busctlTimeout, err)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if se := strings.TrimSpace(string(ee.Stderr)); se != "" {
			return fmt.Sprintf("%v: %s", err, se)
		}
	}
	return err.Error()
}

// readClients is the allowlist reader used by the account gate and --check;
// a variable so tests can stand in for the busctl/SSSD call.
var readClients = busctlClients

// newAcctLogger opens the --pam-acct log; a variable so tests can make it fail.
var newAcctLogger = logger.NewLogger

// acctExitInfraFailure is the --pam-acct exit code for "cannot decide" (no
// audit log). The C module's acct_mgmt treats every code other than 0 (allow)
// and 1 (per-user deny) as a helper-infrastructure failure: it logs it at
// LOG_ERR and denies (fail closed). 2 is avoided (Go's panic exit, the auth
// phase's hard deny), as is 127 (execl failed).
const acctExitInfraFailure = 3

// runPamAcct is the entry point for `--pam-acct`: the PAM account-phase hook
// that enforces the directory-provided "clients" IP allowlist. It is
// deliberately conservative: any internal surprise for a non-root user fails
// closed (deny), while root is always exempt and never touches busctl/ifp.
//
// Returns 0 (allow), 1 (per-user deny) or acctExitInfraFailure; never panics
// or calls os.Exit itself, so it stays unit-testable end to end except for the
// busctl subprocess call.
func runPamAcct() int {
	debug := hasFlag(os.Args[1:], "--debug")
	user := os.Getenv("PAM_USER")
	rhost := os.Getenv("PAM_RHOST")
	// Only the two break-glass keys are read, and nothing else of the config
	// is checked: the emergency accounts must not depend on the rest of it.
	bg, bgErr := loadBreakGlass("")
	log, err := newAcctLogger(logFile, debug)
	if err != nil {
		// NewLogger fails when the log cannot be opened (missing directory,
		// immutable file, read-only filesystem, no space to create a missing
		// file), is no regular file (symlink, FIFO, directory) or has mode
		// bits beyond 0640 that cannot be removed (append-only file,
		// filesystem without chmod). An existing log on a full disk opens
		// fine. Either way: no account decision without an audit log. The
		// decision does not use the logger; the reason goes to stderr and
		// syslog. root stays exempt from the account check.
		if !requiresIPGate(user) {
			reportLogFailure(logFailureMessage(err, "root is exempt, allowing"))
			return 0
		}
		// A break-glass account is decided without the audit log as well: a
		// log that cannot be opened must not close the emergency path.
		if bg.Has(user) {
			v := breakGlassVerdict(user, rhost, bg, localAccount, breakGlassSSS)
			if v.allow {
				reportLogFailure(logFailureMessage(err, "break-glass account "+user+" is exempt, allowing"))
				return 0
			}
			reportLogFailure(v.msg)
		}
		reportLogFailure(logFailureMessage(err, "denying"))
		return acctExitInfraFailure
	}
	defer log.Close()

	if bgErr != nil {
		log.Error("pam-acct: break_glass_users not read, no break-glass exemption: %v", bgErr)
	}
	return pamAccount(log, user, rhost, acctInputs{
		read: readClients, bg: bg, local: localAccount, sss: breakGlassSSS, block: breakGlassBlockUsersOnDisk,
		ad: directoryIsAD, state: readAccountState,
	})
}

// pamAccount is the decision logic of runPamAcct with its inputs injected: it
// returns 0 (allow) or 1 (deny). root is exempt before read is ever called; any
// failure to read a directory user's allowlist denies.
func pamAccount(log *logger.Logger, user, rhost string, in acctInputs) int {
	if user == "" {
		log.Error("pam-acct: PAM_USER not set; denying (defensive)")
		return 1
	}

	requiresGate := requiresIPGate(user)
	if !requiresGate {
		log.Info("pam-acct: user=root; exempt, allow (break-glass)")
		return 0
	}

	if in.bg.Has(user) {
		v := breakGlassVerdict(user, rhost, in.bg, in.local, in.sss)
		logVerdict(log, v)
		if v.allow {
			return 0
		}
		return 1
	}

	// The drop-in still holds a break-glass block for this name, but the
	// config no longer lists it: sshd accepted the local key without OIDC. For
	// a local-only name the clients read below would fail and deny anyway; when
	// the directory knows the name it would succeed, and the local key would
	// log in on the allowlist of the directory identity. Deny here until
	// --enable has taken the block out.
	if in.block != nil && slices.Contains(in.block(), user) {
		log.Error("pam-acct: user=%s has a break-glass block in the sshd drop-in but is not in break_glass_users; deny (run 'pam-device-auth --enable')", user)
		return 1
	}

	// The name becomes an argument of busctl; one that looks like an option is
	// no directory user.
	if err := loginNameError(user); err != nil {
		log.Error("pam-acct: refusing user name %q: %v; denying", user, err)
		return 1
	}

	// Active Directory keeps a disabled or expired account in its groups and
	// leaves its key in place, and a key login never binds to the directory:
	// the account state is all that tells such an account from a valid one.
	if in.ad != nil {
		isAD, err := in.ad()
		if err != nil {
			log.Error("pam-acct: user=%s cannot read ldap.profile from the config, fail-closed deny: %v", user, err)
			return 1
		}
		if isAD {
			state, err := in.state(user)
			if err != nil {
				log.Error("pam-acct: user=%s account state read failed, fail-closed deny: %v", user, err)
				return 1
			}
			if why := state.refusal(time.Now()); why != "" {
				log.Warn("pam-acct: user=%s %s; deny", user, why)
				return 1
			}
		}
	}

	clients, readErr := in.read(user)
	if bad := invalidAllowlistEntries(clients); len(bad) > 0 {
		// Ignored by the match, so name them: a typo here silently denies the user.
		log.Warn("pam-acct: user=%s clients allowlist has %d invalid entr(y/ies) that never match: %v", user, len(bad), bad)
	}
	allow := decideIPGate(requiresGate, clients, readErr, rhost)
	switch {
	case readErr != nil:
		log.Error("pam-acct: user=%s clients read failed, fail-closed deny: %v", user, readErr)
	case len(clients) == 0:
		log.Info("pam-acct: user=%s directory user, no clients allowlist set; allow (unrestricted)", user)
	case allow:
		log.Info("pam-acct: user=%s rhost=%s matched clients allowlist; allow", user, rhost)
	default:
		log.Warn("pam-acct: user=%s rhost=%s not in clients allowlist %v; deny", user, rhost, clients)
	}

	if allow {
		return 0
	}
	return 1
}
