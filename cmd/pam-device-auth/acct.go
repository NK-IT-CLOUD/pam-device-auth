package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/logger"
)

// busctlTimeout bounds the busctl/D-Bus round-trip so a wedged SSSD cannot
// hang the login. Errors from a timeout are treated identically to any other
// read failure: fail-closed deny (see decideIPGate).
const busctlTimeout = 5 * time.Second

// decideIPGate is the pure IP-allowlist decision. It never touches the
// network, SSSD, or busctl — every input is already resolved by the caller.
//
//   - !isDirUser        -> allow (break-glass: root/local accounts are exempt,
//     they never had a "clients" attribute in the first place)
//   - readErr != nil     -> deny (fail-closed: we know the user IS a directory
//     user but could not read their allowlist — never fail open on a read error)
//   - len(clients) == 0  -> allow (directory user with no "clients" attribute
//     set is unrestricted by design)
//   - otherwise          -> allow iff rhost matches one of clients
//     (matchesAllowedIP also denies on an empty/unparseable rhost, which
//     covers "PAM_RHOST unset for a directory user with clients" -> deny)
func decideIPGate(isDirUser bool, clients []string, readErr error, rhost string) bool {
	switch {
	case !isDirUser:
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
//   - has clients:    {"type":"a{sv}","data":[{"clients":{"type":"as","data":["10.0.99.203",...]}}]}
//   - no clients attr: {"type":"a{sv}","data":[{}]}
//
// The second shape is NOT an error — it means the directory user has no
// "clients" attribute set, i.e. unrestricted. Returns (nil, nil) for it.
func parseBusctlClients(jsonOut []byte) ([]string, error) {
	var resp struct {
		Data []map[string]struct {
			Data []string `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(jsonOut, &resp); err != nil {
		return nil, fmt.Errorf("parse busctl GetUserAttr output: %w", err)
	}
	if len(resp.Data) == 0 {
		return nil, nil
	}
	attr, ok := resp.Data[0]["clients"]
	if !ok {
		return nil, nil
	}
	return attr.Data, nil
}

// isLocalUser is a pure parser: it reports whether user appears as the first
// (name) field of any line in the content of /etc/passwd. /etc/passwd is the
// "files" NSS source and is authoritative for local accounts independent of
// SSSD — root is always present here, which is what makes root break-glass
// bulletproof even when SSSD/D-Bus is completely down.
//
// This deliberately does NOT shell out to `getent -s sss ...`: that command
// returns exit 2 ("not found") for every user, directory or local, whenever
// SSSD is down, which would misclassify real directory users as exempt and
// silently bypass the IP gate. Reading /etc/passwd directly has no such
// failure mode.
func isLocalUser(passwd []byte, user string) bool {
	for _, line := range bytes.Split(passwd, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		fields := bytes.SplitN(line, []byte(":"), 2)
		if len(fields) < 2 || len(fields[0]) == 0 {
			continue
		}
		if string(fields[0]) == user {
			return true
		}
	}
	return false
}

// isDirectoryUser reports whether user is subject to the IP allowlist gate
// (i.e. NOT a local/root/break-glass account). root is exempted before any
// file access, as belt-and-suspenders defense in depth matching the C PAM
// module. For every other user, presence in /etc/passwd means local (exempt);
// absence means the account resolved via SSSD at login time, so it is a
// directory user and the gate applies.
//
// If /etc/passwd itself cannot be read (should never happen), that is a
// broken system, not a reason to grant break-glass to an unconfirmed user:
// callers MUST treat a non-nil error here as fail-closed deny.
func isDirectoryUser(user string) (bool, error) {
	if user == "root" {
		return false, nil
	}
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return true, fmt.Errorf("read /etc/passwd: %w", err)
	}
	return !isLocalUser(data, user), nil
}

// busctlClients reads the "clients" IP allowlist attribute for a directory
// user via sssd-infopipe over D-Bus. Callers MUST only invoke this for a user
// already confirmed by isDirectoryUser — for such a user, any non-zero exit
// here is a genuine read failure (ifp down, D-Bus unavailable, etc.), not an
// "unknown user" signal, and must be treated as fail-closed by the caller.
//
// Bounded by busctlTimeout: a wedged SSSD/D-Bus must not hang the login —
// a timeout surfaces as an error here, which the caller (decideIPGate) turns
// into a bounded, fail-closed deny.
func busctlClients(user string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), busctlTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "busctl", "--json=short", "call",
		"org.freedesktop.sssd.infopipe",
		"/org/freedesktop/sssd/infopipe",
		"org.freedesktop.sssd.infopipe",
		"GetUserAttr", "sas", user, "1", "clients",
	).Output()
	if err != nil {
		return nil, fmt.Errorf("busctl GetUserAttr clients failed for %q: %w", user, err)
	}
	return parseBusctlClients(out)
}

// runPamAcct is the entry point for `--pam-acct`: the PAM account-phase hook
// that enforces the directory-provided "clients" IP allowlist. It is
// deliberately conservative: any internal surprise for a directory user
// fails closed (deny), while non-directory users (root, local, break-glass)
// are always exempt and never touch busctl/ifp at all.
//
// Returns 0 (allow) or 1 (deny); never panics or calls os.Exit itself, so it
// stays unit-testable end to end except for the /etc/passwd read and busctl
// subprocess call.
func runPamAcct() int {
	debug := hasFlag(os.Args[1:], "--debug")
	log, err := logger.NewLogger(logFile, debug)
	if err != nil {
		// Logging infrastructure must never gate the security decision itself;
		// fall back to a stderr-only logger (NewLogger("", ...) never fails).
		log, _ = logger.NewLogger("", debug)
	}
	defer log.Close()

	user := os.Getenv("PAM_USER")
	rhost := os.Getenv("PAM_RHOST")

	if user == "" {
		log.Error("pam-acct: PAM_USER not set; denying (defensive)")
		return 1
	}

	dirUser, luErr := isDirectoryUser(user)
	if luErr != nil {
		log.Error("pam-acct: user=%s local/directory check failed (could not read /etc/passwd), fail-closed deny: %v", user, luErr)
		return 1
	}
	if !dirUser {
		log.Info("pam-acct: user=%s local/root user; exempt, allow (break-glass)", user)
		return 0
	}

	clients, readErr := busctlClients(user)
	if readErr != nil {
		log.Error("pam-acct: user=%s clients read failed, fail-closed deny: %v", user, readErr)
		return 1
	}

	allow := decideIPGate(dirUser, clients, readErr, rhost)
	switch {
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
