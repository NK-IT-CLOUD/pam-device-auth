package main

import (
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
//   - has clients:    {"type":"a{sv}","data":[{"clients":{"type":"as","data":["10.0.99.203",...]}}]}
//   - no clients attr: {"type":"a{sv}","data":[{}]}
//
// The second shape is NOT an error — it means the directory user has no
// "clients" attribute set, i.e. unrestricted. Returns (nil, nil) for it.
func parseBusctlClients(jsonOut []byte) ([]string, error) {
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
	attr, ok := resp.Data[0]["clients"]
	if !ok {
		return nil, nil
	}
	if attr.Type != "as" {
		return nil, fmt.Errorf("unexpected clients attribute type %q", attr.Type)
	}
	return attr.Data, nil
}

// requiresIPGate keeps the break-glass boundary deliberately narrow: only
// root is exempt. Treating every name found in /etc/passwd as local/exempt is
// unsafe because a same-named SSSD identity can still supply the SSH key and
// groups while the local passwd entry shadows identity lookup. Non-root local
// accounts are not a supported login tier (AuthorizedKeysFile is disabled for
// them), so an attempted account check for one safely fails closed in busctl.
func requiresIPGate(user string) bool {
	return user != "root"
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
// deliberately conservative: any internal surprise for a non-root user fails
// closed (deny), while root is always exempt and never touches busctl/ifp.
//
// Returns 0 (allow) or 1 (deny); never panics or calls os.Exit itself, so it
// stays unit-testable end to end except for the busctl subprocess call.
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

	requiresGate := requiresIPGate(user)
	if !requiresGate {
		log.Info("pam-acct: user=root; exempt, allow (break-glass)")
		return 0
	}

	clients, readErr := busctlClients(user)
	if readErr != nil {
		log.Error("pam-acct: user=%s clients read failed, fail-closed deny: %v", user, readErr)
		return 1
	}

	allow := decideIPGate(requiresGate, clients, readErr, rhost)
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
