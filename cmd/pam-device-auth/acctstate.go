package main

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
)

// The account state of an Active Directory user, under the names SSSD's ad
// schema keeps the two attributes in its cache (userAccountControl and
// accountExpires in the directory). SSSD fetches both without a mapping of
// its own. --setup-ldap lists them in [ifp] user_attributes next to clients,
// as sssd-ifp(5) asks for; GetUserAttr of SSSD 2.9 to 2.12 hands out every
// cached attribute without looking at that list.
const (
	adAccountControlAttr = "adUserAccountControl"
	adAccountExpiresAttr = "adAccountExpires"
)

// loadLDAPProfile reads ldap.profile for the account phase; a variable so
// tests can stand in for the config file.
var loadLDAPProfile = config.LoadLDAPProfile

// directoryIsAD reports for the account phase whether config.json declares an
// Active Directory (ldap.profile "ad"). It reads this one key: a mistake
// elsewhere in the config must not decide the logins of key-only accounts.
// The phase does not read sssd.conf for this, a file sshd has no business
// with.
func directoryIsAD() (bool, error) {
	profile, err := loadLDAPProfile("")
	return profile == config.LDAPProfileAD, err
}

// adAccountState is the account state of an Active Directory user.
type adAccountState struct {
	control uint32 // userAccountControl
	expires uint64 // accountExpires: 100 ns steps since 1601-01-01 UTC
}

// userAccountControl bit ACCOUNTDISABLE, and the two accountExpires values
// that stand for "never".
const (
	adAccountDisabled   = 0x2
	adNeverExpires      = 0x7FFFFFFFFFFFFFFF
	adEpochToUnixSecond = 11644473600 // seconds from 1601-01-01 to 1970-01-01
)

// parseADAccountState reads the state from the attributes the InfoPipe
// returned. A missing or malformed value is an error, which the account phase
// turns into a deny: SSSD's own check of these attributes grants access when
// one is missing (sssd-ldap(5), ldap_account_expire_policy = ad).
func parseADAccountState(attrs map[string][]string) (adAccountState, error) {
	one := func(name string, bits int) (uint64, error) {
		vals, ok := attrs[name]
		if !ok {
			return 0, fmt.Errorf("the InfoPipe returned no %s: SSSD has no such value for the user "+
				"(the bind account must be able to read userAccountControl and accountExpires)", name)
		}
		if len(vals) != 1 {
			return 0, fmt.Errorf("%s has %d values, expected one", name, len(vals))
		}
		n, err := strconv.ParseUint(vals[0], 10, bits)
		if err != nil {
			return 0, fmt.Errorf("%s %q is no unsigned %d-bit number", name, vals[0], bits)
		}
		return n, nil
	}
	control, err := one(adAccountControlAttr, 32)
	if err != nil {
		return adAccountState{}, err
	}
	// accountExpires is a signed 64-bit value in the directory.
	expires, err := one(adAccountExpiresAttr, 63)
	if err != nil {
		return adAccountState{}, err
	}
	return adAccountState{control: uint32(control), expires: expires}, nil
}

// expiry returns the time the account expires; ok is false when it never does.
func (s adAccountState) expiry() (at time.Time, ok bool) {
	if s.expires == 0 || s.expires == adNeverExpires {
		return time.Time{}, false
	}
	return time.Unix(int64(s.expires/1e7)-adEpochToUnixSecond, int64(s.expires%1e7)*100).UTC(), true
}

// refusal says why the account must not log in at now: it is disabled, or its
// expiry time has come. "" means the state allows the login.
func (s adAccountState) refusal(now time.Time) string {
	if s.control&adAccountDisabled != 0 {
		return fmt.Sprintf("is disabled in the directory (userAccountControl %d)", s.control)
	}
	if at, ok := s.expiry(); ok && !now.Before(at) {
		return fmt.Sprintf("expired in the directory on %s (accountExpires)", at.Format(time.RFC3339))
	}
	return ""
}

// accountStateLines returns the --check lines on the account state of the
// members of group: how many were read and who is refused at login, and a
// warning for the members whose state cannot be read (with the first reason),
// as the account phase denies them.
func accountStateLines(group string, members []string, read func(string) (adAccountState, error), now time.Time) []checkLine {
	if len(members) == 0 {
		return nil
	}
	var refused, unreadable []string
	var firstErr error
	for _, m := range members {
		state, err := read(m)
		if err != nil {
			unreadable = append(unreadable, m)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if why := state.refusal(now); why != "" {
			refused = append(refused, m+" "+why)
		}
	}
	msg := fmt.Sprintf("group %q: account state read for %d of %d member(s), %d refused at login",
		group, len(members)-len(unreadable), len(members), len(refused))
	if len(refused) > 0 {
		msg += ": " + strings.Join(refused, "; ")
	}
	lines := []checkLine{{ok: true, msg: msg}}
	if len(unreadable) > 0 {
		lines = append(lines, checkLine{msg: fmt.Sprintf(
			"group %q: %d member(s) with an UNREADABLE account state; the account phase fails closed and will DENY their login: %s (%v)",
			group, len(unreadable), strings.Join(unreadable, ", "), firstErr)})
	}
	return lines
}

// busctlAccountState reads the account state of a directory user through the
// SSSD InfoPipe, like busctlClients reads the allowlist and under the same
// timeout. Callers must only invoke it for a name that passed loginNameError.
func busctlAccountState(user string) (adAccountState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), busctlTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "busctl", busctlUserAttrArgs(user, adAccountControlAttr, adAccountExpiresAttr)...).Output()
	if err != nil {
		return adAccountState{}, fmt.Errorf("busctl GetUserAttr failed for %q: %s", user, busctlFailure(ctx, err))
	}
	attrs, err := parseBusctlAttrs(out)
	if err != nil {
		return adAccountState{}, err
	}
	return parseADAccountState(attrs)
}

// readAccountState is the account state reader of the account phase and of
// --check; a variable so tests can stand in for the busctl/SSSD call.
var readAccountState = busctlAccountState
