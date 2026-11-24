package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
)

// stubLDAPProfile gives the account phase this ldap.profile, never the config
// of the host the tests run on.
func stubLDAPProfile(t *testing.T, profile string, err error) {
	t.Helper()
	orig := loadLDAPProfile
	t.Cleanup(func() { loadLDAPProfile = orig })
	loadLDAPProfile = func(string) (string, error) { return profile, err }
}

func TestDirectoryIsAD(t *testing.T) {
	for _, c := range []struct {
		profile string
		err     error
		want    bool
	}{
		{"ad", nil, true},
		{"lldap", nil, false},
		{"", nil, false}, // no ldap block
		{"", errors.New("parse config: unexpected end of JSON input"), false},
	} {
		stubLDAPProfile(t, c.profile, c.err)
		if ad, err := directoryIsAD(); ad != c.want || err != c.err {
			t.Errorf("profile %q, %v: got %v, %v", c.profile, c.err, ad, err)
		}
	}
}

func TestParseADAccountState(t *testing.T) {
	for _, c := range []struct {
		name    string
		attrs   map[string][]string
		want    adAccountState
		wantErr string
	}{
		{"enabled, never expires", map[string][]string{"adUserAccountControl": {"66048"}, "adAccountExpires": {"0"}}, adAccountState{66048, 0}, ""},
		{"disabled", map[string][]string{"adUserAccountControl": {"66050"}, "adAccountExpires": {"9223372036854775807"}}, adAccountState{66050, 9223372036854775807}, ""},
		{"no control value", map[string][]string{"adAccountExpires": {"0"}}, adAccountState{}, "returned no adUserAccountControl"},
		{"no expiry value", map[string][]string{"adUserAccountControl": {"512"}}, adAccountState{}, "returned no adAccountExpires"},
		{"nothing", map[string][]string{}, adAccountState{}, "returned no adUserAccountControl"},
		{"two control values", map[string][]string{"adUserAccountControl": {"512", "514"}, "adAccountExpires": {"0"}}, adAccountState{}, "adUserAccountControl has 2 values"},
		{"control is no number", map[string][]string{"adUserAccountControl": {"enabled"}, "adAccountExpires": {"0"}}, adAccountState{}, "adUserAccountControl"},
		{"control is negative", map[string][]string{"adUserAccountControl": {"-2"}, "adAccountExpires": {"0"}}, adAccountState{}, "adUserAccountControl"},
		{"expiry is no number", map[string][]string{"adUserAccountControl": {"512"}, "adAccountExpires": {"never"}}, adAccountState{}, "adAccountExpires"},
	} {
		got, err := parseADAccountState(c.attrs)
		switch {
		case c.wantErr == "" && (err != nil || got != c.want):
			t.Errorf("%s: got %+v, %v; want %+v", c.name, got, err, c.want)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s: err = %v, want one with %q", c.name, err, c.wantErr)
		}
	}
}

// 2026-11-24T08:34:51Z as an AD timestamp (100 ns steps since 1601-01-01).
const adStamp = 134399828910000000

func TestADAccountStateRefusal(t *testing.T) {
	at := time.Date(2026, 11, 24, 8, 34, 51, 0, time.UTC)
	for _, c := range []struct {
		name  string
		state adAccountState
		now   time.Time
		want  string // a part of the reason, "" when the account may log in
	}{
		{"enabled, expiry 0", adAccountState{66048, 0}, at, ""},
		{"enabled, expiry never", adAccountState{512, 9223372036854775807}, at, ""},
		{"disabled", adAccountState{66050, 0}, at, "is disabled in the directory (userAccountControl 66050)"},
		{"disabled and expired names the disabled state", adAccountState{514, adStamp}, at.Add(time.Hour), "is disabled in the directory"},
		{"expires later", adAccountState{512, adStamp}, at.Add(-time.Second), ""},
		{"expires now", adAccountState{512, adStamp}, at, "expired in the directory on 2026-11-24T08:34:51Z"},
		{"expired", adAccountState{512, adStamp}, at.Add(24 * time.Hour), "expired in the directory on 2026-11-24T08:34:51Z"},
		{"expired before 1970", adAccountState{512, 1}, at, "expired in the directory on 1601-01-01T00:00:00Z"},
	} {
		got := c.state.refusal(c.now)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: refusal = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestBusctlUserAttrArgs(t *testing.T) {
	got := strings.Join(busctlUserAttrArgs("alice", adAccountControlAttr, adAccountExpiresAttr), " ")
	want := "--json=short -- call org.freedesktop.sssd.infopipe /org/freedesktop/sssd/infopipe org.freedesktop.sssd.infopipe " +
		"GetUserAttr sas alice 2 adUserAccountControl adAccountExpires"
	if got != want {
		t.Errorf("args = %q, want %q", got, want)
	}
}

func TestParseBusctlAttrs(t *testing.T) {
	got, err := parseBusctlAttrs([]byte(`{"type":"a{sv}","data":[{"clients":{"type":"as","data":["192.0.2.0/24"]},` +
		`"adUserAccountControl":{"type":"as","data":["66048"]},"adAccountExpires":{"type":"as","data":["0"]}}]}`))
	if err != nil || len(got) != 3 || got["adUserAccountControl"][0] != "66048" || got["clients"][0] != "192.0.2.0/24" {
		t.Errorf("got %v, %v", got, err)
	}
	if got, err := parseBusctlAttrs([]byte(`{"type":"a{sv}","data":[{}]}`)); err != nil || len(got) != 0 {
		t.Errorf("empty answer: got %v, %v", got, err)
	}
	for _, bad := range []string{`not json`, `{"type":"s","data":[{}]}`, `{"type":"a{sv}","data":[]}`,
		`{"type":"a{sv}","data":[{"adUserAccountControl":{"type":"s","data":["1"]}}]}`} {
		if _, err := parseBusctlAttrs([]byte(bad)); err == nil {
			t.Errorf("%s: no error", bad)
		}
	}
}

// The account phase looks at the account state only where the config declares
// an Active Directory, and there every doubt denies.
func TestPamAccount_ADAccountState(t *testing.T) {
	enabled := adAccountState{66048, 0}
	never := func(string) ([]string, error) { return nil, nil }
	boom := errors.New("ifp down")
	for _, c := range []struct {
		name      string
		user      string
		ad        bool
		adErr     error
		state     adAccountState
		stateErr  error
		clients   []string
		want      int
		wantState bool
		wantLog   string
	}{
		{"lldap: no state read", "svc", false, nil, adAccountState{}, nil, nil, 0, false, "no clients allowlist set; allow"},
		{"ad, enabled", "svc", true, nil, enabled, nil, nil, 0, true, "no clients allowlist set; allow"},
		{"ad, enabled, allowlist still decides", "svc", true, nil, enabled, nil, []string{"192.0.2.1"}, 1, true, "not in clients allowlist"},
		{"ad, disabled", "svc", true, nil, adAccountState{66050, 0}, nil, nil, 1, true, "WARN  pam-acct: user=svc is disabled in the directory (userAccountControl 66050); deny"},
		{"ad, expired", "svc", true, nil, adAccountState{512, adStamp}, nil, nil, 1, true, "WARN  pam-acct: user=svc expired in the directory on 2026-11-24T08:34:51Z (accountExpires); deny"},
		{"ad, state not readable", "svc", true, nil, adAccountState{}, boom, nil, 1, true, "ERROR pam-acct: user=svc account state read failed, fail-closed deny: ifp down"},
		{"profile not readable", "svc", false, boom, adAccountState{}, nil, nil, 1, false, "ERROR pam-acct: user=svc cannot read ldap.profile from the config, fail-closed deny: ifp down"},
		{"root never reads", "root", true, nil, adAccountState{66050, 0}, nil, nil, 0, false, "user=root; exempt"},
	} {
		t.Run(c.name, func(t *testing.T) {
			log, done := testLog(t)
			stateRead := false
			got := pamAccount(log, c.user, "198.51.100.11", acctInputs{
				read: func(u string) ([]string, error) {
					if c.clients != nil {
						return c.clients, nil
					}
					return never(u)
				},
				ad: func() (bool, error) { return c.ad, c.adErr },
				state: func(string) (adAccountState, error) {
					stateRead = true
					return c.state, c.stateErr
				},
			})
			out := done()
			if got != c.want {
				t.Errorf("pamAccount() = %d, want %d\n%s", got, c.want, out)
			}
			if stateRead != c.wantState {
				t.Errorf("state read = %v, want %v", stateRead, c.wantState)
			}
			if !strings.Contains(out, c.wantLog) {
				t.Errorf("log has no %q:\n%s", c.wantLog, out)
			}
		})
	}
}

func TestAccountStateLines(t *testing.T) {
	at := time.Date(2026, 11, 24, 8, 34, 51, 0, time.UTC)
	states := map[string]adAccountState{"alice": {66048, 0}, "bob": {66050, 0}, "carol": {512, adStamp}}
	read := func(u string) (adAccountState, error) {
		if s, ok := states[u]; ok {
			return s, nil
		}
		return adAccountState{}, errors.New("the InfoPipe returned no adUserAccountControl")
	}
	if got := accountStateLines("g", nil, read, at); got != nil {
		t.Errorf("no members: %v", got)
	}
	got := accountStateLines("ssh-access", []string{"alice"}, read, at)
	if len(got) != 1 || !got[0].ok || got[0].msg != `group "ssh-access": account state read for 1 of 1 member(s), 0 refused at login` {
		t.Errorf("all enabled: %+v", got)
	}
	got = accountStateLines("ssh-service", []string{"alice", "bob", "carol", "dave", "erin"}, read, at.Add(time.Hour))
	want := []checkLine{
		{ok: true, msg: `group "ssh-service": account state read for 3 of 5 member(s), 2 refused at login: ` +
			`bob is disabled in the directory (userAccountControl 66050); carol expired in the directory on 2026-11-24T08:34:51Z (accountExpires)`},
		{msg: `group "ssh-service": 2 member(s) with an UNREADABLE account state; the account phase fails closed and will DENY their login: ` +
			`dave, erin (the InfoPipe returned no adUserAccountControl)`},
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

// A break-glass account is local: its state in the directory is not asked for.
func TestPamAccount_BreakGlassSkipsAccountState(t *testing.T) {
	log, done := testLog(t)
	got := pamAccount(log, "breakglass", "198.51.100.11", acctInputs{
		bg:    config.BreakGlass{Users: []string{"breakglass"}},
		local: lookupYes, sss: lookupNo,
		ad: func() (bool, error) { t.Error("ldap.profile read for a break-glass account"); return true, nil },
		state: func(string) (adAccountState, error) {
			t.Error("state read for a break-glass account")
			return adAccountState{}, nil
		},
	})
	done()
	if got != 0 {
		t.Errorf("pamAccount() = %d, want 0", got)
	}
}
