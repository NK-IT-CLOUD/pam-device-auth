package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/cache"
)

// requireOutcome fails the test when the login ended differently.
func requireOutcome(t *testing.T, got, want outcome) {
	t.Helper()
	if got != want {
		names := map[outcome]string{denySoft: "denySoft", denyHard: "denyHard", allow: "allow"}
		t.Fatalf("outcome = %s, want %s", names[got], names[want])
	}
}

func requireContains(t *testing.T, what, text string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(text, w) {
			t.Errorf("%s lacks %q; got:\n%s", what, w, text)
		}
	}
}

func TestOutcomeExitCodes(t *testing.T) {
	var zero outcome
	if zero != denySoft {
		t.Fatal("the zero outcome must deny")
	}
	for o, want := range map[outcome]int{allow: 0, denySoft: 1, denyHard: 2, outcome(99): 1} {
		if got := o.exitCode(); got != want {
			t.Errorf("outcome(%d).exitCode() = %d, want %d", o, got, want)
		}
	}
}

func TestFlow_DeviceSuccess(t *testing.T) {
	idp := newFakeIdP(t)
	idp.deviceGrant(idp.ok(t, flowUser, "rt-1"))
	f, out, _ := newFlow(t, idp, "\n")

	requireOutcome(t, f.run(flowUser, flowAddr), allow)

	requireContains(t, "output", out.String(),
		"Link:  https://sso.example.com/device?user_code=ABCD-EFGH",
		"Code:  ABCD-EFGH",
		"FLUSH:Authorize in browser, then press Enter... \n")
	s := cachedSession(t, flowUser)
	if s == nil || s.RefreshToken != "rt-1" || !s.HasIP(flowAddr) {
		t.Fatalf("session cache = %+v, want refresh token rt-1 and address %s", s, flowAddr)
	}
}

func TestFlow_PendingThenSuccess(t *testing.T) {
	idp := newFakeIdP(t)
	idp.deviceGrant(pending(), idp.ok(t, flowUser, "rt-1"))
	f, _, _ := newFlow(t, idp, "\n")

	requireOutcome(t, f.run(flowUser, flowAddr), allow)

	if _, tokenRequests, _ := idp.hits(); tokenRequests != 2 {
		t.Errorf("token requests = %d, want 2", tokenRequests)
	}
}

func TestFlow_AccessDenied(t *testing.T) {
	idp := newFakeIdP(t)
	idp.deviceGrant(oauthError("access_denied"))
	f, out, _ := newFlow(t, idp, "\n")

	requireOutcome(t, f.run(flowUser, flowAddr), denySoft)

	requireContains(t, "output", out.String(), "Authentication failed.")
	if s := cachedSession(t, flowUser); s != nil {
		t.Errorf("a denied login left a session cache: %+v", s)
	}
}

func TestFlow_ExpiredCode(t *testing.T) {
	idp := newFakeIdP(t)
	idp.deviceGrant(oauthError("expired_token"))
	f, _, _ := newFlow(t, idp, "\n")

	requireOutcome(t, f.run(flowUser, flowAddr), denySoft)
}

func TestFlow_Timeout(t *testing.T) {
	idp := newFakeIdP(t) // the grant stays pending
	f, _, logPath := newFlow(t, idp, "\n")

	start := time.Now()
	requireOutcome(t, f.run(flowUser, flowAddr), denySoft)

	if d := time.Since(start); d < 1500*time.Millisecond || d > 5*time.Second {
		t.Errorf("timed out after %s, want about 2 s (auth_timeout)", d)
	}
	requireContains(t, "log", logText(t, logPath), "device authorization timed out")
}

func TestFlow_WrongUser(t *testing.T) {
	idp := newFakeIdP(t)
	idp.deviceGrant(idp.ok(t, "bob", "rt-1"))
	f, _, logPath := newFlow(t, idp, "\n")

	requireOutcome(t, f.run(flowUser, flowAddr), denySoft)

	requireContains(t, "log", logText(t, logPath), "username mismatch")
	if s := cachedSession(t, flowUser); s != nil {
		t.Errorf("a token of another user left a session cache: %+v", s)
	}
}

func TestFlow_MissingRole(t *testing.T) {
	idp := newFakeIdP(t)
	noRole := idp.token(t, flowUser, func(c map[string]any) { delete(c, "realm_access") })
	idp.deviceGrant(tokens(noRole, "rt-1"))
	f, out, _ := newFlow(t, idp, "\n\n")

	requireOutcome(t, f.run(flowUser, flowAddr), denyHard)

	requireContains(t, "output", out.String(),
		"lacks required role 'ssh-access'",
		"FLUSH:Press Enter to disconnect... \n")
	if s := cachedSession(t, flowUser); s != nil {
		t.Errorf("a login without the role left a session cache: %+v", s)
	}
}

func TestFlow_NoDirectoryIdentity(t *testing.T) {
	idp := newFakeIdP(t)
	f, out, _ := newFlow(t, idp, "\n")
	f.nss = func(string) (bool, error) { return false, nil }

	requireOutcome(t, f.run(flowUser, flowAddr), denyHard)

	requireContains(t, "output", out.String(), "no directory identity", "FLUSH:Press Enter to disconnect... \n")
	if deviceRequests, _, _ := idp.hits(); deviceRequests != 0 {
		t.Errorf("device requests = %d, want 0 for a user without a directory identity", deviceRequests)
	}
}

func TestFlow_NSSError(t *testing.T) {
	idp := newFakeIdP(t)
	f, _, logPath := newFlow(t, idp, "\n")
	f.nss = func(string) (bool, error) { return false, errors.New("sssd is down") }

	requireOutcome(t, f.run(flowUser, flowAddr), denyHard)

	requireContains(t, "log", logText(t, logPath), "NSS lookup for alice failed", "sssd is down")
	if deviceRequests, _, _ := idp.hits(); deviceRequests != 0 {
		t.Errorf("device requests = %d, want 0 when the directory lookup fails", deviceRequests)
	}
}

func TestFlow_CachedRefresh(t *testing.T) {
	idp := newFakeIdP(t)
	idp.refreshGrant(idp.ok(t, flowUser, "rt-new"))
	f, out, _ := newFlow(t, idp, "")
	seedCache(t, flowUser, "rt-old", flowAddr)

	requireOutcome(t, f.run(flowUser, flowAddr), allow)

	if out.Len() != 0 {
		t.Errorf("a cached login must print nothing, got:\n%s", out.String())
	}
	if s := cachedSession(t, flowUser); s == nil || s.RefreshToken != "rt-new" {
		t.Errorf("session cache = %+v, want the rotated refresh token rt-new", s)
	}
	if deviceRequests, _, refreshRequests := idp.hits(); deviceRequests != 0 || refreshRequests != 1 {
		t.Errorf("device requests = %d, refresh requests = %d, want 0 and 1", deviceRequests, refreshRequests)
	}
}

func TestFlow_CachedUnknownAddress(t *testing.T) {
	idp := newFakeIdP(t)
	idp.refreshGrant(idp.ok(t, flowUser, "rt-new"))
	idp.deviceGrant(idp.ok(t, flowUser, "rt-device"))
	f, _, _ := newFlow(t, idp, "\n")
	seedCache(t, flowUser, "rt-old", "198.51.100.20")

	requireOutcome(t, f.run(flowUser, flowAddr), allow)

	if deviceRequests, _, refreshRequests := idp.hits(); deviceRequests != 1 || refreshRequests != 0 {
		t.Errorf("device requests = %d, refresh requests = %d, want 1 and 0 from an unknown address", deviceRequests, refreshRequests)
	}
}

func TestFlow_RefreshRejected(t *testing.T) {
	idp := newFakeIdP(t) // every refresh is rejected with invalid_grant
	idp.deviceGrant(idp.ok(t, flowUser, "rt-device"))
	f, out, _ := newFlow(t, idp, "\n")
	seedCache(t, flowUser, "rt-dead", flowAddr)

	requireOutcome(t, f.run(flowUser, flowAddr), allow)

	requireContains(t, "output", out.String(), "FLUSH:Authorize in browser")
	if s := cachedSession(t, flowUser); s == nil || s.RefreshToken != "rt-device" {
		t.Errorf("session cache = %+v, want the refresh token of the device login", s)
	}
}

func TestFlow_RefreshNetworkError(t *testing.T) {
	idp := newFakeIdP(t)
	idp.refreshGrant(tokenStep{status: http.StatusInternalServerError, body: map[string]string{}})
	idp.deviceGrant(oauthError("access_denied"))
	f, _, _ := newFlow(t, idp, "\n")
	seedCache(t, flowUser, "rt-old", flowAddr)

	requireOutcome(t, f.run(flowUser, flowAddr), denySoft)

	if s := cachedSession(t, flowUser); s == nil || s.RefreshToken != "rt-old" {
		t.Errorf("session cache = %+v, want it kept with rt-old after a failed refresh request", s)
	}
}

func TestFlow_RevokedRoleOnKnownAddress(t *testing.T) {
	idp := newFakeIdP(t)
	noRole := idp.token(t, flowUser, func(c map[string]any) { delete(c, "realm_access") })
	idp.refreshGrant(tokens(noRole, "rt-new"))
	f, out, _ := newFlow(t, idp, "\n")
	seedCache(t, flowUser, "rt-old", flowAddr)

	requireOutcome(t, f.run(flowUser, flowAddr), denyHard)

	requireContains(t, "output", out.String(), "lacks required role", "FLUSH:Press Enter to disconnect... \n")
	if s := cachedSession(t, flowUser); s != nil {
		t.Errorf("a revoked role left the session cache: %+v", s)
	}
	if deviceRequests, _, _ := idp.hits(); deviceRequests != 0 {
		t.Errorf("device requests = %d, want 0 after a hard deny", deviceRequests)
	}
}

func TestFlow_CorruptCache(t *testing.T) {
	idp := newFakeIdP(t)
	idp.deviceGrant(idp.ok(t, flowUser, "rt-device"))
	f, _, logPath := newFlow(t, idp, "\n")
	if err := os.MkdirAll(cache.CacheDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache.CacheDir, flowUser+".json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}

	requireOutcome(t, f.run(flowUser, flowAddr), allow)

	requireContains(t, "log", logText(t, logPath), "is corrupt")
	if s := cachedSession(t, flowUser); s == nil || s.RefreshToken != "rt-device" {
		t.Errorf("session cache = %+v, want it rebuilt by the device login", s)
	}
}

// The PAM side is gone (the SSH client disconnected at the prompt): the
// helper must stop instead of polling for a login nobody waits for.
func TestFlow_EOFAtPromptAborts(t *testing.T) {
	for name, stdin := range map[string]string{"EOF": "", "partial line then EOF": "x"} {
		t.Run(name, func(t *testing.T) {
			idp := newFakeIdP(t)
			idp.deviceGrant(idp.ok(t, flowUser, "rt-1")) // an approval that arrives later
			f, _, logPath := newFlow(t, idp, stdin)

			requireOutcome(t, f.run(flowUser, flowAddr), denySoft)

			if _, tokenRequests, _ := idp.hits(); tokenRequests != 0 {
				t.Errorf("token requests = %d, want 0 after the client went away", tokenRequests)
			}
			if s := cachedSession(t, flowUser); s != nil {
				t.Errorf("an abandoned login left a session cache: %+v", s)
			}
			requireContains(t, "log", logText(t, logPath), "went away at the prompt")
		})
	}
}

// A refreshed token that lacks the required authentication level says nothing
// about a revocation: a new device login can reach the level, so the cached
// path hands over to the device flow.
func TestFlow_CachedACRFallsBackToDeviceFlow(t *testing.T) {
	idp := newFakeIdP(t)
	silver := idp.token(t, flowUser, func(c map[string]any) { c["acr"] = "silver" })
	gold := idp.token(t, flowUser, func(c map[string]any) { c["acr"] = "gold" })
	idp.refreshGrant(tokens(silver, "rt-refreshed"))
	idp.deviceGrant(tokens(gold, "rt-device"))
	f, out, logPath := newFlow(t, idp, "\n")
	f.cfg.RequiredACR = []string{"gold"}
	seedCache(t, flowUser, "rt-old", flowAddr)

	requireOutcome(t, f.run(flowUser, flowAddr), allow)

	if deviceRequests, _, refreshRequests := idp.hits(); deviceRequests != 1 || refreshRequests != 1 {
		t.Errorf("device requests = %d, refresh requests = %d, want 1 and 1", deviceRequests, refreshRequests)
	}
	requireContains(t, "output", out.String(), "FLUSH:Authorize in browser")
	if strings.Contains(out.String(), "Access denied") {
		t.Errorf("the user must not see a denial, got:\n%s", out.String())
	}
	requireContains(t, "log", logText(t, logPath), `authentication level "silver" is not accepted`)
	if s := cachedSession(t, flowUser); s == nil || s.RefreshToken != "rt-device" {
		t.Errorf("session cache = %+v, want the refresh token of the device login", s)
	}
}

// On the device path there is nothing left to try: a token without the
// required level is a hard deny, as before.
func TestFlow_DeviceACRMissingIsHardDeny(t *testing.T) {
	idp := newFakeIdP(t)
	idp.deviceGrant(idp.ok(t, flowUser, "rt-1")) // no acr claim
	f, out, _ := newFlow(t, idp, "\n\n")
	f.cfg.RequiredACR = []string{"gold"}

	requireOutcome(t, f.run(flowUser, flowAddr), denyHard)

	requireContains(t, "output", out.String(), "carries no authentication level (acr)")
	if s := cachedSession(t, flowUser); s != nil {
		t.Errorf("a denied login left a session cache: %+v", s)
	}
}

// A login name that looks like an option never reaches a command line.
func TestFlow_DashNameDenied(t *testing.T) {
	idp := newFakeIdP(t)
	f, out, logPath := newFlow(t, idp, "\n")
	nssCalled := false
	f.nss = func(string) (bool, error) { nssCalled = true; return true, nil }

	requireOutcome(t, f.run("-oProxyCommand=x", flowAddr), denyHard)

	if nssCalled {
		t.Error("the directory lookup ran for a name that looks like an option")
	}
	if deviceRequests, _, _ := idp.hits(); deviceRequests != 0 {
		t.Errorf("device requests = %d, want 0", deviceRequests)
	}
	requireContains(t, "output", out.String(), "no directory identity")
	requireContains(t, "log", logText(t, logPath), "refusing login name")
}

// A user name with a dot gets a cached login like any other name.
func TestFlow_DottedUserGetsCache(t *testing.T) {
	const user = "john.doe"
	idp := newFakeIdP(t)
	idp.deviceGrant(idp.ok(t, user, "rt-device"))
	idp.refreshGrant(idp.ok(t, user, "rt-refreshed"))
	f, _, logPath := newFlow(t, idp, "\n")

	requireOutcome(t, f.run(user, flowAddr), allow)
	requireOutcome(t, f.run(user, flowAddr), allow)

	if deviceRequests, _, refreshRequests := idp.hits(); deviceRequests != 1 || refreshRequests != 1 {
		t.Errorf("device requests = %d, refresh requests = %d; want 1 and 1: the second login must use the cache", deviceRequests, refreshRequests)
	}
	if strings.Contains(logText(t, logPath), "session cache") {
		t.Errorf("the log reports a session cache problem:\n%s", logText(t, logPath))
	}
}
