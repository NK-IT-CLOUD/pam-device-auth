//go:build login

// Login tests drive real SSH logins against a host that runs pam-device-auth in
// directory mode and has a fixed set of directory test users (see CONTRIBUTING.md,
// "Login tests"). They check the outcome of every login and, when root access to
// the host is configured, the reason the host logged for a refusal. Environment:
//
//	PDA_LOGIN_HOST         host to log in to (the tests skip when unset)
//	PDA_LOGIN_KEYDIR       directory with one private key per test user, named like the user
//	PDA_LOGIN_ROOT         optional ssh target with root access (user@host) to read the host's logs
//	PDA_LOGIN_KNOWN_HOSTS  optional pinned known_hosts file; without it host keys are accepted on first use
//
// Build and run: go test -tags login -run Login ./cmd/pam-device-auth
package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type loginEnv struct{ host, keyDir, root, knownHosts string }

func loginSetup(t *testing.T) loginEnv {
	t.Helper()
	e := loginEnv{
		host:       os.Getenv("PDA_LOGIN_HOST"),
		keyDir:     os.Getenv("PDA_LOGIN_KEYDIR"),
		root:       os.Getenv("PDA_LOGIN_ROOT"),
		knownHosts: os.Getenv("PDA_LOGIN_KNOWN_HOSTS"),
	}
	if e.host == "" {
		t.Skip("PDA_LOGIN_HOST is not set")
	}
	if e.keyDir == "" {
		t.Fatal("PDA_LOGIN_KEYDIR is not set")
	}
	return e
}

func (e loginEnv) hostKeyArgs() []string {
	if e.knownHosts != "" {
		return []string{"-o", "UserKnownHostsFile=" + e.knownHosts, "-o", "StrictHostKeyChecking=yes"}
	}
	return []string{"-o", "StrictHostKeyChecking=accept-new"}
}

// sshCommand is the ssh client call every login test uses: only the given key,
// the pinned or first-use host key, no stdin.
func (e loginEnv) sshCommand(ctx context.Context, env []string, args ...string) *exec.Cmd {
	full := append(append([]string{"-o", "ConnectTimeout=10", "-o", "IdentitiesOnly=yes"}, e.hostKeyArgs()...), args...)
	cmd := exec.CommandContext(ctx, "ssh", full...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = nil
	return cmd
}

// ssh runs ssh with the given arguments and returns the combined output and the
// exit code (-1 when the command did not finish within the timeout).
func (e loginEnv) ssh(t *testing.T, timeout time.Duration, env []string, args ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := e.sshCommand(ctx, env, args...)
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	switch {
	case ctx.Err() != nil:
		code = -1
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case err != nil:
		t.Fatalf("ssh: %v", err)
	}
	return string(out), code
}

// login performs a non-interactive key login as user with the key of keyOwner
// and runs remote on the host.
func (e loginEnv) login(t *testing.T, user, keyOwner, remote string) (string, int) {
	t.Helper()
	key := filepath.Join(e.keyDir, keyOwner)
	if _, err := os.Stat(key); err != nil {
		t.Fatalf("missing test key %s: %v", key, err)
	}
	return e.ssh(t, 30*time.Second, nil, "-o", "BatchMode=yes", "-i", key, user+"@"+e.host, remote)
}

// hostNow returns the host's clock in epoch seconds, or 0 without root access.
func (e loginEnv) hostNow(t *testing.T) int64 {
	if e.root == "" {
		return 0
	}
	out, code := e.ssh(t, 20*time.Second, nil, "-o", "BatchMode=yes", e.root, "date +%s")
	if code != 0 {
		t.Fatalf("root access to the host failed: %s", out)
	}
	// An ssh client newer than the host's sshd can print warnings (for example
	// about the key exchange) before the output: the clock is the last line.
	lines := strings.Split(strings.TrimSpace(out), "\n")
	n, err := strconv.ParseInt(strings.TrimSpace(lines[len(lines)-1]), 10, 64)
	if err != nil {
		t.Fatalf("host clock: %q", out)
	}
	return n
}

// hostLog returns what sshd, PAM and pam-device-auth logged since the epoch second since.
func (e loginEnv) hostLog(t *testing.T, since int64) string {
	t.Helper()
	cmd := "journalctl --no-pager --since @" + strconv.FormatInt(since, 10) + " -t sshd -t sshd-session 2>/dev/null; tail -n 200 /var/log/pam-device-auth.log"
	out, code := e.ssh(t, 30*time.Second, nil, "-o", "BatchMode=yes", e.root, cmd)
	if code != 0 {
		t.Fatalf("reading the host log failed: %s", out)
	}
	return out
}

// Logins that must work.
func TestLoginAllowed(t *testing.T) {
	e := loginSetup(t)
	cases := []struct {
		name, user, remote, want string
		wantCode                 int
	}{
		{"key-only service account", "ci-svc-ok", "id -un", "ci-svc-ok", 0},
		{"service account is not a sudoer", "ci-svc-ok", "sudo -n true", "", 1},
		{"service account in the NOPASSWD group", "ci-svc-sudo", "sudo -n true && echo sudo-ok", "sudo-ok", 0},
		{"source IP matches the allowlist", "ci-svc-ipallow", "id -un", "ci-svc-ipallow", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, code := e.login(t, c.user, c.user, c.remote)
			if code != c.wantCode || !strings.Contains(out, c.want) {
				t.Fatalf("%s: exit %d, output %q; want exit %d containing %q", c.user, code, out, c.wantCode, c.want)
			}
		})
	}
}

// Logins that must be refused, each for a specific reason the host logs.
func TestLoginRefused(t *testing.T) {
	e := loginSetup(t)
	cases := []struct {
		name, user, keyOwner string
		reason               []string // all must appear in the host log
	}{
		{"source IP not in the allowlist", "ci-svc-ipdeny", "ci-svc-ipdeny",
			[]string{"user=ci-svc-ipdeny", "not in clients allowlist", "Account check denied for user ci-svc-ipdeny"}},
		{"user in no access group", "ci-nogroup", "ci-nogroup",
			[]string{"pam_sss(sshd:account): Access denied for user ci-nogroup"}},
		{"service account without an SSH key", "ci-nokey", "ci-svc-ok",
			[]string{"Failed publickey for ci-nokey"}},
		{"service account with an unparseable SSH key", "ci-badkey", "ci-svc-ok",
			[]string{"Failed publickey for ci-badkey"}},
		{"valid user with someone else's key", "ci-svc-ok", "ci-svc-sudo",
			[]string{"Failed publickey for ci-svc-ok"}},
		{"user that does not exist", "ci-no-such-user", "ci-svc-ok",
			[]string{"ci-no-such-user"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			since := e.hostNow(t)
			out, code := e.login(t, c.user, c.keyOwner, "id -un")
			if code == 0 {
				t.Fatalf("%s was let in: %q", c.user, out)
			}
			if e.root == "" {
				t.Log("PDA_LOGIN_ROOT not set: refusal reason not checked")
				return
			}
			log := e.hostLog(t, since)
			if strings.Contains(log, "Accepted publickey for "+c.user+" ") || strings.Contains(log, "Accepted keyboard-interactive/pam for "+c.user+" ") {
				t.Errorf("the host logged an accepted login for %s:\n%s", c.user, log)
			}
			for _, want := range c.reason {
				if !strings.Contains(log, want) {
					t.Errorf("host log lacks %q for %s:\n%s", want, c.user, log)
				}
			}
		})
	}
}

// A user of the OIDC tier passes the key factor and is then asked to approve the
// login in a browser. The test cannot approve it; reaching the prompt proves that
// layer 1 accepted the key and layer 2 started the device flow.
func TestLoginOIDCTierStartsDeviceFlow(t *testing.T) {
	e := loginSetup(t)
	dir := t.TempDir()
	logFile := filepath.Join(dir, "prompts")
	askpass := filepath.Join(dir, "askpass.sh")
	script := "#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$ASKPASS_LOG\"\nexit 1\n"
	if err := os.WriteFile(askpass, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	env := []string{"SSH_ASKPASS=" + askpass, "SSH_ASKPASS_REQUIRE=force", "ASKPASS_LOG=" + logFile}
	key := filepath.Join(e.keyDir, "ci-oidc")
	// The login cannot finish; the timeout ends it after the prompt was shown.
	e.ssh(t, 20*time.Second, env, "-o", "NumberOfPasswordPrompts=1", "-i", key, "ci-oidc@"+e.host, "true")
	prompts, _ := os.ReadFile(logFile)
	if !strings.Contains(string(prompts), "Authorize in browser") {
		t.Fatalf("no device-flow prompt after the key was accepted; prompts seen: %q", prompts)
	}
}

// helperPIDs returns the PIDs of the pam-device-auth helpers that run on the host.
func (e loginEnv) helperPIDs(t *testing.T) []string {
	t.Helper()
	out, code := e.ssh(t, 20*time.Second, nil, "-o", "BatchMode=yes", e.root, "pgrep -x pam-device-auth; true")
	if code != 0 {
		t.Fatalf("listing the helper processes failed: %s", out)
	}
	var pids []string
	for _, f := range strings.Fields(out) {
		if _, err := strconv.Atoi(f); err == nil {
			pids = append(pids, f)
		}
	}
	return pids
}

// processAlive reports whether pid still exists on the host.
func (e loginEnv) processAlive(t *testing.T, pid string) bool {
	t.Helper()
	out, code := e.ssh(t, 20*time.Second, nil, "-o", "BatchMode=yes", e.root, "test -d /proc/"+pid+" && echo alive || echo gone")
	if code != 0 {
		t.Fatalf("checking process %s failed: %s", pid, out)
	}
	return strings.Contains(out, "alive")
}

// The client disconnects at the device-flow prompt without answering it. sshd
// then ends its PAM process; the helper must end with it instead of polling
// the identity provider as an orphan until its own timeout.
func TestLoginDisconnectAtPromptLeavesNoHelper(t *testing.T) {
	e := loginSetup(t)
	if e.root == "" {
		t.Skip("PDA_LOGIN_ROOT is not set: the host's processes cannot be checked")
	}
	dir := t.TempDir()
	logFile := filepath.Join(dir, "prompts")
	askpass := filepath.Join(dir, "askpass.sh")
	// Logs the prompt and never answers it.
	script := "#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$ASKPASS_LOG\"\nexec sleep 30\n"
	if err := os.WriteFile(askpass, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	env := []string{"SSH_ASKPASS=" + askpass, "SSH_ASKPASS_REQUIRE=force", "ASKPASS_LOG=" + logFile}
	key := filepath.Join(e.keyDir, "ci-oidc")

	before := map[string]bool{}
	for _, pid := range e.helperPIDs(t) {
		before[pid] = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client := e.sshCommand(ctx, env, "-o", "NumberOfPasswordPrompts=1", "-i", key, "ci-oidc@"+e.host, "true")
	if err := client.Start(); err != nil {
		t.Fatalf("ssh: %v", err)
	}
	disconnected := false
	disconnect := func() {
		if !disconnected {
			disconnected = true
			client.Process.Kill()
			client.Wait()
		}
	}
	defer disconnect()

	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		if prompts, _ := os.ReadFile(logFile); strings.Contains(string(prompts), "Authorize in browser") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no device-flow prompt within 20 s")
		}
	}
	var started []string
	for _, pid := range e.helperPIDs(t) {
		if !before[pid] {
			started = append(started, pid)
		}
	}
	if len(started) != 1 {
		t.Fatalf("expected one new helper for this login, found %v", started)
	}

	disconnect()

	for deadline := time.Now().Add(5 * time.Second); e.processAlive(t, started[0]); time.Sleep(500 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("helper %s still runs 5 s after the client disconnected at the prompt", started[0])
		}
	}
}
