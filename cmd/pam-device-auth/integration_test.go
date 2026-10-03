//go:build integration

// Integration tests run on a real host (as root, with the package installed and,
// for most of them, set up in directory mode). CI builds them with
//
//	go test -c -tags integration -o pda-integration.test ./cmd/pam-device-auth
//
// copies the binary to every test host after the deploy and runs it there. They
// read users and groups from the host's own config, so nothing site specific is
// hardcoded. A host that is not set up skips the directory tests; the version
// test runs everywhere.
package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
)

const installedBin = "/usr/local/bin/pam-device-auth"

// runInstalled runs the installed binary with extra environment variables and
// returns its combined output and exit code.
func runInstalled(t *testing.T, env []string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(installedBin, args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run %s %v: %v", installedBin, args, err)
	}
	return string(out), code
}

// configuredHost returns the host config, or skips when the host is not set up
// in directory mode.
func configuredHost(t *testing.T) *config.Config {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("integration tests need root")
	}
	if _, err := os.Stat(installedBin); err != nil {
		t.Skip("pam-device-auth is not installed on this host")
	}
	cfg, err := config.Load("")
	if err != nil || strings.Contains(cfg.IssuerURL, "example.com") || cfg.LDAP == nil {
		t.Skip("host runs the default config (not set up)")
	}
	if !fileExists("/etc/sssd/sssd.conf") {
		t.Skip("directory mode is not set up (no sssd.conf)")
	}
	return cfg
}

func accessMembers(t *testing.T, cfg *config.Config) []string {
	t.Helper()
	members, err := getentGroup(cfg.LDAP.AccessGroup)
	if err != nil || len(members) == 0 {
		t.Skipf("access group %q has no resolvable members here: %v", cfg.LDAP.AccessGroup, err)
	}
	return members
}

// Runs on every host: the deploy really replaced the installed binary.
func TestIntegrationInstalledVersion(t *testing.T) {
	if _, err := os.Stat(installedBin); err != nil {
		t.Fatalf("%s is missing after the deploy: %v", installedBin, err)
	}
	out, code := runInstalled(t, nil, "--version")
	if code != 0 || !strings.Contains(out, VERSION) {
		t.Fatalf("installed binary reports %q (exit %d), the build under test is %s", strings.TrimSpace(out), code, VERSION)
	}
}

func TestIntegrationCheckPasses(t *testing.T) {
	configuredHost(t)
	out, code := runInstalled(t, nil, "--check")
	// "Critical checks passed; N warning(s)" is the summary when only warnings
	// remain; the warning loop below decides whether they are expected.
	if code != 0 || !(strings.Contains(out, "All checks passed") || strings.Contains(out, "Critical checks passed")) {
		t.Fatalf("--check exit %d:\n%s", code, out)
	}
	if strings.Contains(out, "[FAIL]") {
		t.Errorf("--check output contains [FAIL]:\n%s", out)
	}
	// A host that deliberately holds broken test users (the login test host) lists
	// substrings of the warnings it expects, one per line, in this file.
	var allowed []string
	if data, err := os.ReadFile("/etc/pam-device-auth/ci-known-warnings"); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				allowed = append(allowed, l)
			}
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "[WARN]") || strings.HasPrefix(strings.TrimSpace(line), "Critical checks passed") {
			continue
		}
		known := false
		for _, a := range allowed {
			if strings.Contains(line, a) {
				known = true
			}
		}
		if !known {
			t.Errorf("unexpected --check warning: %s", strings.TrimSpace(line))
		}
	}
}

// Directory mode leaves no SSSD unit failed: the socket units of the responders
// from the services line are masked, and nothing is left in a failed state.
func TestIntegrationNoFailedSSSDUnits(t *testing.T) {
	configuredHost(t)
	conf, err := os.ReadFile("/etc/sssd/sssd.conf")
	if err != nil {
		t.Fatal(err)
	}
	if socks := conflictingSSSDSockets(string(conf)); len(socks) > 0 {
		t.Errorf("socket units compete with responders from the services line: %v", socks)
	}
	out, err := exec.Command("systemctl", "list-units", "--failed", "--no-legend", "--plain", "sssd*").CombinedOutput()
	if err != nil {
		t.Fatalf("systemctl list-units --failed: %s: %v", out, err)
	}
	if failed := strings.TrimSpace(string(out)); failed != "" {
		t.Errorf("failed SSSD units:\n%s", failed)
	}
}

func TestIntegrationNSSLookup(t *testing.T) {
	cfg := configuredHost(t)
	member := accessMembers(t, cfg)[0]
	found, err := nssLookup(member)
	if err != nil || !found {
		t.Fatalf("nssLookup(%q) = %v, %v; want found", member, found, err)
	}
	// A name that does not exist is "not found", never an SSSD error.
	found, err = nssLookup("no-such-user-pda-integration")
	if err != nil || found {
		t.Fatalf("nssLookup(unknown) = %v, %v; want not found without an error", found, err)
	}
	// A local-only account must not satisfy the directory gate.
	if found, _ := nssLookup("root"); found {
		t.Error("root resolved through sss; the directory gate would accept a local account")
	}
}

// The account-phase gate fails closed on a read error, so every access-group
// member's allowlist must be readable through the InfoPipe.
func TestIntegrationInfoPipeReadsClients(t *testing.T) {
	cfg := configuredHost(t)
	for _, m := range accessMembers(t, cfg) {
		if _, err := readClients(m); err != nil {
			t.Errorf("readClients(%q): %v", m, err)
		}
	}
}

func TestIntegrationPamAcct(t *testing.T) {
	cfg := configuredHost(t)
	const rhost = "192.0.2.1" // documentation range
	cases := []struct {
		name string
		env  []string
		want int
	}{
		{"root is exempt", []string{"PAM_USER=root", "PAM_RHOST=" + rhost}, 0},
		{"PAM_USER unset denies", []string{"PAM_USER="}, 1},
		{"unknown user fails closed", []string{"PAM_USER=no-such-user-pda-integration", "PAM_RHOST=" + rhost}, 1},
	}
	// A real member: the binary must agree with the pure decision on the member's
	// actual allowlist.
	m := accessMembers(t, cfg)[0]
	clients, rerr := readClients(m)
	want := 1
	if decideIPGate(true, clients, rerr, rhost) {
		want = 0
	}
	cases = append(cases, struct {
		name string
		env  []string
		want int
	}{"member " + "follows its allowlist", []string{"PAM_USER=" + m, "PAM_RHOST=" + rhost}, want})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, code := runInstalled(t, c.env, "--pam-acct")
			if code != c.want {
				t.Errorf("--pam-acct exit %d, want %d:\n%s", code, c.want, out)
			}
		})
	}
}

func TestIntegrationSSHDPolicy(t *testing.T) {
	cfg := configuredHost(t)
	if !isEnabled() {
		t.Skip("pam-device-auth is not enabled on this host")
	}
	am, ok := sshdParam("authenticationmethods", "")
	if !ok {
		t.Fatal("sshd -T could not be evaluated")
	}
	if am != "publickey,keyboard-interactive:pam" {
		t.Errorf("non-root AuthenticationMethods = %q, want exactly publickey,keyboard-interactive:pam", am)
	}
	if cfg.RootLoginIsDisabled() {
		if permit, _ := sshdParam("permitrootlogin", "root"); permit != "no" {
			t.Errorf("root_login is disabled but PermitRootLogin = %q, want no", permit)
		}
	} else {
		if rootAm, _ := sshdParam("authenticationmethods", "root"); rootAm != "publickey" {
			t.Errorf("root AuthenticationMethods = %q, want publickey only (break-glass)", rootAm)
		}
		if permit, _ := sshdParam("permitrootlogin", "root"); permit == "no" {
			t.Errorf("PermitRootLogin = no although root_login is key; the emergency path is gone")
		}
	}
	if akf, _ := sshdParam("authorizedkeysfile", "nobody"); akf != "none" {
		t.Errorf("non-root AuthorizedKeysFile = %q, want none", akf)
	}
	akc, _ := sshdParam("authorizedkeyscommand", "")
	if fields := strings.Fields(akc); len(fields) == 0 || !fileExists(fields[0]) {
		t.Errorf("AuthorizedKeysCommand %q does not exist", akc)
	}
}

func TestIntegrationPAMStack(t *testing.T) {
	configuredHost(t)
	if !isEnabled() {
		t.Skip("pam-device-auth is not enabled on this host")
	}
	data, err := os.ReadFile("/etc/pam.d/sshd")
	if err != nil {
		t.Fatal(err)
	}
	var auth, account int
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !strings.Contains(line, "pam_device_auth.so") || strings.HasPrefix(f[0], "#") {
			continue
		}
		switch f[0] {
		case "auth":
			auth++
		case "account":
			account++
		}
	}
	if auth != 1 || account != 1 {
		t.Errorf("pam_device_auth.so appears in %d auth and %d account lines, want 1 each", auth, account)
	}
	if orig, err := os.ReadFile("/etc/pam.d/sshd.original"); err != nil {
		t.Errorf("rollback copy /etc/pam.d/sshd.original missing: %v", err)
	} else if strings.Contains(string(orig), "pam_device_auth.so") {
		t.Error("/etc/pam.d/sshd.original already contains pam_device_auth.so; it is not a pristine original")
	}
}

// After at least one login the OIDC metadata cache exists; whatever is there
// must be root-only.
func TestIntegrationOIDCCacheModes(t *testing.T) {
	configuredHost(t)
	dir := "/run/pam-device-auth/oidc"
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Skip("no OIDC cache yet (no login since boot)")
	}
	st := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || fi.Mode().Perm() != 0700 || st.Uid != 0 {
		t.Errorf("%s: dir=%v mode=%v uid=%d, want a root-owned 0700 directory", dir, fi.IsDir(), fi.Mode().Perm(), st.Uid)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		info, err := os.Lstat(dir + "/" + e.Name())
		if err != nil {
			t.Error(err)
			continue
		}
		est := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || est.Uid != 0 {
			t.Errorf("%s: regular=%v mode=%v uid=%d, want a root-owned 0600 file", e.Name(), info.Mode().IsRegular(), info.Mode().Perm(), est.Uid)
		}
	}
}
