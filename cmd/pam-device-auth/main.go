package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/discovery"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/distro"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/logger"
)

var VERSION = "0.5.7"

const (
	logFile     = "/var/log/pam-device-auth.log"
	httpTimeout = 10 * time.Second
)

// newOIDCClient builds an http.Client hardened for OIDC/JWKS traffic: short
// timeout and blocked redirects. All endpoints are either scheme-validated
// at discovery or derived from that document, so legitimate redirects never
// occur; following them would open downgrade/hijack paths on a MITM.
func newOIDCClient() *http.Client {
	return &http.Client{
		Timeout: httpTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// runPreflight runs every pre-activation check, printing [OK]/[WARN]/[FAIL] per
// item, and returns the count of blockers and warnings. It is shared by --check
// (which adds the verdict) and --enable (which refuses to activate on a blocker).
func runPreflight() (fails, warns int) {
	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: config error: %v\n", err)
		os.Exit(1)
	}

	// Check for default/example config
	if strings.Contains(cfg.IssuerURL, "example.com") {
		fmt.Fprintf(os.Stderr, "FAIL: default config detected. Edit /etc/pam-device-auth/config.json first.\n")
		os.Exit(1)
	}

	fmt.Printf("Config OK: issuer=%s client=%s role=%s sudo_role=%s\n", cfg.IssuerURL, cfg.ClientID, cfg.RequiredRole, cfg.SudoRole)

	// chk reports one check. fatal=true counts as a blocker (non-zero exit);
	// fatal=false is an advisory warning that still lets activation proceed.
	chk := func(ok, fatal bool, okMsg, badMsg string) {
		switch {
		case ok:
			fmt.Printf("  [OK]   %s\n", okMsg)
		case fatal:
			fmt.Printf("  [FAIL] %s\n", badMsg)
			fails++
		default:
			fmt.Printf("  [WARN] %s\n", badMsg)
			warns++
		}
	}

	// --- OIDC ---
	fmt.Println("OIDC:")
	httpClient := newOIDCClient()
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	endpoints, derr := discovery.Fetch(ctx, httpClient, cfg.IssuerURL)
	cancel()
	if derr != nil {
		fmt.Printf("  [FAIL] discovery failed: %v\n", derr)
		fails++
	} else {
		fmt.Printf("  [OK]   discovery reachable (device=%s)\n", endpoints.DeviceAuthorizationEndpoint)
		chk(strings.TrimRight(endpoints.Issuer, "/") == cfg.IssuerURL, true,
			"issuer matches config",
			fmt.Sprintf("issuer mismatch: discovery=%q config=%q (MITM/misconfig)", endpoints.Issuer, cfg.IssuerURL))
	}

	// --- Directory identity (SSSD/NSS) ---
	fmt.Println("Directory (SSSD/NSS):")
	chk(sssAuthorizedKeysCmd() != "", true,
		"sss_ssh_authorizedkeys present (publickey factor source)",
		"sss_ssh_authorizedkeys not found; install sssd-ldap/libnss-sss; non-root publickey factor cannot work")
	sssdConf := fileExists("/etc/sssd/sssd.conf")
	chk(sssdConf, true,
		"/etc/sssd/sssd.conf present",
		"/etc/sssd/sssd.conf missing; run 'pam-device-auth --setup-ldap' first")
	chk(serviceActive("sssd"), true,
		"sssd service active",
		"sssd not active; run 'pam-device-auth --setup-ldap' / 'systemctl start sssd'")
	if cfg.LDAP == nil {
		chk(false, false, "", "no 'ldap' block in config; required for --setup-ldap")
	} else {
		if cfg.LDAP.AccessGroup != "" {
			members, gerr := getentGroup(cfg.LDAP.AccessGroup)
			chk(gerr == nil, true,
				fmt.Sprintf("access group %q resolves via NSS (%d member(s)); SSSD↔LDAP↔CA path OK", cfg.LDAP.AccessGroup, len(members)),
				fmt.Sprintf("access group %q does not resolve via NSS; directory path broken (LDAP/CA/bind/firewall)", cfg.LDAP.AccessGroup))
			// Every access-group member needs a VALID sshPublicKey, or they cannot
			// satisfy the publickey factor and are locked out of non-root login after
			// --enable. "invalid" = present but not parseable as an SSH key (sshd rejects).
			if gerr == nil && len(members) > 0 {
				warns += reportMemberKeyStatus(members,
					fmt.Sprintf("all %d access-group member(s) have a valid sshPublicKey (publickey factor)", len(members)),
					"%d of %d member(s) have NO sshPublicKey; locked out of non-root login until set: %s",
					"%d of %d member(s) have an UNPARSEABLE sshPublicKey; sshd will reject it: %s")
			}
		}
		for _, g := range cfg.LDAP.ServiceAccountGroups {
			members, gerr := getentGroup(g)
			chk(gerr == nil, false,
				fmt.Sprintf("service group %q resolves (%d member(s)); KEY-ONLY tier (no OIDC)", g, len(members)),
				fmt.Sprintf("service group %q does NOT resolve via NSS; check it exists with a gidNumber", g))
			// Service accounts are KEY-ONLY: the SSH key is their SOLE authentication
			// factor (no OIDC/2FA fallback), so a member with no valid sshPublicKey is
			// completely locked out. Warn-only: never blocks --enable.
			if gerr == nil && len(members) > 0 {
				warns += reportMemberKeyStatus(members,
					fmt.Sprintf("all %d member(s) of service group %q have a valid sshPublicKey (key-only factor)", len(members), g),
					fmt.Sprintf("%%d of %%d member(s) of service group %q have NO sshPublicKey; locked out (key-only tier): %%s", g),
					fmt.Sprintf("%%d of %%d member(s) of service group %q have an UNPARSEABLE sshPublicKey; sshd will reject it: %%s", g))
			}
		}
		for _, g := range cfg.LDAP.NopasswdSudoGroups {
			members, gerr := getentGroup(g)
			chk(gerr == nil, false,
				fmt.Sprintf("nopasswd-sudo group %q resolves (%d member(s)); PASSWORDLESS sudo (elevated)", g, len(members)),
				fmt.Sprintf("nopasswd-sudo group %q does NOT resolve via NSS; check it exists with a gidNumber", g))
		}
	}

	// --- IP allowlist (account-phase gate) ---
	if cfg.LDAP != nil {
		fmt.Println("IP allowlist (account-phase gate):")

		// pam_device_auth.so wired into /etc/pam.d/sshd always brings the
		// account-phase line with it (see configs/pam-sshd-device-auth{,-rhel}),
		// so isEnabled() doubles as "the IP gate is live".
		accountActive := isEnabled()

		// InfoPipe health: probe with one known resolvable directory user so a
		// wedged SSSD/D-Bus surfaces here instead of at login, where it would
		// fail-closed every IP-pinned (and, if unrestricted-by-default is not
		// desired, every directory) user.
		var probeUser string
		if cfg.LDAP.AccessGroup != "" {
			if members, gerr := getentGroup(cfg.LDAP.AccessGroup); gerr == nil && len(members) > 0 {
				probeUser = members[0]
			}
		}
		if probeUser == "" {
			for _, g := range cfg.LDAP.ServiceAccountGroups {
				if members, gerr := getentGroup(g); gerr == nil && len(members) > 0 {
					probeUser = members[0]
					break
				}
			}
		}
		if probeUser == "" {
			chk(false, false, "", "no resolvable directory user found to probe SSSD InfoPipe; skipping health check")
		} else if _, ierr := busctlClients(probeUser); ierr == nil {
			fmt.Printf("  [OK]   SSSD InfoPipe reachable (probed user=%s via busctl)\n", probeUser)
		} else if accountActive {
			fmt.Printf("  [WARN] SSSD InfoPipe query failed for user=%s: %v; account-phase IP gate is ACTIVE and fails closed, this would lock out ALL directory users\n", probeUser, ierr)
			warns++
		} else {
			fmt.Printf("  [WARN] SSSD InfoPipe query failed for user=%s: %v; account-phase IP gate is not yet active, but would fail closed once enabled\n", probeUser, ierr)
			warns++
		}

		// IP-pin posture: how many access-group / service-group members have a
		// "clients" allowlist set (pinned) vs none (unrestricted). Service-group
		// (key-only, single-factor) members with no pin get a dedicated WARN —
		// they have no OIDC fallback if their key leaks.
		reportPinPosture := func(group string, members []string, serviceGroup bool) {
			if len(members) == 0 {
				return
			}
			var pinned, unrestricted, unknown []string
			for _, m := range members {
				clients, err := busctlClients(m)
				switch {
				case err != nil:
					unknown = append(unknown, m)
				case len(clients) > 0:
					pinned = append(pinned, m)
				default:
					unrestricted = append(unrestricted, m)
				}
			}
			fmt.Printf("  [OK]   group %q: %d IP-pinned, %d unrestricted, %d unreadable (of %d member(s))\n",
				group, len(pinned), len(unrestricted), len(unknown), len(members))
			if serviceGroup && len(unrestricted) > 0 {
				fmt.Printf("  [WARN] service group %q: %d member(s) with NO clients allowlist (key-only, unrestricted source IP); recommend pinning: %s\n",
					group, len(unrestricted), strings.Join(unrestricted, ", "))
				warns++
			}
		}

		if cfg.LDAP.AccessGroup != "" {
			if members, gerr := getentGroup(cfg.LDAP.AccessGroup); gerr == nil {
				reportPinPosture(cfg.LDAP.AccessGroup, members, false)
			}
		}
		for _, g := range cfg.LDAP.ServiceAccountGroups {
			if members, gerr := getentGroup(g); gerr == nil {
				reportPinPosture(g, members, true)
			}
		}
	}

	// --- SSH daemon (factors + break-glass) ---
	fmt.Println("SSH daemon:")
	if akc, ok := sshdParam("authorizedkeyscommand", ""); ok {
		chk(strings.Contains(akc, "sss_ssh_authorizedkeys"), true,
			"AuthorizedKeysCommand → sss_ssh_authorizedkeys (directory key = factor 1)",
			"AuthorizedKeysCommand not set to sss_ssh_authorizedkeys ("+akc+"); non-root publickey factor will fail")
		am, _ := sshdParam("authenticationmethods", "")
		chk(strings.Contains(am, "publickey") && strings.Contains(am, "keyboard-interactive:pam"), false,
			"non-root: "+am+" (2FA)",
			"non-root AuthenticationMethods not 2FA (got "+am+"); expected publickey,keyboard-interactive:pam")
		rootAm, _ := sshdParam("authenticationmethods", "root")
		chk(rootAm == "publickey", false,
			"root: publickey only (break-glass)",
			"root AuthenticationMethods is "+rootAm+"; break-glass should be 'publickey' to avoid OIDC/SSSD lockout")
		if akf, ok := sshdParam("authorizedkeysfile", "nobody"); ok {
			chk(akf == "none", false,
				"non-root: AuthorizedKeysFile none (directory key is the only publickey source)",
				"non-root AuthorizedKeysFile is "+akf+", not 'none'; local authorized_keys still satisfy "+
					"factor 1 for non-root users; package upgrades do not rewrite an existing sshd drop-in. "+
					"Re-run 'pam-device-auth --setup-ldap' or update /etc/ssh/sshd_config.d/10-pam-device-auth.conf")
		}
	} else {
		chk(false, false, "", "could not run 'sshd -T' to verify factors (run --check as root after --setup-ldap)")
	}

	return fails, warns
}

// runCheck runs the preflight and prints the verdict; exits non-zero on a blocker.
func runCheck() {
	fails, warns := runPreflight()
	fmt.Println()
	if isEnabled() {
		fmt.Println("Activation: pam-device-auth is already active (pam_device_auth.so in /etc/pam.d/sshd).")
	} else {
		fmt.Println("Activation: not yet enabled; run 'pam-device-auth --enable' once checks are green.")
	}
	switch {
	case fails > 0:
		fmt.Fprintf(os.Stderr, "\n%d blocker(s), %d warning(s). Fix the [FAIL] items before activating.\n", fails, warns)
		os.Exit(1)
	case warns > 0:
		fmt.Printf("\nCritical checks passed; %d warning(s); review the [WARN] items.\n", warns)
	default:
		fmt.Println("\nAll checks passed.")
	}
}

// fileExists reports whether the path exists.
func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// sssAuthorizedKeysCmd returns the path to sss_ssh_authorizedkeys, or "".
func sssAuthorizedKeysCmd() string {
	for _, p := range []string{
		"/usr/bin/sss_ssh_authorizedkeys",
		"/usr/libexec/sssd/sss_ssh_authorizedkeys",
		"/usr/sbin/sss_ssh_authorizedkeys",
	} {
		if fileExists(p) {
			return p
		}
	}
	return ""
}

// serviceActive reports whether a systemd unit is active.
func serviceActive(name string) bool {
	out, _ := exec.Command("systemctl", "is-active", name).Output()
	return strings.TrimSpace(string(out)) == "active"
}

// getentGroup resolves a group via NSS and returns its explicit member names. A
// non-nil error means the group does not resolve (the SSSD→LDAP path is broken).
func getentGroup(name string) ([]string, error) {
	out, err := exec.Command("getent", "group", name).Output()
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), ":", 4)
	if len(parts) < 4 || parts[3] == "" {
		return nil, nil
	}
	return strings.Split(parts[3], ","), nil
}

// userKeyStatus classifies the directory SSH key for a user, as sshd would see
// it via sss_ssh_authorizedkeys:
//
//	"none"    — no key returned
//	"invalid" — a key is returned but it does not parse as an SSH public key
//	"ok"      — at least one parseable key (the user can satisfy the publickey factor)
func userKeyStatus(user string) string {
	cmd := sssAuthorizedKeysCmd()
	if cmd == "" {
		return "none"
	}
	out, err := exec.Command(cmd, user).Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return "none"
	}
	if hasValidSSHKey(out) {
		return "ok"
	}
	return "invalid"
}

// reportMemberKeyStatus classifies each member's sshPublicKey via userKeyStatus
// and prints an [OK]/[WARN] summary, returning the number of warnings raised
// (0 or 2, one per non-empty noKey/badKey bucket). okMsg is printed verbatim
// when every member has a valid key; noKeyFmt/badKeyFmt are Printf-style
// formats consuming (badCount, totalCount, joinedNames) for the two failure
// buckets ("none" and "invalid" respectively).
func reportMemberKeyStatus(members []string, okMsg, noKeyFmt, badKeyFmt string) int {
	var noKey, badKey []string
	for _, m := range members {
		switch userKeyStatus(m) {
		case "none":
			noKey = append(noKey, m)
		case "invalid":
			badKey = append(badKey, m)
		}
	}
	if len(noKey) == 0 && len(badKey) == 0 {
		fmt.Printf("  [OK]   %s\n", okMsg)
		return 0
	}
	warns := 0
	if len(noKey) > 0 {
		fmt.Printf("  [WARN] "+noKeyFmt+"\n", len(noKey), len(members), strings.Join(noKey, ", "))
		warns++
	}
	if len(badKey) > 0 {
		fmt.Printf("  [WARN] "+badKeyFmt+"\n", len(badKey), len(members), strings.Join(badKey, ", "))
		warns++
	}
	return warns
}

// hasValidSSHKey reports whether an authorized_keys blob contains at least one
// key that parses, using ssh-keygen -l (the same parser family as sshd).
func hasValidSSHKey(authKeys []byte) bool {
	c := exec.Command("ssh-keygen", "-l", "-f", "/dev/stdin")
	c.Stdin = bytes.NewReader(authKeys)
	out, err := c.Output()
	return err == nil && strings.TrimSpace(string(out)) != ""
}

// sshdParam returns the effective value of an sshd_config keyword (lowercased
// keyword as printed by `sshd -T`). When user != "" the value is resolved for
// that user (Match blocks applied). The bool is false if `sshd -T` could not run.
func sshdParam(keyword, user string) (string, bool) {
	bin := "sshd"
	if _, err := exec.LookPath("sshd"); err != nil {
		bin = "/usr/sbin/sshd"
	}
	args := []string{"-T"}
	if user != "" {
		args = append(args, "-C", "user="+user)
	}
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		return "", false
	}
	prefix := keyword + " "
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.ToLower(line), prefix) {
			return strings.TrimSpace(line[len(prefix):]), true
		}
	}
	return "", true
}

// isEnabled reports whether pam-device-auth is already wired into SSH auth,
// i.e. --enable has installed pam_device_auth.so into /etc/pam.d/sshd.
func isEnabled() bool {
	data, err := os.ReadFile("/etc/pam.d/sshd")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "pam_device_auth.so")
}

// backupFile copies src to dst, but only when dst does not already exist (an
// existing backup is the pristine original and must never be overwritten with
// an already-modified config). It reports whether a backup was written. A
// missing or unreadable src is treated as "nothing to back up" (no error); a
// failed write to dst is returned so the caller can warn the operator.
func backupFile(src, dst string) (bool, error) {
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		return false, nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return false, nil
	}
	if err := os.WriteFile(dst, data, 0644); err != nil {
		return false, err
	}
	return true, nil
}

// pamTemplateName returns the basename of the sshd PAM stack template to
// activate for the given distro Profile: RHEL-family hosts get the
// authselect/password-auth-based stack, everyone else gets the Debian
// common-auth-based stack.
func pamTemplateName(prof distro.Profile) string {
	if prof.Family == "rhel" {
		return "pam-sshd-device-auth-rhel"
	}
	return "pam-sshd-device-auth"
}

func runEnable() {
	// Run the full preflight and refuse to activate on any blocker, so --enable
	// never wires PAM/sshd against a MITM'd issuer or a directory that cannot
	// resolve users / serve keys (which would lock non-root users out).
	if fails, _ := runPreflight(); fails > 0 {
		fmt.Fprintf(os.Stderr, "\nFAIL: %d blocker(s); refusing to activate. Fix the [FAIL] items above (see --check).\n", fails)
		os.Exit(1)
	}
	fmt.Println()

	if isEnabled() {
		fmt.Println("Note: pam-device-auth is already active; re-applying config and restarting sshd.")
	}

	// Activate PAM config
	shareDir := "/usr/share/pam-device-auth/config"

	// Install sshd config if not present
	sshdConf := "/etc/ssh/sshd_config.d/10-pam-device-auth.conf"
	if _, err := os.Stat(sshdConf); os.IsNotExist(err) {
		src := shareDir + "/10-pam-device-auth.conf"
		data, err := os.ReadFile(src)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: cannot read %s: %v\n", src, err)
			os.Exit(1)
		}
		if err := os.WriteFile(sshdConf, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: cannot write %s: %v\n", sshdConf, err)
			os.Exit(1)
		}
		fmt.Println("Installed SSH config")
	}

	// Install PAM config (backup original)
	pamConf := "/etc/pam.d/sshd"
	pamBackup := "/etc/pam.d/sshd.original"
	pamSrc := shareDir + "/" + pamTemplateName(distro.Detect())
	if didBackup, err := backupFile(pamConf, pamBackup); err != nil {
		// Don't abort activation, but make the missing recovery copy loud:
		// the operator needs to know the rollback path isn't there.
		fmt.Fprintf(os.Stderr, "[WARN] could not back up %s to %s: %v\n", pamConf, pamBackup, err)
	} else if didBackup {
		fmt.Println("Backed up original PAM config")
	}
	data, err := os.ReadFile(pamSrc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: cannot read %s: %v\n", pamSrc, err)
		os.Exit(1)
	}
	if err := os.WriteFile(pamConf, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: cannot write %s: %v\n", pamConf, err)
		os.Exit(1)
	}
	fmt.Println("PAM config activated")

	// Restart sshd
	sshRestarted := false
	cmd := exec.Command("systemctl", "restart", "ssh.service")
	if err := cmd.Run(); err != nil {
		cmd2 := exec.Command("systemctl", "restart", "sshd.service")
		if err := cmd2.Run(); err != nil {
			fmt.Println("WARNING: Could not restart SSH. Run: sudo systemctl restart ssh")
		} else {
			sshRestarted = true
		}
	} else {
		sshRestarted = true
	}
	if sshRestarted {
		fmt.Println("SSH service restarted")
	}

	fmt.Println("\npam-device-auth is now active.")
	fmt.Println("Root: SSH key only (no OIDC)")
	fmt.Println("Other users: SSH key + OIDC Device Authorization")
}

// hasFlag reports whether flag appears anywhere in args. The dispatch loop in
// main exits on the first subcommand it sees, so position-independent flags
// like --debug need a pre-pass.
func hasFlag(args []string, flag string) bool {
	for _, arg := range args {
		if arg == flag {
			return true
		}
	}
	return false
}

func main() {
	debug := hasFlag(os.Args[1:], "--debug")
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--version":
			fmt.Printf("pam-device-auth %s\n", VERSION)
			os.Exit(0)
		case "--help":
			fmt.Println("Usage: pam-device-auth [--debug] [--version] [--check] [--setup-ldap] [--enable] [--pam-acct] [--help]")
			fmt.Println("  SSH authentication via OIDC Device Authorization Grant (RFC 8628)")
			fmt.Println("")
			fmt.Println("  --check       Pre-activation preflight: config, OIDC, directory/SSSD, sshd factors")
			fmt.Println("  --setup-ldap  Configure SSSD/LLDAP directory identity from config (NSS + sudo)")
			fmt.Println("  --enable      Activate PAM authentication (runs --check first)")
			fmt.Println("  --pam-acct    Run the PAM account-phase IP allowlist gate")
			fmt.Println("  --debug       Run with debug logging")
			fmt.Println("  --version     Show version")
			os.Exit(0)
		case "--check":
			runCheck()
			os.Exit(0)
		case "--setup-ldap":
			runSetupLDAP()
			os.Exit(0)
		case "--enable":
			runEnable()
			os.Exit(0)
		case "--pam-acct":
			os.Exit(runPamAcct())
		}
	}

	log, err := logger.NewLogger(logFile, debug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Logger init failed: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	log.Info("pam-device-auth %s starting", VERSION)

	cfg, err := config.Load("")
	if err != nil {
		log.Error("Config error: %v", err)
		os.Exit(1)
	}

	sshUser := os.Getenv("PAM_USER")
	if sshUser == "" {
		log.Error("PAM_USER not set")
		os.Exit(1)
	}

	clientIP := os.Getenv("PAM_RHOST")
	if clientIP == "" {
		clientIP = "unknown"
	}

	log.Info("Authenticating user: %s from IP: %s", sshUser, clientIP)

	httpClient := newOIDCClient()

	// OIDC Discovery (fail-fast if OIDC provider unreachable)
	discoveryCtx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	endpoints, err := discovery.Fetch(discoveryCtx, httpClient, cfg.IssuerURL)
	cancel()
	if err != nil {
		log.Error("OIDC Discovery failed: %v", err)
		os.Exit(1)
	}
	// Verify discovery issuer matches configured issuer (MITM protection)
	if strings.TrimRight(endpoints.Issuer, "/") != cfg.IssuerURL {
		log.Error("OIDC issuer mismatch: discovery=%q config=%q", endpoints.Issuer, cfg.IssuerURL)
		os.Exit(1)
	}
	log.Debug("Discovery OK: device=%s", endpoints.DeviceAuthorizationEndpoint)

	// Identity, groups, home and the sudo password come from the directory
	// (LLDAP via SSSD/NSS). pam-device-auth is only the OIDC SSH-login layer:
	// it validates the OIDC token (signature/issuer/client/exp/iat, required
	// role, optional IP allowlist) and grants or denies the login. It never
	// reads /etc/shadow, prompts for a local password, or manages users.
	directoryAuthFlow(log, cfg, httpClient, endpoints, sshUser, clientIP)
	os.Exit(0)
}

// canRenderQR checks if the URL would produce a QR code small enough to scan.
// Returns false if the URL would require QR version > 5 (84 bytes at ECC M).
func canRenderQR(url string) bool {
	return len(url) <= 84
}

// matchesAllowedIP checks if clientIP is in the OIDC-provided IP allowlist.
// Supports both plain IPs ("10.0.20.2") and CIDR notation ("10.0.0.0/24").
func matchesAllowedIP(clientIP string, allowed []string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	for _, entry := range allowed {
		if strings.Contains(entry, "/") {
			_, network, err := net.ParseCIDR(entry)
			if err != nil {
				continue
			}
			if network.Contains(ip) {
				return true
			}
		} else {
			// Compare parsed addresses, not strings: on dual-stack sshd the
			// client IP may be IPv4-mapped IPv6 ("::ffff:10.0.1.2") while the
			// allowlist holds the plain IPv4 form, or vice versa.
			if entryIP := net.ParseIP(entry); entryIP != nil && entryIP.Equal(ip) {
				return true
			}
		}
	}
	return false
}
