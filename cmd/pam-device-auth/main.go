package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/syslog"
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

var VERSION = "0.5.11"

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
	if sssdConf {
		conf, rerr := os.ReadFile("/etc/sssd/sssd.conf")
		if rerr != nil {
			chk(false, true, "", "cannot read /etc/sssd/sssd.conf: "+rerr.Error())
		} else {
			extra, ifp := sssdClientsExposure(string(conf))
			var missing []string
			if !extra {
				missing = append(missing, "[domain/*] ldap_user_extra_attrs = clients:clients")
			}
			if !ifp {
				missing = append(missing, "[ifp] user_attributes = +clients")
			}
			// An enabled ifp service without its binary makes sssd fail to start at
			// its next restart, which takes the whole directory identity with it.
			if sssdServicesInclude(string(conf), "ifp") {
				ifpPath := sssdIfpPath()
				chk(ifpPath != "", true,
					"SSSD InfoPipe responder present: "+ifpPath,
					"sssd.conf enables the 'ifp' service but sssd_ifp is not installed; sssd fails to start at its next restart and the directory identity goes with it; install the sssd-dbus package")
			}
			chk(len(missing) == 0, true,
				"sssd.conf exposes the clients attribute to the InfoPipe (IP allowlist gate input)",
				"sssd.conf does not expose the 'clients' attribute (missing: "+strings.Join(missing, "; ")+
					"); the account-phase IP gate would treat every user as unrestricted; re-run 'pam-device-auth --setup-ldap'")
		}
	}
	chk(serviceActive("sssd"), true,
		"sssd service active",
		"sssd not active; run 'pam-device-auth --setup-ldap' / 'systemctl start sssd'")
	if cfg.LDAP == nil {
		chk(false, false, "", "no 'ldap' block in config; required for --setup-ldap")
	} else {
		uriErr := validateLDAPURI(cfg.LDAP.URI)
		uriMsg := ""
		if uriErr != nil {
			uriMsg = uriErr.Error()
		}
		chk(uriErr == nil, true,
			"ldap.uri is a single ldaps:// URI (TLS enforced for the bind)",
			uriMsg)
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
		} else if _, ierr := readClients(probeUser); ierr == nil {
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
				clients, err := readClients(m)
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
			// An unreadable clients attribute is exactly what decideIPGate turns
			// into a fail-closed deny at login, so these members are locked out.
			if len(unknown) > 0 {
				fmt.Printf("  [WARN] group %q: %d member(s) with an UNREADABLE clients attribute (SSSD InfoPipe); the account-phase IP gate fails closed and will DENY their login: %s\n",
					group, len(unknown), strings.Join(unknown, ", "))
				warns++
			}
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
		if f := strings.Fields(akc); len(f) > 0 && strings.Contains(akc, "sss_ssh_authorizedkeys") {
			chk(fileExists(f[0]), true,
				"AuthorizedKeysCommand binary exists: "+f[0],
				"AuthorizedKeysCommand binary "+f[0]+" does not exist; sshd serves no directory key and non-root publickey logins fail; re-run 'pam-device-auth --setup-ldap'")
		}
		am, _ := sshdParam("authenticationmethods", "")
		chk(strings.Contains(am, "publickey") && strings.Contains(am, "keyboard-interactive:pam"), false,
			"non-root: "+am+" (2FA)",
			"non-root AuthenticationMethods not 2FA (got "+am+"); expected publickey,keyboard-interactive:pam")
		rootAm, _ := sshdParam("authenticationmethods", "root")
		rootPermit, _ := sshdParam("permitrootlogin", "root")
		rok, rfatal, rokMsg, rbadMsg := rootLoginCheck(cfg.RootLogin, rootPermit, rootAm)
		chk(rok, rfatal, rokMsg, rbadMsg)
		if akf, ok := sshdParam("authorizedkeysfile", "nobody"); ok {
			chk(akf == "none", false,
				"non-root: AuthorizedKeysFile none (directory key is the only publickey source)",
				"non-root AuthorizedKeysFile is "+akf+", not 'none'; local authorized_keys still satisfy "+
					"factor 1 for non-root users; package upgrades do not rewrite an existing sshd drop-in. "+
					"Re-run 'pam-device-auth --setup-ldap' or update /etc/ssh/sshd_config.d/10-pam-device-auth.conf")
		}
	} else {
		// Fatal: if sshd -T cannot be evaluated the effective sshd policy is
		// unverified (or the config is invalid), so --enable must not proceed.
		chk(false, true, "", "could not run 'sshd -T' to verify the sshd factors (run as root; if it fails, the sshd config is invalid)")
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
//	"error"   — sss_ssh_authorizedkeys failed (SSSD down, unknown user): the key state is unknown
//	"invalid" — a key is returned but it does not parse as an SSH public key
//	"ok"      — at least one parseable key (the user can satisfy the publickey factor)
func userKeyStatus(user string) string {
	cmd := sssAuthorizedKeysCmd()
	if cmd == "" {
		return "none"
	}
	out, err := exec.Command(cmd, user).Output()
	if err != nil {
		return "error"
	}
	if strings.TrimSpace(string(out)) == "" {
		return "none"
	}
	if hasValidSSHKey(out) {
		return "ok"
	}
	return "invalid"
}

// classifyMembers buckets members by their key status; status is injectable.
func classifyMembers(members []string, status func(string) string) (noKey, badKey, errKey []string) {
	for _, m := range members {
		switch status(m) {
		case "none":
			noKey = append(noKey, m)
		case "invalid":
			badKey = append(badKey, m)
		case "error":
			errKey = append(errKey, m)
		}
	}
	return noKey, badKey, errKey
}

// reportMemberKeyStatus classifies each member's sshPublicKey via userKeyStatus
// and prints an [OK]/[WARN] summary, returning the number of warnings raised
// (0 to 3, one per non-empty noKey/badKey/lookup-error bucket). okMsg is printed
// verbatim when every member has a valid key; noKeyFmt/badKeyFmt are
// Printf-style formats consuming (badCount, totalCount, joinedNames) for the
// "none" and "invalid" buckets. Members whose key lookup itself failed are
// reported separately: their key state is unknown, not absent.
func reportMemberKeyStatus(members []string, okMsg, noKeyFmt, badKeyFmt string) int {
	noKey, badKey, errKey := classifyMembers(members, userKeyStatus)
	if len(noKey) == 0 && len(badKey) == 0 && len(errKey) == 0 {
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
	if len(errKey) > 0 {
		fmt.Printf("  [WARN] %d of %d member(s): sss_ssh_authorizedkeys failed, key state UNKNOWN (SSSD/directory problem?): %s\n",
			len(errKey), len(members), strings.Join(errKey, ", "))
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
// missing src is "nothing to back up" (no error). Everything that leaves the
// operator without a usable rollback copy is returned as an error so the caller
// can warn: an unreadable src or dst, a failed write, an existing backup that
// already contains pam_device_auth.so, or a src that already contains it with
// no backup (nothing pristine left to save).
func backupFile(src, dst string) (bool, error) {
	existing, err := os.ReadFile(dst)
	if err == nil {
		if strings.Contains(string(existing), "pam_device_auth.so") {
			return false, fmt.Errorf("existing backup %s already contains pam_device_auth.so; it is not a pristine original", dst)
		}
		return false, nil
	}
	if !os.IsNotExist(err) {
		return false, fmt.Errorf("cannot check existing backup %s: %w", dst, err)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("cannot read %s: %w", src, err)
	}
	if strings.Contains(string(data), "pam_device_auth.so") {
		return false, fmt.Errorf("%s already contains pam_device_auth.so and no backup exists; no pristine original to save", src)
	}
	if err := atomicWriteFile(dst, data, 0644); err != nil {
		return false, err
	}
	return true, nil
}

// dropinNeedsRender reports whether --enable must (re)render the sshd drop-in:
// when it is missing, or when it does not reference the resolved
// sss_ssh_authorizedkeys path. The latter catches a stale drop-in left by an
// older version (for example a hardcoded /usr/bin path on RHEL-family hosts,
// where the binary lives in /usr/libexec/sssd), which would otherwise leave
// sshd serving no directory key.
func dropinNeedsRender(path, sssCmd, rootLogin string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	// A changed root_login must reach sshd, so the PermitRootLogin line has to
	// match the configured mode.
	want := "\nPermitRootLogin prohibit-password\n"
	if rootLogin == config.RootLoginDisabled {
		want = "\nPermitRootLogin no\n"
	}
	if !strings.Contains(string(data), want) {
		return true
	}
	return sssCmd != "" && !strings.Contains(string(data), sssCmd)
}

// sssdServicesInclude reports whether the [sssd] section of an sssd.conf lists
// service in its `services` line.
func sssdServicesInclude(conf, service string) bool {
	section := ""
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' && line[len(line)-1] == ']' {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok || section != "sssd" || strings.ToLower(strings.TrimSpace(key)) != "services" {
			continue
		}
		for _, tok := range strings.FieldsFunc(val, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			if strings.EqualFold(tok, service) {
				return true
			}
		}
	}
	return false
}

// sssdIfpPath returns the path of the InfoPipe responder binary, or "" when no
// package provides it. It lives in the sssd-dbus package on Debian, Ubuntu and
// the RHEL family.
func sssdIfpPath() string {
	for _, p := range []string{
		"/usr/libexec/sssd/sssd_ifp",
		"/usr/lib/x86_64-linux-gnu/sssd/sssd_ifp",
		"/usr/lib/sssd/sssd_ifp",
		"/usr/lib64/sssd/sssd_ifp",
	} {
		if fileExists(p) {
			return p
		}
	}
	return ""
}

// rootLoginCheck judges root's effective SSH policy against the configured
// root_login mode. permitRootLogin and rootAuthMethods are the values sshd -T
// reports for user root. With root_login "disabled" a root that can still log in
// is a blocker: the operator asked for the opposite. In the default mode a root
// that cannot log in is only a warning, because it removes the emergency path
// without the config saying so.
func rootLoginCheck(mode, permitRootLogin, rootAuthMethods string) (ok, fatal bool, okMsg, badMsg string) {
	if mode == config.RootLoginDisabled {
		return permitRootLogin == "no", true,
			"root: SSH login disabled (root_login = disabled); root is reachable only through a console",
			"root_login is 'disabled' but sshd allows root (PermitRootLogin " + permitRootLogin +
				"); an sshd drop-in that sorts before 10-pam-device-auth.conf may override it; re-run 'pam-device-auth --setup-ldap' and check /etc/ssh/sshd_config.d"
	}
	if permitRootLogin == "no" {
		return false, false, "",
			"root SSH login is disabled in sshd (PermitRootLogin no) although root_login is 'key'; there is no emergency path if LDAP, SSSD or the identity provider fail; set root_login to 'disabled' to make this explicit"
	}
	return rootAuthMethods == "publickey", false,
		"root: publickey only (break-glass)",
		"root AuthenticationMethods is " + rootAuthMethods + "; break-glass should be 'publickey' to avoid OIDC/SSSD lockout"
}

// sssdClientsExposure reports whether sssd.conf makes the directory "clients"
// attribute readable through the InfoPipe: the domain must fetch it
// (ldap_user_extra_attrs = clients:clients) and [ifp] must allow it
// (user_attributes = +clients). Without either, GetUserAttr returns an empty
// answer and the account-phase IP gate sees "no allowlist" for every user.
func sssdClientsExposure(conf string) (extraAttrs, ifp bool) {
	section := ""
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' && line[len(line)-1] == ']' {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		for _, tok := range strings.FieldsFunc(val, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			switch {
			case key == "ldap_user_extra_attrs" && strings.HasPrefix(section, "domain/") && (tok == "clients" || tok == "clients:clients"):
				extraAttrs = true
			case key == "user_attributes" && section == "ifp" && tok == "+clients":
				ifp = true
			}
		}
	}
	return extraAttrs, ifp
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

// commandRunner runs a command and returns its combined output; a seam so the
// enable steps can be tested without touching systemd.
type commandRunner func(name string, args ...string) ([]byte, error)

func execRunner(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// errSSHRestart marks the one --enable failure after which the PAM config and
// drop-in are already written but sshd still runs the old configuration.
var errSSHRestart = errors.New("sshd was NOT restarted")

// restartSSH restarts the sshd unit: ssh.service on Debian/Ubuntu, sshd.service
// on RHEL-family hosts. The error carries both units' output.
func restartSSH(run commandRunner) error {
	out1, err1 := run("systemctl", "restart", "ssh.service")
	if err1 == nil {
		return nil
	}
	out2, err2 := run("systemctl", "restart", "sshd.service")
	if err2 == nil {
		return nil
	}
	return fmt.Errorf("%w (ssh.service: %s; sshd.service: %s)", errSSHRestart,
		strings.TrimSpace(string(out1)), strings.TrimSpace(string(out2)))
}

// activatePAM backs up the original PAM stack (a failed backup only warns on
// warn: activation must stay possible, but the operator must know the rollback
// copy is missing) and installs the template atomically, so a crash or full
// disk can never leave a truncated PAM stack that also breaks root's
// break-glass login.
func activatePAM(pamConf, pamBackup, pamSrc string, warn io.Writer) error {
	if didBackup, err := backupFile(pamConf, pamBackup); err != nil {
		fmt.Fprintf(warn, "[WARN] could not back up %s to %s: %v\n", pamConf, pamBackup, err)
	} else if didBackup {
		fmt.Println("Backed up original PAM config")
	}
	data, err := os.ReadFile(pamSrc)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", pamSrc, err)
	}
	if err := atomicWriteFile(pamConf, data, 0644); err != nil {
		return fmt.Errorf("cannot write %s: %w", pamConf, err)
	}
	fmt.Println("PAM config activated")
	return nil
}

// enableSteps are the side-effecting activation steps of --enable, injectable
// so the ordering contract is testable.
type enableSteps struct {
	renderDropin func() error
	activatePAM  func() error
	restartSSH   func() error
}

// runEnableSteps runs the steps in the only safe order: the sshd drop-in must
// be valid before the PAM stack is switched, and sshd is restarted last. A
// failing step stops the sequence: a rejected drop-in must never be followed by
// a PAM switch or an sshd restart.
func runEnableSteps(s enableSteps) error {
	if err := s.renderDropin(); err != nil {
		return err
	}
	if err := s.activatePAM(); err != nil {
		return err
	}
	return s.restartSSH()
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

	// runPreflight already loaded and validated the config; reload it here for
	// the service-group list the sshd drop-in needs.
	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: config error: %v\n", err)
		os.Exit(1)
	}

	if isEnabled() {
		fmt.Println("Note: pam-device-auth is already active; re-applying config and restarting sshd.")
	}

	shareDir := "/usr/share/pam-device-auth/config"
	sshdConf := sshdDropinPath
	sssCmd := sssAuthorizedKeysCmd()

	err = runEnableSteps(enableSteps{
		// Render the drop-in from the resolved sss_ssh_authorizedkeys path
		// (RHEL ships it under /usr/libexec/sssd) instead of copying the
		// packaged template, which hardcodes /usr/bin. writeSshdDropin validates
		// with `sshd -t` and rolls back on rejection.
		renderDropin: func() error {
			if !dropinNeedsRender(sshdConf, sssCmd, cfg.RootLogin) {
				return nil
			}
			if sssCmd == "" {
				return errors.New("sss_ssh_authorizedkeys not found; run --setup-ldap first")
			}
			var serviceGroups []string
			if cfg.LDAP != nil {
				serviceGroups = cfg.LDAP.ServiceAccountGroups
			}
			if err := writeSshdDropin(sssCmd, serviceGroups, cfg.RootLogin); err != nil {
				return fmt.Errorf("cannot write %s: %w", sshdConf, err)
			}
			fmt.Println("Installed SSH config")
			return nil
		},
		activatePAM: func() error {
			return activatePAM("/etc/pam.d/sshd", "/etc/pam.d/sshd.original",
				shareDir+"/"+pamTemplateName(distro.Detect()), os.Stderr)
		},
		restartSSH: func() error { return restartSSH(execRunner) },
	})
	if errors.Is(err, errSSHRestart) {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		fmt.Fprintln(os.Stderr, "pam-device-auth is NOT fully active: the PAM config and sshd drop-in are written, but sshd still runs the old configuration.")
		fmt.Fprintln(os.Stderr, "Run: systemctl restart ssh (or sshd), then 'pam-device-auth --check'.")
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("SSH service restarted")

	fmt.Println("\npam-device-auth is now active.")
	if cfg.RootLoginIsDisabled() {
		fmt.Println("Root: SSH login disabled (root_login = disabled); console access only")
	} else {
		fmt.Println("Root: SSH key only (no OIDC)")
	}
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
		// Fail closed (no audit log, no login), but not invisibly: sshd discards
		// our stderr and the C side only sees "exit code 1", so also send the
		// reason to syslog (authpriv).
		reportLogInitFailure(err)
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

	// OIDC Discovery (fail-fast if OIDC provider unreachable). Served from the
	// root-only metadata cache when fresh; a cached document runs through the
	// same validation and the issuer pin below exactly like a live one.
	discoveryCtx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	endpoints, err := discovery.FetchCached(discoveryCtx, httpClient, cfg.IssuerURL, log.Debug)
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

// logInitFailureMessage is the text reported when the auth log cannot be opened.
func logInitFailureMessage(err error) string {
	return fmt.Sprintf("pam-device-auth: cannot open %s: %v; denying login (fail closed)", logFile, err)
}

// reportLogInitFailure writes logInitFailureMessage to stderr and, best effort,
// to syslog so an operator can find out why every login is being denied.
func reportLogInitFailure(err error) {
	msg := logInitFailureMessage(err)
	fmt.Fprintln(os.Stderr, msg)
	if w, serr := syslog.New(syslog.LOG_AUTHPRIV|syslog.LOG_ERR, "pam-device-auth"); serr == nil {
		_ = w.Err(msg)
		_ = w.Close()
	}
}

// invalidAllowlistEntries returns the allowlist entries that are neither a valid
// IP nor a valid CIDR. matchesAllowedIP skips them silently, so without this a
// typo in the directory attribute denies the user with no hint in the log.
func invalidAllowlistEntries(allowed []string) []string {
	var bad []string
	for _, entry := range allowed {
		if strings.Contains(entry, "/") {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				bad = append(bad, entry)
			}
		} else if net.ParseIP(entry) == nil {
			bad = append(bad, entry)
		}
	}
	return bad
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
