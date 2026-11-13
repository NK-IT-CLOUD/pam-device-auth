package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/syslog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/discovery"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/distro"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/logger"
)

var VERSION = "0.7.2"

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

// timedDiscovery fetches the discovery document over a connection of its own
// and returns how long that took: the name lookup, the TCP and TLS handshakes
// and the request, as the first request of a login has them. newOIDCClient
// shares the connection pool of http.DefaultTransport, where a second request
// would reuse the open connection and measure the request alone.
func timedDiscovery(issuerURL string) (*discovery.Endpoints, time.Duration, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	client := newOIDCClient()
	client.Transport = transport
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	start := time.Now()
	endpoints, err := discovery.Fetch(ctx, client, issuerURL)
	return endpoints, time.Since(start), err
}

// runPreflight runs every pre-activation check, printing [OK]/[WARN]/[FAIL] per
// item, and returns the count of blockers and warnings. It is shared by --check
// (which adds the verdict) and --enable (which refuses to activate on a blocker).
// prof is the detected platform (requirePlatform).
func runPreflight(prof distro.Profile) (fails, warns int) {
	cfg, err := loadConfig("")
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
	// The config loads, but a key the loader does not know or an algorithm it
	// cannot verify is a blocker here: a login only logs it.
	fails += reportConfigWarnings(cfg, os.Stdout)
	if len(cfg.RequiredACR) > 0 {
		fmt.Printf("Token policy: acr must be one of %s (checked at login; the IdP must issue the acr claim)\n", strings.Join(cfg.RequiredACR, ", "))
	}

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
	endpoints, discoveryTook, derr := timedDiscovery(cfg.IssuerURL)
	if derr != nil {
		fmt.Printf("  [FAIL] discovery failed: %v\n", derr)
		fails++
	} else {
		fmt.Printf("  [OK]   discovery reachable (device=%s)\n", endpoints.DeviceAuthorizationEndpoint)
		tok, tokMsg, tbadMsg := discoveryTiming(discoveryTook, func() (time.Duration, error) {
			_, d, err := timedDiscovery(cfg.IssuerURL)
			return d, err
		})
		chk(tok, false, tokMsg, tbadMsg)
		chk(strings.TrimRight(endpoints.Issuer, "/") == cfg.IssuerURL, true,
			"issuer matches config",
			fmt.Sprintf("issuer mismatch: discovery=%q config=%q (MITM/misconfig)", endpoints.Issuer, cfg.IssuerURL))
	}

	// --- Directory identity (SSSD/NSS) ---
	fmt.Println("Directory (SSSD/NSS):")
	sssErr := checkSSSAuthKeys(prof.SSSAuthKeysPath)
	chk(sssErr == nil, true,
		"sss_ssh_authorizedkeys present (publickey factor source)",
		fmt.Sprintf("%v; non-root publickey factor cannot work", sssErr))
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
				missing = append(missing, "[domain/*] ldap_user_extra_attrs = clients:<LDAP attribute>")
			}
			if !ifp {
				missing = append(missing, "[ifp] user_attributes = +clients")
			}
			// An enabled ifp service without its binary makes sssd fail to start at
			// its next restart, which takes the whole directory identity with it.
			if sssdServicesInclude(string(conf), "ifp") {
				ifpErr := checkSSSDIfp(prof.SSSDIfpPath)
				chk(ifpErr == nil, true,
					"SSSD InfoPipe responder present: "+prof.SSSDIfpPath,
					fmt.Sprintf("sssd.conf enables the 'ifp' service but %v; sssd fails to start at its next restart and the directory identity goes with it", ifpErr))
			}
			socks := conflictingSSSDSockets(string(conf))
			chk(len(socks) == 0, false,
				"no SSSD socket unit competes with a responder from the sssd.conf services line",
				"SSSD socket unit(s) "+strings.Join(socks, ", ")+" are enabled or failed although sssd.conf starts their responder from the services line; "+
					"they fail at every start and leave systemd degraded; re-run 'pam-device-auth --setup-ldap' (or 'systemctl mask' them)")
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
		uok, uokMsg, ubadMsg := ldapURICheck(cfg.LDAP)
		chk(uok, true, uokMsg, ubadMsg)
		pok, pokMsg, pbadMsg := ldapProfileCheck(cfg.LDAP)
		chk(pok, true, pokMsg, pbadMsg)
		sok, sokMsg, sbadMsg := ldapShellCheck(cfg.LDAP)
		chk(sok, true, sokMsg, sbadMsg)
		if cfg.LDAP.CAFile != "" {
			cok, cokMsg, cbadMsg := caFileCheck(cfg.LDAP.CAFile)
			chk(cok, true, cokMsg, cbadMsg)
		}
		if k := cfg.LDAP.Kerberos; k != nil {
			fmt.Printf("  [OK]   Kerberos realm %s, KDC %s (sudo and passwd via krb5)\n", k.Realm, k.KDC)
			if _, lerr := net.LookupHost(kdcHost(k.KDC)); lerr != nil {
				chk(false, false, "", fmt.Sprintf("Kerberos KDC %s does not resolve: %v", k.KDC, lerr))
			}
			if k.Keytab != "" {
				kerr := checkSecretFile(k.Keytab)
				chk(kerr == nil, true, "keytab "+k.Keytab+" is root-only",
					fmt.Sprintf("ldap.kerberos.keytab: %v", kerr))
			}
		}
		// Member names that start with '-' are left out of every per-member
		// check below (see splitMembers) and reported once.
		var optionLike []string
		if cfg.LDAP.AccessGroup != "" {
			members, skipped, gerr := getentGroup(cfg.LDAP.AccessGroup)
			optionLike = append(optionLike, skipped...)
			chk(gerr == nil, true,
				fmt.Sprintf("access group %q resolves via NSS (%d member(s)); %s", cfg.LDAP.AccessGroup, len(members), directoryPathOK(cfg.LDAP)),
				accessGroupFailMessage(cfg.LDAP.AccessGroup))
			// Every access-group member needs a VALID sshPublicKey, or they cannot
			// satisfy the publickey factor and are locked out of non-root login after
			// --enable. "invalid" = present but not parseable as an SSH key (sshd rejects).
			if gerr == nil && len(members) > 0 {
				warns += reportMemberKeyStatus(prof.SSSAuthKeysPath, members,
					fmt.Sprintf("all %d access-group member(s) have a valid sshPublicKey (publickey factor)", len(members)),
					"%d of %d member(s) have NO sshPublicKey; locked out of non-root login until set: %s",
					"%d of %d member(s) have an UNPARSEABLE sshPublicKey; sshd will reject it: %s")
			}
		}
		for _, g := range cfg.LDAP.ServiceAccountGroups {
			members, skipped, gerr := getentGroup(g)
			optionLike = append(optionLike, skipped...)
			chk(gerr == nil, false,
				fmt.Sprintf("service group %q resolves (%d member(s)); KEY-ONLY tier (no OIDC)", g, len(members)),
				fmt.Sprintf("service group %q does NOT resolve via NSS; check it exists with a gidNumber", g))
			// Service accounts are KEY-ONLY: the SSH key is their SOLE authentication
			// factor (no OIDC/2FA fallback), so a member with no valid sshPublicKey is
			// completely locked out. Warn-only: never blocks --enable.
			if gerr == nil && len(members) > 0 {
				warns += reportMemberKeyStatus(prof.SSSAuthKeysPath, members,
					fmt.Sprintf("all %d member(s) of service group %q have a valid sshPublicKey (key-only factor)", len(members), g),
					fmt.Sprintf("%%d of %%d member(s) of service group %q have NO sshPublicKey; locked out (key-only tier): %%s", g),
					fmt.Sprintf("%%d of %%d member(s) of service group %q have an UNPARSEABLE sshPublicKey; sshd will reject it: %%s", g))
			}
		}
		if len(optionLike) > 0 {
			slices.Sort(optionLike)
			chk(false, false, "",
				"group member name(s) that start with '-' are left out of every check and are refused at login: "+
					strings.Join(slices.Compact(optionLike), ", "))
		}
		// IDs must exist in this host's user namespace, or the login fails in
		// setresuid (unprivileged containers map only 65536 IDs; SSSD's AD ID
		// mapping starts at 200000 unless ldap.id_range is set).
		uidMap, uerr := os.ReadFile("/proc/self/uid_map")
		gidMap, gerr2 := os.ReadFile("/proc/self/gid_map")
		if uerr == nil && gerr2 == nil {
			// A group that does not resolve is already reported above (access
			// group FAIL, service group WARN); it simply contributes no members.
			var members []string
			for _, g := range append([]string{cfg.LDAP.AccessGroup}, cfg.LDAP.ServiceAccountGroups...) {
				m, _, _ := getentGroup(g)
				members = append(members, m...)
			}
			checked, outside, unresolved := idMapReport(members, directoryUserIDs,
				parseIDMap(string(uidMap)), parseIDMap(string(gidMap)))
			switch {
			case len(outside) > 0:
				chk(false, true, "",
					"directory user(s) outside this host's uid/gid map, their login fails in setresuid: "+strings.Join(outside, ", ")+
						"; set ldap.id_range (ad) or lower uidNumber/gidNumber (lldap)")
			case checked > 0:
				chk(true, true,
					fmt.Sprintf("UIDs/GIDs of %d directory user(s) exist in this host's ID map", checked), "")
			}
			if len(unresolved) > 0 {
				chk(false, false, "",
					"could not read uid/gid of directory user(s) "+strings.Join(unresolved, ", ")+"; their ID map fit is unverified")
			}
		}
		for _, g := range cfg.LDAP.NopasswdSudoGroups {
			members, _, gerr := getentGroup(g)
			chk(gerr == nil, false,
				fmt.Sprintf("nopasswd-sudo group %q resolves (%d member(s)); PASSWORDLESS sudo (elevated)", g, len(members)),
				fmt.Sprintf("nopasswd-sudo group %q does NOT resolve via NSS; check it exists with a gidNumber", g))
		}
		// Every member count above and every check per member below works on
		// these lists; with profile ad they can miss an account.
		reportMemberListNote(cfg.LDAP, os.Stdout)
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
			if members, _, gerr := getentGroup(cfg.LDAP.AccessGroup); gerr == nil && len(members) > 0 {
				probeUser = members[0]
			}
		}
		if probeUser == "" {
			for _, g := range cfg.LDAP.ServiceAccountGroups {
				if members, _, gerr := getentGroup(g); gerr == nil && len(members) > 0 {
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
			if members, _, gerr := getentGroup(cfg.LDAP.AccessGroup); gerr == nil {
				reportPinPosture(cfg.LDAP.AccessGroup, members, false)
			}
		}
		for _, g := range cfg.LDAP.ServiceAccountGroups {
			if members, _, gerr := getentGroup(g); gerr == nil {
				reportPinPosture(g, members, true)
			}
		}

		// Migration preview: what --setup-ldap would do with local accounts
		// that shadow a directory user. A warning, never a blocker.
		preview, perr := shadowingPreview("/proc")
		if perr != nil {
			chk(false, false, "", "local accounts that shadow directory users were NOT checked: "+perr.Error())
		}
		for _, line := range preview {
			chk(false, false, "", line)
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
		chk(methodsRequire2FA(am), false,
			"non-root: "+am+" (2FA)",
			"non-root AuthenticationMethods not 2FA (got "+am+"); expected publickey,keyboard-interactive:pam "+
				"(a space instead of the comma makes each factor enough on its own)")
		// A Match block of another sshd drop-in can change the methods for
		// single users, groups or addresses, so sshd is asked for every member.
		if cfg.LDAP != nil {
			var access, service []string
			if cfg.LDAP.AccessGroup != "" {
				access, _, _ = getentGroup(cfg.LDAP.AccessGroup)
			}
			for _, g := range cfg.LDAP.ServiceAccountGroups {
				m, _, _ := getentGroup(g)
				service = append(service, m...)
			}
			twoFactor, keyOnly, weak, notEvaluated := factorReport(access, service, func(spec string) (string, bool) {
				return sshdParamFor("authenticationmethods", spec)
			})
			if len(twoFactor)+len(keyOnly)+len(weak) > 0 {
				chk(len(weak) == 0, false,
					fmt.Sprintf("SSH factors per member: %d with key and OIDC, %d key-only (service groups)", len(twoFactor), len(keyOnly)),
					"member(s) whose SSH factors do not fit their tier (a Match block in another sshd drop-in?): "+strings.Join(weak, ", ")+
						"; expected publickey,keyboard-interactive:pam, for service-group members publickey")
			}
			if len(notEvaluated) > 0 {
				chk(false, false, "",
					"SSH factors not evaluated for member(s) "+strings.Join(notEvaluated, ", ")+
						" (the name cannot be written into an sshd connection spec, or sshd -T gave no answer)")
			}
		}
		// Without PAM sshd runs neither the OIDC step nor the account phase
		// (clients allowlist, access group); the OIDC step itself is a
		// keyboard-interactive conversation.
		for _, kw := range []struct{ key, name, why string }{
			{"usepam", "UsePAM", "without PAM sshd runs neither the OIDC step nor the account phase (clients allowlist, access group)"},
			{"kbdinteractiveauthentication", "KbdInteractiveAuthentication", "the OIDC step is a keyboard-interactive conversation"},
		} {
			v, _ := sshdParam(kw.key, "")
			chk(v == "yes", true, kw.name+" yes", fmt.Sprintf("%s is %q, must be yes: %s", kw.name, v, kw.why))
		}
		rootPermit, rootAm, rootKeys, sources := rootSSHDPolicy(cfg.RootLoginSources)
		rok, rfatal, rokMsg, rbadMsg := rootLoginWithSources(cfg.RootLogin, rootPermit, rootAm, rootKeys, sources)
		chk(rok, rfatal, rokMsg, rbadMsg)
		if akf, ok := sshdKeysFileFor("user=nobody"); ok {
			chk(akf == "none", false,
				"non-root: AuthorizedKeysFile none (directory key is the only publickey source)",
				"non-root AuthorizedKeysFile is "+akf+", not 'none'; local authorized_keys still satisfy "+
					"factor 1 for non-root users; package upgrades do not rewrite an existing sshd drop-in. "+
					"Re-run 'pam-device-auth --setup-ldap' or update /etc/ssh/sshd_config.d/10-pam-device-auth.conf")
		}
		// With UseDNS yes sshd hands PAM the client's host name instead of its
		// address, which the account-phase IP gate cannot match (fail closed).
		if useDNS, ok := sshdParam("usedns", ""); ok {
			chk(useDNS != "yes", false,
				"UseDNS no (PAM receives the client IP for the IP allowlist)",
				"sshd has UseDNS yes; PAM receives the client host name instead of its IP and the account-phase IP gate denies every user with a clients allowlist; set UseDNS no")
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
	prof := requirePlatform()
	fails, warns := runPreflight(prof)
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

// ldapTransportDescription names how the directory connection is protected.
// LDAPS detection matches renderSSSDConf (case-insensitive scheme).
func ldapTransportDescription(l *config.LDAPConfig) string {
	keytab := l.Kerberos != nil && l.Kerberos.Keytab != ""
	ldaps := strings.HasPrefix(strings.ToLower(l.URI), "ldaps://")
	switch {
	case keytab:
		return "GSSAPI with SASL sealing"
	case ldaps:
		return "LDAPS"
	default:
		return "StartTLS"
	}
}

// ldapURICheck is the --check result for ldap.uri and the transport derived
// from it, with the URI rules --setup-ldap enforces (validateLDAPURI,
// keytabTransportError, keytabHostError).
func ldapURICheck(l *config.LDAPConfig) (ok bool, okMsg, badMsg string) {
	if err := validateLDAPURI(l.URI); err != nil {
		return false, "", err.Error()
	}
	if err := keytabTransportError(l); err != nil {
		return false, "", err.Error()
	}
	if err := keytabHostError(l); err != nil {
		return false, "", err.Error()
	}
	return true, "ldap.uri is a single URI, transport " + ldapTransportDescription(l) + " (no cleartext bind)", ""
}

// ldapProfileCheck is the --check result for ldap.profile, by the rule
// --setup-ldap enforces.
func ldapProfileCheck(l *config.LDAPConfig) (ok bool, okMsg, badMsg string) {
	if err := validateLDAPProfile(l); err != nil {
		return false, "", err.Error()
	}
	return true, "profile " + l.Profile, ""
}

// ldapShellCheck is the --check result for the login shell of directory users
// (ldap.shell or the default): checkLDAPShell, the check --setup-ldap runs,
// including the absolute-path rule before the file is looked at.
func ldapShellCheck(l *config.LDAPConfig) (ok bool, okMsg, badMsg string) {
	sh := ldapShell(l)
	if err := checkLDAPShell(sh); err != nil {
		return false, "", err.Error()
	}
	return true, "login shell " + sh + " is executable", ""
}

// caFileCheck is the --check result for ldap.ca_file, with the rule
// --setup-ldap enforces (caFileError).
func caFileCheck(path string) (ok bool, okMsg, badMsg string) {
	if err := caFileError(path); err != nil {
		return false, "", err.Error()
	}
	return true, "ldap.ca_file is a regular file: " + path, ""
}

// kdcHost returns the host part of ldap.kerberos.kdc for the DNS lookup:
// "host", "host:port", "[v6]:port", "[v6]" or a bare IPv6 address.
func kdcHost(kdc string) string {
	if host, _, err := net.SplitHostPort(kdc); err == nil {
		return host
	}
	return strings.Trim(kdc, "[]")
}

// directoryPathOK names the path a resolving access group proves. A keytab
// bind runs GSSAPI with SASL sealing, so no CA certificate is involved.
func directoryPathOK(l *config.LDAPConfig) string {
	if l.Kerberos != nil && l.Kerberos.Keytab != "" {
		return "SSSD↔LDAP path OK (GSSAPI)"
	}
	return "SSSD↔LDAP↔CA path OK"
}

// accessGroupFailMessage is the --check FAIL for an access group that does not
// resolve via NSS. With ldap:// a server without StartTLS (LLDAP has none)
// leaves SSSD offline, which looks exactly like this.
func accessGroupFailMessage(group string) string {
	return fmt.Sprintf("access group %q does not resolve via NSS; directory path broken (LDAP/CA/bind/firewall; with ldap:// the server must support StartTLS)", group)
}

// fileExists reports whether the path exists.
func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// checkSSSAuthKeys verifies that path (the platform's sss_ssh_authorizedkeys,
// distro.Profile.SSSAuthKeysPath) is a regular file executable by its owner:
// sshd runs it as AuthorizedKeysCommand to fetch the directory key.
func checkSSSAuthKeys(path string) error {
	fi, err := os.Stat(path)
	switch {
	case err != nil:
		return fmt.Errorf("sss_ssh_authorizedkeys %s: %w (shipped by the sssd-common package)", path, err)
	case !fi.Mode().IsRegular():
		return fmt.Errorf("sss_ssh_authorizedkeys %s is not a regular file (%s); reinstall the sssd-common package", path, fi.Mode().Type())
	case fi.Mode().Perm()&0100 == 0:
		return fmt.Errorf("sss_ssh_authorizedkeys %s is not executable (mode %s); reinstall the sssd-common package", path, fi.Mode().Perm())
	}
	return nil
}

// serviceActive reports whether a systemd unit is active.
func serviceActive(name string) bool {
	out, _ := exec.Command("systemctl", "is-active", name).Output()
	return strings.TrimSpace(string(out)) == "active"
}

// getentGroup resolves a group via NSS and returns its explicit member names. A
// non-nil error means the group does not resolve (the SSSD→LDAP path is broken).
// skipped holds the member names that must not become a command argument
// (splitMembers); callers hand only members to per-member commands.
func getentGroup(name string) (members, skipped []string, err error) {
	out, err := exec.Command("getent", "group", "--", name).Output()
	if err != nil {
		return nil, nil, err
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), ":", 4)
	if len(parts) < 4 {
		return nil, nil, nil
	}
	members, skipped = splitMembers(parts[3])
	return members, skipped, nil
}

// userKeyStatus classifies the directory SSH key for a user, as sshd would see
// it via sss_ssh_authorizedkeys (keysCmd):
//
//	"none"    — no key returned
//	"error"   — sss_ssh_authorizedkeys failed (SSSD down, unknown user): the key state is unknown
//	"invalid" — a key is returned but it does not parse as an SSH public key
//	"ok"      — at least one parseable key (the user can satisfy the publickey factor)
func userKeyStatus(keysCmd, user string) string {
	out, err := exec.Command(keysCmd, "--", user).Output()
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
// (keysCmd is the sss_ssh_authorizedkeys path) and prints an [OK]/[WARN]
// summary, returning the number of warnings raised (0 to 3, one per non-empty
// noKey/badKey/lookup-error bucket). okMsg is printed
// verbatim when every member has a valid key; noKeyFmt/badKeyFmt are
// Printf-style formats consuming (badCount, totalCount, joinedNames) for the
// "none" and "invalid" buckets. Members whose key lookup itself failed are
// reported separately: their key state is unknown, not absent.
func reportMemberKeyStatus(keysCmd string, members []string, okMsg, noKeyFmt, badKeyFmt string) int {
	noKey, badKey, errKey := classifyMembers(members, func(user string) string { return userKeyStatus(keysCmd, user) })
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

// sshdTOutput runs `sshd -T` with the given arguments; a seam for tests.
// sshd is found through the fixed PATH of setSystemPath.
var sshdTOutput = func(args ...string) ([]byte, error) {
	return exec.Command("sshd", args...).Output()
}

// sshdParamFor returns the effective value of an sshd_config keyword for the
// connection spec of `sshd -T -C` ("user=root", "user=root,addr=192.0.2.10");
// an empty spec evaluates without Match criteria. The bool is false if
// `sshd -T` could not run.
func sshdParamFor(keyword, connSpec string) (string, bool) {
	args := []string{"-T"}
	if connSpec != "" {
		args = append(args, "-C", connSpec)
	}
	out, err := sshdTOutput(args...)
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

// sshdKeysFileFor returns the effective AuthorizedKeysFile for connSpec; the
// bool is false if `sshd -T` could not run. A missing authorizedkeysfile line
// means none: since OpenSSH 10.5, AuthorizedKeysFile none is stored as an
// empty list (V_10_5_P1 servconf.c:450, CLEAR_ON_NONE_ARRAY(authorized_keys_files,
// num_authkeys_files, "none")), and `sshd -T` prints no line for an empty
// list (dump_cfg_strarray_oneline); 10.2 kept "none" as a list element and
// printed "authorizedkeysfile none". This holds only for this keyword.
func sshdKeysFileFor(connSpec string) (string, bool) {
	v, ok := sshdParamFor("authorizedkeysfile", connSpec)
	if ok && v == "" {
		return "none", true
	}
	return v, ok
}

// rootSSHDPolicy returns root's effective PermitRootLogin, AuthenticationMethods
// and AuthorizedKeysFile, and root's policy for each root_login_sources address.
func rootSSHDPolicy(rootSources []string) (permit, methods, keysFile string, sources []rootSourcePolicy) {
	methods, _ = sshdParam("authenticationmethods", "root")
	permit, _ = sshdParam("permitrootlogin", "root")
	keysFile, _ = sshdKeysFileFor("user=root")
	for _, src := range rootSources {
		spec := "user=root,addr=" + src
		p, _ := sshdParamFor("permitrootlogin", spec)
		m, _ := sshdParamFor("authenticationmethods", spec)
		k, _ := sshdKeysFileFor(spec)
		sources = append(sources, rootSourcePolicy{Source: src, Permit: p, Methods: m, KeysFile: k})
	}
	return permit, methods, keysFile, sources
}

// sshdParam is sshdParamFor for a user without an address.
func sshdParam(keyword, user string) (string, bool) {
	if user == "" {
		return sshdParamFor(keyword, "")
	}
	return sshdParamFor(keyword, "user="+user)
}

// isEnabled reports whether pam-device-auth is already wired into SSH auth,
// i.e. --enable has installed pam_device_auth.so into /etc/pam.d/sshd.
func isEnabled() bool {
	data, err := os.ReadFile("/etc/pam.d/sshd")
	if err != nil {
		return false
	}
	return pamStackUsesModule(data)
}

// pamStackUsesModule reports whether a PAM stack has a line that names
// pam_device_auth.so outside a comment. The package scripts use the same rule
// (grep '^[^#]*pam_device_auth\.so'), so a commented-out line is "not active"
// everywhere.
func pamStackUsesModule(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		code, _, _ := strings.Cut(line, "#")
		if strings.Contains(code, "pam_device_auth.so") {
			return true
		}
	}
	return false
}

// errNoPristinePAM marks a backupFile error where no pristine PAM stack is
// left to save or keep (as opposed to an I/O failure): the operator has to
// restore /etc/pam.d/sshd by hand.
var errNoPristinePAM = errors.New("no pristine PAM config")

// pristinePAMError says why data cannot serve as the rollback copy of a PAM
// stack, by the rule of valid_backup in debian/prerm and debian/postrm: it must
// be non-empty, have a line that starts with "auth" or "@include" (the Debian
// default has only '@include common-auth') and must not use pam_device_auth.so.
// nil means data is a valid rollback copy.
func pristinePAMError(data []byte) error {
	s := string(data)
	switch {
	case len(data) == 0:
		return errors.New("it is empty")
	case strings.Contains(s, "pam_device_auth.so"):
		return errors.New("it contains pam_device_auth.so")
	}
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "auth") || strings.HasPrefix(line, "@include") {
			return nil
		}
	}
	return errors.New("it has no line starting with auth or @include")
}

// backupFile copies the PAM stack src to dst, but only when dst does not
// already exist (an existing backup is the pristine original and must never be
// overwritten with an already-modified config). It reports whether a backup
// was written. On success dst is a valid rollback copy (pristinePAMError), the
// one the package's prerm requires before it lets the package go. Everything
// else is an error: an existing dst or a src that is not a valid copy and a
// missing src (openssh-server ships /etc/pam.d/sshd on every supported
// platform) wrap errNoPristinePAM; an unreadable src or dst and a failed write
// do not.
func backupFile(src, dst string) (bool, error) {
	existing, err := os.ReadFile(dst)
	if err == nil {
		if perr := pristinePAMError(existing); perr != nil {
			return false, fmt.Errorf("%w: existing backup %s is not a valid rollback copy: %v", errNoPristinePAM, dst, perr)
		}
		return false, nil
	}
	if !os.IsNotExist(err) {
		return false, fmt.Errorf("cannot check existing backup %s: %w", dst, err)
	}
	data, err := os.ReadFile(src)
	if os.IsNotExist(err) {
		return false, fmt.Errorf("%w: %s does not exist (the openssh-server package ships it)", errNoPristinePAM, src)
	}
	if err != nil {
		return false, fmt.Errorf("cannot read %s: %w", src, err)
	}
	if perr := pristinePAMError(data); perr != nil {
		return false, fmt.Errorf("%w: %s is not a valid rollback copy and no backup exists: %v", errNoPristinePAM, src, perr)
	}
	if err := atomicWriteFile(dst, data, 0644); err != nil {
		return false, err
	}
	return true, nil
}

// dropinNeedsRender reports whether --enable must (re)render the sshd drop-in:
// when it is missing, or when it does not reference the resolved
// sss_ssh_authorizedkeys path. The latter catches a stale drop-in that names
// another AuthorizedKeysCommand path, which would otherwise leave sshd serving
// no directory key.
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

// checkSSSDIfp verifies that path (the platform's InfoPipe responder,
// distro.Profile.SSSDIfpPath) exists. It ships in the sssd-dbus package on
// Debian, Ubuntu and the RHEL family alike.
func checkSSSDIfp(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("SSSD InfoPipe responder %s: %w; install the sssd-dbus package", path, err)
	}
	return nil
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

// rootSourcePolicy is root's effective sshd policy for one root_login_sources
// address; KeysFile is the effective AuthorizedKeysFile.
type rootSourcePolicy struct{ Source, Permit, Methods, KeysFile string }

// noKeysFile reports whether an effective AuthorizedKeysFile value is "none",
// so sshd reads no authorized_keys file for that connection.
func noKeysFile(v string) bool { return strings.EqualFold(strings.TrimSpace(v), "none") }

// rootLoginWithSources extends rootLoginCheck with root's AuthorizedKeysFile
// (keysFile) and the addresses from root_login_sources. With root_login "key",
// a global PermitRootLogin no is fine when a configured source still reaches
// root by key (Match Address), and a key path needs a key file: the drop-in
// sets AuthorizedKeysFile none for everyone but root. With root_login
// "disabled", any source that reaches root is a blocker.
func rootLoginWithSources(mode, permit, methods, keysFile string, sources []rootSourcePolicy) (ok, fatal bool, okMsg, badMsg string) {
	var keyFrom, allowFrom, noFileFrom []string
	for _, s := range sources {
		if s.Permit == "no" {
			continue
		}
		allowFrom = append(allowFrom, s.Source)
		if noKeysFile(s.KeysFile) {
			noFileFrom = append(noFileFrom, s.Source)
			continue
		}
		// OpenSSH up to 10.0 prints prohibit-password as without-password.
		if (s.Permit == "prohibit-password" || s.Permit == "without-password") && s.Methods == "publickey" && s.KeysFile != "" {
			keyFrom = append(keyFrom, s.Source)
		}
	}
	if mode == config.RootLoginDisabled {
		if len(allowFrom) > 0 {
			return false, true, "", "root_login is 'disabled' but sshd allows root from " + strings.Join(allowFrom, ", ") + " (Match Address)"
		}
		return rootLoginCheck(mode, permit, methods)
	}
	if permit == "no" && len(sources) > 0 {
		if len(noFileFrom) > 0 {
			msg := "root is allowed from " + strings.Join(noFileFrom, ", ") +
				" but AuthorizedKeysFile is none there; add AuthorizedKeysFile .ssh/authorized_keys to the Match block"
			if len(keyFrom) > 0 {
				msg += "; the emergency path works from " + strings.Join(keyFrom, ", ") + " (publickey)"
			}
			return false, false, "", msg
		}
		if len(keyFrom) > 0 {
			return true, false, "root: publickey only from " + strings.Join(keyFrom, ", ") + " (break-glass via Match Address)", ""
		}
		return false, false, "", "root SSH login is refused globally and from every root_login_sources address; there is no emergency path if LDAP, SSSD or the identity provider fail"
	}
	if permit != "no" && noKeysFile(keysFile) {
		return false, false, "", "root has no key source (AuthorizedKeysFile none); the emergency path does not work"
	}
	return rootLoginCheck(mode, permit, methods)
}

// sssdClientsExposure reports whether sssd.conf makes the directory "clients"
// attribute readable through the InfoPipe: the domain must fetch it under the
// name "clients" (ldap_user_extra_attrs = clients, or clients:<LDAP attribute>
// when the directory stores the allowlist in another attribute) and [ifp] must
// allow it (user_attributes = +clients). Without either, GetUserAttr returns an
// empty answer and the account-phase IP gate sees "no allowlist" for every user.
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
			case key == "ldap_user_extra_attrs" && strings.HasPrefix(section, "domain/") && (tok == "clients" || (strings.HasPrefix(tok, "clients:") && len(tok) > len("clients:"))):
				extraAttrs = true
			case key == "user_attributes" && section == "ifp" && tok == "+clients":
				ifp = true
			}
		}
	}
	return extraAttrs, ifp
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

// restartSSH restarts unit, the platform's sshd unit (distro.Profile.SSHService).
// The error carries the unit's output.
func restartSSH(run commandRunner, unit string) error {
	if out, err := run("systemctl", "restart", unit); err != nil {
		return fmt.Errorf("%w (%s: %s: %v)", errSSHRestart, unit, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// backupPAM is the first step of --enable: it saves the pristine PAM stack
// pamConf to pamBackup, or keeps a valid existing backup (a re-run of
// --enable). Without a valid rollback copy the package can never be removed
// (prerm refuses), so every failure is an error before anything else is
// written; when no pristine stack is left, the message names the manual step.
// A backup that is in place but whose directory sync failed is a valid copy,
// and the message says so.
func backupPAM(pamConf, pamBackup string) error {
	didBackup, err := backupFile(pamConf, pamBackup)
	if errors.Is(err, errNoPristinePAM) {
		return fmt.Errorf("cannot back up %s to %s: %w; nothing was changed: restore %s from your distribution's openssh-server package, remove any %s that is not a copy of it, then run 'pam-device-auth --enable' again",
			pamConf, pamBackup, err, pamConf, pamBackup)
	}
	if errors.Is(err, errWrittenNotSynced) {
		return fmt.Errorf("cannot back up %s to %s: %w; %s is in place as a valid copy of %s; nothing else was changed, run 'pam-device-auth --enable' again",
			pamConf, pamBackup, err, pamBackup, pamConf)
	}
	if err != nil {
		return fmt.Errorf("cannot back up %s to %s: %w; nothing was changed", pamConf, pamBackup, err)
	}
	if didBackup {
		fmt.Println("Backed up original PAM config")
	}
	return nil
}

// activatePAM installs the template pamSrc as pamConf atomically, so a crash
// or full disk can never leave a truncated PAM stack that also breaks root's
// break-glass login. backupPAM has saved the original before.
func activatePAM(pamConf, pamSrc string) error {
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

// detectPlatform, loadConfig, runPreflightFn and runEnableStepsFn are stages of
// --enable, --check and --setup-ldap; seams so a test can run the commands
// with every side-effecting stage stubbed out.
var (
	detectPlatform   = distro.Detect
	loadConfig       = config.Load
	runPreflightFn   = runPreflight
	runEnableStepsFn = runEnableSteps
)

// requirePlatform is the first step of --enable, --check and --setup-ldap: it
// returns the Profile of a supported platform and refuses everything else
// before any command reads the config or touches the host.
func requirePlatform() distro.Profile {
	prof, err := detectPlatform()
	if err != nil {
		fail("%v", err)
	}
	return prof
}

// enableSteps are the side-effecting activation steps of --enable, injectable
// so the ordering contract is testable.
type enableSteps struct {
	backupPAM    func() error
	renderDropin func() error
	activatePAM  func() error
	restartSSH   func() error
}

// runEnableSteps runs the steps in the only safe order: the PAM backup comes
// first (without a valid rollback copy nothing is written), the sshd drop-in
// must be valid before the PAM stack is switched, and sshd is restarted last.
// A failing step stops the sequence: a rejected drop-in must never be
// followed by a PAM switch or an sshd restart.
func runEnableSteps(s enableSteps) error {
	if err := s.backupPAM(); err != nil {
		return err
	}
	if err := s.renderDropin(); err != nil {
		return err
	}
	if err := s.activatePAM(); err != nil {
		return err
	}
	return s.restartSSH()
}

func runEnable() {
	// Refuse an unsupported platform first, before preflight and before any
	// step writes the sshd drop-in or the PAM stack.
	prof := requirePlatform()

	// Run the full preflight and refuse to activate on any blocker, so --enable
	// never wires PAM/sshd against a MITM'd issuer or a directory that cannot
	// resolve users / serve keys (which would lock non-root users out).
	if fails, _ := runPreflightFn(prof); fails > 0 {
		fmt.Fprintf(os.Stderr, "\nFAIL: %d blocker(s); refusing to activate. Fix the [FAIL] items above (see --check).\n", fails)
		os.Exit(1)
	}
	fmt.Println()

	// runPreflight already loaded and validated the config; reload it here for
	// the service-group list the sshd drop-in needs.
	cfg, err := loadConfig("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: config error: %v\n", err)
		os.Exit(1)
	}

	if isEnabled() {
		fmt.Println("Note: pam-device-auth is already active; re-applying config and restarting sshd.")
	}

	shareDir := "/usr/share/pam-device-auth/config"
	sshdConf := sshdDropinPath
	sssCmd := prof.SSSAuthKeysPath

	err = runEnableStepsFn(enableSteps{
		backupPAM: func() error { return backupPAM("/etc/pam.d/sshd", "/etc/pam.d/sshd.original") },
		// Render the drop-in from the platform's sss_ssh_authorizedkeys path
		// (distro.Profile.SSSAuthKeysPath) instead of copying the packaged
		// template, so it matches the checked binary. writeSshdDropin validates
		// with `sshd -t` and rolls back on rejection.
		renderDropin: func() error {
			if !dropinNeedsRender(sshdConf, sssCmd, cfg.RootLogin) {
				return nil
			}
			if err := checkSSSAuthKeys(sssCmd); err != nil {
				return fmt.Errorf("%w; run --setup-ldap first", err)
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
			return activatePAM("/etc/pam.d/sshd", shareDir+"/"+prof.PamTemplate)
		},
		restartSSH: func() error { return restartSSH(execRunner, prof.SSHService) },
	})
	if errors.Is(err, errSSHRestart) {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		fmt.Fprintln(os.Stderr, "pam-device-auth is NOT fully active: the PAM config and sshd drop-in are written, but sshd still runs the old configuration.")
		fmt.Fprintf(os.Stderr, "Run: systemctl restart %s, then 'pam-device-auth --check'.\n", prof.SSHService)
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

// systemPath is the PATH of every command the helper runs. It is the value
// the PAM module sets for the login modes (pam_device_auth.c).
const systemPath = "/usr/sbin:/usr/bin:/sbin:/bin"

// setSystemPath replaces PATH with systemPath. The CLI commands run sshd,
// visudo, pam-auth-update, sss_cache and userdel by name; a root shell that
// came from `su` has no sbin directory in its PATH on Debian, and the caller's
// PATH should not decide which binaries a root tool runs anyway.
func setSystemPath() {
	os.Setenv("PATH", systemPath)
}

// discoveryTimingLimit is how long the discovery request of --check may take
// before it is reported.
const discoveryTimingLimit = 2 * time.Second

// discoveryTiming is the --check result for the duration of the discovery
// request. Every login makes requests to the same host, so a slow answer here
// is a slow login. The usual cause is DNS: the helper is a static binary and
// uses Go's resolver, which has no cache and waits its full timeout (5 s per
// name server) when the first name server of /etc/resolv.conf does not answer
// properly, where the C library moves on at once.
//
// One slow request does not show that: a name server that had to ask upstream
// first, or a busy identity provider, delays a single request. So a request
// above the limit is repeated once (again, over a new connection with a new
// name lookup), and only two slow requests in a row are reported.
func discoveryTiming(first time.Duration, again func() (time.Duration, error)) (ok bool, okMsg, badMsg string) {
	first = first.Round(10 * time.Millisecond)
	if first <= discoveryTimingLimit {
		return true, fmt.Sprintf("discovery answered in %s", first), ""
	}
	second, err := again()
	second = second.Round(10 * time.Millisecond)
	switch {
	case err != nil:
		return false, "", fmt.Sprintf("discovery took %s (more than %s) and a second request failed: %v",
			first, discoveryTimingLimit, err)
	case second <= discoveryTimingLimit:
		return true, fmt.Sprintf("discovery answered in %s (the first request took %s)", second, first), ""
	}
	return false, "", fmt.Sprintf("discovery took %s and %s on two requests in a row (more than %s): every login waits like this; "+
		"check DNS first: the helper asks the name servers of /etc/resolv.conf in order and waits 5 s for one that does not answer properly",
		first, second, discoveryTimingLimit)
}

func main() {
	setSystemPath()
	debug := hasFlag(os.Args[1:], "--debug")
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--version":
			fmt.Printf("pam-device-auth %s\n", VERSION)
			os.Exit(0)
		case "--help":
			fmt.Println("Usage: pam-device-auth [--debug] [--version] [--check] [--setup-ldap] [--enable] [--migrate-config] [--prepare-log] [--pam-acct] [--help]")
			fmt.Println("  SSH authentication via OIDC Device Authorization Grant (RFC 8628)")
			fmt.Println("")
			fmt.Println("  --check       Pre-activation preflight: config, OIDC, directory/SSSD, sshd factors")
			fmt.Println("  --setup-ldap  Configure the SSSD directory identity from config (NSS + sudo)")
			fmt.Println("  --enable      Activate PAM authentication (runs --check first)")
			fmt.Println("  --migrate-config  Set ldap.profile = \"lldap\" in a 0.6.x config that has none (run by the package on upgrade)")
			fmt.Println("  --prepare-log  Create the log file or check it: a regular file, mode at most 0640 (run by the package on install and upgrade)")
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
		case "--migrate-config":
			os.Exit(runMigrateConfig(config.DefaultConfigPath, os.Stdout, os.Stderr))
		case "--pam-acct":
			os.Exit(runPamAcct())
		case "--prepare-log":
			os.Exit(runPrepareLog())
		}
	}

	log, err := logger.NewLogger(logFile, debug)
	if err != nil {
		// Fail closed (no audit log, no login), but not invisibly: sshd discards
		// our stderr and the C side only sees "exit code 1", so also send the
		// reason to syslog (authpriv).
		reportLogFailure(logFailureMessage(err, "denying login (fail closed)"))
		os.Exit(1)
	}
	defer log.Close()

	log.Info("pam-device-auth %s starting", VERSION)

	cfg, err := config.Load("")
	if err != nil {
		log.Error("Config error: %v", err)
		os.Exit(1)
	}
	// Findings that must not stop a login (an upgrade must not lock a host
	// out over a stray key) but must not stay silent either.
	for _, line := range configWarningLines(cfg) {
		log.Warn("%s", line)
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
	var endpoints *discovery.Endpoints
	timed(log, "Discovery", func() {
		endpoints, err = discovery.FetchCached(discoveryCtx, httpClient, cfg.IssuerURL, log.Debug, log.Warn)
	})
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
	// (via SSSD/NSS). pam-device-auth is only the OIDC SSH-login layer:
	// it validates the OIDC token (signature/issuer/client/exp/iat, required
	// role, optional required_acr) and grants or denies the login. It never
	// reads /etc/shadow, prompts for a local password, or manages users.
	// The exit status is the outcome of the flow and nothing else: 0 only for
	// an explicit allow.
	flow := &authFlow{
		log: log, cfg: cfg, client: httpClient, endpoints: endpoints,
		io:  &authIO{in: bufio.NewReader(os.Stdin), out: os.Stdout},
		nss: nssLookup,
	}
	os.Exit(flow.run(sshUser, clientIP).exitCode())
}

// qrMaxURLBytes is the longest verification URL rendered as a QR: QR version 5
// holds 84 bytes at ECC M.
const qrMaxURLBytes = 84

// canRenderQR checks if the URL would produce a QR code small enough to scan.
// Returns false if the URL would require QR version > 5.
func canRenderQR(url string) bool {
	return len(url) <= qrMaxURLBytes
}

// logFailureMessage is the text reported when logger.NewLogger(logFile) fails;
// outcome says what the caller does about it. NewLogger fails either opening
// the file or, when its mode is not 0640, setting it to 0640
// (logger.ErrLogMode, whose wrapped *os.PathError already names chmod and the
// path).
func logFailureMessage(err error, outcome string) string {
	if errors.Is(err, logger.ErrLogMode) {
		return fmt.Sprintf("pam-device-auth: %v; %s", err, outcome)
	}
	return fmt.Sprintf("pam-device-auth: cannot open %s: %v; %s", logFile, err, outcome)
}

// reportLogFailure writes msg to stderr and, best effort, to syslog: sshd
// discards the helper's stderr, so syslog is where an operator finds out why
// logins are being denied.
func reportLogFailure(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	syslogAuthErr(msg)
}

// syslogAuthErr sends msg to syslog (authpriv, err), best effort; a variable so
// tests do not write the host's syslog.
var syslogAuthErr = func(msg string) {
	if w, err := syslog.New(syslog.LOG_AUTHPRIV|syslog.LOG_ERR, "pam-device-auth"); err == nil {
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
// Supports both plain IPs ("198.51.100.2") and CIDR notation ("198.51.100.0/24").
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
			// client IP may be IPv4-mapped IPv6 ("::ffff:198.51.100.21") while the
			// allowlist holds the plain IPv4 form, or vice versa.
			if entryIP := net.ParseIP(entry); entryIP != nil && entryIP.Equal(ip) {
				return true
			}
		}
	}
	return false
}
