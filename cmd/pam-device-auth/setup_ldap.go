package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/distro"
)

// writeSSSDConfAt atomically writes sssd.conf-style content to path (0600, and
// chowned root:root for the real path) and returns a restore func that
// reinstates the prior file — or removes a newly-created one — if a downstream
// step (e.g. `systemctl restart sssd`) rejects the new config. A corrupt
// sssd.conf takes down NSS identity and locks out all directory logins, so this
// mirrors writeSshdDropin/writeSudoers: never leave a partial or rejected
// config behind. Path-parameterized for testability.
func writeSSSDConfAt(path, content string) (restore func(), err error) {
	prior, readErr := os.ReadFile(path) // readErr == nil => a file existed to restore
	if err := atomicWriteFile(path, []byte(content), 0600); err != nil {
		return nil, err
	}
	_ = os.Chown(path, 0, 0) // best-effort; no-op/EPERM off-target (tests)

	restore = func() {
		if readErr == nil {
			// The rollback must be as crash-safe as the forward write: a
			// truncate-then-write here could leave a partial sssd.conf —
			// exactly the failure mode this function exists to prevent.
			_ = atomicWriteFile(path, prior, 0600)
			_ = os.Chown(path, 0, 0)
		} else {
			_ = os.Remove(path)
		}
	}
	return restore, nil
}

// atomicWriteFile writes content to path via a same-directory temp file and
// rename, so the target is never observable in a truncated or partial state.
func atomicWriteFile(path string, content []byte, mode os.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup of the temp file on any failure before the rename.
	defer func() {
		if err != nil {
			os.Remove(tmpName)
		}
	}()
	if err = tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err = tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s into place: %w", path, err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open parent directory for %s: %w", path, err)
	}
	if err = dir.Sync(); err != nil {
		dir.Close()
		return fmt.Errorf("sync parent directory for %s: %w", path, err)
	}
	if err = dir.Close(); err != nil {
		return fmt.Errorf("close parent directory for %s: %w", path, err)
	}
	return nil
}

var (
	// groupNameRe matches a safe Unix group name. The group name is rendered
	// both into sudoers (%name) and into the LDAP access filter (cn=name), so
	// restricting it to this charset guarantees it carries no sudoers- or
	// LDAP-filter-significant metacharacters (space, '=', ':', '!', '#', and
	// the filter metacharacters ()*\,).
	groupNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)
	// dnRe matches a conservative LDAP distinguished-name charset: ordinary
	// value characters plus the RDN separators ('=' and ','). It deliberately
	// rejects the LDAP-filter metacharacters ()*\ and every control character,
	// so a DN interpolated into an ldap_*_search_base line or into the
	// (memberOf=cn=<group>,<base>) access filter can neither inject an sssd.conf
	// directive (newline) nor break out of the filter structure.
	dnRe = regexp.MustCompile(`^[A-Za-z0-9 ._=,-]+$`)
)

// validateLDAPConfig is the security boundary for directory-mode setup. Every
// field it checks is written verbatim into a config file consumed by a
// privileged service (sssd.conf, sudoers), so this single choke point must
// reject anything that could inject an INI directive (a newline), widen the
// LDAP access filter (filter metacharacters in a DN), or alter the sudoers
// grant (sudoers metacharacters in a group name). It returns an error rather
// than exiting so it can be unit-tested; the caller maps the error to fail().
func validateLDAPConfig(l *config.LDAPConfig) error {
	if l == nil || l.URI == "" || l.BaseDN == "" || l.BindDN == "" || l.BindPassword == "" || l.AccessGroup == "" || l.AdminGroup == "" {
		return fmt.Errorf("config 'ldap' block incomplete: need uri, base_dn, bind_dn, bind_password, access_group, admin_group")
	}
	// Reject control chars in EVERY value written into sssd.conf — including the
	// optional search bases, which previously bypassed this guard. A stray
	// newline injects an arbitrary SSSD directive (e.g. a TLS downgrade or an
	// access-filter override that defeats the login gate). The error names the
	// field only, never echoing the value (bind_password is a secret).
	for field, v := range map[string]string{
		"uri": l.URI, "base_dn": l.BaseDN, "bind_dn": l.BindDN,
		"bind_password": l.BindPassword, "access_group": l.AccessGroup,
		"admin_group": l.AdminGroup, "user_search_base": l.UserSearchBase,
		"group_search_base": l.GroupSearchBase,
	} {
		if strings.ContainsAny(v, "\n\r") {
			return fmt.Errorf("ldap.%s contains a newline; refusing (sssd.conf injection)", field)
		}
	}
	// Group names must be bare Unix group names: they land in sudoers (%name)
	// and in the access filter (cn=name).
	if !groupNameRe.MatchString(l.AccessGroup) {
		return fmt.Errorf("ldap.access_group must be a bare group name [A-Za-z_][A-Za-z0-9_-]*, got %q", l.AccessGroup)
	}
	if !groupNameRe.MatchString(l.AdminGroup) {
		return fmt.Errorf("ldap.admin_group must be a bare group name [A-Za-z_][A-Za-z0-9_-]*, got %q", l.AdminGroup)
	}
	// Base/search DNs are interpolated into ldap_*_search_base lines and the
	// access filter; constrain them to a conservative DN charset. Optional
	// search bases may be empty (they default from base_dn at render time).
	for field, v := range map[string]string{
		"base_dn": l.BaseDN, "user_search_base": l.UserSearchBase, "group_search_base": l.GroupSearchBase,
	} {
		if v == "" {
			continue
		}
		if !dnRe.MatchString(v) {
			return fmt.Errorf("ldap.%s contains characters not allowed in a DN [A-Za-z0-9 ._=,-]: %q", field, v)
		}
	}
	// Service-account and nopasswd-sudo group names land in the widened access
	// filter and in sudoers, same as access_group/admin_group above.
	for _, g := range l.ServiceAccountGroups {
		if !groupNameRe.MatchString(g) {
			return fmt.Errorf("ldap.service_account_groups entry %q must be a bare group name [A-Za-z_][A-Za-z0-9_-]*", g)
		}
	}
	for _, g := range l.NopasswdSudoGroups {
		if !groupNameRe.MatchString(g) {
			return fmt.Errorf("ldap.nopasswd_sudo_groups entry %q must be a bare group name [A-Za-z_][A-Za-z0-9_-]*", g)
		}
	}
	return nil
}

// ldapRenderData is the validated set of values interpolated into sssd.conf.
// It is a plain data carrier so renderSSSDConf can be unit-tested without a
// config.LDAPConfig or any filesystem/process access.
type ldapRenderData struct {
	URI           string
	BaseDN        string
	UserBase      string
	GroupBase     string
	BindDN        string
	BindPassword  string
	AccessGroup   string
	ServiceGroups []string
}

// renderSSSDConf renders the sssd.conf content for directory mode. caCertPath
// is profile-supplied (distro.Profile.CACertPath) so the same template works
// across Debian (/etc/ssl/certs/ca-certificates.crt) and RHEL
// (/etc/pki/tls/certs/ca-bundle.crt). Pure transform — no I/O — so it is
// testable independent of validateLDAPConfig and the atomic-write path.
func renderSSSDConf(d ldapRenderData, caCertPath string) string {
	// Access filter (model B): access_group plus every service group, OR-ed, so
	// membership in ANY auth-tier group grants login. Single group ⇒ the plain
	// (memberOf=...) form (byte-identical to the pre-tier config).
	filter := fmt.Sprintf("(memberOf=cn=%s,%s)", d.AccessGroup, d.GroupBase)
	if len(d.ServiceGroups) > 0 {
		var b strings.Builder
		b.WriteString("(|")
		b.WriteString(fmt.Sprintf("(memberOf=cn=%s,%s)", d.AccessGroup, d.GroupBase))
		for _, g := range d.ServiceGroups {
			b.WriteString(fmt.Sprintf("(memberOf=cn=%s,%s)", g, d.GroupBase))
		}
		b.WriteString(")")
		filter = b.String()
	}
	return fmt.Sprintf(`[sssd]
config_file_version = 2
services = nss, pam, ssh, ifp
domains = nkit

[nss]
filter_users = root
filter_groups = root

[pam]

[ssh]

[domain/nkit]
id_provider = ldap
auth_provider = ldap
access_provider = ldap
ldap_uri = %s
ldap_search_base = %s
ldap_user_search_base = %s
ldap_group_search_base = %s
ldap_default_bind_dn = %s
ldap_default_authtok = %s
ldap_schema = rfc2307bis
ldap_user_extra_attrs = clients:clients
ldap_user_object_class = posixAccount
ldap_user_name = uid
ldap_user_ssh_public_key = sshPublicKey
ldap_user_uid_number = uidNumber
ldap_user_gid_number = gidNumber
ldap_group_object_class = groupOfNames
ldap_group_name = cn
ldap_group_member = member
ldap_group_gid_number = gidNumber
ldap_id_mapping = false
ldap_tls_reqcert = hard
ldap_tls_cacert = %s
override_homedir = /home/%%u
default_shell = /bin/bash
ldap_access_filter = %s
enumerate = false
cache_credentials = false
entry_cache_timeout = 600

[ifp]
user_attributes = +clients
`, d.URI, d.BaseDN, d.UserBase, d.GroupBase, d.BindDN, d.BindPassword, caCertPath, filter)
}

// runSetupLDAP configures the host for "directory mode": SSSD resolves users
// from LLDAP (NSS best practice), pam-device-auth adds the OIDC SSH layer. It
// is idempotent and reads everything from the JSON config's `ldap` block. The
// RO bind password is needed only here; it is written into the root-only
// /etc/sssd/sssd.conf for SSSD's runtime use.
//
// Steps: validate config -> ensure SSSD packages -> write sssd.conf ->
// enable mkhomedir -> nsswitch (sss) -> sudoers (%admin_group) -> restart sssd.
// (mkhomedir before nsswitch on RHEL: authselect owns nsswitch.conf too.)
func runSetupLDAP() {
	cfg, err := config.Load("")
	if err != nil {
		fail("config error: %v", err)
	}
	l := cfg.LDAP
	prof := distro.Detect()
	// Single security choke point: validates every directory value before any
	// of them is written into sssd.conf / sudoers (see validateLDAPConfig).
	if err := validateLDAPConfig(l); err != nil {
		fail("%v", err)
	}
	userBase := l.UserSearchBase
	if userBase == "" {
		userBase = "ou=people," + l.BaseDN
	}
	groupBase := l.GroupSearchBase
	if groupBase == "" {
		groupBase = "ou=groups," + l.BaseDN
	}

	ensureSSSDPackages(prof)

	// 1) /etc/sssd/sssd.conf (0600 root). auth_provider=ldap so sudo (%admin_group)
	//    re-auths against the LLDAP password via pam_sss; access_provider gates
	//    pam_sss services (sudo/su/login) to access_group members.
	sssdConf := renderSSSDConf(ldapRenderData{
		URI:           l.URI,
		BaseDN:        l.BaseDN,
		UserBase:      userBase,
		GroupBase:     groupBase,
		BindDN:        l.BindDN,
		BindPassword:  l.BindPassword,
		AccessGroup:   l.AccessGroup,
		ServiceGroups: l.ServiceAccountGroups,
	}, prof.CACertPath)

	restoreSSSD, err := writeSSSDConfAt("/etc/sssd/sssd.conf", sssdConf)
	if err != nil {
		fail("write /etc/sssd/sssd.conf: %v", err)
	}
	fmt.Println("Wrote /etc/sssd/sssd.conf (0600)")

	// 2) auto-create home dirs on first login (directory provides no home).
	//    On RHEL this is wired via authselect, which also owns nsswitch.conf —
	//    ensureNsswitchSSS() below MUST run after this so authselect doesn't
	//    clobber the 'sss' entries it just added.
	switch prof.PamWiring {
	case "authselect":
		// `select sssd` (not just enable-feature) is required: on a minimal RHEL
		// host no authselect profile is active, and it is what actually wires
		// pam_sss into system-auth/password-auth (which our sshd PAM template
		// includes) plus nsswitch. `with-mkhomedir` adds pam_oddjob_mkhomedir;
		// --force overwrites any stock profile so directory login works headless.
		if out, err := exec.Command("authselect", "select", "sssd", "with-mkhomedir", "--force").CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "warn: authselect select sssd with-mkhomedir: %s: %v\n", strings.TrimSpace(string(out)), err)
		} else {
			exec.Command("systemctl", "enable", "--now", "oddjobd").Run()
			fmt.Println("SSSD PAM/nsswitch wired via authselect (with mkhomedir)")
		}
	default:
		if out, err := exec.Command("pam-auth-update", "--enable", "mkhomedir").CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "warn: pam-auth-update mkhomedir: %s: %v\n", strings.TrimSpace(string(out)), err)
		} else {
			fmt.Println("pam_mkhomedir enabled")
		}
	}

	// 3) nsswitch: ensure 'sss' on passwd/group/shadow. Must run after the
	//    mkhomedir wiring above (see comment there) so authselect's nsswitch
	//    rewrite is not overwritten/clobbered by our own edit, and vice versa.
	if err := ensureNsswitchSSS(); err != nil {
		fail("nsswitch: %v", err)
	}
	fmt.Println("nsswitch.conf: sss enabled for passwd/group/shadow")

	// 4) sudoers: members of admin_group get sudo (password-prompted -> LLDAP via pam_sss);
	//    members of nopasswd_sudo_groups get passwordless sudo (opt-in, Task 2/4).
	if err := writeSudoers(prof, l.AdminGroup, l.NopasswdSudoGroups); err != nil {
		fail("sudoers: %v", err)
	}
	fmt.Printf("sudoers: %%%s may sudo (LLDAP password)\n", l.AdminGroup)

	// 5) sshd drop-in: non-root needs key (from LLDAP via sss_ssh_authorizedkeys)
	//    AND OIDC; root stays key-only (break-glass via local authorized_keys).
	//    Prefer the ACTUAL on-disk path of sss_ssh_authorizedkeys (Rocky 9/10 ship
	//    it in /usr/bin, older RHEL in /usr/libexec/sssd) over the profile default,
	//    so the AuthorizedKeysCommand sshd runs really exists — a wrong path makes
	//    sshd serve no directory key and silently falls back to password.
	sssCmd := sssAuthorizedKeysCmd()
	if sssCmd == "" {
		sssCmd = prof.SSSAuthKeysPath // fall back to the distro default if not yet on disk
	}
	if err := writeSshdDropin(sssCmd, l.ServiceAccountGroups); err != nil {
		fail("sshd config: %v", err)
	}

	// 6) (re)start SSSD
	if out, err := exec.Command("systemctl", "enable", "--now", "sssd").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "warn: enable sssd: %s\n", strings.TrimSpace(string(out)))
	}
	exec.Command("sss_cache", "-E").Run()
	if out, err := exec.Command("systemctl", "restart", "sssd").CombinedOutput(); err != nil {
		// New sssd.conf was rejected — reinstate the prior known-good config so
		// directory identity (and thus non-root login) is not left broken.
		restoreSSSD()
		exec.Command("systemctl", "restart", "sssd").Run() // best-effort, on the restored config
		fail("restart sssd: %s: %v (restored previous sssd.conf)", strings.TrimSpace(string(out)), err)
	}
	fmt.Println("sssd restarted")

	migrateLocalShadowing()

	fmt.Println("\nDirectory mode configured. Verify with:  getent -s sss passwd <a-directory-user>")
	fmt.Printf("Then enable the OIDC SSH layer:  pam-device-auth --enable\n")
}

// ensureSSSDPackages installs the SSSD LDAP/NSS/PAM packages if sssd is
// absent, using the distro profile's install command and package list.
func ensureSSSDPackages(prof distro.Profile) {
	// Install the SSSD (and, on RHEL, the mkhomedir) packages unconditionally.
	// This is deliberately NOT gated on the `sssd` daemon already being present:
	// on RHEL the daemon ships in sssd-common and can exist WITHOUT the LDAP
	// backend (sssd-ldap / libsss_ldap.so), and skipping the install then leaves
	// the directory domain unable to start ("Could not restart critical service").
	// Package managers no-op on already-installed packages, so running every time
	// is safe and idempotent.
	pkgs := append(append([]string{}, prof.SSSDPackages...), prof.MkhomedirPackages...)
	fmt.Printf("Installing %s ...\n", strings.Join(pkgs, " "))
	args := append([]string{"install", "-y"}, pkgs...)
	cmd := exec.Command(prof.InstallCmd, args...)
	if prof.InstallCmd == "apt-get" {
		exec.Command("apt-get", "update").Run() // refresh stale index (best-effort)
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		fail("%s install %s: %s: %v", prof.InstallCmd, strings.Join(pkgs, " "), strings.TrimSpace(string(out)), err)
	}
}

// nsswitchWithSSS appends 'sss' to the passwd/group/shadow databases in
// nsswitch.conf content if not already present. Pure transform so it is
// testable without touching /etc.
func nsswitchWithSSS(data []byte) ([]byte, bool) {
	lines := strings.Split(string(data), "\n")
	changed := false
	for i, line := range lines {
		for _, db := range []string{"passwd:", "group:", "shadow:"} {
			if strings.HasPrefix(line, db) && !strings.Contains(line, "sss") {
				lines[i] = strings.TrimRight(line, " \t") + " sss"
				changed = true
			}
		}
	}
	return []byte(strings.Join(lines, "\n")), changed
}

// ensureNsswitchSSS rewrites /etc/nsswitch.conf crash-safely: a torn write
// here would break ALL name resolution on the host (PDA-BUG-004).
func ensureNsswitchSSS() error {
	data, err := os.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		return err
	}
	out, changed := nsswitchWithSSS(data)
	if !changed {
		return nil
	}
	return atomicWriteFile("/etc/nsswitch.conf", out, 0644)
}

// renderSudoers builds the single tool-managed sudoers drop-in. The admin group
// gets password sudo; each nopasswd group gets NOPASSWD:ALL. NOPASSWD rules come
// LAST so that for a user in both, sudo's last-match-wins yields NOPASSWD.
func renderSudoers(adminGroup string, nopasswdGroups []string) string {
	var b strings.Builder
	b.WriteString("# Managed by pam-device-auth --setup-ldap\n")
	b.WriteString(fmt.Sprintf("%%%s ALL=(ALL:ALL) ALL\n", adminGroup))
	for _, g := range nopasswdGroups {
		b.WriteString(fmt.Sprintf("%%%s ALL=(ALL:ALL) NOPASSWD:ALL\n", g))
	}
	return b.String()
}

// writeSudoers writes a validated sudoers drop-in granting the admin group sudo
// and, for each entry in nopasswdGroups, passwordless sudo. Ensures sudo is
// installed (minimal LXC images may lack it, via the profile's install
// command/package) and that /etc/sudoers.d exists before writing. All rules
// are consolidated into the single tool-managed file so uninstall/cleanup only
// has to reason about one path.
func writeSudoers(prof distro.Profile, adminGroup string, nopasswdGroups []string) error {
	if _, err := exec.LookPath("visudo"); err != nil {
		args := append([]string{"install", "-y"}, prof.SudoInstall...)
		cmd := exec.Command(prof.InstallCmd, args...)
		if prof.InstallCmd == "apt-get" {
			exec.Command("apt-get", "update").Run() // refresh stale index (best-effort)
			cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("install %s: %s: %w", strings.Join(prof.SudoInstall, " "), strings.TrimSpace(string(out)), err)
		}
	}
	if err := os.MkdirAll("/etc/sudoers.d", 0755); err != nil {
		return fmt.Errorf("mkdir /etc/sudoers.d: %w", err)
	}
	path := "/etc/sudoers.d/pam-device-auth"
	content := renderSudoers(adminGroup, nopasswdGroups)
	prior, priorErr := os.ReadFile(path) // priorErr==nil means a drop-in existed to restore
	if err := atomicWriteFile(path, []byte(content), 0440); err != nil {
		return err
	}
	// Validate the whole sudoers set; restore the previous drop-in (or remove
	// ours) if it would break sudo — never leave a broken state behind.
	if out, err := exec.Command("visudo", "-c").CombinedOutput(); err != nil {
		var restoreErr error
		if priorErr == nil {
			restoreErr = atomicWriteFile(path, prior, 0440)
		} else {
			restoreErr = os.Remove(path)
		}
		if restoreErr != nil {
			return fmt.Errorf("visudo -c rejected the drop-in (%s) AND restore failed (%v); fix %s manually: %w",
				strings.TrimSpace(string(out)), restoreErr, path, err)
		}
		return fmt.Errorf("visudo -c rejected the drop-in (%s): %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// renderSshdDropin renders the directory-mode sshd drop-in written by
// --setup-ldap. Non-root: publickey (served exclusively by
// sssAuthKeysPath, a distro.Profile-supplied path to sss_ssh_authorizedkeys —
// local authorized_keys files are disabled) AND keyboard-interactive (OIDC) —
// true 2FA whose first factor lives in the directory. Service accounts (members
// of serviceGroups, already name-validated by validateLDAPConfig before this is
// called) get a Match Group block overriding AuthenticationMethods to
// publickey-only, since automation cannot complete an interactive OIDC prompt.
// Root: local key only (break-glass), restored via the Match block. Pure
// transform — no I/O — so it is testable independent of the
// atomic-write/sshd-t validation path.
func renderSshdDropin(sssAuthKeysPath string, serviceGroups []string) string {
	base := fmt.Sprintf(`# Managed by pam-device-auth --setup-ldap (directory mode)
KbdInteractiveAuthentication yes
PermitRootLogin prohibit-password
UsePAM yes
PasswordAuthentication no
MaxAuthTries 3
LogLevel DEBUG1
# Non-root: SSH key (from LLDAP via SSSD) AND OIDC (keyboard-interactive/PAM).
# AuthorizedKeysFile none: local ~/.ssh/authorized_keys must NOT work for
# non-root, otherwise a same-named local account bypasses directory revocation.
AuthenticationMethods publickey,keyboard-interactive:pam
AuthorizedKeysFile none
AuthorizedKeysCommand %s
AuthorizedKeysCommandUser nobody
`, sssAuthKeysPath)

	// Service accounts (automation/management): directory key ONLY, no OIDC.
	// A Match block overrides the global AuthenticationMethods for these members;
	// their key is still served exclusively by sss_ssh_authorizedkeys.
	if len(serviceGroups) > 0 {
		base += fmt.Sprintf(`
# Service accounts (LLDAP service groups): key-only (no OIDC) for automation.
Match Group %s
    AuthenticationMethods publickey
`, strings.Join(serviceGroups, ","))
	}

	// Root: local SSH key only (break-glass); root never uses OIDC/SSSD.
	base += `
Match User root
    AuthenticationMethods publickey
    AuthorizedKeysFile .ssh/authorized_keys
`
	return base
}

// writeSshdDropin writes the directory-mode sshd drop-in: non-root must satisfy
// publickey (key fetched from LLDAP via sssAuthKeysPath) AND
// keyboard-interactive (OIDC via pam_device_auth) — true 2FA. Root stays
// key-only (break-glass): the root Match block restores the local
// AuthorizedKeysFile, so root's ~/.ssh/authorized_keys keeps working
// regardless of the LLDAP command. The file is validated with `sshd -t` and
// reverted on failure; it takes effect at the next sshd restart (performed by
// `--enable`), avoiding a lockout window.
func writeSshdDropin(sssAuthKeysPath string, serviceGroups []string) error {
	path := "/etc/ssh/sshd_config.d/10-pam-device-auth.conf"
	backup, readErr := os.ReadFile(path) // readErr==nil means a file existed to restore
	content := renderSshdDropin(sssAuthKeysPath, serviceGroups)
	if err := atomicWriteFile(path, []byte(content), 0644); err != nil {
		return err
	}
	if out, err := exec.Command("sshd", "-t").CombinedOutput(); err != nil {
		var restoreErr error
		if readErr == nil {
			restoreErr = atomicWriteFile(path, backup, 0644)
		} else {
			restoreErr = os.Remove(path)
		}
		if restoreErr != nil {
			return fmt.Errorf("sshd -t rejected drop-in (%s) AND rollback failed (%v); fix %s manually before restarting sshd: %w",
				strings.TrimSpace(string(out)), restoreErr, path, err)
		}
		return fmt.Errorf("sshd -t rejected drop-in (%s): %w", strings.TrimSpace(string(out)), err)
	}
	fmt.Println("Wrote sshd drop-in: publickey,keyboard-interactive (2FA), local keys disabled for non-root")
	return nil
}

// migrateLocalShadowing automatically migrates pre-existing LOCAL accounts (in
// /etc/passwd) whose name also exists in the directory with a DIFFERENT uid.
// Because nsswitch resolves `files` before `sss`, such a local account would
// otherwise shadow the directory identity. For each collision it: kills the
// user's processes, removes the LOCAL account (keeping the home directory), and
// re-owns the home to the directory uid:gid so files are preserved and the user
// now resolves via the directory. Only homes under /home are re-chowned (a
// reused uid must not cause chown of system files elsewhere).
func migrateLocalShadowing() {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return
	}
	// Pass 1 — find local accounts that collide with (shadow) a directory user
	// at a different uid. Collect them first so the destructive scope can be
	// shown BEFORE anything is deleted.
	type shadowed struct{ name, localUID, dirUID, dirGID, home string }
	var victims []shadowed
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 6 {
			continue
		}
		name := f[0]
		uid, err := strconv.Atoi(f[2])
		if err != nil || uid < 1000 || uid >= 65000 { // human range; skip system + nobody
			continue
		}
		out, err := exec.Command("getent", "-s", "sss", "passwd", name).Output()
		if err != nil {
			continue // not in directory → genuine local-only account, leave it
		}
		p := strings.Split(strings.TrimSpace(string(out)), ":")
		if len(p) < 6 || p[2] == f[2] {
			continue // no collision
		}
		victims = append(victims, shadowed{name, f[2], p[2], p[3], f[5]})
	}
	if len(victims) == 0 {
		return
	}

	// Show the destructive scope up front. This runs as part of the
	// operator-invoked `--setup-ldap`, so it is intentional (not interactive),
	// but it must never silently delete a local account.
	fmt.Println("------------------------------------------------------------")
	fmt.Printf("WARNING: %d local account(s) shadow a directory user and will be MIGRATED:\n", len(victims))
	for _, v := range victims {
		fmt.Printf("  - %s : kill processes, userdel (local uid %s), chown %s -> %s:%s\n",
			v.name, v.localUID, v.home, v.dirUID, v.dirGID)
	}
	fmt.Println("  Local passwd/shadow entries are removed; home files are preserved and")
	fmt.Println("  re-owned to the directory uid:gid. Genuine local-only accounts are untouched.")
	fmt.Println("------------------------------------------------------------")

	// Pass 2 — act.
	migrated := 0
	for _, v := range victims {
		fmt.Printf("Migrating %q: local uid %s -> directory uid %s\n", v.name, v.localUID, v.dirUID)
		exec.Command("pkill", "-KILL", "-u", v.name).Run()
		if out, err := exec.Command("userdel", v.name).CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "  warn: userdel %s failed: %s; skipping\n", v.name, strings.TrimSpace(string(out)))
			continue
		}
		// Re-own the home dir plus the two other paths unambiguously owned by the
		// user (mail spool, crontab). We deliberately do NOT walk the whole FS by
		// old uid — a reused uid could own unrelated system files.
		owner := v.dirUID + ":" + v.dirGID
		if strings.HasPrefix(v.home, "/home/") {
			if out, err := exec.Command("chown", "-R", owner, v.home).CombinedOutput(); err != nil {
				fmt.Fprintf(os.Stderr, "  warn: chown %s failed: %s\n", v.home, strings.TrimSpace(string(out)))
			} else {
				fmt.Printf("  re-owned %s to %s\n", v.home, owner)
			}
		}
		for _, p := range []string{"/var/mail/" + v.name, "/var/spool/cron/crontabs/" + v.name} {
			if _, err := os.Lstat(p); err == nil {
				exec.Command("chown", "-R", owner, p).Run()
				fmt.Printf("  re-owned %s to %s\n", p, owner)
			}
		}
		migrated++
	}
	fmt.Printf("Migrated %d local user(s) to the directory.\n", migrated)
}

func fail(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", a...)
	os.Exit(1)
}
