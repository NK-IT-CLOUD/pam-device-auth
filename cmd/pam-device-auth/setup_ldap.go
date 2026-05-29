package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
)

// runSetupLDAP configures the host for "directory mode": SSSD resolves users
// from LLDAP (NSS best practice), pam-device-auth adds the OIDC SSH layer. It
// is idempotent and reads everything from the JSON config's `ldap` block. The
// RO bind password is needed only here; it is written into the root-only
// /etc/sssd/sssd.conf for SSSD's runtime use.
//
// Steps: validate config -> ensure SSSD packages -> write sssd.conf ->
// nsswitch (sss) -> enable mkhomedir -> sudoers (%admin_group) -> restart sssd.
func runSetupLDAP() {
	cfg, err := config.Load("")
	if err != nil {
		fail("config error: %v", err)
	}
	l := cfg.LDAP
	if l == nil || l.URI == "" || l.BaseDN == "" || l.BindDN == "" || l.BindPassword == "" || l.AccessGroup == "" || l.AdminGroup == "" {
		fail("config 'ldap' block incomplete: need uri, base_dn, bind_dn, bind_password, access_group, admin_group")
	}
	// Reject control chars in any ldap value: they are written verbatim into the
	// sssd.conf INI file, so a stray newline could inject arbitrary SSSD
	// directives (e.g. a TLS downgrade). Also reject LDAP-filter metacharacters
	// in the group names that go into ldap_access_filter.
	for field, v := range map[string]string{"uri": l.URI, "base_dn": l.BaseDN, "bind_dn": l.BindDN, "bind_password": l.BindPassword, "access_group": l.AccessGroup, "admin_group": l.AdminGroup} {
		if strings.ContainsAny(v, "\n\r") {
			fail("ldap.%s contains a newline — refusing (sssd.conf injection)", field)
		}
	}
	if strings.ContainsAny(l.AccessGroup, "()*,\\") || strings.ContainsAny(l.AdminGroup, "()*,\\") {
		fail("ldap.access_group/admin_group must be a bare group name (no LDAP-filter metacharacters)")
	}
	userBase := l.UserSearchBase
	if userBase == "" {
		userBase = "ou=people," + l.BaseDN
	}
	groupBase := l.GroupSearchBase
	if groupBase == "" {
		groupBase = "ou=groups," + l.BaseDN
	}

	ensureSSSDPackages()

	// 1) /etc/sssd/sssd.conf (0600 root). auth_provider=ldap so sudo (%admin_group)
	//    re-auths against the LLDAP password via pam_sss; access_provider gates
	//    pam_sss services (sudo/su/login) to access_group members.
	sssdConf := fmt.Sprintf(`[sssd]
config_file_version = 2
services = nss, pam, ssh
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
ldap_tls_cacert = /etc/ssl/certs/ca-certificates.crt
override_homedir = /home/%%u
default_shell = /bin/bash
ldap_access_filter = (memberOf=cn=%s,%s)
enumerate = false
cache_credentials = false
entry_cache_timeout = 600
`, l.URI, l.BaseDN, userBase, groupBase, l.BindDN, l.BindPassword, l.AccessGroup, groupBase)

	if err := os.WriteFile("/etc/sssd/sssd.conf", []byte(sssdConf), 0600); err != nil {
		fail("write /etc/sssd/sssd.conf: %v", err)
	}
	if err := os.Chown("/etc/sssd/sssd.conf", 0, 0); err != nil {
		fmt.Fprintf(os.Stderr, "warn: chown sssd.conf: %v\n", err)
	}
	fmt.Println("Wrote /etc/sssd/sssd.conf (0600)")

	// 2) nsswitch: ensure 'sss' on passwd/group/shadow
	if err := ensureNsswitchSSS(); err != nil {
		fail("nsswitch: %v", err)
	}
	fmt.Println("nsswitch.conf: sss enabled for passwd/group/shadow")

	// 3) auto-create home dirs on first login (directory provides no home)
	if out, err := exec.Command("pam-auth-update", "--enable", "mkhomedir").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "warn: pam-auth-update mkhomedir: %s: %v\n", strings.TrimSpace(string(out)), err)
	} else {
		fmt.Println("pam_mkhomedir enabled")
	}

	// 4) sudoers: members of admin_group get sudo (password-prompted -> LLDAP via pam_sss)
	if err := writeSudoers(l.AdminGroup); err != nil {
		fail("sudoers: %v", err)
	}
	fmt.Printf("sudoers: %%%s may sudo (LLDAP password)\n", l.AdminGroup)

	// 5) sshd drop-in: non-root needs key (from LLDAP via sss_ssh_authorizedkeys)
	//    AND OIDC; root stays key-only (break-glass via local authorized_keys).
	if err := writeSshdDropin(); err != nil {
		fail("sshd config: %v", err)
	}

	// 6) (re)start SSSD
	if out, err := exec.Command("systemctl", "enable", "--now", "sssd").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "warn: enable sssd: %s\n", strings.TrimSpace(string(out)))
	}
	exec.Command("sss_cache", "-E").Run()
	if out, err := exec.Command("systemctl", "restart", "sssd").CombinedOutput(); err != nil {
		fail("restart sssd: %s: %v", strings.TrimSpace(string(out)), err)
	}
	fmt.Println("sssd restarted")

	migrateLocalShadowing()

	fmt.Println("\nDirectory mode configured. Verify with:  getent passwd <a-directory-user>")
	fmt.Printf("Then enable the OIDC SSH layer:  pam-device-auth --enable\n")
}

// ensureSSSDPackages installs the SSSD LDAP/NSS/PAM packages if sssd is absent.
func ensureSSSDPackages() {
	if _, err := exec.LookPath("sssd"); err == nil {
		return
	}
	fmt.Println("Installing sssd-ldap libnss-sss libpam-sss ...")
	exec.Command("apt-get", "update").Run() // refresh stale index (best-effort)
	cmd := exec.Command("apt-get", "install", "-y", "sssd-ldap", "libnss-sss", "libpam-sss")
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	if out, err := cmd.CombinedOutput(); err != nil {
		fail("apt-get install sssd-ldap: %s: %v", strings.TrimSpace(string(out)), err)
	}
}

// ensureNsswitchSSS appends 'sss' to the passwd/group/shadow databases in
// /etc/nsswitch.conf if not already present.
func ensureNsswitchSSS() error {
	data, err := os.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		return err
	}
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
	if !changed {
		return nil
	}
	return os.WriteFile("/etc/nsswitch.conf", []byte(strings.Join(lines, "\n")), 0644)
}

// writeSudoers writes a validated sudoers drop-in granting the admin group sudo.
// Ensures sudo is installed (minimal LXC images may lack it) and that
// /etc/sudoers.d exists before writing.
func writeSudoers(adminGroup string) error {
	if _, err := exec.LookPath("visudo"); err != nil {
		exec.Command("apt-get", "update").Run() // refresh stale index (best-effort)
		cmd := exec.Command("apt-get", "install", "-y", "sudo")
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("install sudo: %s: %w", strings.TrimSpace(string(out)), err)
		}
	}
	if err := os.MkdirAll("/etc/sudoers.d", 0755); err != nil {
		return fmt.Errorf("mkdir /etc/sudoers.d: %w", err)
	}
	path := "/etc/sudoers.d/pam-device-auth"
	content := fmt.Sprintf("# Managed by pam-device-auth --setup-ldap\n%%%s ALL=(ALL:ALL) ALL\n", adminGroup)
	if err := os.WriteFile(path, []byte(content), 0440); err != nil {
		return err
	}
	// Validate the whole sudoers set; remove the drop-in if it would break sudo.
	if out, err := exec.Command("visudo", "-c").CombinedOutput(); err != nil {
		os.Remove(path)
		return fmt.Errorf("visudo -c rejected the drop-in (%s): %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// writeSshdDropin writes the directory-mode sshd drop-in: non-root must satisfy
// publickey (key fetched from LLDAP via sss_ssh_authorizedkeys) AND
// keyboard-interactive (OIDC via pam_device_auth) — true 2FA. Root stays
// key-only (break-glass): sshd also consults the local AuthorizedKeysFile, so
// root's ~/.ssh/authorized_keys keeps working regardless of the LLDAP command.
// The file is validated with `sshd -t` and reverted on failure; it takes effect
// at the next sshd restart (performed by `--enable`), avoiding a lockout window.
func writeSshdDropin() error {
	path := "/etc/ssh/sshd_config.d/10-pam-device-auth.conf"
	content := `# Managed by pam-device-auth --setup-ldap (directory mode)
KbdInteractiveAuthentication yes
PermitRootLogin prohibit-password
UsePAM yes
PasswordAuthentication no
MaxAuthTries 3
LogLevel DEBUG1
# Non-root: SSH key (from LLDAP via SSSD) AND OIDC (keyboard-interactive/PAM).
AuthenticationMethods publickey,keyboard-interactive:pam
AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys
AuthorizedKeysCommandUser nobody

# Root: local SSH key only (break-glass). sshd still checks AuthorizedKeysFile,
# so root's ~/.ssh/authorized_keys authenticates; root never uses OIDC/SSSD.
Match User root
    AuthenticationMethods publickey
`
	backup, readErr := os.ReadFile(path) // readErr==nil means a file existed to restore
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return err
	}
	if out, err := exec.Command("sshd", "-t").CombinedOutput(); err != nil {
		if readErr == nil {
			os.WriteFile(path, backup, 0644)
		} else {
			os.Remove(path)
		}
		return fmt.Errorf("sshd -t rejected drop-in (%s): %w", strings.TrimSpace(string(out)), err)
	}
	fmt.Println("Wrote sshd drop-in: publickey,keyboard-interactive (2FA) + sss AuthorizedKeysCommand")
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
			fmt.Fprintf(os.Stderr, "  warn: userdel %s failed: %s — skipping\n", v.name, strings.TrimSpace(string(out)))
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
