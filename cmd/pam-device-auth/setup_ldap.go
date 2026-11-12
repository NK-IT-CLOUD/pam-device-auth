package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/distro"
)

// chownRoot makes path owned by root:root; a seam so tests (which may run as
// non-root) replace it instead of the production path swallowing EPERM.
var chownRoot = func(path string) error { return os.Chown(path, 0, 0) }

// writeSSSDConfAt atomically writes sssd.conf-style content to path (0600,
// root:root) and returns a restore func that reinstates the prior file — or
// removes a newly-created one — if a downstream step (e.g. `systemctl restart
// sssd`) rejects the new config. A corrupt sssd.conf takes down NSS identity
// and locks out all directory logins, so this mirrors
// writeSshdDropin/writeSudoers: never leave a partial or rejected config
// behind. A failed chown is an error (sssd refuses a config it does not own)
// and restores the prior file. An existing file that cannot be read is an
// error before the write (readPrior). restore reports what it did, for the
// abort message. When the write fails after the rename (errWrittenNotSynced), the
// new file is in place: the error comes with a working restore, which the
// caller must run (sssdConfWriteAbort). Path-parameterized for testability.
func writeSSSDConfAt(path, content string) (restore func() (string, error), err error) {
	prior, existed, err := readPrior(path)
	if err != nil {
		return nil, err
	}

	restore = func() (string, error) {
		if existed {
			// The rollback must be as crash-safe as the forward write: a
			// truncate-then-write here could leave a partial sssd.conf —
			// exactly the failure mode this function exists to prevent.
			if err := atomicWriteFile(path, prior, 0600); err != nil {
				return "", err
			}
			if err := chownRoot(path); err != nil {
				return "", err
			}
			return "restored previous " + filepath.Base(path), nil
		}
		if err := os.Remove(path); err != nil {
			return "", err
		}
		return "removed the new " + filepath.Base(path) + " (none existed before)", nil
	}
	if err := atomicWriteFile(path, []byte(content), 0600); err != nil {
		if errors.Is(err, errWrittenNotSynced) {
			return restore, err
		}
		return nil, err
	}
	if err := chownRoot(path); err != nil {
		did, rerr := restore()
		if rerr != nil {
			return nil, fmt.Errorf("%w (could NOT roll back %s: %v)", err, path, rerr)
		}
		return nil, fmt.Errorf("%w (%s)", err, did)
	}
	return restore, nil
}

// sssdConfWriteAbort is the abort message for a failed write of
// /etc/sssd/sssd.conf. A non-nil restore (writeSSSDConfAt: the new file is in
// place) is run first, and the message says what it did; sssd still runs on
// its previous config, so it is not restarted.
func sssdConfWriteAbort(err error, restore func() (string, error)) string {
	msg := "write /etc/sssd/sssd.conf: " + err.Error()
	if restore == nil {
		return msg
	}
	return setupAbortMessage(msg, rollbackSSSD(execRunner, restore, false), nil)
}

// errWrittenNotSynced marks an atomicWriteFile error after the rename: the
// new content is in place at the path, only the directory sync failed. A
// caller that rolls back on errors must also roll back on this one.
var errWrittenNotSynced = errors.New("the new file is in place, but syncing its directory failed")

// syncDir fsyncs the directory dir, so a rename into it survives a crash; a
// seam so tests can make the step after the rename fail.
var syncDir = func(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}

// atomicWriteFile writes content to path via a same-directory temp file and
// rename, so the target is never observable in a truncated or partial state.
// An error after the rename wraps errWrittenNotSynced.
func atomicWriteFile(path string, content []byte, mode os.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	renamed := false
	// Best-effort cleanup of the temp file on any failure before the rename.
	defer func() {
		if err != nil && !renamed {
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
	renamed = true
	if err = syncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("%s: %w: %w", path, errWrittenNotSynced, err)
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
	// bindDNRe extends dnRe for bind_dn, which may also be a UPN
	// (svc@example.com) or a down-level logon name (EXAMPLE\svc). It still
	// rejects the filter metacharacters ()* and every control character.
	bindDNRe = regexp.MustCompile(`^[A-Za-z0-9 ._=,@\\-]+$`)
	// principalRe is a Kerberos principal with an optional upper-case realm
	// (svc-sssd@EXAMPLE.COM, host/dc1.example.com@EXAMPLE.COM,
	// HOST$@EXAMPLE.COM). With kerberos.keytab, bind_dn is the SASL authid.
	principalRe = regexp.MustCompile(`^[A-Za-z0-9._$/-]+(@[A-Z0-9.-]+)?$`)
	// attrNameRe is an RFC 4512 attribute descriptor (keystring).
	attrNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)
	// realmRe is an upper-case Kerberos realm in DNS form.
	realmRe = regexp.MustCompile(`^[A-Z0-9]([A-Z0-9-]*[A-Z0-9])?(\.[A-Z0-9]([A-Z0-9-]*[A-Z0-9])?)*$`)
	// hostRe is a host name or IP address with an optional port.
	hostRe = regexp.MustCompile(`^[A-Za-z0-9.:\[\]-]+$`)
	// pathRe is an absolute path without whitespace or control characters;
	// %u, %d and %f stay for SSSD's home directory expansion.
	pathRe = regexp.MustCompile(`^/[A-Za-z0-9._%/+-]*$`)
)

// validateLDAPURI requires exactly one ldaps:// or ldap:// URI with a host.
// ldap:// is safe only because renderSSSDConf then enforces StartTLS
// (ldap_id_use_start_tls, ldap_tls_reqcert = hard) or, with a keytab, SASL
// sealing; there is no cleartext mode. SSSD reads ldap_uri as a failover
// list, and url.Parse accepts a comma inside the host, so every list
// separator is rejected: a failed first server must never fall back to
// another transport. Shared by --setup-ldap and --check.
func validateLDAPURI(uri string) error {
	if strings.ContainsAny(uri, ", \t\r\n") {
		return fmt.Errorf("ldap.uri must be a single ldaps:// or ldap:// URI (got %q): a comma/space separated list is an SSSD failover list", uri)
	}
	u, err := url.Parse(uri)
	if err != nil || (u.Scheme != "ldaps" && u.Scheme != "ldap") || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("ldap.uri must be ldaps://<host>[:port] or ldap://<host>[:port] (StartTLS), got %q", uri)
	}
	return nil
}

// keytabTransportError rejects a keytab bind over ldaps://. GSSAPI over
// ldaps:// without a SASL layer needs TLS channel bindings and fails against
// Samba, and AD and Samba refuse GSSAPI sealing inside TLS: the keytab bind
// runs over ldap:// with SASL sealing only. Shared by --setup-ldap and
// --check.
func keytabTransportError(l *config.LDAPConfig) error {
	if l.Kerberos != nil && l.Kerberos.Keytab != "" && strings.HasPrefix(strings.ToLower(l.URI), "ldaps://") {
		return fmt.Errorf("ldap.kerberos.keytab requires an ldap:// URI: the GSSAPI bind is protected by SASL sealing, not TLS")
	}
	return nil
}

// keytabHostError rejects a keytab bind whose ldap.uri names the DC by IP
// address. GSSAPI builds the service principal ldap/<host> from the URI host
// as written (ldap_sasl_canonicalize defaults to false), and the DC's
// principal carries its host name, not an address. Shared by --setup-ldap and
// --check, both after validateLDAPURI.
func keytabHostError(l *config.LDAPConfig) error {
	if l.Kerberos == nil || l.Kerberos.Keytab == "" {
		return nil
	}
	u, err := url.Parse(l.URI)
	if err != nil {
		return nil // reported by validateLDAPURI
	}
	// Hostname drops the port and the brackets. u.Host catches an IPv6
	// address without brackets, which Hostname splits at its last colon.
	for _, h := range []string{u.Hostname(), u.Host} {
		if _, perr := netip.ParseAddr(h); perr == nil {
			return fmt.Errorf("ldap.kerberos.keytab needs the DC's host name in ldap.uri, not an IP address: GSSAPI uses the ldap/<host> service principal")
		}
	}
	return nil
}

// validateLDAPProfile accepts "lldap" and "ad"; there is no implicit profile
// (--migrate-config sets it on configs from 0.6.x). Shared by --setup-ldap,
// --check and --migrate-config.
func validateLDAPProfile(l *config.LDAPConfig) error {
	switch l.Profile {
	case config.LDAPProfileLLDAP, config.LDAPProfileAD:
		return nil
	case "":
		return fmt.Errorf("config: ldap.profile is required (%q or %q)", config.LDAPProfileLLDAP, config.LDAPProfileAD)
	default:
		return fmt.Errorf("ldap.profile must be %q or %q, got %q", config.LDAPProfileLLDAP, config.LDAPProfileAD, l.Profile)
	}
}

// validateLDAPConfig is the security boundary for directory-mode setup. Every
// field it checks is written verbatim into a config file consumed by a
// privileged service (sssd.conf, sudoers), so this single choke point must
// reject anything that could inject an INI directive (a newline), widen the
// LDAP access filter (filter metacharacters in a DN), or alter the sudoers
// grant (sudoers metacharacters in a group name). It returns an error rather
// than exiting so it can be unit-tested; the caller maps the error to fail().
func validateLDAPConfig(l *config.LDAPConfig) error {
	if l == nil || l.URI == "" || l.BaseDN == "" || l.BindDN == "" || l.AccessGroup == "" || l.AdminGroup == "" {
		return fmt.Errorf("config 'ldap' block incomplete: need uri, base_dn, bind_dn, access_group, admin_group")
	}
	if err := validateLDAPProfile(l); err != nil {
		return err
	}
	keytab := l.Kerberos != nil && l.Kerberos.Keytab != ""
	switch {
	case keytab && (l.BindPassword != "" || l.BindPasswordFile != ""):
		return fmt.Errorf("ldap.kerberos.keytab replaces the bind password; remove bind_password/bind_password_file")
	case !keytab && l.BindPassword != "" && l.BindPasswordFile != "":
		return fmt.Errorf("set either ldap.bind_password or ldap.bind_password_file, not both")
	case !keytab && l.BindPassword == "" && l.BindPasswordFile == "":
		return fmt.Errorf("config 'ldap' block incomplete: need bind_password, bind_password_file or kerberos.keytab")
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
		"group_search_base": l.GroupSearchBase, "profile": l.Profile,
		"ca_file": l.CAFile, "bind_password_file": l.BindPasswordFile,
		"attributes.username": l.Attributes.Username, "attributes.ssh_key": l.Attributes.SSHKey,
		"attributes.clients": l.Attributes.Clients, "home": l.Home, "shell": l.Shell,
	} {
		if hasControlChar(v) {
			return fmt.Errorf("ldap.%s contains a control character; refusing (sssd.conf injection)", field)
		}
	}
	if err := validateLDAPURI(l.URI); err != nil {
		return err
	}
	if err := keytabTransportError(l); err != nil {
		return err
	}
	if err := keytabHostError(l); err != nil {
		return err
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
	if keytab {
		if !principalRe.MatchString(l.BindDN) {
			return fmt.Errorf("ldap.bind_dn must be a Kerberos principal like svc-sssd@EXAMPLE.COM when kerberos.keytab is set")
		}
	} else if !bindDNRe.MatchString(l.BindDN) {
		return fmt.Errorf("ldap.bind_dn contains characters not allowed in a bind DN [A-Za-z0-9 ._=,@\\-]")
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
	for field, v := range map[string]string{
		"attributes.username": l.Attributes.Username, "attributes.ssh_key": l.Attributes.SSHKey,
		"attributes.clients": l.Attributes.Clients,
	} {
		if v != "" && !attrNameRe.MatchString(v) {
			return fmt.Errorf("ldap.%s must be an LDAP attribute name [A-Za-z][A-Za-z0-9-]*, got %q", field, v)
		}
	}
	if l.Profile == config.LDAPProfileAD && (l.Attributes.SSHKey == "" || l.Attributes.Clients == "") {
		return fmt.Errorf("profile %q needs ldap.attributes.ssh_key and ldap.attributes.clients (AD has no standard attributes for them)", config.LDAPProfileAD)
	}
	for field, v := range map[string]string{"ca_file": l.CAFile, "bind_password_file": l.BindPasswordFile, "home": l.Home, "shell": l.Shell} {
		if v != "" && !pathRe.MatchString(v) {
			return fmt.Errorf("ldap.%s must be an absolute path without whitespace, got %q", field, v)
		}
	}
	if r := l.IDRange; r != nil {
		if l.Profile != config.LDAPProfileAD {
			return fmt.Errorf("ldap.id_range applies to profile %q only", config.LDAPProfileAD)
		}
		if l.IDMapping != nil && !*l.IDMapping {
			return fmt.Errorf("ldap.id_range needs id_mapping (it bounds the IDs SSSD maps from the objectSid)")
		}
		if r.Min < 1000 || r.Max <= r.Min {
			return fmt.Errorf("ldap.id_range needs 1000 <= min < max, got min=%d max=%d", r.Min, r.Max)
		}
	}
	if l.IDMapping != nil && l.Profile != config.LDAPProfileAD {
		return fmt.Errorf("ldap.id_mapping applies to profile %q only", config.LDAPProfileAD)
	}
	if k := l.Kerberos; k != nil {
		if !realmRe.MatchString(k.Realm) {
			return fmt.Errorf("ldap.kerberos.realm must be an upper-case realm like EXAMPLE.COM, got %q", k.Realm)
		}
		if !hostRe.MatchString(k.KDC) || (k.Kpasswd != "" && !hostRe.MatchString(k.Kpasswd)) {
			return fmt.Errorf("ldap.kerberos.kdc/kpasswd must be host names or addresses")
		}
		if k.Keytab != "" && !pathRe.MatchString(k.Keytab) {
			return fmt.Errorf("ldap.kerberos.keytab must be an absolute path, got %q", k.Keytab)
		}
	}
	return nil
}

// checkSecretFile accepts only a regular file (no symlink) that is not
// readable by group or others and belongs to the effective user (root for
// --setup-ldap). Used for the Kerberos keytab; bind_password_file goes through
// openSecretFile directly so that the file checked is the file read.
func checkSecretFile(path string) error {
	f, err := openSecretFile(path)
	if err != nil {
		return err
	}
	f.Close()
	return nil
}

// openSecretFile opens path read-only without following a symlink in the last
// component and runs checkSecretFileInfo on the open file. O_NONBLOCK keeps
// the open of a FIFO from waiting for a writer; it has no effect on a regular
// file. The caller closes the returned file.
func openSecretFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("%s is a symlink", path)
	}
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err == nil {
		err = checkSecretFileInfo(path, fi)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// checkSecretFileInfo holds the rules of checkSecretFile. Without a
// syscall.Stat_t the owner is unknown and the file is refused.
func checkSecretFileInfo(path string, fi os.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%s has mode %o; group and others must have no access (chmod 600)", path, fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: owner unknown, refusing", path)
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is owned by uid %d, not by uid %d", path, st.Uid, os.Geteuid())
	}
	return nil
}

// caFileError reports why path cannot serve as ldap.ca_file, nil when it can:
// it must be a regular file (a symlink to one is fine). Shared by
// --setup-ldap and --check.
func caFileError(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("ldap.ca_file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("ldap.ca_file %s is not a regular file", path)
	}
	return nil
}

// resolveBindPassword returns the simple-bind password from bind_password or
// from bind_password_file, "" for a keytab bind. The file may hold at most
// 4096 bytes; a longer one is refused rather than truncated. One trailing LF
// or CRLF is stripped; any other line break or control character is rejected
// because the value lands in sssd.conf. Errors never contain the secret.
func resolveBindPassword(l *config.LDAPConfig) (string, error) {
	if l.BindPasswordFile == "" {
		return l.BindPassword, nil
	}
	f, err := openSecretFile(l.BindPasswordFile)
	if err != nil {
		return "", fmt.Errorf("ldap.bind_password_file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return "", fmt.Errorf("ldap.bind_password_file: %w", err)
	}
	if len(data) > 4096 {
		return "", fmt.Errorf("ldap.bind_password_file is longer than 4096 bytes")
	}
	pw := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if pw == "" || hasControlChar(pw) {
		return "", fmt.Errorf("ldap.bind_password_file must hold the password on a single line without control characters")
	}
	return pw, nil
}

// hasControlChar reports whether s contains an ASCII control character
// (U+0000 to U+001F or U+007F); none of them may reach sssd.conf.
func hasControlChar(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// ldapRenderData is the validated set of values interpolated into sssd.conf.
// It is a plain data carrier so renderSSSDConf can be unit-tested without a
// config.LDAPConfig or any filesystem/process access.
type ldapRenderData struct {
	Profile       string // config.LDAPProfileLLDAP or config.LDAPProfileAD (validated)
	URI           string
	BaseDN        string
	UserBase      string
	GroupBase     string
	BindDN        string
	BindPassword  string // simple bind; empty with Keytab
	Keytab        string // GSSAPI bind (ldap_sasl_mech)
	AccessGroup   string
	ServiceGroups []string
	UserNameAttr  string // default uid (lldap) / sAMAccountName (ad)
	SSHKeyAttr    string // default sshPublicKey
	ClientsAttr   string // default clients
	IDMapping     bool   // ad only
	IDRangeMin    int    // ad only; 0 = SSSD default
	IDRangeMax    int
	Home          string // default /home/%u
	Shell         string // default defaultLDAPShell
	KrbRealm      string // non-empty switches auth/chpass to krb5
	KrbKDC        string
	KrbKpasswd    string
}

// withDefaults fills the profile defaults into empty fields, so callers and
// tests may leave them out.
func (d ldapRenderData) withDefaults() ldapRenderData {
	if d.UserNameAttr == "" {
		d.UserNameAttr = "uid"
		if d.Profile == config.LDAPProfileAD {
			d.UserNameAttr = "sAMAccountName"
		}
	}
	if d.SSHKeyAttr == "" {
		d.SSHKeyAttr = "sshPublicKey"
	}
	if d.ClientsAttr == "" {
		d.ClientsAttr = "clients"
	}
	if d.Home == "" {
		d.Home = "/home/%u"
	}
	if d.Shell == "" {
		d.Shell = defaultLDAPShell
	}
	return d
}

// defaultLDAPShell is the login shell sssd.conf gives directory users when
// ldap.shell is empty.
const defaultLDAPShell = "/bin/bash"

// ldapShell returns the login shell sssd.conf gives directory users.
func ldapShell(l *config.LDAPConfig) string {
	if l.Shell != "" {
		return l.Shell
	}
	return defaultLDAPShell
}

// checkLDAPShell verifies that path, the login shell of directory users, is an
// absolute path by the rule validateLDAPConfig applies to ldap.shell (pathRe),
// and a regular file they can execute (other-execute bit; they are neither its
// owner nor in its group). Without it every directory login ends right after
// authentication. Shared by --setup-ldap and --check, so --check never accepts
// a relative path that happens to resolve from its working directory.
func checkLDAPShell(path string) error {
	if !pathRe.MatchString(path) {
		return fmt.Errorf("ldap.shell must be an absolute path without whitespace, got %q", path)
	}
	fi, err := os.Stat(path)
	switch {
	case err != nil:
		return fmt.Errorf("login shell %s (ldap.shell): %w", path, err)
	case !fi.Mode().IsRegular():
		return fmt.Errorf("login shell %s (ldap.shell) is not a regular file (%s)", path, fi.Mode().Type())
	case fi.Mode().Perm()&0001 == 0:
		return fmt.Errorf("login shell %s (ldap.shell) is not executable by directory users (mode %s)", path, fi.Mode().Perm())
	}
	return nil
}

// renderSSSDConf renders sssd.conf for the configured profile. caCertPath is
// ca_file or the distro bundle (distro.Profile.CACertPath). Values are
// validated by validateLDAPConfig before they get here; the renderer never
// passes them through a format string. Pure transform, no I/O.
func renderSSSDConf(d ldapRenderData, caCertPath string) string {
	d = d.withDefaults()
	// No option may produce a cleartext bind: a simple bind skips StartTLS only
	// on a URI that is positively ldaps://, and a keytab bind always demands
	// SASL sealing. url.Parse lowercases the scheme, so validateLDAPURI also
	// lets LDAP:// through.
	ldaps := strings.HasPrefix(strings.ToLower(d.URI), "ldaps://")
	startTLS := !ldaps && d.Keytab == ""
	var b strings.Builder
	kv := func(k, v string) { b.WriteString(k + " = " + v + "\n") }

	b.WriteString("[sssd]\n")
	kv("services", "nss, pam, ssh, ifp")
	kv("domains", "nkit")
	b.WriteString("\n[nss]\n")
	kv("filter_users", "root")
	kv("filter_groups", "root")
	b.WriteString("\n[pam]\n\n[ssh]\n\n[domain/nkit]\n")
	kv("id_provider", "ldap")
	switch {
	case d.KrbRealm != "":
		kv("auth_provider", "krb5")
		kv("chpass_provider", "krb5")
	case d.Profile == config.LDAPProfileAD:
		kv("auth_provider", "ldap")
		kv("chpass_provider", "none") // AD does not implement the RFC 3062 exop
	default:
		kv("auth_provider", "ldap")
	}
	if d.Profile == config.LDAPProfileAD {
		kv("access_provider", "simple")
		kv("simple_allow_groups", strings.Join(append([]string{d.AccessGroup}, d.ServiceGroups...), ", "))
	} else {
		kv("access_provider", "ldap")
	}
	kv("ldap_uri", d.URI)
	if startTLS {
		kv("ldap_id_use_start_tls", "true")
	} else if !ldaps {
		// Keytab bind: SSSD 2.10 and later default to StartTLS, and AD and Samba
		// refuse GSSAPI sealing inside TLS.
		kv("ldap_id_use_start_tls", "false")
	}
	kv("ldap_search_base", d.BaseDN)
	kv("ldap_user_search_base", d.UserBase)
	kv("ldap_group_search_base", d.GroupBase)
	if d.Keytab != "" {
		kv("ldap_sasl_mech", "GSSAPI")
		kv("ldap_sasl_authid", d.BindDN)
		kv("ldap_krb5_keytab", d.Keytab)
		kv("ldap_krb5_init_creds", "true")
		kv("ldap_sasl_minssf", "56") // SASL sealing instead of TLS
	} else {
		kv("ldap_default_bind_dn", d.BindDN)
		kv("ldap_default_authtok", d.BindPassword)
	}
	if d.Profile == config.LDAPProfileAD {
		kv("ldap_schema", "ad")
		kv("ldap_referrals", "false")
		kv("case_sensitive", "false")
		kv("ldap_user_extra_attrs", "clients:"+d.ClientsAttr)
		kv("ldap_user_name", d.UserNameAttr)
		kv("ldap_user_ssh_public_key", d.SSHKeyAttr)
		kv("ldap_id_mapping", strconv.FormatBool(d.IDMapping))
		if d.IDMapping && d.IDRangeMax > d.IDRangeMin {
			kv("ldap_idmap_range_min", strconv.Itoa(d.IDRangeMin))
			kv("ldap_idmap_range_max", strconv.Itoa(d.IDRangeMax))
			kv("ldap_idmap_range_size", strconv.Itoa(d.IDRangeMax-d.IDRangeMin))
		}
	} else {
		kv("ldap_schema", "rfc2307bis")
		kv("ldap_user_extra_attrs", "clients:"+d.ClientsAttr)
		kv("ldap_user_object_class", "posixAccount")
		kv("ldap_user_name", d.UserNameAttr)
		kv("ldap_user_ssh_public_key", d.SSHKeyAttr)
		kv("ldap_user_uid_number", "uidNumber")
		kv("ldap_user_gid_number", "gidNumber")
		kv("ldap_group_object_class", "groupOfNames")
		kv("ldap_group_name", "cn")
		kv("ldap_group_member", "member")
		kv("ldap_group_gid_number", "gidNumber")
		kv("ldap_id_mapping", "false")
	}
	kv("ldap_tls_reqcert", "hard")
	kv("ldap_tls_cacert", caCertPath)
	if d.KrbRealm != "" {
		kv("krb5_realm", d.KrbRealm)
		kv("krb5_server", d.KrbKDC)
		if d.KrbKpasswd != "" {
			kv("krb5_kpasswd", d.KrbKpasswd)
		}
		if d.Profile == config.LDAPProfileAD {
			// The principal comes from userPrincipalName, whose realm part AD
			// delivers as the lower-case DNS domain; no KDC serves that realm.
			// SSSD's ad provider sets both; the ldap provider defaults to false.
			kv("krb5_use_enterprise_principal", "true")
			kv("ldap_force_upper_case_realm", "true")
		}
	}
	kv("override_homedir", d.Home)
	kv("default_shell", d.Shell)
	if d.Profile != config.LDAPProfileAD {
		kv("ldap_access_filter", lldapAccessFilter(d.AccessGroup, d.ServiceGroups, d.GroupBase))
	}
	kv("enumerate", "false")
	kv("cache_credentials", "false")
	kv("entry_cache_timeout", "600")
	b.WriteString("\n[ifp]\n")
	kv("user_attributes", "+clients")
	return b.String()
}

// renderDataFor maps the validated ldap block to the renderer's input. Search
// bases default to ou=people/ou=groups under base_dn for lldap and to base_dn
// itself for ad, where users and groups live in arbitrary OUs.
func renderDataFor(l *config.LDAPConfig, bindPassword string) ldapRenderData {
	ad := l.Profile == config.LDAPProfileAD
	userBase, groupBase := l.UserSearchBase, l.GroupSearchBase
	if userBase == "" {
		userBase = "ou=people," + l.BaseDN
		if ad {
			userBase = l.BaseDN
		}
	}
	if groupBase == "" {
		groupBase = "ou=groups," + l.BaseDN
		if ad {
			groupBase = l.BaseDN
		}
	}
	d := ldapRenderData{
		Profile: l.Profile, URI: l.URI, BaseDN: l.BaseDN, UserBase: userBase, GroupBase: groupBase,
		BindDN: l.BindDN, BindPassword: bindPassword, AccessGroup: l.AccessGroup,
		ServiceGroups: l.ServiceAccountGroups, UserNameAttr: l.Attributes.Username,
		SSHKeyAttr: l.Attributes.SSHKey, ClientsAttr: l.Attributes.Clients, Home: l.Home, Shell: l.Shell,
	}
	if ad {
		d.IDMapping = l.IDMapping == nil || *l.IDMapping
		if l.IDRange != nil {
			d.IDRangeMin, d.IDRangeMax = l.IDRange.Min, l.IDRange.Max
		}
	}
	if k := l.Kerberos; k != nil {
		d.KrbRealm, d.KrbKDC, d.KrbKpasswd, d.Keytab = k.Realm, k.KDC, k.Kpasswd, k.Keytab
	}
	return d
}

// caCertFor returns ldap.ca_file or the distro CA bundle.
func caCertFor(l *config.LDAPConfig, prof distro.Profile) string {
	if l.CAFile != "" {
		return l.CAFile
	}
	return prof.CACertPath
}

// lldapAccessFilter ORs access_group and every service group (model B); a
// single group gives the plain (memberOf=...) form.
func lldapAccessFilter(access string, service []string, groupBase string) string {
	one := func(g string) string { return "(memberOf=cn=" + g + "," + groupBase + ")" }
	if len(service) == 0 {
		return one(access)
	}
	var b strings.Builder
	b.WriteString("(|" + one(access))
	for _, g := range service {
		b.WriteString(one(g))
	}
	b.WriteString(")")
	return b.String()
}

// runSetupLDAP configures the host for "directory mode": SSSD resolves users
// from the directory (LLDAP or Active Directory, per ldap.profile; NSS best
// practice), pam-device-auth adds the OIDC SSH layer. It is idempotent and
// reads everything from the JSON config's `ldap` block. The RO bind password
// (bind_password or bind_password_file; none with a Kerberos keytab) is needed
// only here; it is written into the root-only /etc/sssd/sssd.conf for SSSD's
// runtime use.
//
// Steps: supported platform -> validate config -> ensure SSSD packages (plus
// krb5 with ldap.kerberos) -> sss_ssh_authorizedkeys present -> write
// sssd.conf -> enable mkhomedir -> nsswitch (sss) -> sudoers (%admin_group) ->
// sshd drop-in -> mask the socket units of the configured responders ->
// restart sssd -> reset-failed -> migrate local accounts that shadow a
// directory user.
// (mkhomedir before nsswitch on RHEL: authselect owns nsswitch.conf too.)
func runSetupLDAP() {
	prof := requirePlatform()
	cfg, err := loadConfig("")
	if err != nil {
		fail("config error: %v", err)
	}
	// A misspelled key or an unsupported algorithm is settled before the setup
	// looks at the ldap block or changes the host.
	if lines := configWarningLines(cfg); len(lines) > 0 {
		fail("%s", strings.Join(lines, "; "))
	}
	l := cfg.LDAP
	// Single security choke point: validates every directory value before any
	// of them is written into sssd.conf / sudoers (see validateLDAPConfig).
	if err := validateLDAPConfig(l); err != nil {
		fail("%v", err)
	}
	bindPassword, err := resolveBindPassword(l)
	if err != nil {
		fail("%v", err)
	}
	if l.CAFile != "" {
		if err := caFileError(l.CAFile); err != nil {
			fail("%v", err)
		}
	}
	if l.Kerberos != nil && l.Kerberos.Keytab != "" {
		if err := checkSecretFile(l.Kerberos.Keytab); err != nil {
			fail("ldap.kerberos.keytab: %v", err)
		}
	}
	// sssd.conf names this shell for every directory user; no package below
	// provides it, so refuse before the first host write.
	if err := checkLDAPShell(ldapShell(l)); err != nil {
		fail("%v", err)
	}

	if err := ensureSSSDPackages(prof, l.Kerberos != nil, execRunner); err != nil {
		fail("%v", err)
	}

	// The sshd drop-in (step 5) names the platform's sss_ssh_authorizedkeys as
	// AuthorizedKeysCommand; a path that does not exist makes sshd serve no
	// directory key. Refuse now, before sssd.conf or any other file is written.
	if err := checkSSSAuthKeys(prof.SSSAuthKeysPath); err != nil {
		fail("%v", err)
	}
	// sssd.conf enables the ifp responder; without its binary sssd does not start.
	if err := checkSSSDIfp(prof.SSSDIfpPath); err != nil {
		fail("%v", err)
	}

	// 1) /etc/sssd/sssd.conf (0600 root).
	sssdConf := renderSSSDConf(renderDataFor(l, bindPassword), caCertFor(l, prof))

	restoreSSSD, err := writeSSSDConfAt("/etc/sssd/sssd.conf", sssdConf)
	if err != nil {
		fail("%s", sssdConfWriteAbort(err, restoreSSSD))
	}
	fmt.Println("Wrote /etc/sssd/sssd.conf (0600)")
	// remaining lists the host changes made after sssd.conf; an abort does not
	// undo them, so its message names them.
	var remaining []string
	// abort reports a failure of steps 2-6 (sssd still runs on its previous
	// config): it reinstates the previous sssd.conf first and says truthfully
	// whether that worked, so the operator is never told about a rollback that
	// did not happen.
	abort := func(format string, args ...any) {
		fail("%s", setupAbortMessage(fmt.Sprintf(format, args...), rollbackSSSD(execRunner, restoreSSSD, false), remaining))
	}

	// 2) auto-create home dirs on first login (directory provides no home).
	//    On RHEL this is wired via authselect, which also owns nsswitch.conf —
	//    ensureNsswitchSSS() below MUST run after this so authselect doesn't
	//    clobber the 'sss' entries it just added.
	if err := wireMkhomedir(prof, execRunner); err != nil {
		abort("mkhomedir: %v", err)
	}
	remaining = append(remaining, "mkhomedir PAM wiring via "+prof.PamWiring)

	// 3) nsswitch: ensure 'sss' on passwd/group/shadow. Must run after the
	//    mkhomedir wiring above (see comment there) so authselect's nsswitch
	//    rewrite is not overwritten/clobbered by our own edit, and vice versa.
	if err := ensureNsswitchSSS(); err != nil {
		abort("nsswitch: %v", err)
	}
	fmt.Println("nsswitch.conf: sss enabled for passwd/group/shadow")
	remaining = append(remaining, "sss in /etc/nsswitch.conf")

	// 4) sudoers: members of admin_group get sudo (password-prompted -> the
	//    directory or, with ldap.kerberos, the KDC via pam_sss);
	//    members of nopasswd_sudo_groups get passwordless sudo (opt-in).
	if err := writeSudoers(prof, l.AdminGroup, l.NopasswdSudoGroups); err != nil {
		abort("sudoers: %v", err)
	}
	fmt.Printf("sudoers: %%%s may sudo (directory password)\n", l.AdminGroup)
	remaining = append(remaining, "sudoers drop-in /etc/sudoers.d/pam-device-auth")

	// 5) sshd drop-in: non-root needs key (from the directory via sss_ssh_authorizedkeys)
	//    AND OIDC; root stays key-only (break-glass via local authorized_keys).
	//    The AuthorizedKeysCommand is the platform's path, checked above.
	if err := writeSshdDropin(prof.SSSAuthKeysPath, l.ServiceAccountGroups, cfg.RootLogin); err != nil {
		abort("sshd config: %v", err)
	}
	remaining = append(remaining, "sshd drop-in "+sshdDropinPath+" (active at the next sshd restart)")

	// 6) The responders run from the services line: their socket units must not
	//    start them a second time (Debian/Ubuntu enable them by preset).
	if err := maskConflictingSSSDSockets(sssdConf); err != nil {
		abort("sssd sockets: %v", err)
	}
	remaining = append(remaining, "the SSSD socket units masked above (if any)")

	// 7) (re)start SSSD and clear failed SSSD units; a failure restores
	//    sssd.conf and restarts sssd on it.
	if remaining, err = startSSSDStep(execRunner, restoreSSSD, remaining); err != nil {
		fail("%v", err)
	}

	// 8) A migrated account resolves only through the directory, so from here
	//    on a failure keeps the new sssd.conf instead of restoring it.
	if removed, err := migrateLocalShadowing(); err != nil {
		fail("%s", setupAbortMessage(err.Error(), keptSSSDConf(removed), remaining))
	}

	if len(setupWarnings) > 0 {
		fmt.Printf("\nDirectory mode configured WITH %d WARNING(S) - review before enabling:\n", len(setupWarnings))
		for _, w := range setupWarnings {
			fmt.Printf("  - %s\n", w)
		}
	} else {
		fmt.Println("\nDirectory mode configured.")
	}
	fmt.Println("Verify with:  getent -s sss passwd <a-directory-user>   and   pam-device-auth --check")
	fmt.Printf("Then enable the OIDC SSH layer:  pam-device-auth --enable\n")
}

// wireMkhomedir enables home directory creation on first login with the
// platform's PAM wiring tool. On RHEL this is authselect, which also owns
// nsswitch.conf, so it must run before ensureNsswitchSSS. Every failure is an
// error: the caller aborts the setup.
func wireMkhomedir(prof distro.Profile, run commandRunner) error {
	switch prof.PamWiring {
	case "pam-auth-update":
		if out, err := run("pam-auth-update", "--enable", "mkhomedir"); err != nil {
			return fmt.Errorf("pam-auth-update --enable mkhomedir: %s: %w", strings.TrimSpace(string(out)), err)
		}
		fmt.Println("pam_mkhomedir enabled")
	case "authselect":
		args, replaced := authselectPlan(authselectCurrent(run))
		if replaced != "" {
			fmt.Printf("authselect: replacing profile %q\n", replaced)
		}
		if out, err := run("authselect", args...); err != nil {
			return fmt.Errorf("authselect %s: %s: %w", strings.Join(args, " "), strings.TrimSpace(string(out)), err)
		}
		// pam_oddjob_mkhomedir asks oddjobd to create the home directory.
		// There is no authselect rollback: the error names what is left behind
		// (args is "select", the profile with its features, "--force").
		if out, err := run("systemctl", "enable", "--now", "oddjobd"); err != nil {
			return fmt.Errorf("systemctl enable --now oddjobd: %s: %w; the authselect profile %q stays selected",
				strings.TrimSpace(string(out)), err, strings.Join(args[1:len(args)-1], " "))
		}
		fmt.Println("SSSD PAM/nsswitch wired via authselect (with mkhomedir)")
	default:
		return fmt.Errorf("internal: unknown PamWiring %q", prof.PamWiring)
	}
	return nil
}

// authselectCurrent returns the active authselect profile with its features
// ("sssd with-faillock"), "" when none is selected. `authselect current` fails
// in that case (a minimal host) and prints why, which is no profile name; a
// broken authselect fails again at the next command.
func authselectCurrent(run commandRunner) string {
	out, err := run("authselect", "current", "--raw")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// authselectPlan decides from the output of `authselect current --raw` (the
// profile, then its features) how pam_oddjob_mkhomedir gets wired. The plan is
// always `select sssd <features> --force`: that is what wires pam_sss into
// system-auth/password-auth (which the sshd PAM template includes) and
// nsswitch.
//
// With the sssd profile active the features the host has (with-faillock,
// with-sudo) are selected again, with with-mkhomedir added once: they stay.
// Everything else, also no profile at all, becomes `sssd with-mkhomedir`;
// replaced names the profile this throws away, "" when there was none.
//
// --force is needed on every run, not only to overwrite a stock profile:
// ensureNsswitchSSS writes /etc/nsswitch.conf where the profile leaves sss out
// of a line, which replaces authselect's symlink by a regular file. authselect
// 1.2 (RHEL 9) then refuses every command without --force
// ("[/etc/nsswitch.conf] was not created by authselect!"), `enable-feature`
// included. authselect keeps a backup of the files it overwrites.
func authselectPlan(currentRaw string) (args []string, replaced string) {
	current := strings.TrimSpace(currentRaw)
	features := []string{"with-mkhomedir"}
	if f := strings.Fields(current); len(f) > 0 && f[0] == "sssd" {
		current = ""
		if features = f[1:]; !slices.Contains(features, "with-mkhomedir") {
			features = append(features, "with-mkhomedir")
		}
	}
	args = append([]string{"select", "sssd"}, features...)
	return append(args, "--force"), current
}

// sssdEnabledNote, sssdEnableUnknownNote and sssdMaskedNote are the entries
// startSSSD reports for sssd's state in the abort message's list of what is
// in place on the host.
const (
	sssdEnabledNote       = "sssd enabled"
	sssdEnableUnknownNote = "enable state of sssd unknown (check `systemctl is-enabled sssd`)"
	sssdMaskedNote        = "sssd is masked (not enabled; `systemctl unmask sssd` to use it)"
)

// sssdEnableState asks systemctl whether sssd is enabled after a failed
// `enable --now`, which may have enabled the unit before its start failed.
// Only the clear answers count: exit 0 with "enabled" is sssdEnabledNote,
// exit 1 with "disabled" is "" (not enabled), exit 1 with "masked" is
// sssdMaskedNote. Every other answer (another exit code or state, systemctl not running) is
// sssdEnableUnknownNote, never a guess.
func sssdEnableState(run commandRunner) string {
	out, err := run("systemctl", "is-enabled", "sssd")
	state := strings.TrimSpace(string(out))
	var ee *exec.ExitError
	switch {
	case err == nil && state == "enabled":
		return sssdEnabledNote
	case errors.As(err, &ee) && ee.ExitCode() == 1 && state == "disabled":
		return ""
	case errors.As(err, &ee) && ee.ExitCode() == 1 && state == "masked":
		return sssdMaskedNote
	default:
		return sssdEnableUnknownNote
	}
}

// startSSSD enables and starts sssd, expires its cache and restarts it on the
// new sssd.conf. Any failed step calls restore once, restarts sssd on the
// restored config and returns one error that names the failed step and says
// whether the restore and that restart worked. enabled is what the abort
// message lists for sssd's enable state: sssdEnabledNote after a successful
// `enable --now`, else sssdEnableState.
func startSSSD(run commandRunner, restore func() (string, error)) (enabled string, err error) {
	for i, step := range [][]string{
		{"systemctl", "enable", "--now", "sssd"},
		{"sss_cache", "-E"},
		{"systemctl", "restart", "sssd"},
	} {
		out, serr := run(step[0], step[1:]...)
		if i == 0 {
			enabled = sssdEnabledNote
			if serr != nil {
				enabled = sssdEnableState(run)
			}
		}
		if serr == nil {
			continue
		}
		return enabled, fmt.Errorf("%s: %s: %w (%s)", strings.Join(step, " "), strings.TrimSpace(string(out)), serr,
			rollbackSSSD(run, restore, true))
	}
	return enabled, nil
}

// startSSSDStep is step 7 of --setup-ldap: startSSSD, then reset-failed on
// the SSSD units. It returns remaining (the host changes an abort leaves in
// place) plus sssd's enable state from startSSSD ("sssd enabled", or that the
// state is unknown), and on failure an error that is the complete abort
// message, after sssd.conf was restored and sssd restarted on it.
func startSSSDStep(run commandRunner, restore func() (string, error), remaining []string) ([]string, error) {
	enabled, err := startSSSD(run, restore)
	if enabled != "" {
		remaining = append(remaining, enabled)
	}
	if err != nil {
		return remaining, errors.New(setupAbortMessage("start sssd: "+err.Error(), "", remaining))
	}
	fmt.Println("sssd restarted")
	if err := resetFailedSSSDUnits(); err != nil {
		return remaining, errors.New(setupAbortMessage(err.Error(), rollbackSSSD(run, restore, true), remaining))
	}
	return remaining, nil
}

// rollbackSSSD undoes the sssd.conf write (restores the previous file, or
// removes the new one when none existed) and, with restart (sssd runs on the
// new one), restarts sssd. It returns what happened, for the abort message.
func rollbackSSSD(run commandRunner, restore func() (string, error), restart bool) string {
	did, err := restore()
	if err != nil {
		return fmt.Sprintf("could NOT roll back sssd.conf: %v; sssd not restarted; fix /etc/sssd/sssd.conf manually", err)
	}
	if !restart {
		return did
	}
	if out, err := run("systemctl", "restart", "sssd"); err != nil {
		return fmt.Sprintf("%s, but sssd did not restart: %s: %v", did, strings.TrimSpace(string(out)), err)
	}
	return did + " and restarted sssd"
}

// keptSSSDConf is the rollback note of a failed account migration: the new
// sssd.conf stays, and when a local entry was already removed, that account
// resolves only through it.
func keptSSSDConf(removed bool) string {
	if removed {
		return "kept the new sssd.conf: the local accounts whose entry was removed resolve only through the directory"
	}
	return "kept the new sssd.conf; no local account was changed"
}

// setupAbortMessage appends the rollback state (if any) and the host changes
// an abort leaves in place to msg.
func setupAbortMessage(msg, rollback string, remaining []string) string {
	if rollback != "" {
		msg += " (" + rollback + ")"
	}
	if len(remaining) > 0 {
		msg += "; still in place on the host: " + strings.Join(remaining, ", ")
	}
	return msg
}

// installPackages installs pkgs with the profile's install command. On apt the
// package index is refreshed first; a failed refresh is an error, the install
// does not run against a stale index.
func installPackages(prof distro.Profile, run commandRunner, pkgs []string) error {
	name, args := prof.InstallCmd, append([]string{"install", "-y"}, pkgs...)
	if prof.InstallCmd == "apt-get" {
		if out, err := run("apt-get", "update"); err != nil {
			return fmt.Errorf("apt-get update: %s: %w", strings.TrimSpace(string(out)), err)
		}
		// debconf must not prompt: the setup runs unattended.
		name, args = "env", append([]string{"DEBIAN_FRONTEND=noninteractive", "apt-get"}, args...)
	}
	if out, err := run(name, args...); err != nil {
		return fmt.Errorf("%s install -y %s: %s: %w", prof.InstallCmd, strings.Join(pkgs, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}

// ensureSSSDPackages installs the SSSD LDAP/NSS/PAM packages using the distro
// profile's install command and package list, and marks them as explicitly
// installed. Every failed command is an error.
func ensureSSSDPackages(prof distro.Profile, kerberos bool, run commandRunner) error {
	// Install the SSSD (and, on RHEL, the mkhomedir) packages unconditionally.
	// This is deliberately NOT gated on the `sssd` daemon already being present:
	// on RHEL the daemon ships in sssd-common and can exist WITHOUT the LDAP
	// backend (sssd-ldap / libsss_ldap.so), and skipping the install then leaves
	// the directory domain unable to start ("Could not restart critical service").
	// Package managers no-op on already-installed packages, so running every time
	// is safe and idempotent.
	pkgs := append(append([]string{}, prof.SSSDPackages...), prof.MkhomedirPackages...)
	if kerberos {
		pkgs = append(pkgs, prof.KrbPackages...)
	}
	fmt.Printf("Installing %s ...\n", strings.Join(pkgs, " "))
	if err := installPackages(prof, run, pkgs); err != nil {
		return err
	}
	// Installing a package that is already present as a dependency leaves its
	// install reason alone. Mark ours as explicitly installed so that removing
	// pam-device-auth never takes sssd-dbus (the ifp responder sssd.conf enables)
	// or the rest of the SSSD stack with it.
	if mark := markManualCommand(prof, pkgs); mark != nil {
		if out, err := run(mark[0], mark[1:]...); err != nil {
			return fmt.Errorf("%s (removing pam-device-auth may remove these packages): %s: %w",
				strings.Join(mark, " "), strings.TrimSpace(string(out)), err)
		}
	}
	return nil
}

// markManualCommand returns the command that marks pkgs as explicitly
// installed, or nil when the profile has none.
func markManualCommand(prof distro.Profile, pkgs []string) []string {
	if len(prof.MarkManualCmd) == 0 || len(pkgs) == 0 {
		return nil
	}
	return append(append([]string{}, prof.MarkManualCmd...), pkgs...)
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
		if err := installPackages(prof, execRunner, prof.SudoInstall); err != nil {
			return err
		}
	}
	if err := os.MkdirAll("/etc/sudoers.d", 0755); err != nil {
		return fmt.Errorf("mkdir /etc/sudoers.d: %w", err)
	}
	return writeSudoersAt("/etc/sudoers.d/pam-device-auth", renderSudoers(adminGroup, nopasswdGroups), visudoCheck)
}

// visudoCheck validates the whole sudoers set; a seam so tests never run the
// host's visudo against a temp file.
var visudoCheck = func() ([]byte, error) { return exec.Command("visudo", "-c").CombinedOutput() }

// writeSudoersAt writes the sudoers drop-in content to path (0440) and
// validates the whole sudoers set with check (visudoCheck); a drop-in that
// would break sudo is rolled back (writeValidated).
func writeSudoersAt(path, content string, check func() ([]byte, error)) error {
	return writeValidated(path, []byte(content), 0440, "visudo -c", "", check)
}

// readPrior reads the file a writer is about to replace, for its rollback.
// existed is false only when there is none (fs.ErrNotExist). Every other read
// error is returned before anything is written: a rollback cannot restore
// what it could not read, and must never delete it instead.
func readPrior(path string) (prior []byte, existed bool, err error) {
	prior, err = os.ReadFile(path)
	switch {
	case err == nil:
		return prior, true, nil
	case errors.Is(err, fs.ErrNotExist):
		return nil, false, nil
	}
	return nil, false, fmt.Errorf("cannot read the existing %s: %w; nothing was written", path, err)
}

// writeValidated writes content to path atomically and validates it with
// check (checkName in messages). A rejected file is rolled back: the previous
// file is restored, or the new one removed when none existed; the error names
// the rejection and, if the rollback failed, the manual fix (fixWhen is
// appended to it). A write that is in place but whose directory sync failed
// (errWrittenNotSynced) is still validated and rolled back on rejection; when
// it passes, that error is returned and says the validated file is in place.
func writeValidated(path string, content []byte, mode os.FileMode, checkName, fixWhen string, check func() ([]byte, error)) error {
	prior, existed, err := readPrior(path)
	if err != nil {
		return err
	}
	werr := atomicWriteFile(path, content, mode)
	if werr != nil && !errors.Is(werr, errWrittenNotSynced) {
		return werr
	}
	out, cerr := check()
	if cerr == nil {
		if werr != nil {
			return fmt.Errorf("%w; it passed %s", werr, checkName)
		}
		return nil
	}
	var rerr error
	if existed {
		rerr = atomicWriteFile(path, prior, mode)
	} else {
		rerr = os.Remove(path)
	}
	if rerr != nil {
		return fmt.Errorf("%s rejected the drop-in (%s) AND rollback failed (%v); fix %s manually%s: %w",
			checkName, strings.TrimSpace(string(out)), rerr, path, fixWhen, cerr)
	}
	return fmt.Errorf("%s rejected the drop-in (%s): %w", checkName, strings.TrimSpace(string(out)), cerr)
}

// sshdLogVerbose makes sshd log the client's version line (kex.c, debug1) at
// any LogLevel; internal/sshclient reads it from the journal.
const sshdLogVerbose = "LogVerbose kex.c:kex_exchange_identification():*"

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
func renderSshdDropin(sssAuthKeysPath string, serviceGroups []string, rootLogin string) string {
	// root_login = "disabled" refuses every SSH login of root; anything else
	// keeps the key-only emergency path.
	permitRoot := "prohibit-password"
	if rootLogin == config.RootLoginDisabled {
		permitRoot = "no"
	}
	base := fmt.Sprintf(`# Managed by pam-device-auth --setup-ldap (directory mode)
KbdInteractiveAuthentication yes
PermitRootLogin %s
UsePAM yes
PasswordAuthentication no
MaxAuthTries 3
# VERBOSE logs the key fingerprint of every accepted and rejected key.
LogLevel VERBOSE
# QR auto-detection needs the client version, which sshd logs at
# debug1 only; this forces just that line.
%s
# Non-root: SSH key (from the directory via SSSD) AND OIDC (keyboard-interactive/PAM).
# AuthorizedKeysFile none: local ~/.ssh/authorized_keys must NOT work for
# non-root, otherwise a same-named local account bypasses directory revocation.
AuthenticationMethods publickey,keyboard-interactive:pam
AuthorizedKeysFile none
AuthorizedKeysCommand %s
AuthorizedKeysCommandUser nobody
`, permitRoot, sshdLogVerbose, sssAuthKeysPath)

	// Service accounts (automation/management): directory key ONLY, no OIDC.
	// A Match block overrides the global AuthenticationMethods for these members;
	// their key is still served exclusively by sss_ssh_authorizedkeys.
	if len(serviceGroups) > 0 {
		base += fmt.Sprintf(`
# Service accounts (directory service groups): key-only (no OIDC) for automation.
Match Group %s
    AuthenticationMethods publickey
`, strings.Join(serviceGroups, ","))
	}

	if rootLogin == config.RootLoginDisabled {
		// No Match block for root: PermitRootLogin no refuses it before any
		// authentication method is tried.
		return base + `
# Root: SSH login disabled (root_login = "disabled" in config.json). Root is
# reachable only through a console.
`
	}
	// Root: local SSH key only (break-glass); root never uses OIDC/SSSD.
	base += `
Match User root
    AuthenticationMethods publickey
    AuthorizedKeysFile .ssh/authorized_keys
`
	return base
}

// setupWarnings collects findings of a --setup-ldap run that need the
// operator but changed nothing on the host (a shadowing local account skipped
// because it has running processes), so the final message cannot claim a
// clean success. A failed step that changes the host is never a warning: it
// aborts the setup.
var setupWarnings []string

// setupWarnf prints a warning now and remembers it for the final summary.
func setupWarnf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	setupWarnings = append(setupWarnings, msg)
	fmt.Fprintf(os.Stderr, "warn: %s\n", msg)
}

// sshdDropinPath and sshdTest are variables so tests can point the drop-in at a
// temp dir and fake a rejecting `sshd -t`.
var (
	sshdDropinPath = "/etc/ssh/sshd_config.d/10-pam-device-auth.conf"
	sshdTest       = func() ([]byte, error) { return exec.Command("sshd", "-t").CombinedOutput() }
)

// writeSshdDropin writes the directory-mode sshd drop-in: non-root must satisfy
// publickey (key fetched from the directory via sssAuthKeysPath) AND
// keyboard-interactive (OIDC via pam_device_auth) — true 2FA. Root stays
// key-only (break-glass): the root Match block restores the local
// AuthorizedKeysFile, so root's ~/.ssh/authorized_keys keeps working
// regardless of the directory command. The file is validated with `sshd -t` and
// reverted on failure; it takes effect at the next sshd restart (performed by
// `--enable`), avoiding a lockout window.
func writeSshdDropin(sssAuthKeysPath string, serviceGroups []string, rootLogin string) error {
	content := renderSshdDropin(sssAuthKeysPath, serviceGroups, rootLogin)
	if err := writeValidated(sshdDropinPath, []byte(content), 0644, "sshd -t", " before restarting sshd", sshdTest); err != nil {
		return err
	}
	fmt.Println("Wrote sshd drop-in: publickey,keyboard-interactive (2FA), local keys disabled for non-root")
	return nil
}

func fail(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", a...)
	os.Exit(1)
}
