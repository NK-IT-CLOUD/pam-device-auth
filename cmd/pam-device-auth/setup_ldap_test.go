package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
)

func TestSudoersAdminOnly(t *testing.T) {
	got := renderSudoers("ssh-admin", nil)
	if !strings.Contains(got, "%ssh-admin ALL=(ALL:ALL) ALL\n") {
		t.Fatalf("admin rule missing:\n%s", got)
	}
	if strings.Contains(got, "NOPASSWD") {
		t.Fatalf("unexpected NOPASSWD:\n%s", got)
	}
}

func TestSudoersWithNopasswdGroups(t *testing.T) {
	got := renderSudoers("ssh-admin", []string{"ssh-admin-nopasswd"})
	// admin (password) rule present, AND a NOPASSWD rule AFTER it (last match wins for dual members)
	iAdmin := strings.Index(got, "%ssh-admin ALL=(ALL:ALL) ALL")
	iNP := strings.Index(got, "%ssh-admin-nopasswd ALL=(ALL:ALL) NOPASSWD:ALL")
	if iAdmin < 0 || iNP < 0 || iNP < iAdmin {
		t.Fatalf("nopasswd rule missing or not after admin rule:\n%s", got)
	}
}

func TestWriteSSSDConfAt_AtomicAndRestores(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sssd.conf")

	// Pre-existing known-good config that must be recoverable.
	if err := os.WriteFile(path, []byte("[old]\nknown-good\n"), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	restore, err := writeSSSDConfAt(path, "[new]\nfresh\n")
	if err != nil {
		t.Fatalf("writeSSSDConfAt: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "[new]\nfresh\n" {
		t.Errorf("after write, content = %q, want new content", got)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0600 {
		t.Errorf("perm = %o, want 0600", fi.Mode().Perm())
	}
	// No stray temp files left behind in the directory.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("expected only sssd.conf, got %d entries (temp leak?)", len(entries))
	}

	// Restore must reinstate the prior known-good config (simulating a failed
	// sssd restart on the new config).
	restore()
	got, _ = os.ReadFile(path)
	if string(got) != "[old]\nknown-good\n" {
		t.Errorf("after restore, content = %q, want prior known-good", got)
	}
}

func TestWriteSSSDConfAt_RestoreRemovesWhenNoPrior(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sssd.conf")

	restore, err := writeSSSDConfAt(path, "[new]\nfresh\n")
	if err != nil {
		t.Fatalf("writeSSSDConfAt: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file should exist after write: %v", err)
	}
	// No prior config existed, so restore removes the file entirely.
	restore()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("restore should remove file when no prior existed; stat err = %v", err)
	}
}

// validLDAP returns a directory config that must pass validation; tests mutate
// one field at a time to assert a specific rejection.
func validLDAP() *config.LDAPConfig {
	return &config.LDAPConfig{
		URI:          "ldaps://lldap.nkit.cloud:636",
		BaseDN:       "dc=nkit,dc=cloud",
		BindDN:       "cn=admin,ou=people,dc=nkit,dc=cloud",
		BindPassword: "s3cr3t-with-symbols!@#",
		AccessGroup:  "ssh-access",
		AdminGroup:   "ssh-admin",
	}
}

func TestValidateLDAPConfig_AcceptsValid(t *testing.T) {
	if err := validateLDAPConfig(validLDAP()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestValidateLDAPConfig_AcceptsExplicitSearchBases(t *testing.T) {
	l := validLDAP()
	l.UserSearchBase = "ou=people,dc=nkit,dc=cloud"
	l.GroupSearchBase = "ou=groups,dc=nkit,dc=cloud"
	if err := validateLDAPConfig(l); err != nil {
		t.Fatalf("valid explicit search bases rejected: %v", err)
	}
}

func TestValidateLDAPConfig_RejectsIncomplete(t *testing.T) {
	l := validLDAP()
	l.URI = ""
	if err := validateLDAPConfig(l); err == nil {
		t.Error("incomplete config (missing uri) should be rejected")
	}
}

// Finding 1: newline in user_search_base / group_search_base injects sssd.conf
// directives — these fields previously bypassed the newline guard entirely.
func TestValidateLDAPConfig_RejectsNewlineInUserSearchBase(t *testing.T) {
	l := validLDAP()
	l.UserSearchBase = "ou=people,dc=x\nldap_tls_reqcert = never"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("newline in user_search_base should be rejected (sssd.conf injection)")
	}
}

func TestValidateLDAPConfig_RejectsNewlineInGroupSearchBase(t *testing.T) {
	l := validLDAP()
	l.GroupSearchBase = "ou=groups,dc=x\nldap_access_filter = (objectClass=*)"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("newline in group_search_base should be rejected (access-filter override)")
	}
}

func TestValidateLDAPConfig_RejectsNewlineInBaseDN(t *testing.T) {
	l := validLDAP()
	l.BaseDN = "dc=x\nldap_tls_reqcert = never"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("newline in base_dn should be rejected")
	}
}

// Finding 2: LDAP-filter metacharacters in a search base break out of the
// (memberOf=cn=<group>,<base>) access filter, widening who may log in.
func TestValidateLDAPConfig_RejectsFilterMetacharsInGroupSearchBase(t *testing.T) {
	l := validLDAP()
	l.GroupSearchBase = "ou=g,dc=x)(uid=*"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("LDAP-filter metacharacters in group_search_base should be rejected")
	}
}

func TestValidateLDAPConfig_RejectsFilterMetacharsInBaseDN(t *testing.T) {
	l := validLDAP()
	l.BaseDN = "dc=x)(uid=*"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("LDAP-filter metacharacters in base_dn should be rejected")
	}
}

// Finding 3: group names land in sudoers (%group) and the access filter; a
// value carrying sudoers grammar can silently grant passwordless root.
func TestValidateLDAPConfig_RejectsSudoersPayloadInAdminGroup(t *testing.T) {
	l := validLDAP()
	l.AdminGroup = "ssh-admin ALL=(ALL:ALL) NOPASSWD:ALL #"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("sudoers-significant characters in admin_group should be rejected")
	}
}

func TestValidateLDAPConfig_RejectsMetacharsInAccessGroup(t *testing.T) {
	for _, bad := range []string{"ssh access", "ssh=access", "ssh,access", "ssh)access", "ssh*"} {
		l := validLDAP()
		l.AccessGroup = bad
		if err := validateLDAPConfig(l); err == nil {
			t.Errorf("access_group %q should be rejected", bad)
		}
	}
}

func TestValidateLDAPConfig_AcceptsHyphenAndUnderscoreGroups(t *testing.T) {
	l := validLDAP()
	l.AccessGroup = "ssh-access_2"
	l.AdminGroup = "ssh_admins"
	if err := validateLDAPConfig(l); err != nil {
		t.Fatalf("hyphen/underscore group names rejected: %v", err)
	}
}

// Guard against the injection error message leaking the (secret) bind password:
// the error must name the field, not echo the value, for password fields.
func TestValidateLDAPConfig_RejectsNewlineInBindPassword(t *testing.T) {
	l := validLDAP()
	l.BindPassword = "pw\nldap_tls_reqcert = never"
	err := validateLDAPConfig(l)
	if err == nil {
		t.Fatal("newline in bind_password should be rejected")
	}
	if strings.Contains(err.Error(), "ldap_tls_reqcert") {
		t.Error("error message must not echo the bind_password value")
	}
}

// The restore closure is the emergency path after a failed `systemctl restart
// sssd` — it must use the same temp-file+rename pattern as the forward write.
// atomicWriteFile is that shared primitive.
func TestAtomicWriteFile_WritesContentModeAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/sssd.conf"
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := atomicWriteFile(path, []byte("[restored]\n"), 0600); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "[restored]\n" {
		t.Errorf("content = %q", got)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temp file left behind: %v", entries)
	}
}

func TestAtomicWriteFile_ErrorLeavesTargetUntouched(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/sub/does-not-exist/sssd.conf"
	if err := atomicWriteFile(path, []byte("x"), 0600); err == nil {
		t.Error("expected error for unwritable directory")
	}
}

func TestSshdDropinDisablesLocalKeysForNonRoot(t *testing.T) {
	content := renderSshdDropin("/usr/bin/sss_ssh_authorizedkeys", nil)
	matchIdx := strings.Index(content, "Match User root")
	if matchIdx < 0 {
		t.Fatal("drop-in must contain a 'Match User root' block")
	}
	global := content[:matchIdx]
	rootBlock := content[matchIdx:]
	if !strings.Contains(global, "AuthorizedKeysFile none") {
		t.Error("global section must set 'AuthorizedKeysFile none' (PDA-SEC-001)")
	}
	if !strings.Contains(rootBlock, "AuthorizedKeysFile .ssh/authorized_keys") {
		t.Error("root Match block must restore 'AuthorizedKeysFile .ssh/authorized_keys' (break-glass)")
	}
}

func TestSshdDropinNoServiceGroupsUnchanged(t *testing.T) {
	got := renderSshdDropin("/usr/bin/sss_ssh_authorizedkeys", nil)
	if strings.Contains(got, "Match Group") {
		t.Fatalf("no service groups but Match Group present:\n%s", got)
	}
}

func TestSshdDropinServiceGroupKeyOnly(t *testing.T) {
	got := renderSshdDropin("/usr/bin/sss_ssh_authorizedkeys", []string{"ssh-service", "ci"})
	if !strings.Contains(got, "Match Group ssh-service,ci\n    AuthenticationMethods publickey\n") {
		t.Fatalf("service Match block wrong:\n%s", got)
	}
	// Root block must still be present and after (or independent of) the service block.
	if !strings.Contains(got, "Match User root") {
		t.Fatalf("root break-glass block lost:\n%s", got)
	}
}

func TestNsswitchWithSSS(t *testing.T) {
	in := []byte("passwd: files systemd\ngroup: files\nshadow: files\nhosts: files dns\n")
	out, changed := nsswitchWithSSS(in)
	if !changed {
		t.Fatal("expected changed=true")
	}
	got := string(out)
	for _, want := range []string{"passwd: files systemd sss", "group: files sss", "shadow: files sss"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "hosts: files dns") || strings.Contains(got, "hosts: files dns sss") {
		t.Error("hosts line must be untouched")
	}
	if _, changed := nsswitchWithSSS(out); changed {
		t.Error("second pass must be a no-op")
	}
}

func TestSshdDropinUsesProfileSSSPath(t *testing.T) {
	got := renderSshdDropin("/usr/libexec/sssd/sss_ssh_authorizedkeys", nil)
	if !strings.Contains(got, "AuthorizedKeysCommand /usr/libexec/sssd/sss_ssh_authorizedkeys") {
		t.Fatalf("sshd drop-in missing RHEL SSS path:\n%s", got)
	}
}

func TestSSSDConfUsesProfileCAPath(t *testing.T) {
	d := ldapRenderData{
		URI:          "ldaps://lldap.nkit.cloud:636",
		BaseDN:       "dc=nkit,dc=cloud",
		UserBase:     "ou=people,dc=nkit,dc=cloud",
		GroupBase:    "ou=groups,dc=nkit,dc=cloud",
		BindDN:       "cn=admin,ou=people,dc=nkit,dc=cloud",
		BindPassword: "s3cr3t-with-symbols!@#",
		AccessGroup:  "ssh-access",
	}
	got := renderSSSDConf(d, "/etc/pki/tls/certs/ca-bundle.crt")
	if !strings.Contains(got, "ldap_tls_cacert = /etc/pki/tls/certs/ca-bundle.crt") {
		t.Fatalf("sssd.conf missing RHEL CA path:\n%s", got)
	}
}

// Debian-family regression: the same renderers must still produce the
// historical Debian values when given the Debian profile's paths.
func TestSSSDConfUsesDebianCAPathByDefault(t *testing.T) {
	d := ldapRenderData{
		URI:          "ldaps://lldap.nkit.cloud:636",
		BaseDN:       "dc=nkit,dc=cloud",
		UserBase:     "ou=people,dc=nkit,dc=cloud",
		GroupBase:    "ou=groups,dc=nkit,dc=cloud",
		BindDN:       "cn=admin,ou=people,dc=nkit,dc=cloud",
		BindPassword: "s3cr3t-with-symbols!@#",
		AccessGroup:  "ssh-access",
	}
	got := renderSSSDConf(d, "/etc/ssl/certs/ca-certificates.crt")
	if !strings.Contains(got, "ldap_tls_cacert = /etc/ssl/certs/ca-certificates.crt") {
		t.Fatalf("sssd.conf missing Debian CA path:\n%s", got)
	}
}

func TestSshdDropinUsesDebianSSSPathByDefault(t *testing.T) {
	got := renderSshdDropin("/usr/bin/sss_ssh_authorizedkeys", nil)
	if !strings.Contains(got, "AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys") {
		t.Fatalf("sshd drop-in missing Debian SSS path:\n%s", got)
	}
}

func TestSSSDConfSingleGroupUnchanged(t *testing.T) {
	got := renderSSSDConf(ldapRenderData{URI: "u", BaseDN: "b", UserBase: "ub", GroupBase: "gb", BindDN: "bd", BindPassword: "pw", AccessGroup: "ssh-access"}, "/ca")
	if !strings.Contains(got, "ldap_access_filter = (memberOf=cn=ssh-access,gb)\n") {
		t.Fatalf("single-group filter changed:\n%s", got)
	}
	for _, want := range []string{
		"services = nss, pam, ssh, ifp\n",
		"ldap_user_extra_attrs = clients:clients\n",
		"[ifp]\nuser_attributes = +clients\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("sssd.conf missing %q:\n%s", want, got)
		}
	}
}

func TestSSSDConfWidenedFilterWithServiceGroups(t *testing.T) {
	got := renderSSSDConf(ldapRenderData{URI: "u", BaseDN: "b", UserBase: "ub", GroupBase: "gb", BindDN: "bd", BindPassword: "pw", AccessGroup: "ssh-access", ServiceGroups: []string{"ssh-service"}}, "/ca")
	want := "ldap_access_filter = (|(memberOf=cn=ssh-access,gb)(memberOf=cn=ssh-service,gb))\n"
	if !strings.Contains(got, want) {
		t.Fatalf("widened filter wrong:\n%s", got)
	}
	for _, want := range []string{
		"services = nss, pam, ssh, ifp\n",
		"ldap_user_extra_attrs = clients:clients\n",
		"[ifp]\nuser_attributes = +clients\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("sssd.conf missing %q:\n%s", want, got)
		}
	}
}

func TestSSSDConfHasInfoPipeForClients(t *testing.T) {
	got := renderSSSDConf(ldapRenderData{URI: "u", BaseDN: "b", UserBase: "ub", GroupBase: "gb", BindDN: "bd", BindPassword: "pw", AccessGroup: "ssh-access"}, "/ca")
	for _, want := range []string{
		"services = nss, pam, ssh, ifp\n",
		"ldap_user_extra_attrs = clients:clients\n",
		"[ifp]\nuser_attributes = +clients\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("sssd.conf missing %q:\n%s", want, got)
		}
	}
}

func TestValidateRejectsBadServiceGroup(t *testing.T) {
	l := validLDAP()
	l.ServiceAccountGroups = []string{"ok", "bad group"}
	if err := validateLDAPConfig(l); err == nil {
		t.Fatal("expected rejection of 'bad group'")
	}
}
