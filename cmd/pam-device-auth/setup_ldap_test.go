package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/distro"
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
		URI:          "ldaps://ldap.example.com:636",
		BaseDN:       "dc=example,dc=com",
		BindDN:       "cn=admin,ou=people,dc=example,dc=com",
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
	l.UserSearchBase = "ou=people,dc=example,dc=com"
	l.GroupSearchBase = "ou=groups,dc=example,dc=com"
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
	content := renderSshdDropin("/usr/bin/sss_ssh_authorizedkeys", nil, "")
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

func TestSshdDropinLogsOnlyClientVersion(t *testing.T) {
	content := renderSshdDropin("/usr/bin/sss_ssh_authorizedkeys", nil, "")
	global := content[:strings.Index(content, "Match ")]
	if !strings.Contains(global, "\nLogLevel VERBOSE\n") || strings.Contains(content, "DEBUG") {
		t.Errorf("drop-in must set LogLevel VERBOSE and no debug level:\n%s", content)
	}
	if !strings.Contains(global, "\n"+sshdLogVerbose+"\n") {
		t.Errorf("global section must force the client version line (%q):\n%s", sshdLogVerbose, content)
	}
}

func TestSshdDropinNoServiceGroupsUnchanged(t *testing.T) {
	got := renderSshdDropin("/usr/bin/sss_ssh_authorizedkeys", nil, "")
	if strings.Contains(got, "Match Group") {
		t.Fatalf("no service groups but Match Group present:\n%s", got)
	}
}

func TestSshdDropinServiceGroupKeyOnly(t *testing.T) {
	got := renderSshdDropin("/usr/bin/sss_ssh_authorizedkeys", []string{"ssh-service", "ci"}, "")
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
	got := renderSshdDropin("/usr/libexec/sssd/sss_ssh_authorizedkeys", nil, "")
	if !strings.Contains(got, "AuthorizedKeysCommand /usr/libexec/sssd/sss_ssh_authorizedkeys") {
		t.Fatalf("sshd drop-in missing RHEL SSS path:\n%s", got)
	}
}

func TestSSSDConfUsesProfileCAPath(t *testing.T) {
	d := ldapRenderData{
		URI:          "ldaps://ldap.example.com:636",
		BaseDN:       "dc=example,dc=com",
		UserBase:     "ou=people,dc=example,dc=com",
		GroupBase:    "ou=groups,dc=example,dc=com",
		BindDN:       "cn=admin,ou=people,dc=example,dc=com",
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
		URI:          "ldaps://ldap.example.com:636",
		BaseDN:       "dc=example,dc=com",
		UserBase:     "ou=people,dc=example,dc=com",
		GroupBase:    "ou=groups,dc=example,dc=com",
		BindDN:       "cn=admin,ou=people,dc=example,dc=com",
		BindPassword: "s3cr3t-with-symbols!@#",
		AccessGroup:  "ssh-access",
	}
	got := renderSSSDConf(d, "/etc/ssl/certs/ca-certificates.crt")
	if !strings.Contains(got, "ldap_tls_cacert = /etc/ssl/certs/ca-certificates.crt") {
		t.Fatalf("sssd.conf missing Debian CA path:\n%s", got)
	}
}

func TestSshdDropinUsesDebianSSSPathByDefault(t *testing.T) {
	got := renderSshdDropin("/usr/bin/sss_ssh_authorizedkeys", nil, "")
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

// The lldap profile must render what 0.5.15 rendered, minus config_file_version
// (SSSD 2.12 reports it; 2.x defaults to version 2). Any other diff is a
// behaviour change on every LLDAP host at the next --setup-ldap.
func TestRenderSSSDConf_LLDAPGolden(t *testing.T) {
	want, err := os.ReadFile("testdata/sssd-lldap.golden")
	if err != nil {
		t.Fatal(err)
	}
	got := renderSSSDConf(ldapRenderData{
		URI: "ldaps://ldap.example.com:6360", BaseDN: "dc=example,dc=com",
		UserBase: "ou=people,dc=example,dc=com", GroupBase: "ou=groups,dc=example,dc=com",
		BindDN: "uid=ro,ou=people,dc=example,dc=com", BindPassword: "pw",
		AccessGroup: "ssh-access", ServiceGroups: []string{"ssh-service"},
	}, "/etc/ssl/certs/ca-certificates.crt")
	if got != string(want) {
		t.Fatalf("lldap sssd.conf differs from the golden file:\n--- got\n%s\n--- want\n%s", got, want)
	}
}

func TestRenderSSSDConf_LLDAPExplicitDefaultsEqualGolden(t *testing.T) {
	want, _ := os.ReadFile("testdata/sssd-lldap.golden")
	got := renderSSSDConf(ldapRenderData{
		Profile: config.LDAPProfileLLDAP, URI: "ldaps://ldap.example.com:6360", BaseDN: "dc=example,dc=com",
		UserBase: "ou=people,dc=example,dc=com", GroupBase: "ou=groups,dc=example,dc=com",
		BindDN: "uid=ro,ou=people,dc=example,dc=com", BindPassword: "pw",
		AccessGroup: "ssh-access", ServiceGroups: []string{"ssh-service"},
		UserNameAttr: "uid", SSHKeyAttr: "sshPublicKey", ClientsAttr: "clients", Home: "/home/%u", Shell: "/bin/bash",
	}, "/etc/ssl/certs/ca-certificates.crt")
	if got != string(want) {
		t.Fatalf("explicit lldap defaults change the output:\n%s", got)
	}
}

func TestRenderSSSDConf_LLDAPStartTLSAndKerberos(t *testing.T) {
	got := renderSSSDConf(ldapRenderData{
		URI: "ldap://ldap.example.com:389", BaseDN: "dc=example,dc=com",
		UserBase: "ou=people,dc=example,dc=com", GroupBase: "ou=groups,dc=example,dc=com",
		BindDN: "uid=ro,ou=people,dc=example,dc=com", BindPassword: "pw", AccessGroup: "ssh-access",
		KrbRealm: "EXAMPLE.COM", KrbKDC: "kdc.example.com", KrbKpasswd: "kdc.example.com",
	}, "/etc/ssl/certs/ca-certificates.crt")
	for _, line := range []string{
		"auth_provider = krb5\n", "chpass_provider = krb5\n", "ldap_id_use_start_tls = true\n",
		"krb5_realm = EXAMPLE.COM\n", "krb5_server = kdc.example.com\n", "krb5_kpasswd = kdc.example.com\n",
		"ldap_tls_reqcert = hard\n",
	} {
		if !strings.Contains(got, line) {
			t.Errorf("missing %q in:\n%s", line, got)
		}
	}
}

// No option may produce a cleartext bind: the renderer itself decides StartTLS
// from the URI, for both profiles. url.Parse lowercases the scheme, so
// validateLDAPURI also lets LDAP:// through; it must get StartTLS as well.
func TestRenderSSSDConf_StartTLSDerivedFromURI(t *testing.T) {
	for _, profile := range []string{config.LDAPProfileLLDAP, config.LDAPProfileAD} {
		for _, c := range []struct {
			uri      string
			startTLS bool
		}{
			{"ldap://ldap.example.com:389", true},
			{"ldap://ldap.example.com", true},
			{"LDAP://ldap.example.com", true},
			{"ldaps://ldap.example.com:636", false},
			{"LDAPS://ldap.example.com", false},
		} {
			got := renderSSSDConf(ldapRenderData{
				Profile: profile, URI: c.uri, BaseDN: "dc=example,dc=com",
				UserBase: "ou=people,dc=example,dc=com", GroupBase: "ou=groups,dc=example,dc=com",
				BindDN: "uid=ro,ou=people,dc=example,dc=com", BindPassword: "pw", AccessGroup: "ssh-access",
			}, "/etc/ssl/certs/ca-certificates.crt")
			if has := strings.Contains(got, "ldap_id_use_start_tls = true\n"); has != c.startTLS {
				t.Errorf("profile %s, uri %s: ldap_id_use_start_tls present = %v, want %v:\n%s", profile, c.uri, has, c.startTLS, got)
			}
		}
	}
}

// A keytab replaces the simple bind: no bind DN/authtok lines, GSSAPI with the
// principal and SASL sealing (minssf 56). StartTLS is switched off explicitly,
// because SSSD 2.10 and later default ldap_id_use_start_tls to true and AD and
// Samba refuse GSSAPI sealing inside TLS.
func TestRenderSSSDConf_KeytabBind(t *testing.T) {
	for _, profile := range []string{config.LDAPProfileLLDAP, config.LDAPProfileAD} {
		for _, uri := range []string{"ldap://dc1.example.com", "LDAP://dc1.example.com"} {
			got := renderSSSDConf(ldapRenderData{
				Profile: profile, URI: uri, BaseDN: "DC=example,DC=com",
				UserBase: "DC=example,DC=com", GroupBase: "DC=example,DC=com",
				BindDN: "host/client1.example.com@EXAMPLE.COM", Keytab: "/etc/krb5.sssd.keytab", AccessGroup: "ssh-access",
				KrbRealm: "EXAMPLE.COM", KrbKDC: "dc1.example.com",
			}, "/etc/ssl/certs/ca-certificates.crt")
			for _, line := range []string{
				"ldap_sasl_mech = GSSAPI\n", "ldap_sasl_authid = host/client1.example.com@EXAMPLE.COM\n",
				"ldap_krb5_keytab = /etc/krb5.sssd.keytab\n", "ldap_krb5_init_creds = true\n",
				"ldap_uri = " + uri + "\nldap_id_use_start_tls = false\n", "ldap_sasl_minssf = 56\n",
			} {
				if !strings.Contains(got, line) {
					t.Errorf("profile %s, uri %s: missing %q:\n%s", profile, uri, line, got)
				}
			}
			for _, absent := range []string{"ldap_default_bind_dn", "ldap_default_authtok", "ldap_id_use_start_tls = true", "ldap_sasl_maxssf"} {
				if strings.Contains(got, absent) {
					t.Errorf("profile %s, uri %s: unexpected %s with a keytab:\n%s", profile, uri, absent, got)
				}
			}
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

// ldap:// is accepted because the renderer then enforces StartTLS (or SASL
// sealing with a keytab); every other scheme and every list stays rejected.
func TestValidateLDAPConfig_URIScheme(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		ok   bool
	}{
		{"ldaps with port accepted", "ldaps://ldap.example.com:6360", true},
		{"ldaps without port accepted", "ldaps://ldap.example.com", true},
		{"ldap accepted (StartTLS)", "ldap://ldap.example.com:389", true},
		{"ldapi rejected", "ldapi:///var/run/slapd.sock", false},
		{"http rejected", "http://ldap.example.com", false},
		{"garbage rejected", "not a uri", false},
		{"ldaps with empty host rejected", "ldaps://", false},
		{"failover list rejected", "ldaps://a.example.com,ldap://b.example.com", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := validLDAP()
			l.URI = c.uri
			err := validateLDAPConfig(l)
			if c.ok && err != nil {
				t.Fatalf("uri %q rejected: %v", c.uri, err)
			}
			if !c.ok && err == nil {
				t.Fatalf("uri %q should be rejected", c.uri)
			}
		})
	}
}

func validADLDAP() *config.LDAPConfig {
	l := validLDAP()
	l.Profile = config.LDAPProfileAD
	l.URI = "ldaps://dc1.example.com"
	l.BaseDN = "DC=example,DC=com"
	l.BindDN = "svc-sssd@example.com"
	l.Attributes = config.LDAPAttributes{SSHKey: "sshPublicKey", Clients: "extensionAttribute1"}
	return l
}

func TestValidateLDAPConfig_Profiles(t *testing.T) {
	if err := validateLDAPConfig(validADLDAP()); err != nil {
		t.Fatalf("valid ad config rejected: %v", err)
	}
	l := validLDAP()
	l.Profile = "openldap"
	if err := validateLDAPConfig(l); err == nil || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("unknown profile: err = %v", err)
	}
}

func TestValidateLDAPConfig_ADNeedsKeyAndClientsAttributes(t *testing.T) {
	for _, mut := range []func(*config.LDAPConfig){
		func(l *config.LDAPConfig) { l.Attributes.SSHKey = "" },
		func(l *config.LDAPConfig) { l.Attributes.Clients = "" },
	} {
		l := validADLDAP()
		mut(l)
		if err := validateLDAPConfig(l); err == nil {
			t.Fatalf("ad config without key/clients attribute accepted: %+v", l.Attributes)
		}
	}
}

func TestValidateLDAPConfig_AttributeNames(t *testing.T) {
	for _, c := range []struct {
		attr string
		ok   bool
	}{
		{"sshPublicKey", true}, {"msDS-cloudExtensionAttribute1", true}, {"extensionAttribute1", true},
		{"1bad", false}, {"bad attr", false}, {"bad:attr", false}, {"bad\nattr", false}, {"bad,attr", false},
	} {
		l := validADLDAP()
		l.Attributes.Clients = c.attr
		if err := validateLDAPConfig(l); (err == nil) != c.ok {
			t.Errorf("clients attribute %q: err = %v, want ok=%v", c.attr, err, c.ok)
		}
	}
}

func TestValidateLDAPConfig_GroupNamesExplainBareNames(t *testing.T) {
	for _, g := range []string{"SSH Access", `EXAMPLE\ssh-access`} {
		l := validADLDAP()
		l.AccessGroup = g
		err := validateLDAPConfig(l)
		if err == nil || !strings.Contains(err.Error(), "bare group name") {
			t.Errorf("access_group %q: err = %v, want a bare-group-name error", g, err)
		}
	}
}

func TestValidateLDAPConfig_PasswordSources(t *testing.T) {
	l := validLDAP()
	l.BindPasswordFile = "/etc/pam-device-auth/ldap.secret"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("bind_password and bind_password_file together accepted")
	}
	l.BindPassword = ""
	if err := validateLDAPConfig(l); err != nil {
		t.Errorf("bind_password_file alone rejected: %v", err)
	}
	l.BindPasswordFile = "relative/ldap.secret"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("relative bind_password_file accepted")
	}
	l = validLDAP()
	l.BindPassword = ""
	if err := validateLDAPConfig(l); err == nil {
		t.Error("no password and no keytab accepted")
	}
}

func TestValidateLDAPConfig_KerberosAndKeytab(t *testing.T) {
	l := validADLDAP()
	l.Kerberos = &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com", Kpasswd: "dc1.example.com"}
	if err := validateLDAPConfig(l); err != nil {
		t.Fatalf("valid kerberos rejected: %v", err)
	}
	l.Kerberos.Keytab = "/etc/krb5.sssd.keytab"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("keytab together with bind_password accepted")
	}
	l.BindPassword = ""
	l.BindDN = "svc-sssd@EXAMPLE.COM"
	l.URI = "ldap://dc1.example.com"
	if err := validateLDAPConfig(l); err != nil {
		t.Errorf("keytab bind over ldap:// rejected: %v", err)
	}
	for _, bad := range []config.KerberosConfig{
		{Realm: "example.com", KDC: "dc1.example.com"},                        // lower-case realm
		{Realm: "EXAMPLE.COM", KDC: ""},                                       // no kdc
		{Realm: "EXAMPLE.COM", KDC: "dc1.example.com\nx = y"},                 // injection
		{Realm: "EXAMPLE.COM", KDC: "dc1.example.com", Keytab: "krb5.keytab"}, // relative keytab
	} {
		l := validADLDAP()
		k := bad
		l.Kerberos = &k
		if k.Keytab != "" {
			l.BindPassword = ""
			l.BindDN = "svc-sssd@EXAMPLE.COM"
			l.URI = "ldap://dc1.example.com"
		}
		if err := validateLDAPConfig(l); err == nil {
			t.Errorf("bad kerberos %+v accepted", bad)
		}
	}
}

func TestKeytabTransportError(t *testing.T) {
	const want = "ldap.kerberos.keytab requires an ldap:// URI: the GSSAPI bind is protected by SASL sealing, not TLS"
	krb := &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com", Keytab: "/etc/krb5.sssd.keytab"}
	for _, c := range []struct {
		name string
		l    *config.LDAPConfig
		bad  bool
	}{
		{"keytab+ldaps", &config.LDAPConfig{URI: "ldaps://dc1.example.com", Kerberos: krb}, true},
		{"keytab+LDAPS", &config.LDAPConfig{URI: "LDAPS://dc1.example.com", Kerberos: krb}, true},
		{"keytab+ldap", &config.LDAPConfig{URI: "ldap://dc1.example.com", Kerberos: krb}, false},
		{"no keytab+ldaps", &config.LDAPConfig{URI: "ldaps://dc1.example.com",
			Kerberos: &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com"}}, false},
		{"no kerberos+ldaps", &config.LDAPConfig{URI: "ldaps://dc1.example.com"}, false},
	} {
		err := keytabTransportError(c.l)
		if c.bad && (err == nil || err.Error() != want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, want)
		}
		if !c.bad && err != nil {
			t.Errorf("%s: err = %v, want nil", c.name, err)
		}
	}
}

// The keytab bind is protected by SASL sealing, and AD and Samba refuse
// GSSAPI sealing inside TLS, so a keytab needs ldap://; ldaps:// is rejected
// in any letter case.
func TestValidateLDAPConfig_KeytabRequiresLDAPURI(t *testing.T) {
	const want = "ldap.kerberos.keytab requires an ldap:// URI: the GSSAPI bind is protected by SASL sealing, not TLS"
	for _, c := range []struct {
		uri string
		ok  bool
	}{
		{"ldap://dc1.example.com", true},
		{"LDAP://dc1.example.com", true},
		{"ldaps://dc1.example.com", false},
		{"LDAPS://dc1.example.com:636", false},
		{"LdApS://dc1.example.com", false},
	} {
		l := validADLDAP()
		l.URI = c.uri
		l.BindPassword = ""
		l.BindDN = "svc-sssd@EXAMPLE.COM"
		l.Kerberos = &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com", Keytab: "/etc/krb5.sssd.keytab"}
		err := validateLDAPConfig(l)
		if c.ok && err != nil {
			t.Errorf("keytab with %s rejected: %v", c.uri, err)
		}
		if !c.ok && (err == nil || err.Error() != want) {
			t.Errorf("keytab with %s: err = %v, want %q", c.uri, err, want)
		}
	}
	// A simple bind over ldaps:// stays valid.
	if err := validateLDAPConfig(validADLDAP()); err != nil {
		t.Errorf("password bind over ldaps:// rejected: %v", err)
	}
}

// With a keytab, bind_dn is the SASL authid, a Kerberos principal: it needs
// '/' and '$' (host/..., HOST$), which the bind DN charset rejects, and a DN
// makes no sense there.
func TestValidateLDAPConfig_KeytabBindDNIsPrincipal(t *testing.T) {
	for _, c := range []struct {
		dn string
		ok bool
	}{
		{"svc-sssd@EXAMPLE.COM", true},
		{"host/dc1.example.com@EXAMPLE.COM", true},
		{"HOST$@EXAMPLE.COM", true},
		{"CN=svc,DC=example,DC=com", false},
		{"svc-sssd@example.com", false},
		{"svc sssd@EXAMPLE.COM", false},
	} {
		l := validADLDAP()
		l.URI = "ldap://dc1.example.com"
		l.BindPassword = ""
		l.Kerberos = &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com", Keytab: "/etc/krb5.sssd.keytab"}
		l.BindDN = c.dn
		err := validateLDAPConfig(l)
		if c.ok && err != nil {
			t.Errorf("principal %q rejected: %v", c.dn, err)
		}
		if !c.ok && (err == nil || !strings.Contains(err.Error(), "Kerberos principal")) {
			t.Errorf("bind_dn %q with keytab: err = %v, want a Kerberos principal error", c.dn, err)
		}
	}
	l := validADLDAP()
	l.BindPassword = ""
	l.Kerberos = &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com", Keytab: "/etc/krb5.sssd.keytab"}
	l.BindDN = "svc-sssd@EXAMPLE.COM\nldap_tls_reqcert = never"
	if err := validateLDAPConfig(l); err == nil || !strings.Contains(err.Error(), "control character") {
		t.Errorf("principal with a newline: err = %v, want the control character error", err)
	}
	// Without a keytab the DN charset still applies: a DN stays valid.
	l = validADLDAP()
	l.BindDN = "CN=svc,DC=example,DC=com"
	if err := validateLDAPConfig(l); err != nil {
		t.Errorf("DN bind_dn without keytab rejected: %v", err)
	}
}

func TestValidateLDAPConfig_IDRangeHomeShell(t *testing.T) {
	l := validADLDAP()
	l.IDRange = &config.IDRange{Min: 10000, Max: 60000}
	l.Home, l.Shell = "/home/%d/%u", "/bin/zsh"
	if err := validateLDAPConfig(l); err != nil {
		t.Fatalf("valid id_range/home/shell rejected: %v", err)
	}
	for _, r := range []config.IDRange{{Min: 60000, Max: 10000}, {Min: 0, Max: 60000}, {Min: 10000, Max: 10000}} {
		l := validADLDAP()
		rr := r
		l.IDRange = &rr
		if err := validateLDAPConfig(l); err == nil {
			t.Errorf("bad id_range %+v accepted", r)
		}
	}
	off := false
	l = validADLDAP()
	l.IDMapping = &off
	l.IDRange = &config.IDRange{Min: 10000, Max: 60000}
	if err := validateLDAPConfig(l); err == nil || !strings.Contains(err.Error(), "ldap.id_range needs id_mapping") {
		t.Errorf("id_range with id_mapping=false: err = %v, want the id_mapping error", err)
	}
	l = validLDAP()
	l.IDRange = &config.IDRange{Min: 10000, Max: 60000}
	if err := validateLDAPConfig(l); err == nil {
		t.Error("id_range accepted for the lldap profile")
	}
	for _, p := range []string{"home/%u", "/home/%u x", "/home/%u\nx"} {
		l := validLDAP()
		l.Home = p
		if err := validateLDAPConfig(l); err == nil {
			t.Errorf("bad home %q accepted", p)
		}
	}
}

// Every value bound for sssd.conf rejects ASCII control characters, not only
// line breaks; the error names the field and never echoes a secret.
func TestValidateLDAPConfig_RejectsControlCharacters(t *testing.T) {
	for _, c := range []struct {
		name  string
		mut   func(*config.LDAPConfig)
		field string
	}{
		{"nul in bind_password", func(l *config.LDAPConfig) { l.BindPassword = "s3cret\x00x" }, "bind_password"},
		{"esc in bind_password", func(l *config.LDAPConfig) { l.BindPassword = "s3cret\x1b[0m" }, "bind_password"},
		{"bel in base_dn", func(l *config.LDAPConfig) { l.BaseDN = "dc=example\x07,dc=com" }, "base_dn"},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := validLDAP()
			c.mut(l)
			err := validateLDAPConfig(l)
			if err == nil || !strings.Contains(err.Error(), "ldap."+c.field+" contains a control character") {
				t.Fatalf("err = %v, want a control-character error for ldap.%s", err, c.field)
			}
			if strings.Contains(err.Error(), "s3cret") {
				t.Fatalf("error echoes the secret: %v", err)
			}
		})
	}
}

// bind_dn may be a DN, a UPN or a down-level logon name, but never carries
// LDAP filter metacharacters.
func TestValidateLDAPConfig_BindDNCharset(t *testing.T) {
	for _, c := range []struct {
		dn string
		ok bool
	}{
		{"CN=svc,OU=x,DC=example,DC=com", true},
		{"svc-sssd@example.com", true},
		{`EXAMPLE\svc-sssd`, true},
		{"svc(sssd)", false},
		{"svc*", false},
	} {
		l := validADLDAP()
		l.BindDN = c.dn
		err := validateLDAPConfig(l)
		if c.ok && err != nil {
			t.Errorf("bind_dn %q rejected: %v", c.dn, err)
		}
		if !c.ok && (err == nil || !strings.Contains(err.Error(), "ldap.bind_dn")) {
			t.Errorf("bind_dn %q: err = %v, want a bind_dn charset error", c.dn, err)
		}
	}
}

func TestCheckSecretFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	os.WriteFile(good, []byte("x\n"), 0600)
	if err := checkSecretFile(good); err != nil {
		t.Fatalf("0600 file rejected: %v", err)
	}
	loose := filepath.Join(dir, "loose")
	os.WriteFile(loose, []byte("x\n"), 0640)
	if err := checkSecretFile(loose); err == nil {
		t.Error("0640 file accepted")
	}
	link := filepath.Join(dir, "link")
	os.Symlink(good, link)
	if err := checkSecretFile(link); err == nil {
		t.Error("symlink accepted")
	}
	if err := checkSecretFile(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file accepted")
	}
}

// A symlink to a valid 0600 file is refused for the keytab and for
// bind_password_file, by name, and the error never carries the secret.
func TestSecretFile_SymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "ldap.secret")
	if err := os.WriteFile(target, []byte("s3cret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.secret")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := checkSecretFile(link); err == nil || err.Error() != link+" is a symlink" {
		t.Errorf("checkSecretFile(symlink) = %v, want %q", err, link+" is a symlink")
	}
	l := validLDAP()
	l.BindPassword = ""
	l.BindPasswordFile = link
	pw, err := resolveBindPassword(l)
	if err == nil || pw != "" {
		t.Fatalf("resolveBindPassword(symlink) = %q, %v; want an error", pw, err)
	}
	if want := "ldap.bind_password_file: " + link + " is a symlink"; err.Error() != want {
		t.Errorf("err = %q, want %q", err, want)
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("error echoes the secret: %v", err)
	}
}

// A FIFO is refused as not a regular file instead of blocking the open until
// a writer appears.
func TestCheckSecretFile_FIFORejected(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- checkSecretFile(fifo) }()
	select {
	case err := <-done:
		if err == nil || err.Error() != fifo+" is not a regular file" {
			t.Fatalf("checkSecretFile(fifo) = %v, want %q", err, fifo+" is not a regular file")
		}
	case <-time.After(2 * time.Second):
		// Release the blocked open so the goroutine ends.
		if w, err := os.OpenFile(fifo, os.O_WRONLY, 0); err == nil {
			w.Close()
		}
		t.Fatal("checkSecretFile blocks on a FIFO")
	}
}

type fakeFileInfo struct {
	mode os.FileMode
	sys  any
}

func (f fakeFileInfo) Name() string       { return "secret" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return f.sys }

// Without a syscall.Stat_t the owner is unknown, so the file is refused.
func TestCheckSecretFileInfo_NoOwnerFailsClosed(t *testing.T) {
	if err := checkSecretFileInfo("/etc/x.secret", fakeFileInfo{mode: 0600}); err == nil {
		t.Fatal("file without owner information accepted")
	}
	own := &syscall.Stat_t{Uid: uint32(os.Geteuid())}
	if err := checkSecretFileInfo("/etc/x.secret", fakeFileInfo{mode: 0600, sys: own}); err != nil {
		t.Fatalf("0600 file of the effective user rejected: %v", err)
	}
}

func TestCAFileError(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, []byte("-----BEGIN CERTIFICATE-----\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := caFileError(ca); err != nil {
		t.Errorf("regular file rejected: %v", err)
	}
	link := filepath.Join(dir, "ca-link.pem")
	if err := os.Symlink(ca, link); err != nil {
		t.Fatal(err)
	}
	if err := caFileError(link); err != nil {
		t.Errorf("symlink to a regular file rejected: %v", err)
	}
	if err := caFileError(dir); err == nil || err.Error() != "ldap.ca_file "+dir+" is not a regular file" {
		t.Errorf("directory: err = %v, want \"ldap.ca_file %s is not a regular file\"", err, dir)
	}
	missing := filepath.Join(dir, "missing.pem")
	if err := caFileError(missing); err == nil || !strings.Contains(err.Error(), "ldap.ca_file") || !strings.Contains(err.Error(), missing) {
		t.Errorf("missing file: err = %v, want an ldap.ca_file error naming %s", err, missing)
	}
}

func TestResolveBindPassword(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(content), 0600)
		return p
	}
	for _, c := range []struct {
		name, content, want string
		ok                  bool
	}{
		{"lf", "s3cret\n", "s3cret", true},
		{"crlf", "s3cret\r\n", "s3cret", true},
		{"no newline", "s3cret", "s3cret", true},
		{"two lines", "s3cret\nldap_tls_reqcert = never\n", "", false},
		{"empty", "\n", "", false},
		{"nul", "s3cret\x00x\n", "", false},
		{"esc", "s3cret\x1b[0m\n", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := validLDAP()
			l.BindPassword = ""
			l.BindPasswordFile = write(c.name, c.content)
			got, err := resolveBindPassword(l)
			if c.ok && (err != nil || got != c.want) {
				t.Fatalf("got %q, %v; want %q", got, err, c.want)
			}
			if !c.ok {
				if err == nil {
					t.Fatal("bad password file accepted")
				}
				if strings.Contains(err.Error(), "s3cret") {
					t.Fatalf("error echoes the secret: %v", err)
				}
			}
		})
	}
	// At most 4096 bytes are read; a longer file fails closed instead of
	// yielding a truncated password.
	l := validLDAP()
	l.BindPassword = ""
	l.BindPasswordFile = write("max", "s3cret"+strings.Repeat("x", 4096-6))
	if got, err := resolveBindPassword(l); err != nil || len(got) != 4096 {
		t.Errorf("4096-byte password file: len %d, %v; want accepted", len(got), err)
	}
	l.BindPasswordFile = write("long", "s3cret"+strings.Repeat("x", 5000-6))
	if got, err := resolveBindPassword(l); err == nil || got != "" || err.Error() != "ldap.bind_password_file is longer than 4096 bytes" {
		t.Errorf("5000-byte password file: %d bytes, %v; want \"ldap.bind_password_file is longer than 4096 bytes\"", len(got), err)
	}
	l = validLDAP()
	if got, err := resolveBindPassword(l); err != nil || got != l.BindPassword {
		t.Fatalf("inline password: %q, %v", got, err)
	}
}

func adRender(t *testing.T, mut func(*config.LDAPConfig)) string {
	t.Helper()
	l := validADLDAP()
	if mut != nil {
		mut(l)
	}
	if err := validateLDAPConfig(l); err != nil {
		t.Fatalf("test config invalid: %v", err)
	}
	pw, _ := resolveBindPassword(l)
	return renderSSSDConf(renderDataFor(l, pw), "/etc/ssl/certs/ca-certificates.crt")
}

func TestRenderSSSDConf_ADDefaults(t *testing.T) {
	got := adRender(t, nil)
	for _, line := range []string{
		"access_provider = simple\n", "simple_allow_groups = ssh-access\n", "ldap_schema = ad\n",
		"ldap_referrals = false\n", "case_sensitive = false\n", "ldap_user_name = sAMAccountName\n",
		"ldap_user_ssh_public_key = sshPublicKey\n", "ldap_user_extra_attrs = clients:extensionAttribute1\n",
		"ldap_id_mapping = true\n", "chpass_provider = none\n", "ldap_user_search_base = DC=example,DC=com\n",
		"ldap_group_search_base = DC=example,DC=com\n", "ldap_tls_reqcert = hard\n", "user_attributes = +clients\n",
	} {
		if !strings.Contains(got, line) {
			t.Errorf("missing %q in:\n%s", line, got)
		}
	}
	for _, absent := range []string{"ldap_access_filter", "posixAccount", "ldap_id_use_start_tls", "config_file_version"} {
		if strings.Contains(got, absent) {
			t.Errorf("unexpected %q in:\n%s", absent, got)
		}
	}
	extra, ifp := sssdClientsExposure(got)
	if !extra || !ifp {
		t.Errorf("--check would reject the rendered ad config (extra=%v ifp=%v)", extra, ifp)
	}
}

func TestRenderSSSDConf_ADServiceGroupsAndIDRange(t *testing.T) {
	got := adRender(t, func(l *config.LDAPConfig) {
		l.ServiceAccountGroups = []string{"ssh-service"}
		l.IDRange = &config.IDRange{Min: 10000, Max: 60000}
	})
	for _, line := range []string{
		"simple_allow_groups = ssh-access, ssh-service\n", "ldap_idmap_range_min = 10000\n",
		"ldap_idmap_range_max = 60000\n", "ldap_idmap_range_size = 50000\n",
	} {
		if !strings.Contains(got, line) {
			t.Errorf("missing %q in:\n%s", line, got)
		}
	}
}

func TestRenderSSSDConf_ADStartTLS(t *testing.T) {
	got := adRender(t, func(l *config.LDAPConfig) { l.URI = "ldap://dc1.example.com" })
	if !strings.Contains(got, "ldap_id_use_start_tls = true\n") {
		t.Fatalf("ldap:// without StartTLS:\n%s", got)
	}
}

func TestRenderSSSDConf_ADGSSAPIOverLDAP(t *testing.T) {
	got := adRender(t, func(l *config.LDAPConfig) {
		l.URI = "ldap://dc1.example.com"
		l.BindPassword = ""
		l.BindDN = "svc-sssd@EXAMPLE.COM"
		l.Kerberos = &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com", Keytab: "/etc/krb5.sssd.keytab"}
	})
	for _, line := range []string{
		"ldap_sasl_mech = GSSAPI\n", "ldap_sasl_authid = svc-sssd@EXAMPLE.COM\n",
		"ldap_krb5_keytab = /etc/krb5.sssd.keytab\n", "ldap_sasl_minssf = 56\n", "auth_provider = krb5\n",
		"ldap_id_use_start_tls = false\n",
	} {
		if !strings.Contains(got, line) {
			t.Errorf("missing %q in:\n%s", line, got)
		}
	}
	for _, absent := range []string{"ldap_default_authtok", "ldap_default_bind_dn", "ldap_id_use_start_tls = true"} {
		if strings.Contains(got, absent) {
			t.Errorf("GSSAPI bind still renders %q:\n%s", absent, got)
		}
	}
}

func TestRenderSSSDConf_ADIDMappingOff(t *testing.T) {
	off := false
	got := adRender(t, func(l *config.LDAPConfig) { l.IDMapping = &off })
	if !strings.Contains(got, "ldap_id_mapping = false\n") || strings.Contains(got, "ldap_idmap_range") {
		t.Fatalf("id_mapping=false:\n%s", got)
	}
}

func TestRenderDataFor_LLDAPDefaultsMatchGolden(t *testing.T) {
	l := validLDAP()
	l.BaseDN = "dc=example,dc=com"
	l.URI = "ldaps://ldap.example.com:6360"
	l.BindDN = "uid=ro,ou=people,dc=example,dc=com"
	l.BindPassword = "pw"
	l.ServiceAccountGroups = []string{"ssh-service"}
	want, _ := os.ReadFile("testdata/sssd-lldap.golden")
	if got := renderSSSDConf(renderDataFor(l, "pw"), "/etc/ssl/certs/ca-certificates.crt"); got != string(want) {
		t.Fatalf("renderDataFor changes the lldap output:\n%s", got)
	}
}

// The password from bind_password_file must reach sssd.conf, not only pass
// validation.
func TestRenderDataFor_BindPasswordFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ldap.secret")
	if err := os.WriteFile(p, []byte("s3cret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	l := validLDAP()
	l.BindPassword = ""
	l.BindPasswordFile = p
	if err := validateLDAPConfig(l); err != nil {
		t.Fatalf("test config invalid: %v", err)
	}
	pw, err := resolveBindPassword(l)
	if err != nil {
		t.Fatalf("resolveBindPassword: %v", err)
	}
	got := renderSSSDConf(renderDataFor(l, pw), "/etc/ssl/certs/ca-certificates.crt")
	if !strings.Contains(got, "ldap_default_authtok = s3cret\n") {
		t.Fatalf("bind_password_file content missing from sssd.conf:\n%s", got)
	}
}

func TestCACertFor(t *testing.T) {
	prof := distro.Profile{CACertPath: "/etc/ssl/certs/ca-certificates.crt"}
	l := validLDAP()
	if got := caCertFor(l, prof); got != prof.CACertPath {
		t.Errorf("default CA = %q", got)
	}
	l.CAFile = "/usr/local/share/ca-certificates/dir-ca.crt"
	if got := caCertFor(l, prof); got != l.CAFile {
		t.Errorf("ca_file ignored: %q", got)
	}
}
