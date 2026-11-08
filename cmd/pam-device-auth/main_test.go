package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
)

func TestCheckSSSAuthKeysMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sss_ssh_authorizedkeys")
	err := checkSSSAuthKeys(path)
	if err == nil {
		t.Fatal("checkSSSAuthKeys(missing) = nil, want an error")
	}
	for _, want := range []string{path, "sssd-common"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

func TestCheckSSSAuthKeysOK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sss_ssh_authorizedkeys")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := checkSSSAuthKeys(path); err != nil {
		t.Errorf("checkSSSAuthKeys(0755 file) = %v, want nil", err)
	}
}

func TestCheckSSSAuthKeysRefusesNonExecutableAndNonRegular(t *testing.T) {
	dir := t.TempDir()
	noExec := filepath.Join(dir, "noexec")
	if err := os.WriteFile(noExec, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"not executable": noExec, "directory": dir} {
		err := checkSSSAuthKeys(path)
		if err == nil || !strings.Contains(err.Error(), path) {
			t.Errorf("%s: checkSSSAuthKeys(%s) = %v, want an error naming the path", name, path, err)
		}
	}
}

func TestBackupFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "sshd")
	const original = "auth required pam_unix.so\n"
	if err := os.WriteFile(src, []byte(original), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// First backup: dst does not exist yet → copy made.
	dst := filepath.Join(dir, "sshd.original")
	didBackup, err := backupFile(src, dst)
	if err != nil {
		t.Fatalf("backupFile() error: %v", err)
	}
	if !didBackup {
		t.Error("backupFile() didBackup = false, want true on first backup")
	}
	got, _ := os.ReadFile(dst)
	if string(got) != original {
		t.Errorf("backup content = %q, want %q", got, original)
	}

	// Second call: dst already exists → must not overwrite, no error.
	if err := os.WriteFile(src, []byte("MODIFIED"), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	didBackup, err = backupFile(src, dst)
	if err != nil {
		t.Fatalf("backupFile() error on existing dst: %v", err)
	}
	if didBackup {
		t.Error("backupFile() didBackup = true, want false when backup exists")
	}
	got, _ = os.ReadFile(dst)
	if string(got) != original {
		t.Errorf("backup overwritten: %q, want preserved %q", got, original)
	}

	// Write failure: parent dir of dst does not exist → error surfaced.
	badDst := filepath.Join(dir, "missing-subdir", "sshd.original")
	didBackup, err = backupFile(src, badDst)
	if err == nil {
		t.Error("backupFile() error = nil, want error on unwritable dst")
	}
	if didBackup {
		t.Error("backupFile() didBackup = true, want false on write failure")
	}
}

// --debug must work regardless of position: the dispatch loop in main exits
// on the first subcommand flag, so debug detection needs a pre-pass.
func TestHasFlag(t *testing.T) {
	if !hasFlag([]string{"--check", "--debug"}, "--debug") {
		t.Error("--debug after subcommand should be found")
	}
	if hasFlag([]string{"--check"}, "--debug") {
		t.Error("absent flag should not be found")
	}
}

// stubSshd installs a fake `sshd` on PATH that answers `-T` (and `-T -C
// user=...`) with the given effective-config lines, mimicking `sshd -T`
// output well enough for sshdParam.
func stubSshd(t *testing.T, config string) {
	t.Helper()
	dir := t.TempDir()
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' '%s'\n", config)
	if err := os.WriteFile(filepath.Join(dir, "sshd"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestSshdParam_AuthorizedKeysFile(t *testing.T) {
	tests := []struct {
		name   string
		config string
		want   string
	}{
		{
			name:   "old drop-in leaves default authorizedkeysfile",
			config: "authorizedkeyscommand /usr/bin/sss_ssh_authorizedkeys\nauthorizedkeysfile .ssh/authorized_keys\n",
			want:   ".ssh/authorized_keys",
		},
		{
			name:   "hardened drop-in disables local keys",
			config: "authorizedkeyscommand /usr/bin/sss_ssh_authorizedkeys\nauthorizedkeysfile none\n",
			want:   "none",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubSshd(t, tt.config)
			got, ok := sshdParam("authorizedkeysfile", "nobody")
			if !ok {
				t.Fatal("sshdParam() ok = false, want true")
			}
			if got != tt.want {
				t.Errorf("sshdParam(authorizedkeysfile) = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLDAPTransportDescription(t *testing.T) {
	for _, c := range []struct {
		uri    string
		keytab string
		want   string
	}{
		{"ldaps://dc1.example.com", "", "LDAPS"},
		{"LDAPS://dc1.example.com", "", "LDAPS"},
		{"ldap://dc1.example.com", "", "StartTLS"},
		{"ldap://dc1.example.com", "/etc/krb5.sssd.keytab", "GSSAPI with SASL sealing"},
	} {
		l := &config.LDAPConfig{URI: c.uri}
		if c.keytab != "" {
			l.Kerberos = &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com", Keytab: c.keytab}
		}
		if got := ldapTransportDescription(l); got != c.want {
			t.Errorf("%s keytab=%q: %q, want %q", c.uri, c.keytab, got, c.want)
		}
	}
}

// --check fails on a keytab over ldaps:// or with an IP address as the URI
// host as --setup-ldap does, and never reports that config as "GSSAPI with
// SASL sealing".
func TestLDAPURICheck(t *testing.T) {
	const keytabErr = "ldap.kerberos.keytab requires an ldap:// URI: the GSSAPI bind is protected by SASL sealing, not TLS"
	const hostErr = "ldap.kerberos.keytab needs the DC's host name in ldap.uri, not an IP address: GSSAPI uses the ldap/<host> service principal"
	for _, c := range []struct {
		uri    string
		keytab bool
		ok     bool
		msg    string
	}{
		{"ldaps://dc1.example.com", false, true, "ldap.uri is a single URI, transport LDAPS (no cleartext bind)"},
		{"ldap://dc1.example.com", true, true, "ldap.uri is a single URI, transport GSSAPI with SASL sealing (no cleartext bind)"},
		{"ldaps://dc1.example.com", true, false, keytabErr},
		{"LDAPS://dc1.example.com", true, false, keytabErr},
		{"ldap://192.0.2.10", true, false, hostErr},
		{"ldap://[2001:db8::1]:389", true, false, hostErr},
		{"ldap://192.0.2.10", false, true, "ldap.uri is a single URI, transport StartTLS (no cleartext bind)"},
		{"ldaps://a.example.com,ldap://b.example.com", true, false, `ldap.uri must be a single ldaps:// or ldap:// URI (got "ldaps://a.example.com,ldap://b.example.com"): a comma/space separated list is an SSSD failover list`},
	} {
		l := &config.LDAPConfig{URI: c.uri}
		if c.keytab {
			l.Kerberos = &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com", Keytab: "/etc/krb5.sssd.keytab"}
		}
		ok, okMsg, badMsg := ldapURICheck(l)
		msg := badMsg
		if ok {
			msg = okMsg
		}
		if ok != c.ok || msg != c.msg {
			t.Errorf("%s keytab=%v: ok=%v msg=%q, want ok=%v msg=%q", c.uri, c.keytab, ok, msg, c.ok, c.msg)
		}
	}
}

// A resolving access group proves the CA path only where TLS carries the
// directory connection; a keytab bind runs GSSAPI with SASL sealing instead.
func TestDirectoryPathOK(t *testing.T) {
	for _, c := range []struct {
		name string
		l    *config.LDAPConfig
		want string
	}{
		{"keytab", &config.LDAPConfig{URI: "ldap://dc1.example.com",
			Kerberos: &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com", Keytab: "/etc/krb5.sssd.keytab"}}, "SSSD↔LDAP path OK (GSSAPI)"},
		{"ldaps password", &config.LDAPConfig{URI: "ldaps://dc1.example.com"}, "SSSD↔LDAP↔CA path OK"},
		{"starttls password", &config.LDAPConfig{URI: "ldap://dc1.example.com"}, "SSSD↔LDAP↔CA path OK"},
		{"kerberos without keytab", &config.LDAPConfig{URI: "ldaps://dc1.example.com",
			Kerberos: &config.KerberosConfig{Realm: "EXAMPLE.COM", KDC: "dc1.example.com"}}, "SSSD↔LDAP↔CA path OK"},
	} {
		if got := directoryPathOK(c.l); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// --check accepts the same profiles as --setup-ldap and fails on any other.
func TestLDAPProfileCheck(t *testing.T) {
	for _, c := range []struct {
		profile string
		ok      bool
		msg     string
	}{
		{"", false, `config: ldap.profile is required ("lldap" or "ad")`},
		{"lldap", true, "profile lldap"},
		{"ad", true, "profile ad"},
		{"openldap", false, `ldap.profile must be "lldap" or "ad", got "openldap"`},
		{"AD", false, `ldap.profile must be "lldap" or "ad", got "AD"`},
	} {
		ok, okMsg, badMsg := ldapProfileCheck(&config.LDAPConfig{Profile: c.profile})
		msg := badMsg
		if ok {
			msg = okMsg
		}
		if ok != c.ok || msg != c.msg {
			t.Errorf("profile %q: ok=%v msg=%q, want ok=%v msg=%q", c.profile, ok, msg, c.ok, c.msg)
		}
	}
}

// --check reports the login shell of directory users (ldap.shell or the
// default) by the rule --setup-ldap enforces.
func TestLDAPShellCheck(t *testing.T) {
	dir := t.TempDir()
	sh := filepath.Join(dir, "sh")
	if err := os.WriteFile(sh, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if ok, okMsg, _ := ldapShellCheck(&config.LDAPConfig{Shell: sh}); !ok || okMsg != "login shell "+sh+" is executable" {
		t.Errorf("valid shell: ok=%v msg=%q", ok, okMsg)
	}
	missing := filepath.Join(dir, "missing")
	if ok, _, badMsg := ldapShellCheck(&config.LDAPConfig{Shell: missing}); ok || !strings.HasPrefix(badMsg, "login shell "+missing+" (ldap.shell): ") {
		t.Errorf("missing shell: ok=%v msg=%q", ok, badMsg)
	}
	// A relative path that resolves from the working directory of --check is
	// still refused, as --setup-ldap refuses it.
	t.Chdir(dir)
	if ok, _, badMsg := ldapShellCheck(&config.LDAPConfig{Shell: "sh"}); ok || badMsg != `ldap.shell must be an absolute path without whitespace, got "sh"` {
		t.Errorf("relative shell: ok=%v msg=%q", ok, badMsg)
	}
}

// --check states what it verified for ldap.ca_file: a regular file. Whether
// the SSSD service user can read it is not checked.
func TestCAFileCheck(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, []byte("-----BEGIN CERTIFICATE-----\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if ok, okMsg, _ := caFileCheck(ca); !ok || okMsg != "ldap.ca_file is a regular file: "+ca {
		t.Errorf("regular file: ok=%v msg=%q, want ok=true msg=%q", ok, okMsg, "ldap.ca_file is a regular file: "+ca)
	}
	if ok, _, badMsg := caFileCheck(dir); ok || badMsg != "ldap.ca_file "+dir+" is not a regular file" {
		t.Errorf("directory: ok=%v msg=%q, want ok=false msg=%q", ok, badMsg, "ldap.ca_file "+dir+" is not a regular file")
	}
}

func TestKDCHost(t *testing.T) {
	for kdc, want := range map[string]string{
		"dc1.example.com":    "dc1.example.com",
		"dc1.example.com:88": "dc1.example.com",
		"[2001:db8::1]:88":   "2001:db8::1",
		"[2001:db8::1]":      "2001:db8::1",
		"2001:db8::1":        "2001:db8::1",
		"192.0.2.10:88":      "192.0.2.10",
	} {
		if got := kdcHost(kdc); got != want {
			t.Errorf("kdcHost(%q) = %q, want %q", kdc, got, want)
		}
	}
}

func TestAccessGroupFailMessage(t *testing.T) {
	msg := accessGroupFailMessage("ssh-access")
	for _, want := range []string{`"ssh-access"`, "StartTLS"} {
		if !strings.Contains(msg, want) {
			t.Errorf("accessGroupFailMessage = %q, missing %q", msg, want)
		}
	}
}
