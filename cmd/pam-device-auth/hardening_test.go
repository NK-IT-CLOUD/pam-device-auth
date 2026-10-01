package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateLDAPURI(t *testing.T) {
	cases := []struct {
		uri string
		ok  bool
	}{
		{"ldaps://lldap.example:6360", true},
		{"ldaps://lldap.example", true},
		{"ldaps://lldap.example/", true},
		{"ldap://lldap.example", false},
		{"ldaps://", false},
		{"", false},
		// SSSD failover lists: url.Parse accepts these, SSSD would fall back to cleartext.
		{"ldaps://a,ldap://b", false},
		{"ldaps://a/,ldap://b", false},
		// No path at all: only the list-separator check catches this; SSSD would
		// read "b" as a second server without a scheme.
		{"ldaps://a,b", false},
		{"ldaps://a:6360,b:389", false},
		{"ldaps://a, ldaps://b", false},
		{"ldaps://a ldaps://b", false},
		{"ldaps://a\tldap://b", false},
		{"ldaps://a\nldap://b", false},
		{"ldaps://a/base?x=1", false},
		{"ldaps://a/dc=x", false},
	}
	for _, c := range cases {
		err := validateLDAPURI(c.uri)
		if c.ok && err != nil {
			t.Errorf("validateLDAPURI(%q) = %v, want ok", c.uri, err)
		}
		if !c.ok && err == nil {
			t.Errorf("validateLDAPURI(%q) accepted, want rejection", c.uri)
		}
	}
}

func TestValidateLDAPConfig_RejectsFailoverList(t *testing.T) {
	l := validLDAP()
	l.URI = "ldaps://a,ldap://b"
	if err := validateLDAPConfig(l); err == nil {
		t.Fatal("validateLDAPConfig accepted a comma separated URI list")
	}
}

func TestSSSDClientsExposure(t *testing.T) {
	good := "[sssd]\ndomains = nkit\n\n[domain/nkit]\nldap_user_extra_attrs = clients:clients\n\n[ifp]\nuser_attributes = +clients\n"
	cases := []struct {
		name      string
		conf      string
		wantExtra bool
		wantIFP   bool
	}{
		{"both present", good, true, true},
		{"spacing and case", "[domain/x]\n LDAP_User_Extra_Attrs=clients:clients , foo:foo\n[ifp]\nuser_attributes=+clients,+foo\n", true, true},
		{"no ifp", "[domain/nkit]\nldap_user_extra_attrs = clients:clients\n", true, false},
		{"no extra attrs", "[domain/nkit]\nldap_uri = ldaps://x\n[ifp]\nuser_attributes = +clients\n", false, true},
		{"empty", "", false, false},
		{"commented out", "[domain/nkit]\n# ldap_user_extra_attrs = clients:clients\n[ifp]\n; user_attributes = +clients\n", false, false},
		{"wrong section", "[nss]\nldap_user_extra_attrs = clients:clients\nuser_attributes = +clients\n", false, false},
		{"different attribute", "[domain/nkit]\nldap_user_extra_attrs = other:other\n[ifp]\nuser_attributes = +other\n", false, false},
		{"clients without plus in ifp", "[ifp]\nuser_attributes = clients\n", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			extra, ifp := sssdClientsExposure(c.conf)
			if extra != c.wantExtra || ifp != c.wantIFP {
				t.Fatalf("sssdClientsExposure() = (%v, %v), want (%v, %v)", extra, ifp, c.wantExtra, c.wantIFP)
			}
		})
	}
}

// What --setup-ldap renders must satisfy what --check demands.
func TestRenderedSSSDConfExposesClients(t *testing.T) {
	conf := renderSSSDConf(ldapRenderData{
		URI: "ldaps://lldap.example:6360", BaseDN: "dc=example,dc=com",
		UserBase: "ou=people,dc=example,dc=com", GroupBase: "ou=groups,dc=example,dc=com",
		BindDN: "uid=ro,ou=people,dc=example,dc=com", BindPassword: "x", AccessGroup: "ssh-access",
	}, "/etc/ssl/certs/ca.pem")
	extra, ifp := sssdClientsExposure(conf)
	if !extra || !ifp {
		t.Fatalf("rendered sssd.conf does not expose clients (extra=%v ifp=%v):\n%s", extra, ifp, conf)
	}
}

func TestDropinNeedsRender(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "10-pam-device-auth.conf")
	if !dropinNeedsRender(path, "/usr/bin/sss_ssh_authorizedkeys") {
		t.Error("missing drop-in must be rendered")
	}
	if err := os.WriteFile(path, []byte("AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if dropinNeedsRender(path, "/usr/bin/sss_ssh_authorizedkeys") {
		t.Error("drop-in with the resolved path must be kept")
	}
	// RHEL: stale template path from an older version, binary lives elsewhere.
	if !dropinNeedsRender(path, "/usr/libexec/sssd/sss_ssh_authorizedkeys") {
		t.Error("stale drop-in (wrong AuthorizedKeysCommand path) must be re-rendered")
	}
	if dropinNeedsRender(path, "") {
		t.Error("unresolved sss path must not trigger a render")
	}
}

func TestBackupFile_RefusesUnusableRollbackCopies(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Existing backup that already contains the module is not a pristine original.
	src := write("pam-a", "auth required pam_unix.so\n")
	dirty := write("pam-a.original", "auth required pam_device_auth.so\n")
	if did, err := backupFile(src, dirty); err == nil || did {
		t.Errorf("polluted backup: did=%v err=%v; want an error", did, err)
	}

	// Source already wired and no backup yet: nothing pristine to save.
	wired := write("pam-b", "auth required pam_device_auth.so\n")
	if did, err := backupFile(wired, filepath.Join(dir, "pam-b.original")); err == nil || did {
		t.Errorf("wired source without backup: did=%v err=%v; want an error", did, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "pam-b.original")); err == nil {
		t.Error("backup of an already modified config was written")
	}

	// Unreadable source (a directory) is an error, not "nothing to back up".
	if did, err := backupFile(dir, filepath.Join(dir, "pam-c.original")); err == nil || did {
		t.Errorf("unreadable src: did=%v err=%v; want an error", did, err)
	}

	// Missing source stays "nothing to back up".
	if did, err := backupFile(filepath.Join(dir, "missing"), filepath.Join(dir, "pam-d.original")); err != nil || did {
		t.Errorf("missing src: did=%v err=%v; want false, nil", did, err)
	}

	// Pristine source is saved.
	if did, err := backupFile(src, filepath.Join(dir, "pam-a.saved")); err != nil || !did {
		t.Errorf("pristine src: did=%v err=%v; want true, nil", did, err)
	}
}

// writeSshdDropin must roll back when `sshd -t` rejects the new drop-in.
func TestWriteSshdDropin_RollsBackOnRejection(t *testing.T) {
	oldPath, oldTest := sshdDropinPath, sshdTest
	t.Cleanup(func() { sshdDropinPath, sshdTest = oldPath, oldTest })
	sshdDropinPath = filepath.Join(t.TempDir(), "10-pam-device-auth.conf")
	rejected := func() ([]byte, error) { return []byte("bad config"), errors.New("exit status 255") }
	accepted := func() ([]byte, error) { return nil, nil }

	// Previous drop-in exists: it must come back byte for byte.
	if err := os.WriteFile(sshdDropinPath, []byte("# previous\n"), 0644); err != nil {
		t.Fatal(err)
	}
	sshdTest = rejected
	err := writeSshdDropin("/usr/bin/sss_ssh_authorizedkeys", nil)
	if err == nil || !strings.Contains(err.Error(), "sshd -t rejected") {
		t.Fatalf("writeSshdDropin() = %v; want sshd -t rejection", err)
	}
	if got, _ := os.ReadFile(sshdDropinPath); string(got) != "# previous\n" {
		t.Errorf("previous drop-in not restored, got %q", got)
	}

	// No previous drop-in: the rejected file must be removed.
	os.Remove(sshdDropinPath)
	if err := writeSshdDropin("/usr/bin/sss_ssh_authorizedkeys", nil); err == nil {
		t.Fatal("expected rejection error")
	}
	if _, err := os.Stat(sshdDropinPath); err == nil {
		t.Error("rejected drop-in left behind with no previous file")
	}

	// Accepted: the drop-in stays and references the resolved path.
	sshdTest = accepted
	if err := writeSshdDropin("/usr/libexec/sssd/sss_ssh_authorizedkeys", nil); err != nil {
		t.Fatalf("writeSshdDropin() accepted case: %v", err)
	}
	if got, _ := os.ReadFile(sshdDropinPath); !strings.Contains(string(got), "/usr/libexec/sssd/sss_ssh_authorizedkeys") {
		t.Errorf("drop-in does not reference the resolved path:\n%s", got)
	}
}

func TestWriteSSSDConfAt_RestoreReportsFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sssd.conf")
	if err := os.WriteFile(path, []byte("[old]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	restore, err := writeSSSDConfAt(path, "[new]\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := restore(); err != nil {
		t.Fatalf("restore() = %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "[old]\n" {
		t.Fatalf("restore did not reinstate previous content, got %q", got)
	}

	// Make the rollback impossible (directory not writable) and expect a real error.
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions; rollback failure cannot be provoked")
	}
	restore, err = writeSSSDConfAt(path, "[new2]\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })
	if err := restore(); err == nil {
		t.Fatal("restore() = nil although the rollback write must fail")
	}
}

func TestBusctlFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	if got := busctlFailure(ctx, errors.New("signal: killed")); !strings.Contains(got, "timed out") {
		t.Errorf("deadline case = %q, want a timeout message", got)
	}

	// A real ExitError with stderr: sh writes a diagnostic and exits 1.
	_, err := exec.Command("sh", "-c", "echo 'Failed to connect to bus' >&2; exit 1").Output()
	got := busctlFailure(context.Background(), err)
	if !strings.Contains(got, "Failed to connect to bus") || !strings.Contains(got, "exit status 1") {
		t.Errorf("exit case = %q, want exit status plus stderr", got)
	}

	if got := busctlFailure(context.Background(), errors.New("boom")); got != "boom" {
		t.Errorf("plain error = %q, want boom", got)
	}
}
