package distro

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestFromOSRelease(t *testing.T) {
	const (
		debCA   = "/etc/ssl/certs/ca-certificates.crt"
		rhelCA  = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
		debSSS  = "/usr/bin/sss_ssh_authorizedkeys"
		rhelSSS = "/usr/bin/sss_ssh_authorizedkeys"
		ifp     = "/usr/libexec/sssd/sssd_ifp" // both families (sssd-dbus)
	)
	accepted := []struct {
		id, version, wantFamily, wantInstall, wantCA, wantTemplate, wantService, wantSSS, wantSoDir string
	}{
		{"ubuntu", "24.04", "debian", "apt-get", debCA, "pam-sshd-device-auth", "ssh.service", debSSS, "/usr/lib/security"},
		{"ubuntu", "26.04", "debian", "apt-get", debCA, "pam-sshd-device-auth", "ssh.service", debSSS, "/usr/lib/security"},
		{"debian", "13", "debian", "apt-get", debCA, "pam-sshd-device-auth", "ssh.service", debSSS, "/usr/lib/security"},
		{"debian", "14", "debian", "apt-get", debCA, "pam-sshd-device-auth", "ssh.service", debSSS, "/usr/lib/security"},
		{"rocky", "9.6", "rhel", "dnf", rhelCA, "pam-sshd-device-auth-rhel", "sshd.service", rhelSSS, "/usr/lib64/security"},
		{"rocky", "10.0", "rhel", "dnf", rhelCA, "pam-sshd-device-auth-rhel", "sshd.service", rhelSSS, "/usr/lib64/security"},
		{"rocky", "10", "rhel", "dnf", rhelCA, "pam-sshd-device-auth-rhel", "sshd.service", rhelSSS, "/usr/lib64/security"},
		{"fedora", "44", "rhel", "dnf", rhelCA, "pam-sshd-device-auth-rhel", "sshd.service", rhelSSS, "/usr/lib64/security"},
		{"fedora", "45", "rhel", "dnf", rhelCA, "pam-sshd-device-auth-rhel", "sshd.service", rhelSSS, "/usr/lib64/security"},
	}
	for _, c := range accepted {
		t.Run(c.id+" "+c.version, func(t *testing.T) {
			p, err := fromOSRelease(c.id, c.version)
			if err != nil {
				t.Fatalf("fromOSRelease(%q,%q) error: %v", c.id, c.version, err)
			}
			if p.Family != c.wantFamily || p.InstallCmd != c.wantInstall || p.CACertPath != c.wantCA ||
				p.PamTemplate != c.wantTemplate || p.SSHService != c.wantService ||
				p.SSSAuthKeysPath != c.wantSSS || p.SoDir != c.wantSoDir || p.SSSDIfpPath != ifp {
				t.Fatalf("fromOSRelease(%q,%q) = %+v", c.id, c.version, p)
			}
		})
	}

	refused := []struct{ id, version string }{
		{"ubuntu", "22.04"},
		{"debian", "12"},
		{"rocky", "8.10"},
		{"rocky", "11"},
		{"fedora", "43"},
		{"almalinux", "9.6"},
		{"centos", "9"},
		{"rhel", "9.6"},
		{"alpine", "3.24.4"},
		{"", ""},
		{"ubuntu", ""},
		{"ubuntu", "abc"},
		{"fedora", "+44"},
		{"rocky", "10.-1"},
		{"ubuntu", "24.04."},
		{"ubuntu", " 24.04"},
	}
	for _, c := range refused {
		t.Run("refuse "+c.id+" "+c.version, func(t *testing.T) {
			p, err := fromOSRelease(c.id, c.version)
			if !errors.Is(err, ErrUnsupported) {
				t.Fatalf("fromOSRelease(%q,%q) = %+v, %v; want ErrUnsupported", c.id, c.version, p, err)
			}
			if want := `"` + c.id + " " + c.version + `"`; !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not name %s", err, want)
			}
		})
	}
}

func TestUnsupportedErrorText(t *testing.T) {
	_, err := fromOSRelease("alpine", "3.24.4")
	want := `unsupported distribution "alpine 3.24.4" (supported: ubuntu >= 24.04, debian >= 13, rocky 9/10, fedora >= 44)`
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %s", err, want)
	}
}

// mustProfile returns the Profile for a supported id/version or fails the test.
func mustProfile(t *testing.T, id, version string) Profile {
	t.Helper()
	p, err := fromOSRelease(id, version)
	if err != nil {
		t.Fatalf("fromOSRelease(%q,%q): %v", id, version, err)
	}
	return p
}

func TestRHELPamWiringIsAuthselect(t *testing.T) {
	if got := mustProfile(t, "rocky", "9.6").PamWiring; got != "authselect" {
		t.Fatalf("rhel PamWiring = %q, want authselect", got)
	}
	if got := mustProfile(t, "debian", "13").PamWiring; got != "pam-auth-update" {
		t.Fatalf("debian PamWiring = %q, want pam-auth-update", got)
	}
}

func TestRHELProfilePackageSets(t *testing.T) {
	p := mustProfile(t, "rocky", "9.6")
	// LDAP backend must be in the install set (sssd daemon alone is not enough on RHEL)
	if !contains(p.SSSDPackages, "sssd-ldap") {
		t.Errorf("rhel SSSDPackages missing sssd-ldap: %v", p.SSSDPackages)
	}
	// The ifp responder is its own package and must be installed explicitly, or
	// removing pam-device-auth takes it along and sssd stops starting.
	if !contains(p.SSSDPackages, "sssd-dbus") {
		t.Errorf("rhel SSSDPackages missing sssd-dbus: %v", p.SSSDPackages)
	}
	// mkhomedir wiring needs authselect + oddjob-mkhomedir installed
	for _, want := range []string{"authselect", "oddjob-mkhomedir"} {
		if !contains(p.MkhomedirPackages, want) {
			t.Errorf("rhel MkhomedirPackages missing %s: %v", want, p.MkhomedirPackages)
		}
	}
	// debian needs no extra mkhomedir packages (pam-auth-update ships in libpam-runtime)
	if d := mustProfile(t, "debian", "13"); len(d.MkhomedirPackages) != 0 {
		t.Errorf("debian MkhomedirPackages should be empty, got %v", d.MkhomedirPackages)
	}
}

// Both families must be able to mark packages as explicitly installed.
func TestProfilesMarkPackagesManual(t *testing.T) {
	for name, p := range map[string]Profile{"debian": mustProfile(t, "debian", "13"), "rhel": mustProfile(t, "rocky", "9.6")} {
		if len(p.MarkManualCmd) < 2 {
			t.Fatalf("%s MarkManualCmd = %v, want a command with a subcommand", name, p.MarkManualCmd)
		}
	}
	if got := mustProfile(t, "rocky", "9.6").MarkManualCmd; got[0] != "dnf" || got[len(got)-1] != "install" {
		t.Errorf("rhel MarkManualCmd = %v, want dnf mark install", got)
	}
	if got := mustProfile(t, "debian", "13").MarkManualCmd; got[0] != "apt-mark" || got[len(got)-1] != "manual" {
		t.Errorf("debian MarkManualCmd = %v, want apt-mark manual", got)
	}
}

// dnf5 (Fedora) has no `dnf mark install`; its subcommand is `dnf mark user`,
// and it asks for confirmation when a reason changes, so it needs -y without a
// terminal. Rocky (dnf4) keeps `dnf mark install`. Apart from the mark command
// Fedora uses the RHEL profile.
func TestMarkManualCmdPerDnfVersion(t *testing.T) {
	for _, c := range []struct {
		id, version string
		want        []string
	}{
		{"fedora", "44", []string{"dnf", "-y", "mark", "user"}},
		{"fedora", "45", []string{"dnf", "-y", "mark", "user"}},
		{"rocky", "9.6", []string{"dnf", "mark", "install"}},
		{"rocky", "10.0", []string{"dnf", "mark", "install"}},
	} {
		t.Run(c.id+" "+c.version, func(t *testing.T) {
			p, err := fromOSRelease(c.id, c.version)
			if err != nil {
				t.Fatalf("fromOSRelease(%q,%q): %v", c.id, c.version, err)
			}
			if !reflect.DeepEqual(p.MarkManualCmd, c.want) {
				t.Errorf("MarkManualCmd = %v, want %v", p.MarkManualCmd, c.want)
			}
			p.MarkManualCmd = rhelProfile.MarkManualCmd
			if !reflect.DeepEqual(p, rhelProfile) {
				t.Errorf("profile apart from MarkManualCmd = %+v, want the RHEL profile", p)
			}
		})
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestDebianProfileHasSSSDDbusForIfp(t *testing.T) {
	// The account-phase IP gate needs the SSSD InfoPipe responder; on Debian
	// that is the sssd-dbus package (the same on the RHEL family).
	if !contains(mustProfile(t, "debian", "13").SSSDPackages, "sssd-tools") {
		t.Errorf("debian SSSDPackages missing sssd-tools (sss_cache): %v", mustProfile(t, "debian", "13").SSSDPackages)
	}
	if !contains(mustProfile(t, "debian", "13").SSSDPackages, "sssd-dbus") {
		t.Errorf("debian SSSDPackages missing sssd-dbus: %v", mustProfile(t, "debian", "13").SSSDPackages)
	}
}

// The GSSAPI keytab bind needs the Cyrus SASL GSSAPI plugin, which Debian
// pulls in only as a Recommends of sssd-krb5-common.
func TestProfilesNameKrbPackages(t *testing.T) {
	for _, c := range []struct {
		p    Profile
		sasl string
	}{{debianProfile, "libsasl2-modules-gssapi-mit"}, {rhelProfile, "cyrus-sasl-gssapi"}} {
		if !contains(c.p.KrbPackages, "sssd-krb5") || !contains(c.p.KrbPackages, c.sasl) {
			t.Errorf("%s KrbPackages = %v, want sssd-krb5 and %s", c.p.Family, c.p.KrbPackages, c.sasl)
		}
	}
}

func TestReadOSRelease(t *testing.T) {
	path := t.TempDir() + "/os-release"
	data := "NAME=\"Rocky Linux\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.6\"\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	id, version, err := readOSRelease(path)
	if err != nil || id != "rocky" || version != "9.6" {
		t.Fatalf("readOSRelease = %q, %q, %v; want rocky, 9.6, nil", id, version, err)
	}
	if _, _, err := readOSRelease(t.TempDir() + "/missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: err = %v, want os.ErrNotExist", err)
	}
}
