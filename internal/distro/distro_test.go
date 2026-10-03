package distro

import "testing"

func TestFromOSRelease(t *testing.T) {
	cases := []struct {
		name, id, idLike, wantFamily, wantInstall, wantCA, wantSSS, wantSoDir string
	}{
		{"ubuntu", "ubuntu", "debian", "debian", "apt-get", "/etc/ssl/certs/ca-certificates.crt", "/usr/bin/sss_ssh_authorizedkeys", "/usr/lib/security"},
		{"debian", "debian", "", "debian", "apt-get", "/etc/ssl/certs/ca-certificates.crt", "/usr/bin/sss_ssh_authorizedkeys", "/usr/lib/security"},
		{"rocky", "rocky", "rhel fedora", "rhel", "dnf", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/usr/libexec/sssd/sss_ssh_authorizedkeys", "/usr/lib64/security"},
		{"almalinux via id_like", "almalinux", "rhel", "rhel", "dnf", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/usr/libexec/sssd/sss_ssh_authorizedkeys", "/usr/lib64/security"},
		{"unknown falls back to debian", "weirdos", "", "debian", "apt-get", "/etc/ssl/certs/ca-certificates.crt", "/usr/bin/sss_ssh_authorizedkeys", "/usr/lib/security"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := fromOSRelease(c.id, c.idLike)
			if p.Family != c.wantFamily || p.InstallCmd != c.wantInstall || p.CACertPath != c.wantCA || p.SSSAuthKeysPath != c.wantSSS || p.SoDir != c.wantSoDir {
				t.Fatalf("fromOSRelease(%q,%q) = %+v", c.id, c.idLike, p)
			}
		})
	}
}

func TestRHELPamWiringIsAuthselect(t *testing.T) {
	if got := fromOSRelease("rocky", "rhel").PamWiring; got != "authselect" {
		t.Fatalf("rhel PamWiring = %q, want authselect", got)
	}
	if got := fromOSRelease("debian", "").PamWiring; got != "pam-auth-update" {
		t.Fatalf("debian PamWiring = %q, want pam-auth-update", got)
	}
}

func TestRHELProfilePackageSets(t *testing.T) {
	p := fromOSRelease("rocky", "rhel")
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
	if d := fromOSRelease("debian", ""); len(d.MkhomedirPackages) != 0 {
		t.Errorf("debian MkhomedirPackages should be empty, got %v", d.MkhomedirPackages)
	}
}

// Both families must be able to mark packages as explicitly installed.
func TestProfilesMarkPackagesManual(t *testing.T) {
	for name, p := range map[string]Profile{"debian": fromOSRelease("debian", ""), "rhel": fromOSRelease("rocky", "rhel")} {
		if len(p.MarkManualCmd) < 2 {
			t.Fatalf("%s MarkManualCmd = %v, want a command with a subcommand", name, p.MarkManualCmd)
		}
	}
	if got := fromOSRelease("rocky", "rhel").MarkManualCmd; got[0] != "dnf" || got[len(got)-1] != "install" {
		t.Errorf("rhel MarkManualCmd = %v, want dnf mark install", got)
	}
	if got := fromOSRelease("debian", "").MarkManualCmd; got[0] != "apt-mark" || got[len(got)-1] != "manual" {
		t.Errorf("debian MarkManualCmd = %v, want apt-mark manual", got)
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
	if !contains(fromOSRelease("debian", "").SSSDPackages, "sssd-tools") {
		t.Errorf("debian SSSDPackages missing sssd-tools (sss_cache): %v", fromOSRelease("debian", "").SSSDPackages)
	}
	if !contains(fromOSRelease("debian", "").SSSDPackages, "sssd-dbus") {
		t.Errorf("debian SSSDPackages missing sssd-dbus: %v", fromOSRelease("debian", "").SSSDPackages)
	}
}
