// Package distro resolves the current Linux distribution family into a
// Profile of the paths and commands that differ across families, so callers
// (setup_ldap, maintainer scripts) branch on data, not on distro name. Adding
// a distro means adding a Profile record here plus a table-test case — no
// structural change anywhere else.
package distro

import (
	"os"
	"strings"
)

// Profile is the per-family data that directory-mode setup needs.
type Profile struct {
	Family     string // "debian" | "rhel"
	InstallCmd string // package-install verb: "apt-get" | "dnf"
	// MarkManualCmd marks packages as explicitly installed (the command takes
	// the package names as its remaining arguments). Installing a package that is
	// already present as a dependency does not change its install reason, so
	// without this step removing pam-device-auth removes the dependency again.
	MarkManualCmd     []string
	SSSDPackages      []string // packages that provide SSSD LDAP/NSS/PAM
	SudoInstall       []string // package(s) providing sudo/visudo
	PamWiring         string   // mkhomedir wiring tool: "pam-auth-update" | "authselect"
	MkhomedirPackages []string // extra packages the mkhomedir wiring needs (RHEL: authselect, oddjob-mkhomedir)
	CACertPath        string   // system CA bundle for ldap_tls_cacert
	SSSAuthKeysPath   string   // AuthorizedKeysCommand path
	PamStackToken     string   // PAM include token for stack restore ("common-auth" | "system-auth")
	SoDir             string   // PAM module install dir
}

var debianProfile = Profile{
	Family:        "debian",
	InstallCmd:    "apt-get",
	MarkManualCmd: []string{"apt-mark", "manual"},
	// sssd-dbus provides the SSSD InfoPipe (ifp) responder that the account-phase
	// IP gate reads `clients` from. It is a separate package on Debian/Ubuntu
	// and on the RHEL family alike, and without it sssd refuses to start once
	// `ifp` is in the config.
	SSSDPackages:    []string{"sssd-ldap", "libnss-sss", "libpam-sss", "sssd-dbus"},
	SudoInstall:     []string{"sudo"},
	PamWiring:       "pam-auth-update",
	CACertPath:      "/etc/ssl/certs/ca-certificates.crt",
	SSSAuthKeysPath: "/usr/bin/sss_ssh_authorizedkeys",
	PamStackToken:   "common-auth",
	SoDir:           "/usr/lib/security",
}

var rhelProfile = Profile{
	Family:        "rhel",
	InstallCmd:    "dnf",
	MarkManualCmd: []string{"dnf", "mark", "install"},
	// sssd-dbus (the ifp responder) is installed explicitly: pulled in only as a
	// dependency, `dnf remove pam-device-auth` would remove it again while
	// sssd.conf still enables ifp, and sssd would then fail to start.
	SSSDPackages:      []string{"sssd", "sssd-ldap", "sssd-tools", "sssd-dbus"},
	SudoInstall:       []string{"sudo"},
	PamWiring:         "authselect",
	MkhomedirPackages: []string{"authselect", "oddjob-mkhomedir"},
	CACertPath:        "/etc/pki/tls/certs/ca-bundle.crt",
	SSSAuthKeysPath:   "/usr/libexec/sssd/sss_ssh_authorizedkeys",
	PamStackToken:     "system-auth",
	SoDir:             "/usr/lib64/security",
}

// fromOSRelease selects a Profile from os-release ID / ID_LIKE. Unknown
// distros fall back to the Debian profile (the historical default), so the
// tool degrades to its prior behaviour rather than misconfiguring a host.
func fromOSRelease(id, idLike string) Profile {
	hay := strings.ToLower(id + " " + idLike)
	for _, k := range []string{"rhel", "fedora", "centos", "rocky", "almalinux"} {
		if strings.Contains(hay, k) {
			return rhelProfile
		}
	}
	return debianProfile
}

// Detect reads /etc/os-release and returns the matching Profile.
func Detect() Profile {
	id, idLike := readOSRelease("/etc/os-release")
	return fromOSRelease(id, idLike)
}

func readOSRelease(path string) (id, idLike string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch strings.TrimSpace(k) {
		case "ID":
			id = v
		case "ID_LIKE":
			idLike = v
		}
	}
	return id, idLike
}
