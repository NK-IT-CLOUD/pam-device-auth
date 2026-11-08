// Package distro resolves the current Linux distribution into a Profile of
// the paths and commands that differ across families, so callers (setup_ldap,
// maintainer scripts) branch on data, not on distro name. Only the platforms
// in the supported table are accepted; everything else is an error. Adding a
// platform means: a table row here plus a table-test case, the supported list
// in the error text (Supported), the version rule in debian/preinst, the
// ssh_service mapping in debian/postinst and debian/postrm, and the docs.
// debian/scripts_test.go ties the scripts to the table and the text.
package distro

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
)

// ErrUnsupported is returned (wrapped) for every distribution or version that
// is not in the supported table.
var ErrUnsupported = errors.New("unsupported distribution")

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
	KrbPackages       []string // SSSD krb5 provider and SASL GSSAPI plugin (keytab bind), only with ldap.kerberos
	SudoInstall       []string // package(s) providing sudo/visudo
	PamWiring         string   // mkhomedir wiring tool: "pam-auth-update" | "authselect"
	MkhomedirPackages []string // extra packages the mkhomedir wiring needs (RHEL: authselect, oddjob-mkhomedir)
	CACertPath        string   // system CA bundle for ldap_tls_cacert
	SSSAuthKeysPath   string   // AuthorizedKeysCommand path
	SSSDIfpPath       string   // SSSD InfoPipe responder binary (sssd-dbus package)
	PamStackToken     string   // PAM include token for stack restore ("common-auth" | "system-auth")
	SoDir             string   // PAM module install dir
	PamTemplate       string   // basename of the sshd PAM stack template in the share dir
	SSHService        string   // systemd unit of sshd: "ssh.service" | "sshd.service"
}

var debianProfile = Profile{
	Family:        "debian",
	InstallCmd:    "apt-get",
	MarkManualCmd: []string{"apt-mark", "manual"},
	// sssd-dbus provides the SSSD InfoPipe (ifp) responder that the account-phase
	// IP gate reads `clients` from. It is a separate package on Debian/Ubuntu
	// and on the RHEL family alike, and without it sssd refuses to start once
	// `ifp` is in the config.
	// sssd-tools provides sss_cache and sssctl: --setup-ldap expires the SSSD
	// cache with sss_cache, and the revocation procedure in the docs uses it.
	// libsasl2-modules-gssapi-mit (KrbPackages) is only a Recommends of
	// sssd-krb5-common; without it the GSSAPI keytab bind fails with
	// "no worthy mechs found".
	SSSDPackages:    []string{"sssd-ldap", "libnss-sss", "libpam-sss", "sssd-dbus", "sssd-tools"},
	KrbPackages:     []string{"sssd-krb5", "libsasl2-modules-gssapi-mit"},
	SudoInstall:     []string{"sudo"},
	PamWiring:       "pam-auth-update",
	CACertPath:      "/etc/ssl/certs/ca-certificates.crt",
	SSSAuthKeysPath: "/usr/bin/sss_ssh_authorizedkeys",
	SSSDIfpPath:     "/usr/libexec/sssd/sssd_ifp",
	PamStackToken:   "common-auth",
	SoDir:           "/usr/lib/security",
	PamTemplate:     "pam-sshd-device-auth",
	SSHService:      "ssh.service",
}

var rhelProfile = Profile{
	Family:        "rhel",
	InstallCmd:    "dnf",
	MarkManualCmd: []string{"dnf", "mark", "install"},
	// sssd-dbus (the ifp responder) is installed explicitly: pulled in only as a
	// dependency, `dnf remove pam-device-auth` would remove it again while
	// sssd.conf still enables ifp, and sssd would then fail to start.
	SSSDPackages:      []string{"sssd", "sssd-ldap", "sssd-tools", "sssd-dbus"},
	KrbPackages:       []string{"sssd-krb5", "cyrus-sasl-gssapi"},
	SudoInstall:       []string{"sudo"},
	PamWiring:         "authselect",
	MkhomedirPackages: []string{"authselect", "oddjob-mkhomedir"},
	CACertPath:        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	SSSAuthKeysPath:   "/usr/bin/sss_ssh_authorizedkeys",
	SSSDIfpPath:       "/usr/libexec/sssd/sssd_ifp",
	PamStackToken:     "system-auth",
	SoDir:             "/usr/lib64/security",
	PamTemplate:       "pam-sshd-device-auth-rhel",
	SSHService:        "sshd.service",
}

// fedoraProfile is rhelProfile with the dnf5 mark command: dnf5 has no
// `dnf mark install`, its subcommand is `dnf mark user`. dnf5 asks for
// confirmation when the reason of a package changes and aborts the whole
// transaction without a terminal, so the command needs -y. Rocky (dnf4) keeps
// rhelProfile.
var fedoraProfile = func() Profile {
	p := rhelProfile
	p.MarkManualCmd = []string{"dnf", "-y", "mark", "user"}
	return p
}()

// platform is one row of the supported table: os-release ID, the lowest
// supported VERSION_ID and, if set, the first VERSION_ID that is no longer
// supported (exclusive upper bound).
type platform struct {
	id         string
	min, below []int
	profile    *Profile
}

var platforms = []platform{
	{id: "ubuntu", min: []int{24, 4}, profile: &debianProfile},
	{id: "debian", min: []int{13}, profile: &debianProfile},
	{id: "rocky", min: []int{9}, below: []int{11}, profile: &rhelProfile},
	{id: "fedora", min: []int{44}, profile: &fedoraProfile},
}

// Supported is the supported table as the ErrUnsupported message (and the
// message of debian/preinst) states it.
const Supported = "ubuntu >= 24.04, debian >= 13, rocky 9/10, fedora >= 44"

// Platform is a row of the supported table as the maintainer scripts encode
// it: os-release ID, VERSION_ID bounds (Below nil = no upper bound) and the
// sshd unit. debian/scripts_test.go checks the scripts against it.
type Platform struct {
	ID         string
	Min, Below []int
	SSHService string
}

// Platforms returns the supported table.
func Platforms() []Platform {
	out := make([]Platform, len(platforms))
	for i, p := range platforms {
		out[i] = Platform{ID: p.id, Min: slices.Clone(p.min), Below: slices.Clone(p.below), SSHService: p.profile.SSHService}
	}
	return out
}

// fromOSRelease selects the Profile for an os-release ID / VERSION_ID pair
// from the supported table. Anything not in the table, and any VERSION_ID that
// does not parse as dot-separated numbers, is ErrUnsupported.
func fromOSRelease(id, versionID string) (Profile, error) {
	v, err := parseVersion(versionID)
	if err == nil {
		for _, p := range platforms {
			if p.id == id && compareVersion(v, p.min) >= 0 &&
				(p.below == nil || compareVersion(v, p.below) < 0) {
				return *p.profile, nil
			}
		}
	}
	return Profile{}, fmt.Errorf("%w %q (supported: %s)", ErrUnsupported, id+" "+versionID, Supported)
}

// parseVersion splits a VERSION_ID such as "24.04" into its numeric
// components. Every component must be non-empty and consist of ASCII digits
// only (no sign, no whitespace); anything else is an error.
func parseVersion(s string) ([]int, error) {
	parts := strings.Split(s, ".")
	v := make([]int, len(parts))
	for i, part := range parts {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return nil, fmt.Errorf("invalid version %q", s)
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		v[i] = n
	}
	return v, nil
}

// compareVersion compares two parsed versions component by component; a
// missing component counts as 0 ("10" == "10.0").
func compareVersion(a, b []int) int {
	for i := 0; i < max(len(a), len(b)); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Detect reads /etc/os-release and returns the matching Profile. A read error
// is returned as is; an unsupported platform is ErrUnsupported.
func Detect() (Profile, error) {
	id, versionID, err := readOSRelease("/etc/os-release")
	if err != nil {
		return Profile{}, err
	}
	return fromOSRelease(id, versionID)
}

func readOSRelease(path string) (id, versionID string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
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
		case "VERSION_ID":
			versionID = v
		}
	}
	return id, versionID, nil
}
