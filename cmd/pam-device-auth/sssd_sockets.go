package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// sssdResponderSockets lists, per SSSD responder, the systemd socket units that
// would start it on demand. sssd-common enables them by preset on Debian and
// Ubuntu. A responder named in the [sssd] services line is started by the sssd
// monitor instead, and its socket then fails at every start ("socket-activated
// but still mentioned in the services line"), leaving systemd degraded.
var sssdResponderSockets = []struct {
	responder string
	units     []string
}{
	{"nss", []string{"sssd-nss.socket"}},
	{"pam", []string{"sssd-pam.socket", "sssd-pam-priv.socket"}},
	{"ssh", []string{"sssd-ssh.socket"}},
	{"sudo", []string{"sssd-sudo.socket"}},
	{"autofs", []string{"sssd-autofs.socket"}},
	{"pac", []string{"sssd-pac.socket"}},
}

// systemctl runs systemctl and returns its trimmed combined output; a variable
// so tests can fake the unit states.
var systemctl = func(args ...string) (string, error) {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// conflictingSSSDSockets returns the socket units of the responders that conf
// starts from its services line and that systemd would start as well: enabled
// (the Debian/Ubuntu preset), active or failed. Masked units, inactive disabled
// ones (the RHEL family default) and absent units do not conflict.
func conflictingSSSDSockets(conf string) []string {
	var units []string
	for _, r := range sssdResponderSockets {
		if !sssdServicesInclude(conf, r.responder) {
			continue
		}
		for _, u := range r.units {
			state, _ := systemctl("is-enabled", u)
			switch {
			case state == "masked":
				continue
			case state == "enabled" || state == "enabled-runtime":
				units = append(units, u)
			default:
				// A disabled socket can still be running (started by hand or as a
				// dependency) or be left failed from an earlier start.
				_, activeErr := systemctl("is-active", "--quiet", u)
				_, failedErr := systemctl("is-failed", "--quiet", u)
				if activeErr == nil || failedErr == nil {
					units = append(units, u)
				}
			}
		}
	}
	return units
}

// maskConflictingSSSDSockets disables, stops and masks the conflicting socket
// units of conf (see conflictingSSSDSockets), so neither a reboot nor an sssd
// package upgrade brings them back. Idempotent; a no-op where no socket
// conflicts, as on the RHEL family.
func maskConflictingSSSDSockets(conf string) {
	for _, u := range conflictingSSSDSockets(conf) {
		if out, err := systemctl("disable", "--now", u); err != nil {
			setupWarnf("disable %s failed (it keeps failing and leaves systemd degraded): %s: %v", u, out, err)
			continue
		}
		if out, err := systemctl("mask", u); err != nil {
			setupWarnf("mask %s failed (an sssd upgrade may enable it again): %s: %v", u, out, err)
			continue
		}
		fmt.Printf("Masked %s (its responder runs from the sssd.conf services line)\n", u)
	}
}

// resetFailedSSSDUnits clears a failed state the reconfiguration left on SSSD
// units: sockets masked above, or sssd-ifp when a D-Bus request started it
// before the restarted monitor took it over and it ran into its start limit.
func resetFailedSSSDUnits() {
	if out, err := systemctl("reset-failed", "sssd-*"); err != nil {
		setupWarnf("systemctl reset-failed sssd-* failed: %s: %v", out, err)
	}
}
