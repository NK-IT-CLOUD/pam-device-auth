package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

const responderConf = "[sssd]\nservices = nss, pam, ssh, ifp\ndomains = nkit\n"

// fakeSystemctl replaces systemctl with a table of unit states: enabled maps a
// unit to its is-enabled answer (absent units answer "not-found"), failed lists
// the units is-failed reports, and a unit whose failed value is false but present
// in the map counts as active. Every call is recorded; disable and mask turn the
// unit masked, as the real commands do. failMask makes mask fail.
func fakeSystemctl(t *testing.T, enabled map[string]string, failed map[string]bool, failMask bool) *[]string {
	t.Helper()
	var calls []string
	orig := systemctl
	t.Cleanup(func() { systemctl = orig })
	systemctl = func(args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		unit := args[len(args)-1]
		switch args[0] {
		case "is-enabled":
			if s, ok := enabled[unit]; ok {
				return s, nil
			}
			return "not-found", errors.New("exit status 4")
		case "is-failed":
			if failed[unit] {
				return "", nil
			}
			return "", errors.New("exit status 1")
		case "is-active":
			if f, ok := failed[unit]; ok && !f && enabled[unit] != "masked" {
				return "", nil
			}
			return "", errors.New("exit status 3")
		case "mask":
			if failMask {
				return "Failed to mask unit", errors.New("exit status 1")
			}
			enabled[unit] = "masked"
			delete(failed, unit)
		}
		return "", nil
	}
	return &calls
}

func TestConflictingSSSDSockets(t *testing.T) {
	cases := []struct {
		name    string
		conf    string
		enabled map[string]string
		failed  map[string]bool
		want    []string
	}{
		{"Debian preset: enabled sockets of configured responders", responderConf,
			map[string]string{"sssd-nss.socket": "enabled", "sssd-pam.socket": "enabled", "sssd-pam-priv.socket": "enabled",
				"sssd-ssh.socket": "enabled", "sssd-sudo.socket": "enabled", "sssd-autofs.socket": "enabled"},
			map[string]bool{},
			[]string{"sssd-nss.socket", "sssd-pam.socket", "sssd-pam-priv.socket", "sssd-ssh.socket"}},
		{"RHEL family: disabled sockets do not conflict", responderConf,
			map[string]string{"sssd-nss.socket": "disabled", "sssd-pam.socket": "disabled", "sssd-ssh.socket": "disabled"},
			map[string]bool{},
			nil},
		{"masked sockets do not conflict, a failed disabled one does", responderConf,
			map[string]string{"sssd-nss.socket": "masked", "sssd-pam.socket": "masked", "sssd-ssh.socket": "disabled"},
			map[string]bool{"sssd-nss.socket": true, "sssd-ssh.socket": true},
			[]string{"sssd-ssh.socket"}},
		{"a disabled but running socket conflicts", responderConf,
			map[string]string{"sssd-nss.socket": "disabled", "sssd-ssh.socket": "disabled"},
			map[string]bool{"sssd-nss.socket": false},
			[]string{"sssd-nss.socket"}},
		{"responder not in services: its socket is left alone", "[sssd]\nservices = nss\n",
			map[string]string{"sssd-nss.socket": "enabled", "sssd-ssh.socket": "enabled"},
			map[string]bool{},
			[]string{"sssd-nss.socket"}},
		{"socket mode (no services line): nothing conflicts", "[sssd]\ndomains = nkit\n",
			map[string]string{"sssd-nss.socket": "enabled"},
			map[string]bool{},
			nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fakeSystemctl(t, c.enabled, c.failed, false)
			if got := conflictingSSSDSockets(c.conf); !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestMaskConflictingSSSDSockets_MasksOnceAndIsIdempotent(t *testing.T) {
	setupWarnings = nil
	enabled := map[string]string{"sssd-nss.socket": "enabled", "sssd-pam.socket": "disabled", "sssd-ssh.socket": "enabled"}
	failed := map[string]bool{"sssd-pam.socket": true}
	calls := fakeSystemctl(t, enabled, failed, false)

	maskConflictingSSSDSockets(responderConf)
	var changes []string
	for _, c := range *calls {
		if strings.HasPrefix(c, "disable ") || strings.HasPrefix(c, "mask ") {
			changes = append(changes, c)
		}
	}
	want := []string{
		"disable --now sssd-nss.socket", "mask sssd-nss.socket",
		"disable --now sssd-pam.socket", "mask sssd-pam.socket",
		"disable --now sssd-ssh.socket", "mask sssd-ssh.socket",
	}
	if !reflect.DeepEqual(changes, want) {
		t.Errorf("first run changed %v, want %v", changes, want)
	}

	*calls = nil
	maskConflictingSSSDSockets(responderConf)
	for _, c := range *calls {
		if strings.HasPrefix(c, "disable ") || strings.HasPrefix(c, "mask ") {
			t.Errorf("second run changed units again: %q", c)
		}
	}
	if len(setupWarnings) != 0 {
		t.Errorf("unexpected warnings: %v", setupWarnings)
	}
}

func TestMaskConflictingSSSDSockets_FailureIsAWarning(t *testing.T) {
	setupWarnings = nil
	t.Cleanup(func() { setupWarnings = nil })
	fakeSystemctl(t, map[string]string{"sssd-nss.socket": "enabled"}, map[string]bool{}, true)

	maskConflictingSSSDSockets(responderConf)
	if len(setupWarnings) != 1 || !strings.Contains(setupWarnings[0], "mask sssd-nss.socket failed") {
		t.Errorf("warnings = %v, want one about masking sssd-nss.socket", setupWarnings)
	}
}

func TestResetFailedSSSDUnits_CoversAllSSSDUnits(t *testing.T) {
	calls := fakeSystemctl(t, map[string]string{}, map[string]bool{}, false)
	resetFailedSSSDUnits()
	if want := []string{"reset-failed sssd-*"}; !reflect.DeepEqual(*calls, want) {
		t.Errorf("calls = %v, want %v", *calls, want)
	}
}
