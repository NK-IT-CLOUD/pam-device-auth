// Package debian holds the maintainer scripts. This test ties their platform
// rules and messages to the supported table of internal/distro, so the two
// cannot drift apart. The scripts are embedded: the test binary may run from
// another directory than the source tree.
package debian

import (
	_ "embed"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/distro"
)

var (
	//go:embed preinst
	preinst string
	//go:embed postinst
	postinst string
	//go:embed postrm
	postrm string
)

// shellFunc returns the body of the POSIX shell function name in script.
func shellFunc(t *testing.T, script, name string) string {
	t.Helper()
	_, body, ok := strings.Cut(script, "\n"+name+"() {\n")
	if !ok {
		t.Fatalf("function %s() not found", name)
	}
	body, _, ok = strings.Cut(body, "\n}\n")
	if !ok {
		t.Fatalf("function %s() has no closing brace", name)
	}
	return body
}

// caseArms returns the arms "pattern) action ;;" of the case statements in
// body (without the "*)" catch-all), keyed by each "|"-separated pattern.
func caseArms(t *testing.T, body string) map[string]string {
	t.Helper()
	arm := regexp.MustCompile(`^\s*([a-z][a-z |]*)\) (.+) ;;$`)
	arms := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		m := arm.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		for _, id := range strings.Split(m[1], "|") {
			id = strings.TrimSpace(id)
			if _, dup := arms[id]; dup {
				t.Errorf("case arm for %q appears twice", id)
			}
			arms[id] = m[2]
		}
	}
	return arms
}

func ids() []string {
	var out []string
	for _, p := range distro.Platforms() {
		out = append(out, p.ID)
	}
	return out
}

func parseVersion(t *testing.T, s string) []int {
	t.Helper()
	var v []int
	for _, part := range strings.Split(s, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			t.Fatalf("version %q: %v", s, err)
		}
		v = append(v, n)
	}
	return v
}

// preinst refuses an unsupported platform with the message of distro.Detect,
// prefixed with the package name.
func TestPreinstUnsupportedMessage(t *testing.T) {
	want := `echo "${PKG}: unsupported distribution \"${_id} ${_version_id}\" (supported: ` + distro.Supported + `)" >&2`
	if !strings.Contains(preinst, "\n        "+want+"\n") {
		t.Errorf("preinst lacks the unsupported-distribution line\n%s", want)
	}
}

// Every row of the supported table has exactly its version rule in
// preinst's supported(), and preinst accepts no other ID.
func TestPreinstVersionRules(t *testing.T) {
	arms := caseArms(t, shellFunc(t, preinst, "supported"))
	rule := regexp.MustCompile(`^version_ge "\$2" ([0-9.]+)(?: && ! version_ge "\$2" ([0-9.]+))?$`)
	for _, p := range distro.Platforms() {
		r, ok := arms[p.ID]
		if !ok {
			t.Errorf("preinst supported() has no rule for %q", p.ID)
			continue
		}
		m := rule.FindStringSubmatch(r)
		if m == nil {
			t.Errorf("preinst rule for %q is %q, want version_ge [&& ! version_ge]", p.ID, r)
			continue
		}
		if got := parseVersion(t, m[1]); !reflect.DeepEqual(got, p.Min) {
			t.Errorf("preinst minimum for %q = %v, Go table %v", p.ID, got, p.Min)
		}
		var below []int
		if m[2] != "" {
			below = parseVersion(t, m[2])
		}
		if !reflect.DeepEqual(below, p.Below) {
			t.Errorf("preinst upper bound for %q = %v, Go table %v", p.ID, below, p.Below)
		}
	}
	for id := range arms {
		if !slices.Contains(ids(), id) {
			t.Errorf("preinst accepts %q, which the Go table does not", id)
		}
	}
}

// postrm validates and restarts sshd on remove and purge only when
// undo_sshd_config changed a file sshd reads. The script cannot run here (its
// paths are the live host's), so the structure is pinned: one restart_ssh per
// arm, guarded by SSHD_CHANGED, after undo_sshd_config.
func TestPostrmRestartsSSHDOnlyAfterAChange(t *testing.T) {
	const guarded = "        if [ -n \"$SSHD_CHANGED\" ]; then\n            restart_ssh\n        fi\n"
	for _, arm := range []string{"    remove | 0)\n", "    purge)\n"} {
		_, body, ok := strings.Cut(postrm, "\n"+arm)
		if !ok {
			t.Fatalf("postrm has no arm %q", arm)
		}
		body, _, _ = strings.Cut(body, "\n        ;;\n")
		undo := strings.Index(body, "\n        undo_sshd_config\n")
		restart := strings.Index(body, guarded)
		if undo < 0 || restart < undo || strings.Count(body, "restart_ssh") != 1 {
			t.Errorf("postrm arm %q: want undo_sshd_config, then the only restart_ssh guarded by SSHD_CHANGED:\n%s", strings.TrimSpace(arm), body)
		}
	}
}

// postinst decides "PAM is active" on the content of /etc/pam.d/sshd only: an
// aborted --enable leaves a valid sshd.original without the module wired, so
// the backup's existence says nothing. A read error stays an error.
func TestPostinstPamActiveReadsTheStack(t *testing.T) {
	body := shellFunc(t, postinst, "pam_active")
	if strings.Contains(body, "sshd.original") {
		t.Errorf("pam_active looks at sshd.original:\n%s", body)
	}
	for _, want := range []string{
		"grep -q 'pam_device_auth.so' /etc/pam.d/sshd || _rc=$?",
		"0) return 0 ;;",
		"1) return 1 ;;",
		`err "cannot read /etc/pam.d/sshd (grep exit $_rc)"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("pam_active lacks %q:\n%s", want, body)
		}
	}
}

// postinst and postrm restart the sshd unit of the Go table for each ID, know
// no other ID, and name exactly the table's IDs in their error.
func TestSSHServiceMapping(t *testing.T) {
	for name, script := range map[string]string{"postinst": postinst, "postrm": postrm} {
		body := shellFunc(t, script, "ssh_service")
		arms := caseArms(t, body)
		for _, p := range distro.Platforms() {
			if got, want := arms[p.ID], "echo "+p.SSHService; got != want {
				t.Errorf("%s ssh_service for %q = %q, want %q", name, p.ID, got, want)
			}
		}
		for id := range arms {
			if !slices.Contains(ids(), id) {
				t.Errorf("%s ssh_service knows %q, which the Go table does not", name, id)
			}
		}
		if want := "(supported: " + strings.Join(ids(), ", ") + ")"; !strings.Contains(body, want) {
			t.Errorf("%s ssh_service error does not list %s", name, want)
		}
	}
}
