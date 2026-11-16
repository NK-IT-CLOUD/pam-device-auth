package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
)

const bgPlain = `
# Break-glass accounts (break_glass_users): local key only, never OIDC or the
# directory.
Match User breakglass
    AuthenticationMethods publickey
    AuthorizedKeysFile .ssh/authorized_keys
    AuthorizedKeysCommand none
`

const bgSources = `
# Break-glass accounts (break_glass_users): local key only, never OIDC or the
# directory. From an address outside break_glass_sources they have no key source.
Match User breakglass,rescue Address 192.0.2.0/24,2001:db8:1::/48
    AuthenticationMethods publickey
    AuthorizedKeysFile .ssh/authorized_keys
    AuthorizedKeysCommand none
Match User breakglass,rescue
    AuthorizedKeysFile none
    AuthorizedKeysCommand none
`

// The section is the only difference to the drop-in without break-glass
// accounts, and it stands before every other Match block: sshd keeps the
// first value it reads, so the section's values win for a listed user.
func TestRenderSshdDropin_BreakGlassSection(t *testing.T) {
	one := config.BreakGlass{Users: []string{"breakglass"}}
	two := config.BreakGlass{Users: []string{"breakglass", "rescue"}, Sources: []string{"192.0.2.0/24", "2001:db8:1::/48"}}
	for _, c := range []struct {
		name      string
		groups    []string
		rootLogin string
		bg        config.BreakGlass
		section   string
		before    string // the section goes in front of this text
	}{
		{"root block follows", nil, "", one, bgPlain, "\nMatch User root\n"},
		{"service block follows", []string{"ssh-service"}, "", two, bgSources, "\n# Service accounts"},
		{"root disabled", nil, "disabled", one, bgPlain, "\n# Root: SSH login disabled"},
	} {
		base := renderSshdDropin(testSSSCmd, c.groups, c.rootLogin, config.BreakGlass{})
		if strings.Count(base, c.before) != 1 {
			t.Fatalf("%s: %q is not in the base drop-in exactly once", c.name, c.before)
		}
		want := strings.Replace(base, c.before, c.section+c.before, 1)
		if got := renderSshdDropin(testSSSCmd, c.groups, c.rootLogin, c.bg); got != want {
			t.Errorf("%s: drop-in =\n%s\nwant\n%s", c.name, got, want)
		}
	}
}

// --enable renders the drop-in again whenever its break-glass section is not
// the one the config asks for, also after the last account was removed.
func TestDropinNeedsRender_BreakGlass(t *testing.T) {
	none := config.BreakGlass{}
	one := config.BreakGlass{Users: []string{"breakglass"}}
	two := config.BreakGlass{Users: []string{"breakglass", "rescue"}}
	src := config.BreakGlass{Users: []string{"breakglass"}, Sources: []string{"192.0.2.0/24"}}
	src2 := config.BreakGlass{Users: []string{"breakglass"}, Sources: []string{"198.51.100.0/24"}}
	for _, c := range []struct {
		name         string
		onDisk, want config.BreakGlass
		render       bool
	}{
		{"default stays", none, none, false},
		{"user added", none, one, true},
		{"up to date", one, one, false},
		{"second user added", one, two, true},
		{"user removed", two, one, true},
		{"last user removed", one, none, true},
		{"sources added", one, src, true},
		{"sources changed", src, src2, true},
		{"sources removed", src, one, true},
		{"sources up to date", src, src, false},
	} {
		path := filepath.Join(t.TempDir(), "10-pam-device-auth.conf")
		if err := os.WriteFile(path, []byte(renderSshdDropin(testSSSCmd, nil, "", c.onDisk)), 0644); err != nil {
			t.Fatal(err)
		}
		if got := dropinNeedsRender(path, testSSSCmd, "", c.want); got != c.render {
			t.Errorf("%s: dropinNeedsRender = %v, want %v", c.name, got, c.render)
		}
		// --check reports the same difference (breakGlassDropinStale).
		if got := breakGlassDropinStale(renderSshdDropin(testSSSCmd, nil, "", c.onDisk), c.want); got != c.render {
			t.Errorf("%s: breakGlassDropinStale = %v, want %v", c.name, got, c.render)
		}
	}
}

func TestWriteSshdDropin_WritesBreakGlassSection(t *testing.T) {
	oldPath, oldTest := sshdDropinPath, sshdTest
	t.Cleanup(func() { sshdDropinPath, sshdTest = oldPath, oldTest })
	sshdDropinPath = filepath.Join(t.TempDir(), "10-pam-device-auth.conf")
	sshdTest = func() ([]byte, error) { return nil, nil }
	if err := writeSshdDropin(testSSSCmd, nil, "", config.BreakGlass{Users: []string{"breakglass"}}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(sshdDropinPath)
	if !strings.Contains(string(got), bgPlain) {
		t.Errorf("written drop-in lacks the break-glass section:\n%s", got)
	}
}

// --enable names the break-glass accounts in its closing lines.
func TestBreakGlassEnableLine(t *testing.T) {
	if got := breakGlassEnableLine(config.BreakGlass{}); got != "" {
		t.Errorf("without accounts: %q, want no line", got)
	}
	want := "Break-glass accounts: SSH key only, local (breakglass, rescue)"
	if got := breakGlassEnableLine(config.BreakGlass{Users: []string{"breakglass", "rescue"}}); got != want {
		t.Errorf("line = %q, want %q", got, want)
	}
}

// The account phase reads the names of the break-glass section from the
// drop-in on disk (breakGlassBlockUsers).
func TestBreakGlassBlockUsers(t *testing.T) {
	for _, c := range []struct {
		name string
		bg   config.BreakGlass
		want string
	}{
		{"no section", config.BreakGlass{}, ""},
		{"one account", config.BreakGlass{Users: []string{"breakglass"}}, "breakglass"},
		{"two accounts with sources", config.BreakGlass{Users: []string{"breakglass", "rescue"}, Sources: []string{"192.0.2.0/24"}}, "breakglass,rescue"},
	} {
		dropin := renderSshdDropin(testSSSCmd, []string{"ssh-service"}, "", c.bg)
		if got := strings.Join(breakGlassBlockUsers(dropin), ","); got != c.want {
			t.Errorf("%s: breakGlassBlockUsers = %q, want %q", c.name, got, c.want)
		}
	}
	// root and the service groups are not break-glass accounts.
	if got := breakGlassBlockUsers(renderSshdDropin(testSSSCmd, []string{"ssh-service"}, "", config.BreakGlass{})); len(got) != 0 {
		t.Errorf("default drop-in: %q, want no names", got)
	}
}
