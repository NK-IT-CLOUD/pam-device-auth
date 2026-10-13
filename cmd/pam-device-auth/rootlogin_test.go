package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/distro"
)

const testSSSCmd = "/usr/bin/sss_ssh_authorizedkeys"

func TestRenderSshdDropin_RootLoginModes(t *testing.T) {
	for _, mode := range []string{"", "key"} {
		got := renderSshdDropin(testSSSCmd, nil, mode)
		for _, want := range []string{"\nPermitRootLogin prohibit-password\n", "Match User root", "AuthorizedKeysFile .ssh/authorized_keys"} {
			if !strings.Contains(got, want) {
				t.Errorf("mode %q: drop-in lacks %q:\n%s", mode, want, got)
			}
		}
	}

	got := renderSshdDropin(testSSSCmd, []string{"ssh-service"}, "disabled")
	if !strings.Contains(got, "\nPermitRootLogin no\n") {
		t.Errorf("disabled: drop-in lacks PermitRootLogin no:\n%s", got)
	}
	for _, bad := range []string{"prohibit-password", "Match User root", "AuthorizedKeysFile .ssh/authorized_keys"} {
		if strings.Contains(got, bad) {
			t.Errorf("disabled: drop-in still contains %q:\n%s", bad, got)
		}
	}
	// Everything that is not about root stays the same.
	for _, want := range []string{"AuthenticationMethods publickey,keyboard-interactive:pam", "AuthorizedKeysFile none", "Match Group ssh-service", "AuthorizedKeysCommand " + testSSSCmd} {
		if !strings.Contains(got, want) {
			t.Errorf("disabled: drop-in lost %q:\n%s", want, got)
		}
	}
}

// The default drop-in must stay byte-for-byte what it was before root_login existed.
func TestRenderSshdDropin_DefaultUnchanged(t *testing.T) {
	if renderSshdDropin(testSSSCmd, nil, "") != renderSshdDropin(testSSSCmd, nil, "key") {
		t.Error("an empty root_login and \"key\" must render the same drop-in")
	}
}

func TestDropinNeedsRender_RootLoginChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "10-pam-device-auth.conf")
	if err := os.WriteFile(path, []byte(renderSshdDropin(testSSSCmd, nil, "")), 0644); err != nil {
		t.Fatal(err)
	}
	if dropinNeedsRender(path, testSSSCmd, "") || dropinNeedsRender(path, testSSSCmd, "key") {
		t.Error("an up-to-date default drop-in must not be re-rendered")
	}
	if !dropinNeedsRender(path, testSSSCmd, "disabled") {
		t.Error("switching root_login to disabled must re-render the drop-in")
	}
	if err := os.WriteFile(path, []byte(renderSshdDropin(testSSSCmd, nil, "disabled")), 0644); err != nil {
		t.Fatal(err)
	}
	if dropinNeedsRender(path, testSSSCmd, "disabled") {
		t.Error("an up-to-date disabled drop-in must not be re-rendered")
	}
	if !dropinNeedsRender(path, testSSSCmd, "") {
		t.Error("switching root_login back to key must re-render the drop-in")
	}
}

func TestWriteSshdDropin_WritesRootLoginMode(t *testing.T) {
	oldPath, oldTest := sshdDropinPath, sshdTest
	t.Cleanup(func() { sshdDropinPath, sshdTest = oldPath, oldTest })
	sshdDropinPath = filepath.Join(t.TempDir(), "10-pam-device-auth.conf")
	sshdTest = func() ([]byte, error) { return nil, nil }
	if err := writeSshdDropin(testSSSCmd, nil, "disabled"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(sshdDropinPath)
	if !strings.Contains(string(got), "PermitRootLogin no") {
		t.Errorf("written drop-in lacks PermitRootLogin no:\n%s", got)
	}
}

func TestRootLoginCheck(t *testing.T) {
	cases := []struct {
		name, mode, permit, am string
		ok, fatal              bool
		msgHas                 string
	}{
		{"default: key only", "", "without-password", "publickey", true, false, "publickey only"},
		{"key: key only", "key", "prohibit-password", "publickey", true, false, "publickey only"},
		{"key: wrong methods warn", "key", "without-password", "publickey,keyboard-interactive:pam", false, false, "should be 'publickey'"},
		{"key: root disabled in sshd warns", "key", "no", "publickey", false, false, "although root_login is 'key'"},
		{"disabled: sshd agrees", "disabled", "no", "publickey,keyboard-interactive:pam", true, true, "SSH login disabled"},
		{"disabled: sshd still allows root blocks", "disabled", "without-password", "publickey", false, true, "sshd allows root"},
		{"disabled: yes blocks", "disabled", "yes", "publickey", false, true, "PermitRootLogin yes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, fatal, okMsg, badMsg := rootLoginCheck(c.mode, c.permit, c.am)
			if ok != c.ok || fatal != c.fatal {
				t.Fatalf("rootLoginCheck(%q,%q,%q) ok=%v fatal=%v, want ok=%v fatal=%v", c.mode, c.permit, c.am, ok, fatal, c.ok, c.fatal)
			}
			msg := badMsg
			if ok {
				msg = okMsg
			}
			if !strings.Contains(msg, c.msgHas) {
				t.Errorf("message %q lacks %q", msg, c.msgHas)
			}
		})
	}
}

func TestSSSDServicesInclude(t *testing.T) {
	cases := []struct {
		name, conf string
		want       bool
	}{
		{"listed", "[sssd]\nservices = nss, pam, ssh, ifp\n", true},
		{"spacing and case", "[SSSD]\n Services=nss,pam , IFP\n", true},
		{"not listed", "[sssd]\nservices = nss, pam, ssh\n", false},
		{"other section", "[domain/x]\nservices = ifp\n[sssd]\nservices = nss\n", false},
		{"commented out", "[sssd]\n# services = nss, ifp\nservices = nss\n", false},
		{"substring is not a match", "[sssd]\nservices = nss, ifpx\n", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		if got := sssdServicesInclude(c.conf, "ifp"); got != c.want {
			t.Errorf("%s: sssdServicesInclude = %v, want %v", c.name, got, c.want)
		}
	}
}

// What --setup-ldap renders enables ifp, so the new check applies to every host it sets up.
func TestRenderedSSSDConfEnablesIfp(t *testing.T) {
	conf := renderSSSDConf(ldapRenderData{
		URI: "ldaps://lldap.example:6360", BaseDN: "dc=example,dc=com",
		UserBase: "ou=people,dc=example,dc=com", GroupBase: "ou=groups,dc=example,dc=com",
		BindDN: "uid=ro,ou=people,dc=example,dc=com", BindPassword: "x", AccessGroup: "ssh-access",
	}, "/etc/ssl/certs/ca.pem")
	if !sssdServicesInclude(conf, "ifp") {
		t.Fatalf("rendered sssd.conf does not enable ifp:\n%s", conf)
	}
}

func TestMarkManualCommand(t *testing.T) {
	rhel := distro.Profile{MarkManualCmd: []string{"dnf", "mark", "install"}}
	got := markManualCommand(rhel, []string{"sssd", "sssd-dbus"})
	want := []string{"dnf", "mark", "install", "sssd", "sssd-dbus"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("markManualCommand = %q, want %q", got, want)
	}
	// The profile's own slice must not be modified by building the command.
	if !reflect.DeepEqual(rhel.MarkManualCmd, []string{"dnf", "mark", "install"}) {
		t.Errorf("profile command was modified: %q", rhel.MarkManualCmd)
	}
	if markManualCommand(distro.Profile{}, []string{"x"}) != nil {
		t.Error("a profile without a mark command must give nil")
	}
	if markManualCommand(rhel, nil) != nil {
		t.Error("no packages must give nil")
	}
}

func TestRootLoginWithSources(t *testing.T) {
	key := rootSourcePolicy{Source: "192.0.2.10", Permit: "prohibit-password", Methods: "publickey"}
	none := rootSourcePolicy{Source: "198.51.100.7", Permit: "no", Methods: "publickey"}
	for _, c := range []struct {
		name            string
		mode, permit    string
		sources         []rootSourcePolicy
		wantOK, wantFat bool
		wantMsg         string
	}{
		{"no sources: unchanged default", "", "prohibit-password", nil, true, false, "publickey only"},
		{"global no, a source allows the key", "", "no", []rootSourcePolicy{key, none}, true, false, "192.0.2.10"},
		{"global no, no source allows it", "", "no", []rootSourcePolicy{none}, false, false, "no emergency path"},
		{"disabled but a source allows root", config.RootLoginDisabled, "no", []rootSourcePolicy{key}, false, true, "192.0.2.10"},
		{"disabled and every source refuses", config.RootLoginDisabled, "no", []rootSourcePolicy{none}, true, true, "disabled"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ok, fatal, okMsg, badMsg := rootLoginWithSources(c.mode, c.permit, "publickey", c.sources)
			if ok != c.wantOK || (!ok && fatal != c.wantFat) {
				t.Fatalf("ok=%v fatal=%v, want ok=%v fatal=%v (ok=%q bad=%q)", ok, fatal, c.wantOK, c.wantFat, okMsg, badMsg)
			}
			msg := badMsg
			if ok {
				msg = okMsg
			}
			if !strings.Contains(msg, c.wantMsg) {
				t.Errorf("message %q does not mention %q", msg, c.wantMsg)
			}
		})
	}
}

func TestSshdParamForPassesConnectionSpec(t *testing.T) {
	old := sshdTOutput
	t.Cleanup(func() { sshdTOutput = old })
	var gotArgs []string
	sshdTOutput = func(args ...string) ([]byte, error) {
		gotArgs = args
		return []byte("permitrootlogin prohibit-password\n"), nil
	}
	v, ok := sshdParamFor("permitrootlogin", "user=root,addr=192.0.2.10")
	if !ok || v != "prohibit-password" {
		t.Fatalf("got %q, %v", v, ok)
	}
	if strings.Join(gotArgs, " ") != "-T -C user=root,addr=192.0.2.10" {
		t.Fatalf("sshd args = %v", gotArgs)
	}
}

// OpenSSH up to 10.0 prints PermitRootLogin prohibit-password as its alias
// without-password in `sshd -T`; both spellings are the key-only path.
func TestRootLoginWithSources_WithoutPasswordAlias(t *testing.T) {
	src := []rootSourcePolicy{{Source: "192.0.2.10", Permit: "without-password", Methods: "publickey"}}
	ok, _, okMsg, badMsg := rootLoginWithSources("", "no", "publickey", src)
	if !ok || !strings.Contains(okMsg, "192.0.2.10") {
		t.Fatalf("ok=%v okMsg=%q badMsg=%q, want the key path from 192.0.2.10", ok, okMsg, badMsg)
	}
}

func TestSshdParamWrapperArgs(t *testing.T) {
	old := sshdTOutput
	t.Cleanup(func() { sshdTOutput = old })
	var gotArgs []string
	sshdTOutput = func(args ...string) ([]byte, error) {
		gotArgs = args
		return []byte("usedns no\n"), nil
	}
	for user, want := range map[string]string{"": "-T", "root": "-T -C user=root"} {
		if v, ok := sshdParam("usedns", user); !ok || v != "no" {
			t.Fatalf("sshdParam(usedns, %q) = %q, %v", user, v, ok)
		}
		if got := strings.Join(gotArgs, " "); got != want {
			t.Errorf("sshdParam(usedns, %q): sshd args %q, want %q", user, got, want)
		}
	}
}
