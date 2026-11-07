package main

import (
	"fmt"
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
	const keys = ".ssh/authorized_keys"
	key := rootSourcePolicy{Source: "192.0.2.10", Permit: "prohibit-password", Methods: "publickey", KeysFile: keys}
	none := rootSourcePolicy{Source: "198.51.100.7", Permit: "no", Methods: "publickey", KeysFile: keys}
	noFile := rootSourcePolicy{Source: "203.0.113.5", Permit: "prohibit-password", Methods: "publickey", KeysFile: "none"}
	unknown := rootSourcePolicy{Source: "203.0.113.6"}                                                  // sshd -T could not evaluate the address
	noAKF := rootSourcePolicy{Source: "203.0.113.7", Permit: "prohibit-password", Methods: "publickey"} // no authorizedkeysfile line
	for _, c := range []struct {
		name               string
		mode, permit, akf  string
		sources            []rootSourcePolicy
		wantOK, wantFat    bool
		wantMsg, wantNoMsg string
	}{
		{"no sources: unchanged default", "", "prohibit-password", keys, nil, true, false, "publickey only", ""},
		{"global no, a source allows the key", "", "no", "none", []rootSourcePolicy{key, none}, true, false, "192.0.2.10", ""},
		{"global no, no source allows it", "", "no", "none", []rootSourcePolicy{none}, false, false, "no emergency path", ""},
		{"disabled but a source allows root", config.RootLoginDisabled, "no", "none", []rootSourcePolicy{key}, false, true, "192.0.2.10", ""},
		{"disabled and every source refuses", config.RootLoginDisabled, "no", "none", []rootSourcePolicy{none}, true, true, "disabled", ""},
		{"disabled: a source without key file still allows root", config.RootLoginDisabled, "no", "none", []rootSourcePolicy{noFile}, false, true, "203.0.113.5", ""},
		{"global no, the only source has AuthorizedKeysFile none", "", "no", "none", []rootSourcePolicy{noFile, none},
			false, false, "root is allowed from 203.0.113.5 but AuthorizedKeysFile is none there; add AuthorizedKeysFile .ssh/authorized_keys to the Match block", "198.51.100.7"},
		{"global no, one source works and one has no key file", "", "no", "none", []rootSourcePolicy{key, noFile},
			false, false, "root is allowed from 203.0.113.5 but AuthorizedKeysFile is none there; add AuthorizedKeysFile .ssh/authorized_keys to the Match block; the emergency path works from 192.0.2.10 (publickey)", ""},
		{"global no, an unevaluated source is no key path", "", "no", "none", []rootSourcePolicy{unknown}, false, false, "no emergency path", ""},
		{"global no, a key source without an AuthorizedKeysFile value is no key path", "", "no", "none", []rootSourcePolicy{noAKF}, false, false, "no emergency path", ""},
		{"key: root's AuthorizedKeysFile none", "", "prohibit-password", "none", nil,
			false, false, "root has no key source (AuthorizedKeysFile none); the emergency path does not work", ""},
		{"key: root's AuthorizedKeysFile none with sources that do not matter", "key", "prohibit-password", "none", []rootSourcePolicy{key},
			false, false, "root has no key source (AuthorizedKeysFile none)", ""},
		{"key: global no wins over the missing key file", "", "no", "none", nil, false, false, "although root_login is 'key'", "AuthorizedKeysFile"},
		{"disabled: AuthorizedKeysFile none is expected", config.RootLoginDisabled, "no", "none", nil, true, true, "SSH login disabled", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			ok, fatal, okMsg, badMsg := rootLoginWithSources(c.mode, c.permit, "publickey", c.akf, c.sources)
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
			if c.wantNoMsg != "" && strings.Contains(msg, c.wantNoMsg) {
				t.Errorf("message %q mentions %q", msg, c.wantNoMsg)
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
	src := []rootSourcePolicy{{Source: "192.0.2.10", Permit: "without-password", Methods: "publickey", KeysFile: ".ssh/authorized_keys"}}
	ok, _, okMsg, badMsg := rootLoginWithSources("", "no", "publickey", "none", src)
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

// OpenSSH 10.5 stores AuthorizedKeysFile none as an empty list and `sshd -T`
// prints no authorizedkeysfile line for it; 10.2 prints "authorizedkeysfile
// none". Both mean that sshd reads no key file.
func TestSshdKeysFileFor(t *testing.T) {
	old := sshdTOutput
	t.Cleanup(func() { sshdTOutput = old })
	for _, c := range []struct {
		name, out string
		fail      bool
		want      string
		wantOK    bool
	}{
		{"OpenSSH 10.2 prints none", "permitrootlogin no\nauthorizedkeysfile none\nusedns no\n", false, "none", true},
		{"OpenSSH 10.5 omits the line for none", "permitrootlogin no\nauthorizedkeyscommand /usr/bin/sss_ssh_authorizedkeys\nusedns no\n", false, "none", true},
		{"key file", "authorizedkeysfile .ssh/authorized_keys\n", false, ".ssh/authorized_keys", true},
		{"default key files", "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\n", false, ".ssh/authorized_keys .ssh/authorized_keys2", true},
		{"sshd -T failed", "", true, "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			sshdTOutput = func(args ...string) ([]byte, error) {
				if c.fail {
					return nil, os.ErrNotExist
				}
				return []byte(c.out), nil
			}
			got, ok := sshdKeysFileFor("user=nobody")
			if got != c.want || ok != c.wantOK {
				t.Fatalf("sshdKeysFileFor = %q, %v, want %q, %v", got, ok, c.want, c.wantOK)
			}
		})
	}
}

// fakeSshdT answers `sshd -T [-C spec]` from per-spec keyword values. With
// omitNone, an authorizedkeysfile of none is left out of the output as
// OpenSSH 10.5 does; otherwise it is printed as OpenSSH 10.2 does.
func fakeSshdT(values map[string]map[string]string, omitNone bool) func(args ...string) ([]byte, error) {
	return func(args ...string) ([]byte, error) {
		spec := ""
		if len(args) == 3 && args[1] == "-C" {
			spec = args[2]
		}
		var b strings.Builder
		for kw, v := range values[spec] {
			if kw == "authorizedkeysfile" && v == "none" && omitNone {
				continue
			}
			b.WriteString(kw + " " + v + "\n")
		}
		return []byte(b.String()), nil
	}
}

// The --check verdicts on root's key path and on the non-root key file are the
// same whether sshd prints "authorizedkeysfile none" (OpenSSH 10.2) or no
// authorizedkeysfile line (OpenSSH 10.5).
func TestKeysFileVerdictsSameOnOpenSSH102And105(t *testing.T) {
	old := sshdTOutput
	t.Cleanup(func() { sshdTOutput = old })
	const keys = ".ssh/authorized_keys"
	policy := func(permit, akf string) map[string]string {
		return map[string]string{"permitrootlogin": permit, "authenticationmethods": "publickey", "authorizedkeysfile": akf}
	}
	nonRoot := map[string]string{"authenticationmethods": "publickey,keyboard-interactive:pam", "authorizedkeysfile": "none"}
	for _, c := range []struct {
		name    string
		values  map[string]map[string]string
		sources []string
		wantOK  bool
		wantMsg string
	}{
		{"root key file, global prohibit-password",
			map[string]map[string]string{"user=root": policy("prohibit-password", keys), "user=nobody": nonRoot},
			nil, true, "publickey only"},
		{"root AuthorizedKeysFile none",
			map[string]map[string]string{"user=root": policy("prohibit-password", "none"), "user=nobody": nonRoot},
			nil, false, "root has no key source (AuthorizedKeysFile none)"},
		{"global no, the source has a key file",
			map[string]map[string]string{"user=root": policy("no", "none"), "user=root,addr=192.0.2.10": policy("prohibit-password", keys), "user=nobody": nonRoot},
			[]string{"192.0.2.10"}, true, "192.0.2.10"},
		{"global no, the source has AuthorizedKeysFile none",
			map[string]map[string]string{"user=root": policy("no", "none"), "user=root,addr=203.0.113.5": policy("prohibit-password", "none"), "user=nobody": nonRoot},
			[]string{"203.0.113.5"}, false, "root is allowed from 203.0.113.5 but AuthorizedKeysFile is none there"},
	} {
		for _, omitNone := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/omitNone=%v", c.name, omitNone), func(t *testing.T) {
				sshdTOutput = fakeSshdT(c.values, omitNone)
				permit, methods, keysFile, sources := rootSSHDPolicy(c.sources)
				ok, _, okMsg, badMsg := rootLoginWithSources("", permit, methods, keysFile, sources)
				msg := badMsg
				if ok {
					msg = okMsg
				}
				if ok != c.wantOK || !strings.Contains(msg, c.wantMsg) {
					t.Fatalf("root verdict ok=%v %q, want ok=%v containing %q", ok, msg, c.wantOK, c.wantMsg)
				}
				if akf, ok := sshdKeysFileFor("user=nobody"); !ok || akf != "none" {
					t.Fatalf("non-root AuthorizedKeysFile = %q, %v, want none", akf, ok)
				}
			})
		}
	}
}
