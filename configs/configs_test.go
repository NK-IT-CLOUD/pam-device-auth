// Package configs holds the shipped example configs. This test pins that a
// fresh install needs no --migrate-config: every shipped JSON config names its
// ldap.profile explicitly. The configs are embedded: the test binary may run
// from another directory than the source tree. The list is explicit like the
// makefile's: a glob would also embed a local, gitignored config-nkit.json
// (internal) into test binaries that are copied to test hosts.
package configs

import (
	"embed"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
)

//go:embed config.json config-auth0.json config-authentik.json config-okta.json
var shipped embed.FS

func TestShippedConfigsSetLDAPProfile(t *testing.T) {
	files, err := shipped.ReadDir(".")
	if err != nil || len(files) == 0 {
		t.Fatalf("no embedded configs: %v", err)
	}
	for _, f := range files {
		b, err := shipped.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			LDAP *struct {
				Profile *string `json:"profile"`
			} `json:"ldap"`
		}
		if err := json.Unmarshal(b, &cfg); err != nil {
			t.Fatalf("%s: %v", f.Name(), err)
		}
		switch {
		case cfg.LDAP == nil:
			t.Errorf("%s: no ldap block", f.Name())
		case cfg.LDAP.Profile == nil:
			t.Errorf("%s: ldap.profile is not set", f.Name())
		case *cfg.LDAP.Profile != "lldap" && *cfg.LDAP.Profile != "ad":
			t.Errorf("%s: ldap.profile = %q, want \"lldap\" or \"ad\"", f.Name(), *cfg.LDAP.Profile)
		}
	}
}

// The example configs are what admins start from: none of them may carry a
// key the loader does not know or an algorithm it cannot verify.
func TestShippedConfigsLoadWithoutWarnings(t *testing.T) {
	files, err := shipped.ReadDir(".")
	if err != nil || len(files) == 0 {
		t.Fatalf("no embedded configs: %v", err)
	}
	for _, f := range files {
		b, err := shipped.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), f.Name())
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(path)
		if err != nil {
			t.Errorf("%s: %v", f.Name(), err)
			continue
		}
		if w := cfg.Warnings(); len(w) != 0 {
			t.Errorf("%s: warnings %q", f.Name(), w)
		}
	}
}

//go:embed pam-sshd-device-auth pam-sshd-device-auth-rhel
var pamStacks embed.FS

// --enable puts one of these stacks in place of the distribution's
// /etc/pam.d/sshd. pam_env's user_readenv makes sshd sessions read
// ~/.pam_environment, which lets a user set variables for the own session;
// Linux-PAM deprecates it, and Debian 13 and Ubuntu 26.04 no longer have it in
// their stack. The package must not switch it back on.
func TestPAMStacksDoNotReadUserEnvironment(t *testing.T) {
	files, err := pamStacks.ReadDir(".")
	if err != nil || len(files) != 2 {
		t.Fatalf("embedded PAM stacks: %d, %v", len(files), err)
	}
	for _, f := range files {
		b, err := pamStacks.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			code, _, _ := strings.Cut(line, "#")
			if strings.Contains(code, "user_readenv") {
				t.Errorf("%s:%d sets user_readenv: %s", f.Name(), i+1, strings.TrimSpace(line))
			}
		}
	}
}
