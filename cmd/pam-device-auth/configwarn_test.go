package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/distro"
)

// writeTestConfig writes body as a config file and returns its path.
func writeTestConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

const configWithTypo = `{
	"issuer_url": "https://sso.example.com/realms/test", "client_id": "ssh-server",
	"required_role": "ssh-access", "requried_acr": ["gold"],
	"allowed_algorithms": ["RS256", "rs256"], "ldap": {"profile": "lldap"}
}`

func TestConfigWarningLines(t *testing.T) {
	cfg, err := config.Load(writeTestConfig(t, configWithTypo))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`config: unknown key "requried_acr" is ignored`,
		`config: allowed_algorithms: "rs256" is not supported (supported: RS256, RS384, RS512, ES256, ES384, ES512)`,
	}
	got := configWarningLines(cfg)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("configWarningLines() = %q\nwant %q", got, want)
	}

	// In the preflight each of them is a blocker.
	var out bytes.Buffer
	if n := reportConfigWarnings(cfg, &out); n != 2 {
		t.Errorf("reportConfigWarnings() = %d, want 2 blockers", n)
	}
	for _, w := range want {
		if !strings.Contains(out.String(), "  [FAIL] "+w+"\n") {
			t.Errorf("preflight output lacks %q; got:\n%s", "[FAIL] "+w, out.String())
		}
	}
}

// --setup-ldap refuses a config with findings before it looks at the ldap
// block or touches the host. The command exits the process, so it runs in a
// child test binary whose side-effecting stages abort with a marker.
func TestSetupLDAP_RefusesConfigWarnings(t *testing.T) {
	const abortMarker = "PDA_TEST_ABORT:"
	if path := os.Getenv("PDA_TEST_CONFIGWARN_CHILD"); path != "" {
		abort := func(stage string) {
			fmt.Fprintln(os.Stderr, abortMarker, stage)
			os.Exit(99)
		}
		detectPlatform = func() (distro.Profile, error) { return distro.Profile{Family: "debian"}, nil }
		loadConfig = func(string) (*config.Config, error) { return config.Load(path) }
		systemctl = func(...string) (string, error) { abort("systemctl"); return "", nil }
		sshdTOutput = func(...string) ([]byte, error) { abort("sshd -T"); return nil, nil }
		sshdTest = func() ([]byte, error) { abort("sshd -t"); return nil, nil }
		readClients = func(string) ([]string, error) { abort("readClients"); return nil, nil }
		sshdDropinPath = filepath.Join(t.TempDir(), "10-pam-device-auth.conf")
		runSetupLDAP()
		abort("setup-ldap returned")
	}

	// The ldap block of this config is incomplete on purpose: a child that
	// gets past the findings stops at the ldap validation, before any command.
	cmd := exec.Command(os.Args[0], "-test.run=^TestSetupLDAP_RefusesConfigWarnings$")
	cmd.Env = append(os.Environ(), "PDA_TEST_CONFIGWARN_CHILD="+writeTestConfig(t, configWithTypo))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("child: err=%v, want exit 1; stderr=%q", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), `FAIL: config: unknown key "requried_acr" is ignored`) {
		t.Errorf("stderr = %q, want the config finding as the reason", stderr.String())
	}
	if strings.Contains(stderr.String(), abortMarker) {
		t.Errorf("the child reached a later stage: %q", stderr.String())
	}
}
