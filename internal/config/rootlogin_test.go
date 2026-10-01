package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validBase() *Config {
	c := DefaultConfig()
	c.IssuerURL = "https://sso.example.com/realms/x"
	c.ClientID = "ssh-server"
	c.RequiredRole = "ssh-access"
	return c
}

func TestValidateRootLogin(t *testing.T) {
	cases := []struct {
		value string
		ok    bool
	}{
		{"", true},
		{"key", true},
		{"disabled", true},
		{"Disabled", false},
		{"none", false},
		{"no", false},
		{"yes", false},
	}
	for _, c := range cases {
		cfg := validBase()
		cfg.RootLogin = c.value
		err := cfg.Validate()
		if c.ok && err != nil {
			t.Errorf("root_login %q rejected: %v", c.value, err)
		}
		if !c.ok {
			if err == nil {
				t.Errorf("root_login %q accepted, want rejection", c.value)
			} else if !strings.Contains(err.Error(), "root_login") {
				t.Errorf("root_login %q: error does not name the field: %v", c.value, err)
			}
		}
	}
}

func TestRootLoginIsDisabled(t *testing.T) {
	for value, want := range map[string]bool{"": false, "key": false, "disabled": true} {
		c := &Config{RootLogin: value}
		if got := c.RootLoginIsDisabled(); got != want {
			t.Errorf("RootLoginIsDisabled(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestLoadParsesRootLogin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	js := `{"issuer_url":"https://sso.example.com/realms/x","client_id":"ssh-server","required_role":"ssh-access","root_login":"disabled"}`
	if err := os.WriteFile(path, []byte(js), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.RootLogin != RootLoginDisabled || !cfg.RootLoginIsDisabled() {
		t.Fatalf("RootLogin = %q", cfg.RootLogin)
	}
	bad := strings.Replace(js, `"disabled"`, `"maybe"`, 1)
	if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted root_login \"maybe\"")
	}
}
