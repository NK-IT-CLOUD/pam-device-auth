package config

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// breakGlassBase is a valid config with extra appended as further keys.
func breakGlassBase(extra string) string {
	return `{"issuer_url": "https://sso.example.com/realms/x", "client_id": "ssh-server", "required_role": "ssh-access"` + extra + `}`
}

// Names become an sshd pattern list (Match User) and sources an sshd address
// list (Match Address): everything sshd would read as a pattern, and every
// range sshd refuses, must fail here.
func TestValidateBreakGlass(t *testing.T) {
	for _, c := range []struct {
		name           string
		users, sources []string
		wantErr        string // "" = valid
	}{
		{"empty", nil, nil, ""},
		{"one user", []string{"breakglass"}, nil, ""},
		{"users and sources", []string{"breakglass", "_ops-2"}, []string{"192.0.2.10", "198.51.100.0/24", "2001:db8:1::/48", "2001:db8::1"}, ""},
		{"upper case", []string{"Breakglass"}, nil, `break_glass_users entry "Breakglass" must be a local account name`},
		{"wildcard", []string{"ops*"}, nil, `break_glass_users entry "ops*"`},
		{"negation", []string{"!ops"}, nil, `break_glass_users entry "!ops"`},
		{"comma", []string{"a,b"}, nil, `break_glass_users entry "a,b"`},
		{"leading dash", []string{"-ops"}, nil, `break_glass_users entry "-ops"`},
		{"empty name", []string{""}, nil, `break_glass_users entry ""`},
		{"33 characters", []string{strings.Repeat("a", 33)}, nil, "of at most 32 characters"},
		{"root", []string{"root"}, nil, "break_glass_users must not list root; root_login controls root"},
		{"user twice", []string{"ops", "ops"}, nil, `break_glass_users lists "ops" twice`},
		{"host bits", []string{"ops"}, []string{"192.0.2.5/24"}, `break_glass_sources entry "192.0.2.5/24" has bits set after its prefix length; write 192.0.2.0/24`},
		{"pattern", []string{"ops"}, []string{"192.0.2.*"}, `break_glass_sources entry "192.0.2.*" must be an IP address or a CIDR range`},
		{"negated", []string{"ops"}, []string{"!192.0.2.1"}, "must be an IP address or a CIDR range"},
		{"host name", []string{"ops"}, []string{"jump.example.com"}, "must be an IP address or a CIDR range"},
		{"zone", []string{"ops"}, []string{"fe80::1%eth0"}, "must be an IP address or a CIDR range"},
		{"mapped", []string{"ops"}, []string{"::ffff:192.0.2.1"}, `is an IPv4-mapped IPv6 address; write 192.0.2.1`},
		{"mapped range", []string{"ops"}, []string{"::ffff:192.0.2.0/120"}, `is an IPv4-mapped IPv6 address; write 192.0.2.0/24`},
		{"source twice", []string{"ops"}, []string{"192.0.2.1", "192.0.2.1"}, `break_glass_sources lists "192.0.2.1" twice`},
	} {
		err := validateBreakGlass(c.users, c.sources)
		if c.wantErr == "" && err != nil || c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.wantErr)
		}
	}
}

func TestLoadBreakGlassKeys(t *testing.T) {
	cfg, err := loadString(t, breakGlassBase(`, "break_glass_users": ["breakglass"], "break_glass_sources": ["192.0.2.0/24"]`))
	if err != nil {
		t.Fatal(err)
	}
	bg := cfg.BreakGlass()
	if !slices.Equal(bg.Users, []string{"breakglass"}) || !slices.Equal(bg.Sources, []string{"192.0.2.0/24"}) {
		t.Errorf("BreakGlass() = %+v", bg)
	}
	if w := cfg.Warnings(); len(w) != 0 {
		t.Errorf("warnings = %q, want none: both keys are known", w)
	}
	if !bg.Has("breakglass") || bg.Has("Breakglass") || bg.Has("") {
		t.Errorf("Has: breakglass=%v Breakglass=%v empty=%v, want true, false, false", bg.Has("breakglass"), bg.Has("Breakglass"), bg.Has(""))
	}
}

func TestLoadRejectsInvalidBreakGlass(t *testing.T) {
	_, err := loadString(t, breakGlassBase(`, "break_glass_users": ["Root"]`))
	if err == nil || !strings.Contains(err.Error(), `break_glass_users entry "Root"`) {
		t.Errorf("err = %v, want the break_glass_users error", err)
	}
}

func TestLoadWarnsSourcesWithoutUsers(t *testing.T) {
	cfg, err := loadString(t, breakGlassBase(`, "break_glass_sources": ["192.0.2.1"]`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"break_glass_sources is set but break_glass_users is empty; it has no effect"}
	if w := cfg.Warnings(); !slices.Equal(w, want) {
		t.Errorf("warnings = %q, want %q", w, want)
	}
}

// The account phase must not lose its break-glass accounts over a mistake in
// another key: LoadBreakGlass reads and checks the two keys and nothing else.
func TestLoadBreakGlass_IgnoresOtherKeys(t *testing.T) {
	path := writeConfig(t, `{"auth_timeout": 5, "root_login": "nope", "break_glass_users": ["breakglass"], "break_glass_sources": ["192.0.2.0/24"]}`)
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted the config; the test needs one that Load refuses")
	}
	bg, err := LoadBreakGlass(path)
	if err != nil {
		t.Fatalf("LoadBreakGlass: %v", err)
	}
	if !slices.Equal(bg.Users, []string{"breakglass"}) || !slices.Equal(bg.Sources, []string{"192.0.2.0/24"}) {
		t.Errorf("LoadBreakGlass = %+v", bg)
	}
}

func TestLoadBreakGlass_Errors(t *testing.T) {
	for name, path := range map[string]string{
		"missing file":  filepath.Join(t.TempDir(), "none.json"),
		"broken JSON":   writeConfig(t, `{"break_glass_users": [`),
		"wrong type":    writeConfig(t, `{"break_glass_users": "breakglass"}`),
		"invalid entry": writeConfig(t, `{"break_glass_users": ["root"]}`),
		// Valid users must not survive an invalid sources list as an
		// exemption without an address limit.
		"valid users, invalid sources":           writeConfig(t, `{"break_glass_users": ["breakglass"], "break_glass_sources": ["192.0.2.5/24"]}`),
		"valid users, sources of the wrong type": writeConfig(t, `{"break_glass_users": ["breakglass"], "break_glass_sources": "192.0.2.0/24"}`),
	} {
		bg, err := LoadBreakGlass(path)
		if err == nil {
			t.Errorf("%s: no error", name)
		}
		if len(bg.Users) != 0 || len(bg.Sources) != 0 {
			t.Errorf("%s: BreakGlass = %+v, want it empty with an error", name, bg)
		}
	}
}

func TestLoadBreakGlass_NoKeys(t *testing.T) {
	bg, err := LoadBreakGlass(writeConfig(t, `{}`))
	if err != nil || len(bg.Users) != 0 || len(bg.Sources) != 0 {
		t.Errorf("LoadBreakGlass({}) = %+v, %v; want empty and no error", bg, err)
	}
}
