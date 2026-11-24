package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadLDAPProfile(t *testing.T) {
	for _, c := range []struct {
		name, json string
		want       string
		wantErr    string
	}{
		{"ad", `{"ldap": {"profile": "ad"}}`, "ad", ""},
		{"lldap", `{"ldap": {"profile": "lldap", "uri": "ldaps://ldap.example.com"}}`, "lldap", ""},
		{"no ldap block", `{"issuer_url": "https://sso.example.com/realms/example"}`, "", ""},
		{"ldap is null", `{"ldap": null}`, "", ""},
		// A mistake in another key, which stops every OIDC login, does not matter here.
		{"other keys invalid", `{"auth_timeout": 5, "root_login": "nope", "ldap": {"profile": "ad", "uri": 7}}`, "ad", ""},
		{"key in another case, as the loader reads it", `{"LDAP": {"Profile": "ad"}}`, "ad", ""},
		{"profile not set", `{"ldap": {"uri": "ldaps://ldap.example.com"}}`, "", "ldap.profile is not set"},
		{"profile empty", `{"ldap": {"profile": ""}}`, "", "ldap.profile is not set"},
		{"profile null", `{"ldap": {"profile": null}}`, "", "ldap.profile is not set"},
		{"unknown profile", `{"ldap": {"profile": "AD"}}`, "", `ldap.profile "AD" is not "lldap" or "ad"`},
		{"profile is no string", `{"ldap": {"profile": 5}}`, "", "parse config"},
		{"ldap is no object", `{"ldap": "ad"}`, "", "parse config"},
		{"broken JSON", `{"ldap": {`, "", "parse config"},
	} {
		got, err := LoadLDAPProfile(writeConfig(t, c.json))
		switch {
		case c.wantErr == "" && (err != nil || got != c.want):
			t.Errorf("%s: got %q, %v; want %q", c.name, got, err, c.want)
		case c.wantErr != "" && (err == nil || got != "" || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s: got %q, %v; want an error with %q", c.name, got, err, c.wantErr)
		}
	}
	if _, err := LoadLDAPProfile(filepath.Join(t.TempDir(), "none.json")); err == nil || !strings.Contains(err.Error(), "read config") {
		t.Errorf("missing file: err = %v", err)
	}
}
