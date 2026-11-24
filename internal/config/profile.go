package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadLDAPProfile reads ldap.profile from the config file and checks this key
// only. The account phase uses it to tell an Active Directory from another
// directory, and like LoadBreakGlass it must not fail on a mistake in another
// key. A config without an ldap block gives "": no directory setup is
// declared. A file that is not JSON, an ldap block without a profile and a
// profile other than "lldap" and "ad" are errors.
func LoadLDAPProfile(path string) (string, error) {
	if path == "" {
		path = DefaultConfigPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read config: %w", err)
	}
	var keys struct {
		LDAP *struct {
			Profile string `json:"profile"`
		} `json:"ldap"`
	}
	if err := json.Unmarshal(data, &keys); err != nil {
		return "", fmt.Errorf("parse config: %w", err)
	}
	if keys.LDAP == nil {
		return "", nil
	}
	switch p := keys.LDAP.Profile; p {
	case LDAPProfileLLDAP, LDAPProfileAD:
		return p, nil
	case "":
		return "", fmt.Errorf("ldap.profile is not set (%q or %q)", LDAPProfileLLDAP, LDAPProfileAD)
	default:
		return "", fmt.Errorf("ldap.profile %q is not %q or %q", p, LDAPProfileLLDAP, LDAPProfileAD)
	}
}
