package main

import (
	"strings"
	"testing"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
)

// validLDAP returns a directory config that must pass validation; tests mutate
// one field at a time to assert a specific rejection.
func validLDAP() *config.LDAPConfig {
	return &config.LDAPConfig{
		URI:          "ldaps://lldap.nkit.cloud:636",
		BaseDN:       "dc=nkit,dc=cloud",
		BindDN:       "cn=admin,ou=people,dc=nkit,dc=cloud",
		BindPassword: "s3cr3t-with-symbols!@#",
		AccessGroup:  "ssh-access",
		AdminGroup:   "ssh-admin",
	}
}

func TestValidateLDAPConfig_AcceptsValid(t *testing.T) {
	if err := validateLDAPConfig(validLDAP()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestValidateLDAPConfig_AcceptsExplicitSearchBases(t *testing.T) {
	l := validLDAP()
	l.UserSearchBase = "ou=people,dc=nkit,dc=cloud"
	l.GroupSearchBase = "ou=groups,dc=nkit,dc=cloud"
	if err := validateLDAPConfig(l); err != nil {
		t.Fatalf("valid explicit search bases rejected: %v", err)
	}
}

func TestValidateLDAPConfig_RejectsIncomplete(t *testing.T) {
	l := validLDAP()
	l.URI = ""
	if err := validateLDAPConfig(l); err == nil {
		t.Error("incomplete config (missing uri) should be rejected")
	}
}

// Finding 1: newline in user_search_base / group_search_base injects sssd.conf
// directives — these fields previously bypassed the newline guard entirely.
func TestValidateLDAPConfig_RejectsNewlineInUserSearchBase(t *testing.T) {
	l := validLDAP()
	l.UserSearchBase = "ou=people,dc=x\nldap_tls_reqcert = never"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("newline in user_search_base should be rejected (sssd.conf injection)")
	}
}

func TestValidateLDAPConfig_RejectsNewlineInGroupSearchBase(t *testing.T) {
	l := validLDAP()
	l.GroupSearchBase = "ou=groups,dc=x\nldap_access_filter = (objectClass=*)"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("newline in group_search_base should be rejected (access-filter override)")
	}
}

func TestValidateLDAPConfig_RejectsNewlineInBaseDN(t *testing.T) {
	l := validLDAP()
	l.BaseDN = "dc=x\nldap_tls_reqcert = never"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("newline in base_dn should be rejected")
	}
}

// Finding 2: LDAP-filter metacharacters in a search base break out of the
// (memberOf=cn=<group>,<base>) access filter, widening who may log in.
func TestValidateLDAPConfig_RejectsFilterMetacharsInGroupSearchBase(t *testing.T) {
	l := validLDAP()
	l.GroupSearchBase = "ou=g,dc=x)(uid=*"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("LDAP-filter metacharacters in group_search_base should be rejected")
	}
}

func TestValidateLDAPConfig_RejectsFilterMetacharsInBaseDN(t *testing.T) {
	l := validLDAP()
	l.BaseDN = "dc=x)(uid=*"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("LDAP-filter metacharacters in base_dn should be rejected")
	}
}

// Finding 3: group names land in sudoers (%group) and the access filter; a
// value carrying sudoers grammar can silently grant passwordless root.
func TestValidateLDAPConfig_RejectsSudoersPayloadInAdminGroup(t *testing.T) {
	l := validLDAP()
	l.AdminGroup = "ssh-admin ALL=(ALL:ALL) NOPASSWD:ALL #"
	if err := validateLDAPConfig(l); err == nil {
		t.Error("sudoers-significant characters in admin_group should be rejected")
	}
}

func TestValidateLDAPConfig_RejectsMetacharsInAccessGroup(t *testing.T) {
	for _, bad := range []string{"ssh access", "ssh=access", "ssh,access", "ssh)access", "ssh*"} {
		l := validLDAP()
		l.AccessGroup = bad
		if err := validateLDAPConfig(l); err == nil {
			t.Errorf("access_group %q should be rejected", bad)
		}
	}
}

func TestValidateLDAPConfig_AcceptsHyphenAndUnderscoreGroups(t *testing.T) {
	l := validLDAP()
	l.AccessGroup = "ssh-access_2"
	l.AdminGroup = "ssh_admins"
	if err := validateLDAPConfig(l); err != nil {
		t.Fatalf("hyphen/underscore group names rejected: %v", err)
	}
}

// Guard against the injection error message leaking the (secret) bind password:
// the error must name the field, not echo the value, for password fields.
func TestValidateLDAPConfig_RejectsNewlineInBindPassword(t *testing.T) {
	l := validLDAP()
	l.BindPassword = "pw\nldap_tls_reqcert = never"
	err := validateLDAPConfig(l)
	if err == nil {
		t.Fatal("newline in bind_password should be rejected")
	}
	if strings.Contains(err.Error(), "ldap_tls_reqcert") {
		t.Error("error message must not echo the bind_password value")
	}
}
