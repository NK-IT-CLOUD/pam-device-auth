package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
)

// With profile "ad" an account that has the access group or a service group
// as its primary group can log in, but NSS lists it in that group only once
// the host has resolved it. --check must say that its member lists, and the
// checks per member, can leave such an account out.
func TestMemberListNote(t *testing.T) {
	ad := &config.LDAPConfig{Profile: config.LDAPProfileAD}
	note := memberListNote(ad)
	for _, want := range []string{"primary group", "NSS", "per member"} {
		if !strings.Contains(note, want) {
			t.Errorf("memberListNote(ad) = %q, want it to mention %q", note, want)
		}
	}
	if strings.Contains(note, "\n") {
		t.Errorf("memberListNote(ad) must be one line, got %q", note)
	}

	// Profile "lldap" needs no note: its access filter asks for memberOf, so an
	// account with a group only as primary group cannot log in.
	for name, l := range map[string]*config.LDAPConfig{
		"lldap":         {Profile: config.LDAPProfileLLDAP},
		"no profile":    {},
		"no ldap block": nil,
	} {
		if got := memberListNote(l); got != "" {
			t.Errorf("memberListNote(%s) = %q, want no note", name, got)
		}
	}
}

// The note is an [INFO] line of the preflight: neither a warning nor a blocker.
func TestReportMemberListNote(t *testing.T) {
	var out bytes.Buffer
	reportMemberListNote(&config.LDAPConfig{Profile: config.LDAPProfileAD}, &out)
	want := "  [INFO] " + memberListNote(&config.LDAPConfig{Profile: config.LDAPProfileAD}) + "\n"
	if out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
	if strings.Contains(out.String(), "[WARN]") || strings.Contains(out.String(), "[FAIL]") {
		t.Errorf("the note must not count as a warning or blocker: %q", out.String())
	}

	out.Reset()
	reportMemberListNote(&config.LDAPConfig{Profile: config.LDAPProfileLLDAP}, &out)
	if out.Len() != 0 {
		t.Errorf("profile lldap: output = %q, want none", out.String())
	}
}
