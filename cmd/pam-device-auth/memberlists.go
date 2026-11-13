package main

import (
	"fmt"
	"io"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
)

// memberListNote says what the member lists of --check can leave out with
// profile "ad"; it is "" for every other profile.
//
// The lists are what NSS reports for a group (getentGroup). Active Directory
// keeps the membership in a primary group on the account (primaryGroupID),
// not in the group's member attribute, and SSSD adds such an account to the
// group from its own cache only, when it refreshes the group entry: a host
// lists the accounts it has resolved before. sshd (Match Group), SSSD
// (simple_allow_groups) and sudo count the primary group, so such an account
// logs in while no check per member has looked at it.
//
// Profile "lldap" needs no note: its access filter asks for memberOf, so an
// account that has a group as primary group only cannot log in.
func memberListNote(l *config.LDAPConfig) string {
	if l == nil || l.Profile != config.LDAPProfileAD {
		return ""
	}
	return "member lists are what NSS reports: an account with one of these groups as its primary group is listed only once " +
		"this host has resolved it, so the checks per member can leave it out; `id <account>` and then `sss_cache -G` make this host list it"
}

// reportMemberListNote prints the note as an [INFO] line of the preflight. It
// is neither a warning nor a blocker.
func reportMemberListNote(l *config.LDAPConfig, out io.Writer) {
	if note := memberListNote(l); note != "" {
		fmt.Fprintf(out, "  [INFO] %s\n", note)
	}
}
