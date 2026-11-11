package main

import (
	"bytes"
	"errors"
	"strings"
)

// loginNameError says why name must not become an argument of an external
// command, nil when it may. sshd passes the login name as the client sent it
// and group members come from the directory: a name that starts with '-'
// would be read as an option by getent, busctl or sss_ssh_authorizedkeys.
func loginNameError(name string) error {
	switch {
	case name == "":
		return errors.New("the name is empty")
	case name[0] == '-':
		return errors.New("the name starts with '-'")
	}
	return nil
}

// passwdEntryName returns the name field of the first passwd entry in the
// output of getent, "" when there is none.
func passwdEntryName(getentOut []byte) string {
	line, _, _ := bytes.Cut(getentOut, []byte("\n"))
	name, _, ok := bytes.Cut(line, []byte(":"))
	if !ok {
		return ""
	}
	return string(name)
}

// nssAnswerMatches reports whether the output of `getent passwd <name>` is the
// entry of exactly that name. getent looks an all-digit key up as a UID, and
// SSSD can match a name without regard to case; in both cases the entry
// carries another name and must not count as the requested user.
func nssAnswerMatches(getentOut []byte, name string) bool {
	return name != "" && passwdEntryName(getentOut) == name
}

// splitMembers splits the member field of a group entry. Names that fail
// loginNameError are returned apart: they never reach a command line.
func splitMembers(field string) (members, skipped []string) {
	if field == "" {
		return nil, nil
	}
	for _, m := range strings.Split(field, ",") {
		if loginNameError(m) != nil {
			skipped = append(skipped, m)
			continue
		}
		members = append(members, m)
	}
	return members, skipped
}
