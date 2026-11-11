package main

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// methodAlternatives splits an AuthenticationMethods value the way sshd reads
// it: alternatives are separated by whitespace, and one alternative lists the
// methods that must all succeed, joined by commas.
func methodAlternatives(am string) [][]string {
	var alts [][]string
	for _, alt := range strings.Fields(am) {
		alts = append(alts, strings.Split(alt, ","))
	}
	return alts
}

// methodsRequire2FA reports whether every alternative of an
// AuthenticationMethods value asks for the key and for the PAM conversation.
// "publickey keyboard-interactive:pam" (a space where the comma belongs) is
// two alternatives, each a single factor.
func methodsRequire2FA(am string) bool {
	alts := methodAlternatives(am)
	for _, alt := range alts {
		if !slices.Contains(alt, "publickey") ||
			!(slices.Contains(alt, "keyboard-interactive:pam") || slices.Contains(alt, "keyboard-interactive")) {
			return false
		}
	}
	return len(alts) > 0
}

// methodsKeyOnly reports whether every alternative is the key alone, as the
// drop-in sets it for service groups and for root.
func methodsKeyOnly(am string) bool {
	alts := methodAlternatives(am)
	for _, alt := range alts {
		if len(alt) != 1 || alt[0] != "publickey" {
			return false
		}
	}
	return len(alts) > 0
}

// connSpecUser returns the connection spec of `sshd -T -C` for a user. The
// spec is a comma-separated list of key=value pairs, so a name with ',', '='
// or whitespace cannot be written into it: ok is false.
func connSpecUser(name string) (spec string, ok bool) {
	if name == "" || strings.ContainsAny(name, ",=") || strings.IndexFunc(name, unicode.IsSpace) >= 0 {
		return "", false
	}
	return "user=" + name, true
}

// factorReport sorts the members of the access group and the service groups
// by what sshd asks of each: key and OIDC (twoFactor) for an access-group
// member, the key alone (keyOnly) for a member of a service group. weak lists
// every member whose methods differ from that, with the methods; notEvaluated
// lists the members whose name cannot be written into a connection spec or
// for whom methodsFor has no answer. methodsFor returns sshd's effective
// AuthenticationMethods for a connection spec.
func factorReport(access, service []string, methodsFor func(spec string) (string, bool)) (twoFactor, keyOnly, weak, notEvaluated []string) {
	seen := map[string]bool{}
	for _, m := range slices.Concat(access, service) {
		if seen[m] {
			continue
		}
		seen[m] = true
		spec, ok := connSpecUser(m)
		if !ok {
			notEvaluated = append(notEvaluated, m)
			continue
		}
		am, ok := methodsFor(spec)
		if !ok {
			notEvaluated = append(notEvaluated, m)
			continue
		}
		switch inService := slices.Contains(service, m); {
		case inService && methodsKeyOnly(am):
			keyOnly = append(keyOnly, m)
		case !inService && methodsRequire2FA(am):
			twoFactor = append(twoFactor, m)
		default:
			weak = append(weak, fmt.Sprintf("%s (%s)", m, am))
		}
	}
	return twoFactor, keyOnly, weak, notEvaluated
}
