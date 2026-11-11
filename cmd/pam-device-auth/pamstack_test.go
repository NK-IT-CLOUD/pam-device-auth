package main

import "testing"

// isEnabled and the package scripts agree on what "active" means: a line that
// is no comment names the module.
func TestPamStackUsesModule(t *testing.T) {
	for stack, want := range map[string]bool{
		"auth       required     pam_device_auth.so\naccount    required     pam_device_auth.so\n": true,
		"@include common-auth\n": false,
		"# auth required pam_device_auth.so\n@include common-auth\n": false,
		"   #auth required pam_device_auth.so\n":                     false,
		"auth required pam_unix.so # was: pam_device_auth.so\n":      false,
		"# note\nauth required pam_device_auth.so # OIDC\n":          true,
		"auth required /usr/lib/security/pam_device_auth.so\n":       true,
		"": false,
	} {
		if got := pamStackUsesModule([]byte(stack)); got != want {
			t.Errorf("pamStackUsesModule(%q) = %v, want %v", stack, got, want)
		}
	}
}
