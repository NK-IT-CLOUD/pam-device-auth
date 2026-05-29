package main

import "testing"

func TestShouldRejectMissingLocalUser(t *testing.T) {
	cases := []struct {
		name       string
		createUser bool
		shadowHash string
		want       bool
	}{
		{"create_user=true, empty hash", true, "", false},
		{"create_user=true, missing user", true, "", false},
		{"create_user=false, missing user (empty hash)", false, "", true},
		{"create_user=false, disabled user (*)", false, "*", true},
		{"create_user=false, locked user (!prefix)", false, "!$6$salt$hash", false},
		{"create_user=false, active user", false, "$6$salt$hash", false},
		{"create_user=true, locked user", true, "!$6$salt$hash", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldRejectMissingLocalUser(tc.createUser, tc.shadowHash)
			if got != tc.want {
				t.Errorf("shouldRejectMissingLocalUser(%v, %q) = %v, want %v",
					tc.createUser, tc.shadowHash, got, tc.want)
			}
		})
	}
}
