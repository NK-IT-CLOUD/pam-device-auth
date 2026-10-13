package main

import (
	"strings"
	"testing"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/token"
)

func TestCheckDirectoryAccess_RequiredACR(t *testing.T) {
	cfg := &config.Config{RequiredRole: "ssh-access", RequiredACR: []string{"3"}}
	base := token.TokenResult{Username: "alice", Roles: []string{"ssh-access"}}
	for _, c := range []struct {
		name, acr, wantSub string
	}{
		{"accepted level", "3", ""},
		{"level 1 by name", "silver", `authentication level "silver" is not accepted`},
		{"cookie sign-in", "0", `authentication level "0" is not accepted`},
		{"no acr claim", "", "carries no authentication level"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := base
			r.ACR = c.acr
			got := checkDirectoryAccess(&r, cfg)
			if c.wantSub == "" && got != "" {
				t.Fatalf("denied: %s", got)
			}
			if c.wantSub != "" && !strings.Contains(got, c.wantSub) {
				t.Fatalf("reason %q does not contain %q", got, c.wantSub)
			}
		})
	}
}

func TestCheckDirectoryAccess_NoRequiredACRIgnoresClaim(t *testing.T) {
	cfg := &config.Config{RequiredRole: "ssh-access"}
	r := token.TokenResult{Username: "alice", Roles: []string{"ssh-access"}}
	if got := checkDirectoryAccess(&r, cfg); got != "" {
		t.Fatalf("denied without required_acr: %s", got)
	}
}

func TestCheckDirectoryAccess_RoleCheckedFirst(t *testing.T) {
	cfg := &config.Config{RequiredRole: "ssh-access", RequiredACR: []string{"3"}}
	r := token.TokenResult{Username: "alice", ACR: "3"}
	if got := checkDirectoryAccess(&r, cfg); !strings.Contains(got, "lacks required role") {
		t.Fatalf("reason %q", got)
	}
}
