package token

import (
	"testing"
)

func TestExtractRoles_RealmOnly(t *testing.T) {
	claims := map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"admin", "user"},
		},
	}

	roles := ExtractRoles(claims, "ssh-server", "")
	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(roles))
	}
	if roles[0] != "admin" || roles[1] != "user" {
		t.Errorf("roles = %v", roles)
	}
}

func TestExtractRoles_ClientOnly(t *testing.T) {
	claims := map[string]interface{}{
		"resource_access": map[string]interface{}{
			"ssh-server": map[string]interface{}{
				"roles": []interface{}{"ssh-access"},
			},
		},
	}

	roles := ExtractRoles(claims, "ssh-server", "")
	if len(roles) != 1 || roles[0] != "ssh-access" {
		t.Errorf("roles = %v, want [ssh-access]", roles)
	}
}

func TestExtractRoles_Both(t *testing.T) {
	claims := map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"user"},
		},
		"resource_access": map[string]interface{}{
			"ssh-server": map[string]interface{}{
				"roles": []interface{}{"ssh-access"},
			},
		},
	}

	roles := ExtractRoles(claims, "ssh-server", "")
	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(roles))
	}
}

func TestExtractRoles_Empty(t *testing.T) {
	claims := map[string]interface{}{}
	roles := ExtractRoles(claims, "ssh-server", "")
	if len(roles) != 0 {
		t.Errorf("expected 0 roles, got %d", len(roles))
	}
}

func TestExtractRoles_WrongClient(t *testing.T) {
	claims := map[string]interface{}{
		"resource_access": map[string]interface{}{
			"other-client": map[string]interface{}{
				"roles": []interface{}{"ssh-access"},
			},
		},
	}

	roles := ExtractRoles(claims, "ssh-server", "")
	if len(roles) != 0 {
		t.Errorf("expected 0 roles for wrong client, got %d", len(roles))
	}
}

func TestHasRole(t *testing.T) {
	roles := []string{"admin", "ssh-access", "user"}

	if !HasRole(roles, "ssh-access") {
		t.Error("should find ssh-access")
	}
	if HasRole(roles, "nonexistent") {
		t.Error("should not find nonexistent")
	}
	if HasRole(nil, "anything") {
		t.Error("should not find anything in nil slice")
	}
}

func TestExtractRolesCustomClaim_FlatArray(t *testing.T) {
	claims := map[string]interface{}{
		"groups": []interface{}{"ssh-access", "admin"},
	}
	roles := ExtractRoles(claims, "ssh-server", "groups")
	if len(roles) != 2 || roles[0] != "ssh-access" || roles[1] != "admin" {
		t.Errorf("expected [ssh-access admin], got %v", roles)
	}
}

func TestExtractRolesCustomClaim_URLKey(t *testing.T) {
	claims := map[string]interface{}{
		"https://myapp.example.com/roles": []interface{}{"ssh-access"},
	}
	roles := ExtractRoles(claims, "ssh-server", "https://myapp.example.com/roles")
	if len(roles) != 1 || roles[0] != "ssh-access" {
		t.Errorf("expected [ssh-access], got %v", roles)
	}
}

func TestExtractRolesCustomClaim_Missing(t *testing.T) {
	claims := map[string]interface{}{}
	roles := ExtractRoles(claims, "ssh-server", "groups")
	if roles != nil {
		t.Errorf("expected nil, got %v", roles)
	}
}

func TestExtractRolesKeycloakDefault_EmptyRoleClaim(t *testing.T) {
	claims := map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"ssh-access"},
		},
	}
	roles := ExtractRoles(claims, "ssh-server", "")
	if len(roles) != 1 || roles[0] != "ssh-access" {
		t.Errorf("expected [ssh-access], got %v", roles)
	}
}

func TestExtractRoles_CustomClaimSupplementsKeycloak(t *testing.T) {
	claims := map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"kc-realm-role"},
		},
		"resource_access": map[string]interface{}{
			"ssh-server": map[string]interface{}{
				"roles": []interface{}{"kc-client-role"},
			},
		},
		"groups": []interface{}{"custom-group"},
	}
	roles := ExtractRoles(claims, "ssh-server", "groups")
	if len(roles) != 3 {
		t.Fatalf("expected 3 roles (2 keycloak + 1 custom), got %d: %v", len(roles), roles)
	}
	want := map[string]bool{"kc-realm-role": true, "kc-client-role": true, "custom-group": true}
	for _, r := range roles {
		if !want[r] {
			t.Errorf("unexpected role %q", r)
		}
	}
}

func TestExtractRoles_DottedPath(t *testing.T) {
	claims := map[string]interface{}{
		"resource_access": map[string]interface{}{
			"ssh": map[string]interface{}{
				"roles": []interface{}{"ssh-access", "admin"},
			},
		},
	}
	roles := ExtractRoles(claims, "not-a-match", "resource_access.ssh.roles")
	if len(roles) != 2 {
		t.Fatalf("expected 2 roles from dotted path, got %d: %v", len(roles), roles)
	}
	if roles[0] != "ssh-access" || roles[1] != "admin" {
		t.Errorf("roles = %v, want [ssh-access admin]", roles)
	}
}

func TestExtractRoles_DottedPath_MissingSegment(t *testing.T) {
	claims := map[string]interface{}{
		"resource_access": map[string]interface{}{
			"other": map[string]interface{}{
				"roles": []interface{}{"x"},
			},
		},
	}
	roles := ExtractRoles(claims, "ssh-server", "resource_access.ssh.roles")
	if roles != nil {
		t.Errorf("expected nil for missing dotted segment, got %v", roles)
	}
}

func TestExtractRoles_URLKeyStillWorksWithDots(t *testing.T) {
	// URL-style keys contain literal dots — flat lookup must win before
	// dotted traversal splits them.
	claims := map[string]interface{}{
		"https://myapp.example.com/roles": []interface{}{"ssh-access"},
	}
	roles := ExtractRoles(claims, "ssh-server", "https://myapp.example.com/roles")
	if len(roles) != 1 || roles[0] != "ssh-access" {
		t.Errorf("expected [ssh-access], got %v", roles)
	}
}

func TestExtractRoles_DottedPathOnNonMap(t *testing.T) {
	// Path traversal must bail cleanly if an intermediate segment is not an object.
	claims := map[string]interface{}{
		"resource_access": "not-an-object",
	}
	roles := ExtractRoles(claims, "ssh-server", "resource_access.ssh.roles")
	if roles != nil {
		t.Errorf("expected nil for non-map intermediate, got %v", roles)
	}
}

func TestExtractStringList_Array(t *testing.T) {
	claims := map[string]interface{}{
		"clients": []interface{}{"10.0.20.2", "10.0.99.202", "10.1.1.2"},
	}
	ips := ExtractStringList(claims, "clients")
	if len(ips) != 3 {
		t.Fatalf("expected 3 IPs, got %d", len(ips))
	}
	if ips[0] != "10.0.20.2" || ips[2] != "10.1.1.2" {
		t.Errorf("IPs = %v", ips)
	}
}

func TestExtractStringList_SingleString(t *testing.T) {
	claims := map[string]interface{}{
		"clients": "10.0.20.2",
	}
	ips := ExtractStringList(claims, "clients")
	if len(ips) != 1 || ips[0] != "10.0.20.2" {
		t.Errorf("expected [10.0.20.2], got %v", ips)
	}
}

func TestExtractStringList_Missing(t *testing.T) {
	claims := map[string]interface{}{}
	ips := ExtractStringList(claims, "clients")
	if ips != nil {
		t.Errorf("expected nil for missing claim, got %v", ips)
	}
}

func TestExtractStringList_EmptyArray(t *testing.T) {
	claims := map[string]interface{}{
		"clients": []interface{}{},
	}
	ips := ExtractStringList(claims, "clients")
	if ips == nil {
		t.Fatal("expected non-nil empty slice")
	}
	if len(ips) != 0 {
		t.Errorf("expected 0 IPs, got %d", len(ips))
	}
}

func TestExtractStringList_WithCIDR(t *testing.T) {
	claims := map[string]interface{}{
		"networks": []interface{}{"10.0.0.0/24", "192.168.1.0/24"},
	}
	nets := ExtractStringList(claims, "networks")
	if len(nets) != 2 || nets[0] != "10.0.0.0/24" {
		t.Errorf("expected CIDRs, got %v", nets)
	}
}
