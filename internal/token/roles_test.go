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
