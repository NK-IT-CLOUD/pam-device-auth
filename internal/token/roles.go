package token

import "strings"

// ExtractStringList extracts a flat string array from a JWT claim.
// Returns nil if the claim does not exist, or the extracted strings if it does.
// An existing but empty claim returns an empty (non-nil) slice.
func ExtractStringList(claims map[string]interface{}, claimKey string) []string {
	val, ok := claims[claimKey]
	if !ok {
		return nil
	}
	arr, ok := val.([]interface{})
	if !ok {
		// Single string value — wrap in slice
		if s, ok := val.(string); ok {
			return []string{s}
		}
		return nil
	}
	result := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// ExtractRoles extracts roles from JWT claims.
// The Keycloak-native paths (realm_access.roles and resource_access.<client>.roles)
// are always consulted. If roleClaim is set, roles at that path SUPPLEMENT the
// Keycloak roles (not replace them), matching the configuration-reference docs.
// roleClaim supports both flat top-level keys (including URL-style keys like
// "https://example.com/roles") and dotted paths like "resource_access.ssh.roles".
func ExtractRoles(claims map[string]interface{}, clientID, roleClaim string) []string {
	roles := extractKeycloakRoles(claims, clientID)
	if roleClaim != "" {
		roles = append(roles, extractFromClaim(claims, roleClaim)...)
	}
	return roles
}

func extractFromClaim(claims map[string]interface{}, claimKey string) []string {
	val := walkClaimPath(claims, claimKey)
	arr, ok := val.([]interface{})
	if !ok {
		if s, ok := val.(string); ok {
			return []string{s}
		}
		return nil
	}
	var roles []string
	for _, r := range arr {
		if role, ok := r.(string); ok {
			roles = append(roles, role)
		}
	}
	return roles
}

// walkClaimPath resolves a claim key that may be a flat top-level name OR a
// dotted path into a nested object. Flat lookup runs first so URL-style keys
// like "https://example.com/roles" — which contain dots but live at the top
// level — resolve correctly before falling through to dotted traversal.
func walkClaimPath(claims map[string]interface{}, path string) interface{} {
	if val, ok := claims[path]; ok {
		return val
	}
	parts := strings.Split(path, ".")
	if len(parts) == 1 {
		return nil
	}
	var current interface{} = claims
	for _, part := range parts {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		v, ok := m[part]
		if !ok {
			return nil
		}
		current = v
	}
	return current
}

func extractKeycloakRoles(claims map[string]interface{}, clientID string) []string {
	var roles []string

	if realmAccess, ok := claims["realm_access"].(map[string]interface{}); ok {
		if realmRoles, ok := realmAccess["roles"].([]interface{}); ok {
			for _, r := range realmRoles {
				if role, ok := r.(string); ok {
					roles = append(roles, role)
				}
			}
		}
	}

	if resourceAccess, ok := claims["resource_access"].(map[string]interface{}); ok {
		if clientAccess, ok := resourceAccess[clientID].(map[string]interface{}); ok {
			if clientRoles, ok := clientAccess["roles"].([]interface{}); ok {
				for _, r := range clientRoles {
					if role, ok := r.(string); ok {
						roles = append(roles, role)
					}
				}
			}
		}
	}

	return roles
}

// HasRole checks if the required role is in the roles slice.
func HasRole(roles []string, required string) bool {
	for _, r := range roles {
		if r == required {
			return true
		}
	}
	return false
}
