package token

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
// If roleClaim is set, extracts from that claim key (flat string array).
// If empty, uses Keycloak default (realm_access + resource_access).
func ExtractRoles(claims map[string]interface{}, clientID, roleClaim string) []string {
	if roleClaim != "" {
		return extractFromClaim(claims, roleClaim)
	}
	return extractKeycloakRoles(claims, clientID)
}

func extractFromClaim(claims map[string]interface{}, claimKey string) []string {
	val, ok := claims[claimKey]
	if !ok {
		return nil
	}
	arr, ok := val.([]interface{})
	if !ok {
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
