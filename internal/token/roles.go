package token

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
