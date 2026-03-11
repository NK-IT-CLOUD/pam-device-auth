package token

// ExtractRoles extracts roles from JWT claims.
// Merges realm_access.roles and resource_access[clientID].roles.
func ExtractRoles(claims map[string]interface{}, clientID string) []string {
	var roles []string

	// Realm roles
	if realmAccess, ok := claims["realm_access"].(map[string]interface{}); ok {
		if realmRoles, ok := realmAccess["roles"].([]interface{}); ok {
			for _, r := range realmRoles {
				if role, ok := r.(string); ok {
					roles = append(roles, role)
				}
			}
		}
	}

	// Client-specific roles
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
