package discovery

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Endpoints struct {
	Issuer                      string `json:"issuer"`
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	JwksURI                     string `json:"jwks_uri"`
}

func Fetch(keycloakURL, realm string) (*Endpoints, error) {
	discoveryURL := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", keycloakURL, realm)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("fetch OIDC discovery: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	var ep Endpoints
	if err := json.NewDecoder(resp.Body).Decode(&ep); err != nil {
		return nil, fmt.Errorf("parse OIDC discovery: %w", err)
	}

	if ep.Issuer == "" {
		return nil, fmt.Errorf("OIDC discovery missing issuer")
	}
	if ep.TokenEndpoint == "" {
		return nil, fmt.Errorf("OIDC discovery missing token_endpoint")
	}
	if ep.DeviceAuthorizationEndpoint == "" {
		return nil, fmt.Errorf("OIDC discovery missing device_authorization_endpoint")
	}
	if ep.JwksURI == "" {
		return nil, fmt.Errorf("OIDC discovery missing jwks_uri")
	}

	return &ep, nil
}
