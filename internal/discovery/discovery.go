package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Endpoints struct {
	Issuer                      string `json:"issuer"`
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	JwksURI                     string `json:"jwks_uri"`
}

func Fetch(ctx context.Context, client *http.Client, issuerURL string) (*Endpoints, error) {
	discoveryURL := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"

	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build OIDC discovery request: %w", err)
	}

	resp, err := client.Do(req)
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

	// Validate endpoint URL schemes
	for name, endpoint := range map[string]string{
		"token_endpoint":                ep.TokenEndpoint,
		"device_authorization_endpoint": ep.DeviceAuthorizationEndpoint,
		"jwks_uri":                      ep.JwksURI,
	} {
		u, err := url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid %s URL: %w", name, err)
		}
		if u.Scheme != "https" {
			if u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1") {
				continue
			}
			return nil, fmt.Errorf("%s must use https:// scheme, got %s", name, u.Scheme)
		}
	}

	return &ep, nil
}
