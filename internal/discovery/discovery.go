package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

	// Bound the body: the discovery document is a few KB; cap at 1 MiB so a
	// host-pinned-but-hostile issuer cannot exhaust memory in the root helper.
	var ep Endpoints
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ep); err != nil {
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

	// The issuer host is our signature-trust anchor: the caller separately
	// pins ep.Issuer to the configured issuer, so an endpoint served by any
	// OTHER host is outside that trust. Pinning here (especially jwks_uri, the
	// root of signature trust) stops a tampered discovery document that keeps a
	// legitimate `issuer` from redirecting key retrieval to an attacker host.
	issuerHost := ""
	if iu, err := url.Parse(ep.Issuer); err == nil {
		issuerHost = iu.Hostname()
	}

	// Validate endpoint URL schemes and pin them to the issuer host.
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
			// Dev-only exception: plain http is tolerated for loopback endpoints,
			// but only when the issuer itself is loopback — otherwise a tampered
			// discovery document for a production HTTPS issuer could route
			// jwks_uri (the root of signature trust) to a local listener past
			// both the scheme check and the host pin below.
			if u.Scheme == "http" && isLoopbackHost(issuerHost) && isLoopbackHost(u.Hostname()) {
				continue
			}
			return nil, fmt.Errorf("%s must use https:// scheme, got %s", name, u.Scheme)
		}
		if issuerHost == "" || u.Hostname() != issuerHost {
			return nil, fmt.Errorf("%s host %q does not match issuer host %q", name, u.Hostname(), issuerHost)
		}
	}

	return &ep, nil
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
