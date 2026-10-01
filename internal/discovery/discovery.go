package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/oidccache"
)

// defaultFetchTimeout bounds a metadata fetch when the caller passes neither a
// context deadline nor an http.Client timeout. A variable so tests can shrink it.
var defaultFetchTimeout = 10 * time.Second

type Endpoints struct {
	Issuer                      string `json:"issuer"`
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	JwksURI                     string `json:"jwks_uri"`
}

// Fetch retrieves and validates the discovery document live.
func Fetch(ctx context.Context, client *http.Client, issuerURL string) (*Endpoints, error) {
	body, err := FetchRaw(ctx, client, issuerURL)
	if err != nil {
		return nil, err
	}
	return Parse(body)
}

// FetchCached serves the discovery document from the on-disk metadata cache
// when a fresh entry for issuerURL exists, otherwise fetches live and caches
// the validated body best-effort. A cached body goes through Parse exactly
// like a live response, so a cache hit never bypasses validation. debugf
// receives non-fatal cache diagnostics; nil disables them.
func FetchCached(ctx context.Context, client *http.Client, issuerURL string, debugf func(string, ...interface{})) (*Endpoints, error) {
	if debugf == nil {
		debugf = func(string, ...interface{}) {}
	}

	if body, err := oidccache.Load(oidccache.DiscoveryFile, issuerURL); err != nil {
		debugf("Discovery cache unusable, fetching live: %v", err)
	} else if body != nil {
		ep, err := Parse(body)
		if err == nil {
			debugf("Discovery served from cache")
			return ep, nil
		}
		debugf("Discovery cache failed validation, fetching live: %v", err)
	}

	body, err := FetchRaw(ctx, client, issuerURL)
	if err != nil {
		return nil, err
	}
	ep, err := Parse(body)
	if err != nil {
		return nil, err
	}
	if err := oidccache.Save(oidccache.DiscoveryFile, issuerURL, body); err != nil {
		debugf("Discovery cache write failed (non-fatal): %v", err)
	}
	return ep, nil
}

// FetchRaw performs the HTTP part of Fetch and returns the bounded raw body
// of the discovery document without parsing it.
func FetchRaw(ctx context.Context, client *http.Client, issuerURL string) ([]byte, error) {
	discoveryURL := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"

	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil {
		client = &http.Client{
			Timeout: defaultFetchTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	// The body read below must never block a login indefinitely: if the caller
	// supplied neither a context deadline nor a client timeout, bound it here.
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && client.Timeout <= 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultFetchTimeout)
		defer cancel()
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read OIDC discovery: %w", err)
	}
	return body, nil
}

// Parse decodes and validates a discovery document body. It is the single
// validation path for both live and cached documents.
func Parse(body []byte) (*Endpoints, error) {
	var ep Endpoints
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&ep); err != nil {
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
