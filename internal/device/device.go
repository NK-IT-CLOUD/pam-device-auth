package device

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

// DeviceCode holds the response from the device authorization endpoint.
type DeviceCode struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// TokenResponse holds a successful token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// MinPollInterval is the minimum polling interval in seconds (RFC 8628).
// Exported as a variable so tests can lower it to avoid slow test runs.
var MinPollInterval = 5

// RequestCode requests a device code from the device authorization endpoint.
func RequestCode(endpoint, clientID string) (*DeviceCode, error) {
	data := url.Values{
		"client_id": {clientID},
		"scope":     {"openid profile email"},
	}

	resp, err := http.Post(endpoint, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("request device code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read device code response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device code request failed (status %d): %s", resp.StatusCode, string(body))
	}

	var dc DeviceCode
	if err := json.Unmarshal(body, &dc); err != nil {
		return nil, fmt.Errorf("parse device code response: %w", err)
	}

	if dc.DeviceCode == "" || dc.UserCode == "" || dc.VerificationURI == "" {
		return nil, fmt.Errorf("device code response missing required fields")
	}

	if dc.Interval < MinPollInterval {
		dc.Interval = MinPollInterval
	}

	return &dc, nil
}

// PollToken polls the token endpoint until authorization completes, is denied, or times out.
func PollToken(ctx context.Context, endpoint, clientID, deviceCode string, interval int) (*TokenResponse, error) {
	if interval < MinPollInterval {
		interval = MinPollInterval
	}

	data := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {clientID},
	}

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("device authorization timed out")
		case <-time.After(time.Duration(interval) * time.Second):
		}

		resp, err := http.Post(endpoint, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
		if err != nil {
			return nil, fmt.Errorf("poll token: %w", err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read token response: %w", err)
		}

		if resp.StatusCode == http.StatusOK {
			var token TokenResponse
			if err := json.Unmarshal(body, &token); err != nil {
				return nil, fmt.Errorf("parse token response: %w", err)
			}
			return &token, nil
		}

		var errResp errorResponse
		if err := json.Unmarshal(body, &errResp); err != nil {
			return nil, fmt.Errorf("parse error response (status %d): %w", resp.StatusCode, err)
		}

		switch errResp.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5
			continue
		case "expired_token":
			return nil, fmt.Errorf("device code expired")
		case "access_denied":
			return nil, fmt.Errorf("access denied by user")
		default:
			return nil, fmt.Errorf("token error: %s (%s)", errResp.Error, errResp.ErrorDescription)
		}
	}
}

// RefreshToken exchanges a refresh token for a new access token.
func RefreshToken(tokenEndpoint, clientID, refreshToken string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(tokenEndpoint, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("refresh token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp errorResponse
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
			return nil, fmt.Errorf("refresh failed: %s (%s)", errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("refresh failed (status %d): %s", resp.StatusCode, string(body))
	}

	var token TokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("parse refresh response: %w", err)
	}

	return &token, nil
}
