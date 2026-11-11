package device

import (
	"context"
	"encoding/json"
	"errors"
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

// DefaultHTTPTimeout is used when callers do not provide a client.
var DefaultHTTPTimeout = 10 * time.Second

// maxResponseBytes caps an IdP response body. The device-code, token, and error
// documents are a few KB at most; a larger body is treated as a fault and the
// read fails closed rather than buffering unbounded memory in a root helper
// (the client Timeout bounds request time, not body size). Only the host-pinned
// issuer can deliver a body here, so this is defense-in-depth.
const maxResponseBytes = 1 << 20 // 1 MiB

// maxErrorTextBytes is how much of an answer of the provider goes into an
// error text, and with it into one line of the helper's log.
const maxErrorTextBytes = 512

// clip shortens a part of the provider's answer for an error text.
func clip(s string) string {
	if len(s) <= maxErrorTextBytes {
		return s
	}
	return fmt.Sprintf("%s… (%d bytes in all)", s[:maxErrorTextBytes], len(s))
}

// errBodyTooLarge is readResponse's error for a body beyond maxResponseBytes.
var errBodyTooLarge = fmt.Errorf("response body exceeds %d byte limit", maxResponseBytes)

// readResponse reads a response body up to maxResponseBytes, returning an error
// if the body exceeds the cap (rather than silently truncating).
func readResponse(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBytes {
		return nil, errBodyTooLarge
	}
	return body, nil
}

// RequestCode requests a device code from the device authorization endpoint.
func RequestCode(ctx context.Context, client *http.Client, endpoint, clientID string) (*DeviceCode, error) {
	data := url.Values{
		"client_id": {clientID},
		"scope":     {"openid profile email"},
	}

	resp, err := postForm(ctx, client, endpoint, data)
	if err != nil {
		return nil, fmt.Errorf("request device code: %w", err)
	}
	defer resp.Body.Close()

	body, err := readResponse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read device code response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device code request failed (status %d): %s", resp.StatusCode, clip(string(body)))
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

// minRetryBackoff is the shortest wait after a transient failure of the token
// endpoint. A variable so tests can shrink it.
var minRetryBackoff = time.Second

// maxRetryBackoff caps the wait after repeated transient failures.
const maxRetryBackoff = 30 * time.Second

// nextBackoff returns the wait after one more consecutive transient failure:
// the poll interval first (at least minRetryBackoff), then twice the previous
// wait, capped at maxRetryBackoff (RFC 8628, section 3.5). The poll interval
// stays the floor: the cap never makes the helper poll faster than the
// provider allows.
func nextBackoff(current, interval time.Duration) time.Duration {
	if current == 0 {
		return max(interval, minRetryBackoff)
	}
	return max(min(current*2, maxRetryBackoff), interval)
}

// PollToken polls the token endpoint until authorization completes, is denied,
// or the context ends. The first request goes out at once: the caller starts
// polling when the user says the code is approved. After that there is one
// request per interval.
//
// A transport error, an HTTP 5xx, 408 or 429 and an error answer that is no
// OAuth error document say nothing about the device code. They are retried
// with a backoff (nextBackoff) until the context ends; the timeout error then
// names the last such failure.
func PollToken(ctx context.Context, client *http.Client, endpoint, clientID, deviceCode string, interval int) (*TokenResponse, error) {
	if interval < MinPollInterval {
		interval = MinPollInterval
	}
	wait := time.Duration(interval) * time.Second

	data := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {clientID},
	}

	var (
		backoff     time.Duration // > 0 while transient failures repeat
		lastFailure error
	)
	timedOut := func() error {
		if lastFailure != nil {
			return fmt.Errorf("device authorization timed out (last failure: %v)", lastFailure)
		}
		return fmt.Errorf("device authorization timed out")
	}
	transient := func(err error) {
		lastFailure = err
		backoff = nextBackoff(backoff, wait)
	}

	for first := true; ; first = false {
		if !first {
			pause := wait
			if backoff > 0 {
				pause = backoff
			}
			timer := time.NewTimer(pause)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, timedOut()
			case <-timer.C:
			}
		}

		resp, err := postForm(ctx, client, endpoint, data)
		if err != nil {
			if ctx.Err() != nil {
				return nil, timedOut()
			}
			transient(fmt.Errorf("poll token: %w", err))
			continue
		}

		body, err := readResponse(resp.Body)
		resp.Body.Close()
		if errors.Is(err, errBodyTooLarge) {
			return nil, fmt.Errorf("read token response: %w", err)
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, timedOut()
			}
			transient(fmt.Errorf("read token response: %w", err))
			continue
		}

		if resp.StatusCode == http.StatusOK {
			var token TokenResponse
			if err := json.Unmarshal(body, &token); err != nil {
				return nil, fmt.Errorf("parse token response: %w", err)
			}
			return &token, nil
		}

		var errResp errorResponse
		isOAuthError := json.Unmarshal(body, &errResp) == nil && errResp.Error != ""
		if !isOAuthError || resp.StatusCode >= 500 ||
			resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests {
			transient(fmt.Errorf("token endpoint answered status %d", resp.StatusCode))
			continue
		}
		backoff, lastFailure = 0, nil

		switch errResp.Error {
		case "authorization_pending":
		case "slow_down":
			wait += 5 * time.Second
		case "expired_token":
			return nil, fmt.Errorf("device code expired")
		case "access_denied":
			return nil, fmt.Errorf("access denied by user")
		default:
			return nil, fmt.Errorf("token error: %s (%s)", clip(errResp.Error), clip(errResp.ErrorDescription))
		}
	}
}

// ErrRefreshRejected marks a refresh that the identity provider answered with
// an HTTP 4xx (invalid_grant, revoked or expired session). Only then is the
// cached refresh token known to be dead; a network error or 5xx says nothing
// about it and the cached session must be kept.
var ErrRefreshRejected = errors.New("refresh token rejected by the identity provider")

// RefreshToken exchanges a refresh token for a new access token.
func RefreshToken(ctx context.Context, client *http.Client, tokenEndpoint, clientID, refreshToken string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	}

	resp, err := postForm(ctx, client, tokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("refresh token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := readResponse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var wrapped error
		// 408 (timeout) and 429 (rate limit) are transient, not a verdict on the token.
		if resp.StatusCode >= 400 && resp.StatusCode < 500 &&
			resp.StatusCode != http.StatusRequestTimeout && resp.StatusCode != http.StatusTooManyRequests {
			wrapped = ErrRefreshRejected
		}
		var errResp errorResponse
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
			return nil, joinRefreshErr(wrapped, fmt.Sprintf("refresh failed: %s (%s)", clip(errResp.Error), clip(errResp.ErrorDescription)))
		}
		return nil, joinRefreshErr(wrapped, fmt.Sprintf("refresh failed (status %d): %s", resp.StatusCode, clip(string(body))))
	}

	var token TokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("parse refresh response: %w", err)
	}

	return &token, nil
}

// joinRefreshErr builds the refresh error text, wrapping sentinel (may be nil)
// so callers can match it with errors.Is.
func joinRefreshErr(sentinel error, msg string) error {
	if sentinel == nil {
		return errors.New(msg)
	}
	return fmt.Errorf("%w: %s", sentinel, msg)
}

func postForm(ctx context.Context, client *http.Client, endpoint string, data url.Values) (*http.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil {
		// Match the hardened default used elsewhere: block redirects so a 3xx
		// cannot re-send the POST body (device_code / refresh_token) to a
		// redirect target. Production always passes newOIDCClient(); a nil
		// client gets this hardened default client with the same behavior.
		client = &http.Client{
			Timeout: DefaultHTTPTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return client.Do(req)
}
