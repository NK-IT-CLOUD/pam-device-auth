package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"keycloak-ssh-auth/internal/config"
	"keycloak-ssh-auth/internal/html"
	"keycloak-ssh-auth/internal/logger"
)

// KeycloakAuth manages the authentication process with Keycloak
type KeycloakAuth struct {
	config       *config.Config
	authCode     string
	state        string
	codeVerifier string
	listener     net.Listener
	token        map[string]interface{}
	logger       *logger.Logger
	authURL      string // Cache the auth URL to prevent regeneration
}

// AuthResult represents the result of an authentication attempt
type AuthResult struct {
	Success      bool
	Username     string
	Email        string
	Name         string
	Roles        []string
	ErrorMessage string
}

// NewKeycloakAuth creates a new KeycloakAuth instance
func NewKeycloakAuth(cfg *config.Config, log *logger.Logger) *KeycloakAuth {
	return &KeycloakAuth{
		config: cfg,
		logger: log,
	}
}

// Authenticate performs the complete authentication flow
func (ka *KeycloakAuth) Authenticate(ctx context.Context, sshUser string) (*AuthResult, error) {
	ka.logger.Info("Starting authentication for user: %s", sshUser)

	// Start the OAuth2 flow only if not already started
	if ka.state == "" {
		_, err := ka.startAuthFlow()
		if err != nil {
			return nil, fmt.Errorf("failed to start auth flow: %v", err)
		}
	}

	ka.logger.Info("Authentication URL generated, waiting for user interaction")

	// Wait for callback with timeout
	authCtx, cancel := context.WithTimeout(ctx, time.Duration(ka.config.AuthTimeout)*time.Second)
	defer cancel()

	if err := ka.waitForCallback(authCtx); err != nil {
		return nil, fmt.Errorf("authentication failed: %v", err)
	}

	// Extract and verify claims
	claims, ok := ka.getTokenClaims(ka.token)
	if !ok {
		return nil, fmt.Errorf("failed to extract token claims")
	}

	result := &AuthResult{
		Success: true,
	}

	// Extract user information
	if username, ok := claims["preferred_username"].(string); ok {
		result.Username = username
	} else {
		return nil, fmt.Errorf("no username in token claims")
	}

	if email, ok := claims["email"].(string); ok {
		result.Email = email
	}

	if name, ok := claims["name"].(string); ok {
		result.Name = name
	}

	// Verify username matches SSH user
	if result.Username != sshUser {
		return nil, fmt.Errorf("username mismatch: SSH user '%s' != SSO user '%s'",
			sshUser, result.Username)
	}

	// Extract roles
	result.Roles = ka.extractRoles(claims)

	// Verify required role
	if !ka.hasRequiredRole(result.Roles) {
		return nil, fmt.Errorf("user does not have required role: %s", ka.config.RequiredRole)
	}

	ka.logger.Info("Authentication successful for user: %s", result.Username)
	return result, nil
}

// GetAuthURL returns the authentication URL for the user to visit
func (ka *KeycloakAuth) GetAuthURL() (string, error) {
	// Return cached URL if already generated
	if ka.authURL != "" {
		return ka.authURL, nil
	}

	// Generate new auth URL and cache it
	authURL, err := ka.startAuthFlow()
	if err != nil {
		return "", err
	}

	ka.authURL = authURL
	return authURL, nil
}

// startAuthFlow generates the authentication URL for Keycloak
func (ka *KeycloakAuth) startAuthFlow() (string, error) {
	ka.codeVerifier = generateRandomString(64)
	h := sha256.New()
	h.Write([]byte(ka.codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	ka.state = generateRandomString(32)
	ka.logger.Debug("Generated OAuth2 state parameter: %s", ka.state)

	params := url.Values{}
	params.Add("client_id", ka.config.ClientID)
	params.Add("response_type", "code")
	params.Add("scope", "openid profile email roles")
	params.Add("redirect_uri", ka.config.GetCallbackURL())
	params.Add("state", ka.state)
	params.Add("code_challenge", codeChallenge)
	params.Add("code_challenge_method", "S256")

	return fmt.Sprintf("%s?%s", ka.config.GetKeycloakAuthURL(), params.Encode()), nil
}

// waitForCallback starts a local server to handle the Keycloak callback
func (ka *KeycloakAuth) waitForCallback(ctx context.Context) error {
	ka.logger.Debug("Starting callback server on %s:%s", ka.config.CallbackIP, ka.config.CallbackPort)

	// Create reusable port listener
	listener, err := newReusePortListener("tcp",
		fmt.Sprintf("%s:%s", ka.config.CallbackIP, ka.config.CallbackPort))
	if err != nil {
		return fmt.Errorf("failed to create listener: %v", err)
	}
	defer listener.Close()

	doneChan := make(chan error, 1)
	var callbackProcessed atomic.Bool

	server := &http.Server{
		Addr:              listener.Addr().String(),
		ReadTimeout:       time.Duration(ka.config.AuthTimeout) * time.Second,
		WriteTimeout:      time.Duration(ka.config.AuthTimeout) * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		Handler:           ka.createCallbackHandler(&callbackProcessed, doneChan),
	}

	// Start server
	go func() {
		if err := server.Serve(listener); err != http.ErrServerClosed {
			if !callbackProcessed.Load() {
				doneChan <- err
			}
		}
	}()

	// Wait for callback or timeout
	select {
	case err := <-doneChan:
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		server.Shutdown(shutdownCtx)
		return err
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		server.Shutdown(shutdownCtx)
		return fmt.Errorf("authentication timeout")
	}
}

// createCallbackHandler creates the HTTP handler for the OAuth2 callback
func (ka *KeycloakAuth) createCallbackHandler(callbackProcessed *atomic.Bool, doneChan chan<- error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept /callback path and process once
		if r.URL.Path != "/callback" {
			ka.logger.Debug("Rejecting non-callback request: %s", r.URL.Path)
			ka.renderTemplate(w, "error.html", http.StatusNotFound)
			return
		}

		if !callbackProcessed.CompareAndSwap(false, true) {
			ka.logger.Debug("Callback already processed")
			ka.renderTemplate(w, "error.html", http.StatusConflict)
			return
		}

		ka.logger.Debug("Processing OAuth2 callback")

		// Check for errors in callback
		if errorParam := r.URL.Query().Get("error"); errorParam != "" {
			errorDescription := r.URL.Query().Get("error_description")
			ka.logger.Error("OAuth2 error: %s - %s", errorParam, errorDescription)
			ka.renderTemplate(w, "error.html", http.StatusUnauthorized)
			doneChan <- fmt.Errorf("OAuth2 error: %s - %s", errorParam, errorDescription)
			return
		}

		// Extract and validate parameters
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if code == "" || state == "" {
			ka.logger.Error("Missing code or state in callback")
			ka.renderTemplate(w, "error.html", http.StatusBadRequest)
			doneChan <- fmt.Errorf("missing code or state in callback")
			return
		}

		ka.logger.Debug("Received state parameter: %s", state)
		ka.logger.Debug("Expected state parameter: %s", ka.state)

		if state != ka.state {
			ka.logger.Error("Invalid state parameter: received '%s', expected '%s'", state, ka.state)
			ka.renderTemplate(w, "error.html", http.StatusBadRequest)
			doneChan <- fmt.Errorf("invalid state parameter")
			return
		}

		// Exchange code for token
		ka.authCode = code
		token, err := ka.exchangeToken()
		if err != nil {
			ka.logger.Error("Token exchange failed: %v", err)
			ka.renderTemplate(w, "error.html", http.StatusUnauthorized)
			doneChan <- err
			return
		}

		ka.token = token
		ka.renderTemplate(w, "success.html", http.StatusOK)
		doneChan <- nil
	}
}

// renderTemplate renders an HTML template
func (ka *KeycloakAuth) renderTemplate(w http.ResponseWriter, templateName string, statusCode int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)

	if template, err := html.GetTemplate(templateName); err == nil {
		w.Write([]byte(template))
	} else {
		ka.logger.Error("Failed to load template %s: %v", templateName, err)
		w.Write([]byte("Authentication Error"))
	}
}

// exchangeToken sends the authorization code to Keycloak to obtain an access token
func (ka *KeycloakAuth) exchangeToken() (map[string]interface{}, error) {
	tokenURL := ka.config.GetKeycloakTokenURL()

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", ka.config.ClientID)
	data.Set("client_secret", ka.config.ClientSecret)
	data.Set("code", ka.authCode)
	data.Set("redirect_uri", ka.config.GetCallbackURL())
	data.Set("code_verifier", ka.codeVerifier)

	ka.logger.Debug("Exchanging authorization code for token")

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.PostForm(tokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, body)
	}

	var token map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %v", err)
	}

	return token, nil
}

// getTokenClaims extracts the claims from the access token
func (ka *KeycloakAuth) getTokenClaims(token map[string]interface{}) (map[string]interface{}, bool) {
	accessToken, ok := token["access_token"].(string)
	if !ok {
		ka.logger.Error("No access_token in token response")
		return nil, false
	}

	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		ka.logger.Error("Invalid JWT format")
		return nil, false
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		ka.logger.Error("Failed to decode JWT payload: %v", err)
		return nil, false
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		ka.logger.Error("Failed to parse JWT claims: %v", err)
		return nil, false
	}

	return claims, true
}

// extractRoles extracts roles from token claims
func (ka *KeycloakAuth) extractRoles(claims map[string]interface{}) []string {
	var roles []string

	// Check realm_access roles
	if realmAccess, ok := claims["realm_access"].(map[string]interface{}); ok {
		if realmRoles, ok := realmAccess["roles"].([]interface{}); ok {
			for _, role := range realmRoles {
				if roleStr, ok := role.(string); ok {
					roles = append(roles, roleStr)
				}
			}
		}
	}

	// Check resource_access roles
	if resourceAccess, ok := claims["resource_access"].(map[string]interface{}); ok {
		if clientAccess, ok := resourceAccess[ka.config.ClientID].(map[string]interface{}); ok {
			if clientRoles, ok := clientAccess["roles"].([]interface{}); ok {
				for _, role := range clientRoles {
					if roleStr, ok := role.(string); ok {
						roles = append(roles, roleStr)
					}
				}
			}
		}
	}

	return roles
}

// hasRequiredRole checks if the user has the required role
func (ka *KeycloakAuth) hasRequiredRole(roles []string) bool {
	for _, role := range roles {
		if role == ka.config.RequiredRole {
			return true
		}
	}
	return false
}

// newReusePortListener creates a listener with SO_REUSEPORT
func newReusePortListener(network, address string) (net.Listener, error) {
	config := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if opErr != nil {
					return
				}
				// SO_REUSEPORT for Linux
				opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 15, 1)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}

	ctx := context.Background()
	return config.Listen(ctx, network, address)
}

// generateRandomString creates a random string of specified length
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// Seed the random number generator with current time
	rand.Seed(time.Now().UnixNano())

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
