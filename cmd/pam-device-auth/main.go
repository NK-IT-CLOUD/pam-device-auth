package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/nk-dev/pam-device-auth/internal/cache"
	"github.com/nk-dev/pam-device-auth/internal/config"
	"github.com/nk-dev/pam-device-auth/internal/device"
	"github.com/nk-dev/pam-device-auth/internal/discovery"
	"github.com/nk-dev/pam-device-auth/internal/logger"
	"github.com/nk-dev/pam-device-auth/internal/token"
	"github.com/nk-dev/pam-device-auth/internal/user"
)

var VERSION = "0.6.0"

const (
	logFile     = "/var/log/keycloak-ssh-auth.log"
	httpTimeout = 10 * time.Second
)

func main() {
	debug := false
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--version":
			fmt.Printf("keycloak-auth %s\n", VERSION)
			os.Exit(0)
		case "--help":
			fmt.Println("Usage: keycloak-auth [--debug] [--version] [--help]")
			fmt.Println("  SSH authentication via Keycloak Device Authorization Grant")
			os.Exit(0)
		case "--debug":
			debug = true
		}
	}

	log, err := logger.NewLogger(logFile, debug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Logger init failed: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	log.Info("keycloak-auth %s starting", VERSION)

	cfg, err := config.Load("")
	if err != nil {
		log.Error("Config error: %v", err)
		os.Exit(1)
	}

	sshUser := os.Getenv("PAM_USER")
	if sshUser == "" {
		log.Error("PAM_USER not set")
		os.Exit(1)
	}
	log.Info("Authenticating user: %s", sshUser)

	httpClient := &http.Client{Timeout: httpTimeout}

	// OIDC Discovery (fail-fast if Keycloak unreachable)
	discoveryCtx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	endpoints, err := discovery.Fetch(discoveryCtx, httpClient, cfg.KeycloakURL, cfg.Realm)
	cancel()
	if err != nil {
		log.Error("OIDC Discovery failed: %v", err)
		os.Exit(1)
	}
	log.Debug("Discovery OK: device=%s", endpoints.DeviceAuthorizationEndpoint)

	// Try cached refresh token
	if tryCachedRefresh(log, cfg, httpClient, endpoints, sshUser) {
		os.Exit(0)
	}

	// Full Device Auth flow
	deviceAuthFlow(log, cfg, httpClient, endpoints, sshUser)
	os.Exit(0)
}

// tryCachedRefresh attempts to use a cached refresh token.
// Returns true on success, false if Device Auth should run.
func tryCachedRefresh(log *logger.Logger, cfg *config.Config, httpClient *http.Client, endpoints *discovery.Endpoints, sshUser string) bool {
	session, err := cache.Load(sshUser)
	if err != nil {
		log.Debug("Cache load error: %v", err)
		return false
	}
	if session == nil {
		return false
	}

	log.Info("Cached session found for user: %s", sshUser)

	// Refresh the token
	refreshCtx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	tokenResp, err := device.RefreshToken(refreshCtx, httpClient, endpoints.TokenEndpoint, cfg.ClientID, session.RefreshToken)
	cancel()
	if err != nil {
		log.Info("Token refresh failed: %v", err)
		cache.Delete(sshUser)
		log.Info("Cache cleared, starting Device Auth")
		return false
	}
	log.Info("Token refresh successful")

	// Validate the new access token
	jwksCtx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	keys, err := token.FetchJWKS(jwksCtx, httpClient, endpoints.JwksURI)
	cancel()
	if err != nil {
		log.Info("JWKS fetch failed after refresh: %v", err)
		cache.Delete(sshUser)
		return false
	}

	result, err := token.Validate(tokenResp.AccessToken, keys, endpoints.Issuer, cfg.ClientID)
	if err != nil {
		log.Info("Token validation failed after refresh: %v", err)
		cache.Delete(sshUser)
		return false
	}

	if result.Username != sshUser {
		log.Error("Username mismatch: token=%q ssh=%q", result.Username, sshUser)
		cache.Delete(sshUser)
		return false
	}

	if !token.HasRole(result.Roles, cfg.RequiredRole) {
		log.Error("User %s lacks required role: %s", sshUser, cfg.RequiredRole)
		cache.Delete(sshUser)
		fmt.Println("Zugriff verweigert.")
		return false
	}

	log.Info("Auth OK: user=%s email=%s roles=%v", result.Username, result.Email, result.Roles)

	// Save rotated refresh token
	if tokenResp.RefreshToken != "" {
		if err := cache.Save(sshUser, tokenResp.RefreshToken); err != nil {
			log.Debug("Cache save error: %v", err)
		}
	}

	created, err := user.Setup(sshUser, log)
	if err != nil {
		log.Error("User setup failed: %v", err)
		return false
	}

	if created {
		fmt.Printf("User %s wurde erstellt. Bitte erneut anmelden.\n", sshUser)
		log.Info("First login: user %s created, session will close (sshd invalid-user constraint)", sshUser)
		return true
	}

	fmt.Println("SSO-Session aktiv.")
	return true
}

// deviceAuthFlow runs the full Device Authorization Grant flow.
func deviceAuthFlow(log *logger.Logger, cfg *config.Config, httpClient *http.Client, endpoints *discovery.Endpoints, sshUser string) {
	requestCtx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	dc, err := device.RequestCode(requestCtx, httpClient, endpoints.DeviceAuthorizationEndpoint, cfg.ClientID)
	cancel()
	if err != nil {
		log.Error("Device code request failed: %v", err)
		os.Exit(1)
	}

	// Print to stdout — PAM pipes to SSH terminal
	fmt.Println("────────────────────────────────────")
	fmt.Printf("Login: %s\n", dc.VerificationURI)
	fmt.Printf("Code:  %s\n", dc.UserCode)
	if dc.VerificationURIComplete != "" {
		fmt.Printf("Link:  %s\n", dc.VerificationURIComplete)
	}
	fmt.Println("────────────────────────────────────")

	timeout := cfg.AuthTimeout
	if dc.ExpiresIn > 0 && dc.ExpiresIn < timeout {
		timeout = dc.ExpiresIn
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	log.Info("Waiting for authorization (timeout: %ds)", timeout)
	tokenResp, err := device.PollToken(ctx, httpClient, endpoints.TokenEndpoint, cfg.ClientID, dc.DeviceCode, dc.Interval)
	if err != nil {
		log.Error("Token polling failed: %v", err)
		fmt.Println("Anmeldung fehlgeschlagen.")
		os.Exit(1)
	}

	jwksCtx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	keys, err := token.FetchJWKS(jwksCtx, httpClient, endpoints.JwksURI)
	cancel()
	if err != nil {
		log.Error("JWKS fetch failed: %v", err)
		os.Exit(1)
	}

	result, err := token.Validate(tokenResp.AccessToken, keys, endpoints.Issuer, cfg.ClientID)
	if err != nil {
		log.Error("Token validation failed: %v", err)
		os.Exit(1)
	}

	if result.Username != sshUser {
		log.Error("Username mismatch: token=%q ssh=%q", result.Username, sshUser)
		os.Exit(1)
	}

	if !token.HasRole(result.Roles, cfg.RequiredRole) {
		log.Error("User %s lacks required role: %s", sshUser, cfg.RequiredRole)
		fmt.Println("Zugriff verweigert.")
		os.Exit(1)
	}

	log.Info("Auth OK: user=%s email=%s roles=%v", result.Username, result.Email, result.Roles)

	// Cache refresh token for next login
	if tokenResp.RefreshToken != "" {
		if err := cache.Save(sshUser, tokenResp.RefreshToken); err != nil {
			log.Debug("Cache save error (non-fatal): %v", err)
		}
	}

	created, err := user.Setup(sshUser, log)
	if err != nil {
		log.Error("User setup failed: %v", err)
		os.Exit(1)
	}

	if created {
		fmt.Printf("Login erfolgreich! User %s wurde erstellt.\n", sshUser)
		fmt.Println("Verbindung wird getrennt — bitte erneut anmelden.")
	} else {
		fmt.Println("Login erfolgreich!")
	}
}
