package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/cache"
	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/config"
	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/device"
	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/discovery"
	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/logger"
	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/token"
	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/user"
)

var VERSION = "0.5.0"

const logFile = "/var/log/keycloak-ssh-auth.log"

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

	// OIDC Discovery (fail-fast if Keycloak unreachable)
	endpoints, err := discovery.Fetch(cfg.KeycloakURL, cfg.Realm)
	if err != nil {
		log.Error("OIDC Discovery failed: %v", err)
		os.Exit(1)
	}
	log.Debug("Discovery OK: device=%s", endpoints.DeviceAuthorizationEndpoint)

	// Try cached refresh token
	if tryCachedRefresh(log, cfg, endpoints, sshUser) {
		os.Exit(0)
	}

	// Full Device Auth flow
	deviceAuthFlow(log, cfg, endpoints, sshUser)
	os.Exit(0)
}

// tryCachedRefresh attempts to use a cached refresh token.
// Returns true on success, false if Device Auth should run.
func tryCachedRefresh(log *logger.Logger, cfg *config.Config, endpoints *discovery.Endpoints, sshUser string) bool {
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
	tokenResp, err := device.RefreshToken(endpoints.TokenEndpoint, cfg.ClientID, session.RefreshToken)
	if err != nil {
		log.Info("Token refresh failed: %v", err)
		cache.Delete(sshUser)
		log.Info("Cache cleared, starting Device Auth")
		return false
	}
	log.Info("Token refresh successful")

	// Validate the new access token
	keys, err := token.FetchJWKS(endpoints.JwksURI)
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

	if err := user.Setup(sshUser, log); err != nil {
		log.Error("User setup failed: %v", err)
		return false
	}

	fmt.Println("SSO-Session aktiv.")
	return true
}

// deviceAuthFlow runs the full Device Authorization Grant flow.
func deviceAuthFlow(log *logger.Logger, cfg *config.Config, endpoints *discovery.Endpoints, sshUser string) {
	dc, err := device.RequestCode(endpoints.DeviceAuthorizationEndpoint, cfg.ClientID)
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
	tokenResp, err := device.PollToken(ctx, endpoints.TokenEndpoint, cfg.ClientID, dc.DeviceCode, dc.Interval)
	if err != nil {
		log.Error("Token polling failed: %v", err)
		fmt.Println("Anmeldung fehlgeschlagen.")
		os.Exit(1)
	}

	keys, err := token.FetchJWKS(endpoints.JwksURI)
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

	if err := user.Setup(sshUser, log); err != nil {
		log.Error("User setup failed: %v", err)
		os.Exit(1)
	}

	fmt.Println("Login erfolgreich!")
}
