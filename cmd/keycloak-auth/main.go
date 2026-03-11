package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/config"
	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/device"
	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/discovery"
	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/logger"
	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/token"
	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/user"
)

var VERSION = "0.4.0"

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

	endpoints, err := discovery.Fetch(cfg.KeycloakURL, cfg.Realm)
	if err != nil {
		log.Error("OIDC Discovery failed: %v", err)
		os.Exit(1)
	}
	log.Debug("Discovery OK: device=%s", endpoints.DeviceAuthorizationEndpoint)

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

	if err := user.Setup(sshUser, log); err != nil {
		log.Error("User setup failed: %v", err)
		os.Exit(1)
	}

	fmt.Println("Login erfolgreich!")
	os.Exit(0)
}
