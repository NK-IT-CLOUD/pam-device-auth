package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/nk-dev/pam-device-auth/internal/cache"
	"github.com/nk-dev/pam-device-auth/internal/config"
	"github.com/nk-dev/pam-device-auth/internal/device"
	"github.com/nk-dev/pam-device-auth/internal/discovery"
	"github.com/nk-dev/pam-device-auth/internal/logger"
	"github.com/nk-dev/pam-device-auth/internal/qr"
	"github.com/nk-dev/pam-device-auth/internal/token"
	"github.com/nk-dev/pam-device-auth/internal/user"
)

var VERSION = "0.1.1"

const (
	logFile     = "/var/log/pam-device-auth.log"
	httpTimeout = 10 * time.Second
)

func runCheck() {
	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: config error: %v\n", err)
		os.Exit(1)
	}

	// Check for default/example config
	if strings.Contains(cfg.IssuerURL, "example.com") {
		fmt.Fprintf(os.Stderr, "FAIL: default config detected. Edit /etc/pam-device-auth/config.json first.\n")
		os.Exit(1)
	}

	fmt.Printf("Config OK: issuer=%s client=%s role=%s\n", cfg.IssuerURL, cfg.ClientID, cfg.RequiredRole)

	// Test OIDC Discovery
	httpClient := &http.Client{Timeout: httpTimeout}
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	endpoints, err := discovery.Fetch(ctx, httpClient, cfg.IssuerURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: OIDC discovery failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("OIDC OK: issuer=%s\n", endpoints.Issuer)
	fmt.Printf("  device_endpoint=%s\n", endpoints.DeviceAuthorizationEndpoint)
	fmt.Printf("  token_endpoint=%s\n", endpoints.TokenEndpoint)
	fmt.Printf("  jwks_uri=%s\n", endpoints.JwksURI)
	fmt.Println("\nAll checks passed. Run 'pam-device-auth --enable' to activate.")
}

func runEnable() {
	// Run check first
	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: config error: %v\n", err)
		os.Exit(1)
	}
	if strings.Contains(cfg.IssuerURL, "example.com") {
		fmt.Fprintf(os.Stderr, "FAIL: default config detected. Edit /etc/pam-device-auth/config.json first.\n")
		os.Exit(1)
	}

	// Test OIDC
	httpClient := &http.Client{Timeout: httpTimeout}
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	if _, err := discovery.Fetch(ctx, httpClient, cfg.IssuerURL); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: OIDC discovery failed: %v\n", err)
		os.Exit(1)
	}

	// Activate PAM config
	shareDir := "/usr/share/pam-device-auth/config"

	// Install sshd config if not present
	sshdConf := "/etc/ssh/sshd_config.d/10-pam-device-auth.conf"
	if _, err := os.Stat(sshdConf); os.IsNotExist(err) {
		src := shareDir + "/10-pam-device-auth.conf"
		data, err := os.ReadFile(src)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: cannot read %s: %v\n", src, err)
			os.Exit(1)
		}
		if err := os.WriteFile(sshdConf, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: cannot write %s: %v\n", sshdConf, err)
			os.Exit(1)
		}
		fmt.Println("Installed SSH config")
	}

	// Install PAM config (backup original)
	pamConf := "/etc/pam.d/sshd"
	pamBackup := "/etc/pam.d/sshd.original"
	pamSrc := shareDir + "/pam-sshd-device-auth"
	if _, err := os.Stat(pamBackup); os.IsNotExist(err) {
		// Backup current
		if data, err := os.ReadFile(pamConf); err == nil {
			os.WriteFile(pamBackup, data, 0644)
			fmt.Println("Backed up original PAM config")
		}
	}
	data, err := os.ReadFile(pamSrc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: cannot read %s: %v\n", pamSrc, err)
		os.Exit(1)
	}
	if err := os.WriteFile(pamConf, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: cannot write %s: %v\n", pamConf, err)
		os.Exit(1)
	}
	fmt.Println("PAM config activated")

	// Restart sshd
	cmd := exec.Command("systemctl", "restart", "ssh.service")
	if err := cmd.Run(); err != nil {
		cmd2 := exec.Command("systemctl", "restart", "sshd.service")
		if err := cmd2.Run(); err != nil {
			fmt.Println("WARNING: Could not restart SSH. Manual restart may be needed.")
		}
	}

	fmt.Println("\npam-device-auth is now active.")
	fmt.Println("Root: SSH key only (no OIDC)")
	fmt.Println("Other users: SSH key + OIDC Device Authorization")
}

func main() {
	debug := false
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--version":
			fmt.Printf("pam-device-auth %s\n", VERSION)
			os.Exit(0)
		case "--help":
			fmt.Println("Usage: pam-device-auth [--debug] [--version] [--check] [--enable] [--help]")
			fmt.Println("  SSH authentication via OIDC Device Authorization Grant (RFC 8628)")
			fmt.Println("")
			fmt.Println("  --check    Validate config and test OIDC connectivity")
			fmt.Println("  --enable   Activate PAM authentication (runs --check first)")
			fmt.Println("  --debug    Run with debug logging")
			fmt.Println("  --version  Show version")
			os.Exit(0)
		case "--check":
			runCheck()
			os.Exit(0)
		case "--enable":
			runEnable()
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

	log.Info("pam-device-auth %s starting", VERSION)

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

	// OIDC Discovery (fail-fast if OIDC provider unreachable)
	discoveryCtx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	endpoints, err := discovery.Fetch(discoveryCtx, httpClient, cfg.IssuerURL)
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

	result, err := token.Validate(tokenResp.AccessToken, keys, endpoints.Issuer, cfg.ClientID, cfg.RoleClaim)
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
		fmt.Println("Access denied.")
		return false
	}

	log.Info("Auth OK: user=%s email=%s roles=%v", result.Username, result.Email, result.Roles)

	// Save rotated refresh token
	if tokenResp.RefreshToken != "" {
		if err := cache.Save(sshUser, tokenResp.RefreshToken); err != nil {
			log.Debug("Cache save error: %v", err)
		}
	}

	if cfg.CreateUser {
		isAdmin := cfg.SudoRole == "" || token.HasRole(result.Roles, cfg.SudoRole)
		created, _, err := user.Setup(sshUser, cfg.UserGroups, cfg.AdminGroups, isAdmin, cfg.ForcePasswordChange, log)
		if err != nil {
			log.Error("User setup failed: %v", err)
			return false
		}
		if created {
			fmt.Printf("User %s created. Please reconnect.\n", sshUser)
			log.Info("First login: user %s created, session will close (sshd invalid-user constraint)", sshUser)
			return true
		}
	}

	fmt.Println("SSO session active.")
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
	if dc.VerificationURIComplete != "" {
		fmt.Printf("Link:  %s\n", dc.VerificationURIComplete)
		fmt.Printf("Code:  %s\n", dc.UserCode)
		fmt.Println()
		qrStr, err := qr.Render(dc.VerificationURIComplete)
		if err == nil {
			fmt.Print(qrStr)
		}
	} else {
		fmt.Printf("Open:  %s\n", dc.VerificationURI)
		fmt.Printf("Code:  %s\n", dc.UserCode)
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
		fmt.Println("Authentication failed.")
		os.Exit(1)
	}

	jwksCtx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	keys, err := token.FetchJWKS(jwksCtx, httpClient, endpoints.JwksURI)
	cancel()
	if err != nil {
		log.Error("JWKS fetch failed: %v", err)
		os.Exit(1)
	}

	result, err := token.Validate(tokenResp.AccessToken, keys, endpoints.Issuer, cfg.ClientID, cfg.RoleClaim)
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
		fmt.Println("Access denied.")
		os.Exit(1)
	}

	log.Info("Auth OK: user=%s email=%s roles=%v", result.Username, result.Email, result.Roles)

	// Cache refresh token for next login
	if tokenResp.RefreshToken != "" {
		if err := cache.Save(sshUser, tokenResp.RefreshToken); err != nil {
			log.Debug("Cache save error (non-fatal): %v", err)
		}
	}

	if cfg.CreateUser {
		isAdmin := cfg.SudoRole == "" || token.HasRole(result.Roles, cfg.SudoRole)
		created, _, err := user.Setup(sshUser, cfg.UserGroups, cfg.AdminGroups, isAdmin, cfg.ForcePasswordChange, log)
		if err != nil {
			log.Error("User setup failed: %v", err)
			os.Exit(1)
		}
		if created {
			fmt.Printf("Login successful! User %s created.\n", sshUser)
			fmt.Println("Disconnecting — please reconnect.")
		} else {
			fmt.Println("Login successful!")
		}
	} else {
		fmt.Println("Login successful!")
	}
}
