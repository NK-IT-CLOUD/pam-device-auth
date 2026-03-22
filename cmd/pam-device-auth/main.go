package main

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/cache"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/device"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/discovery"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/logger"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/qr"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/token"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/user"
)

var VERSION = "0.3.3"

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
	sshRestarted := false
	cmd := exec.Command("systemctl", "restart", "ssh.service")
	if err := cmd.Run(); err != nil {
		cmd2 := exec.Command("systemctl", "restart", "sshd.service")
		if err := cmd2.Run(); err != nil {
			fmt.Println("WARNING: Could not restart SSH. Run: sudo systemctl restart ssh")
		} else {
			sshRestarted = true
		}
	} else {
		sshRestarted = true
	}
	if sshRestarted {
		fmt.Println("SSH service restarted")
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

	clientIP := os.Getenv("PAM_RHOST")
	if clientIP == "" {
		clientIP = "unknown"
	}

	log.Info("Authenticating user: %s from IP: %s", sshUser, clientIP)

	httpClient := &http.Client{Timeout: httpTimeout}

	// OIDC Discovery (fail-fast if OIDC provider unreachable)
	discoveryCtx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	endpoints, err := discovery.Fetch(discoveryCtx, httpClient, cfg.IssuerURL)
	cancel()
	if err != nil {
		log.Error("OIDC Discovery failed: %v", err)
		os.Exit(1)
	}
	// Verify discovery issuer matches configured issuer (MITM protection)
	if strings.TrimRight(endpoints.Issuer, "/") != cfg.IssuerURL {
		log.Error("OIDC issuer mismatch: discovery=%q config=%q", endpoints.Issuer, cfg.IssuerURL)
		os.Exit(1)
	}
	log.Debug("Discovery OK: device=%s", endpoints.DeviceAuthorizationEndpoint)

	// Try cached refresh token (known IP + password + OIDC refresh)
	authenticated, pwVerified := tryCachedRefresh(log, cfg, httpClient, endpoints, sshUser, clientIP)
	if authenticated {
		os.Exit(0)
	}

	// Full Device Auth flow (new IP, no cache, or refresh failed)
	deviceAuthFlow(log, cfg, httpClient, endpoints, sshUser, clientIP, pwVerified)
	os.Exit(0)
}

// shouldShowQR determines whether to render the QR code.
// Priority: config "show_qr" (explicit override) > auto-detect via SSH client version.
// Auto-detect skips QR for Win32-OpenSSH (broken Unicode in strnvis).
func shouldShowQR(cfg *config.Config) bool {
	// Explicit config override takes priority
	if cfg.ShowQR != nil {
		return *cfg.ShowQR
	}
	// Auto-detect: skip QR for Windows OpenSSH clients
	v := os.Getenv("SSH_CLIENT_VERSION")
	if strings.Contains(v, "Windows") {
		return false
	}
	return true
}

// getPasswordHash reads the user's password hash from /etc/shadow.
// Returns empty string if user not found, no hash, or shadow unreadable.
// Runs as root (PAM context), so /etc/shadow is readable.
func getPasswordHash(username string) string {
	data, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 || parts[0] != username {
			continue
		}
		return parts[1]
	}
	return ""
}

// hasPasswordHash returns true if the user has a usable (non-empty, non-locked) password hash.
func hasPasswordHash(username string) bool {
	hash := getPasswordHash(username)
	if hash == "" || hash == "*" || strings.HasPrefix(hash, "!") {
		return false
	}
	return true
}

// isAccountLocked checks if the user's shadow hash has a '!' prefix (locked by usermod --lock).
func isAccountLocked(username string) bool {
	hash := getPasswordHash(username)
	return strings.HasPrefix(hash, "!")
}

// checkPassword verifies the local Linux password using crypt_r(3) from libxcrypt.
// Reads the shadow hash directly (root context) and compares via crypt_r.
func checkPassword(username, password string) error {
	hash := getPasswordHash(username)
	if hash == "" {
		return fmt.Errorf("no password hash for user %s", username)
	}
	if !verifyCrypt(password, hash) {
		return fmt.Errorf("password mismatch for user %s", username)
	}
	return nil
}

// verifyPassword prompts for the local password via the PROMPT: protocol and verifies it.
// Exits the process on failure.
func verifyPassword(log *logger.Logger, sshUser string) {
	fmt.Println("PROMPT:Password: ")
	reader := bufio.NewReaderSize(os.Stdin, 512)
	password, err := reader.ReadString('\n')
	if err != nil {
		log.Error("Failed to read password input")
		fmt.Println("Authentication failed.")
		os.Exit(1)
	}
	password = strings.TrimRight(password, "\n\r")

	// Sanitize: reject null bytes and oversized passwords
	if strings.ContainsRune(password, 0) || len(password) > 512 || len(password) == 0 {
		log.Error("Invalid password input for user %s", sshUser)
		fmt.Println("Authentication failed.")
		os.Exit(1)
	}

	if err := checkPassword(sshUser, password); err != nil {
		log.Error("Password verification failed for user %s", sshUser)
		fmt.Println("Authentication failed.")
		os.Exit(1)
	}
	log.Info("Password verified for user %s", sshUser)
}

// tryCachedRefresh attempts to use a cached refresh token from a known IP.
// Returns (authenticated, passwordVerified).
// Locks the account and exits on explicit OIDC access denial.
func tryCachedRefresh(log *logger.Logger, cfg *config.Config, httpClient *http.Client, endpoints *discovery.Endpoints, sshUser, clientIP string) (bool, bool) {
	session, err := cache.Load(sshUser)
	if err != nil {
		log.Debug("Cache load error: %v", err)
		return false, false
	}
	if session == nil {
		return false, false
	}

	log.Info("Cached session found for user: %s", sshUser)

	// Require known IP for cached path — new IPs must go through device auth
	if !session.HasIP(clientIP) {
		log.Info("New IP %s for user %s, requiring device auth", clientIP, sshUser)
		return false, false
	}

	// Known IP — verify local password
	if !hasPasswordHash(sshUser) {
		log.Info("User %s has no password hash in shadow, requiring device auth", sshUser)
		return false, false
	}

	verifyPassword(log, sshUser)

	// Refresh token to verify user still exists + has required role in OIDC
	refreshCtx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	tokenResp, err := device.RefreshToken(refreshCtx, httpClient, endpoints.TokenEndpoint, cfg.ClientID, session.RefreshToken)
	cancel()
	if err != nil {
		log.Info("Token refresh failed: %v", err)
		cache.Delete(sshUser)
		log.Info("Cache cleared, starting Device Auth")
		return false, true // password verified, OIDC transient failure
	}
	log.Info("Token refresh successful")

	// Validate the new access token
	jwksCtx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	keys, err := token.FetchJWKS(jwksCtx, httpClient, endpoints.JwksURI)
	cancel()
	if err != nil {
		log.Info("JWKS fetch failed after refresh: %v", err)
		cache.Delete(sshUser)
		return false, true
	}

	result, err := token.Validate(tokenResp.AccessToken, keys, endpoints.Issuer, cfg.ClientID, cfg.RoleClaim)
	if err != nil {
		log.Info("Token validation failed after refresh: %v", err)
		cache.Delete(sshUser)
		return false, true
	}

	if result.Username != sshUser {
		log.Error("Username mismatch: token=%q ssh=%q", result.Username, sshUser)
		cache.Delete(sshUser)
		return false, true
	}

	// Explicit OIDC denial: user lost required role — lock account
	if !token.HasRole(result.Roles, cfg.RequiredRole) {
		log.Error("User %s lacks required role %s — locking account", sshUser, cfg.RequiredRole)
		user.Lock(sshUser, log)
		cache.Delete(sshUser)
		fmt.Println("Access denied.")
		os.Exit(1)
		return false, true // unreachable
	}

	log.Info("Auth OK: user=%s email=%s roles=%v", result.Username, result.Email, result.Roles)

	// Save rotated refresh token (preserves KnownIPs)
	if tokenResp.RefreshToken != "" {
		session.RefreshToken = tokenResp.RefreshToken
		if err := cache.Save(session); err != nil {
			log.Debug("Cache save error: %v", err)
		}
	}

	if cfg.CreateUser {
		isAdmin := cfg.SudoRole == "" || token.HasRole(result.Roles, cfg.SudoRole)
		created, _, err := user.Setup(sshUser, cfg.UserGroups, cfg.AdminGroups, isAdmin, cfg.ForcePasswordChange, log)
		if err != nil {
			log.Error("User setup failed: %v", err)
			return false, true
		}
		if created {
			fmt.Printf("User %s created. Please reconnect.\n", sshUser)
			log.Info("First login: user %s created, session will close (sshd invalid-user constraint)", sshUser)
			return true, true
		}
	}

	fmt.Println("------------------------------------")
	fmt.Println("Access granted -- password verified, SSO session active.")
	fmt.Println("------------------------------------")
	return true, true
}

// deviceAuthFlow runs the full Device Authorization Grant flow.
// Required for new IPs, first-time logins, or when cached refresh fails.
func deviceAuthFlow(log *logger.Logger, cfg *config.Config, httpClient *http.Client, endpoints *discovery.Endpoints, sshUser, clientIP string, passwordVerified bool) {
	requestCtx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	dc, err := device.RequestCode(requestCtx, httpClient, endpoints.DeviceAuthorizationEndpoint, cfg.ClientID)
	cancel()
	if err != nil {
		log.Error("Device code request failed: %v", err)
		os.Exit(1)
	}

	// Print to stdout — PAM pipes to SSH terminal
	fmt.Println("------------------------------------")
	if dc.VerificationURIComplete != "" {
		fmt.Printf("Link:  %s\n", dc.VerificationURIComplete)
		fmt.Printf("Code:  %s\n", dc.UserCode)
		if shouldShowQR(cfg) {
			fmt.Println()
			qrStr, err := qr.Render(dc.VerificationURIComplete)
			if err == nil {
				fmt.Print(qrStr)
			}
		}
	} else {
		fmt.Printf("Open:  %s\n", dc.VerificationURI)
		fmt.Printf("Code:  %s\n", dc.UserCode)
	}
	fmt.Println("------------------------------------")

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
		fmt.Println("------------------------------------")
		fmt.Printf("Error: authorized as '%s', but SSH user is '%s'.\n", result.Username, sshUser)
		fmt.Println("You must authorize with the matching account.")
		fmt.Println("------------------------------------")
		os.Exit(1)
	}

	if !token.HasRole(result.Roles, cfg.RequiredRole) {
		log.Error("User %s lacks required role: %s", sshUser, cfg.RequiredRole)
		fmt.Println("------------------------------------")
		fmt.Printf("Access denied: '%s' lacks required role '%s'.\n", result.Username, cfg.RequiredRole)
		fmt.Println("Contact your administrator.")
		fmt.Println("------------------------------------")
		os.Exit(1)
	}

	log.Info("Auth OK: user=%s email=%s roles=%v", result.Username, result.Email, result.Roles)

	// Unlock account if it was locked due to prior OIDC revocation
	if isAccountLocked(sshUser) {
		user.Unlock(sshUser, log)
	}

	// Save cache with IP
	session, _ := cache.Load(sshUser)
	if session == nil {
		session = &cache.CachedSession{Username: sshUser}
	}
	if tokenResp.RefreshToken != "" {
		session.RefreshToken = tokenResp.RefreshToken
	}
	session.AddIP(clientIP)
	if err := cache.Save(session); err != nil {
		log.Debug("Cache save error (non-fatal): %v", err)
	}

	created := false
	tempPassword := ""
	if cfg.CreateUser {
		isAdmin := cfg.SudoRole == "" || token.HasRole(result.Roles, cfg.SudoRole)
		var err error
		created, tempPassword, err = user.Setup(sshUser, cfg.UserGroups, cfg.AdminGroups, isAdmin, cfg.ForcePasswordChange, log)
		if err != nil {
			log.Error("User setup failed: %v", err)
			os.Exit(1)
		}
	}

	// Verify local password for existing users (skip if already verified or new user)
	if !created && !passwordVerified && hasPasswordHash(sshUser) {
		verifyPassword(log, sshUser)
	}

	if created {
		fmt.Printf("Login successful! User %s created.\n", sshUser)
		if tempPassword != "" {
			fmt.Println("------------------------------------")
			fmt.Printf("Temporary password: %s\n", tempPassword)
			fmt.Println("Use this on your next login.")
			fmt.Println("You will be asked to set a new password.")
			fmt.Println("------------------------------------")
		}
		fmt.Println("Disconnecting -- please reconnect.")
	} else {
		fmt.Println("Login successful!")
	}
}
