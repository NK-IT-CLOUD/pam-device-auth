package main

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/cache"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/device"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/discovery"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/logger"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/qr"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/sshclient"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/token"
)

// directoryAuthFlow is the auth path for hosts where identity comes from the
// directory (LLDAP via SSSD/NSS). pam-device-auth here is ONLY the extra OIDC
// SSH-login layer: it validates an OIDC token (signature/issuer/client/exp/iat,
// required_role, optional IP allowlist) for the SSH user, then grants or denies
// the login. It NEVER reads /etc/shadow, never prompts for a local password,
// and never creates users or manages groups — SSSD/LLDAP own identity, groups,
// home dir, and the sudo password (pam_sss).
func directoryAuthFlow(log *logger.Logger, cfg *config.Config, httpClient *http.Client, endpoints *discovery.Endpoints, sshUser, clientIP string) {
	if tryCachedDirectory(log, cfg, httpClient, endpoints, sshUser, clientIP) {
		return
	}
	deviceDirectory(log, cfg, httpClient, endpoints, sshUser, clientIP)
	// Success falls through; main() owns the single os.Exit(0). Hard-deny/error
	// paths inside the two flows terminate directly via os.Exit(2)/os.Exit(1).
}

// tryCachedDirectory uses a cached refresh token for a known IP to re-validate
// with the IdP without a browser round-trip. Returns true on success. A soft
// failure (network, expired refresh) returns false to fall back to the device
// flow; a genuine access denial on a known IP (role revoked, IP removed) is a
// hard deny (exit 2) — no point re-prompting.
func tryCachedDirectory(log *logger.Logger, cfg *config.Config, httpClient *http.Client, endpoints *discovery.Endpoints, sshUser, clientIP string) bool {
	session, err := cache.Load(sshUser)
	if err != nil || session == nil {
		return false
	}
	if clientIP == "unknown" || !session.HasIP(clientIP) {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	tokenResp, err := device.RefreshToken(ctx, httpClient, endpoints.TokenEndpoint, cfg.ClientID, session.RefreshToken)
	cancel()
	if err != nil {
		log.Warn("Directory: token refresh failed (cache cleared, device auth): %v", err)
		cache.Delete(sshUser)
		return false
	}

	result, err := validateDirectoryToken(httpClient, endpoints, cfg, tokenResp.AccessToken, sshUser)
	if err != nil {
		log.Warn("Directory: validation failed after refresh (cache cleared, device auth): %v", err)
		cache.Delete(sshUser)
		return false
	}

	if reason := checkDirectoryAccess(result, clientIP, cfg); reason != "" {
		log.Error("Directory: access revoked for %s on known IP %s: %s", sshUser, clientIP, reason)
		cache.Delete(sshUser)
		denyBanner(reason)
		os.Exit(2)
	}

	log.Info("Directory auth OK (cached): user=%s roles=%v", result.Username, result.Roles)
	if tokenResp.RefreshToken != "" {
		session.RefreshToken = tokenResp.RefreshToken
		if err := cache.Save(session); err != nil {
			log.Debug("Cache save error: %v", err)
		}
	}
	return true
}

// deviceDirectory runs the full device-grant flow and grants or denies login.
func deviceDirectory(log *logger.Logger, cfg *config.Config, httpClient *http.Client, endpoints *discovery.Endpoints, sshUser, clientIP string) {
	reqCtx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	dc, err := device.RequestCode(reqCtx, httpClient, endpoints.DeviceAuthorizationEndpoint, cfg.ClientID)
	cancel()
	if err != nil {
		log.Error("Device code request failed: %v", err)
		fmt.Println("Authentication failed.")
		os.Exit(1)
	}

	fmt.Println("------------------------------------")
	if dc.VerificationURIComplete != "" {
		fmt.Printf("Link:  %s\n", dc.VerificationURIComplete)
		fmt.Printf("Code:  %s\n", dc.UserCode)
		if sshclient.ShouldShowQR(cfg.ShowQR) && canRenderQR(dc.VerificationURIComplete) {
			fmt.Println()
			if qrStr, err := qr.Render(dc.VerificationURIComplete); err == nil {
				fmt.Print(qrStr)
			}
		}
	} else {
		fmt.Printf("Open:  %s\n", dc.VerificationURI)
		fmt.Printf("Code:  %s\n", dc.UserCode)
	}
	fmt.Println("------------------------------------")
	fmt.Println("FLUSH:Authorize in browser, then press Enter... ")
	bufio.NewReaderSize(os.Stdin, 64).ReadString('\n')

	timeout := cfg.AuthTimeout
	if dc.ExpiresIn > 0 && dc.ExpiresIn < timeout {
		timeout = dc.ExpiresIn
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	log.Info("Directory: waiting for authorization (timeout: %ds)", timeout)
	tokenResp, err := device.PollToken(ctx, httpClient, endpoints.TokenEndpoint, cfg.ClientID, dc.DeviceCode, dc.Interval)
	if err != nil {
		log.Error("Token polling failed: %v", err)
		fmt.Println("Authentication failed.")
		os.Exit(1)
	}

	result, err := validateDirectoryToken(httpClient, endpoints, cfg, tokenResp.AccessToken, sshUser)
	if err != nil {
		log.Error("Token validation failed: %v", err)
		fmt.Println("Authentication failed.")
		os.Exit(1)
	}

	if reason := checkDirectoryAccess(result, clientIP, cfg); reason != "" {
		log.Error("Directory: access denied for %s: %s", sshUser, reason)
		denyBanner(reason)
		os.Exit(2)
	}

	log.Info("Directory auth OK: user=%s email=%s roles=%v", result.Username, result.Email, result.Roles)

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
}

// validateDirectoryToken fetches JWKS, validates the token (signature, issuer,
// client binding, exp/iat, allowed algorithms), and confirms the token subject
// matches the SSH user. Policy (role/IP) is checked separately by
// checkDirectoryAccess so callers can distinguish "bad token" from "denied".
func validateDirectoryToken(httpClient *http.Client, endpoints *discovery.Endpoints, cfg *config.Config, accessToken, sshUser string) (*token.TokenResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	keys, err := token.FetchJWKS(ctx, httpClient, endpoints.JwksURI)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("JWKS fetch: %w", err)
	}

	result, err := token.Validate(accessToken, keys, endpoints.Issuer, cfg.ClientID, cfg.RoleClaim, cfg.IPClaim, cfg.AllowedAlgorithms)
	if err != nil {
		return nil, err
	}
	if result.Username != sshUser {
		return nil, fmt.Errorf("username mismatch: token=%q ssh=%q", result.Username, sshUser)
	}
	return result, nil
}

// checkDirectoryAccess applies the policy gates (OIDC IP allowlist + required
// role). Returns "" when access is allowed, or a human-readable denial reason.
func checkDirectoryAccess(result *token.TokenResult, clientIP string, cfg *config.Config) string {
	if result.AllowedIPs != nil && !matchesAllowedIP(clientIP, result.AllowedIPs) {
		return fmt.Sprintf("Access denied: IP '%s' not authorized.", clientIP)
	}
	if !token.HasRole(result.Roles, cfg.RequiredRole) {
		return fmt.Sprintf("Access denied: '%s' lacks required role '%s'.", result.Username, cfg.RequiredRole)
	}
	return ""
}

// denyBanner prints a standard hard-deny message to the SSH client and waits
// for Enter (the FLUSH triggers OpenSSH to display batched info lines).
func denyBanner(reason string) {
	fmt.Println("------------------------------------")
	fmt.Println(reason)
	fmt.Println("Contact your administrator.")
	fmt.Println("------------------------------------")
	fmt.Println("FLUSH:Press Enter to disconnect... ")
	bufio.NewReaderSize(os.Stdin, 64).ReadString('\n')
}
