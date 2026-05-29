package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/discovery"
	"github.com/NK-IT-CLOUD/pam-device-auth/internal/logger"
)

var VERSION = "0.5.0"

const (
	logFile     = "/var/log/pam-device-auth.log"
	httpTimeout = 10 * time.Second
)

// newOIDCClient builds an http.Client hardened for OIDC/JWKS traffic: short
// timeout and blocked redirects. All endpoints are either scheme-validated
// at discovery or derived from that document, so legitimate redirects never
// occur; following them would open downgrade/hijack paths on a MITM.
func newOIDCClient() *http.Client {
	return &http.Client{
		Timeout: httpTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

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
	httpClient := newOIDCClient()
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
	if isEnabled() {
		fmt.Println("\nAll checks passed. pam-device-auth is already active (pam_device_auth.so in /etc/pam.d/sshd).")
	} else {
		fmt.Println("\nAll checks passed. Run 'pam-device-auth --enable' to activate.")
	}
}

// isEnabled reports whether pam-device-auth is already wired into SSH auth,
// i.e. --enable has installed pam_device_auth.so into /etc/pam.d/sshd.
func isEnabled() bool {
	data, err := os.ReadFile("/etc/pam.d/sshd")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "pam_device_auth.so")
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
	httpClient := newOIDCClient()
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	if _, err := discovery.Fetch(ctx, httpClient, cfg.IssuerURL); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: OIDC discovery failed: %v\n", err)
		os.Exit(1)
	}

	if isEnabled() {
		fmt.Println("Note: pam-device-auth is already active — re-applying config and restarting sshd.")
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
			fmt.Println("Usage: pam-device-auth [--debug] [--version] [--check] [--setup-ldap] [--enable] [--help]")
			fmt.Println("  SSH authentication via OIDC Device Authorization Grant (RFC 8628)")
			fmt.Println("")
			fmt.Println("  --check       Validate config and test OIDC connectivity")
			fmt.Println("  --setup-ldap  Configure SSSD/LLDAP directory identity from config (NSS + sudo)")
			fmt.Println("  --enable      Activate PAM authentication (runs --check first)")
			fmt.Println("  --debug       Run with debug logging")
			fmt.Println("  --version     Show version")
			os.Exit(0)
		case "--check":
			runCheck()
			os.Exit(0)
		case "--setup-ldap":
			runSetupLDAP()
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

	httpClient := newOIDCClient()

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

	// Identity, groups, home and the sudo password come from the directory
	// (LLDAP via SSSD/NSS). pam-device-auth is only the OIDC SSH-login layer:
	// it validates the OIDC token (signature/issuer/client/exp/iat, required
	// role, optional IP allowlist) and grants or denies the login. It never
	// reads /etc/shadow, prompts for a local password, or manages users.
	directoryAuthFlow(log, cfg, httpClient, endpoints, sshUser, clientIP)
	os.Exit(0)
}

// canRenderQR checks if the URL would produce a QR code small enough to scan.
// Returns false if the URL would require QR version > 5 (84 bytes at ECC M).
func canRenderQR(url string) bool {
	return len(url) <= 84
}

// matchesAllowedIP checks if clientIP is in the OIDC-provided IP allowlist.
// Supports both plain IPs ("10.0.20.2") and CIDR notation ("10.0.0.0/24").
func matchesAllowedIP(clientIP string, allowed []string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	for _, entry := range allowed {
		if strings.Contains(entry, "/") {
			_, network, err := net.ParseCIDR(entry)
			if err != nil {
				continue
			}
			if network.Contains(ip) {
				return true
			}
		} else {
			if entry == clientIP {
				return true
			}
		}
	}
	return false
}
