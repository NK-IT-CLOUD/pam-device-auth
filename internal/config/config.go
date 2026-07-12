package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const DefaultConfigPath = "/etc/pam-device-auth/config.json"

type Config struct {
	IssuerURL    string `json:"issuer_url"`
	ClientID     string `json:"client_id"`
	RequiredRole string `json:"required_role"`
	SudoRole     string `json:"sudo_role"`
	RoleClaim    string `json:"role_claim"`
	AuthTimeout  int    `json:"auth_timeout"`
	ShowQR       *bool  `json:"show_qr,omitempty"`
	IPClaim      string `json:"ip_claim,omitempty"`
	// AllowedAlgorithms constrains acceptable JWT `alg` header values.
	// nil or empty = accept any supported algorithm (RS256/384/512 +
	// ES256/384/512). Operators should pin this to their IdP's actual
	// signing algorithm (e.g. ["RS256"] for Keycloak defaults) to close
	// the algorithm-confusion window on a poisoned JWKS response.
	AllowedAlgorithms []string `json:"allowed_algorithms,omitempty"`
	// LDAP holds the directory settings consumed ONLY by `--setup-ldap` to write
	// /etc/sssd/sssd.conf. It is not used by the auth runtime (SSSD owns the
	// bind), so it may be absent in the deployed runtime config.
	LDAP *LDAPConfig `json:"ldap,omitempty"`
}

// LDAPConfig is the directory wiring for the SSSD setup wizard. The bind
// password is needed only at setup time; it ends up in /etc/sssd/sssd.conf
// (0600) which SSSD reads at runtime.
type LDAPConfig struct {
	URI             string `json:"uri"`
	BaseDN          string `json:"base_dn"`
	BindDN          string `json:"bind_dn"`
	BindPassword    string `json:"bind_password"`
	AccessGroup     string `json:"access_group"` // ssh-access — login gate
	AdminGroup      string `json:"admin_group"`  // ssh-admin — sudo
	UserSearchBase  string `json:"user_search_base,omitempty"`
	GroupSearchBase string `json:"group_search_base,omitempty"`
	// ServiceAccountGroups are LLDAP groups whose members authenticate SSH with
	// a directory key ONLY (no OIDC) — for automation/management accounts. Empty
	// ⇒ no service tier (all non-root require OIDC, as before).
	ServiceAccountGroups []string `json:"service_account_groups,omitempty"`
	// NopasswdSudoGroups are LLDAP groups granted passwordless sudo (NOPASSWD:ALL).
	// Opt-in and admin-declared; empty ⇒ only admin_group gets (password) sudo.
	NopasswdSudoGroups []string `json:"nopasswd_sudo_groups,omitempty"`
}

func DefaultConfig() *Config {
	return &Config{
		AuthTimeout: 180,
		// ShowQR: nil = auto-detect (skip for Win32-OpenSSH, show for others)
	}
}

func Load(configPath string) (*Config, error) {
	if configPath == "" {
		configPath = DefaultConfigPath
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.loadFromEnvironment(); err != nil {
		return nil, err
	}
	cfg.IssuerURL = strings.TrimRight(cfg.IssuerURL, "/")

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) loadFromEnvironment() error {
	if v := os.Getenv("PAM_DEVICE_AUTH_ISSUER"); v != "" {
		c.IssuerURL = v
	}
	if v := os.Getenv("PAM_DEVICE_AUTH_CLIENT_ID"); v != "" {
		c.ClientID = v
	}
	if v := os.Getenv("PAM_DEVICE_AUTH_REQUIRED_ROLE"); v != "" {
		c.RequiredRole = v
	}
	if v := os.Getenv("PAM_DEVICE_AUTH_SUDO_ROLE"); v != "" {
		c.SudoRole = v
	}
	if v := os.Getenv("PAM_DEVICE_AUTH_ROLE_CLAIM"); v != "" {
		c.RoleClaim = v
	}
	if v := os.Getenv("PAM_DEVICE_AUTH_IP_CLAIM"); v != "" {
		c.IPClaim = v
	}
	if v := os.Getenv("PAM_DEVICE_AUTH_TIMEOUT"); v != "" {
		// Fail closed: the env var is an explicit operator override — silently
		// falling back to the JSON value would hide the misconfiguration.
		timeout, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("PAM_DEVICE_AUTH_TIMEOUT=%q is not a number", v)
		}
		c.AuthTimeout = timeout
	}
	return nil
}

func (c *Config) Validate() error {
	if c.IssuerURL == "" {
		return fmt.Errorf("issuer_url is required")
	}
	u, err := url.Parse(c.IssuerURL)
	if err != nil {
		return fmt.Errorf("invalid issuer_url: %w", err)
	}
	if u.Scheme != "https" {
		host := u.Hostname()
		if u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
			// Allow http on loopback for development
		} else {
			return fmt.Errorf("issuer_url must use https:// scheme, got %s://", u.Scheme)
		}
	}
	if c.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	if c.RequiredRole == "" {
		return fmt.Errorf("required_role is required")
	}
	// Upper bound 240 leaves 60s headroom below the C wrapper's
	// AUTH_TOTAL_TIMEOUT_S=300 SIGKILL in pam_device_auth.c, which must cover
	// child startup, PAM conversation round-trips, and process reap.
	if c.AuthTimeout < 30 || c.AuthTimeout > 240 {
		return fmt.Errorf("auth_timeout must be between 30 and 240 seconds, got %d", c.AuthTimeout)
	}
	return nil
}
