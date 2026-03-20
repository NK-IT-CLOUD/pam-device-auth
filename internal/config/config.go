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
	IssuerURL           string   `json:"issuer_url"`
	ClientID            string   `json:"client_id"`
	RequiredRole        string   `json:"required_role"`
	RoleClaim           string   `json:"role_claim"`
	AuthTimeout         int      `json:"auth_timeout"`
	CreateUser          bool     `json:"create_user"`
	UserGroups          []string `json:"user_groups"`
	ForcePasswordChange bool     `json:"force_password_change"`
}

func DefaultConfig() *Config {
	return &Config{
		AuthTimeout:         180,
		CreateUser:          true,
		UserGroups:          []string{"sudo"},
		ForcePasswordChange: true,
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

	cfg.loadFromEnvironment()
	cfg.IssuerURL = strings.TrimRight(cfg.IssuerURL, "/")

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) loadFromEnvironment() {
	if v := os.Getenv("PAM_DEVICE_AUTH_ISSUER"); v != "" {
		c.IssuerURL = v
	}
	if v := os.Getenv("PAM_DEVICE_AUTH_CLIENT_ID"); v != "" {
		c.ClientID = v
	}
	if v := os.Getenv("PAM_DEVICE_AUTH_REQUIRED_ROLE"); v != "" {
		c.RequiredRole = v
	}
	if v := os.Getenv("PAM_DEVICE_AUTH_ROLE_CLAIM"); v != "" {
		c.RoleClaim = v
	}
	if v := os.Getenv("PAM_DEVICE_AUTH_TIMEOUT"); v != "" {
		if timeout, err := strconv.Atoi(v); err == nil {
			c.AuthTimeout = timeout
		}
	}
}

func (c *Config) Validate() error {
	if c.IssuerURL == "" {
		return fmt.Errorf("issuer_url is required")
	}
	if _, err := url.Parse(c.IssuerURL); err != nil {
		return fmt.Errorf("invalid issuer_url: %w", err)
	}
	if c.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	if c.RequiredRole == "" {
		return fmt.Errorf("required_role is required")
	}
	if c.AuthTimeout < 30 || c.AuthTimeout > 600 {
		return fmt.Errorf("auth_timeout must be between 30 and 600 seconds, got %d", c.AuthTimeout)
	}
	return nil
}
