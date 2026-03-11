package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
)

const DefaultConfigPath = "/etc/keycloak-ssh-auth/keycloak-pam.json"

type Config struct {
	KeycloakURL  string `json:"keycloak_url"`
	Realm        string `json:"realm"`
	ClientID     string `json:"client_id"`
	RequiredRole string `json:"required_role"`
	AuthTimeout  int    `json:"auth_timeout"`
}

func DefaultConfig() *Config {
	return &Config{
		AuthTimeout: 180,
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

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) loadFromEnvironment() {
	if v := os.Getenv("KEYCLOAK_URL"); v != "" {
		c.KeycloakURL = v
	}
	if v := os.Getenv("KEYCLOAK_REALM"); v != "" {
		c.Realm = v
	}
	if v := os.Getenv("KEYCLOAK_CLIENT_ID"); v != "" {
		c.ClientID = v
	}
	if v := os.Getenv("KEYCLOAK_REQUIRED_ROLE"); v != "" {
		c.RequiredRole = v
	}
	if v := os.Getenv("KEYCLOAK_AUTH_TIMEOUT"); v != "" {
		if timeout, err := strconv.Atoi(v); err == nil {
			c.AuthTimeout = timeout
		}
	}
}

func (c *Config) Validate() error {
	if c.KeycloakURL == "" {
		return fmt.Errorf("keycloak_url is required")
	}
	if _, err := url.Parse(c.KeycloakURL); err != nil {
		return fmt.Errorf("invalid keycloak_url: %w", err)
	}
	if c.Realm == "" {
		return fmt.Errorf("realm is required")
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
