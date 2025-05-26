package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Config holds the configuration settings for Keycloak authentication
type Config struct {
	KeycloakURL   string `json:"keycloak_url"`
	Realm         string `json:"realm"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	RequiredRole  string `json:"required_role"`
	CallbackIP    string `json:"callback_ip"`
	CallbackPort  string `json:"callback_port"`
	
	// Optional settings with defaults
	AuthTimeout   int  `json:"auth_timeout,omitempty"`   // in seconds, default 180
	DebugMode     bool `json:"debug_mode,omitempty"`     // default false
	CreateUsers   bool `json:"create_users,omitempty"`   // default true
	AddToSudo     bool `json:"add_to_sudo,omitempty"`    // default true
}

// DefaultConfig returns a config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		AuthTimeout: 180, // 3 minutes
		DebugMode:   false,
		CreateUsers: true,
		AddToSudo:   true,
	}
}

// LoadConfig reads and parses the configuration file
func LoadConfig(configPath string) (*Config, error) {
	config := DefaultConfig()
	
	// Try to read from file first
	if configPath == "" {
		configPath = "/etc/keycloak-ssh-auth/keycloak-pam.json"
	}
	
	file, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("could not read config file %s: %v", configPath, err)
	}

	if err := json.Unmarshal(file, config); err != nil {
		return nil, fmt.Errorf("could not parse config file: %v", err)
	}

	// Override with environment variables if present
	config.loadFromEnvironment()

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	return config, nil
}

// loadFromEnvironment overrides config values with environment variables
func (c *Config) loadFromEnvironment() {
	if val := os.Getenv("KEYCLOAK_URL"); val != "" {
		c.KeycloakURL = val
	}
	if val := os.Getenv("KEYCLOAK_REALM"); val != "" {
		c.Realm = val
	}
	if val := os.Getenv("KEYCLOAK_CLIENT_ID"); val != "" {
		c.ClientID = val
	}
	if val := os.Getenv("KEYCLOAK_CLIENT_SECRET"); val != "" {
		c.ClientSecret = val
	}
	if val := os.Getenv("KEYCLOAK_REQUIRED_ROLE"); val != "" {
		c.RequiredRole = val
	}
	if val := os.Getenv("CALLBACK_IP"); val != "" {
		c.CallbackIP = val
	}
	if val := os.Getenv("CALLBACK_PORT"); val != "" {
		c.CallbackPort = val
	}
	if val := os.Getenv("AUTH_TIMEOUT"); val != "" {
		if timeout, err := strconv.Atoi(val); err == nil {
			c.AuthTimeout = timeout
		}
	}
	if val := os.Getenv("DEBUG_MODE"); val != "" {
		c.DebugMode = strings.ToLower(val) == "true"
	}
	if val := os.Getenv("CREATE_USERS"); val != "" {
		c.CreateUsers = strings.ToLower(val) == "true"
	}
	if val := os.Getenv("ADD_TO_SUDO"); val != "" {
		c.AddToSudo = strings.ToLower(val) == "true"
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.KeycloakURL == "" {
		return fmt.Errorf("keycloak_url is required")
	}
	
	// Validate URL format
	if _, err := url.Parse(c.KeycloakURL); err != nil {
		return fmt.Errorf("invalid keycloak_url: %v", err)
	}
	
	if c.Realm == "" {
		return fmt.Errorf("realm is required")
	}
	
	if c.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	
	if c.ClientSecret == "" {
		return fmt.Errorf("client_secret is required")
	}
	
	if c.RequiredRole == "" {
		return fmt.Errorf("required_role is required")
	}
	
	if c.CallbackIP == "" {
		return fmt.Errorf("callback_ip is required")
	}
	
	if c.CallbackPort == "" {
		return fmt.Errorf("callback_port is required")
	}
	
	// Validate port number
	if port, err := strconv.Atoi(c.CallbackPort); err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid callback_port: must be between 1 and 65535")
	}
	
	// Validate timeout
	if c.AuthTimeout < 30 || c.AuthTimeout > 600 {
		return fmt.Errorf("auth_timeout must be between 30 and 600 seconds")
	}
	
	return nil
}

// GetCallbackURL returns the full callback URL
func (c *Config) GetCallbackURL() string {
	return fmt.Sprintf("http://%s:%s/callback", c.CallbackIP, c.CallbackPort)
}

// GetKeycloakAuthURL returns the Keycloak authentication endpoint URL
func (c *Config) GetKeycloakAuthURL() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth", c.KeycloakURL, c.Realm)
}

// GetKeycloakTokenURL returns the Keycloak token endpoint URL
func (c *Config) GetKeycloakTokenURL() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.KeycloakURL, c.Realm)
}

// String returns a string representation of the config (without sensitive data)
func (c *Config) String() string {
	return fmt.Sprintf("Config{KeycloakURL: %s, Realm: %s, ClientID: %s, RequiredRole: %s, CallbackIP: %s, CallbackPort: %s}",
		c.KeycloakURL, c.Realm, c.ClientID, c.RequiredRole, c.CallbackIP, c.CallbackPort)
}
