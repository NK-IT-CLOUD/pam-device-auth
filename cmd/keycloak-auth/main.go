package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"keycloak-ssh-auth/internal/auth"
	"keycloak-ssh-auth/internal/config"
	"keycloak-ssh-auth/internal/logger"
	"keycloak-ssh-auth/internal/user"
)

const (
	VERSION  = "0.2.6"
	LOG_FILE = "/var/log/keycloak-ssh-auth.log"
)

// printHelp displays usage information
func printHelp() {
	help := fmt.Sprintf(`Keycloak SSH Authentication v%s

Usage: keycloak-auth [OPTIONS]

Options:
  --version       Display version information
  --help          Display this help message
  --debug         Enable debug logging

Authentication Configuration:
  1. Edit /etc/keycloak-ssh-auth/keycloak-pam.json to configure:
     - Keycloak URL
     - Realm
     - Client ID
     - Client Secret
     - Required Role

  Configuration Example:
  {
    "keycloak_url": "https://your-keycloak.example.com",
    "realm": "your-realm",
    "client_id": "ssh-auth-client",
    "client_secret": "your-client-secret",
    "required_role": "ssh-access",
    "callback_ip": "YOUR_SERVER_IP",
    "callback_port": "33499"
  }

Environment Variables (override config file):
  KEYCLOAK_URL              Keycloak server URL
  KEYCLOAK_REALM            Keycloak realm name
  KEYCLOAK_CLIENT_ID        OAuth2 client ID
  KEYCLOAK_CLIENT_SECRET    OAuth2 client secret
  KEYCLOAK_REQUIRED_ROLE    Required role for SSH access
  CALLBACK_IP               Server IP for OAuth2 callback
  CALLBACK_PORT             Server port for OAuth2 callback
  AUTH_TIMEOUT              Authentication timeout in seconds
  DEBUG_MODE                Enable debug logging (true/false)

Troubleshooting:
  - Check logs: %s
  - Verify Keycloak connectivity
  - Ensure correct role assignments
  - Test configuration with --debug flag
`, VERSION, LOG_FILE)

	fmt.Println(help)
}

// getClientIP retrieves the client IP from environment variables
func getClientIP() string {
	envVars := []string{
		"SSH_CONNECTION", // Contains "client-ip client-port server-ip server-port"
		"SSH_CLIENT",     // Contains "client-ip client-port server-port"
		"PAM_RHOST",      // Should contain the remote host
		"REMOTE_ADDR",    // Fallback
	}

	for _, env := range envVars {
		if value := os.Getenv(env); value != "" {
			parts := strings.Fields(value)
			if len(parts) > 0 {
				if net.ParseIP(parts[0]) != nil {
					return parts[0]
				}
			}
		}
	}
	return "unknown"
}

// main is the entry point of the application
func main() {
	// Parse command line arguments
	debugMode := false
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--version":
			fmt.Printf("Keycloak SSH Authentication v%s\n", VERSION)
			os.Exit(0)
		case "--help":
			printHelp()
			os.Exit(0)
		case "--debug":
			debugMode = true
		}
	}

	// Initialize logger
	log, err := logger.NewLogger(LOG_FILE, debugMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	log.LogPhase("SSH LOGIN INITIATED")

	// Get SSH username
	sshUser := os.Getenv("PAM_USER")
	if sshUser == "" {
		log.Error("No SSH username provided (PAM_USER environment variable missing)")
		os.Exit(1)
	}

	// Get client IP
	clientIP := getClientIP()
	if clientIP == "unknown" {
		log.Warn("Could not determine client IP address")
	}

	log.Info("Login attempt from IP: %s", clientIP)
	log.Info("Requested user account: %s", sshUser)

	// Load configuration
	cfg, err := config.LoadConfig("")
	if err != nil {
		log.Error("Failed to load configuration: %v", err)
		os.Exit(1)
	}

	log.Debug("Configuration loaded: %s", cfg.String())

	// Perform authentication
	if err := authenticate(log, cfg, sshUser); err != nil {
		log.Error("Authentication failed: %v", err)
		os.Exit(1)
	}

	log.LogPhase("LOGIN COMPLETED")
	log.Info("SSH authentication successful for user: %s", sshUser)
	os.Exit(0)
}

// authenticate performs the complete authentication flow
func authenticate(log *logger.Logger, cfg *config.Config, sshUser string) error {
	log.LogPhase("SSO AUTHENTICATION")

	// Create Keycloak authenticator
	keycloakAuth := auth.NewKeycloakAuth(cfg, log)

	// Get authentication URL
	authURL, err := keycloakAuth.GetAuthURL()
	if err != nil {
		return fmt.Errorf("failed to generate auth URL: %v", err)
	}

	// Display authentication URL to user
	fmt.Printf("SSO Login erforderlich!\nOpen the following Link:\n%s\n", authURL)
	log.Info("Authentication URL provided to user")

	// Perform authentication with context
	ctx := context.Background()
	result, err := keycloakAuth.Authenticate(ctx, sshUser)
	if err != nil {
		return err
	}

	if !result.Success {
		return fmt.Errorf("authentication failed: %s", result.ErrorMessage)
	}

	log.LogPhase("USER VERIFICATION")
	log.LogSummary("SSO Identity Verification", map[string]string{
		"Username": result.Username,
		"Name":     result.Name,
		"Email":    result.Email,
		"Roles":    strings.Join(result.Roles, ", "),
	})

	// Setup user account if needed
	if cfg.CreateUsers || cfg.AddToSudo {
		log.LogPhase("SYSTEM SETUP")

		userManager := user.NewManager(log)
		if err := userManager.SetupUser(result.Username, cfg.CreateUsers, cfg.AddToSudo); err != nil {
			return fmt.Errorf("user setup failed: %v", err)
		}
	}

	// Log final summary
	log.LogSummary("Login Summary", map[string]string{
		"User":           result.Username,
		"Name":           result.Name,
		"Email":          result.Email,
		"System Account": "Configured",
		"Sudo Access":    fmt.Sprintf("%v", cfg.AddToSudo),
	})

	return nil
}
