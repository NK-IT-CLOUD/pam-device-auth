package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/auth"
	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/config"
	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/logger"
	"git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth/internal/user"
)

const (
	VERSION  = "0.3.0"
	LOG_FILE = "/var/log/keycloak-ssh-auth.log"
)

func printHelp() {
	help := fmt.Sprintf(`Keycloak SSH Authentication v%s

Usage: keycloak-auth [OPTIONS]

Options:
  --version       Display version information
  --help          Display this help message
  --debug         Enable debug logging
  --mode <mode>   Authentication mode: "browser" (default) or "code"
                  browser: User clicks link in browser
                  code:    User sees code + link, auth via browser callback

Configuration:
  File: /etc/keycloak-ssh-auth/keycloak-pam.json
  
  Environment variables override config file:
    KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID,
    KEYCLOAK_CLIENT_SECRET, KEYCLOAK_REQUIRED_ROLE,
    CALLBACK_IP, CALLBACK_PORT, AUTH_TIMEOUT, DEBUG_MODE

Logs: %s

Repository: https://git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth
`, VERSION, LOG_FILE)

	fmt.Println(help)
}

// getClientIP retrieves the client IP from environment variables
func getClientIP() string {
	envVars := []string{"SSH_CONNECTION", "SSH_CLIENT", "PAM_RHOST", "REMOTE_ADDR"}

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

func main() {
	debugMode := false
	authMode := "browser"

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--version":
			fmt.Printf("Keycloak SSH Authentication v%s\n", VERSION)
			os.Exit(0)
		case "--help":
			printHelp()
			os.Exit(0)
		case "--debug":
			debugMode = true
		case "--mode":
			if i+1 < len(os.Args) {
				i++
				authMode = os.Args[i]
			}
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

	clientIP := getClientIP()
	if clientIP == "unknown" {
		log.Warn("Could not determine client IP address")
	}

	log.Info("Login attempt from IP: %s", clientIP)
	log.Info("Requested user account: %s", sshUser)
	log.Info("Auth mode: %s", authMode)

	// Load configuration
	cfg, err := config.LoadConfig("")
	if err != nil {
		log.Error("Failed to load configuration: %v", err)
		os.Exit(1)
	}

	log.Debug("Configuration loaded: %s", cfg.String())

	// Perform authentication
	if err := authenticate(log, cfg, sshUser, authMode); err != nil {
		log.Error("Authentication failed: %v", err)
		os.Exit(1)
	}

	log.LogPhase("LOGIN COMPLETED")
	log.Info("SSH authentication successful for user: %s", sshUser)
	os.Exit(0)
}

// authenticate performs the complete authentication flow
func authenticate(log *logger.Logger, cfg *config.Config, sshUser string, mode string) error {
	log.LogPhase("SSO AUTHENTICATION")

	keycloakAuth := auth.NewKeycloakAuth(cfg, log)

	var result *auth.AuthResult
	var err error

	ctx := context.Background()

	switch mode {
	case "code":
		result, err = keycloakAuth.AuthenticateWithCode(ctx, sshUser)
	default: // "browser"
		// Get auth URL first to display
		authURL, urlErr := keycloakAuth.GetAuthURL()
		if urlErr != nil {
			return fmt.Errorf("failed to generate auth URL: %v", urlErr)
		}
		fmt.Printf("\nSSO Login erforderlich!\nÖffne den folgenden Link:\n%s\n\n", authURL)
		log.Info("Authentication URL provided to user")

		result, err = keycloakAuth.Authenticate(ctx, sshUser)
	}

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

	// Setup user account
	if cfg.CreateUsers || cfg.AddToSudo {
		log.LogPhase("SYSTEM SETUP")

		userManager := user.NewManager(log)
		if err := userManager.SetupUser(result.Username, cfg.CreateUsers, cfg.AddToSudo); err != nil {
			return fmt.Errorf("user setup failed: %v", err)
		}
	}

	log.LogSummary("Login Summary", map[string]string{
		"User":           result.Username,
		"Name":           result.Name,
		"Email":          result.Email,
		"System Account": "Configured",
		"Sudo Access":    fmt.Sprintf("%v", cfg.AddToSudo),
	})

	return nil
}
