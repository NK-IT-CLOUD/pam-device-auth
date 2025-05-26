#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdarg.h>

#define KEYCLOAK_AUTH_BIN "/usr/local/bin/keycloak-auth"
#define BUFFER_SIZE 4096
#define LOG_FILE "/var/log/keycloak-ssh-auth.log"
#define PAM_LOG_PREFIX "[PAM] "

// Helper function for logging
void log_message(int priority, const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    // Prepare message
    char full_message[1024];
    vsnprintf(full_message, sizeof(full_message), format, args);
    
    // Get current time
    time_t now;
    time(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y/%m/%d %H:%M:%S", localtime(&now));
    
    // Write to file with consistent format
    FILE *f = fopen(LOG_FILE, "a");
    if (f != NULL) {
        fprintf(f, "%s%s %s\n", PAM_LOG_PREFIX, timestamp, full_message);
        fclose(f);
    }
    
    // Also write to syslog for system logging
    syslog(priority, "%s", full_message);
    
    va_end(args);
}

// Function to extract IP address from various sources
const char* get_client_ip(pam_handle_t *pamh) {
    static char ip_str[INET6_ADDRSTRLEN] = "unknown";
    const char *rhost = NULL;

    // Check PAM_RHOST first
    if (pam_get_item(pamh, PAM_RHOST, (const void **)&rhost) == PAM_SUCCESS && rhost) {
        strncpy(ip_str, rhost, sizeof(ip_str) - 1);
        return ip_str;
    }

    // Check SSH_CONNECTION environment variable
    const char *ssh_conn = getenv("SSH_CONNECTION");
    if (ssh_conn) {
        char *token = strtok((char *)ssh_conn, " ");
        if (token) {
            strncpy(ip_str, token, sizeof(ip_str) - 1);
            return ip_str;
        }
    }

    // Check SSH_CLIENT environment variable
    const char *ssh_client = getenv("SSH_CLIENT");
    if (ssh_client) {
        char *token = strtok((char *)ssh_client, " ");
        if (token) {
            strncpy(ip_str, token, sizeof(ip_str) - 1);
            return ip_str;
        }
    }

    return ip_str;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    const char *client_ip;
    FILE *fp;
    char buffer[BUFFER_SIZE];
    int result = PAM_AUTH_ERR;
    
    // Get username for logging
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) {
        log_message(LOG_ERR, "Could not get username");
        return PAM_USER_UNKNOWN;
    }
    
    // Get client IP address
    client_ip = get_client_ip(pamh);
    
    log_message(LOG_INFO, "Authentication attempt for user %s from IP %s", 
           username, client_ip);
    
    // Set environment variables for the Go program
    setenv("PAM_USER", username, 1);
    setenv("PAM_RHOST", client_ip, 1);
    
    // Execute the Go helper program
    fp = popen(KEYCLOAK_AUTH_BIN, "r");
    if (fp == NULL) {
        log_message(LOG_ERR, "Failed to execute %s", KEYCLOAK_AUTH_BIN);
        unsetenv("PAM_USER");
        unsetenv("PAM_RHOST");
        return PAM_SYSTEM_ERR;
    }
    
    // Read and display output to user
    while (fgets(buffer, sizeof(buffer)-1, fp) != NULL) {
        buffer[strcspn(buffer, "\n")] = 0;  // Remove newline
        if (strlen(buffer) > 0) {
            pam_info(pamh, "%s", buffer);
        }
    }
    
    // Get exit status
    int status = pclose(fp);
    if (WIFEXITED(status)) {
        int exit_status = WEXITSTATUS(status);
        if (exit_status == 0) {
            log_message(LOG_INFO, "Authentication successful for user %s from IP %s", 
                   username, client_ip);
            result = PAM_SUCCESS;
        } else {
            log_message(LOG_WARNING, "Authentication failed for user %s from IP %s (exit code: %d)", 
                   username, client_ip, exit_status);
            result = PAM_AUTH_ERR;
        }
    } else {
        log_message(LOG_ERR, "Helper program terminated abnormally");
        result = PAM_SYSTEM_ERR;
    }
    
    // Clean up environment variables
    unsetenv("PAM_USER");
    unsetenv("PAM_RHOST");
    
    return result;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_keycloak_modstruct = {
    "pam_keycloak",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    NULL,
    NULL,
    NULL
};
#endif
