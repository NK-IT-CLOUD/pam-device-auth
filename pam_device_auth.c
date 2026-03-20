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

#define AUTH_BIN "/usr/local/bin/pam-device-auth"
#define BUFFER_SIZE 4096
#define LOG_FILE "/var/log/pam-device-auth.log"
#define PAM_LOG_PREFIX "[PAM] "

// Map syslog priority to level string
static const char* priority_to_level(int priority) {
    switch (priority) {
        case LOG_ERR:     return "ERROR";
        case LOG_WARNING: return "WARN ";
        case LOG_INFO:    return "INFO ";
        case LOG_DEBUG:   return "DEBUG";
        default:          return "INFO ";
    }
}

// Helper function for logging
void log_message(int priority, const char *format, ...) {
    va_list args;
    va_start(args, format);

    char full_message[1024];
    vsnprintf(full_message, sizeof(full_message), format, args);

    time_t now;
    time(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y/%m/%d %H:%M:%S", localtime(&now));

    FILE *f = fopen(LOG_FILE, "a");
    if (f != NULL) {
        fprintf(f, "%s " PAM_LOG_PREFIX "   %s %s\n", timestamp, priority_to_level(priority), full_message);
        fclose(f);
    }

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
        ip_str[sizeof(ip_str) - 1] = '\0';
        return ip_str;
    }

    // Check SSH_CONNECTION environment variable
    const char *ssh_conn = getenv("SSH_CONNECTION");
    if (ssh_conn) {
        // Copy to local buffer before tokenizing (strtok modifies the string)
        char conn_buf[256];
        strncpy(conn_buf, ssh_conn, sizeof(conn_buf) - 1);
        conn_buf[sizeof(conn_buf) - 1] = '\0';
        char *token = strtok(conn_buf, " ");
        if (token) {
            strncpy(ip_str, token, sizeof(ip_str) - 1);
            ip_str[sizeof(ip_str) - 1] = '\0';
            return ip_str;
        }
    }

    // Check SSH_CLIENT environment variable
    const char *ssh_client = getenv("SSH_CLIENT");
    if (ssh_client) {
        char client_buf[256];
        strncpy(client_buf, ssh_client, sizeof(client_buf) - 1);
        client_buf[sizeof(client_buf) - 1] = '\0';
        char *token = strtok(client_buf, " ");
        if (token) {
            strncpy(ip_str, token, sizeof(ip_str) - 1);
            ip_str[sizeof(ip_str) - 1] = '\0';
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

    // Suppress unused parameter warnings
    (void)flags;
    (void)argc;
    (void)argv;

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
    fp = popen(AUTH_BIN, "r");
    if (fp == NULL) {
        log_message(LOG_ERR, "Failed to execute %s", AUTH_BIN);
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
    // Suppress unused parameter warnings
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;

    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    // Suppress unused parameter warnings
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;

    return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_device_auth_modstruct = {
    "pam_device_auth",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    NULL,
    NULL,
    NULL
};
#endif
