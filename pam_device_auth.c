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
#include <sys/wait.h>
#include <time.h>
#include <stdarg.h>
#include <errno.h>

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
static void log_message(int priority, const char *format, ...) {
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

// Write all bytes to fd, retrying on partial writes. Returns 0 on success, -1 on error.
static int write_all(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

// Extract client IP into caller-supplied buffer
static void get_client_ip(pam_handle_t *pamh, char *ip_buf, size_t ip_buf_size) {
    const char *rhost = NULL;

    strncpy(ip_buf, "unknown", ip_buf_size - 1);
    ip_buf[ip_buf_size - 1] = '\0';

    // Check PAM_RHOST first
    if (pam_get_item(pamh, PAM_RHOST, (const void **)&rhost) == PAM_SUCCESS && rhost && *rhost) {
        strncpy(ip_buf, rhost, ip_buf_size - 1);
        ip_buf[ip_buf_size - 1] = '\0';
        return;
    }

    // Check SSH_CONNECTION environment variable
    const char *ssh_conn = getenv("SSH_CONNECTION");
    if (ssh_conn) {
        char conn_buf[256];
        strncpy(conn_buf, ssh_conn, sizeof(conn_buf) - 1);
        conn_buf[sizeof(conn_buf) - 1] = '\0';
        char *token = strtok(conn_buf, " ");
        if (token) {
            strncpy(ip_buf, token, ip_buf_size - 1);
            ip_buf[ip_buf_size - 1] = '\0';
            return;
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
            strncpy(ip_buf, token, ip_buf_size - 1);
            ip_buf[ip_buf_size - 1] = '\0';
        }
    }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    char client_ip[INET6_ADDRSTRLEN];
    char buffer[BUFFER_SIZE];
    int result = PAM_AUTH_ERR;

    (void)flags;
    (void)argc;
    (void)argv;

    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) {
        log_message(LOG_ERR, "Could not get username");
        return PAM_USER_UNKNOWN;
    }

    get_client_ip(pamh, client_ip, sizeof(client_ip));
    log_message(LOG_INFO, "Authentication attempt for user %s from IP %s", username, client_ip);

    setenv("PAM_USER", username, 1);
    setenv("PAM_RHOST", client_ip, 1);

    // Bidirectional pipes: parent ↔ child
    int to_child[2];   // parent writes, child reads (stdin)
    int from_child[2]; // child writes, parent reads (stdout)

    if (pipe(to_child) != 0 || pipe(from_child) != 0) {
        log_message(LOG_ERR, "Failed to create pipes");
        unsetenv("PAM_USER");
        unsetenv("PAM_RHOST");
        return PAM_SYSTEM_ERR;
    }

    pid_t pid = fork();
    if (pid < 0) {
        log_message(LOG_ERR, "Fork failed");
        close(to_child[0]); close(to_child[1]);
        close(from_child[0]); close(from_child[1]);
        unsetenv("PAM_USER");
        unsetenv("PAM_RHOST");
        return PAM_SYSTEM_ERR;
    }

    if (pid == 0) {
        // Child: wire up stdin/stdout, close everything else
        close(to_child[1]);
        close(from_child[0]);

        dup2(to_child[0], STDIN_FILENO);
        dup2(from_child[1], STDOUT_FILENO);

        close(to_child[0]);
        close(from_child[1]);

        // Close leaked fds (syslog, etc.) — keep only 0,1,2
        for (int fd = 3; fd < 1024; fd++) {
            close(fd);
        }

        execl(AUTH_BIN, AUTH_BIN, NULL);
        _exit(127);
    }

    // Parent: read child stdout, handle PROMPT: lines via PAM conversation
    close(to_child[0]);
    close(from_child[1]);

    FILE *fp = fdopen(from_child[0], "r");
    if (fp == NULL) {
        log_message(LOG_ERR, "fdopen failed");
        close(to_child[1]);
        close(from_child[0]);
        waitpid(pid, NULL, 0);
        unsetenv("PAM_USER");
        unsetenv("PAM_RHOST");
        return PAM_SYSTEM_ERR;
    }

    int prompt_used = 0; // Only allow one PROMPT: per session

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        buffer[strcspn(buffer, "\n")] = 0;

        if (strncmp(buffer, "PROMPT:", 7) == 0) {
            // Only one password prompt allowed per authentication
            if (prompt_used) {
                log_message(LOG_ERR, "Multiple PROMPT: requests rejected");
                write_all(to_child[1], "\n", 1);
                continue;
            }
            prompt_used = 1;

            const char *prompt_text = buffer + 7;
            const struct pam_conv *conv = NULL;

            if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS || conv == NULL) {
                log_message(LOG_ERR, "Failed to get PAM conversation function");
                write_all(to_child[1], "\n", 1);
                continue;
            }

            struct pam_message msg;
            const struct pam_message *msgp = &msg;
            struct pam_response *resp = NULL;

            msg.msg_style = PAM_PROMPT_ECHO_OFF;
            msg.msg = prompt_text;

            int conv_result = conv->conv(1, &msgp, &resp, conv->appdata_ptr);

            // Always zero and free resp->resp if allocated, regardless of conv result
            if (resp) {
                if (resp->resp) {
                    size_t len = strlen(resp->resp);
                    if (conv_result == PAM_SUCCESS && len > 0) {
                        write_all(to_child[1], resp->resp, len);
                        write_all(to_child[1], "\n", 1);
                    } else {
                        write_all(to_child[1], "\n", 1);
                    }
                    memset(resp->resp, 0, len);
                    free(resp->resp);
                } else {
                    write_all(to_child[1], "\n", 1);
                }
                free(resp);
            } else {
                write_all(to_child[1], "\n", 1);
            }
        } else if (strlen(buffer) > 0) {
            pam_info(pamh, "%s", buffer);
        }
    }

    fclose(fp);
    close(to_child[1]);

    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
        int exit_status = WEXITSTATUS(status);
        if (exit_status == 0) {
            log_message(LOG_INFO, "Authentication successful for user %s from IP %s", username, client_ip);
            result = PAM_SUCCESS;
        } else {
            log_message(LOG_WARNING, "Authentication failed for user %s from IP %s (exit code: %d)", username, client_ip, exit_status);
            result = PAM_AUTH_ERR;
        }
    } else {
        log_message(LOG_ERR, "Helper program terminated abnormally");
        result = PAM_SYSTEM_ERR;
    }

    unsetenv("PAM_USER");
    unsetenv("PAM_RHOST");

    return result;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;

    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;

    return PAM_IGNORE; // Let pam_unix handle account management
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
