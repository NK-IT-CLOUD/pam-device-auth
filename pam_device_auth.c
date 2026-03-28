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
#include <fcntl.h>
#include <signal.h>

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

// Sanitize a string for safe logging: replace control chars and bytes >= 0x7F.
static void sanitize_for_log(const char *src, char *dst, size_t dst_size) {
    size_t i = 0;
    for (; *src && i < dst_size - 1; src++) {
        if ((unsigned char)*src >= 0x20 && (unsigned char)*src < 0x7F) {
            dst[i++] = *src;
        } else {
            dst[i++] = '?';
        }
    }
    dst[i] = '\0';
}

// Helper function for logging
static void log_message(int priority, const char *format, ...) {
    va_list args;
    va_start(args, format);

    char full_message[1024];
    vsnprintf(full_message, sizeof(full_message), format, args);

    time_t now;
    time(&now);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y/%m/%d %H:%M:%S", &tm_buf);

    int log_fd = open(LOG_FILE, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, 0640);
    FILE *f = (log_fd >= 0) ? fdopen(log_fd, "a") : NULL;
    if (f != NULL) {
        fprintf(f, "%s " PAM_LOG_PREFIX "   %s %s\n", timestamp, priority_to_level(priority), full_message);
        fclose(f);
    } else if (log_fd >= 0) {
        close(log_fd);
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

static volatile sig_atomic_t child_timed_out = 0;
static volatile pid_t timeout_child_pid = 0;

static void alarm_handler(int sig) {
    (void)sig;
    child_timed_out = 1;
    if (timeout_child_pid > 0) {
        kill(timeout_child_pid, SIGKILL);
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

    char safe_user[64], safe_ip[INET6_ADDRSTRLEN];
    sanitize_for_log(username, safe_user, sizeof(safe_user));
    sanitize_for_log(client_ip, safe_ip, sizeof(safe_ip));
    log_message(LOG_INFO, "Authentication attempt for user %s from IP %s", safe_user, safe_ip);

    setenv("PAM_USER", username, 1);
    setenv("PAM_RHOST", client_ip, 1);

    // Bidirectional pipes: parent ↔ child
    int to_child[2];   // parent writes, child reads (stdin)
    int from_child[2]; // child writes, parent reads (stdout)

    if (pipe(to_child) != 0) {
        log_message(LOG_ERR, "Failed to create pipes");
        unsetenv("PAM_USER");
        unsetenv("PAM_RHOST");
        return PAM_SYSTEM_ERR;
    }
    if (pipe(from_child) != 0) {
        log_message(LOG_ERR, "Failed to create pipes");
        close(to_child[0]);
        close(to_child[1]);
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

    // Ignore SIGPIPE — prevents sshd termination if child exits during write
    struct sigaction sa_ign, sa_old_pipe;
    memset(&sa_ign, 0, sizeof(sa_ign));
    sa_ign.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa_ign, &sa_old_pipe);

    FILE *fp = fdopen(from_child[0], "r");
    if (fp == NULL) {
        log_message(LOG_ERR, "fdopen failed");
        close(to_child[1]);
        close(from_child[0]);
        waitpid(pid, NULL, 0);
        unsetenv("PAM_USER");
        unsetenv("PAM_RHOST");
        sigaction(SIGPIPE, &sa_old_pipe, NULL);
        return PAM_SYSTEM_ERR;
    }

    int prompt_used = 0;

    // Message batching: accumulate PAM_TEXT_INFO lines, flush with next prompt
    #define MAX_BATCH 64
    char *batch_lines[MAX_BATCH];
    int batch_count = 0;

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        buffer[strcspn(buffer, "\n")] = 0;

        if (strncmp(buffer, "FLUSH:", 6) == 0) {
            // Send all accumulated info + this prompt in ONE conv call
            const char *flush_text = buffer + 6;
            const struct pam_conv *conv = NULL;
            if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS || conv == NULL) {
                for (int i = 0; i < batch_count; i++) free(batch_lines[i]);
                batch_count = 0;
                write_all(to_child[1], "\n", 1);
                continue;
            }

            int total = batch_count + 1;
            struct pam_message *msgs = calloc(total, sizeof(struct pam_message));
            const struct pam_message **ptrs = calloc(total, sizeof(const struct pam_message *));
            if (!msgs || !ptrs) {
                free(msgs); free(ptrs);
                for (int i = 0; i < batch_count; i++) free(batch_lines[i]);
                batch_count = 0;
                write_all(to_child[1], "\n", 1);
                continue;
            }

            for (int i = 0; i < batch_count; i++) {
                msgs[i].msg_style = PAM_TEXT_INFO;
                msgs[i].msg = batch_lines[i];
                ptrs[i] = &msgs[i];
            }
            msgs[batch_count].msg_style = PAM_PROMPT_ECHO_ON;
            msgs[batch_count].msg = flush_text;
            ptrs[batch_count] = &msgs[batch_count];

            struct pam_response *resp = NULL;
            conv->conv(total, ptrs, &resp, conv->appdata_ptr);

            if (resp) {
                for (int i = 0; i < total; i++) {
                    if (resp[i].resp) free(resp[i].resp);
                }
                free(resp);
            }
            write_all(to_child[1], "\n", 1);

            for (int i = 0; i < batch_count; i++) free(batch_lines[i]);
            batch_count = 0;
            free(msgs);
            free(ptrs);

        } else if (strncmp(buffer, "PROMPT:", 7) == 0) {
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
                for (int i = 0; i < batch_count; i++) free(batch_lines[i]);
                batch_count = 0;
                write_all(to_child[1], "\n", 1);
                continue;
            }

            int total = batch_count + 1;
            struct pam_message *msgs = calloc(total, sizeof(struct pam_message));
            const struct pam_message **ptrs = calloc(total, sizeof(const struct pam_message *));
            if (!msgs || !ptrs) {
                free(msgs); free(ptrs);
                for (int i = 0; i < batch_count; i++) free(batch_lines[i]);
                batch_count = 0;
                write_all(to_child[1], "\n", 1);
                continue;
            }

            for (int i = 0; i < batch_count; i++) {
                msgs[i].msg_style = PAM_TEXT_INFO;
                msgs[i].msg = batch_lines[i];
                ptrs[i] = &msgs[i];
            }
            msgs[batch_count].msg_style = PAM_PROMPT_ECHO_OFF;
            msgs[batch_count].msg = prompt_text;
            ptrs[batch_count] = &msgs[batch_count];

            struct pam_response *resp = NULL;
            int conv_result = conv->conv(total, ptrs, &resp, conv->appdata_ptr);

            // Extract password from the LAST response (the prompt slot)
            if (resp) {
                if (resp[batch_count].resp) {
                    size_t len = strlen(resp[batch_count].resp);
                    if (conv_result == PAM_SUCCESS && len > 0) {
                        write_all(to_child[1], resp[batch_count].resp, len);
                        write_all(to_child[1], "\n", 1);
                    } else {
                        write_all(to_child[1], "\n", 1);
                    }
                    memset(resp[batch_count].resp, 0, len);
                    free(resp[batch_count].resp);
                    resp[batch_count].resp = NULL;
                } else {
                    write_all(to_child[1], "\n", 1);
                }
                // Free ALL responses
                for (int i = 0; i < total; i++) {
                    if (resp[i].resp) {
                        memset(resp[i].resp, 0, strlen(resp[i].resp));
                        free(resp[i].resp);
                    }
                }
                free(resp);
            } else {
                write_all(to_child[1], "\n", 1);
            }

            for (int i = 0; i < batch_count; i++) free(batch_lines[i]);
            batch_count = 0;
            free(msgs);
            free(ptrs);

        } else if (strlen(buffer) > 0) {
            // Accumulate info line for batching
            if (batch_count < MAX_BATCH) {
                char *line = strdup(buffer);
                if (line) {
                    batch_lines[batch_count++] = line;
                }
            }
        }
    }

    // Clean up any remaining batched lines (not displayed — Go binary should
    // not leave trailing info without a FLUSH/PROMPT)
    for (int i = 0; i < batch_count; i++) free(batch_lines[i]);

    fclose(fp);
    close(to_child[1]);

    int status = -1;
    child_timed_out = 0;
    timeout_child_pid = pid;
    struct sigaction sa_alarm, sa_old_alarm;
    memset(&sa_alarm, 0, sizeof(sa_alarm));
    sa_alarm.sa_handler = alarm_handler;
    sigaction(SIGALRM, &sa_alarm, &sa_old_alarm);
    alarm(300);

    waitpid(pid, &status, 0);

    alarm(0);
    sigaction(SIGALRM, &sa_old_alarm, NULL);
    timeout_child_pid = 0;

    // Restore SIGPIPE
    sigaction(SIGPIPE, &sa_old_pipe, NULL);

    if (WIFEXITED(status)) {
        int exit_status = WEXITSTATUS(status);
        if (exit_status == 0) {
            log_message(LOG_INFO, "Authentication successful for user %s from IP %s", safe_user, safe_ip);
            result = PAM_SUCCESS;
        } else if (exit_status == 2) {
            // Exit code 2 = hard deny (IP not allowed, role revoked)
            // PAM_MAXTRIES signals sshd to stop retrying immediately
            log_message(LOG_WARNING, "Permission denied for user %s from IP %s (hard deny)", safe_user, safe_ip);
            result = PAM_MAXTRIES;
        } else {
            log_message(LOG_WARNING, "Authentication failed for user %s from IP %s (exit code: %d)", safe_user, safe_ip, exit_status);
            result = PAM_AUTH_ERR;
        }
    } else {
        log_message(LOG_ERR, "Helper program terminated abnormally");
        result = PAM_SYSTEM_ERR;
    }

    if (child_timed_out) {
        log_message(LOG_ERR, "Helper program timed out after 300s");
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
