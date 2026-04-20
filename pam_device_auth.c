#define _GNU_SOURCE  // required for pipe2, clearenv
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
#include <poll.h>
#include <limits.h>

#define AUTH_BIN "/usr/local/bin/pam-device-auth"
#define BUFFER_SIZE 4096
#define LOG_FILE "/var/log/pam-device-auth.log"
#define PAM_LOG_PREFIX "[PAM] "

// Total wall-clock budget for a single authentication attempt, end-to-end
// (child startup, all PAM conversations, device-flow polling, shutdown).
// Must exceed cfg.AuthTimeout (180s default, 240s max) with headroom; the
// Go-side validator in internal/config/config.go enforces the 240s ceiling
// so this SIGKILL deadline always fires after a clean Go-context timeout.
#define AUTH_TOTAL_TIMEOUT_S 300

// Sleep step when polling for child exit after EOF on stdout.
#define WAITPID_POLL_MS 50

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

// Monotonic deadline helpers. PAM modules may be invoked concurrently in the
// same sshd process; all timeout state must be per-call (stack-local), never
// process-global. SIGALRM + a global alarm handler is unsafe here because
// (a) there is only one alarm per process, so concurrent logins clobber each
// other, and (b) the signal handler ran outside the authenticate frame and
// relied on globals that two sessions would race on.
static void deadline_from_now(struct timespec *deadline, int seconds) {
    clock_gettime(CLOCK_MONOTONIC, deadline);
    deadline->tv_sec += seconds;
}

// remaining_ms returns the time left until `deadline`, clamped to int range.
// Negative return means the deadline has passed.
static int remaining_ms(const struct timespec *deadline) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long long ms = (long long)(deadline->tv_sec - now.tv_sec) * 1000LL
                 + (long long)(deadline->tv_nsec - now.tv_nsec) / 1000000LL;
    if (ms > INT_MAX) return INT_MAX;
    if (ms < INT_MIN) return INT_MIN;
    return (int)ms;
}

// Per-call line reader over a non-blocking fd. Replaces fdopen/fgets, which
// would block indefinitely on a misbehaving child no matter what timeout we
// set around the surrounding waitpid.
typedef struct {
    int fd;
    struct timespec deadline;
    char buf[BUFFER_SIZE];
    size_t buf_len;
    int eof;
} line_reader_t;

static void line_reader_init(line_reader_t *lr, int fd, const struct timespec *deadline) {
    lr->fd = fd;
    lr->deadline = *deadline;
    lr->buf_len = 0;
    lr->eof = 0;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

// line_reader_next reads one '\n'-terminated line into `line` (stripped of \n,
// NUL-terminated). Returns 1 on success, 0 on clean EOF, -1 on deadline or
// fatal read error. A partial line remaining at EOF is returned as a final
// successful line.
static int line_reader_next(line_reader_t *lr, char *line, size_t line_size) {
    for (;;) {
        char *nl = memchr(lr->buf, '\n', lr->buf_len);
        if (nl != NULL) {
            size_t line_len = (size_t)(nl - lr->buf);
            size_t copy_len = line_len < line_size - 1 ? line_len : line_size - 1;
            memcpy(line, lr->buf, copy_len);
            line[copy_len] = '\0';
            size_t consumed = line_len + 1;
            memmove(lr->buf, lr->buf + consumed, lr->buf_len - consumed);
            lr->buf_len -= consumed;
            return 1;
        }

        if (lr->eof) return 0;

        // Full buffer without a newline → flush as a (very long) line.
        if (lr->buf_len >= BUFFER_SIZE) {
            size_t copy_len = BUFFER_SIZE < line_size - 1 ? BUFFER_SIZE : line_size - 1;
            memcpy(line, lr->buf, copy_len);
            line[copy_len] = '\0';
            lr->buf_len = 0;
            return 1;
        }

        int ms = remaining_ms(&lr->deadline);
        if (ms <= 0) return -1;

        struct pollfd pfd = { .fd = lr->fd, .events = POLLIN, .revents = 0 };
        int pret = poll(&pfd, 1, ms);
        if (pret < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (pret == 0) return -1; // deadline hit

        if (pfd.revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = read(lr->fd, lr->buf + lr->buf_len, BUFFER_SIZE - lr->buf_len);
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                return -1;
            }
            if (n == 0) {
                lr->eof = 1;
                if (lr->buf_len > 0) {
                    size_t copy_len = lr->buf_len < line_size - 1 ? lr->buf_len : line_size - 1;
                    memcpy(line, lr->buf, copy_len);
                    line[copy_len] = '\0';
                    lr->buf_len = 0;
                    return 1;
                }
                return 0;
            }
            lr->buf_len += (size_t)n;
        }
    }
}

// Wait for the child to exit, or until the deadline. Sends SIGKILL and reaps
// if the deadline passes. Sets *timed_out to 1 iff the deadline fired.
// Returns the waitpid status (as reported by waitpid()).
static int waitpid_until_deadline(pid_t pid, const struct timespec *deadline, int *timed_out) {
    int status = -1;
    *timed_out = 0;

    for (;;) {
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            return status;
        }
        if (w < 0) {
            // Child already reaped or a true error — give up without blocking.
            return status;
        }
        if (remaining_ms(deadline) <= 0) {
            kill(pid, SIGKILL);
            *timed_out = 1;
            // Blocking wait is bounded: SIGKILL is synchronous on process exit.
            waitpid(pid, &status, 0);
            return status;
        }
        struct timespec ts = { .tv_sec = 0, .tv_nsec = WAITPID_POLL_MS * 1000L * 1000L };
        nanosleep(&ts, NULL);
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

    // Bidirectional pipes: parent ↔ child. O_CLOEXEC closes these fds on
    // exec — important if another PAM module in the same sshd process
    // spawns a subprocess while our fds are still open, which would
    // otherwise leak the authentication channel into that subprocess.
    int to_child[2];   // parent writes, child reads (stdin)
    int from_child[2]; // child writes, parent reads (stdout)

    if (pipe2(to_child, O_CLOEXEC) != 0) {
        log_message(LOG_ERR, "Failed to create pipes");
        unsetenv("PAM_USER");
        unsetenv("PAM_RHOST");
        return PAM_SYSTEM_ERR;
    }
    if (pipe2(from_child, O_CLOEXEC) != 0) {
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

        // Sanitize environment before exec: sshd may have inherited
        // LD_PRELOAD, LD_LIBRARY_PATH, IFS, or similar from its init unit
        // or from a misconfigured AcceptEnv. Forwarding them to the Go
        // helper would give any attacker who can influence that env a direct
        // code-injection vector. Snapshot the whitelist on the stack,
        // clearenv(), then restore with a minimal sanitized PATH.
        static const char *const keep[] = {
            "PAM_USER",
            "PAM_RHOST",
            "PAM_DEVICE_AUTH_ISSUER",
            "PAM_DEVICE_AUTH_CLIENT_ID",
            "PAM_DEVICE_AUTH_REQUIRED_ROLE",
            "PAM_DEVICE_AUTH_SUDO_ROLE",
            "PAM_DEVICE_AUTH_ROLE_CLAIM",
            "PAM_DEVICE_AUTH_IP_CLAIM",
            "PAM_DEVICE_AUTH_TIMEOUT",
        };
        const int keep_n = (int)(sizeof(keep) / sizeof(keep[0]));
        char saved[9][2048];
        int saved_set[9] = {0};
        for (int i = 0; i < keep_n; i++) {
            const char *v = getenv(keep[i]);
            if (v && strlen(v) < sizeof(saved[i])) {
                strcpy(saved[i], v);
                saved_set[i] = 1;
            }
        }
        clearenv();
        setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
        for (int i = 0; i < keep_n; i++) {
            if (saved_set[i]) {
                setenv(keep[i], saved[i], 1);
            }
        }

        execl(AUTH_BIN, AUTH_BIN, NULL);
        _exit(127);
    }

    // Parent: read child stdout, handle PROMPT: lines via PAM conversation.
    // Single per-call deadline covers ALL parent-side waiting (pipe reads +
    // final child reap). Replaces the earlier SIGALRM scheme which only
    // covered waitpid and used process-global state (unsafe under concurrent
    // PAM calls in the same sshd process).
    close(to_child[0]);
    close(from_child[1]);

    struct timespec deadline;
    deadline_from_now(&deadline, AUTH_TOTAL_TIMEOUT_S);

    // Ignore SIGPIPE — prevents sshd termination if child exits during write
    struct sigaction sa_ign, sa_old_pipe;
    memset(&sa_ign, 0, sizeof(sa_ign));
    sa_ign.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa_ign, &sa_old_pipe);

    line_reader_t lr;
    line_reader_init(&lr, from_child[0], &deadline);

    int prompt_used = 0;
    int read_timed_out = 0;

    // Message batching: accumulate PAM_TEXT_INFO lines, flush with next prompt
    #define MAX_BATCH 64
    char *batch_lines[MAX_BATCH];
    int batch_count = 0;

    for (;;) {
        int rc = line_reader_next(&lr, buffer, sizeof(buffer));
        if (rc == 0) break;               // EOF
        if (rc < 0) {                     // deadline or fatal read error
            if (remaining_ms(&deadline) <= 0) {
                read_timed_out = 1;
            }
            break;
        }

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

    close(from_child[0]);
    close(to_child[1]);

    int child_timed_out = read_timed_out;
    int waitpid_timed_out = 0;
    int status = waitpid_until_deadline(pid, &deadline, &waitpid_timed_out);
    if (waitpid_timed_out) {
        child_timed_out = 1;
    }

    // Restore SIGPIPE
    sigaction(SIGPIPE, &sa_old_pipe, NULL);

    if (child_timed_out) {
        log_message(LOG_ERR, "Helper program timed out after %ds for user %s", AUTH_TOTAL_TIMEOUT_S, safe_user);
        result = PAM_SYSTEM_ERR;
    } else if (WIFEXITED(status)) {
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
