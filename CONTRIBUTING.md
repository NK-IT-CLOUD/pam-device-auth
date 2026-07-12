# Contributing

Contributions are welcome. This document covers the development workflow.

## Development setup

```bash
git clone https://github.com/NK-IT-CLOUD/pam-device-auth
cd pam-device-auth

# Prerequisites
# - Go 1.26.5 (security-pinned by go.mod)
# - GCC (for the C PAM module; the Go helper is CGO-free)
# - libpam0g-dev

# Ubuntu/Debian:
sudo apt install build-essential libpam0g-dev

# Rocky Linux/RHEL:
sudo dnf install gcc pam-devel

# Build everything
make build-all

# Run tests
make test
```

## Running tests

```bash
# All tests with race detector and coverage
make test

# Unit tests only
make test-unit

# View coverage
go tool cover -html=coverage.out
```

Tests use temporary directories, local HTTP test servers and command stubs where
privileged host behavior is involved. They do not modify production `/etc`
configuration, but some tests require local helper binaries and loopback sockets.

## Code style

- **Zero external Go dependencies**: pure Go stdlib, CGO-free (`CGO_ENABLED=0`). This is a security-sensitive PAM module; the dependency surface must stay minimal. The only native artifact is the C PAM shim (links `libpam`).
- Run `go fmt ./...` before committing
- Run `go vet ./...` to catch issues (`make lint`)
- Run `go mod verify` to verify the module cache
- Keep functions focused and testable

## Project structure

```
cmd/pam-device-auth/     Main binary: OIDC layer + directory-mode auth flow + --setup-ldap
internal/
  cache/                 Refresh token + IP cache (tmpfs)
  config/                Config loading + validation
  device/                Device Authorization Grant + token refresh
  discovery/             OIDC Discovery
  logger/                Structured logging
  qr/                    QR code encoder + terminal renderer
  sshclient/             SSH client version detection (QR auto-detect)
  token/                 JWKS fetch, JWT verification, role extraction
pam_device_auth.c        PAM module (C) with bidirectional pipes + FLUSH: batching protocol
configs/                 Default and provider-specific config templates
debian/                  Debian package metadata
```

## Wire protocol: C Module ↔ Go Binary

The C PAM module (`pam_device_auth.c`) communicates with the Go binary over stdin/stdout pipes. Two message prefixes control behavior (directory mode never prompts for a password, so there is no secret-input prefix):

| Prefix | Direction | PAM Message Type | Purpose |
|--------|-----------|-----------------|---------|
| `FLUSH:` | Go → C | `PAM_PROMPT_ECHO_ON` | Force display of buffered info messages |
| *(plain text)* | Go → C | `PAM_TEXT_INFO` | Informational output (link, code, QR, status) |

### Why FLUSH exists

OpenSSH 10+ buffers `PAM_TEXT_INFO` messages and only delivers them to the client when a prompt (`PAM_PROMPT_ECHO_ON` or `PAM_PROMPT_ECHO_OFF`) follows. Without a prompt, info messages are never displayed.

`FLUSH:` solves this by sending all accumulated info messages together with a visible prompt in a single batched `pam_conv()` call. The user sees the info text and a prompt like "Authorize in browser, then press Enter...". The `FLUSH:` prefix itself is stripped; only the text after it is shown.

### Batched conversation

The C module collects all `PAM_TEXT_INFO` messages until it encounters a `FLUSH:` line, then sends everything in one `pam_conv()` call. This eliminates the extra Enter presses that occurred when each message triggered a separate conversation round-trip.

```
Go binary stdout          C module                    SSH client
─────────────────────────────────────────────────────────────────
"--- Link: ... ---"       accumulate as TEXT_INFO
"--- Code: ... ---"       accumulate as TEXT_INFO
"[QR code lines]"         accumulate as TEXT_INFO
"FLUSH:Press Enter..."    send batch: [INFO,INFO,...,PROMPT]  →  display all + prompt
                          read response                      ←  user presses Enter
```

## Pull request process

1. Fork the repository and create a feature branch
2. Make your changes
3. Ensure all tests pass: `make test`
4. Ensure code is formatted: `make format`
5. Ensure no lint issues: `make lint`
6. Submit a pull request with a clear description of the change

## Development workflow

Fork the GitHub repository and submit pull requests there. The `main` branch on
GitHub reflects the latest published release. Release candidates pass the full
CI and test-host checks before a stable release is published.

## Reporting issues

Use GitHub Issues for bug reports and feature requests. For security vulnerabilities, see [SECURITY.md](SECURITY.md).
