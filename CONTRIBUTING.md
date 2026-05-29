# Contributing

Contributions are welcome. This document covers the development workflow.

## Development Setup

```bash
git clone https://github.com/NK-IT-CLOUD/pam-device-auth
cd pam-device-auth

# Prerequisites
# - Go 1.26+
# - GCC
# - libpam0g-dev
# - libcrypt-dev (for crypt_r password verification)

# Ubuntu/Debian:
sudo apt install build-essential libpam0g-dev libcrypt-dev

# Build everything
make build-all

# Run tests
make test
```

## Running Tests

```bash
# All tests with race detector and coverage
make test

# Unit tests only
make test-unit

# View coverage
go tool cover -html=coverage.out
```

Tests use mocked command execution -- no real system commands are run during testing.

## Code Style

- **Zero external Go dependencies** -- stdlib + CGO (libxcrypt for crypt_r) only. This is a security-sensitive PAM module; the dependency surface must stay minimal.
- Run `go fmt ./...` before committing
- Run `go vet ./...` to catch issues (`make lint`)
- Keep functions focused and testable

## Project Structure

```
cmd/pam-device-auth/     Main binary + CGO crypt_r verification
internal/
  cache/                 Refresh token + IP cache (tmpfs)
  config/                Config loading + validation
  device/                Device Authorization Grant + token refresh
  discovery/             OIDC Discovery
  logger/                Structured logging
  qr/                    QR code encoder + terminal renderer
  sshclient/             SSH client version detection (QR auto-detect)
  token/                 JWKS fetch, JWT verification, role extraction
  user/                  Local user creation, group management, lock/unlock
pam_device_auth.c        PAM module (C) with bidirectional pipes + PROMPT: protocol
configs/                 Default and provider-specific config templates
debian/                  Debian package metadata
scripts/                 Build, deploy, version bump, release scripts
```

## Wire Protocol: C Module ↔ Go Binary

The C PAM module (`pam_device_auth.c`) communicates with the Go binary over stdin/stdout pipes. Three message prefixes control behavior:

| Prefix | Direction | PAM Message Type | Purpose |
|--------|-----------|-----------------|---------|
| `PROMPT:` | Go → C | `PAM_PROMPT_ECHO_OFF` | Password input (max 1 per session) |
| `FLUSH:` | Go → C | `PAM_PROMPT_ECHO_ON` | Force display of buffered info messages |
| *(plain text)* | Go → C | `PAM_TEXT_INFO` | Informational output (link, code, QR, status) |

### Why FLUSH exists

OpenSSH 10+ buffers `PAM_TEXT_INFO` messages and only delivers them to the client when a prompt (`PAM_PROMPT_ECHO_ON` or `PAM_PROMPT_ECHO_OFF`) follows. Without a prompt, info messages are never displayed.

`FLUSH:` solves this by sending all accumulated info messages together with a visible prompt in a single batched `pam_conv()` call. The user sees the info text and a prompt like "Authorize in browser, then press Enter...". The `FLUSH:` prefix itself is stripped — only the text after it is shown.

### Batched conversation

The C module collects all `PAM_TEXT_INFO` messages until it encounters a `FLUSH:` or `PROMPT:` line, then sends everything in one `pam_conv()` call. This eliminates the extra Enter presses that occurred when each message triggered a separate conversation round-trip.

```
Go binary stdout          C module                    SSH client
─────────────────────────────────────────────────────────────────
"--- Link: ... ---"       accumulate as TEXT_INFO
"--- Code: ... ---"       accumulate as TEXT_INFO
"[QR code lines]"         accumulate as TEXT_INFO
"FLUSH:Press Enter..."    send batch: [INFO,INFO,...,PROMPT]  →  display all + prompt
                          read response                      ←  user presses Enter
"PROMPT:Password: "       send as ECHO_OFF prompt            →  password input
                          read response                      ←  user enters password
```

### Single-prompt guard

The C module enforces a maximum of 1 `PROMPT:` (password) per session. `FLUSH:` prompts do not count against this limit — they use `PAM_PROMPT_ECHO_ON` and are purely for display flushing.

## Pull Request Process

1. Fork the repository and create a feature branch
2. Make your changes
3. Ensure all tests pass: `make test`
4. Ensure code is formatted: `make format`
5. Ensure no lint issues: `make lint`
6. Submit a pull request with a clear description of the change

## Development Workflow

Primary development happens on an internal Gitea instance. GitHub receives clean
orphan pushes for tagged releases only.

- **Contributing**: Fork from GitHub. Pull requests are welcome on GitHub.
- **Release cycle**: RC versions are built and tested internally before a final
  version is tagged and pushed to GitHub.
- **Branches**: The `main` branch on GitHub always reflects the latest release.
  Feature branches live on Gitea and are not mirrored.

## Reporting Issues

Use GitHub Issues for bug reports and feature requests. For security vulnerabilities, see [SECURITY.md](SECURITY.md).
