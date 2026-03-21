# Contributing

Contributions are welcome. This document covers the development workflow.

## Development Setup

```bash
git clone https://github.com/NK-IT-CLOUD/pam-device-auth
cd pam-device-auth

# Prerequisites
# - Go 1.22+
# - GCC
# - libpam0g-dev

# Ubuntu/Debian:
sudo apt install build-essential libpam0g-dev

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

- **stdlib only** -- no external Go dependencies. This is a security-sensitive PAM module; the dependency surface must stay at zero.
- Run `go fmt ./...` before committing
- Run `go vet ./...` to catch issues (`make lint`)
- Keep functions focused and testable

## Project Structure

```
cmd/pam-device-auth/     Main binary
internal/
  cache/                 Refresh token cache (tmpfs)
  config/                Config loading + validation
  device/                Device Authorization Grant + token refresh
  discovery/             OIDC Discovery
  logger/                Structured logging
  token/                 JWKS fetch, JWT verification, role extraction
  user/                  Local user creation + group management
pam_device_auth.c        PAM module (C)
configs/                 Default and provider-specific config templates
debian/                  Debian package metadata
```

## Pull Request Process

1. Fork the repository and create a feature branch
2. Make your changes
3. Ensure all tests pass: `make test`
4. Ensure code is formatted: `make format`
5. Ensure no lint issues: `make lint`
6. Submit a pull request with a clear description of the change

## Reporting Issues

Use GitHub Issues for bug reports and feature requests. For security vulnerabilities, see [SECURITY.md](SECURITY.md).
