# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-03-12

### Added
- **Token Caching**: Refresh tokens cached in `/run/keycloak-ssh-auth/<user>.json` (tmpfs)
  - Repeat SSH logins skip Device Auth — instant "SSO-Session aktiv." response
  - Cache-first flow: try refresh → on failure delete cache → fall through to Device Auth
  - Keycloak validates user/roles on every refresh — deactivation or role removal takes effect immediately
- **`internal/cache/` package**: Load/Save/Delete with atomic writes (temp + rename)
  - Username validation prevents path traversal in cache file paths
  - Directory `0700 root:root`, files `0600 root:root`
- **`device.RefreshToken()` function**: Token refresh via Keycloak token endpoint
- **tmpfiles.d integration**: `/run/keycloak-ssh-auth` persists across service restarts (cleared on reboot)

### Fixed
- **PAM PATH resolution**: `findBin()` resolves absolute paths for getent/useradd/usermod/visudo — fixes "executable not found" in minimal PAM environment
- **Debian postinst crash**: `VERSION` variable collision with `/etc/os-release` (renamed to `PKG_VERSION`), `set -e` abort on version comparison
- **Root SSH lockout**: postinst no longer overwrites SSH config on upgrade — configs only installed on first install
- **SSH config**: `PermitRootLogin prohibit-password` (was `no`), `MaxAuthTries 6` (was `3`)

### Changed
- **Unified log format**: Both PAM (C) and Go binary now use `TIMESTAMP [SOURCE] LEVEL MESSAGE`
- **Debian packaging**: Proper `remove` vs `purge` separation in postrm, config preservation on upgrade
- **Dependency**: `openssh-server (>= 1:9.6p1)` enforces Ubuntu 24.04+ requirement (PAM conversation compatibility)

### Security
- Cache isolated in tmpfs — tokens never written to persistent disk
- Atomic file writes prevent partial reads of cached tokens
- Username regex validation before any file path construction

## [0.4.0] - 2026-03-11

### Added
- **Device Authorization Grant (RFC 8628)**: Complete rewrite from browser-redirect OAuth2 to device flow
  - No local HTTP server, no browser redirect, no callback — works on headless servers
  - User opens URL + enters code on any device (phone, other computer)
  - Binary polls token endpoint until authorization completes
- **`internal/discovery/` package**: OIDC Discovery — auto-fetch endpoints from Keycloak
- **`internal/device/` package**: Device Auth Grant + token polling with slow_down/pending handling
- **`internal/token/` package**: JWKS fetch, JWT signature verification (RS256/384/512, ES256/384/512), role extraction
- **`internal/config/` rewrite**: 5-field config (keycloak_url, realm, client_id, required_role, auth_timeout), all env-var overridable
- **`internal/user/` rewrite**: Flat `Setup()` function, sudoers.d drop-in file (validated with `visudo -cf`)
- **137 unit tests** across all packages (config 96.7%, logger 100%)

### Removed
- **`internal/auth/` package**: Old OAuth2 browser-redirect flow (replaced by Device Auth)
- **`internal/html/` package**: Embedded HTML templates for browser callback (no longer needed)

### Changed
- **Entry point rewrite**: Config → OIDC Discovery → Device Auth → JWT Verify → User Setup
- **Config simplified**: Removed `redirect_url`, `create_users`, `add_to_sudo`, `debug_mode` from config file — debug via `--debug` CLI flag
- **Debian packaging**: Updated configs, control file, makefile for v0.4.0

### Security
- **JWT signature verification via JWKS** — cryptographic proof, not just claim parsing
- **OIDC Discovery** — fail-fast if Keycloak unreachable
- **Issuer/Expiry/Not-Before validation** on every token
- **Username matching** — SSO username must match SSH username
- **Role-based access control** — configurable required role

## [0.3.0] - 2026-02-15

### Security
- **crypto/rand**: Replace `math/rand` with `crypto/rand` for OAuth2 state/verifier generation
- **JWT issuer verification**: Token issuer must match configured Keycloak URL
- **JWT expiry check**: Reject expired tokens
- **Authorized party (azp) check**: Validate token audience

### Added
- **`--mode code` option**: Display verification code alongside browser link
- **CLAUDE.md**: AI agent context file for codebase navigation
- **Gitea CI**: `.gitea/workflows/ci.yaml` (Gitea Actions on linux_amd64 runner)

### Changed
- **Repository migration**: GitHub → Gitea (`git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth`)
- **Refactor**: Extract `verifyAndBuildResult()` to reduce duplication in auth flow
- **Dependencies**: `golang.org/x/sys` v0.33.0 → v0.41.0, Go 1.23 → 1.24

### Removed
- Compiled binary from repository
- GitHub Actions workflows (replaced by Gitea CI)

## [0.2.6] - 2024-05-26

### Fixed
- **Critical OAuth2 State Parameter Bug**: Fixed race condition causing "invalid state parameter" errors
  - State parameter was being regenerated between `GetAuthURL()` and `Authenticate()` calls
  - Added URL caching to prevent duplicate state generation
  - Enhanced debug logging for state parameter tracking
- **Random Number Generator**: Added proper seeding for better randomness
- **Authentication Flow**: Improved consistency in OAuth2 flow execution

### Added
- **Enhanced Debug Logging**: Added detailed state parameter tracking for troubleshooting
- **State Consistency Test**: Added unit test to verify state parameter consistency
- **URL Caching**: Authentication URLs are now cached to prevent regeneration

### Changed
- **KeycloakAuth Structure**: Added `authURL` field for caching authentication URLs
- **Authentication Logic**: Modified to reuse existing state when already generated

## [0.2.4] - 2024-05-26

### Added
- **Modular Architecture**: Restructured codebase into separate packages
  - `internal/config/` - Configuration management
  - `internal/auth/` - Authentication logic
  - `internal/logger/` - Structured logging
  - `internal/user/` - User management
- **Environment Variable Support**: Override configuration with environment variables
  - `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, etc.
  - `DEBUG_MODE`, `AUTH_TIMEOUT`, `CREATE_USERS`, `ADD_TO_SUDO`
- **Enhanced Logging System**: Structured logging with debug mode
- **Comprehensive Testing**: Unit tests, integration tests, and benchmarks
- **GitHub Actions CI/CD**: Automated testing and building
- **Security Enhancements**: Better input validation and error handling
- **Performance Optimizations**: Improved HTTP client handling and resource management

### Changed
- **Improved Error Messages**: More detailed and user-friendly error messages
- **Better Configuration Validation**: Comprehensive validation of all config values
- **Enhanced Documentation**: Complete README with examples and troubleshooting
- **Code Quality**: Following Go best practices and conventions

### Fixed
- **Memory Leaks**: Better resource cleanup and management
- **Race Conditions**: Thread-safe operations where needed
- **Error Handling**: Proper error propagation and handling
- **Timeout Issues**: Better timeout configuration and handling

### Security
- **Input Validation**: Comprehensive validation of all user inputs
- **Environment Variables**: Secure handling of sensitive configuration data
- **Permission Management**: Improved file and directory permission handling
- **Command Injection Prevention**: Protection against command injection attacks

## [0.2.3] - 2024-03-05

### Added
- Role verification functionality
- User management improvements
- Enhanced error handling

### Changed
- Improved authentication flow
- Better logging output

### Fixed
- Various bug fixes and stability improvements

## [0.2.2] - 2024-02-15

### Added
- Basic SSO functionality
- PAM module integration
- Web-based authentication templates

### Changed
- Initial stable release structure

## [0.2.1] - 2024-02-01

### Added
- Initial release with basic Keycloak integration
- SSH authentication via OAuth2/OIDC
- Debian packaging

## [0.1.x] - Development Versions

### Added
- Development and testing versions
- Proof of concept implementations
