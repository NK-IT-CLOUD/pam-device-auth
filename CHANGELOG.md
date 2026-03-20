# Changelog

All notable changes to this project will be documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [0.2.0] - 2026-03-20

### Added
- `--check` command: validates config and tests OIDC provider connectivity before activation
- `--enable` command: activates PAM authentication after successful config check, restarts SSH
- Safe installation: fresh installs no longer auto-activate PAM — prevents lockout with default config

### Changed
- Upgrade installs preserve existing PAM activation and restart SSH automatically

## [0.1.1] - 2026-03-20

### Changed
- Root user authenticates via SSH key only (no OIDC required)
- `Match User root` added to default sshd config

## [0.1.0] - 2026-03-20

First public release. Generic OIDC Device Authorization Grant for SSH PAM authentication.

### Features
- OIDC Device Authorization Grant (RFC 8628) for SSH login
- Works with any OIDC provider: Keycloak, Auth0, Okta, Authentik
- Custom role claim extraction via `role_claim` config
- Refresh token caching in tmpfs for fast repeat logins (~200ms)
- Automatic user creation with configurable group membership
- Role-based group assignment: `sudo_role` + `admin_groups` for admin/user separation
- Automatic demotion: revoking `sudo_role` removes admin groups on next login
- QR code displayed during device authorization for easy mobile scanning
- Forced local password setup on first login via `.bash_profile` prompt (used for sudo)
- JWT signature verification via JWKS (RSA + ECDSA)
- Debian package with zero-config install
- stdlib-only Go binary -- zero external dependencies

### Security
- Cryptographic JWT verification (RS256/384/512, ES256/384/512)
- OIDC Discovery fail-fast (no silent degradation)
- Username validation (path-traversal protected)
- Atomic cache writes in tmpfs (ephemeral on reboot)
- Token refresh validates at provider on every cached login
