# CLAUDE.md — Keycloak SSH Auth

## Überblick
Go-Binary + PAM-Modul für SSH-Login via Keycloak SSO (v0.5.0).
User → SSH → PAM → Go Binary → Cache/Refresh oder Device Auth → JWT Verify → SSH Access.

## Struktur
- `cmd/keycloak-auth/main.go` — Entry point, cache-first flow
- `internal/cache/` — Refresh Token cache (Load/Save/Delete in /run/)
- `internal/config/` — JSON config + env var override
- `internal/discovery/` — OIDC Discovery (endpoints)
- `internal/device/` — Device Auth Grant + RefreshToken (RFC 8628)
- `internal/token/` — JWKS fetch, JWT verify, role extraction
- `internal/user/manager.go` — Linux user creation + sudo
- `internal/logger/` — Structured logging (unified format)
- `pam_keycloak.c` — PAM module (C)
- `configs/` — Default config files for .deb
- `debian/` — Debian packaging (postinst/postrm)

## Build
```bash
make build          # Go binary only
make build-all      # Binary + PAM module
make deb            # Debian package
make test           # Run tests
```

## Config
`/etc/keycloak-ssh-auth/keycloak-pam.json` — Keycloak URL, realm, client, required role.
All values overridable via environment variables.

## Auth Flow
1. Cache check: try refresh token from `/run/keycloak-ssh-auth/<user>.json`
2. On hit: refresh at Keycloak → validate JWT → "SSO-Session aktiv."
3. On miss/fail: Device Authorization Grant (URL + code in terminal)
4. JWT issuer + expiry + username + role verification
5. User setup (create + sudo)

## Security
- JWT signature verification via JWKS (RSA + ECDSA)
- Refresh Token in tmpfs (gone on reboot)
- Keycloak validates user/roles on every refresh
- Username validation prevents path traversal in cache
- Atomic file writes (temp + rename)

## Requirements
- Ubuntu 24.04+ (OpenSSH >= 9.6)
- Keycloak OIDC client with Device Authorization Grant enabled
- Required role (e.g. `ssh-access`) assigned to users
