# CLAUDE.md — Keycloak SSH Auth

## Überblick
Go-Binary + PAM-Modul für SSH-Login via Keycloak SSO.
User → SSH → PAM → Go Binary → Keycloak OAuth2 → Browser Auth → SSH Access.

## Struktur
- `cmd/keycloak-auth/main.go` — Entry point, CLI flags
- `internal/auth/keycloak.go` — OAuth2/OIDC Flow, Token handling
- `internal/config/config.go` — JSON config + env var override
- `internal/user/manager.go` — Linux user creation + sudo
- `internal/logger/logger.go` — Structured logging
- `internal/html/` — Browser response templates
- `pam_keycloak.c` — PAM module (C)
- `configs/` — Default config files for .deb
- `debian/` — Debian packaging

## Build
```bash
make build          # Go binary only
make build-all      # Binary + PAM module
make deb            # Debian package
make test           # Run tests
```

## Config
`/etc/keycloak-ssh-auth/keycloak-pam.json` — Keycloak URL, realm, client, required role, callback IP/port.
All values overridable via environment variables.

## Auth Modes
- `--mode browser` (default): User gets URL, opens in browser, callback completes auth
- `--mode code`: Same flow but with verification code display

## Security
- PKCE (S256) for auth code exchange
- crypto/rand for all random strings (state, code_verifier)
- JWT issuer + expiry verification
- Role-based access control
- Username must match between SSH and Keycloak

## Keycloak Requirements
- OIDC client with Authorization Code Flow + PKCE
- Required role (e.g. `ssh-access`) assigned to users
- Redirect URI: `http://SERVER_IP:33499/callback`
