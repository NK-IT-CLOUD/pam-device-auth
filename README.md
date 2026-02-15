# Keycloak SSH Authentication

SSH-Login via Keycloak SSO — PAM-Modul + Go-Binary für OAuth2/OIDC-basierte SSH-Authentifizierung.

## Architektur

```
SSH Client → PAM Module (C) → keycloak-auth (Go) → Keycloak OIDC
                                    ↓
                              Local HTTP Server ← Browser Callback
                                    ↓
                              JWT Verification (JWKS)
                                    ↓
                              User Setup (create, sudo)
```

### Komponenten

| Komponente | Sprache | Beschreibung |
|---|---|---|
| `pam_keycloak.so` | C | PAM-Modul, ruft Go-Binary auf |
| `keycloak-auth` | Go | OAuth2/OIDC Flow mit PKCE, JWT-Verifizierung |
| Config | JSON | `/etc/keycloak-ssh-auth/keycloak-pam.json` |

### Auth-Flow

1. User verbindet per SSH → PAM ruft `keycloak-auth` auf
2. Binary startet lokalen HTTP-Server für OAuth2 Callback
3. User öffnet angezeigten Link im Browser → Keycloak Login
4. Keycloak redirected zu Callback-URL mit Auth-Code
5. Binary tauscht Code gegen Token (mit PKCE)
6. **JWT-Signatur wird via JWKS-Endpoint verifiziert** (RSA/ECDSA)
7. Claims werden geprüft: Issuer, Expiry, Required Role, Username-Match
8. Optional: System-User wird erstellt + sudo konfiguriert

## Build

```bash
# Alles bauen (Binary + PAM Module)
make build-all

# Nur Binary
make build

# Tests
make test-unit

# Debian-Paket
make deb
```

**Voraussetzungen:** Go 1.23+, GCC, libpam0g-dev

## Konfiguration

`/etc/keycloak-ssh-auth/keycloak-pam.json`:

```json
{
  "keycloak_url": "https://sso.nk-it.cloud",
  "realm": "nk-it.cloud",
  "client_id": "ssh-auth",
  "client_secret": "...",
  "required_role": "ssh-access",
  "callback_ip": "0.0.0.0",
  "callback_port": "33499",
  "auth_timeout": 180,
  "create_users": true,
  "add_to_sudo": true
}
```

Alle Werte können per Umgebungsvariable überschrieben werden:
`KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, etc.

## Installation

```bash
# Via .deb Paket
make install

# Oder manuell
sudo cp build/bin/keycloak-auth /usr/local/bin/
sudo cp pam_keycloak.so /usr/lib/security/
sudo cp configs/keycloak-pam.json /etc/keycloak-ssh-auth/
```

PAM-Konfiguration in `/etc/pam.d/sshd` und SSHD-Config in `/etc/ssh/sshd_config.d/`.

## Sicherheit

- **JWT-Signatur-Verifizierung** via Keycloak JWKS-Endpoint (RSA256, RS384, RS512, ES256, ES384, ES512)
- **PKCE** (S256) für den Authorization Code Flow
- **State-Parameter** gegen CSRF
- **Issuer/Expiry/Audience** Validation
- **Username-Matching**: SSO-Username muss SSH-Username entsprechen
- **Role-Based Access**: Nur User mit konfigurierter Rolle dürfen sich einloggen

## Projektstruktur

```
cmd/keycloak-auth/     → Main Binary (CLI + Auth Flow)
internal/
  auth/                → Keycloak Auth + JWKS Verification
  config/              → Config Loading + Validation
  html/                → HTML Templates für Browser-Callback
  logger/              → Structured Logging
  user/                → System User Management
pam_keycloak.c         → PAM Module (C)
configs/               → Default Configs
debian/                → Debian Package Files
test/                  → Additional Tests
```

## Repository

- **Repo**: https://git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth
- **CI**: Gitea Actions (`.gitea/workflows/ci.yaml`)
- **Build Host**: CT 104 (ssh-keycloak-build) auf proxmox-ai
