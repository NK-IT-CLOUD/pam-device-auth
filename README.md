# Keycloak SSH Authentication

SSH-Login via Keycloak SSO — PAM-Modul + Go-Binary mit Device Authorization Grant (RFC 8628).

## Architektur

```
SSH Client → PAM Module (C) → keycloak-auth (Go) → Keycloak OIDC
                                    ↓
                              Device Auth Grant (RFC 8628)
                              User öffnet URL + Code im Browser
                                    ↓
                              JWT Verification (JWKS)
                                    ↓
                              User Setup (create + sudo)
```

### Komponenten

| Komponente | Sprache | Beschreibung |
|---|---|---|
| `pam_keycloak.so` | C | PAM-Modul, ruft Go-Binary auf |
| `keycloak-auth` | Go | Device Auth Grant, JWT-Verifizierung, User-Setup |
| Config | JSON | `/etc/keycloak-ssh-auth/keycloak-pam.json` |

### Auth-Flow (Device Authorization Grant)

1. User verbindet per SSH → PAM ruft `keycloak-auth` auf
2. Binary holt Device Code von Keycloak
3. Terminal zeigt Verification-URL + User-Code an:
   ```
   ────────────────────────────────────
   Login: https://sso.nk-it.cloud/realms/nk-it.cloud/protocol/openid-connect/auth/device
   Code:  ABCD-EFGH
   ────────────────────────────────────
   ```
4. User öffnet URL in beliebigem Browser (lokal, Handy, anderes Gerät) und gibt Code ein
5. Binary pollt Token-Endpoint bis Autorisierung erfolgt (RFC 8628)
6. **JWT-Signatur wird via JWKS-Endpoint verifiziert** (RSA/ECDSA)
7. Claims werden geprüft: Issuer, Expiry, Username-Match, Required Role
8. System-User wird erstellt + sudo konfiguriert

Kein lokaler HTTP-Server, kein Browser-Redirect, kein Callback — funktioniert identisch auf headless Servern und Desktop-Terminals.

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

**Voraussetzungen:** Go 1.22+, GCC, libpam0g-dev

## Konfiguration

`/etc/keycloak-ssh-auth/keycloak-pam.json`:

```json
{
    "keycloak_url": "https://sso.nk-it.cloud",
    "realm": "nk-it.cloud",
    "client_id": "ssh-server",
    "required_role": "ssh-access"
}
```

| Feld | Pflicht | Default | Beschreibung |
|------|---------|---------|-------------|
| `keycloak_url` | Ja | — | Keycloak Base-URL |
| `realm` | Ja | — | Keycloak Realm |
| `client_id` | Ja | — | OAuth2 Client ID (Public Client) |
| `required_role` | Ja | — | Benötigte Rolle für SSH-Zugang |
| `auth_timeout` | Nein | 180 | Timeout in Sekunden (30–600) |

Alle Werte können per Umgebungsvariable überschrieben werden:
`KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_REQUIRED_ROLE`, `KEYCLOAK_AUTH_TIMEOUT`

Debug-Modus: `keycloak-auth --debug` (CLI-Flag, kein Config-Feld)

Die Shipped Config funktioniert out-of-the-box auf NKIT-Hosts — kein Editieren nötig nach `dpkg -i`.

## Installation

```bash
# Via .deb Paket (empfohlen)
make install

# Oder manuell
sudo cp build/bin/keycloak-auth /usr/local/bin/
sudo cp pam_keycloak.so /usr/lib/security/
sudo cp configs/keycloak-pam.json /etc/keycloak-ssh-auth/
```

PAM-Konfiguration in `/etc/pam.d/sshd` und SSHD-Config in `/etc/ssh/sshd_config.d/`.

### SSH-Konfiguration

Die SSHD-Config (`10-keycloak-auth.conf`) erlaubt SSH-Key-Fallback:

```
AuthenticationMethods publickey keyboard-interactive
```

SSH-Key-Login funktioniert weiterhin — Device Auth wird nur genutzt wenn kein Key vorhanden.

## Keycloak-Setup

**Client `ssh-server`** im Realm `nk-it.cloud`:

| Setting | Value |
|---------|-------|
| Client Type | Public (kein Secret) |
| Standard Flow | Disabled |
| Direct Access Grants | Disabled |
| Device Authorization Grant | **Enabled** |
| Scopes | `openid profile email` |

**Rolle `ssh-access`**: Als Client-Rolle auf `ssh-server` anlegen, an Admin-User zuweisen.

## Sicherheit

- **JWT-Signatur-Verifizierung** via Keycloak JWKS-Endpoint (RS256, RS384, RS512, ES256, ES384, ES512)
- **OIDC Discovery** beim Start — fail-fast wenn SSO nicht erreichbar
- **Issuer/Expiry/Not-Before** Validation
- **Username-Matching**: SSO-Username muss SSH-Username entsprechen
- **Role-Based Access**: Nur User mit konfigurierter Rolle dürfen sich einloggen
- **Public Client** — kein Secret zu verwalten/rotieren
- **Sudoers Drop-in**: `/etc/sudoers.d/keycloak-ssh-auth` (validiert mit `visudo -cf`)

## Projektstruktur

```
cmd/keycloak-auth/     → Main Binary (Config → Discovery → Device Auth → User Setup)
internal/
  config/              → Config Loading + Validation (5 Felder)
  discovery/           → OIDC Discovery (Endpoints laden)
  device/              → Device Authorization Grant (RFC 8628)
  token/               → JWKS Fetch, JWT Verify, Role Extraction
  user/                → System User Management (create + sudo)
  logger/              → Structured Logging
pam_keycloak.c         → PAM Module (C)
configs/               → Default Configs (Zero-Config für NKIT)
debian/                → Debian Package Files
```

## Repository

- **Repo**: https://git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth
- **CI**: Gitea Actions (`.gitea/workflows/ci.yaml`)
- **Build Host**: CT 104 (ssh-keycloak-build) auf proxmox-ai
- **Test Host**: CT 110 (kc-ssh-test) auf proxmox-ai
