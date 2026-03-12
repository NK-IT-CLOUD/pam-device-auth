# Keycloak SSH Authentication

SSH-Login via Keycloak SSO — PAM-Modul + Go-Binary mit Device Authorization Grant (RFC 8628).

**Version:** 0.6.0 | **Voraussetzung:** Ubuntu 24.04+ (OpenSSH >= 9.6)

## Architektur

```
SSH Client → PAM Module (C) → keycloak-auth (Go) → Keycloak OIDC
                                    ↓
                          1. Cache-Prüfung (Refresh Token)
                             → Treffer: Token Refresh → "SSO-Session aktiv."
                             → Kein Treffer: weiter zu 2.
                          2. Device Auth Grant (RFC 8628)
                             → User öffnet URL + Code im Browser
                                    ↓
                          3. JWT Verification (JWKS)
                                    ↓
                          4. User Setup (create + sudo)
```

### Komponenten

| Komponente | Sprache | Beschreibung |
|---|---|---|
| `pam_keycloak.so` | C | PAM-Modul, ruft Go-Binary auf |
| `keycloak-auth` | Go | Device Auth Grant, Token Caching, JWT-Verifizierung, User-Setup |
| Config | JSON | `/etc/keycloak-ssh-auth/keycloak-pam.json` |

### Auth-Flow

1. User verbindet per SSH → PAM ruft `keycloak-auth` auf
2. **Cache-Check**: Existiert ein Refresh Token für den User?
   - **Ja**: Token Refresh via Keycloak → JWT-Validierung → Rolle prüfen → `SSO-Session aktiv.`
   - **Nein** (oder Refresh fehlgeschlagen): weiter mit Device Auth
3. Binary holt Device Code von Keycloak
4. Terminal zeigt Verification-URL + User-Code an:
   ```
   ────────────────────────────────────
   Login: https://sso.nk-it.cloud/realms/nk-it.cloud/device
   Code:  ABCD-EFGH
   ────────────────────────────────────
   ```
5. User öffnet URL in beliebigem Browser (lokal, Handy, anderes Gerät) und gibt Code ein
6. Binary pollt Token-Endpoint bis Autorisierung erfolgt (RFC 8628)
7. **JWT-Signatur wird via JWKS-Endpoint verifiziert** (RSA/ECDSA)
8. Claims werden geprüft: Issuer, Expiry, Username-Match, Required Role
9. Refresh Token wird gecacht für nächsten Login
10. System-User wird erstellt + sudo konfiguriert

Kein lokaler HTTP-Server, kein Browser-Redirect, kein Callback — funktioniert identisch auf headless Servern und Desktop-Terminals.

### Token Caching (v0.6.0)

Refresh Tokens werden in `/run/keycloak-ssh-auth/<user>.json` gecacht (tmpfs — verschwindet bei Reboot). Bei jedem Cache-Hit wird der Token bei Keycloak refreshed — User-Deaktivierung oder Rollen-Entzug wirken sofort.

| Szenario | Verhalten |
|----------|-----------|
| Erster Login | Device Auth (URL + Code) → `Login erfolgreich!` |
| Repeat Login (Cache) | Sofort → `SSO-Session aktiv.` |
| Refresh fehlgeschlagen | Cache gelöscht → Device Auth |
| Reboot | Alle Sessions gelöscht → Device Auth |

## Build

```bash
# Alles bauen (Binary + PAM Module)
make build-all

# Nur Binary
make build

# Nur PAM-Modul
make pam

# Tests
make test

# Debian-Paket
make deb
```

**Build-Voraussetzungen:** Go 1.22+, GCC, libpam0g-dev

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

**Systemanforderung:** Ubuntu 24.04 LTS (OpenSSH >= 9.6, libpam 1.5+)

```bash
# Via .deb Paket (empfohlen)
make install

# Oder manuell
sudo cp build/bin/keycloak-auth /usr/local/bin/
sudo cp pam_keycloak.so /usr/lib/security/
sudo cp configs/keycloak-pam.json /etc/keycloak-ssh-auth/
```

Das .deb-Paket installiert PAM- und SSH-Configs nur bei Erstinstallation. Lokale Anpassungen bleiben bei Upgrades erhalten.

Wichtig: Bei der Erstinstallation sichert `postinst` die bestehende Datei `/etc/pam.d/sshd` nach `/etc/pam.d/sshd.original` und ersetzt sie mit dem Template aus diesem Projekt. Auf Hosts mit angepasstem PAM-Stack sollte die Datei `configs/pam-sshd-keycloak` vor dem Rollout manuell in die bestehende PAM-Konfiguration eingemerged werden.

### SSH-Konfiguration

Die SSHD-Config (`10-keycloak-auth.conf`) erlaubt SSH-Key-Fallback:

```
AuthenticationMethods publickey keyboard-interactive
PermitRootLogin prohibit-password
```

SSH-Key-Login funktioniert weiterhin — Device Auth wird nur genutzt wenn der `keyboard-interactive`/PAM-Pfad gewaehlt wird.

## Keycloak-Setup

**Client `ssh-server`** im Realm `nk-it.cloud`:

| Setting | Value |
|---------|-------|
| Client Type | Public (kein Secret) |
| Standard Flow | Disabled |
| Direct Access Grants | Disabled |
| Device Authorization Grant | **Enabled** |
| Scopes | `openid profile email` |

**Rolle `ssh-access`**: Als Client-Rolle auf `ssh-server` anlegen, an User zuweisen.

## Sicherheit

- **JWT-Signatur-Verifizierung** via Keycloak JWKS-Endpoint (RS256, RS384, RS512, ES256, ES384, ES512)
- **OIDC Discovery** beim Start — fail-fast wenn SSO nicht erreichbar
- **Issuer/Expiry/Not-Before** Validation
- **Authorized Party / Audience Validation**: `azp` oder `aud` muss zur konfigurierten `client_id` passen
- **Username-Matching**: SSO-Username muss SSH-Username entsprechen
- **Role-Based Access**: Nur User mit konfigurierter Rolle dürfen sich einloggen
- **Token Refresh validiert bei Keycloak**: Kein staler Cache — User-Deaktivierung wirkt sofort
- **Cache in tmpfs**: Tokens in `/run/` — verschwindet bei Reboot, nicht auf Disk
- **Cache-Isolation**: Dir `0700 root:root`, Files `0600 root:root`
- **Atomic Writes**: temp + rename verhindert teilweise Reads
- **Path-Traversal-Schutz**: Username-Validierung vor Dateipfad-Konstruktion
- **Public Client** — kein Secret zu verwalten/rotieren
- **Sudoers Drop-in**: `/etc/sudoers.d/keycloak-ssh-auth` (validiert mit `visudo -cf`)

## Projektstruktur

```
cmd/keycloak-auth/     → Main Binary (Config → Discovery → Cache → Device Auth → User Setup)
internal/
  cache/               → Refresh Token Cache (Load/Save/Delete in /run/)
  config/              → Config Loading + Validation
  discovery/           → OIDC Discovery (Endpoints laden)
  device/              → Device Authorization Grant + Token Refresh (RFC 8628)
  token/               → JWKS Fetch, JWT Verify, Role Extraction
  user/                → System User Management (create + sudo)
  logger/              → Structured Logging (unified format)
pam_keycloak.c         → PAM Module (C)
configs/               → Default Configs (Zero-Config für NKIT)
debian/                → Debian Package Files (postinst/postrm)
```

## Logging

Einheitliches Format für PAM-Modul und Go-Binary:

```
2026/03/12 02:13:11 [PAM]    INFO  Authentication attempt for user nk from IP 10.0.88.70
2026/03/12 02:13:11 [SSO-GO] INFO  keycloak-auth 0.6.0 starting
2026/03/12 02:13:24 [SSO-GO] INFO  Cached session found for user: nk
2026/03/12 02:13:24 [SSO-GO] INFO  Token refresh successful
2026/03/12 02:13:24 [SSO-GO] INFO  Auth OK: user=nk email=nk@nk-it.cloud roles=[...]
2026/03/12 02:13:24 [PAM]    INFO  Authentication successful for user nk from IP 10.0.88.70
```

Log-Datei: `/var/log/keycloak-ssh-auth.log` (logrotate konfiguriert)

## Repository

- **Repo**: https://git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth
- **Build Host**: CT 3005 (security-api) auf proxmox-ai
- **Test Host**: CT 110 (kc-ssh-test) auf proxmox-ai
