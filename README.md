# pam-device-auth

SSH authentication via OIDC Device Authorization Grant ([RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)).

Users connect via SSH, see a URL and code (+ QR) in their terminal, authorize in any browser, and the session is granted. Works with any OIDC provider — Keycloak, Auth0, Okta, Authentik.

- **Zero-trust SSH** — every session verified against your identity provider
- **IP-bound sessions** — new IPs require browser re-authorization
- **OIDC IP allowlist** — centrally manage allowed IPs via signed JWT claims
- **Automatic user provisioning** — users created on first login with role-based groups
- **QR code** — scannable device auth URL (auto-detected per client/server)
- **Zero external dependencies** — stdlib + CGO (libxcrypt) only
- **Debian package** — `apt install` with automatic updates

## Quick Start

```bash
# 1. Install
curl -fsSL https://apt.nk-it.cloud/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nk-it-cloud.gpg
echo "deb [signed-by=/etc/apt/keyrings/nk-it-cloud.gpg] https://apt.nk-it.cloud/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/nk-it-cloud.list
sudo apt update && sudo apt install pam-device-auth

# 2. Configure
sudo nano /etc/pam-device-auth/config.json
```

Recommended config (Keycloak example with all features):

```json
{
    "issuer_url": "https://sso.example.com/realms/myrealm",
    "client_id": "ssh-server",
    "required_role": "ssh-access",
    "sudo_role": "ssh-admin",
    "ip_claim": "clients",
    "user_groups": ["users"],
    "admin_groups": ["sudo", "users"]
}
```

Template configs for each provider are in `configs/` (`config-keycloak.json`, `config-auth0.json`, `config-okta.json`, `config-authentik.json`).

```bash
# 3. Validate + activate
sudo pam-device-auth --check
sudo pam-device-auth --enable
```

> PAM is **not activated** on install — root SSH key access always works. See [INSTALL.md](INSTALL.md) for full setup guide including OIDC provider configuration, IP allowlist setup, and troubleshooting.

## How it works

```
New user / new IP:
  SSH → PAM → OIDC Device Auth → URL + Code + QR in terminal
     → User authorizes in browser → JWT validated → User created → Shell

Returning user (known IP):
  SSH → PAM → Password → OIDC Token Refresh → Role check → Shell
```

**First login:** Device auth in browser → user created with temp password → reconnect → set permanent password. **Subsequent logins:** password + background OIDC refresh (~200ms). **New IP:** full device auth again.

### User lifecycle

| Event | Action |
|-------|--------|
| First login | User created, temp password, groups assigned |
| Role revoked | Account locked, cache deleted |
| Role re-granted | Device auth → account unlocked |
| Admin role change | Groups updated on every login |

## Configuration

Config file: `/etc/pam-device-auth/config.json`

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `issuer_url` | Yes | — | OIDC issuer URL |
| `client_id` | Yes | — | OAuth2 client ID (public, no secret) |
| `required_role` | Yes | — | Role claim value required for SSH access |
| `sudo_role` | No | — | Role that grants admin group membership |
| `role_claim` | No | `realm_access.roles` | JWT claim key for roles |
| `ip_claim` | No | — | JWT claim with allowed IPs/CIDRs (centrally managed) |
| `auth_timeout` | No | `180` | Device flow timeout in seconds (30–600) |
| `create_user` | No | `true` | Create local user on first login |
| `user_groups` | No | `["sudo"]` | Groups for normal users |
| `admin_groups` | No | — | Groups for users with `sudo_role` |
| `force_password_change` | No | `true` | Require password change on first login |
| `show_qr` | No | auto | `true` = always, `false` = never, omit = auto-detect |

All fields can be overridden via `PAM_DEVICE_AUTH_*` environment variables (e.g., `PAM_DEVICE_AUTH_ISSUER`).

CLI: `--check` · `--enable` · `--debug` · `--version` · `--help`

### OIDC IP allowlist (`ip_claim`)

When `ip_claim` is set, the OIDC provider controls which IPs can access each user's session. The allowed IPs/CIDRs are read from a signed JWT claim — they cannot be tampered locally. Users without the claim in their token have no IP restriction (backward compatible).

```json
{
    "ip_claim": "clients"
}
```

Requires a matching OIDC token claim, e.g.: `"clients": ["10.0.20.2", "192.168.0.0/16"]`

### QR code display

QR display depends on the **server's OpenSSH version**:

| Server sshd | QR behavior |
|-------------|-------------|
| **OpenSSH 10+** (Debian 13+) | QR for all clients — `vis()` fixed |
| **OpenSSH 9.x** (Ubuntu 24.04) | Auto-detect: QR for PuTTY, Ubuntu, Debian, Fedora clients. Filtered for Win32-OpenSSH, Termux. |

Override with `"show_qr": true` or `"show_qr": false` in config.

### Role-based groups

| User has | Groups | Sudo |
|----------|--------|------|
| `required_role` only | `user_groups` | No |
| `required_role` + `sudo_role` | `admin_groups` | Yes |
| Loses `sudo_role` | Demoted to `user_groups` | No |
| Loses `required_role` | Account locked | — |

## Provider Examples

<details>
<summary><strong>Keycloak</strong></summary>

```json
{
    "issuer_url": "https://sso.example.com/realms/myrealm",
    "client_id": "ssh-server",
    "required_role": "ssh-access"
}
```

Client settings: Public client, Device Authorization Grant enabled, scopes `openid profile email`. Create client role `ssh-access` and assign to users.
</details>

<details>
<summary><strong>Auth0</strong></summary>

```json
{
    "issuer_url": "https://your-tenant.auth0.com",
    "client_id": "your-client-id",
    "required_role": "ssh-access",
    "role_claim": "https://your-app.example.com/roles"
}
```

Enable Device Authorization Grant. Auth0 uses a custom namespace for role claims.
</details>

<details>
<summary><strong>Okta</strong></summary>

```json
{
    "issuer_url": "https://your-org.okta.com/oauth2/default",
    "client_id": "your-client-id",
    "required_role": "ssh-access",
    "role_claim": "groups"
}
```

Enable Device Authorization Grant in your authorization server.
</details>

<details>
<summary><strong>Authentik</strong></summary>

```json
{
    "issuer_url": "https://auth.example.com/application/o/ssh-server",
    "client_id": "ssh-server",
    "required_role": "ssh-access",
    "role_claim": "groups"
}
```

Create an OAuth2/OIDC provider with Device Code flow enabled.
</details>

## Security

**Authentication:** IP-bound sessions, local password + OIDC dual verification, OIDC IP allowlist via signed JWT claims, account locking on role revocation, single password prompt per session.

**Token security:** JWT signature verification (RS/ES 256/384/512) with algorithm/key-type binding, OIDC endpoint HTTPS enforcement, issuer cross-validation, audience binding, shadow TOCTOU elimination.

**C module:** Fork/exec (no shell), bidirectional pipes, password zeroing, fd cleanup, SIGPIPE handling, waitpid timeout, log sanitization.

**Cache:** tmpfs (`/run/pam-device-auth/`), `0700 root:root`, atomic writes, cleared on reboot, KnownIPs capped at 20 (FIFO).

See [SECURITY.md](SECURITY.md) for the full threat model and vulnerability reporting.

## Building from Source

```bash
# Prerequisites: Go 1.26+, GCC, libpam0g-dev, libcrypt-dev
sudo apt install build-essential libpam0g-dev libcrypt-dev

make build-all   # Binary + PAM module
make test        # Tests with race detector
make deb         # Debian package
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development workflow.

## License

[MIT](LICENSE)
