# pam-device-auth

SSH authentication via OIDC Device Authorization Grant (RFC 8628).

A PAM module and Go binary that lets users log in to SSH using any OIDC provider -- Keycloak, Auth0, Okta, Authentik, or anything that supports Device Authorization Grant. No browser redirect, no callback server, no external dependencies.

## What is this?

**pam-device-auth** replaces password-based SSH authentication with OIDC single sign-on. When a user connects via SSH, they see a URL and a one-time code in their terminal. They open the URL on any device (phone, laptop, tablet), enter the code, and authenticate with their identity provider. The SSH session is granted automatically.

- **PAM module** (`pam_device_auth.so`) -- C shared library that integrates with sshd
- **Go binary** (`pam-device-auth`) -- handles OIDC discovery, device flow, JWT validation, and user provisioning
- **RFC 8628** -- Device Authorization Grant, designed for input-constrained devices
- **Zero external Go dependencies** -- stdlib + CGO (libxcrypt) only

## How it works

### Authentication flow

```
First login (new user or new IP):

  SSH Client → sshd (PAM) → pam_device_auth.so → pam-device-auth binary
                                                    │
                                       OIDC Discovery (.well-known)
                                                    │
                                       Device Authorization Request
                                                    │
                                 User sees URL + Code + QR in terminal
                                 → Opens browser → Authorizes at OIDC provider
                                                    │
                                       Token Polling (RFC 8628)
                                                    │
                                       JWKS Fetch + JWT Validation
                                                    │
                              Role Check → User Setup → Local Password → Shell


Returning user (known IP, cached session):

  SSH Client → sshd (PAM) → pam_device_auth.so → pam-device-auth binary
                                                    │
                                       Cache found, IP in known list
                                                    │
                                       PROMPT: Password (PAM echo-off)
                                                    │
                                       crypt_r(3) verification vs /etc/shadow
                                                    │
                                       OIDC Token Refresh + Role Check
                                                    │
                                       Access granted → Shell
```

### First-time setup (single device auth)

1. SSH as new user → device auth (QR code + browser) → user created
2. Temporary password is displayed → session disconnects (sshd constraint)
3. SSH again → enter temp password → OIDC refresh → login
4. Shell prompts to set a permanent password → done
5. All subsequent logins from the same IP: password + OIDC refresh (no browser)

### IP-bound sessions

Each client IP must be independently authorized via device auth. Once authorized, the IP is stored in the user's session cache. Subsequent logins from the same IP only require the local password + OIDC token refresh.

- New IP → full device auth (browser confirmation required)
- Known IP → local password + OIDC refresh (fast path)
- Reboot → tmpfs cache cleared, all IPs require fresh device auth

### User lifecycle

| Event | Action |
|-------|--------|
| First OIDC login | User created, temp password set, groups assigned |
| Role revoked in OIDC | Account locked (`usermod --lock`), cache deleted |
| Role re-granted | Device auth succeeds → account unlocked |
| Admin role added/removed | Group memberships updated on every login |
| Username mismatch | Clear error: "authorized as X, but SSH user is Y" |
| Missing required role | Clear error: "lacks required role" |

## Quick Start

### 1. Install

```bash
sudo dpkg -i pam-device-auth_0.3.0_amd64.deb
```

> PAM is **not activated** on install. Root SSH key access continues to work.

Upgrade: `sudo dpkg -i pam-device-auth_<version>_amd64.deb` (config preserved, sshd restarted).
Uninstall: `sudo dpkg -P pam-device-auth` (restores original PAM config, restarts sshd). See [INSTALL.md](INSTALL.md).

### 2. Configure

Edit `/etc/pam-device-auth/config.json`:

```json
{
    "issuer_url": "https://sso.example.com/realms/myrealm",
    "client_id": "ssh-server",
    "required_role": "ssh-access"
}
```

### 3. Check

Validate your config and test OIDC connectivity:

```bash
sudo pam-device-auth --check
# Config OK: issuer=https://sso.example.com/realms/myrealm client=ssh-server role=ssh-access
# OIDC OK: issuer=https://sso.example.com/realms/myrealm
# All checks passed. Run 'pam-device-auth --enable' to activate.
```

### 4. Enable

Activate PAM authentication (restarts SSH automatically):

```bash
sudo pam-device-auth --enable
# PAM config activated
# SSH service restarted
# pam-device-auth is now active.
```

### 5. Test

First login -- device auth + user creation:

```bash
ssh youruser@hostname
# ------------------------------------
# Link:  https://sso.example.com/.../device?user_code=ABCD-EFGH
# Code:  ABCD-EFGH
# [QR code]
# ------------------------------------
# Login successful! User youruser created.
# ------------------------------------
# Temporary password: Kx7mP2qR4bvN
# Use this on your next login.
# You will be asked to set a new password.
# ------------------------------------
# Disconnecting -- please reconnect.
```

Second login -- enter temp password, then set your own:

```bash
ssh youruser@hostname
# Password: [enter temp password]
# ------------------------------------
#   Please set your local password.
# ------------------------------------
# Current password: [enter temp password]
# New password: [your chosen password]
# Retype new password: [confirm]
# Password set successfully.
```

All subsequent logins from the same IP -- just your password:

```bash
ssh youruser@hostname
# Password: [your password]
# ------------------------------------
# Access granted -- password verified, SSO session active.
# ------------------------------------
```

## Configuration

Config file: `/etc/pam-device-auth/config.json`

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `issuer_url` | Yes | -- | OIDC issuer URL (used for discovery) |
| `client_id` | Yes | -- | OAuth2 client ID (public client, no secret) |
| `required_role` | Yes | -- | Role claim value required for SSH access |
| `sudo_role` | No | -- | Role that grants admin group membership (see below) |
| `role_claim` | No | `realm_access.roles` | JWT claim key to extract roles from |
| `auth_timeout` | No | `180` | Device flow timeout in seconds (30--600) |
| `create_user` | No | `true` | Create local Linux user on first login |
| `user_groups` | No | `["sudo"]` | Groups for normal users |
| `admin_groups` | No | -- | Groups for users with `sudo_role` (overrides `user_groups`) |
| `force_password_change` | No | `true` | Set temp password and force change on first login |
| `show_qr` | No | auto | QR code display: `true` = always, `false` = never, omit = auto-detect |

### QR code and Windows/PowerShell

The QR code uses Unicode half-block characters for compact, scannable output. This works in PuTTY, Linux terminals, macOS Terminal, and Windows Terminal.

**Win32-OpenSSH** (PowerShell's `ssh.exe`) has a [known bug](https://github.com/PowerShell/Win32-OpenSSH/issues/1623) where `strnvis()` escapes all UTF-8 bytes >= 0x80 as octal sequences, making the QR code unreadable.

By default, pam-device-auth **auto-detects Win32-OpenSSH** clients (via `LogLevel DEBUG1` in sshd_config) and skips the QR code for them. The Link + Code text is always displayed as a fallback.

| `show_qr` value | Behavior |
|---|---|
| omitted (default) | Auto-detect: QR for PuTTY/Linux, no QR for Win32-OpenSSH |
| `true` | Always show QR (disable auto-detection) |
| `false` | Never show QR |

To disable auto-detection and reduce sshd logging, change `LogLevel DEBUG1` to `LogLevel VERBOSE` in `/etc/ssh/sshd_config.d/10-pam-device-auth.conf` and set `"show_qr": true` or `"show_qr": false` explicitly.

### Role-based group assignment

When `sudo_role` is configured, users are assigned to different groups based on their OIDC roles:

| User has... | Groups assigned | Sudo? |
|---|---|---|
| `required_role` only | `user_groups` | No |
| `required_role` + `sudo_role` | `admin_groups` | Yes |
| Loses `sudo_role` | Demoted to `user_groups`, removed from admin-only groups | No |
| Loses `required_role` | Account locked, SSH access denied | -- |
| Role re-granted | Device auth → account unlocked | Restored |

When `sudo_role` is not set, all users get `user_groups` (backward compatible).

### Environment variable overrides

Every config field can be overridden via environment variables:

| Variable | Overrides |
|----------|-----------|
| `PAM_DEVICE_AUTH_ISSUER` | `issuer_url` |
| `PAM_DEVICE_AUTH_CLIENT_ID` | `client_id` |
| `PAM_DEVICE_AUTH_REQUIRED_ROLE` | `required_role` |
| `PAM_DEVICE_AUTH_SUDO_ROLE` | `sudo_role` |
| `PAM_DEVICE_AUTH_ROLE_CLAIM` | `role_claim` |
| `PAM_DEVICE_AUTH_TIMEOUT` | `auth_timeout` |

Debug mode: `pam-device-auth --debug` (CLI flag, not a config field).

## Provider Examples

### Keycloak

```json
{
    "issuer_url": "https://sso.example.com/realms/myrealm",
    "client_id": "ssh-server",
    "required_role": "ssh-access"
}
```

Client settings in Keycloak admin:
- Client type: **Public** (no client secret)
- Standard flow: Disabled
- Direct access grants: Disabled
- Device Authorization Grant: **Enabled**
- Scopes: `openid profile email`

Create a client role `ssh-access` and assign it to users who should have SSH access.

### Auth0

```json
{
    "issuer_url": "https://your-tenant.auth0.com",
    "client_id": "your-client-id",
    "required_role": "ssh-access",
    "role_claim": "https://your-app.example.com/roles"
}
```

Enable Device Authorization Grant in your Auth0 application settings. Auth0 uses a custom namespace for role claims -- set `role_claim` accordingly.

### Okta

```json
{
    "issuer_url": "https://your-org.okta.com/oauth2/default",
    "client_id": "your-client-id",
    "required_role": "ssh-access",
    "role_claim": "groups"
}
```

Enable Device Authorization Grant in your Okta authorization server. Use `groups` as the role claim to match Okta group membership.

### Authentik

```json
{
    "issuer_url": "https://auth.example.com/application/o/ssh-server",
    "client_id": "ssh-server",
    "required_role": "ssh-access",
    "role_claim": "groups"
}
```

Create an OAuth2/OIDC provider in Authentik with Device Code flow enabled. Authentik exposes group membership in the `groups` claim by default.

## Building from Source

### Prerequisites

- Go 1.22 or later
- GCC + libcrypt-dev (for crypt_r)
- libpam0g-dev

```bash
# Ubuntu/Debian
sudo apt install build-essential libpam0g-dev libcrypt-dev

# Verify Go version
go version  # must be >= 1.22
```

### Make targets

```bash
make build       # Build Go binary only (CGO_ENABLED=1)
make pam         # Build PAM module only
make build-all   # Build binary + PAM module
make test        # Run all tests (with race detector)
make test-unit   # Run unit tests only (./internal/...)
make lint        # Run go vet
make format      # Run go fmt
make deb         # Build Debian package
make release     # Full release (clean + build + deb + tarball)
make install     # Build and install via dpkg
make uninstall   # Remove via dpkg
make clean       # Remove build artifacts
```

## Security

### Authentication hardening

- **IP-bound sessions** -- cached sessions are tied to the client IP; new IPs require full device auth
- **Local password + OIDC** -- returning users must verify both local password and OIDC session
- **Password verification via crypt_r(3)** -- direct shadow hash verification using libxcrypt (no setgid unix_chkpwd dependency)
- **Account locking** -- accounts are locked when OIDC roles are explicitly revoked
- **OIDC issuer cross-validation** -- discovery issuer must match config (MITM protection)
- **Single PROMPT: per session** -- C module limits password prompts to prevent social engineering

### Token and cache security

- **JWT signature verification** via JWKS endpoint (RS256, RS384, RS512, ES256, ES384, ES512)
- **OIDC Discovery** -- fail-fast if the identity provider is unreachable
- **Issuer, expiry, and not-before** validation on every token
- **Audience/authorized party** validation against configured `client_id`
- **Username matching** -- SSO username must match SSH username
- **Token refresh validates at provider** -- user deactivation takes effect immediately
- **Cache in tmpfs** -- refresh tokens stored in `/run/pam-device-auth/`, cleared on reboot
- **Cache isolation** -- directory `0700 root:root`, files `0600 root:root`
- **Atomic cache writes** -- temp file + rename prevents partial reads
- **Path traversal protection** -- username validation before file path construction
- **Public client** -- no client secret to manage or rotate (RFC 8628 design)

### C module hardening

- **Fork/exec with bidirectional pipes** -- replaces popen() for secure Go binary communication
- **PROMPT: protocol** -- password input via PAM conversation (echo-off), limited to 1 per session
- **Password zeroing** -- memory cleared after use regardless of conversation result
- **File descriptor cleanup** -- inherited fds (3..1023) closed in child process
- **Thread-safe IP extraction** -- caller-supplied buffer, no static state

See [SECURITY.md](SECURITY.md) for the security policy and vulnerability reporting.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and PR guidelines.

## License

[MIT](LICENSE)
