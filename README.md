# pam-device-auth

SSH authentication via OIDC Device Authorization Grant (RFC 8628).

A PAM module and Go binary that lets users log in to SSH using any OIDC provider -- Keycloak, Auth0, Okta, Authentik, or anything that supports Device Authorization Grant. No browser redirect, no callback server, no external dependencies.

## What is this?

**pam-device-auth** replaces password-based SSH authentication with OIDC single sign-on. When a user connects via SSH, they see a URL and a one-time code in their terminal. They open the URL on any device (phone, laptop, tablet), enter the code, and authenticate with their identity provider. The SSH session is granted automatically.

- **PAM module** (`pam_device_auth.so`) -- C shared library that integrates with sshd
- **Go binary** (`pam-device-auth`) -- handles OIDC discovery, device flow, JWT validation, and user provisioning
- **RFC 8628** -- Device Authorization Grant, designed for input-constrained devices
- **Zero external Go dependencies** -- stdlib only, single static binary

## How it works

```
SSH Client --> sshd (PAM) --> pam_device_auth.so --> pam-device-auth binary
                                                      |
                                         OIDC Discovery (.well-known)
                                                      |
                                         Device Authorization Request
                                                      |
                                   User sees URL + Code in terminal
                                   --> Opens browser --> Logs in at OIDC provider
                                                      |
                                         Token Polling (RFC 8628)
                                                      |
                                         JWKS Fetch + JWT Validation
                                                      |
                                         Role Check --> User Setup --> Shell
```

On repeat logins, a cached refresh token is used instead. The token is refreshed against the OIDC provider on every login, so user deactivation or role removal takes effect immediately.

## Quick Start

### 1. Install

```bash
sudo dpkg -i pam-device-auth_1.0.0_amd64.deb
```

### 2. Configure

Edit `/etc/pam-device-auth/config.json`:

```json
{
    "issuer_url": "https://sso.example.com/realms/myrealm",
    "client_id": "ssh-server",
    "required_role": "ssh-access"
}
```

### 3. Test

```bash
ssh youruser@hostname
# You'll see:
# ────────────────────────────────────
# Login: https://sso.example.com/realms/myrealm/protocol/openid-connect/auth/device
# Code:  ABCD-EFGH
# ────────────────────────────────────
```

Open the URL, enter the code, authorize -- done.

## Configuration

Config file: `/etc/pam-device-auth/config.json`

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `issuer_url` | Yes | -- | OIDC issuer URL (used for discovery) |
| `client_id` | Yes | -- | OAuth2 client ID (public client, no secret) |
| `required_role` | Yes | -- | Role claim value required for SSH access |
| `role_claim` | No | `realm_access.roles` | JSON path to extract roles from the ID token |
| `auth_timeout` | No | `180` | Device flow timeout in seconds (30--600) |
| `create_user` | No | `true` | Create local Linux user on first login |
| `user_groups` | No | `["sudo"]` | Groups to add new users to |
| `force_password_change` | No | `true` | Force password change on first login (for sudo) |

### Environment variable overrides

Every config field can be overridden via environment variables:

| Variable | Overrides |
|----------|-----------|
| `PAM_DEVICE_AUTH_ISSUER` | `issuer_url` |
| `PAM_DEVICE_AUTH_CLIENT_ID` | `client_id` |
| `PAM_DEVICE_AUTH_REQUIRED_ROLE` | `required_role` |
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
- GCC
- libpam0g-dev

```bash
# Ubuntu/Debian
sudo apt install build-essential libpam0g-dev

# Verify Go version
go version  # must be >= 1.22
```

### Make targets

```bash
make build       # Build Go binary only
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

- **JWT signature verification** via JWKS endpoint (RS256, RS384, RS512, ES256, ES384, ES512)
- **OIDC Discovery** -- fail-fast if the identity provider is unreachable
- **Issuer, expiry, and not-before** validation on every token
- **Audience/authorized party** validation against configured `client_id`
- **Username matching** -- SSO username must match SSH username
- **Role-based access control** -- configurable required role
- **Token refresh validates at provider** -- user deactivation takes effect immediately
- **Cache in tmpfs** -- refresh tokens stored in `/run/pam-device-auth/`, cleared on reboot
- **Cache isolation** -- directory `0700 root:root`, files `0600 root:root`
- **Atomic cache writes** -- temp file + rename prevents partial reads
- **Path traversal protection** -- username validation before file path construction
- **Public client** -- no client secret to manage or rotate

See [SECURITY.md](SECURITY.md) for the security policy and vulnerability reporting.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and PR guidelines.

## License

[MIT](LICENSE)
