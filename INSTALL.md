# Installation Guide

## Prerequisites

- **OS**: Ubuntu 24.04+ or Debian 13+ (tested on Ubuntu 24.04 LTS)
- **OpenSSH**: version 9.6 or later (for PAM conversation compatibility)
- **Architecture**: amd64

Verify your OpenSSH version:

```bash
ssh -V
# OpenSSH_9.6p1 or later required
```

## Install from .deb Package

Download the latest release and install:

```bash
sudo dpkg -i pam-device-auth_0.3.1_amd64.deb
```

The package installs:

| Component | Path |
|-----------|------|
| Go binary | `/usr/local/bin/pam-device-auth` |
| PAM module | `/usr/lib/security/pam_device_auth.so` |
| Config template | `/etc/pam-device-auth/config.json` |
| SSH config | `/usr/share/pam-device-auth/config/10-pam-device-auth.conf` |
| PAM config | `/usr/share/pam-device-auth/config/pam-sshd-device-auth` |
| Log file | `/var/log/pam-device-auth.log` |
| Token cache | `/run/pam-device-auth/` (tmpfs) |

On first install, the package:
1. Installs binaries and config templates
2. Creates logrotate and tmpfiles entries
3. Does **NOT** activate PAM (prevents lockout with unconfigured OIDC)

On upgrade, existing configuration files are preserved and sshd is restarted.

### Upgrade

```bash
sudo dpkg -i pam-device-auth_0.3.1_amd64.deb
```

Your `config.json`, PAM config, and SSH config are preserved. sshd is restarted automatically.

### Uninstall

```bash
# Remove (keeps config files)
sudo dpkg -r pam-device-auth

# Remove completely (deletes config, logs, cache)
sudo dpkg -P pam-device-auth
```

On removal, the package automatically:
- Restores your original `/etc/pam.d/sshd` from backup
- Removes the sshd config (`10-pam-device-auth.conf`)
- Removes logrotate and tmpfiles entries
- Restarts sshd

OIDC-created local users are **not** deleted. Remove them manually if needed (`userdel -r <username>`).

### Activate PAM

After configuring your OIDC provider:

```bash
# 1. Edit config
sudo nano /etc/pam-device-auth/config.json

# 2. Validate config and test OIDC connectivity
sudo pam-device-auth --check

# 3. Activate PAM authentication (backs up /etc/pam.d/sshd, restarts SSH)
sudo pam-device-auth --enable
```

## Manual Install from Source

```bash
# Install build dependencies
sudo apt install build-essential libpam0g-dev libcrypt-dev golang-go

# Clone and build
git clone https://github.com/NK-IT-CLOUD/pam-device-auth
cd pam-device-auth
make build-all

# Install binaries
sudo cp build/bin/pam-device-auth /usr/local/bin/
sudo chmod 755 /usr/local/bin/pam-device-auth

sudo cp pam_device_auth.so /usr/lib/security/
sudo chmod 755 /usr/lib/security/pam_device_auth.so

# Install config
sudo mkdir -p /etc/pam-device-auth
sudo cp configs/config.json /etc/pam-device-auth/
sudo chmod 600 /etc/pam-device-auth/config.json

# Create cache directory (tmpfs)
sudo mkdir -p /run/pam-device-auth
sudo chmod 700 /run/pam-device-auth

# Persist cache directory across reboots
echo "d /run/pam-device-auth 0700 root root -" | sudo tee /etc/tmpfiles.d/pam-device-auth.conf
```

## OIDC Provider Setup

This example uses Keycloak, but the same principles apply to any OIDC provider.

### Create a Keycloak Client

1. Open the Keycloak admin console
2. Select your realm
3. Go to **Clients** > **Create client**
4. Set the following:

| Setting | Value |
|---------|-------|
| Client ID | `ssh-server` |
| Client type | Public (no client secret) |
| Standard flow | Disabled |
| Direct access grants | Disabled |
| Device Authorization Grant | **Enabled** |
| Valid redirect URIs | (leave empty) |

5. Under **Client scopes**, ensure `openid`, `profile`, and `email` are assigned

### Create the SSH Roles

1. Go to your client > **Roles** > **Create role**
2. Create two roles:
   - `ssh-access` -- required for all SSH users
   - `ssh-admin` -- grants sudo/admin group membership
3. Assign roles to users:
   - Go to **Users** > select user > **Role mapping** > **Assign role**
   - Filter by client, select `ssh-access` for regular users
   - Assign both `ssh-access` and `ssh-admin` to users who need sudo privileges

Users with only `ssh-access` are created as normal users. Users with both `ssh-access` and `ssh-admin` are placed into admin groups (e.g., `sudo`) and can elevate privileges.

### Update config.json

```json
{
    "issuer_url": "https://sso.example.com/realms/myrealm",
    "client_id": "ssh-server",
    "required_role": "ssh-access",
    "sudo_role": "ssh-admin",
    "user_groups": ["users"],
    "admin_groups": ["sudo", "users"]
}
```

With this configuration:

- Users with only `ssh-access` are added to the `users` group (no sudo).
- Users with both `ssh-access` and `ssh-admin` are added to `sudo` and `users` groups.
- If a user loses `ssh-admin`, they are demoted to `users` only on next login.
- If a user loses `ssh-access`, their account is **locked** on next login.

The `issuer_url` is the base URL of your realm. You can verify it works by visiting:

```
https://sso.example.com/realms/myrealm/.well-known/openid-configuration
```

## SSH/PAM Configuration

### PAM Configuration

The `.deb` package installs the PAM config via `--enable`. For manual installs, update `/etc/pam.d/sshd`:

```
# OIDC Device Authorization Grant Authentication
auth       required     pam_device_auth.so
auth       required     pam_env.so
account    required     pam_nologin.so
@include common-account
session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_keyinit.so force revoke
@include common-session
session    optional     pam_motd.so motd=/run/motd.dynamic
session    optional     pam_motd.so noupdate
session    required     pam_limits.so
session    required     pam_env.so
session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale
session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so open
```

### SSH Daemon Configuration

Create or edit `/etc/ssh/sshd_config.d/10-pam-device-auth.conf`:

```
KbdInteractiveAuthentication yes
PermitRootLogin prohibit-password
UsePAM yes
PasswordAuthentication no
MaxAuthTries 6
LogLevel DEBUG1
AuthenticationMethods publickey keyboard-interactive

# Root: SSH key only (no OIDC required)
Match User root
    AuthenticationMethods publickey
```

`LogLevel DEBUG1` is required for auto-detection of Win32-OpenSSH clients (QR code is automatically hidden for PowerShell users). To disable this, set `LogLevel VERBOSE` and configure `"show_qr": true` or `"show_qr": false` explicitly in `config.json`.

Restart sshd after making changes:

```bash
sudo systemctl restart ssh
```

## First Login Flow

1. **First SSH connection**: device auth (QR code + browser confirmation) -- user is created with a temporary password, session disconnects
2. **Second SSH connection**: enter the temp password -- you are prompted to set a permanent password
3. **Subsequent logins from the same IP**: just your password (OIDC session refreshed in background)
4. **Login from a new IP**: full device auth required again (IP-bound sessions)

The temporary password is displayed during the first login. It is used once on the second login and then replaced with your chosen password.

## IP-Bound Sessions

Each client IP must be independently authorized via device auth. Once authorized, the IP is stored in the user's session cache (tmpfs -- cleared on reboot). Subsequent logins from the same IP only require the local password + OIDC token refresh.

- New IP -- full device auth (browser confirmation required)
- Known IP -- local password + OIDC refresh (fast path)
- Server reboot -- all sessions cleared, fresh device auth for everyone

## Upgrading from keycloak-ssh-auth

If you have `keycloak-ssh-auth` installed, the `pam-device-auth` package handles migration automatically:

1. Old config from `/etc/keycloak-ssh-auth/keycloak-pam.json` is preserved as `/etc/pam-device-auth/keycloak-pam.json.migrated`
2. Old logrotate, tmpfiles, and SSH config entries are removed
3. The old package directory `/etc/keycloak-ssh-auth/` is cleaned up

After installing `pam-device-auth`, update your config to use the new format:

**Old format** (`keycloak-pam.json`):
```json
{
    "keycloak_url": "https://sso.example.com",
    "realm": "myrealm",
    "client_id": "ssh-server",
    "required_role": "ssh-access"
}
```

**New format** (`config.json`):
```json
{
    "issuer_url": "https://sso.example.com/realms/myrealm",
    "client_id": "ssh-server",
    "required_role": "ssh-access"
}
```

Key changes:
- `keycloak_url` + `realm` replaced by a single `issuer_url` (the full OIDC issuer URL)
- Config path changed from `/etc/keycloak-ssh-auth/` to `/etc/pam-device-auth/`
- Environment variables changed from `KEYCLOAK_*` to `PAM_DEVICE_AUTH_*`
- New optional fields: `role_claim`, `create_user`, `user_groups`, `sudo_role`, `admin_groups`, `force_password_change`, `show_qr`

## Troubleshooting

### "PAM_USER not set"

The binary must be invoked by the PAM module, not run directly. It reads `PAM_USER` from the environment.

### "OIDC Discovery failed"

- Check that `issuer_url` is correct and reachable from the server
- Verify the `.well-known/openid-configuration` endpoint responds
- Check DNS resolution and firewall rules

### "User lacks required role"

- Verify the user has the configured role assigned in your OIDC provider
- Check `role_claim` if your provider uses a non-standard claim path
- Use `--debug` to see the actual roles extracted from the token

### "Token validation failed"

- Ensure the server clock is synchronized (NTP)
- Verify the JWKS endpoint is reachable
- Check that `client_id` matches the OIDC client configuration

### SSH key login stopped working

- Verify `AuthenticationMethods publickey keyboard-interactive` is set (not `keyboard-interactive` alone)

### QR code shows garbage in PowerShell

Win32-OpenSSH has a [known bug](https://github.com/PowerShell/Win32-OpenSSH/issues/1623) with Unicode rendering. With `LogLevel DEBUG1`, pam-device-auth auto-detects Win32-OpenSSH and hides the QR code. The Link + Code text always works. Alternatively, use PuTTY which renders the QR code correctly.

### Log file location

All authentication events are logged to `/var/log/pam-device-auth.log`. Enable debug mode for verbose output:

```bash
pam-device-auth --debug
```
