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
sudo dpkg -i pam-device-auth_1.0.0_amd64.deb
```

The package installs:

| Component | Path |
|-----------|------|
| Go binary | `/usr/local/bin/pam-device-auth` |
| PAM module | `/usr/lib/security/pam_device_auth.so` |
| Config template | `/etc/pam-device-auth/config.json` |
| SSH config | `/etc/ssh/sshd_config.d/10-pam-device-auth.conf` |
| PAM config | `/etc/pam.d/sshd` (original backed up to `sshd.original`) |
| Log file | `/var/log/pam-device-auth.log` |
| Token cache | `/run/pam-device-auth/` (tmpfs) |

On first install, the package:
1. Backs up your existing `/etc/pam.d/sshd` to `/etc/pam.d/sshd.original`
2. Installs the PAM and SSH configurations
3. Creates logrotate and tmpfiles entries
4. Restarts sshd

On upgrade, existing configuration files are preserved.

## Manual Install from Source

```bash
# Install build dependencies
sudo apt install build-essential libpam0g-dev golang-go

# Clone and build
git clone https://github.com/nk-dev/pam-device-auth.git
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

### Create the SSH Access Role

1. Go to your client > **Roles** > **Create role**
2. Name it `ssh-access`
3. Assign this role to users who should have SSH access:
   - Go to **Users** > select user > **Role mapping** > **Assign role**
   - Filter by client, select `ssh-access`

### Update config.json

```json
{
    "issuer_url": "https://sso.example.com/realms/myrealm",
    "client_id": "ssh-server",
    "required_role": "ssh-access"
}
```

The `issuer_url` is the base URL of your realm. You can verify it works by visiting:

```
https://sso.example.com/realms/myrealm/.well-known/openid-configuration
```

## SSH/PAM Configuration

### PAM Configuration

The `.deb` package installs the PAM config automatically. For manual installs, update `/etc/pam.d/sshd`:

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
AuthenticationMethods publickey keyboard-interactive
```

This allows both SSH key and OIDC authentication. SSH key login continues to work -- the device flow only runs when the keyboard-interactive/PAM path is used.

Restart sshd after making changes:

```bash
sudo systemctl restart ssh
```

## Testing Your Setup

### 1. Verify the binary

```bash
pam-device-auth --version
# pam-device-auth 1.0.0
```

### 2. Test with debug logging

```bash
# In one terminal, watch the log:
sudo tail -f /var/log/pam-device-auth.log

# In another terminal, connect:
ssh youruser@hostname
```

### 3. Check OIDC discovery

The binary fetches OIDC endpoints automatically. If discovery fails, you'll see an error in the log. Verify your issuer URL is reachable:

```bash
curl -s https://sso.example.com/realms/myrealm/.well-known/openid-configuration | head -5
```

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
- New optional fields: `role_claim`, `create_user`, `user_groups`, `force_password_change`

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
- This allows either method to succeed independently

### Log file location

All authentication events are logged to `/var/log/pam-device-auth.log`. Enable debug mode for verbose output:

```bash
# Edit the PAM config to pass --debug:
# auth required pam_device_auth.so debug
```
