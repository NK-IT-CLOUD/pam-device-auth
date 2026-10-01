# pam-device-auth

[![CI](https://img.shields.io/github/actions/workflow/status/NK-IT-CLOUD/pam-device-auth/ci.yml?branch=main&label=CI)](https://github.com/NK-IT-CLOUD/pam-device-auth/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/NK-IT-CLOUD/pam-device-auth)](https://github.com/NK-IT-CLOUD/pam-device-auth/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Browser sign-in as a second factor for SSH, with users, groups and keys in your LDAP directory**

pam-device-auth is a PAM module with a small helper that adds a second factor to
SSH. A user first proves possession of an SSH key. They then approve the login
with your identity provider in a browser, using the OAuth 2.0 Device
Authorization Grant (RFC 8628). Access is granted only when both steps succeed.

Accounts, groups, SSH keys and sudo permissions stay in your central LDAP
directory, so nothing is managed separately on each server.

[Install](INSTALL.md) ·
[Documentation](docs/README.md) ·
[Configuration](docs/configuration-reference.md) ·
[Changelog](CHANGELOG.md) ·
[Security](SECURITY.md)

## Why

SSH keys alone give you no second factor and no central place to switch a person
off. Local accounts and sudo passwords drift between servers, and an admin who
leaves has to be removed host by host.

pam-device-auth keeps the SSH key as the first factor and adds your identity
provider as the second. It moves accounts, keys, groups and sudo rights into the
directory you already run. Removing someone from a directory group stops their
new logins on every host, within SSSD's cache time (up to 10 minutes). Sessions
that are already open stay open.

## How it works

1. The user runs `ssh user@host`.
2. OpenSSH checks the user's public key, which it fetches from LDAP.
3. pam-device-auth displays a URL, a code and an optional QR code.
4. The user approves the login with the identity provider in a browser.
5. pam-device-auth verifies the token, the required role and the optional source
   IP restriction.
6. The shell opens and the home directory is created if needed.

Later logins from a known IP can use a cached refresh token, so the user does not
open the browser every time. The SSH key is still required on every login.
`sudo` asks for the user's directory password. Root uses only its local SSH key
and never depends on LDAP or OIDC.

### Security layers

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/auth-flow-dark.svg">
  <img alt="A non-root SSH login passes three layers on the SSH host. Layer 1: sshd accepts only a public key that SSSD fetches from the LDAP directory; local authorized_keys files are ignored. Layer 2: pam-device-auth runs the OIDC sign-in with the identity provider, through a device flow or a cached refresh, and validates the token and role locally. Layer 3: the PAM account phase checks the per-user source-IP allowlist and the group membership. Service accounts use only their directory key and skip layer 2. Root uses only its local SSH key. A failure in any layer ends the login." src="docs/assets/auth-flow-light.svg" width="100%">
</picture>

Every non-root login passes three independent layers. A failure in any of them
ends the login. Denials in layers 2 and 3 are written to
`/var/log/pam-device-auth.log`; `sshd` logs a rejected key in layer 1.

| Layer | Enforced by | What it checks |
|---|---|---|
| 1. SSH key | `sshd` with `sss_ssh_authorizedkeys` | The public key comes from the directory (`sshPublicKey`). Local `authorized_keys` files are ignored for non-root users. |
| 2. OIDC sign-in | `pam_device_auth.so` (keyboard-interactive) | The user resolves through SSSD. Browser approval through the Device Authorization Grant, or a silent refresh from a known source IP. Token signature, issuer, `azp`/`aud`, `exp`/`nbf`/`iat`, `kid`, username equal to the SSH user, and the required role. |
| 3. Account phase | `pam_device_auth.so --pam-acct` and `pam_sss` | The `clients` source-IP allowlist, which fails closed when it cannot be read. Membership in the access group or a service-account group. |

Service accounts skip layer 2 only: they still need their directory key and pass
layer 3. Root logs in with its local SSH key only and skips layers 2 and 3, so it
keeps working when LDAP, SSSD or the identity provider is down.

#### Layer 2 in detail

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/oidc-sign-in-dark.svg">
  <img alt="After the SSH key is accepted, pam-device-auth checks that the user resolves through SSSD. With a cached session for the same source IP it refreshes the token at the identity provider's token endpoint; otherwise it runs the device flow, where the user opens a link in the browser and approves the code. A rejected refresh clears the cache, a network error keeps it. The token is validated locally against the JWKS, which is cached for 10 minutes: signature, issuer, azp or aud, exp, nbf, iat, kid, the username and the required role. Layer 3 follows." src="docs/assets/oidc-sign-in-light.svg" width="100%">
</picture>

The cache holds the refresh token in tmpfs (`/run/pam-device-auth/`, `0700 root:root`)
and is cleared on reboot.

## Features

- Two factors for every non-root login: a key from the directory and an OIDC
  approval, both checked again on each login.
- Any OIDC provider that supports the device grant. Keycloak with
  [LLDAP](https://github.com/lldap/lldap) is the tested setup, and templates for
  Auth0, Okta and Authentik are included.
- Silent re-login from a known source IP with a cached refresh token.
- Access control through directory groups, with sudo either by directory password
  or passwordless for selected groups.
- Key-only service accounts for automation, in their own directory group, without
  the browser step.
- An optional per-user source IP allowlist, enforced for service accounts too.
- A local root SSH key as an emergency path when LDAP or the identity provider is
  unavailable.
- A preflight check (`--check`) that reports what would lock someone out before
  you activate anything.
- Packages for Debian and Ubuntu (`.deb`, APT repository) and for Rocky Linux
  (`.rpm`). The Go helper is a static binary without CGO.

## What you need

- Ubuntu 24.04+, Debian 13+ or Rocky Linux 9 or 10 on amd64, with OpenSSH 9.6+.
  Other amd64 distributions with OpenSSH 9.6+ and SSSD may work, but they are not
  tested or packaged.
- An LDAP directory containing each user's Unix ID, group membership and SSH
  public key.
- An OIDC provider with the Device Authorization Grant enabled, such as Keycloak,
  Auth0, Okta or Authentik. It must serve its discovery, token and JWKS endpoints
  from the issuer host and issue an access token with `preferred_username`, the
  configured role claim, and either `azp` or a matching `aud`.
- A root SSH-key session during setup, so you can recover from configuration
  mistakes.

pam-device-auth configures SSSD and OpenSSH for this model. It does not replace
LDAP or your identity provider.

## Quick start

The steps below are the short version. [INSTALL.md](INSTALL.md) walks through
each one with the expected output.

### 1. Prepare the directory and the identity provider

- LDAP connectivity from the server. Use LDAPS where possible and install the
  directory CA on the server.
- An access group such as `ssh-access` and an optional sudo group such as
  `ssh-admin`.
- `uidNumber`, `gidNumber` and `sshPublicKey` for every user who should log in.
  On unprivileged LXC containers, keep IDs below 65536.
- A public OIDC client with Device Authorization enabled and the access role
  included in its tokens.

LLDAP does not ship the POSIX and SSH attributes by default, so create them
before configuring the first host (tested with LLDAP 0.6.3):

| Schema | Attribute | Type | List | Value |
|---|---|---|---|---|
| Group | `gidNumber` | Integer | No | unique Unix group ID |
| User | `uidNumber` | Integer | No | unique Unix user ID |
| User | `gidNumber` | Integer | No | primary group ID, usually the access-group ID |
| User | `sshPublicKey` | String | No | complete OpenSSH public key |
| User, optional | `clients` | String | Yes | allowed source IPs or CIDRs |

Every group named in the config needs a `gidNumber`. SSSD drops a group without
one, so its members cannot log in and the sudoers rules never match. Groups stay
`groupOfNames`; do not convert them to `posixGroup`. Numbering, the data model and
the migration of existing hosts are in
[docs/ldap-directory-setup.md](docs/ldap-directory-setup.md).

### 2. Install

Use the APT repository (recommended). It pulls `sssd-ldap`, `libnss-sss`,
`libpam-sss` and `sssd-dbus` as recommended dependencies:

```bash
sudo install -d -m755 /etc/apt/keyrings
curl -fsSL https://apt.nk-it.cloud/gpg.key \
  | sudo gpg --batch --yes --dearmor -o /etc/apt/keyrings/nk-it-cloud.gpg
echo "deb [signed-by=/etc/apt/keyrings/nk-it-cloud.gpg] https://apt.nk-it.cloud/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/nk-it-cloud.list
sudo apt update
sudo apt install pam-device-auth
```

Or install a downloaded package: `sudo apt install ./pam-device-auth_<version>_amd64.deb`.
On Rocky Linux 9 or 10, install the RPM release asset instead:
`sudo dnf install ./pam-device-auth-<version>.x86_64.rpm`.

### 3. Configure

Start from `configs/config.json`:

```bash
sudo install -m600 /dev/stdin /etc/pam-device-auth/config.json <<'JSON'
{
  "issuer_url": "https://sso.example.com/realms/myrealm",
  "client_id": "ssh-server",
  "required_role": "ssh-access",
  "sudo_role": "ssh-admin",
  "allowed_algorithms": ["RS256"],
  "ldap": {
    "uri": "ldaps://ldap.example.com:636",
    "base_dn": "dc=example,dc=com",
    "bind_dn": "uid=nss-ro,ou=people,dc=example,dc=com",
    "bind_password": "<read-only bind password>",
    "access_group": "ssh-access",
    "admin_group": "ssh-admin",
    "service_account_groups": ["ssh-service"],
    "nopasswd_sudo_groups": ["ssh-admin-nopasswd"]
  }
}
JSON
```

The last two `ldap` fields are optional. Members of `service_account_groups` log
in with a directory key only, without the OIDC step, which suits automation
accounts. Members of `nopasswd_sudo_groups` get passwordless sudo. Leave both out
if you do not use those tiers.

### 4. Set up, check and activate

```bash
sudo pam-device-auth --setup-ldap   # SSSD + nsswitch + mkhomedir + sudoers + sshd drop-in (+ auto-migrate)
sudo pam-device-auth --check        # verify OIDC, SSSD, directory keys and effective sshd policy
sudo pam-device-auth --enable       # activate the PAM/sshd config (restarts sshd)
```

> **Activation order matters.** Populate every user's `sshPublicKey` in LDAP
> before `--enable`. Without it, non-root users cannot satisfy the key factor and
> are locked out. Root is unaffected.
>
> **Existing local accounts.** `--setup-ldap` migrates same-name local accounts
> that shadow a directory identity. It prints the full scope, terminates those
> users' processes, removes their local passwd and shadow entries, and re-owns
> their home files. Run it from a persistent root session and read the warning
> before you activate.

`--check` must report no `[FAIL]` items before activation. A `[WARN]` does not
block and can be intentional, for example an access-group member who is
deliberately not provisioned with an SSH key. The
[preflight example](INSTALL.md#5-preflight-check) shows the full output.

Commands: `--check`, `--setup-ldap`, `--enable`, `--pam-acct` (internal, used by
the PAM account phase), `--debug`, `--version`, `--help`.

## Configuration

`/etc/pam-device-auth/config.json` (root-only, `0600`):

| Field | Req | Description |
|-------|-----|-------------|
| `issuer_url` | yes | OIDC issuer URL (https) |
| `client_id` | yes | public OAuth2 client (device grant enabled) |
| `required_role` | yes | OIDC role required to log in (e.g. `ssh-access`) |
| `sudo_role` | no | admin-role label shown by `--check`; sudo enforcement uses `ldap.admin_group` |
| `allowed_algorithms` | no | pin accepted JWT `alg` (e.g. `["RS256"]` / `["ES256"]`); empty = any supported |
| `role_claim` | no | extra dotted/flat claim path for roles (supplements Keycloak realm/client roles) |
| `auth_timeout` | no | device-flow timeout, 30-240 s (default 180) |
| `show_qr` | no | `true`/`false`/omit (auto-detect client) |
| `ldap` | setup/check | directory settings for `--setup-ldap` and the directory preflight: `uri`, `base_dn`, `bind_dn`, `bind_password`, `access_group`, `admin_group`; optional `user_search_base`, `group_search_base`, `service_account_groups`, `nopasswd_sudo_groups` |

`--setup-ldap` reads `ldap.bind_password` and writes it into the root-only
`/etc/sssd/sssd.conf` for SSSD. Environment overrides exist only for
`issuer_url`, `client_id`, `required_role`, `sudo_role`, `role_claim` and
`auth_timeout`, through `PAM_DEVICE_AUTH_ISSUER`, `PAM_DEVICE_AUTH_CLIENT_ID`,
`PAM_DEVICE_AUTH_REQUIRED_ROLE`, `PAM_DEVICE_AUTH_SUDO_ROLE`,
`PAM_DEVICE_AUTH_ROLE_CLAIM` and `PAM_DEVICE_AUTH_TIMEOUT`. Every field is
described in [docs/configuration-reference.md](docs/configuration-reference.md).

### Group model

Two group axes are independent of each other:

- SSH login: `ldap.access_group` gets the normal key and OIDC login. Any group in
  `ldap.service_account_groups` logs in with the SSH key only, which is meant for
  automation and other service accounts. A user needs membership in one of the two
  to log in at all.
- sudo: `ldap.admin_group` gets password sudo through `pam_sss`. Any group in
  `ldap.nopasswd_sudo_groups` gets passwordless sudo (`NOPASSWD:ALL`), written to
  `/etc/sudoers.d/pam-device-auth` by `--setup-ldap`.

### Per-user IP allowlist

The optional `clients` LDAP attribute holds a per-user list of source IPs or
CIDRs. The PAM account phase (`--pam-acct`) enforces it on every login, including
key-only service accounts. It reads `clients` for the logging-in user from the SSSD
InfoPipe over `busctl`. Only root is exempt, because break-glass access must not
depend on SSSD. Local non-root accounts are not a supported login tier and fail
the check closed.

The check fails closed: if the InfoPipe lookup for a directory user errors out,
that login is denied. An SSSD or InfoPipe outage therefore denies all directory
users, not only those with a `clients` value. `--check` reports both the IP-pin
posture and the InfoPipe health, so you can catch this before production. On
Debian and Ubuntu the InfoPipe responder needs the `sssd-dbus` package, which
`--setup-ldap` installs. On RHEL-family systems it ships in `sssd-common`. The
whole pipeline is described in [docs/ip-allowlist.md](docs/ip-allowlist.md).

## Documentation

| Document | What it covers |
|---|---|
| [INSTALL.md](INSTALL.md) | Step-by-step install, preflight output, upgrade, uninstall, installed files |
| [docs/architecture.md](docs/architecture.md) | Components, request flows, the protocol between the C module and the Go helper, cache lifecycle |
| [docs/configuration-reference.md](docs/configuration-reference.md) | Every `config.json` field, with defaults and validation |
| [docs/keycloak-setup.md](docs/keycloak-setup.md) | Keycloak client, roles, mappers, token lifetimes |
| [docs/ldap-directory-setup.md](docs/ldap-directory-setup.md) | Directory data model, host setup, migration of existing hosts, revocation |
| [docs/ip-allowlist.md](docs/ip-allowlist.md) | The source IP allowlist from LDAP to the PAM account phase |
| [docs/operations.md](docs/operations.md) | Logs, monitoring, upgrades, failure modes |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Symptoms and fixes |
| [CHANGELOG.md](CHANGELOG.md) | What changed in each release |

## Known limitations

- Revoking access ends new logins only. Sessions that are already open are not
  terminated.
- An SSSD or InfoPipe outage denies all directory users, because the source IP
  check fails closed.
- Root is not covered by the second factor. Its key-only login is the emergency
  path by design.
- Non-root local accounts are not a supported login tier. Users must exist in the
  directory.
- Keycloak with LLDAP is the tested combination. Auth0, Okta and Authentik have
  config templates but are not covered in depth.
- The packages are built for amd64.

## Security

The first factor is a key from the directory, the second an OIDC approval, and
both are checked on every login. The token is validated locally: signature,
issuer, `azp`/`aud`, `exp`/`nbf`/`iat`, required role, algorithm and key-type
binding (RS and ES, 256/384/512), a required `kid`, and no `none` or HMAC.

- **Source IP allowlist.** Enforced in the PAM account phase for every login. Only
  root is exempt.
- **Directory revocation.** Remove a user from the access group and from its
  mapped OIDC access role. New logins are denied after SSSD and identity-provider
  caches expire. Existing sessions are not terminated.
- **sudo.** Members of `ldap.admin_group` use the directory password through
  `pam_sss`. Members of `ldap.nopasswd_sudo_groups` get `NOPASSWD:ALL`. There are
  no local passwords or `/etc/shadow` entries to drift.
- **C PAM shim.** It uses fork and exec without a shell, `clearenv` with a
  whitelisted environment, `pipe2(O_CLOEXEC)`, `strtok_r`, SIGPIPE handling, a
  per-call timeout and log sanitization.
- **Cache.** The refresh token lives in tmpfs at `/run/pam-device-auth/`
  (`0700 root:root`, cleared on reboot), and the list of known IPs is capped.
  Cached discovery and JWKS documents are read only from a root-owned directory,
  and never through a symlink.
- **Root break-glass.** Key-only, independent of OIDC, SSSD and LDAP.
- **Uninstall.** Removing the package restores the original `/etc/pam.d/sshd`,
  removes the sshd drop-in and deletes the managed `/etc/sudoers.d/pam-device-auth`
  file, so no `NOPASSWD` grant stays behind. This applies to the `.deb` and the
  `.rpm`.

[SECURITY.md](SECURITY.md) has the threat model and how to report a
vulnerability.

## Building from source

```bash
# Go 1.26+, GCC, libpam0g-dev
sudo apt install build-essential libpam0g-dev
make build-all   # Go helper (CGO-free) + C PAM module
make test        # tests with race detector
make deb         # Debian package, built with nfpm from nfpm.yaml
make rpm         # RPM package, from the same nfpm.yaml
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow.

## License

[MIT](LICENSE)
