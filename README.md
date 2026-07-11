# pam-device-auth

Two-factor SSH login: an **SSH key from your directory** plus **OIDC Device Authorization** ([RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)).

Identity (users, groups, home, SSH keys, sudo password) comes from an LDAP directory via **SSSD/NSS**; pam-device-auth adds OIDC (Keycloak, Auth0, Okta, Authentik, …) as a second factor for every SSH login. Built for and validated against Keycloak + [LLDAP](https://github.com/lldap/lldap), but works with any RFC 8628 provider and any POSIX-capable LDAP directory.

Every login requires two factors by default: `publickey` (served from the directory) **and** an OIDC device grant. Identity is directory-backed, so there are no per-host local accounts; users, groups, keys, and the sudo password all live in LDAP. This works on OpenSSH 10.2+, where modules that provision local users on the fly no longer can.

Control stays central: login is gated by an OIDC role, sudo by directory group, and an IP allowlist enforced through a signed JWT claim. Running `pam-device-auth --setup-ldap` wires SSSD, nsswitch, `pam_mkhomedir`, sudoers, and sshd on its own. Pre-existing local accounts that shadow a directory user are migrated automatically. Root stays SSH-key-only and never depends on OIDC or SSSD, so root access survives IdP or directory outages (break-glass). The helper itself is a statically linked, pure-Go binary: no CGO, no runtime dependencies.

## How auth works

```
ssh user@host
  ├─ publickey          → sshd fetches the user's key from LDAP (sss_ssh_authorizedkeys)   [factor 1]
  └─ keyboard-interactive → pam-device-auth runs the OIDC device flow                      [factor 2]
        first login / new IP → browser authorization (URL + code + QR)
        known IP             → silent token refresh (re-validated: role + IP allowlist)
  → shell (home auto-created via pam_mkhomedir)
sudo → re-authenticate with the directory password (members of sudo_role)
```

`AuthenticationMethods publickey,keyboard-interactive:pam` requires **both** factors for non-root logins. Root uses `AuthenticationMethods publickey` against its local `authorized_keys` (break-glass; never OIDC/SSSD).

## Quick start

**Prerequisites**
- LDAP reachable from the host. **LDAPS is recommended**: if the `ldap.uri` uses `ldaps://`, trust the directory's CA on the host (`update-ca-certificates`). Plain `ldap://` or StartTLS also work; the transport is whatever you put in `ldap.uri`.
- Each SSH user in LDAP with: membership in your access group (e.g. `ssh-access`) and admin group (e.g. `ssh-admin`), POSIX `uidNumber`/`gidNumber` (**< 65536** on unprivileged LXC), and an `sshPublicKey`.
- A Keycloak (or other) public client with **Device Authorization Grant** enabled, emitting the access/admin roles (and optionally an IP-allowlist claim).

> **Using [LLDAP](https://github.com/lldap/lldap)?** Use **LLDAP ≥ 0.6.2** (first release with official SSSD support). It ships no POSIX schema, so add these as **custom attributes** (Admin UI → *Attributes*, or GraphQL): on users `uidNumber`, `gidNumber`, `sshPublicKey` (plus your `ip_claim` attribute, for example `clients`, if used); on the access **and** admin groups `gidNumber`. Built-in `uid` and `member` are used as-is; groups are `groupOfNames`/`member` (rfc2307bis), not `posixGroup`. You do **not** need `homeDirectory`/`loginShell`: the wizard sets `override_homedir`/`default_shell`.

**Install** via the APT repository (recommended; pulls `sssd-ldap`/`libnss-sss`/`libpam-sss` via Recommends, with automatic updates):
```bash
curl -fsSL https://apt.nk-it.cloud/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nk-it-cloud.gpg
echo "deb [signed-by=/etc/apt/keyrings/nk-it-cloud.gpg] https://apt.nk-it.cloud/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/nk-it-cloud.list
sudo apt update && sudo apt install pam-device-auth
```
Or install a downloaded package manually: `sudo apt install ./pam-device-auth_<version>_amd64.deb`.

**Configure** (see `configs/config.json`):
```bash
sudo install -m600 /dev/stdin /etc/pam-device-auth/config.json <<'JSON'
{
  "issuer_url": "https://sso.example.com/realms/myrealm",
  "client_id": "ssh-server",
  "required_role": "ssh-access",
  "sudo_role": "ssh-admin",
  "ip_claim": "clients",
  "allowed_algorithms": ["RS256"],
  "ldap": {
    "uri": "ldaps://ldap.example.com:636",
    "base_dn": "dc=example,dc=com",
    "bind_dn": "uid=nss-ro,ou=people,dc=example,dc=com",
    "bind_password": "<read-only bind password>",
    "access_group": "ssh-access",
    "admin_group": "ssh-admin"
  }
}
JSON

sudo pam-device-auth --setup-ldap   # SSSD + nsswitch + mkhomedir + sudoers + sshd drop-in (+ auto-migrate)
sudo pam-device-auth --enable       # activate the PAM/sshd config (restarts sshd)
```

> **Activation order matters:** populate every user's `sshPublicKey` in LDAP *before* `--enable`, or non-root users cannot satisfy the key factor and are locked out (root is unaffected).

CLI: `--check` · `--setup-ldap` · `--enable` · `--debug` · `--version` · `--help`

## Configuration

`/etc/pam-device-auth/config.json` (root-only, `0600`):

| Field | Req | Description |
|-------|-----|-------------|
| `issuer_url` | yes | OIDC issuer URL (https) |
| `client_id` | yes | public OAuth2 client (device grant enabled) |
| `required_role` | yes | OIDC role required to log in (e.g. `ssh-access`) |
| `sudo_role` | no | OIDC role / directory group for sudo (e.g. `ssh-admin`) |
| `ip_claim` | no | JWT claim holding allowed source IPs/CIDRs (empty per-user = unrestricted) |
| `allowed_algorithms` | no | pin accepted JWT `alg` (e.g. `["RS256"]` / `["ES256"]`); empty = any supported |
| `role_claim` | no | extra dotted/flat claim path for roles (supplements Keycloak realm/client roles) |
| `auth_timeout` | no | device-flow timeout, 30-240 s (default 180) |
| `show_qr` | no | `true`/`false`/omit (auto-detect client) |
| **`ldap`** | setup | directory settings for `--setup-ldap`: `uri`, `base_dn`, `bind_dn`, `bind_password`, `access_group`, `admin_group` |

The `ldap.bind_password` is read only by `--setup-ldap`; it is written into the root-only `/etc/sssd/sssd.conf` for SSSD's runtime use. All scalar fields can be overridden via `PAM_DEVICE_AUTH_*` env vars.

## Migration of existing hosts

On a host that already has a **local** account with the same name as a directory user (different uid), nsswitch resolves `files` before `sss`, so the local account would shadow the directory identity. `--setup-ldap` handles this automatically: it kills the user's processes, removes the local account, and re-owns `/home/<user>` to the directory uid:gid; files are preserved and the user then resolves via the directory. Genuine local-only accounts (not present in the directory) are left untouched.

## Security

- **2FA**: directory SSH key **and** OIDC, re-validated every login (signature, issuer, `azp`/`aud`, `exp`/`nbf`/`iat`, required role, IP allowlist). Algorithm/key-type binding (RS/ES 256/384/512), `kid` required, no `none`/HMAC.
- **Directory revocation**: remove a user from the access group → SSSD access filter + role check deny new logins and sudo (within `entry_cache_timeout`). When the `ldap.uri` uses LDAPS, the wizard sets `tls_reqcert = hard`.
- **sudo**: directory password via `pam_sss` for `sudo_role` members; no local passwords or `/etc/shadow` to drift.
- **C PAM shim**: fork/exec (no shell), `clearenv` + whitelisted env, `pipe2(O_CLOEXEC)`, `strtok_r`, SIGPIPE handling, per-call timeout, log sanitization.
- **Cache**: refresh token in tmpfs `/run/pam-device-auth/` (`0700 root:root`, cleared on reboot); known-IP list capped (FIFO). The silent cached-refresh path still requires the SSH key factor.
- **Root break-glass**: key-only, independent of OIDC/SSSD/LDAP availability.

See [SECURITY.md](SECURITY.md) for the threat model and reporting.

## Building from source

```bash
# Go 1.26+, GCC, libpam0g-dev
sudo apt install build-essential libpam0g-dev
make build-all   # Go helper (CGO-free) + C PAM module
make test        # tests with race detector
make deb         # Debian package
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow.

## License

[MIT](LICENSE)
