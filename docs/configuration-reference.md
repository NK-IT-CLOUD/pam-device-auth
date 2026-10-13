# Configuration Reference

All settings live in `/etc/pam-device-auth/config.json` (permissions
`0600 root:root`). Six fields can be overridden at runtime via
`PAM_DEVICE_AUTH_*` environment variables; see [Environment overrides](#environment-overrides).

Identity (users, groups, home directory, SSH keys, sudo password) comes from an
LDAP directory via SSSD/NSS. pam-device-auth is the OIDC layer: it validates an
access token for the SSH user and grants or denies the login. The authentication
path never reads `/etc/shadow`, prompts for a local password, or modifies local
accounts. The separate `--setup-ldap` operation can migrate a local account that
shadows a directory identity; see [Directory Mode Setup](ldap-directory-setup.md#migration-on-existing-hosts-important).

Config is validated on every helper invocation (`pam-device-auth --check` runs
the same validation). Invalid config aborts the call with a logged error; PAM
returns `PAM_AUTH_ERR`.

## Schema

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| [`issuer_url`](#issuer_url) | string | yes | (none) | Full OIDC issuer URL (Keycloak: `https://host/realms/<realm>`). Must be `https://` (or `http://localhost` for development). |
| [`client_id`](#client_id) | string | yes | (none) | OAuth2 client ID. Public client (no secret). Matched against the token's `azp` or `aud`. |
| [`required_role`](#required_role) | string | yes | (none) | Role that must appear in the user's token. Users without it are denied. |
| [`sudo_role`](#sudo_role) | string | no | (none) | OIDC role / directory group that grants sudo (via `pam_sss`). Informational here; enforcement is the directory group. |
| [`role_claim`](#role_claim) | string | no | (none) | Extra dotted JWT claim path for roles, e.g. `groups`. Supplements Keycloak's `realm_access.roles` and `resource_access.<client>.roles`. |
| [`auth_timeout`](#auth_timeout) | int (seconds) | no | `180` | Device-flow polling timeout. Range: 30-240. Capped further by the provider's `expires_in`. |
| [`allowed_algorithms`](#allowed_algorithms) | string[] | no | `[]` (accept all supported) | Pin accepted JWT `alg` header values (e.g. `["RS256"]`). Empty/unset accepts any of RS256/384/512, ES256/384/512. |
| [`show_qr`](#show_qr) | bool (nullable) | no | `null` (auto-detect) | `true` = always render QR, `false` = never, `null` = auto-detect client capability. |
| [`root_login`](#root_login) | string | no | `"key"` | `"key"` keeps root's own SSH key as the emergency path. `"disabled"` refuses every SSH login of root. Applied by `--setup-ldap` and `--enable`. |
| [`required_acr`](#required_acr) | string[] | no | `[]` (no check) | Accepted values of the access token's `acr` claim, exact match. A token without `acr` or with another value is denied. |
| [`root_login_sources`](#root_login_sources) | string[] | no | `[]` | Client IP addresses for which `--check` evaluates root's sshd policy (`Match Address` blocks). Used by `--check` only. |
| [`ldap`](#ldap) | object | setup only | (none) | Directory wiring consumed by `--setup-ldap` to write `/etc/sssd/sssd.conf`. Not used by the auth runtime. |

Unknown fields are ignored; extra fields do not fail validation. (Configs from
older releases that still carry `create_user`, `user_groups`, `admin_groups`,
`force_password_change` or `directory_mode` remain valid; those fields are
ignored.)

## Field details

### `issuer_url`

- Keycloak format: `https://<host>/realms/<realm>`
- Trailing slash is normalised away at load
- Cross-checked against the `issuer` field returned by the `.well-known`
  discovery document; a mismatch is a hard fail (MITM protection)
- Used verbatim as the `iss` check on every token

### `client_id`

- Public OAuth2 client (no secret). Keycloak: **Client type** = OpenID
  Connect, **Client authentication** = Off
- Must have **Device Authorization Grant** enabled
- At validation time, the token must carry either `azp == client_id` or
  an `aud` array containing `client_id`

### `required_role`

- Keycloak realm role is preferred (appears under `realm_access.roles`)
- Client roles also work (`resource_access.<client_id>.roles`)
- Revocation effect: on the next login attempt the token no longer carries the
  role and the helper denies the login (exit 2, `PAM_MAXTRIES`). Because SSSD's
  access control (`ldap_access_filter`, or `simple_allow_groups` with the `ad`
  profile) is also evaluated, removing the user from the access group denies
  login and sudo independently, bounded by the SSSD cache TTL. There is no local
  account to lock.

### `sudo_role`

- The directory **admin group** (e.g. `ssh-admin`) is what actually grants sudo:
  `--setup-ldap` writes `/etc/sudoers.d/pam-device-auth` with `%<admin_group>`,
  and `pam_sss` re-authenticates sudo against the directory password (against
  the KDC with `ldap.kerberos`).
- `sudo_role` names the matching OIDC role for documentation/parity; the helper
  does not assign local groups (SSSD/NSS owns group membership).

### `role_claim`

- Dotted path into the JWT payload, e.g. `groups`, `roles`, or
  `https://example.com/roles` (for Auth0-style namespaced claims)
- Empty string uses the Keycloak-native dual lookup (both `realm_access.roles`
  and `resource_access.<client>.roles`)
- `role_claim` **supplements** the Keycloak lookup: if set, the claim at
  that path is added to the extracted role list. It does not replace the
  Keycloak paths.

### source-IP allowlist (`ip_claim` removed in 0.5.7)

The `ip_claim` setting is gone. Earlier versions read a JWT `clients` claim and
enforced the source-IP allowlist during the OIDC auth phase, which covered only
users who completed OIDC. Since 0.5.6 the PAM account phase
(`pam-device-auth --pam-acct`) enforces the allowlist for **every** directory
login, key-only service accounts included, so the OIDC-side check was redundant
and was retired.

The account-phase gate reads the LDAP `clients` attribute straight from SSSD over
the InfoPipe D-Bus interface (`busctl`), not from a JWT. A directory user without
`clients` is unrestricted; one whose lookup fails is denied (fail-closed). Only
root is exempt. Local non-root accounts are unsupported and fail closed at the
InfoPipe lookup. A config that still carries
`ip_claim` loads without error; the field is ignored. See
[ip-allowlist.md](ip-allowlist.md).

### `auth_timeout`

- Upper bound for the device-flow polling loop
- Effective timeout is `min(auth_timeout, dc.ExpiresIn)`, whichever is
  smaller. Keycloak defaults to `oauth2DeviceCodeLifespan = 600 s`, so
  `auth_timeout = 180` is always the binding constraint in practice.
- Range 30-240. Values outside this are rejected at config load.
- The upper bound 240 leaves 60 s of headroom below the C wrapper's hard
  `AUTH_TOTAL_TIMEOUT_S=300` SIGKILL; raising it above 240 would let PAM
  kill the helper mid-flow.

### `allowed_algorithms`

- JWT `alg` header allowlist. When set to a non-empty array, the helper
  rejects tokens whose header `alg` is not in the list, even if the
  signature verifies against a JWKS key.
- Defaults to accepting any algorithm the verifier supports:
  `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`.
- **Recommended:** pin to your IdP's actual signing algorithm. For
  Keycloak / Authentik / Okta default realms:
  ```json
  "allowed_algorithms": ["RS256"]
  ```
  Realms that sign with ECDSA (e.g. an `ES256`-default realm) should pin
  `["ES256"]` instead: match whatever your IdP's JWKS actually advertises.
- Purpose: closes the algorithm-confusion window if a hostile actor
  influences the JWKS response.

### `show_qr`

| Value | Behaviour |
|---|---|
| `true` | Always render the QR |
| `false` | Never render; show link + code only |
| omitted / `null` | Auto-detect (see `internal/sshclient/detect.go`) |

Auto-detect disables QR for Win32-OpenSSH (broken Unicode rendering) and
Termux (busybox `less`). On OpenSSH 10+ servers the QR is always shown and
no detection runs. On older servers the detection reads the client version
line from sshd's journal; if it finds none, it hides the QR. Detection walks the
parent processes with `journalctl` under one 2 s deadline per login; an
explicit `true`/`false` skips it entirely and is the faster choice on hosts
where the client type is known.

> **sshd logging:** sshd logs the client version line at debug1 only. The
> managed `10-pam-device-auth.conf` therefore sets
> `LogVerbose kex.c:kex_exchange_identification():*`, which forces this one
> line without raising `LogLevel` to DEBUG1 (the drop-in sets `VERBOSE`).
> Without it, auto-detection on OpenSSH < 10 hides the QR for every client; an
> explicit `show_qr` does not need it.

### `root_login`

Controls the emergency SSH path for root. `--setup-ldap`, `--enable` and `--check`
use it; the login itself does not.

| Value | Effect |
|---|---|
| `"key"` or omitted | Root can log in over SSH with a key from its own `~/.ssh/authorized_keys`, with no OIDC step and no dependency on LDAP, SSSD or the identity provider. The sshd drop-in sets `PermitRootLogin prohibit-password` and a `Match User root` block. This is the default. |
| `"disabled"` | The sshd drop-in sets `PermitRootLogin no` and has no block for root. Root cannot log in over SSH. It stays reachable through a console only (hypervisor, serial or provider console). |

To switch the mode, change the value, then run `--setup-ldap` (it rewrites the
drop-in), `--check` and `--enable` (it restarts sshd), in that order. `--enable`
refuses to run while `--check` reports a blocker, and a drop-in that has not been
rewritten yet is one.

`--check` compares the effective sshd policy with the setting. With `"disabled"`,
a root that sshd still lets in is a blocker. With `"key"`, a root that sshd
refuses is a warning, because the emergency path is gone without the config
saying so. sshd takes the first value it reads for `PermitRootLogin`, so a file in
`/etc/ssh/sshd_config.d/` that sorts before `10-pam-device-auth.conf` overrides
the drop-in, and one that sorts after it has no effect.

> **Before you disable root:** nothing that logs in as root over SSH keeps working,
> including automation that uses a root key. Give automation a service account
> (`service_account_groups`) with passwordless sudo (`nopasswd_sudo_groups`), and
> make sure you can reach a console. If LDAP or the identity provider is down,
> the console is then the only way in.

To allow root only from some addresses, keep `"key"`, restrict root in sshd
yourself and list the addresses in [`root_login_sources`](#root_login_sources).

### `required_acr`

Accepted values of the `acr` claim (authentication context class) in the access
token. Empty or absent: no check.

- Values are compared as exact strings. There is no ordering of levels, so list
  every value you accept.
- The helper checks the claim after the device flow and after every refresh of
  the cached login, next to `required_role`. A token whose `acr` is missing is
  denied with `Access denied: the token carries no authentication level (acr);
  the identity provider must add the acr claim (Keycloak: client scope acr).`;
  a token with another value with `Access denied: authentication level "<acr>"
  is not accepted (required: <list>).` Both are hard denies (exit 2), and a
  denied refresh also removes the cached session.
- Each entry must be non-empty and contain no whitespace or control
  characters; otherwise the config does not load.
- `--check` prints the policy (`Token policy: acr must be one of …`) but
  cannot test it: it sees no token.

Keycloak does not enforce a minimum level for the device grant itself. With the
browser flow override from
[keycloak-setup.md](keycloak-setup.md#require-a-strong-factor-in-the-browser)
and the `acr` client scope, the token carries `"3"`, also after a refresh:

```json
"required_acr": ["3"]
```

### `root_login_sources`

Client IP addresses (IPv4 or IPv6; no CIDR range, no host name) for which
`--check` evaluates root's sshd policy, usually the hosts root is meant to log
in from. Only `--check` (and the same preflight in `--enable`) uses them;
nothing writes sshd configuration from them. An entry that is not an IP address
is a config error.

For each address, `--check` evaluates root's effective policy with
`sshd -T -C user=root,addr=<address>` in addition to the run without an
address:

- With `root_login` `"key"` and a global `PermitRootLogin no`, an address from
  which sshd allows root with `prohibit-password` and `AuthenticationMethods
  publickey` is the emergency path: `--check` reports
  `root: publickey only from <addresses> (break-glass via Match Address)`. If no
  address reaches root that way, it warns that there is no emergency path. When
  sshd does not refuse root globally, the addresses do not change the result.
- With `root_login` `"disabled"`, an address from which sshd still allows root
  is a blocker.

OpenSSH up to 10.0 prints `prohibit-password` as `without-password` in
`sshd -T`; both count. The sshd side is yours to write, for example in a file in
`/etc/ssh/sshd_config.d/` that sorts before `10-pam-device-auth.conf` (sshd uses
the first value it reads for `PermitRootLogin`):

```
PermitRootLogin no

Match User root Address 192.0.2.10
    PermitRootLogin prohibit-password
    AuthenticationMethods publickey
```

with `"root_login_sources": ["192.0.2.10"]` in `config.json`.

### `ldap`

Consumed only by `pam-device-auth --setup-ldap`, which writes
`/etc/sssd/sssd.conf` (0600 root). Not read by the auth runtime (SSSD owns the
bind), so it may be absent in the deployed runtime config.

For an Active Directory, set `profile` to `"ad"`; see
[active-directory-setup.md](active-directory-setup.md).

| Key | Description |
|---|---|
| `uri` | Directory URL: one `ldaps://<host>[:port]` or `ldap://<host>[:port]` (for example `ldaps://ldap.example.com:636`). `ldap://` means StartTLS: the generated `sssd.conf` sets `ldap_id_use_start_tls = true`, and SSSD does not talk to the server without TLS. With `kerberos.keytab`, `uri` must be `ldap://`: the bind uses GSSAPI with SASL sealing (`ldap_sasl_minssf = 56`) instead of TLS, and `sssd.conf` sets `ldap_id_use_start_tls = false`; `--setup-ldap` and `--check` reject a keytab with `ldaps://`. There is no cleartext option. LLDAP does not offer StartTLS, so use `ldaps://` with LLDAP. A comma- or whitespace-separated URI list is rejected, because SSSD would treat it as a failover list. `--setup-ldap` and `--check` both enforce this. |
| `base_dn` | Directory base DN, e.g. `dc=example,dc=com`. |
| `bind_dn` | Read-only bind identity for SSSD lookups: a DN, a UPN (`svc-sssd@example.com`) or a down-level logon name (`EXAMPLE\svc-sssd`). With `kerberos.keytab` the Kerberos principal, for example `svc-sssd@EXAMPLE.COM`. |
| `bind_password` | Read-only bind password. Set exactly one of `bind_password` and `bind_password_file` for a password bind, neither with `kerberos.keytab`. Read only at setup time; written into root-only `sssd.conf`. |
| `access_group` | Login gate group (e.g. `ssh-access`). Interactive users: directory SSH key plus OIDC. Becomes part of `ldap_access_filter` (`lldap`) or `simple_allow_groups` (`ad`). |
| `admin_group` | Sudo group (e.g. `ssh-admin`). Members get password sudo via `pam_sss`. Gets the `/etc/sudoers.d` rule. |
| `user_search_base` | Optional. Defaults to `ou=people,<base_dn>` (`lldap`) or `<base_dn>` (`ad`). |
| `group_search_base` | Optional. Defaults to `ou=groups,<base_dn>` (`lldap`) or `<base_dn>` (`ad`). |
| `service_account_groups` | Optional array of directory groups whose members authenticate SSH with a directory key only, no OIDC device flow. For automation and service accounts. Widens the access gate (OR'd with `access_group`) but skips the OIDC factor. Empty or unset: no service tier, every non-root login requires OIDC. |
| `nopasswd_sudo_groups` | Optional array of directory groups granted passwordless sudo (`NOPASSWD:ALL`). Opt-in and admin-declared; empty or unset means only `admin_group` gets (password) sudo. |

Optional keys for the directory layout, the password file and Kerberos:

| Key | Default | Description |
|---|---|---|
| `profile` | `"lldap"` | `"lldap"` (rfc2307bis, `ldap_access_filter`) or `"ad"` (`ldap_schema = ad`, SSSD's simple access provider, nested groups, groups in any OU). Anything else is a config error. |
| `ca_file` | distro CA bundle | Absolute path of the CA bundle written to `ldap_tls_cacert`. `--setup-ldap` and `--check` fail when it does not exist or is not a regular file. It must be readable by the user SSSD runs as: on distributions where `sssd_be` runs as user `sssd`, a file below the 0700 directory `/etc/pam-device-auth` is not readable. Use `/usr/local/share/ca-certificates/` (Debian, Ubuntu) or `/etc/pki/ca-trust/source/anchors/` (RHEL family). |
| `bind_password_file` | (none) | Absolute path of a file that holds the bind password on one line; one trailing newline is stripped. It must be a regular file (no symlink) owned by root, without access for group or others (mode 0600), and at most 4096 bytes long; `--setup-ldap` fails on a longer file. |
| `attributes.username` | `uid` (`lldap`), `sAMAccountName` (`ad`) | LDAP attribute of the login name (`ldap_user_name`). |
| `attributes.ssh_key` | `sshPublicKey` (`lldap`); required for `ad` | LDAP attribute with the SSH public keys (`ldap_user_ssh_public_key`). |
| `attributes.clients` | `clients` (`lldap`); required for `ad` | LDAP attribute with the source-IP allowlist, exposed to the InfoPipe as `clients` (`ldap_user_extra_attrs = clients:<attribute>`). One IP address or CIDR range per value; more than one allowed address needs a multi-valued attribute. A single-valued attribute such as `extensionAttribute1` … `15` or `msDS-cloudExtensionAttribute1` … `20` holds exactly one entry. |
| `id_mapping` | `true` | `ad` only. `true` derives UIDs and GIDs from the objectSid; `false` reads `uidNumber` and `gidNumber` from the directory. |
| `id_range` | (none: SSSD maps from 200000) | `ad` only, needs `id_mapping`. `{"min": 10000, "max": 60000}` with `1000 <= min < max` sets `ldap_idmap_range_min`, `ldap_idmap_range_max` and `ldap_idmap_range_size = max - min` (one ID slice, one domain). Needed in unprivileged containers. |
| `home` | `/home/%u` | Home directory (`override_homedir`). `%u`, `%d` and `%f` are passed to SSSD. |
| `shell` | `/bin/bash` | Login shell (`default_shell`). |
| `kerberos.realm` | (none) | Upper-case realm, e.g. `EXAMPLE.COM`. A `kerberos` block switches `auth_provider` and `chpass_provider` to `krb5`: sudo and `passwd` talk to the KDC, the user password never goes over LDAP. With it, `--setup-ldap` also installs the SSSD Kerberos provider and the SASL GSSAPI plugin. Without it, the `ad` profile sets `chpass_provider = none` (AD does not implement the LDAP password modify operation). Applies to both profiles. |
| `kerberos.kdc` | (none) | KDC host name or address, optionally with a port (`krb5_server`). Required in a `kerberos` block. `--check` warns when it does not resolve. |
| `kerberos.kpasswd` | (none) | Optional password-change server (`krb5_kpasswd`). |
| `kerberos.keytab` | (none) | Absolute path of a keytab for `bind_dn`: a regular file owned by root, mode 0600. Switches the identity bind to GSSAPI (`ldap_sasl_mech = GSSAPI`) and replaces the bind password. Needs an `ldap://` `uri`: the bind is protected by SASL sealing, not TLS. `--setup-ldap` and `--check` fail when it is missing, a symlink, not owned by root or accessible to group or others. |

`--setup-ldap` validates every value before it is written into `sssd.conf` /
`sudoers` (injection guard). Every value, including the bind password and the
content of `bind_password_file`, is rejected when it contains a control
character (newline, tab and the rest of U+0000 to U+001F, U+007F); the error
names the field and never the value. Beyond that:

- `access_group`, `admin_group`, and every entry in `service_account_groups`
  and `nopasswd_sudo_groups` must be a bare Unix group name
  (`[A-Za-z_][A-Za-z0-9_-]*`, so no spaces and no `DOMAIN\`).
- `base_dn`, `user_search_base` and `group_search_base` are constrained to a DN
  charset (`[A-Za-z0-9 ._=,-]`) so they cannot inject directives or alter the
  access filter.
- `bind_dn` is constrained to `[A-Za-z0-9 ._=,@\-]`; with `kerberos.keytab` it
  must be a Kerberos principal (`[A-Za-z0-9._$/-]`, optionally `@` and an
  upper-case realm).
- `attributes.*` must be LDAP attribute names (`[A-Za-z][A-Za-z0-9-]*`).
- `ca_file`, `bind_password_file`, `home`, `shell` and `kerberos.keytab` must be
  absolute paths of `[A-Za-z0-9._%/+-]`.
- `uri` must be a single URL (see above), and `ldap_tls_reqcert = hard` is
  always set.

**Two orthogonal group axes.** SSH auth and sudo are controlled
independently: `access_group` (key plus OIDC) and `service_account_groups`
(key only) both grant SSH login, a user only needs to be in one of them
(the access gate ORs them together). Separately, `admin_group` grants
password sudo and `nopasswd_sudo_groups` grants passwordless sudo. A user
can be in any combination of these four groups.

With the `lldap` profile, any new group referenced here needs a POSIX
**gidNumber** set, or SSSD will not resolve it and the group is effectively
invisible to the access filter and sudoers rules.

`--setup-ldap` also renders the `ifp` (InfoPipe) responder into
`sssd.conf`, which the PAM account-phase IP gate (`--pam-acct`) depends on
to read the `clients` attribute. That responder needs the
`sssd-dbus` package on Debian, Ubuntu and the RHEL family, and `--setup-ldap`
installs it. `pam-device-auth --check` reports IP-pin
posture and InfoPipe health.

## Environment overrides

Every override is a string; numeric fields are parsed with `strconv.Atoi`.
Unset variables leave the file value in place.

| Variable | Overrides |
|---|---|
| `PAM_DEVICE_AUTH_ISSUER` | `issuer_url` |
| `PAM_DEVICE_AUTH_CLIENT_ID` | `client_id` |
| `PAM_DEVICE_AUTH_REQUIRED_ROLE` | `required_role` |
| `PAM_DEVICE_AUTH_SUDO_ROLE` | `sudo_role` |
| `PAM_DEVICE_AUTH_ROLE_CLAIM` | `role_claim` |
| `PAM_DEVICE_AUTH_TIMEOUT` | `auth_timeout` (integer) |

Use cases: CI smoke tests, per-host variation without per-host config
templating, emergency overrides via `/etc/default/<service>`.

## Example configs

### Minimal

```json
{
  "issuer_url": "https://sso.example.com/realms/myrealm",
  "client_id": "ssh-server",
  "required_role": "ssh-access"
}
```

(Sufficient for the auth runtime. The `ldap` block is still required to run
`--setup-ldap` and wire SSSD/NSS.)

### Full (OIDC + directory wiring)

```json
{
  "issuer_url": "https://sso.example.com/realms/myrealm",
  "client_id": "ssh-server",
  "required_role": "ssh-access",
  "sudo_role": "ssh-admin",
  "allowed_algorithms": ["RS256"],
  "auth_timeout": 180,
  "ldap": {
    "uri": "ldaps://ldap.example.com:636",
    "base_dn": "dc=example,dc=com",
    "bind_dn": "uid=nss-ro,ou=people,dc=example,dc=com",
    "bind_password": "<read-only bind password>",
    "access_group": "ssh-access",
    "admin_group": "ssh-admin",
    "service_account_groups": ["ssh-automation"],
    "nopasswd_sudo_groups": ["ssh-nopasswd-admin"]
  }
}
```

### Production template (recommended)

The production reference config is kept outside the repository, on the
deployment host. `configs/config.json` is the template to mirror: copy it and
override only the values that differ.
