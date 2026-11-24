# Configuration Reference

All settings live in `/etc/pam-device-auth/config.json` (permissions
`0600 root:root`). For a command run by hand, six fields can be overridden via
`PAM_DEVICE_AUTH_*` environment variables; they do not reach a login. See
[Environment overrides](#environment-overrides).

Identity (users, groups, home directory, SSH keys, sudo password) comes from an
LDAP directory via SSSD/NSS. pam-device-auth is the OIDC layer: it validates an
access token for the SSH user and grants or denies the login. The authentication
path never reads `/etc/shadow`, prompts for a local password, or modifies local
accounts. The separate `--setup-ldap` operation can migrate a local account that
shadows a directory identity; see [Directory Mode Setup](ldap-directory-setup.md#migration-on-existing-hosts-important).

## Unknown keys

A key the loader does not know is ignored, at every level of the file. A
misspelled key such as `requried_acr` would therefore switch its setting off,
so it is reported:

- A login writes one WARN line per finding to `/var/log/pam-device-auth.log`
  (`config: unknown key "requried_acr" is ignored`) and goes on. An upgrade
  never locks a host out over a stray key.
- `--check`, `--enable` and `--setup-ldap` treat each finding as a blocker
  (`[FAIL] config: unknown key …`).

Keys are matched without regard to case. Keys that earlier versions used and
that were removed since (`create_user`, `user_groups`, `admin_groups`,
`force_password_change`, `directory_mode`, `ip_claim` and older ones) are not
reported; a config that still carries them stays valid.

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
| [`auth_timeout`](#auth_timeout) | int (seconds) | no | `180` | How long the helper waits for the approval. Range: 30-240. Capped further by the provider's `expires_in`; sshd's `LoginGraceTime` (default 120 s) bounds the login as a whole. |
| [`allowed_algorithms`](#allowed_algorithms) | string[] | no | `[]` (accept all supported) | Pin accepted JWT `alg` header values (e.g. `["RS256"]`). Empty/unset accepts any of RS256/384/512, ES256/384/512. |
| [`show_qr`](#show_qr) | bool (nullable) | no | `null` (auto-detect) | `true` = always render QR, `false` = never, `null` = auto-detect client capability. |
| [`root_login`](#root_login) | string | no | `"key"` | `"key"` keeps root's own SSH key as the emergency path. `"disabled"` refuses every SSH login of root. Applied by `--setup-ldap` and `--enable`. |
| [`required_acr`](#required_acr) | string[] | no | `[]` (no check) | Accepted values of the access token's `acr` claim, exact match. A token without `acr` or with another value is denied. |
| [`root_login_sources`](#root_login_sources) | string[] | no | `[]` | Client IP addresses for which `--check` evaluates root's sshd policy (`Match Address` blocks). Used by `--check` only. |
| [`break_glass_users`](#break_glass_users) | string[] | no | `[]` | Local accounts that log in with their own SSH key while LDAP, SSSD or the identity provider is down. Applied by `--setup-ldap` and `--enable`, read at every login. |
| [`break_glass_sources`](#break_glass_sources) | string[] | no | `[]` (any address) | Client IP addresses and CIDR ranges the break-glass accounts may log in from. |
| [`ldap`](#ldap) | object | setup only | (none) | Directory wiring consumed by `--setup-ldap` to write `/etc/sssd/sssd.conf`, and checked by `--check`. `ldap.profile` is required in it. Not used by the auth runtime. |

A field that is not in this table is reported; see
[Unknown keys](#unknown-keys). Configs from older releases that still carry
`create_user`, `user_groups`, `admin_groups`, `force_password_change` or
`directory_mode` remain valid; those fields are ignored without a report.

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
root and the accounts in [`break_glass_users`](#break_glass_users) are exempt.
Every other local account is unsupported and fails closed at the InfoPipe
lookup. A config that still carries
`ip_claim` loads without error; the field is ignored. See
[ip-allowlist.md](ip-allowlist.md).

### `auth_timeout`

- How long the helper waits for the approval, counted from the moment the user
  presses Enter at the prompt
- Effective timeout is `min(auth_timeout, expires_in)`, where `expires_in` is
  the lifetime of the device code the provider reports. Keycloak defaults to
  `oauth2DeviceCodeLifespan = 600 s`, so there `auth_timeout` is the smaller
  one.
- Range 30-240. Values outside this are rejected at config load.
- sshd's `LoginGraceTime` bounds the login as a whole, from the moment the
  connection is opened to the end of the OIDC step, and its default of 120 s
  is shorter than the default `auth_timeout`. With the defaults sshd therefore
  ends the login two minutes after the connection was opened, whatever
  `auth_timeout` says. To use a longer wait, set `LoginGraceTime` in a file in
  `/etc/ssh/sshd_config.d/` that sorts before `10-pam-device-auth.conf`; see
  [troubleshooting](troubleshooting.md#the-login-ends-after-two-minutes-timeout-before-authentication).
- The upper bound 240 leaves 60 s of headroom below the PAM module's own limit
  for the OIDC step (`AUTH_TOTAL_TIMEOUT_S`, 300 s), after which it stops the
  helper.

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
- An entry the verifier does not support (`rs256`, `PS256`, `none`) never
  matches a token. It is reported like an unknown key (see
  [Unknown keys](#unknown-keys)):
  `config: allowed_algorithms: "rs256" is not supported (supported: RS256, RS384, RS512, ES256, ES384, ES512)`.
  A list without any supported entry is a config error
  (`allowed_algorithms has no supported entry (…)`), because no token could
  ever pass.
- Purpose: closes the algorithm-confusion window if a hostile actor
  influences the JWKS response.

### `show_qr`

| Value | Behaviour |
|---|---|
| `true` | Always render the QR |
| `false` | Never render; show link + code only |
| omitted / `null` | Auto-detect (see `internal/sshclient/detect.go`) |

Auto-detect decides per SSH client, on every OpenSSH version of the server:
whether the QR survives depends on the client, which may escape the UTF-8 block
characters. The detection reads the client version line from sshd's journal:

| Client version | QR |
|---|---|
| Distribution build (contains `Ubuntu`, `Debian`, `Fedora`, `Red Hat` or `RHEL`) | shown |
| PuTTY | shown |
| Plain `OpenSSH_<major>` with major 10 or later | shown |
| `OpenSSH_for_Windows_*` (Win32-OpenSSH, any version) | hidden |
| Plain OpenSSH < 10 (for example Termux) | hidden |
| Any other client, or no version line found | hidden |

Link and code are always shown. The device flow logs the detected client and
the decision at INFO, for example
`Directory: SSH client "OpenSSH_for_Windows_9.5", QR hidden (client)`; with an
explicit `show_qr` no client is detected and the line ends in `(configured)`.
Detection walks the parent processes with `journalctl` under one 2 s deadline
per login; an explicit `true`/`false` skips it entirely and is the faster
choice on hosts where the client type is known.

> **sshd logging:** sshd logs the client version line at debug1 only. The
> managed `10-pam-device-auth.conf` therefore sets
> `LogVerbose kex.c:kex_exchange_identification():*`, which forces this one
> line without raising `LogLevel` to DEBUG1 (the drop-in sets `VERBOSE`). On
> OpenSSH 10, `sshd-session` logs it. Without the line, auto-detection hides the
> QR for every client; an explicit `show_qr` does not need it.

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
saying so, and so is a root whose effective `AuthorizedKeysFile` is `none`
(`root has no key source (AuthorizedKeysFile none); the emergency path does not
work`). sshd takes the first value it reads for `PermitRootLogin`, so a file in
`/etc/ssh/sshd_config.d/` that sorts before `10-pam-device-auth.conf` overrides
the drop-in, and one that sorts after it has no effect.

> **Before you disable root:** nothing that logs in as root over SSH keeps working,
> including automation that uses a root key. Give automation a service account
> (`service_account_groups`) with passwordless sudo (`nopasswd_sudo_groups`), and
> make sure you can reach a console. If LDAP or the identity provider is down,
> the console is then the only way in, unless the host has a break-glass
> account ([`break_glass_users`](#break_glass_users)).
>
> Software that connects from host to host as root over SSH needs root as
> well: the nodes of a Proxmox VE or Proxmox Mail Gateway cluster do, for
> example. Keep `"key"` on such hosts; a break-glass account does not replace
> root there.

To allow root only from some addresses, keep `"key"`, restrict root in sshd
yourself and list the addresses in [`root_login_sources`](#root_login_sources).

### `required_acr`

Accepted values of the `acr` claim (authentication context class) in the access
token. Empty or absent: no check.

- Values are compared as exact strings. There is no ordering of levels, so list
  every value you accept.
- The helper checks the claim after the device flow and after every refresh of
  the cached login, next to `required_role`. After the device flow a token
  whose `acr` is missing is denied with `Access denied: the token carries no
  authentication level (acr); the identity provider must add the acr claim
  (Keycloak: client scope acr).`; a token with another value with `Access
  denied: authentication level "<acr>" is not accepted (required: <list>).`
  Both are hard denies (exit 2).
- After a refresh the same finding is no denial: the helper logs it, removes
  the cached session and starts the device flow, because a new sign-in can
  reach the required level.
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
  which sshd allows root with `prohibit-password`, `AuthenticationMethods
  publickey` and an `AuthorizedKeysFile` other than `none` is the emergency
  path: `--check` reports
  `root: publickey only from <addresses> (break-glass via Match Address)`. An
  address that allows root while its `AuthorizedKeysFile` is `none` is a
  warning: `root is allowed from <addresses> but AuthorizedKeysFile is none
  there; add AuthorizedKeysFile .ssh/authorized_keys to the Match block`,
  followed by `; the emergency path works from <addresses> (publickey)` when
  other addresses do reach root by key. If no address reaches root by key, it
  warns that there is no emergency path. When sshd does not refuse root
  globally, the addresses do not change the result.
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
    AuthorizedKeysFile .ssh/authorized_keys
```

with `"root_login_sources": ["192.0.2.10"]` in `config.json`. Keep the
`AuthorizedKeysFile` line: the drop-in sets `AuthorizedKeysFile none` for
everyone else, and only its own `Match User root` block (with `root_login`
`"key"`) gives root its key file back. With the line, the address keeps root's
`~/.ssh/authorized_keys` whatever the drop-in contains.

### `break_glass_users`

Local accounts that log in with their own SSH key while LDAP, SSSD or the
identity provider is down: a named emergency account next to root, or in its
place when `root_login` is `"disabled"`. Empty or absent: there are none, and
nothing in this section applies.

```json
"break_glass_users": ["breakglass"],
"break_glass_sources": ["192.0.2.0/24"]
```

The package creates neither the account nor its key nor a sudo rule:

1. Create the account, for example `useradd -m -s /bin/bash breakglass`, and
   put the public key into its `~/.ssh/authorized_keys` (home and `.ssh` not
   writable by group or others). Keep the private key where you can reach it
   when the directory is down.
2. If the account needs sudo, give it a rule in `/etc/sudoers.d/`. With a
   locked password the rule has to be `NOPASSWD`.
3. Add the name to `break_glass_users`, run `--check`, then `--enable` (it
   renders the sshd drop-in again and restarts sshd), then `--check` again.

`--enable` is also what applies a later change of this key or of
[`break_glass_sources`](#break_glass_sources): it renders the drop-in again
whenever its break-glass section is not the one the config asks for, also
after the last account was removed. `--setup-ldap` writes the same section.
Between taking a name out of the config and the next `--enable`, sshd still
accepts that account's key; the account phase denies the login.

A name must match `[a-z_][a-z0-9_-]*`, have at most 32 characters and must not
be `root` (root has [`root_login`](#root_login)). An invalid name or a name
listed twice is a config error.

What a listed account gets:

- **sshd.** The drop-in gets a block in front of every other `Match` block:

  ```
  # Break-glass accounts (break_glass_users): local key only, never OIDC or the
  # directory.
  Match User breakglass
      AuthenticationMethods publickey
      AuthorizedKeysFile .ssh/authorized_keys
      AuthorizedKeysCommand none
  ```

  sshd reads no key for the account from the directory:
  `AuthorizedKeysCommand none` keeps it from accepting a key that the
  directory serves for the same name. A user CA that you configured in sshd
  (`TrustedUserCAKeys`) keeps applying to these accounts as to every other
  one; `--check` names it.
- **Account phase.** The account is exempt from the `clients` gate like root,
  but only on local facts, checked in this order: it has an entry in
  `/etc/passwd`; the client address is in `break_glass_sources` when that key
  is set; and its name does not resolve in the directory (`getent -s sss`, at
  most 3 s). A local entry never stands in for a directory identity: when the
  directory knows the name, the login is denied. Only that positive answer
  denies. A stopped SSSD allows the login, and so does one that does not
  answer in time (with a warning in the log): that is the situation the
  account is for.
- **Auth phase.** A listed name gets no OIDC login, whatever the directory says
  about it. With `publickey` alone that phase is not reached.
- **`--setup-ldap`** never migrates a listed account (see "A directory account
  of the same name" below).

Every other local account stays what it was: no key source in sshd and denied
in the account phase.

Log lines of the account phase (`/var/log/pam-device-auth.log`):

| Line | Meaning |
|---|---|
| `pam-acct: user=<name> local break-glass account; exempt, allow` | Allowed. |
| `pam-acct: user=<name> local break-glass account; directory lookup failed (<error>), treated as not in the directory; exempt, allow` | Allowed; SSSD gave no answer within 3 s. |
| `pam-acct: user=<name> is listed in break_glass_users but has no entry in /etc/passwd; deny` | The account does not exist on this host. |
| `pam-acct: user=<name> rhost=<address> break-glass account, address not in break_glass_sources <list>; deny` | The client address is outside the sources. |
| `pam-acct: user=<name> is a break-glass account but the name also resolves in the directory; deny (rename the local account or the directory user)` | The directory has an account of the same name. |
| `pam-acct: user=<name> has a break-glass block in the sshd drop-in but is not in break_glass_users; deny (run 'pam-device-auth --enable')` | The name was taken out of the config, and the drop-in was not rendered since. |

The helper reads only `break_glass_users` and `break_glass_sources` for this
decision. A mistake in another key, which stops every OIDC login, does not
close the emergency path; a `config.json` that is not JSON does, and so does an
invalid entry in one of the two keys (the log then has
`pam-acct: break_glass_users not read, no break-glass exemption: <error>`). An
invalid entry also stops every OIDC login, like any other config error: run
`--check` after a change of these keys, before you close your session.
A log file that cannot be opened does not close it either: the decision is
reported to syslog, as for root.

#### What `--check` reports

With accounts configured, `--check` prints a section `Break-glass accounts:`
with one verdict per account:

| Line | When |
|---|---|
| `[OK]   break-glass <name>: local account (uid <n>), not in the directory, <n> key(s) in <home>/.ssh/authorized_keys, sshd: publickey only` | The path works. With sources the line goes on with ` from <sources>, no key source from any other address`, and on a host with `TrustedUserCAKeys` with `; certificates of the user CA <file> are accepted as well (TrustedUserCAKeys)`. |
| `[FAIL] break-glass <name>: the name also resolves in the directory; logins of this account are denied until the local account or the directory user is renamed` | See below. A blocker: `--enable` refuses to run. |
| `[FAIL] break-glass <name>: the name is a directory user and has no entry in /etc/passwd; a listed name never logs in through the directory on this host. Take the name out of break_glass_users` | A directory user was listed. That user cannot log in to this host while the name is in the list. |
| `[WARN] break-glass <name>: no entry in /etc/passwd; the package does not create the account` | The account is missing. |
| `[WARN] break-glass <name>: the directory lookup failed (<error>); whether the name also exists in the directory was not checked` | SSSD gave no answer within 3 s. A login of a local account is allowed in that state. The line also follows `no entry in /etc/passwd`: the name may then be a directory user listed by mistake, which is the blocker above once SSSD answers. |
| `[WARN] break-glass <name>: no valid key in <home>/.ssh/authorized_keys` | No file, or no line `ssh-keygen -l` accepts. |
| `[WARN] break-glass <name>: sshd will not use <home>/.ssh/authorized_keys: <path> …` | The home, `.ssh` or the file `belongs to uid <n>, not to the account or root`, `is writable by group or others (mode <mode>)` or `cannot be entered by the account` (the file: `cannot be read by the account`; sshd opens it as the account, so a key file that only root can read does not count), or the file `is not a regular file`. |
| `[WARN] break-glass <name>: the account expired on <date>; pam_unix denies the login (chage -E -1 <name>)` | Account expiry in `/etc/shadow`; a date ahead reads `the account expires on <date>; from then on …`. |
| `[WARN] break-glass <name>: the password reached its maximum age of <n> days on <date>; pam_unix demands a password change at login, which a key-only login cannot complete (chage -M -1 <name>)` | Password aging in `/etc/shadow`; a date ahead reads `the password reaches its maximum age of <n> days on <date>; from then on …`. A password that must be changed at the next login is reported the same way. |
| `[WARN] break-glass <name>: sshd does not apply the break-glass policy from <source> (AuthenticationMethods …, AuthorizedKeysFile …, AuthorizedKeysCommand …); run 'pam-device-auth --enable', and if this line stays look for a file in /etc/ssh/sshd_config.d that sorts before 10-pam-device-auth.conf` | The drop-in was not rendered yet, or another file overrides it: the policy is `publickey`, the key file `.ssh/authorized_keys` and no key command. Without sources `<source>` is `any address`. |
| `[WARN] break-glass <name>: sshd leaves a key source open from addresses outside break_glass_sources (…)` | sshd would read a key for the account from an address the config does not list. |
| `[WARN] break-glass <name>: the sshd drop-in holds another break-glass section than the config asks for; run 'pam-device-auth --enable' (until then the account phase denies what the config no longer allows)` | Accounts or sources changed since the drop-in was rendered. |
| `[WARN] root_login is 'disabled' and no break-glass account is usable; there is no emergency path over SSH if LDAP, SSSD or the identity provider fail` | Root is switched off and every configured account has a finding that stops its login. |

Without accounts the section is absent. One line can still appear: `[WARN] the
sshd drop-in still holds a break-glass section although break_glass_users is
empty; run 'pam-device-auth --enable' to remove it (…)`, after the last name
was taken out of the config and before `--enable` ran.

`--check` asks sshd for the account's policy with
`sshd -T -C user=<name>,addr=<address>`, once per entry of `break_glass_sources`
(for a range with its first address) and once without an address for "any other
address".

#### A directory account of the same name

A break-glass name must not exist in the directory. If it does:

- the login of the local account is denied in the account phase, and `--check`
  reports the `[FAIL]` line above, until one of the two is renamed;
- `--setup-ldap` does not migrate the account. Its last step removes the local
  entry of an account whose name resolves in the directory with another UID
  (see [ldap-directory-setup.md](ldap-directory-setup.md)); for a listed
  account it prints `break-glass account <name> also resolves in the directory
  (uid <n>); it is not migrated, and its logins are denied until the local
  account or the directory user is renamed` and leaves the account as it is.

How soon a host notices such an account depends on its SSSD. SSSD remembers
that a local name is not in the directory, in every one of its services that
was asked about the name. The SSSD of Ubuntu 24.04, Debian 13 and Rocky Linux
9 (2.9 and 2.10) keeps that for `local_negative_timeout`, four hours by
default: a directory account created under the name of a break-glass account
that is already in use is denied and reported after that time, or after
`systemctl restart sssd`. The SSSD of Ubuntu 26.04, Rocky Linux 10 and Fedora
(2.12 and 2.13) sees it within seconds. Until the host notices, the name
stays what it was, the local account, and sshd reads no key for it from the
directory either way.

Whoever can create accounts in the directory can therefore switch this
emergency path off. `--check` shows it; root's own key (`root_login` `"key"`)
has no such dependency.

#### How it differs from root

Root is exempted in the PAM module before the helper is started. A break-glass
account is decided by the helper, and the distribution's account stack applies
to it:

- It needs the helper binary and a `config.json` that parses as JSON. Root
  needs neither.
- `pam_nologin` applies: no login while `/etc/nologin` or `/run/nologin`
  exists (during boot and shutdown).
- `pam_unix` applies: an expired account is denied, and an aged password
  demands a password change that a key-only login cannot complete. Switch
  aging off for the account (`chage -M -1 -E -1 <name>`, and `chage -d <today>
  <name>` when a password change at the next login was forced); `--check`
  warns.
- sudo is yours to set up.
- While SSSD runs but its server does not answer, the first login can take a
  few seconds longer: sshd asks NSS for the account's groups, and the helper
  waits up to 3 s for the directory lookup.
- A directory account of the same name switches the path off (see above).
- `MaxAuthTries` is 3: an SSH agent that offers other keys first uses the
  tries up. Log in with `ssh -o IdentitiesOnly=yes -i <key> <name>@<host>`.

A console stays the last way in. On a host whose software connects as root
over SSH, a break-glass account does not replace root; see the note under
[`root_login`](#root_login).

### `break_glass_sources`

Client addresses the break-glass accounts may log in from: IP addresses and
CIDR ranges, IPv4 and IPv6. Empty or absent: any address. The key applies to
every account in [`break_glass_users`](#break_glass_users).

- Write a range in its network form: `192.0.2.0/24`, not `192.0.2.5/24` (sshd
  refuses a range with bits set after the prefix length). A pattern
  (`192.0.2.*`), a host name, an address with a zone, the IPv4-mapped IPv6
  form (`::ffff:192.0.2.1`) and an entry listed twice are config errors.
- With sources the drop-in has two blocks for the accounts. The first applies
  to the listed addresses; the second leaves every other address without a
  key source:

  ```
  # Break-glass accounts (break_glass_users): local key only, never OIDC or the
  # directory. From an address outside break_glass_sources they have no key source.
  Match User breakglass Address 192.0.2.0/24,2001:db8:1::/48
      AuthenticationMethods publickey
      AuthorizedKeysFile .ssh/authorized_keys
      AuthorizedKeysCommand none
  Match User breakglass
      AuthorizedKeysFile none
      AuthorizedKeysCommand none
  ```

- The account phase compares the client address with the list as well, so a
  narrowed list holds from the next login on, before `--enable` has rendered
  the drop-in again. It gets the address from sshd through PAM: with `UseDNS
  yes` that is a host name, and every break-glass login is denied. `--check`
  warns about `UseDNS yes`.
- Without `break_glass_users` the key does nothing, and that is reported:
  `config: break_glass_sources is set but break_glass_users is empty; it has no
  effect` (a blocker in `--check`, `--enable` and `--setup-ldap`, a line in the
  log at a login).

This key is written into sshd. [`root_login_sources`](#root_login_sources)
is not: it only tells `--check` which addresses to evaluate for root.

### `ldap`

Consumed by `pam-device-auth --setup-ldap`, which writes
`/etc/sssd/sssd.conf` (0600 root), and checked by `--check` and `--enable`.
Not read by the auth runtime (SSSD owns the bind), so it may be absent in the
deployed runtime config; `--check` then warns, and `--setup-ldap` refuses to
run.

For an Active Directory, set `profile` to `"ad"`; see
[active-directory-setup.md](active-directory-setup.md).

| Key | Description |
|---|---|
| `profile` | `"lldap"` (rfc2307bis, `ldap_access_filter`) or `"ad"` (`ldap_schema = ad`, SSSD's simple access provider, nested groups, groups in any OU; the account phase also denies [disabled and expired accounts](active-directory-setup.md#disabled-and-expired-accounts)). There is no default: without it `--setup-ldap`, `--check` and `--enable` fail with `config: ldap.profile is required ("lldap" or "ad")`, and any other value is a config error. On install and upgrade the package runs `pam-device-auth --migrate-config`, which sets `"lldap"` in an `ldap` block without `profile` (or with `null` or `""`) and keeps the original as `config.json.pre-0.7.0`; see [INSTALL.md](../INSTALL.md#upgrade). |
| `uri` | Directory URL: one `ldaps://<host>[:port]` or `ldap://<host>[:port]` (for example `ldaps://ldap.example.com:636`). `ldap://` means StartTLS: the generated `sssd.conf` sets `ldap_id_use_start_tls = true`, and SSSD does not talk to the server without TLS. With `kerberos.keytab`, `uri` must be `ldap://`: the bind uses GSSAPI with SASL sealing (`ldap_sasl_minssf = 56`) instead of TLS, and `sssd.conf` sets `ldap_id_use_start_tls = false`; `--setup-ldap` and `--check` reject a keytab with `ldaps://` or with an IP address as the host (GSSAPI uses the `ldap/<host>` service principal). There is no cleartext option. LLDAP does not offer StartTLS, so use `ldaps://` with LLDAP. A comma- or whitespace-separated URI list is rejected, because SSSD would treat it as a failover list. `--setup-ldap` and `--check` both enforce this. |
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
| `ca_file` | distro CA bundle | Absolute path of the CA bundle written to `ldap_tls_cacert`. `--setup-ldap` and `--check` fail when it does not exist or is not a regular file. It must be readable by the user SSSD runs as: on distributions where `sssd_be` runs as user `sssd`, a file below the 0700 directory `/etc/pam-device-auth` is not readable. Use `/usr/local/share/ca-certificates/` (Debian, Ubuntu) or `/etc/pki/ca-trust/source/anchors/` (Rocky Linux, Fedora). |
| `bind_password_file` | (none) | Absolute path of a file that holds the bind password on one line; one trailing newline is stripped. It must be a regular file (no symlink) owned by root, without access for group or others (mode 0600), and at most 4096 bytes long; `--setup-ldap` fails on a longer file. |
| `attributes.username` | `uid` (`lldap`), `sAMAccountName` (`ad`) | LDAP attribute of the login name (`ldap_user_name`). |
| `attributes.ssh_key` | `sshPublicKey` (`lldap`); required for `ad` | LDAP attribute with the SSH public keys (`ldap_user_ssh_public_key`). |
| `attributes.clients` | `clients` (`lldap`); required for `ad` | LDAP attribute with the source-IP allowlist, exposed to the InfoPipe as `clients` (`ldap_user_extra_attrs = clients:<attribute>`). One IP address or CIDR range per value; more than one allowed address needs a multi-valued attribute. A single-valued attribute such as `extensionAttribute1` … `15` or `msDS-cloudExtensionAttribute1` … `20` holds exactly one entry. |
| `id_mapping` | `true` | `ad` only. `true` derives UIDs and GIDs from the objectSid; `false` reads `uidNumber` and `gidNumber` from the directory. |
| `id_range` | (none: SSSD maps from 200000) | `ad` only, needs `id_mapping`. `{"min": 10000, "max": 60000}` with `1000 <= min < max` sets `ldap_idmap_range_min`, `ldap_idmap_range_max` and `ldap_idmap_range_size = max - min` (one ID slice, one domain). Needed in unprivileged containers. |
| `home` | `/home/%u` | Home directory (`override_homedir`). `%u`, `%d` and `%f` are passed to SSSD. |
| `shell` | `/bin/bash` | Login shell (`default_shell`). It must be an absolute path to a regular file that others may execute (directory users are neither its owner nor in its group): `--setup-ldap` refuses before its first change to the host, `--check` reports a `[FAIL]`. The same check applies to the default. |
| `kerberos.realm` | (none) | Upper-case realm, e.g. `EXAMPLE.COM`. A `kerberos` block switches `auth_provider` and `chpass_provider` to `krb5`: sudo and `passwd` talk to the KDC, the user password never goes over LDAP. With it, `--setup-ldap` also installs the SSSD Kerberos provider and the SASL GSSAPI plugin. Without it, the `ad` profile sets `chpass_provider = none` (AD does not implement the LDAP password modify operation). Applies to both profiles. With the `ad` profile it also sets `krb5_use_enterprise_principal = true` and `ldap_force_upper_case_realm = true`, as SSSD's own ad provider does: SSSD treats the UPN as an enterprise principal and upper-cases its realm, so users whose UPN suffix is the lower-case DNS domain (`alice@example.com`) authenticate for sudo and `passwd`. |
| `kerberos.kdc` | (none) | KDC host name or address, optionally with a port (`krb5_server`). Required in a `kerberos` block. `--check` warns when it does not resolve. |
| `kerberos.kpasswd` | (none) | Optional password-change server (`krb5_kpasswd`). |
| `kerberos.keytab` | (none) | Absolute path of a keytab for `bind_dn`: a regular file owned by root, mode 0600. Switches the identity bind to GSSAPI (`ldap_sasl_mech = GSSAPI`) and replaces the bind password. Needs an `ldap://` `uri`: the bind is protected by SASL sealing, not TLS. The `uri` must name the DC by host name, the name in its `ldap/` service principal (`ldap://dc1.example.com` for `ldap/dc1.example.com`), and that name must resolve on the host (an `/etc/hosts` entry is enough); `--setup-ldap` and `--check` reject an IP address. The keytab becomes invalid when the service account's password changes. `--setup-ldap` and `--check` fail when it is missing, a symlink, not owned by root or accessible to group or others. Building a keytab with `ktutil` without changing AD: [active-directory-setup.md](active-directory-setup.md#building-a-keytab-without-changing-ad). |

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
`sssd-dbus` package on Debian, Ubuntu, Rocky Linux and Fedora, and `--setup-ldap`
installs it. `pam-device-auth --check` reports IP-pin
posture and InfoPipe health.

## Environment overrides

Six fields can be set through the environment of a command run by hand:
`--check`, `--enable`, `--setup-ldap`, or a login run for a test with
`PAM_USER` and `PAM_RHOST` set. Every override is a string; numeric fields are
parsed with `strconv.Atoi`. Unset variables leave the file value in place.

| Variable | Overrides |
|---|---|
| `PAM_DEVICE_AUTH_ISSUER` | `issuer_url` |
| `PAM_DEVICE_AUTH_CLIENT_ID` | `client_id` |
| `PAM_DEVICE_AUTH_REQUIRED_ROLE` | `required_role` |
| `PAM_DEVICE_AUTH_SUDO_ROLE` | `sudo_role` |
| `PAM_DEVICE_AUTH_ROLE_CLAIM` | `role_claim` |
| `PAM_DEVICE_AUTH_TIMEOUT` | `auth_timeout` (integer) |

The variables do not reach a login that sshd starts: sshd runs the PAM
conversation with an empty environment, so a value in the sshd unit or in
`/etc/default/ssh` changes nothing there. Settings that logins should use
belong in `config.json`. A `--check` run with one of the variables set checks
other values than the logins use. The variables are deprecated; 0.8.0 removes
them.

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
    "profile": "lldap",
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
