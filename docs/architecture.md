# Architecture

pam-device-auth is an OIDC device-authorization-grant backend for SSH. It is
composed of two cooperating processes and a file-backed session cache.

## Components

```
┌──────────────────┐   PAM    ┌──────────────────┐  fork+   ┌──────────────────┐
│                  │─────────▶│                  │─────────▶│                  │
│      sshd        │          │ pam_device_auth  │          │  pam-device-auth │
│                  │◀─────────│    .so  (C)      │◀─────────│     (Go helper)  │
└──────────────────┘  verdict └──────────────────┘   pipes  └──────────────────┘
                                                                      │
                                                             HTTPS    │
                                                                      ▼
                                                             ┌──────────────────┐
                                                             │    Keycloak      │
                                                             │  (OIDC provider) │
                                                             └──────────────────┘
```

| Piece | Path | Role |
|---|---|---|
| PAM module | `/usr/lib/security/pam_device_auth.so` (deb) or `/usr/lib64/security/pam_device_auth.so` (rpm) | Loaded by sshd, spawns the helper, mediates the PAM conversation (auth phase) and the account-phase IP gate |
| Helper binary | `/usr/local/bin/pam-device-auth` | Runs the OIDC flow and verifies the token in the auth phase (identity comes from SSSD/NSS); in the account phase, run as `--pam-acct`, checks the directory `clients` IP allowlist |
| Config | `/etc/pam-device-auth/config.json` | Issuer, client_id, roles, claims, LDAP block (access/admin/service/nopasswd groups) |
| Session cache | `/run/pam-device-auth/<user>.json` (tmpfs, `0700 root:root`) | Refresh token + authorized IPs, cleared on reboot |
| Log | `/var/log/pam-device-auth.log` (`0640 root:adm`) | Auth events, failures, lifecycle |

The package is built with a single [nfpm](https://nfpm.goreleaser.com/) manifest
(`nfpm.yaml`) that produces both the `.deb` and the `.rpm`, so the two
distro packages come from the same file list with per-format overrides
(the `.so` install path differs, everything else is shared). Distro
differences at setup time (Debian/Ubuntu vs. RHEL family: package names,
`pam-auth-update` vs. `authselect`, CA bundle path, `sss_ssh_authorizedkeys`
location, PAM stack include token) are resolved once in `internal/distro`
into a `Profile` struct, so `--setup-ldap` and the maintainer scripts branch
on data instead of on distro name.

## Authentication model

Non-root SSH access for interactive users requires **both** factors (OpenSSH
`AuthenticationMethods publickey,keyboard-interactive:pam`, where the comma means AND):

- **`publickey`**: sshd fetches the user's key from the directory via
  `AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys` (SSSD `ssh` responder,
  `ldap_user_ssh_public_key = sshPublicKey`).
- **`keyboard-interactive`**: `pam_device_auth.so` runs the OIDC Device
  Authorization flow and validates the token (required role). The source-IP
  `clients` allowlist is enforced in the PAM account phase, not here.

Identity, groups, home directory and the sudo password come from the directory
via SSSD/NSS. The authentication path never reads `/etc/shadow`, never prompts
for a local password, and never modifies accounts. The separate, operator-run
`--setup-ldap` command can migrate a pre-existing local account that shadows a
directory user; see [Directory Mode Setup](ldap-directory-setup.md#migration-on-existing-hosts-important).

### Two group axes

Access control runs on two orthogonal group axes in the `ldap` block of
`config.json`, not one:

- **SSH auth tier**: `access_group` (key + OIDC, the interactive path above)
  and the opt-in `service_account_groups` (key-only, no OIDC: automation and
  service accounts that cannot complete a browser device flow). A user needs
  membership in at least one of these groups; the SSSD access filter ORs them
  so either grants login.
- **Sudo tier**: `admin_group` (password sudo via `pam_sss`) and the opt-in
  `nopasswd_sudo_groups` (`NOPASSWD:ALL`, written to the managed sudoers file
  `/etc/sudoers.d/pam-device-auth`).

The two axes are independent: a user can be in a service-account group (no
OIDC) and still be in `nopasswd_sudo_groups`, or in `access_group` without any
sudo group at all. Any new LLDAP group used here needs a POSIX `gidNumber` or
SSSD will not resolve it.

> **Root break-glass:** `Match User root` overrides to `AuthenticationMethods
> publickey` against root's local `authorized_keys`. Root never depends on
> OIDC/SSSD/LDAP availability.

Revocation: removing a user from the access group (or stripping their
`required_role`) denies the next login and sudo. The OIDC factor is mandatory,
and SSSD's `ldap_access_filter` gates `pam_sss` services (login/sudo)
independently, bounded by the SSSD cache TTL. There is no local account to lock.

## Per-login flows

All flows are per-SSH-connection. sshd satisfies the `publickey` factor first
(directory key via `sss_ssh_authorizedkeys`), then invokes PAM for the OIDC
factor. The helper is spawned fresh each time; there is no long-running daemon.

### 1 · Known IP (silent fast path)

```
sshd ──► pam.so ──► helper:
  cache.Load(user) → session found
  clientIP ∈ session.KnownIPs  → true
  OIDC token refresh           → new access token
  JWT validate (iss, azp, exp, sig, kid, iat, role)
  role check                   → ssh-access present
  exit 0                       → PAM_SUCCESS
```

No browser and no password prompt: the user only completed the SSH key
handshake, and the OIDC token is refreshed and re-validated silently.

### 2 · New IP (or cache miss)

```
sshd ──► pam.so ──► helper:
  cache.Load(user)             → session missing / IP unknown
  Device Authorization Grant   → URL + user_code + verification_uri_complete
  print "Link / Code / QR" to SSH terminal (FLUSH)
  poll token endpoint (≤ cfg.AuthTimeout, default 180 s)
  JWT validate                 → ok
  token.username == sshUser    → ok
  role check                   → ssh-access present
  cache.Save(session + clientIP)
  exit 0                       → PAM_SUCCESS
```

The home directory is created by `pam_mkhomedir` in the session phase; the
helper does not provision users or groups.

### 3 · Role / access revocation

At token validation the helper checks `HasRole(result.Roles,
cfg.RequiredRole)`. If the role is gone:

```
  log.Error("access denied: lacks required role …")
  cache.Delete(sshUser)
  print "Access denied: '<user>' lacks required role '<role>'."
  exit 2                        → hard deny (sshd won't retry)
```

Independently, SSSD's `ldap_access_filter` (access group) denies `pam_sss`
for login/sudo once the user is removed from the group. No `usermod` is involved.

### 4 · OIDC transient failure on the fast path

Between a found cache and a fresh access token, several things can go wrong
(refresh rejected, JWKS unreachable, token parse fails):

```
  RefreshToken → fails (or JWKS/validate fails)
  log.Warn(…)
  cache.Delete(sshUser)
  fall through to flow 2 (full device auth)
```

The SSH key factor was already satisfied by sshd. The device flow is still
required. If the IdP is still unreachable, flow 2 also fails (PAM_AUTH_ERR).

## Account phase: the `clients` IP gate

`pam_sm_acct_mgmt` in `pam_device_auth.c` runs on every login, including
sudo and key-only service accounts, independently of the auth-phase OIDC
flow above. It enforces the directory-provided `clients` source-IP/CIDR
allowlist:

1. Root is exempt and returns `PAM_SUCCESS` immediately, before any fork or
   network activity. It is the sole break-glass path and never touches the
   helper, SSSD, or the IdP. Local non-root users are not exempt because a
   same-named directory identity could otherwise bypass its IP policy.
2. For every non-root user, the module forks and `execl`s the helper as
   `pam-device-auth --pam-acct`. This run is non-interactive: there is no
   PAM conversation, so no pipes are wired to the child beyond the closed
   fd table; the module only waits for an exit code.
3. The helper (`cmd/pam-device-auth/acct.go`) reads the user's `clients`
   attribute from SSSD over D-Bus (`busctl … GetUserAttr sas <user> 1
   clients`, the SSSD InfoPipe `ifp` responder) and compares it against
   `PAM_RHOST`.
4. The module waits up to 7 seconds (`ACCT_TOTAL_TIMEOUT_S`) for the
   helper. A timeout, a wait error, or any non-0/1 exit code (helper
   crashed, `execl` itself failed) is treated as an infrastructure
   failure and denies the login (fail-closed); exit 0 allows, exit 1 is a
   clean per-user deny.

Fail-closed means an SSSD/InfoPipe outage denies every directory user, not
only the ones with a `clients` allowlist set, until InfoPipe recovers. Users
with no `clients` attribute at all are unrestricted (allow). `pam-device-auth
--check` reports IP-pin posture and InfoPipe health so operators can see this
before it becomes an outage. Full details, including the SSSD `ifp`
responder prerequisite (the `sssd-dbus` package on Debian, Ubuntu and the RHEL
family) and the matching semantics shared with the auth-phase
check, are in [ip-allowlist.md](ip-allowlist.md).

## C ↔ Go IPC protocol

The PAM module (`pam_device_auth.c`) spawns the helper via `fork` + `execl`
with two pipes wired to stdin/stdout in the **auth phase**
(`pam_sm_authenticate`). The account-phase call above does not use this
protocol: it has no conversation, just an exit code. The helper writes
lines terminated by `\n`; the module parses them and responds on the
helper's stdin.

### Line types

| Prefix | Direction | Meaning |
|---|---|---|
| `FLUSH:<text>` | helper → module | Flush all previously buffered info lines and display a visible `PAM_PROMPT_ECHO_ON` with `<text>`. User hits Enter (no password). |
| any other non-empty line | helper → module | Buffered as `PAM_TEXT_INFO`, flushed when the next `FLUSH:` arrives. Up to 64 lines buffered. |
| `\n` | module → helper | Enter response to a prior `FLUSH:` prompt (discarded). |

Directory mode never prompts for a password, so the C module has no `PROMPT:`/secret-relay path: only `FLUSH:` and buffered `PAM_TEXT_INFO`.

### Why batching

OpenSSH 10+ sshd does not render `PAM_TEXT_INFO` until a subsequent prompt
forces a conversation flush. Without `FLUSH:` the device-auth URL, code, and
QR would be invisible to the user until the helper exits. Batching groups
multiple info lines with a single prompt so sshd renders them as one block.

### Timeouts

The PAM module enforces a single per-call deadline of **300 s** over the
entire auth-phase child lifecycle (pipe reads + final `waitpid`). The
account-phase gate above has its own, much shorter, 7 s deadline since it
has no user interaction to wait on. On the auth-phase deadline:

1. read-loop's `poll()` returns zero → break
2. close pipes → child SIGPIPEs on next write, exits
3. `waitpid_until_deadline` polls with `WNOHANG` + 50 ms `nanosleep`
4. if the child is still alive, `SIGKILL` + blocking reap
5. helper program timed out after 300 s → `PAM_SYSTEM_ERR`

There is **no** `SIGALRM` or process-global state; all deadline state is
stack-local per PAM call. This matters because sshd can call
`pam_sm_authenticate` concurrently for multiplexed sessions in the same
process.

### Exit codes (auth phase)

These map the auth-phase helper's exit code to the PAM result sshd sees.
The account-phase helper (`--pam-acct`) uses a different, simpler mapping:
exit 0 allows, exit 1 is a per-user deny, anything else is treated as an
infrastructure failure and denies (see [Account phase](#account-phase-the-clients-ip-gate) above).

| Helper exit | PAM result | Meaning |
|---|---|---|
| 0 | `PAM_SUCCESS` | Authenticated |
| 2 | `PAM_MAXTRIES` | Hard deny: required role missing or revoked; sshd does not retry |
| other | `PAM_AUTH_ERR` | Soft failure (user cancelled, bad password, timeout at device endpoint) |
| killed / timed-out | `PAM_SYSTEM_ERR` | Infrastructure failure |

## Session cache

`internal/cache/cache.go` manages one JSON file per user at
`/run/pam-device-auth/<user>.json` on tmpfs:

```json
{
  "username": "alice",
  "refresh_token": "…",
  "known_ips": ["10.0.20.2", "192.0.2.5"]
}
```

- Written atomically (`os.Rename` from a tmpfile)
- `KnownIPs` capped at 20, FIFO eviction
- `tmpfiles.d` recreates the directory on boot; sessions do not survive reboot
- On role revocation or explicit denial, `cache.Delete` removes the file
  before exiting

## Token validation guarantees

`internal/token/verify.go` applies, in order:

1. JWT shape (three base64url parts)
2. Header parses; `alg` is in the supported set (`RS256/384/512`,
   `ES256/384/512`); `none` is rejected explicitly
3. Header `kid` is non-empty and present in the JWKS map (empty-kid
   collision prevented at both fetch and verify)
4. Signature verifies under the matched key (algorithm-key type binding:
   RS* requires RSA, ES* requires ECDSA in raw JWS r||s form)
5. Issuer equals configured `issuer_url`
6. `azp` matches `client_id`; else `aud` contains `client_id`
7. `exp` is in the future; `nbf` (if present) is in the past
8. `iat` (if present) is not more than 60 s in the future
9. `preferred_username` is present
10. Roles extracted from `realm_access.roles` + `resource_access.<client>.roles`
    (or from a custom `role_claim` path); `required_role` membership enforced

The source-IP `clients` allowlist is enforced separately in the PAM account
phase, not during token validation; see [ip-allowlist.md](ip-allowlist.md).

Violation at any step is logged and the helper exits 1 (soft fail) or 2
(hard deny for role revocation).

## Process security

- PAM module runs in the sshd process, as root
- Helper is spawned as root (PAM context); inherits no extra fds beyond 0/1/2
  (all fds ≥ 3 closed in child pre-execl, up to the descriptor limit)
- Fork + execl uses no shell
- No password is read anywhere: directory mode is OIDC-only (the SSH key factor
  is handled by sshd, the sudo password by `pam_sss`), so the C module has no
  secret-input path
- `SIGPIPE` is ignored in the PAM parent to prevent the helper's exit from
  killing sshd
- No `setuid` helpers; no world-writable paths; cache dir is `0700`, config
  is `0600`, log is `0640 root:adm`
