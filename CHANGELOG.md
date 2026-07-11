# Changelog

All notable changes to this project will be documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [0.5.5] - 2026-07-11

### Fixed
- **Refresh-token rotation is serialized for concurrent SSH sessions.** The
  per-user cache lock now covers the complete load, IdP refresh, validation and
  save/delete transaction, preventing one process from deleting or overwriting
  another process's newly rotated token.
- **Atomic privileged-config writes are durable across crashes.** After replacing
  a config file, `--setup-ldap` now fsyncs the parent directory as well as the
  temporary file.

### Documentation
- Corrected the directory-setup guide to describe the automatic migration of
  same-name local accounts, including process termination and `userdel`.
- Clarified the setup/authentication boundary, SSSD-only troubleshooting command,
  README migration warning and current helper scripts.
- Added the current structured `--check` output, warning semantics and preflight
  links across the README, install, Keycloak, operations and troubleshooting docs.
- Reworked README and INSTALL around user goals and a safe step-by-step path;
  removed duplicated hand-managed PAM/sshd instructions in favor of package setup.
  The APT signing key is now verified before the repository is added.
- Corrected the security model for provider trust/outages, refresh-token IP
  semantics, LDAP transport protection and denial-of-service responsibility.
- Revalidated every public release guide against code, packaging, CI and the
  Ubuntu/Debian test matrix; corrected sudo-role semantics, environment
  overrides, revocation timing, uninstall scope and contributor requirements.

## [0.5.4] - 2026-07-11

### Security
- **Directory mode verifies the SSH user against SSSD only.** The identity
  gate now runs `getent -s sss passwd` instead of a plain NSS lookup, so a
  local-only `/etc/passwd` account can no longer satisfy the directory
  identity check; removing a user's directory identity reliably revokes
  access.
- **sshd drop-in disables local `authorized_keys` for non-root users**
  (`AuthorizedKeysFile none`). SSH keys are served exclusively from the
  directory via `sss_ssh_authorizedkeys`; a same-named local account with a
  local key can no longer supply the first factor. Root break-glass keys are
  unaffected (the `Match User root` block restores the local file). Note for
  upgrades: a package upgrade does not rewrite an existing drop-in at
  `/etc/ssh/sshd_config.d/10-pam-device-auth.conf`. On hosts that already had
  pam-device-auth installed, re-run `pam-device-auth --setup-ldap` (or update
  the drop-in by hand) to apply this hardening; `--check` now warns if
  `AuthorizedKeysFile` is not `none` for non-root.
- **Toolchain bumped to Go 1.26.5** for the crypto/tls and os stdlib security
  fixes (crypto/tls is on the active OIDC/JWKS fetch path).

### Fixed
- **Session cache files are safe against concurrent writes.** Each write uses a
  unique fsynced temp file, and cache load-modify-save updates are
  serialized with a per-user lock. Full refresh-token rotation serialization
  followed in v0.5.5.
- **`--setup-ldap` writes system configs crash-safely.** `/etc/nsswitch.conf`,
  the sudoers drop-in and the sshd drop-in are replaced atomically; a
  previously valid sudoers drop-in is restored (not deleted) if validation
  fails, and an sshd rollback failure is reported instead of ignored.

### Documentation
- README and all docs reviewed for accuracy; removed the stale claim that
  revoking `ssh-access` "locks the local account" (directory mode has no
  local account; the login is hard-denied and the cached session cleared).

## [0.5.3] - 2026-06-10

### Security
- **OIDC discovery: the `http://localhost` development exception no longer
  bypasses the issuer host-pin.** Plain-http endpoints are accepted only when
  the issuer itself is loopback (`localhost`/`127.0.0.1`/`::1`); a tampered
  discovery document for a production HTTPS issuer can no longer point
  `jwks_uri` (the root of signature trust) at a local listener.
- **IdP-supplied verification URI and user code are sanitized before display.**
  C0/C1 control bytes (ANSI/OSC escapes) and raw newlines are replaced with
  `?` before the values reach the SSH client's terminal or the line-based
  PAM relay protocol — a compromised IdP cannot inject terminal escapes or
  forge protocol lines.
- **C module: the client IP is taken exclusively from `PAM_RHOST`.** The
  `SSH_CONNECTION`/`SSH_CLIENT` environment fallbacks were removed; those
  variables never exist in the PAM phase under normal sshd, and any present
  value would be attacker-influencable input to the IP-allowlist check.
- **C module: a failed PAM conversation now aborts authentication**
  (`PAM_CONV_ERR`) instead of sending a phantom acknowledgement that started
  the device flow invisibly on broken/non-interactive PAM stacks.
- **C module: usernames over 255 bytes are rejected** before entering the
  process environment, and the helper's exit status is determined explicitly
  (`waitpid` errors fail closed instead of relying on `WIFEXITED(-1)`
  behaving as hoped).
- **`release.sh` matches the hardened release pipeline:** refuses to overwrite
  an already-published release tag and stages an explicit file allowlist for
  the public mirror instead of the whole `configs/` directory. The
  `make release` tarball likewise copies an explicit config list.

### Fixed
- **IP allowlist: exact entries now match across IPv4/IPv6 notation.** On
  dual-stack sshd a client arriving as `::ffff:192.0.2.10` matches the allowlist
  entry `192.0.2.10` (and vice versa) instead of being hard-denied.
- **`--setup-ldap`: the sssd.conf rollback path is now atomic** (temp file +
  rename), closing the same partial-write window the forward path already
  guarded against.
- **Invalid `PAM_DEVICE_AUTH_TIMEOUT` values are rejected** with an error
  naming the variable instead of being silently ignored.
- **`--debug` now works in any argument position**, including after
  `--check`/`--enable`/`--setup-ldap`.
- **`http://[::1]` accepted as development issuer** alongside
  `localhost`/`127.0.0.1`.
- **Docs: INSTALL.md's manual sshd example enforced only one factor.** The
  example now uses `AuthenticationMethods publickey,keyboard-interactive:pam`
  (comma = both factors required) and `MaxAuthTries 3`, matching the shipped
  configuration; stale log patterns in the operations guide and the man-page
  version were refreshed.

### Fixed
- **Cache username charset** now allows mixed case (`[a-zA-Z0-9_-]{1,32}`), so
  case-preserving LDAP/`preferred_username` values keep a working silent-refresh
  cache instead of falling back to a full device flow on every login. Path
  separators, dots and other metacharacters that could escape the cache
  directory remain excluded.
- **`AddIP` ignores the `unknown`/empty IP sentinels** instead of storing them.
  The cached-refresh path never matches `unknown`, so persisting it only wasted
  a slot in the 20-entry FIFO.
- **`--enable` warns on backup failure.** A failed write of
  `/etc/pam.d/sshd.original` is now surfaced as `[WARN]` instead of being
  silently swallowed behind a misleading "Backed up original PAM config"
  message; an existing backup is never overwritten.

### Security
- **Migrated predecessor config no longer left world-readable.** Upgrading from
  the legacy `keycloak-ssh-auth` package copied `keycloak-pam.json` (historically
  an OIDC `client_secret` / LDAP `bind_password`) to a `0644` file via a bare
  `cp`. It is now `chmod 600` / `chown root:root`, and `/etc/pam-device-auth` is
  created `0700`, so a migrated secret is no longer readable by local users.
- **Log lines are sanitized against ANSI/escape injection.** The Go logger now
  replaces ESC and all other C0/C1 control bytes (not just CR/LF) with `?`,
  matching the C module's `sanitize_for_log`, so an unauthenticated SSH
  username/host cannot inject terminal escapes into the root-owned log.
- **OIDC/JWKS/discovery response bodies are size-bounded** (1 MiB, fail-closed)
  instead of being read with unbounded `io.ReadAll`/decoder — removes a
  memory-exhaustion vector from a hostile (host-pinned) issuer.

### Hardening
- **PAM `.so` built with FORTIFY_SOURCE, stack-protector-strong,
  stack-clash-protection and full RELRO/BIND_NOW** — the root-resident native
  artifact now matches the hardening already applied to the Go helper.
- **`--setup-ldap` writes `sssd.conf` atomically with rollback.** The new config
  is written via temp-file + `rename` and reverted to the prior known-good file
  if `sssd` fails to restart, matching the existing `sshd`/`sudoers` writers —
  a rejected config can no longer leave SSSD down and lock out directory logins.
- **`postrm` removal no longer assumes `@include common-auth`.** On a PAM stack
  without `/etc/pam.d/common-auth` it now inserts `auth required pam_unix.so`
  instead, so uninstall cannot leave non-root SSH login unauthenticatable.
- Device/token HTTP client blocks redirects on the nil-client fallback path too.

### Build
- **Go toolchain bumped to 1.26.4** to clear two stdlib advisories flagged by
  `govulncheck`: GO-2026-5039 (unescaped inputs in `net/textproto` errors,
  reachable via the JWKS/token fetch path) and GO-2026-5037 (inefficient
  hostname parsing in `crypto/x509`). No source changes.
- **Reproducible `.deb`:** `gzip -9n`, `SOURCE_DATE_EPOCH`-clamped member mtimes
  and `dpkg-deb --root-owner-group` make the package byte-identical across
  builds from identical source.

## [0.5.2] - 2026-05-31

### Hardening
- **`--setup-ldap` directory-config validation** is now a single choke point
  (`validateLDAPConfig`) that closes injection gaps in the values written into
  `sssd.conf`/`sudoers`. Previously `user_search_base` and `group_search_base`
  bypassed the newline guard entirely (sssd.conf directive injection — e.g. an
  `ldap_access_filter = (objectClass=*)` override nullifying the per-host login
  gate, or `ldap_tls_reqcert = never` downgrading directory TLS), and the
  group/DN fields were only blocklist-checked. Now: newlines rejected in **all**
  fields; `access_group`/`admin_group` must be bare Unix group names
  (`[A-Za-z_][A-Za-z0-9_-]*`, blocking sudoers-grammar payloads such as a
  smuggled `NOPASSWD: ALL`); `base_dn`/`user_search_base`/`group_search_base`
  constrained to a DN charset (`[A-Za-z0-9 ._=,-]`, blocking LDAP-filter
  break-out like `)(uid=*`).
- **OIDC discovery endpoints are pinned to the issuer host.** `jwks_uri`,
  `token_endpoint`, and `device_authorization_endpoint` must now share the
  issuer's hostname, so a tampered discovery document that keeps a legitimate
  `issuer` can no longer redirect JWKS retrieval (the root of signature trust)
  to an attacker-controlled host.
- **JWKS key-parameter sanity checks.** RSA keys with a modulus < 2048 bits or
  exponent < 3 (e.g. the trivially-forgeable `e=1`) and EC points not on the
  named curve are now rejected before a key is ever used to verify a signature
  — defense-in-depth against a poisoned JWKS response.

### Build
- **Go toolchain bumped to 1.26.3** to clear two standard-library advisories
  flagged by `govulncheck` against 1.26.2: GO-2026-4971 (`net` Dial/LookupPort
  NUL-byte panic, Windows-only) and GO-2026-4918 (`net/http` HTTP/2 transport
  infinite loop on a malformed `SETTINGS_MAX_FRAME_SIZE`). Both are reachable
  only via the JWKS fetch path and neither is exploitable on a Linux-only module
  talking to a trusted Keycloak, but the toolchain bump keeps the security gate
  green. No source changes.

## [0.5.1] - 2026-05-29

### Changed
- `--check` is now a full pre-activation preflight. In addition to config validity
  and OIDC discovery it verifies issuer match, the directory path
  (`sss_ssh_authorizedkeys` present, `/etc/sssd/sssd.conf` present, `sssd` active,
  the access group resolves via NSS — which exercises the whole SSSD↔LDAP↔CA chain —
  and every access-group member has a **valid** `sshPublicKey` — validated with
  `ssh-keygen -l`, flagging members with no key or an unparseable key who would be
  locked out of non-root login), and the sshd factors (`AuthorizedKeysCommand` → `sss_ssh_authorizedkeys`, non-root
  2FA, root `publickey` break-glass). Each item reports `[OK]/[WARN]/[FAIL]`; blockers
  exit non-zero so lockout risks are caught before `--enable`.
- `--enable` now actually runs that preflight and refuses to activate on any blocker
  (it previously only loaded config + tested OIDC discovery, despite the help text
  promising "runs --check first") — so activation can no longer wire PAM/sshd against
  a MITM'd issuer or a directory that cannot resolve users / serve keys.

### Hardening
- **C PAM module:** removed the now-unreachable `PROMPT:`/password-relay branch
  (directory mode never prompts for a password — the SSH key factor is handled by
  sshd, the sudo password by `pam_sss`); the env-whitelist backing arrays now derive
  their size from the whitelist (was a hardcoded `9` — a latent stack overflow if the
  list grew); the child closes all fds ≥ 3 up to the descriptor limit (was `1024`).
- **logger:** open the log with `O_NOFOLLOW` (symlink-redirect defence) and escape
  newlines in logged values (log-line injection).
- **qr:** cap the encoder at version 6 and error above it — versions ≥ 7 require the
  ISO/IEC 18004 version-information blocks this encoder does not emit (they would be
  undecodable) — and fix the version-selection off-by-one. The device-auth path gates
  URLs to ≤ 84 bytes, so generated QR codes were never affected in practice.

### Fixed
- Uninstall (`dpkg -r`/`-P`): the postrm restore guard only matched a literal `^auth`
  line, so it never recognised the distro-default sshd PAM (which authenticates via
  `@include common-auth` and has no `auth` line) and left a dangling `pam_device_auth.so`
  reference in `/etc/pam.d/sshd` after removal. It now restores an `@include`-based
  original, refuses a backup that itself contains `pam_device_auth.so`, and as a fallback
  strips the module while ensuring `@include common-auth` remains — so SSH PAM is always
  left working.
- The shipped sshd drop-in (`configs/10-pam-device-auth.conf`) now carries the
  directory-mode 2FA directives (`AuthenticationMethods publickey,keyboard-interactive:pam`
  + `AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys`) — identical to what
  `--setup-ldap` writes — instead of the legacy single-factor (`publickey keyboard-interactive`)
  config, so the package and the wizard are a single source of truth.

### Docs
- INSTALL.md and the man page note Ubuntu 26.04 LTS in the tested-OS list.

## [0.5.0] - 2026-05-29

Breaking release: **directory mode is now the only mode.** The legacy local-account
(`create_user`) path is removed entirely; pam-device-auth is purely the OIDC layer on
top of directory identity (LLDAP via SSSD/NSS).

### Removed (breaking)
- Legacy **local mode**: on-the-fly local user creation, `/etc/shadow` password
  verification (libxcrypt/CGO), account lock/unlock and the temporary-password machinery.
- Config fields `create_user`, `user_groups`, `admin_groups`, `force_password_change`
  and `directory_mode`. Identity is always directory-backed and `directory_mode` is now
  implicit. Deployed configs that still contain these fields remain valid (ignored).
- Go package `internal/user`, `verify_crypt.go` (CGO) and the related auth code paths
  (`tryCachedRefresh`, `deviceAuthFlow`, local password verification).

### Changed
- The Go helper is now **CGO-free and statically linked** (`CGO_ENABLED=0`) — no
  libxcrypt/libc runtime dependency for the binary; the C PAM shim remains the only
  native artifact (links `libpam` only).
- README: restored the APT-repository install instructions; clarified that LDAPS is
  recommended. Plain `ldap://` is accepted but unencrypted; the managed setup does
  not add StartTLS directives. Removed the "Operating modes" section. man page and all example
  configs updated to directory-only.
- `--setup-ldap` no longer requires a `directory_mode` flag; it runs from the `ldap`
  config block alone.
- `--check` and `--enable` now detect when pam-device-auth is already active
  (`pam_device_auth.so` present in `/etc/pam.d/sshd`) and report that instead of
  suggesting activation.
- `--setup-ldap` lists the local accounts it will migrate (userdel + re-own home)
  as a warning *before* acting, instead of only reporting after the fact.
- Defensive NSS-identity gate: the auth path denies (and never caches a token) if
  the SSH user does not resolve via NSS, restoring the pre-0.5 "no Unix identity →
  deny" invariant even if the module is wired without the matching sshd drop-in.

### Upgrade notes
- Ensure every SSH user has `uidNumber`/`gidNumber`/`sshPublicKey` in the directory and
  run `--setup-ldap` before relying on this version. There is no in-place local-account
  fallback: hosts still on the legacy path must migrate to directory mode.

## [0.4.0] - 2026-05-29

Major release: **directory-backed identity + two-factor SSH**. Includes all of the
unreleased 0.3.8 hardening below.

### Added — directory mode (`directory_mode: true`)
- Identity, groups, home directory, SSH keys and the sudo password come from an LDAP
  directory via **SSSD/NSS**; pam-device-auth becomes the OIDC SSH-login layer only.
  Fixes login on **OpenSSH 10.2+**, which refuses PAM for not-yet-existing local users.
- **Two-factor login** for non-root: `AuthenticationMethods publickey,keyboard-interactive:pam`
  — SSH key served from LDAP (`AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys`,
  `sshPublicKey`) **and** OIDC device grant. Root stays key-only (break-glass).
- **`--setup-ldap` wizard** — writes `/etc/sssd/sssd.conf` (rfc2307bis, ldaps,
  `ssh`/`auth`/`access` providers, `ldap_user_ssh_public_key`, `entry_cache_timeout`),
  `nsswitch` (`sss`), `pam_mkhomedir`, sudoers (`%<admin_group>`, visudo-validated) and the
  sshd drop-in; installs SSSD packages; idempotent.
- **Automatic migration** of pre-existing local accounts that shadow a directory user
  (userdel + re-own `/home/<user>` to the directory uid:gid; files preserved).
- New config: `directory_mode`, `ldap` block (`uri`, `base_dn`, `bind_dn`, `bind_password`,
  `access_group`, `admin_group`). Bind password only read at setup → written to root-only sssd.conf.
- sudo re-authenticates against the directory password (`pam_sss`, `auth_provider=ldap`) for
  `sudo_role`/`ssh-admin` members; no local passwords or `/etc/shadow`.

### Security
- Directory-mode auth reuses the full token validation (kid/alg-allowlist/iss/azp-aud/exp/iat/
  role/IP); revocation enforced via SSSD access filter + role check (bounded by cache TTL).
- Wizard rejects newline/LDAP-filter-metachar injection into sssd.conf; `ldap_tls_reqcert=hard`.
- The silent cached-refresh fast path now sits behind the mandatory SSH-key factor (no IP-only login).

### Docs
- README rewritten around directory mode and two-factor SSH
  (prerequisites, UID<65536 on LXC, numbering scheme, migration, revocation SLA, SSSD cache wipe);
  example configs updated for directory mode.

### Packaging
- `Recommends: sssd-ldap, libnss-sss, libpam-sss`; dropped obsolete `Conflicts/Replaces keycloak-ssh-auth`.

### Verified
- End-to-end on OpenSSH 9.6 / 10.0 / 10.2 (Ubuntu 24.04, Debian 13, Ubuntu 26.04) incl. a
  production host: 2FA login, migration (local → directory, files kept), sudo via directory
  password, DNS service unaffected, root break-glass intact.

## [0.3.8] - 2026-05-29

### Security / Docs
- **Auth-model documentation corrected** — README/SECURITY.md no longer claim "every session
  is verified by the IdP". `publickey` and `keyboard-interactive` are alternatives (OR), so a
  key-holding user bypasses OIDC by design (enables keyless onboarding). Documented that
  role-revocation, the OIDC IP-allowlist, and `usermod --lock` bind only the keyless/OIDC path,
  and that full revocation requires removing `authorized_keys`/the local account.
- **Algorithm pinning shipped in example configs** — `allowed_algorithms` set to `RS256` in
  the shipped examples (Keycloak/Okta/Auth0/Authentik), closing the algorithm-confusion window
  on a poisoned JWKS by default. `configuration-reference.md` documents the `ES256` case for
  ECDSA-signing realms.

### Fixed
- **sshd `MaxAuthTries` 1 → 3** — `1` disconnected clients after a single rejected agent key,
  before the OIDC `keyboard-interactive` method ran, breaking keyless onboarding and leaving no
  margin for a mistyped local password.
- **C module: `strtok` → `strtok_r`** in `get_client_ip` — removes non-reentrant static state.
- **Packaging: `sshd -t` before restart** in postinst/postrm — refuses to restart on invalid
  config, preventing a dropped SSH listener; stderr captured in a variable (no predictable temp
  path); postrm validates the PAM backup before restoring.
- **`config.json` ownership** — explicit `chown root:root` alongside `chmod 600`.
- **bump-version.sh** — anchored the `main.go` VERSION sed.

### CI / Supply chain
- syft installer pinned to its release tag and run from disk (no `curl|sh` from `main`).
- APT publish made atomic (`stable` never left empty on the success path).
- GitHub release **tags are now immutable** (workflow refuses to overwrite an existing tag).
- `SHA256SUMS` published with each release; manual install docs instruct `sha256sum -c`.

### Notes
- `LogLevel DEBUG1` is retained and **documented as required** for SSH-client QR auto-detection
  (`show_qr` is the opt-out for operators who want lower verbosity).

## [0.3.7] - 2026-04-20

Combined scope of the internal v0.3.6-rc1 and v0.3.7-rc1 release
candidates (both host-verified). Collapsed into a single 0.3.7 final.

### Security — PAM wrapper hardening

- **Sanitized child environment** — `clearenv()` prior to launching the
  Go helper with a minimal whitelist (`PAM_USER`, `PAM_RHOST`,
  `PAM_DEVICE_AUTH_*`) and a hardcoded
  `PATH=/usr/sbin:/usr/bin:/sbin:/bin`. Closes a code-injection vector
  where `LD_PRELOAD`, `LD_LIBRARY_PATH`, or `IFS` inherited from sshd
  (via misconfigured `AcceptEnv` or a hostile init-unit environment)
  would propagate into the helper and get loaded at dlopen.
- **`pipe2(O_CLOEXEC)`** — replaces `pipe()` on both child-bound
  pipes. Prevents fd leakage into any concurrent fork+launch from
  another PAM module running inside the same sshd process.

### Security — JWT validation

- **`iat` claim required** — absence of `iat` is now a hard rejection
  instead of silently skipping the forward-clock check. All mainstream
  IdPs emit `iat`; closes the one path that previously bypassed
  timestamp validation.
- **Algorithm allowlist** — new optional config field
  `allowed_algorithms` (string array). When set, tokens whose `alg`
  header is not in the list are rejected before signature verification,
  closing the algorithm-confusion window on a hostile JWKS response.
  Default empty/unset = accept any supported algorithm (RS256/384/512,
  ES256/384/512). Recommended pin for Keycloak/Authentik/Okta:
  `"allowed_algorithms": ["RS256"]`.

### Security — network + filesystem

- **Strict no-redirect policy on OIDC/JWKS clients** — all outbound
  calls (discovery, token exchange, refresh, JWKS fetch) now set
  `CheckRedirect: http.ErrUseLastResponse`. Legitimate Keycloak/
  Authentik/Okta deployments never redirect these endpoints; blocking
  them closes a downgrade-to-http and cross-origin hijack window on a
  MITM with a misissued cert.
- **`.bash_profile` symlink-plant defense** — install now uses
  `O_WRONLY|O_CREATE|O_EXCL`. An existing file (or a symlink planted on
  a shared-home NFS mount) is detected, logged, and skipped instead of
  being followed or clobbered. Closes TOCTOU on pre-user-home access.

### Fixed

- **`auth_timeout` validator clamp 30–240** (was 30–600) — the C PAM
  wrapper `SIGKILL`s the helper at `AUTH_TOTAL_TIMEOUT_S=300`, so any
  configured value above 240 was silently truncated mid-flow. 240
  leaves 60 s of headroom for child startup, PAM conversation round-
  trips, and process reap. Docs and in-C comment updated.
- **`role_claim` now supplements Keycloak roles instead of replacing
  them**. Previously,
  setting `role_claim` dropped the `realm_access.roles` and
  `resource_access.<client>.roles` lookup entirely, so deployments that
  relied on Keycloak-native roles AND a custom claim silently lost
  access.
- **`role_claim` dotted-path traversal** — `role_claim:
  "resource_access.ssh.roles"` now walks the nested payload as
  documented. Flat lookup still runs first so URL-style keys like
  `https://example.com/roles` keep working unchanged.
- **`create_user=false` enforcement** — helper now exits `2`
  (`PAM_PERM_DENIED`) before `cache.Save` when the OIDC-authenticated
  user has no local shadow entry. Previously it exited `0` and returned
  `PAM_SUCCESS` for a user that only the downstream `pam_unix` account
  phase could reject, leaving a cache entry on disk for an invalid
  identity. Locked accounts (hash prefix `!`) remain exempt — the
  unlock path above handles them.

### Supply chain

- **Reproducible Go builds** — `-trimpath -ldflags="-buildid="` added
  to `GO_BUILD_FLAGS`. Byte-identical binaries from identical sources;
  verified with repeated `make clean build` on the same host.
- **SBOM generation in release workflow** — syft (pinned to v1.42.4)
  emits both SPDX-JSON and CycloneDX-JSON for every release, attached
  to the GitHub release alongside the .deb. Syft scans both the Go
  binary dependency graph AND the C PAM module inside the .deb in one
  pass.

## [0.3.5] - 2026-04-16

### Security
- **JWT `kid` collision closed** — JWK entries with empty `kid` dropped at
  JWKS fetch; JWTs with empty header `kid` rejected at verification.
  Closes a forgery path where a kid-less token would silently match any
  empty-kid JWKS entry.
- **`iat` sanity check** — tokens with `iat` more than 60 s in the future
  (beyond NTP skew tolerance) are rejected.
- **Group-name validation** — `user_groups` / `admin_groups` entries must
  match `^[a-z_][a-z0-9_-]{0,31}$` before reaching `usermod -aG`. Blocks a
  misconfigured value like `"sudo,root"` from silently adding the user to
  both groups (shadow-utils splits `-aG` on commas inside a single arg).
- **PAM module reentrant timeout** — replaced process-global `SIGALRM` +
  `child_timed_out` / `timeout_child_pid` state with a per-call
  stack-local monotonic deadline and `poll()`-based read loop. Concurrent
  PAM auth calls in the same sshd process no longer clobber each other's
  timer; a child that hangs mid-stream (not just at `waitpid`) is now
  killed and reaped by the deadline.
- **Log file perms `0640 root:adm`** — previously `0644`. Log contains
  PII (usernames, emails, IPs, roles). Tightened via postinst, logrotate
  policy, runtime `Chmod` in the Go logger (for in-place upgrades), and
  the C PAM module's `O_NOFOLLOW` open.
- **Rebuilt with Go 1.26.2** (via `toolchain` directive) — picks up four
  stdlib CVEs: GO-2026-4866 (`crypto/x509` excludedSubtrees case-sensitive
  auth bypass), GO-2026-4870 (`crypto/tls` 1.3 KeyUpdate DoS),
  GO-2026-4946 (`crypto/x509` inefficient policy validation), GO-2026-4947
  (`crypto/x509` chain-building unexpected work).

### Changed
- Cache-refresh transient failures (refresh / JWKS / token-validate) now
  log at `WARN` with reason before falling through to device flow;
  previously hidden in `INFO`.

## [0.3.4] - 2026-03-28

### Security
- **JWT algorithm/key-type binding** — RS256/384/512 requires RSA keys, ES256/384/512 requires EC keys; prevents key-confusion attacks
- **OIDC endpoint HTTPS enforcement** — all discovery, token, and device authorization endpoints validated for `https://` scheme
- **KnownIPs capped at 20** per user with FIFO eviction — prevents unbounded cache growth
- **Shadow TOCTOU elimination** — `/etc/shadow` read once per auth cycle (no race between check and use)
- **C module: fork/exec hardening** — `popen()` replaced with `fork/exec` + bidirectional pipes (removes shell from auth path)
- **C module: fd leak fix** — partial `pipe()` fd leak on error path closed
- **C module: SIGPIPE handling** — signal restored after child process communication
- **C module: waitpid timeout** — prevents indefinite hang if Go binary stalls
- **C module: log input sanitization** — no tokens, passwords, or unsanitized user input in logs
- **C module: password zeroing** — memory cleared regardless of PAM conversation result
- **C module: double-free fix** — conversation error path no longer frees response twice
- **IP bypass fix** — cached session validation corrected

### Added
- **OIDC IP allowlist** (`ip_claim`) — optional JWT claim containing allowed IPs/CIDRs per user; centrally managed in the identity provider, cryptographically signed, supports plain IPs and CIDR notation
- **Hard deny via `PAM_MAXTRIES`** — IP/role denials use exit code 2 → sshd stops retrying immediately (no 3x password loop)
- **FLUSH on all denial messages** — IP denied, role revoked, and username mismatch messages are visible before disconnect (OpenSSH 10+ buffering)
- SSH client version detection in Go (`internal/sshclient`) — PID-walk from parent upward to find client version in journalctl
- QR auto-detection: OpenSSH 10+ always shows QR (vis() fixed), OpenSSH 9.x uses client allowlist (Ubuntu, Debian, Fedora, PuTTY)
- QR version cap — URLs longer than 84 bytes skip QR generation (Version 5 ECC M limit)
- `FLUSH:` protocol for OpenSSH 10+ PAM info message buffering compatibility
- Batched PAM conversation — single `conv()` call eliminates extra Enter presses after auth
- Man page (`man/pam-device-auth.8`, section 8)

### Changed
- **`MaxAuthTries 1`** in default sshd config — prevents retry loops on denial
- QR detection rewritten: OpenSSH 10+ skip client detection entirely (vis() fixed in openbsd-compat); OpenSSH 9.x detects client via PPID journalctl lookup
- Multi-line temp password display uses batched FLUSH for correct rendering
- OSC 8 hyperlink escapes removed (broken through `strnvis` on Windows/Termux)
- Dead code removed (unused render guard, post-exit return, inlined `shouldShowQR`)

### Removed
- Post-auth SSO session banner (reverted — not delivered by OpenSSH keyboard-interactive)
- PID-based grandparent walk for client detection (replaced by parent-upward walk)

## [0.3.3] - 2026-03-22

### Security
- Rebuilt with Go 1.26 — fixes 18 Go stdlib vulnerabilities (previously built with Go 1.22)

### Changed
- Go module path corrected to `github.com/NK-IT-CLOUD/pam-device-auth`
- Minimum Go version for source builds: 1.26

## [0.3.2] - 2026-03-21

### Changed
- Go module path aligned with GitHub org (nk-dev → NK-IT-CLOUD)

## [0.3.1] - 2026-03-21

### Added
- Auto-detect Win32-OpenSSH clients and skip QR code (broken Unicode in ssh.exe strnvis)
- `show_qr` config option: `true` (always), `false` (never), omit (auto-detect)
- SSH client version detection via journald (requires LogLevel DEBUG1)

### Changed
- Replace Unicode separators with ASCII for PowerShell compatibility
- sshd config uses LogLevel DEBUG1 by default (for client auto-detection)

## [0.3.0] - 2026-03-21

### Added
- IP-bound sessions: new client IPs require full device auth (browser confirmation)
- Known IPs stored per-user in cache (tmpfs, wiped on reboot)
- User lock/unlock: account locked on OIDC role revocation, unlocked on re-grant
- Temp password on user creation (eliminates double device auth on first setup)
- Password verification via crypt_r(3)/libxcrypt (replaces unix_chkpwd)
- Clear error messages for username mismatch and missing OIDC roles
- Detect locked accounts (! prefix in shadow hash)
- OIDC issuer cross-validation (MITM protection)

### Changed
- C PAM module rewritten: popen() replaced with fork/exec + bidirectional pipes
- PROMPT: protocol for secure password input via PAM conversation (echo off)
- Single PROMPT: per session (prevents social engineering)
- Password zeroed in memory after use
- Close inherited fds (3..1023) in child process
- pam_sm_acct_mgmt returns PAM_IGNORE (delegates to pam_unix)
- Thread-safe get_client_ip() with caller-supplied buffer
- CGO enabled for libxcrypt/crypt_r integration

### Fixed
- Authentication bypass: cached refresh tokens no longer accepted without local password
- unix_chkpwd broken on glibc 2.38+ (setgid fd sanitization) -- replaced with crypt_r
- User-writable ~/.password_set flag replaced with /etc/shadow hash check

## [0.2.0] - 2026-03-20

### Added
- `--check` command: validates config and tests OIDC provider connectivity before activation
- `--enable` command: activates PAM authentication after successful config check, restarts SSH
- Safe installation: fresh installs no longer auto-activate PAM -- prevents lockout with default config

### Changed
- Upgrade installs preserve existing PAM activation and restart SSH automatically

## [0.1.1] - 2026-03-20

### Changed
- Root user authenticates via SSH key only (no OIDC required)
- `Match User root` added to default sshd config

## [0.1.0] - 2026-03-20

First public release. Generic OIDC Device Authorization Grant for SSH PAM authentication.

### Features
- OIDC Device Authorization Grant (RFC 8628) for SSH login
- Works with any OIDC provider: Keycloak, Auth0, Okta, Authentik
- Custom role claim extraction via `role_claim` config
- Refresh token caching in tmpfs for fast repeat logins (~200ms)
- Automatic user creation with configurable group membership
- Role-based group assignment: `sudo_role` + `admin_groups` for admin/user separation
- Automatic demotion: revoking `sudo_role` removes admin groups on next login
- QR code displayed during device authorization for easy mobile scanning
- Forced local password setup on first login via `.bash_profile` prompt (used for sudo)
- JWT signature verification via JWKS (RSA + ECDSA)
- Debian package with zero-config install
- stdlib-only Go binary -- zero external dependencies

### Security
- Cryptographic JWT verification (RS256/384/512, ES256/384/512)
- OIDC Discovery fail-fast (no silent degradation)
- Username validation (path-traversal protected)
- Atomic cache writes in tmpfs (ephemeral on reboot)
- Token refresh validates at provider on every cached login
