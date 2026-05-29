# Changelog

All notable changes to this project will be documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/).

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
- README rewritten around directory mode + 2FA; `docs/ldap-directory-setup.md` operator guide
  (prerequisites, UID<65536 on LXC, numbering scheme, migration, revocation SLA, SSSD cache wipe);
  `configs/config-ldap.example.json`.

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
  them**, matching `docs/configuration-reference.md`. Previously,
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
