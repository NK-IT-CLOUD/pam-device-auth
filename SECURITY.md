# Security Policy

## Supported Versions

Only the latest 0.5.x point release receives security fixes. Upgrade
via `apt upgrade pam-device-auth`.

| Version | Supported |
|---------|-----------|
| 0.5.x   | Yes       |
| < 0.5.0 | No -- please upgrade |

## Security Design

pam-device-auth provides two-factor SSH login with a minimal attack surface.
Identity (users, groups, home, SSH keys, sudo password) comes from an LDAP
directory via SSSD/NSS; pam-device-auth is the OIDC layer. It never reads
`/etc/shadow`, prompts for a local password, or creates/modifies local accounts.

- **Two factors, AND-combined** -- `AuthenticationMethods publickey,keyboard-interactive:pam`
  for non-root: the SSH key (served from the directory by `sss_ssh_authorizedkeys`)
  **and** the OIDC device grant are both required. Root is `publickey`-only (break-glass).
- **OIDC token validation** -- JWT signatures verified via JWKS; issuer
  cross-validated against discovery to prevent MITM; audience, expiry,
  not-before and issued-at claims checked on every token (60 s clock-skew
  tolerance on `iat`). Re-validated on the silent cached-refresh path too.
- **JWT algorithm/key-type binding** -- RS256/384/512 requires RSA keys,
  ES256/384/512 requires EC keys; `alg=none` and HMAC rejected; prevents
  key-confusion. `allowed_algorithms` pins the accepted set.
- **JWT `kid` collision closed** -- JWK entries with empty `kid` are dropped at
  JWKS fetch, and JWT headers without `kid` are rejected at verification.
- **OIDC endpoint HTTPS enforcement** -- all discovery, token, and device
  authorization endpoint URLs validated for `https://` scheme.
- **Directory revocation** -- removing a user from the access group denies new
  logins and sudo via the SSSD access filter plus the OIDC role check, bounded
  by the SSSD cache TTL. Because the OIDC factor is mandatory, revoking the IdP
  role also blocks login on the next attempt.
- **sudo via `pam_sss`** -- sudo re-authenticates against the directory password;
  no local passwords or `/etc/shadow` to drift.
- **KnownIPs capped at 20** -- per-user IP list uses FIFO eviction to prevent
  unbounded cache growth.
- **Cache in tmpfs** -- refresh tokens stored in `/run/pam-device-auth/`
  (mode 0700 root:root), cleared on reboot; atomic writes prevent partial reads.
  The cached-refresh fast path still requires the SSH key factor.
- **PAM module hardening** -- fork/exec with bidirectional pipes (no popen, no
  shell), `clearenv` + whitelisted env, inherited-fd cleanup, `pipe2(O_CLOEXEC)`,
  `strtok_r`, SIGPIPE handling, symlink-protected (`O_NOFOLLOW`) log opening,
  sanitized log output (no tokens or unsanitized user input).
- **Reentrant per-call deadline** -- a single monotonic-clock deadline
  (stack-local, no process globals, no SIGALRM) covers the full child lifecycle:
  pipe reads via `poll()` and final `waitpid`. Concurrent PAM invocations in the
  same sshd process cannot interfere; a child that hangs is killed and reaped.
- **Log file perms `0640 root:adm`** -- log contains PII (usernames, emails,
  IPs, roles); tightened via postinst, logrotate, the Go logger `Chmod`, and
  `O_NOFOLLOW` in the C module.
- **OIDC IP allowlist** (`ip_claim`) -- optional JWT claim containing allowed
  IPs or CIDRs per user. Centrally managed in the identity provider,
  cryptographically signed in the token, not modifiable on the server.
- **Setup-time injection guard** -- `--setup-ldap` writes `/etc/sssd/sssd.conf`
  (0600 root) and rejects newline / LDAP-filter-metacharacter injection in the
  `ldap` config values; LDAPS uses `tls_reqcert = hard`.
- **CGO-free static binary** -- the Go helper links no native libraries,
  shrinking the runtime dependency surface; the C PAM shim links `libpam` only.

See the README for the full security breakdown.

## Threat Model

### Trust boundaries

```
Untrusted                          Trusted
─────────────────────────────────────────────────────
SSH client (user input)    →  sshd (PAM) → pam_device_auth.so → pam-device-auth binary
OIDC provider responses    →  JWT verification (JWKS + claims)
Network (client IP)        →  IP binding (per-session cache) + optional signed ip_claim
Directory (LDAP via SSSD)  →  identity, groups, SSH key, sudo password (NSS)
```

### In scope

| Threat | Mitigation |
|--------|------------|
| Stolen SSH key | Insufficient alone: non-root login also requires a valid OIDC token carrying `required_role` (factors are AND-combined). |
| Stolen OIDC credential | Insufficient alone: the directory SSH-key factor is still required. |
| Stolen refresh token (from tmpfs) | Requires root on the server; tokens are IP-bound, cache is `0700 root:root` in tmpfs, scoped to `client_id`. With `ip_claim`, the IP allowlist is in the signed JWT. |
| OIDC provider compromise | JWT signature verification via JWKS; issuer cross-validation; algorithm/key-type binding; `kid` required. |
| MITM on OIDC endpoints | HTTPS scheme enforced on all discovery, token, and device authorization URLs. |
| MITM on the directory | LDAPS with `tls_reqcert = hard` when `ldap.uri` is `ldaps://`. |
| Brute-force IP accumulation | KnownIPs capped at 20 per user (FIFO); new IPs require full device auth; `ip_claim` restricts to OIDC-authorized IPs. |
| Access revocation | Remove the user from the access group → SSSD access filter + OIDC role check deny login and sudo within the cache TTL. |
| Log exfiltration | No tokens, passwords, or unsanitized user input in logs; log file `0640 root:adm`; `O_NOFOLLOW`. |
| Child process hang | Per-call monotonic deadline covering pipe reads + waitpid; reentrant under concurrent sshd auth calls. |
| Shell injection via PAM | No shell in auth path — fork/exec with pipes, no popen(). |
| sssd.conf injection via config | `--setup-ldap` rejects newlines / LDAP-filter metacharacters in `ldap` values. |
| Token replay via wall-clock drift | `iat` enforced with 60 s skew; `nbf`/`exp` bound the replay window. |

### Out of scope

- **Compromised server (root)** — if an attacker has root, all local auth is bypassed. This is a PAM module, not a full endpoint security solution. Root SSH is key-only by design (break-glass).
- **OIDC provider availability** — if the provider is down, new device auth fails. A known-IP session with a valid refresh token works until token expiry (the SSH key factor still applies).
- **Directory availability** — if SSSD/LDAP is unreachable, affected users may not resolve via NSS and cannot log in; root stays key-only and unaffected.
- **Client-side security** — the browser used for device authorization is outside our control.
- **Denial of service** — rate limiting is handled by sshd (`MaxAuthTries`, `PerSourcePenalties`), not by the PAM module.

## Reporting a Vulnerability

Please report security vulnerabilities via email to nk@dev.nk-it.cloud.

Do NOT open public GitHub issues for security vulnerabilities.

Expected response time: 48 hours.
