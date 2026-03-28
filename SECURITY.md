# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | Yes       |
| < 0.3    | No -- please upgrade |

## Security Design

pam-device-auth is a PAM authentication module with a minimal attack surface:

- **IP-bound sessions** -- cached sessions are tied to the client IP; a new IP
  always requires full device authorization via the browser.
- **OIDC token validation** -- JWT signatures verified via JWKS; issuer
  cross-validated against discovery to prevent MITM; audience, expiry, and
  not-before claims checked on every token.
- **JWT algorithm/key-type binding** -- RS256/384/512 requires RSA keys,
  ES256/384/512 requires EC keys; prevents key-confusion attacks.
- **OIDC endpoint HTTPS enforcement** -- all discovery, token, and device
  authorization endpoint URLs validated for `https://` scheme.
- **KnownIPs capped at 20** -- per-user IP list uses FIFO eviction to prevent
  unbounded cache growth.
- **Shadow TOCTOU elimination** -- `/etc/shadow` read once per auth cycle;
  no race between password check and use.
- **Password verification via crypt_r(3)** -- direct shadow hash verification
  using libxcrypt; no setgid unix_chkpwd dependency.
- **Cache in tmpfs** -- refresh tokens stored in `/run/pam-device-auth/`
  (mode 0700 root:root), cleared on reboot; atomic writes prevent partial reads.
- **PAM module hardening** -- fork/exec with bidirectional pipes (no popen),
  single password prompt per session, inherited fd cleanup (3..1023),
  password zeroed in memory (regardless of conversation result),
  SIGPIPE handling, waitpid timeout, symlink-protected log file opening,
  sanitized log output (no tokens, passwords, or unsanitized user input).
- **OIDC IP allowlist** (`ip_claim`) -- optional JWT claim containing
  allowed IPs or CIDRs per user. Centrally managed in the identity provider,
  cryptographically signed in the token, not modifiable on the server.
  Supports plain IPs and CIDR notation.
- **No shell in the authentication path** -- the C module communicates with
  the Go binary over pipes; no shell is spawned.

See the README for the full security breakdown.

## Threat Model

### Trust boundaries

```
Untrusted                          Trusted
─────────────────────────────────────────────────────
SSH client (user input)    →  sshd (PAM) → pam_device_auth.so → pam-device-auth binary
OIDC provider responses    →  JWT verification (JWKS + claims)
Network (client IP)        →  IP binding (per-session cache)
/etc/shadow (root-only)    →  crypt_r(3) verification
```

### In scope

| Threat | Mitigation |
|--------|------------|
| Stolen SSH password | Useless alone — requires valid OIDC session (token refresh validated at provider) |
| Stolen refresh token (from tmpfs) | Requires root on server; tokens are IP-bound, cache is `0700 root:root` in tmpfs. Token is scoped to `client_id` (useless for other OIDC clients). With `ip_claim`, IP allowlist is in the signed JWT — even root cannot add IPs without OIDC admin access. |
| OIDC provider compromise | JWT signature verification via JWKS; issuer cross-validation; algorithm/key-type binding |
| MITM on OIDC endpoints | HTTPS scheme enforced on all discovery, token, and device authorization URLs |
| Brute-force IP accumulation | KnownIPs capped at 20 per user (FIFO eviction); new IPs require full device auth. With `ip_claim`, only OIDC-authorized IPs are accepted regardless of local cache. |
| Shadow file race condition | `/etc/shadow` read once per auth cycle (TOCTOU eliminated) |
| Log exfiltration | No tokens, passwords, or unsanitized user input in log output |
| Child process hang | waitpid timeout prevents indefinite PAM blocking |
| Shell injection via PAM | No shell in auth path — fork/exec with pipes, no popen() |
| PAM conversation abuse | Single password prompt per session; PROMPT: protocol enforced in C module |
| Symlink attack on log file | Log opened with `O_NOFOLLOW` |
| Role escalation | Group membership re-evaluated on every login; role revocation → account lock |

### Out of scope

- **Compromised server (root)** — if an attacker has root, all local auth is bypassed. This is a PAM module, not a full endpoint security solution.
- **OIDC provider availability** — if the provider is down, new device auth fails. Cached sessions (known IP + valid refresh token) continue to work until token expiry.
- **Client-side security** — the browser used for device authorization is outside our control.
- **Denial of service** — rate limiting is handled by sshd (`MaxAuthTries`, `PerSourcePenalties`), not by the PAM module.

## Reporting a Vulnerability

Please report security vulnerabilities via email to nk@dev.nk-it.cloud.

Do NOT open public GitHub issues for security vulnerabilities.

Expected response time: 48 hours.
