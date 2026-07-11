# Security Policy

## Supported Versions

Only the latest stable point release receives security fixes. Upgrade with
`apt install --only-upgrade pam-device-auth`.

| Version | Supported |
|---------|-----------|
| Latest stable release | Yes |
| Older releases | No, please upgrade |

## Security model

For non-root users, pam-device-auth requires two independent proofs: an SSH key
stored in the directory and an OIDC login carrying the required role. Possession
of only one factor is not enough.

Identity (users, groups, home, SSH keys, sudo password) comes from an LDAP
directory via SSSD/NSS; pam-device-auth is the OIDC layer. The authentication
path never reads `/etc/shadow`, prompts for a local password, or modifies local
accounts. The separate root-run `--setup-ldap` command can migrate a same-name
local account to its directory identity; this is announced before `userdel`.

- **Two factors, AND-combined**: `AuthenticationMethods publickey,keyboard-interactive:pam`
  for non-root: the SSH key (served from the directory by `sss_ssh_authorizedkeys`)
  **and** the OIDC device grant are both required. Root is `publickey`-only (break-glass).
- **OIDC token validation**: JWT signatures verified via JWKS; issuer
  cross-validated against discovery to prevent MITM; audience, expiry,
  not-before and issued-at claims checked on every token (60 s clock-skew
  tolerance on `iat`). Re-validated on the silent cached-refresh path too.
- **JWT algorithm/key-type binding**: RS256/384/512 requires RSA keys,
  ES256/384/512 requires EC keys; `alg=none` and HMAC rejected; prevents
  key-confusion. `allowed_algorithms` pins the accepted set.
- **JWT `kid` collision closed**: JWK entries with empty `kid` are dropped at
  JWKS fetch, and JWT headers without `kid` are rejected at verification.
- **OIDC endpoint transport enforcement**: production discovery, token, device
  authorization and JWKS URLs use HTTPS; the Go client verifies the server
  certificate, redirects are blocked, and endpoint hosts are pinned to the
  configured issuer host. Plain HTTP is accepted only for loopback development.
- **Directory revocation**: removing a user from the access group and its mapped
  OIDC access role denies new login after SSSD and identity-provider
  federation/cache updates. Existing SSH sessions are not terminated.
- **sudo via `pam_sss`**: sudo re-authenticates against the directory password;
  no local passwords or `/etc/shadow` to drift.
- **KnownIPs capped at 20**: per-user IP list uses FIFO eviction to prevent
  unbounded cache growth.
- **Cache in tmpfs**: refresh tokens stored in `/run/pam-device-auth/`
  (mode 0700 root:root), cleared on reboot; atomic writes prevent partial reads.
  The cached-refresh fast path still requires the SSH key factor.
- **PAM module hardening**: fork/exec with bidirectional pipes (no popen, no
  shell), `clearenv` + whitelisted env, inherited-fd cleanup, `pipe2(O_CLOEXEC)`,
  `strtok_r`, SIGPIPE handling, symlink-protected (`O_NOFOLLOW`) log opening,
  sanitized log output (no tokens or unsanitized user input).
- **Reentrant per-call deadline**: a single monotonic-clock deadline
  (stack-local, no process globals, no SIGALRM) covers the full child lifecycle:
  pipe reads via `poll()` and final `waitpid`. Concurrent PAM invocations in the
  same sshd process cannot interfere; a child that hangs is killed and reaped.
- **Log file perms `0640 root:adm`**: log contains PII (usernames, emails,
  IPs, roles); tightened via postinst, logrotate, the Go logger `Chmod`, and
  `O_NOFOLLOW` in the C module.
- **OIDC IP allowlist** (`ip_claim`): optional JWT claim containing allowed
  IPs or CIDRs per user. The helper trusts the value only after token signature
  validation. If the configured claim is absent or empty, the user is
  unrestricted by IP.
- **Setup-time injection guard**: `--setup-ldap` writes `/etc/sssd/sssd.conf`
  (0600 root) and rejects newline / LDAP-filter-metacharacter injection in the
  `ldap` config values; LDAPS uses `tls_reqcert = hard`.
- **CGO-free static binary**: the Go helper links no native libraries,
  shrinking the runtime dependency surface; the C PAM shim links `libpam` only.

## Operator responsibilities

The security guarantees above depend on correct deployment:

- Protect the LDAP bind password and keep `config.json` mode `0600 root:root`.
- Use LDAPS with certificate verification for the managed setup path. Plain
  `ldap://` does not protect directory credentials or results from interception.
- Keep the OIDC provider, directory, host OS and SSH keys trusted and patched.
- Pin `allowed_algorithms` to the algorithm used by the provider.
- Review every `pam-device-auth --check` warning before activation.
- Keep a tested root SSH key outside LDAP/OIDC for emergency access.
- Treat members without `sshPublicKey` as intentionally unable to SSH; the
  preflight reports them as warnings.
- Configure network-level connection throttling where denial-of-service risk
  requires more than sshd's authentication limits.

## Threat Model

### Trust boundaries

| Boundary | Trust decision |
|---|---|
| SSH client → sshd/PAM/helper | Usernames, client IPs and terminal-facing provider data are untrusted and sanitized/validated. |
| Helper → OIDC provider | The configured issuer is trusted; TLS, discovery issuer, endpoint host and JWT claims/signature are validated. |
| Host → LDAP directory | The configured directory is trusted; the managed secure path is certificate-verified LDAPS. |
| Local root → authentication stack | Root controls PAM, sshd, config and token cache and is therefore fully trusted. |

### In scope

| Threat | Mitigation |
|--------|------------|
| Stolen SSH key | Insufficient alone: non-root login also requires a valid OIDC token carrying `required_role` (factors are AND-combined). |
| Stolen OIDC credential | Insufficient alone: the directory SSH-key factor is still required. |
| Stolen refresh token from the host | Reading the cache normally requires root. Cache lookup is limited to previously approved client IPs; a configured `ip_claim` adds a signed provider-side restriction. The refresh token itself is not cryptographically IP-bound. |
| Forged or modified OIDC token | JWT signature, issuer, client binding, lifetime, algorithm/key type and `kid` are validated. The OIDC provider itself remains trusted. |
| MITM on OIDC endpoints | HTTPS with normal certificate verification, blocked redirects and issuer-host pinning for discovered endpoints. |
| MITM on the directory | The managed setup must use LDAPS; it configures certificate verification with `tls_reqcert = hard`. Plain LDAP is not protected. |
| Brute-force IP accumulation | KnownIPs capped at 20 per user (FIFO); new IPs require full device auth; `ip_claim` restricts to OIDC-authorized IPs. |
| Access revocation | Remove directory access membership and its mapped OIDC role; new login is denied after the relevant SSSD/provider caches update. Existing sessions require separate termination. |
| Log exfiltration | No tokens, passwords, or unsanitized user input in logs; log file `0640 root:adm`; `O_NOFOLLOW`. |
| Child process hang | Per-call monotonic deadline covering pipe reads + waitpid; reentrant under concurrent sshd auth calls. |
| Shell injection via PAM | No shell in auth path: fork/exec with pipes, no popen(). |
| sssd.conf injection via config | `--setup-ldap` rejects newlines / LDAP-filter metacharacters in `ldap` values. |
| Token accepted outside its validity window | Required `exp`, optional `nbf`, and required `iat` are checked; `iat` permits at most 60 seconds of future clock skew. |

### Out of scope

- **Compromised server (root)**: if an attacker has root, all local auth is bypassed. This is a PAM module, not a full endpoint security solution. Root SSH is key-only by design (break-glass).
- **OIDC provider trust and availability**: the provider is a trusted authority.
  If it is compromised, an attacker may issue accepted tokens and roles. If it
  is unavailable, both new device authorization and known-IP refresh fail;
  non-root login fails closed. Root remains available by local key.
- **Directory availability**: if SSSD/LDAP is unreachable, affected users may not resolve via NSS and cannot log in; root stays key-only and unaffected.
- **Client-side security**: the browser used for device authorization is outside our control.
- **Denial of service**: the PAM module limits each helper call, but it does not
  provide network-level rate limiting. sshd, firewalling or an upstream control
  must limit connection floods.

## Reporting a Vulnerability

Please report security vulnerabilities via email to nk@dev.nk-it.cloud.

Do NOT open public GitHub issues for security vulnerabilities.

Expected response time: 48 hours.
