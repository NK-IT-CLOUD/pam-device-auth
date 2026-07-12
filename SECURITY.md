# Security Policy

## Supported versions

Only the latest stable point release receives security fixes. Upgrade with
`apt install --only-upgrade pam-device-auth` on Debian/Ubuntu, or
`sudo dnf upgrade pam-device-auth` on Rocky Linux/RHEL.

| Version | Supported |
|---------|-----------|
| Latest stable release | Yes |
| Older releases | No, please upgrade |

## Security model

For interactive users (members of `access_group`), pam-device-auth requires two
independent proofs: an SSH key stored in the directory and an OIDC login
carrying the required role. Possession of only one factor is not enough.
Members of `service_account_groups` are a separate, single-factor tier for
automation and service accounts: they authenticate with the directory SSH key
only, with no OIDC step. Because that tier has only one factor, these accounts
should be pinned to known source IPs (see the `clients` allowlist below).

Identity (users, groups, home, SSH keys, sudo password) comes from an LDAP
directory via SSSD/NSS; pam-device-auth is the OIDC and IP-policy layer. The
authentication path never reads `/etc/shadow`, prompts for a local password,
or modifies local accounts. The separate root-run `--setup-ldap` command can
migrate a same-name local account to its directory identity; this is
announced before `userdel`.

- **Two factors, AND-combined**: `AuthenticationMethods publickey,keyboard-interactive:pam`
  for `access_group` members: the SSH key (served from the directory by
  `sss_ssh_authorizedkeys`) **and** the OIDC device grant are both required.
  `service_account_groups` members get `publickey`-only (see above). Root is
  `publickey`-only for a different reason: break-glass access that never
  depends on the directory or OIDC provider being reachable.
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
- **Two sudo tiers**: `admin_group` members sudo with the LLDAP password via
  `pam_sss` (no local passwords or `/etc/shadow` to drift). `nopasswd_sudo_groups`
  is a separate, opt-in, admin-declared list of groups granted `NOPASSWD:ALL`
  through a managed sudoers file (`/etc/sudoers.d/pam-device-auth`, validated
  with `visudo -c` at write time). A group can be in both lists; NOPASSWD wins
  for members of both.
- **Directory `clients` IP allowlist**: a per-user `clients` attribute (IPs or
  CIDRs) in the directory is enforced in the PAM account phase (`--pam-acct`,
  invoked from `pam_sm_acct_mgmt`, not the auth phase) for every directory
  user, including key-only service accounts. It reads the attribute from the
  SSSD InfoPipe over `busctl`. If a user has no `clients` attribute set, they
  are unrestricted. **Fail-closed**: any lookup error (InfoPipe down, D-Bus
  timeout, malformed response) denies that login. Because the check runs for
  every directory user regardless of whether they have an allowlist
  configured, an SSSD/InfoPipe outage denies all directory-based logins, not
  only those pinned to specific IPs. **Root and local (non-directory) users
  are exempt**: root's account-phase check returns success before any
  SSSD/D-Bus access, so root login never depends on SSSD availability.
  `pam-device-auth --check` reports IP-pin posture and InfoPipe health.
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
- **Setup-time injection guard**: `--setup-ldap` writes `/etc/sssd/sssd.conf`
  (0600 root) and rejects newline / LDAP-filter-metacharacter injection in the
  `ldap` config values; LDAPS uses `tls_reqcert = hard`.
- **CGO-free static binary**: the Go helper links no native libraries, which
  shrinks the runtime dependency surface; the C PAM shim links `libpam` only.
- **Clean uninstall**: removing the package (`dpkg -r`/`--purge` or
  `dnf remove`, both driven by the same postrm script) restores
  `/etc/pam.d/sshd` from its backup, removes the sshd drop-in, and removes the
  managed sudoers file `/etc/sudoers.d/pam-device-auth`, so no NOPASSWD grant
  is left behind.

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
- `service_account_groups` members are key-only (single factor): give each
  such account a `clients` IP allowlist in the directory so a leaked key
  alone is not enough to log in from anywhere.
- Monitor SSSD InfoPipe health (`pam-device-auth --check`); because the
  `clients` gate fails closed, an InfoPipe outage denies all directory-based
  logins, not just IP-pinned ones.

## Threat model

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
| Stolen SSH key (access_group user) | Insufficient alone: login also requires a valid OIDC token carrying `required_role` (factors are AND-combined). |
| Stolen SSH key (service_account_groups user) | This tier is single-factor by design; the mitigation is the `clients` IP allowlist, not a second factor. Pin these accounts. |
| Stolen OIDC credential | Insufficient alone: the directory SSH-key factor is still required. |
| Stolen refresh token from the host | Reading the cache normally requires root. Cache lookup is limited to previously approved client IPs; the directory `clients` allowlist further restricts source IPs in the PAM account phase. The refresh token itself is not cryptographically IP-bound. |
| Forged or modified OIDC token | JWT signature, issuer, client binding, lifetime, algorithm/key type and `kid` are validated. The OIDC provider itself remains trusted. |
| MITM on OIDC endpoints | HTTPS with normal certificate verification, blocked redirects and issuer-host pinning for discovered endpoints. |
| MITM on the directory | The managed setup must use LDAPS; it configures certificate verification with `tls_reqcert = hard`. Plain LDAP is not protected. |
| Brute-force IP accumulation | KnownIPs capped at 20 per user (FIFO); new IPs require full device auth; the directory `clients` allowlist restricts source IPs in the account phase. |
| Login from an unapproved source IP | The directory `clients` allowlist is checked in the PAM account phase for every directory user (root exempt); non-matching source IPs are denied. |
| sudoers left behind after removal | postrm deletes `/etc/sudoers.d/pam-device-auth` on both remove and purge, on deb and rpm. |
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
- **Directory availability**: if SSSD/LDAP is unreachable, affected users may
  not resolve via NSS and cannot log in; root stays key-only and unaffected.
  Separately, if SSSD resolves users but its InfoPipe/D-Bus responder is down,
  the account-phase `clients` check fails closed and denies every directory
  user, including ones with no IP allowlist configured; this is an accepted
  side effect of fail-closed IP enforcement, not a bug.
- **Client-side security**: the browser used for device authorization is outside our control.
- **Denial of service**: the PAM module limits each helper call, but it does not
  provide network-level rate limiting. sshd, firewalling or an upstream control
  must limit connection floods.

## Reporting a vulnerability

Please report security vulnerabilities via email to nk@dev.nk-it.cloud.

Do NOT open public GitHub issues for security vulnerabilities.

Expected response time: 48 hours.
