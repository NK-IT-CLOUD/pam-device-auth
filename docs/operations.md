# Operations

Running pam-device-auth in production: logging, rotation, monitoring,
upgrades, failure modes.

## Files and ownership

| Path | Perms | Owner | Purpose |
|---|---|---|---|
| `/etc/pam-device-auth/config.json` | `0600` | `root:root` | OIDC config |
| `/usr/local/bin/pam-device-auth` | `0755` | `root:root` | Go helper binary |
| `/usr/lib/security/pam_device_auth.so` (deb) or `/usr/lib64/security/pam_device_auth.so` (rpm) | `0755` | `root:root` | PAM module |
| `/var/log/pam-device-auth.log` | `0640` | `root:adm` | Auth log (PAM + Go) |
| `/run/pam-device-auth/` | `0700` | `root:root` | tmpfs session cache dir |
| `/run/pam-device-auth/<user>.json` | `0600` | `root:root` | Per-user cached session |
| `/etc/logrotate.d/pam-device-auth` | `0644` | `root:root` | Log rotation policy |
| `/etc/tmpfiles.d/pam-device-auth.conf` | `0644` | `root:root` | Recreates cache dir at boot |
| `/etc/ssh/sshd_config.d/10-pam-device-auth.conf` | `0644` | `root:root` | sshd overrides; written by `--setup-ldap` / `--enable`, not by the package |
| `/etc/pam.d/sshd` | `0644` | `root:root` | Auth stack, backed up to `sshd.original` on enable |
| `/etc/sudoers.d/pam-device-auth` | `0440` | `root:root` | Managed sudoers file for `admin_group`/`nopasswd_sudo_groups`; written by `--setup-ldap`, removed on uninstall |

## Service accounts and the IP allowlist

Two axes of `ldap` config decide what a directory member can do on the host:

- SSH access: `access_group` (interactive, key plus OIDC) and `service_account_groups`
  (key-only, no OIDC device flow at all). A user needs membership in one of
  these to log in over SSH; the access filter SSSD applies is widened to OR
  them together.
- Sudo: `admin_group` (password sudo) and `nopasswd_sudo_groups`
  (`NOPASSWD:ALL`, for automation that can't type an interactive password).

`service_account_groups` is the mechanism for automation and service
accounts: members authenticate with their directory SSH key only, the same
way root does, but they are still directory users and still subject to the
IP allowlist below. Any new LLDAP group used in either list needs a POSIX
`gidNumber` set or SSSD will not resolve it and members are silently denied.

The `clients` attribute on an LLDAP user is a per-user source-IP/CIDR
allowlist, enforced on every login (including key-only service accounts)
by the PAM account phase, which reads `clients` from the SSSD InfoPipe
responder over `busctl`. Only root is exempt: this is the break-glass path and
it never touches SSSD. Unsupported local non-root users fail closed.

The check is fail-closed: if the InfoPipe lookup for a directory user
errors for any reason (SSSD down, D-Bus unreachable, timeout), that login
is denied. A broken InfoPipe responder denies every directory user, not
just the ones with a `clients` allowlist set, so treat InfoPipe health as
a hard dependency. `pam-device-auth --check` reports both IP-pin posture
(which users/groups have `clients` set) and InfoPipe health (a live probe
against a resolvable directory user via `busctl`); run it after any change
to `clients`, `access_group`, or `service_account_groups`.

The InfoPipe responder needs the `sssd-dbus` package on Debian, Ubuntu and the
RHEL family, and `--setup-ldap` installs it. Keep it installed for as long as
`sssd.conf` enables `ifp`: sssd does not start without the responder.

Changing `access_group`, `service_account_groups`, or `nopasswd_sudo_groups`
in `config.json` requires re-running `pam-device-auth --setup-ldap` to push
the new sssd.conf, sudoers, and sshd drop-in. `--setup-ldap` restarts sssd
but does **not** restart sshd; the sshd drop-in only takes effect after
`pam-device-auth --enable` (which restarts sshd) or a manual
`systemctl reload ssh`.

## Logging

### Log file

One unified log at `/var/log/pam-device-auth.log`. Both the C PAM module
and the Go helper append to it with distinct line prefixes:

```
2026/04/16 09:12:03 [PAM]    INFO  Authentication attempt for user alice from IP 10.0.20.2
2026/07/11 09:12:03 [AUTH]   INFO  pam-device-auth x.y.z starting
2026/04/16 09:12:03 [AUTH]   INFO  Authenticating user: alice from IP: 10.0.20.2
2026/04/16 09:12:04 [AUTH]   INFO  Directory auth OK (cached): user=alice roles=[ssh-access]
2026/04/16 09:12:04 [PAM]    INFO  Authentication successful for user alice from IP 10.0.20.2
```

| Prefix | Source | Key levels |
|---|---|---|
| `[PAM]` | PAM module (C) | `INFO` / `WARN` / `ERROR` per `log_message()` |
| `[AUTH]` | Go helper | `DEBUG` / `INFO` / `WARN` / `ERROR` |

Go helper `DEBUG` is suppressed unless the binary runs with `--debug`
(rare in production; used only for manual invocation during reproduction).

### syslog

The PAM module additionally writes every line to syslog at the same
priority, so `/var/log/auth.log` / `journalctl` carries a copy. The Go
helper does **not** write to syslog, with one exception: if it cannot open
`/var/log/pam-device-auth.log` it denies the login (fail closed) and sends the
reason to syslog (`authpriv`, tag `pam-device-auth`), because sshd discards its
stderr. If you need everything in one stream, point Journal's `ImportantLog` or
a Fluentd tail at the file.

### What gets logged

Included: usernames, email addresses, IPs, roles, PAM events, verdict.

Not included: passwords, temporary passwords, access tokens, refresh
tokens, device codes, JWT payloads. Tokens never traverse the log path;
passwords are zeroed (`memset`/`defer` zero) before any string would
escape.

### File perms rationale

`0640 root:adm` gives the `adm` group read access, which is the standard
Linux channel for log readers (syslog daemon, logwatch, journald
forwarders, etc.) without granting other services rights to read. This
matches `/var/log/auth.log` semantics on Debian/Ubuntu.

If you run on a host that doesn't have an `adm` group, postinst falls
back to leaving ownership at `root:root` and the permissions at `0640`;
the log is still readable to anyone who can become root.

## Rotation

logrotate policy at `/etc/logrotate.d/pam-device-auth`:

```
/var/log/pam-device-auth.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}
```

- weekly rotation, 4 generations → ≈ 1 month retention
- compressed (gzip) after one rotation (`delaycompress`)
- new file created with the correct perms/owner immediately

To keep longer history, edit the policy and re-run:

```bash
sudo logrotate -v /etc/logrotate.d/pam-device-auth
```

## Monitoring signals

No Prometheus endpoint: the helper is not a daemon. Monitor via logs.

### Key grep patterns

| Signal | Regex | Meaning |
|---|---|---|
| Hard deny (sshd stops retrying) | `\[AUTH\].*Access denied:` | Missing directory identity or role revocation |
| Soft auth failure | `\[AUTH\].*Authentication failed` or `\[PAM\].*exit code: (1\|3-9)` | Bad password, cancelled device flow, network blip |
| Helper timed out | `\[PAM\].*timed out after [0-9]+s` | Helper stuck; infrastructure issue |
| IdP reachable but token invalid | `\[AUTH\].*Token validation failed` | Key rotation mid-session, clock skew, MITM |
| IdP unreachable | `\[AUTH\].*token refresh failed` or `JWKS fetch` | Network between PAM host and Keycloak broken |
| Backup failed on enable | `WARN: could not back up` | `--enable` proceeded without a PAM-config backup; investigate before the next change |
| Access revoked mid-session | `\[AUTH\].*access revoked for` | Cached session rejected; user lost the required role or IP authorization |
| Account-phase IP gate deny | `\[AUTH\].*not in clients allowlist` | Source IP not in the user's `clients` attribute; expected for a locked-down account logging in from a new location |
| InfoPipe read failure (fail-closed deny) | `\[AUTH\].*clients read failed, fail-closed deny` | SSSD InfoPipe/D-Bus unreachable or timed out; denies this login and, if it persists, every directory user |

### Suggested alerts

- **ERROR rate** (`[AUTH].*ERROR`) > 5/min → page
- **Helper timeouts** (`timed out after`) > 0/min → page
- **Refresh failures** (`token refresh failed`) > 10/min → investigate
  Keycloak availability
- **Account-phase IP denies** (`not in clients allowlist`) sudden spike →
  possible IP enumeration or a stale `clients` attribute after a network change
- **InfoPipe read failures** (`clients read failed, fail-closed deny`) any
  occurrence → SSSD/D-Bus health, this denies all directory logins if it
  persists

## Upgrades

### Via APT (normal path)

```bash
sudo apt update && sudo apt upgrade pam-device-auth
```

On upgrade, `postinst`:

- preserves `/etc/pam-device-auth/config.json`
- rewrites `/etc/logrotate.d/pam-device-auth` (new perms if upgraded)
- re-applies file perms (config 0600, log 0640 root:adm)
- restarts sshd **only** if PAM was previously activated (detected by
  presence of `/etc/pam.d/sshd.original`)
- on fresh install: does **not** activate PAM automatically; run
  `pam-device-auth --enable` after configuring

### Via .deb or .rpm

```bash
sudo dpkg -i pam-device-auth_<version>_amd64.deb
# or, on Rocky/RHEL-family:
sudo dnf install ./pam-device-auth-<version>.x86_64.rpm
```

Both packages come from the same nfpm manifest and run the same pre/postinstall
scripts, so upgrade behavior is identical.

### Safe-upgrade checklist

Before any upgrade on a host reachable only via SSH:

1. Keep a root SSH key session open in a second terminal. `Match User
   root` is configured to bypass PAM, so this session survives a broken
   PAM module
2. `pam-device-auth --check` after upgrade, before disconnecting. There must be
   no `[FAIL]`; review every `[WARN]` against the intended directory state (for
   example, a deliberately keyless access-group member is expected but cannot SSH).
   `--check` also reports IP-pin posture and SSSD InfoPipe health; a `[WARN]` on
   InfoPipe means the account-phase IP gate will fail closed and deny directory
   users once active.
3. Attempt a fresh SSH login from a different source; only then log out of
   the rescue session

If `--check` fails post-upgrade, disable PAM while you debug:

```bash
sudo cp /etc/pam.d/sshd.original /etc/pam.d/sshd
sudo systemctl restart ssh
```

(This is reversible at any time by re-running `pam-device-auth --enable`.)

## Failure modes and blast radius

| Failure | Effect | Recovery |
|---|---|---|
| Helper binary missing or corrupted | Every SSH login denied (`PAM_AUTH_ERR`) | `dpkg -i` / `dnf reinstall` redeploy |
| Config file syntactically broken | Every login denied, error logged each attempt | Fix JSON, no restart needed |
| Keycloak realm down | Fast path denies (refresh fails), new device flows fail | No action needed; self-heals when Keycloak returns |
| JWKS endpoint returns 500 | New tokens cannot be validated, existing cached sessions fail on refresh | No action needed |
| Host clock drift > 60 s ahead of IdP | `iat` check rejects tokens | NTP; or temporarily widen the skew window (source change) |
| Log file disk full | Helper still authenticates; new log writes fail silently | logrotate should run; check free space on `/var` |
| `/run/pam-device-auth` removed at runtime | Every user pushed back to device flow once (cache rebuilt on success) | `systemd-tmpfiles --create` to recreate |
| PAM module segfault | sshd refuses auth, logs SEGV in dmesg | `cp /etc/pam.d/sshd.original /etc/pam.d/sshd` via the root-key session, report bug |
| SSSD InfoPipe (ifp) down or `busctl` unreachable | Account-phase IP gate fails closed: every directory user denied at login, including key-only service accounts. root is unaffected (exempt from the gate) | Restore SSSD (`systemctl status sssd`, check `ifp` responder in sssd.conf); root-key session stays usable throughout |

## Root escape hatch

`/etc/ssh/sshd_config.d/10-pam-device-auth.conf` includes:

```
Match User root
    AuthenticationMethods publickey
```

Root SSH-key logins bypass PAM entirely. This is **by design**: an
operator locked out by a PAM misconfiguration must have a way back in.
Keep the root SSH key safe, and do not change this block without a
documented alternative rescue path.

## Removing pam-device-auth

```bash
# remove (keeps config)
sudo apt remove pam-device-auth
# or on Rocky/RHEL-family:
sudo dnf remove pam-device-auth

# purge (removes config, logs, cache; apt only, dnf has no separate purge)
sudo apt purge pam-device-auth
```

`postrm` restores `/etc/pam.d/sshd` from `sshd.original`, drops the sshd
override file, removes the managed sudoers file
(`/etc/sudoers.d/pam-device-auth`, including any `NOPASSWD:ALL` grant it
carried) so no leftover privilege escalation stays behind, and restarts
sshd. This runs the same way for `.deb` (dpkg) and `.rpm` (dnf/rpm)
removals. Directory users and groups live in LLDAP, not on the host;
uninstalling pam-device-auth does not touch them or SSSD's identity cache.

## Package source of truth

Both `.deb` and `.rpm` build from the same `nfpm.yaml` manifest (see
[CONTRIBUTING.md](../CONTRIBUTING.md) for the release workflow). The `.deb`
is published to the APT repository at `apt.nk-it.cloud` (see
[INSTALL.md](../INSTALL.md)) and updated with the usual `apt upgrade`; the `.rpm`
is a GitHub release asset, installed with
`dnf install ./pam-device-auth-<version>.x86_64.rpm`.
