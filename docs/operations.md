# Operations

Running pam-device-auth in production: logging, rotation, monitoring,
upgrades, failure modes.

## Files and ownership

| Path | Perms | Owner | Purpose |
|---|---|---|---|
| `/etc/pam-device-auth/config.json` | `0600` | `root:root` | OIDC config |
| `/etc/pam-device-auth/config.json.pre-0.7.0` | as `config.json` | as `config.json` | Copy kept by `--migrate-config` when it set `ldap.profile` |
| `/usr/local/bin/pam-device-auth` | `0755` | `root:root` | Go helper binary |
| `/usr/lib/security/pam_device_auth.so` (deb) or `/usr/lib64/security/pam_device_auth.so` (rpm) | `0755` | `root:root` | PAM module |
| `/var/log/pam-device-auth.log` | `0640` | `root:adm` | Auth log (PAM + Go) |
| `/run/pam-device-auth/` | `0700` | `root:root` | tmpfs session cache dir |
| `/run/pam-device-auth/<user>.json` | `0600` | `root:root` | Per-user cached session; bytes of the name outside `[A-Za-z0-9_-]` are written as `%XX` (`john%2Edoe.json`) |
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

The InfoPipe responder needs the `sssd-dbus` package on Debian, Ubuntu, Rocky
Linux and Fedora, and `--setup-ldap` installs it. Keep it installed for as long as
`sssd.conf` enables `ifp`: sssd does not start without the responder.

Changing `access_group`, `service_account_groups`, or `nopasswd_sudo_groups`
in `config.json` requires re-running `pam-device-auth --setup-ldap` to push
the new sssd.conf, sudoers, and sshd drop-in. `--setup-ldap` restarts sssd
but does **not** restart sshd; the sshd drop-in only takes effect after
`pam-device-auth --enable` (which restarts sshd) or a manual
`systemctl reload ssh.service` (`sshd.service` on Rocky Linux and Fedora).

## Logging

### Log file

One unified log at `/var/log/pam-device-auth.log`. Both the C PAM module
and the Go helper append to it with distinct line prefixes:

```
2026/04/16 09:12:03 [PAM]    INFO  Authentication attempt for user alice from IP 198.51.100.2
2026/07/11 09:12:03 [AUTH]   INFO  pam-device-auth x.y.z starting
2026/04/16 09:12:03 [AUTH]   INFO  Authenticating user: alice from IP: 198.51.100.2
2026/04/16 09:12:04 [AUTH]   INFO  Directory auth OK (cached): user=alice roles=[ssh-access]
2026/04/16 09:12:04 [PAM]    INFO  Authentication successful for user alice from IP 198.51.100.2
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
`/var/log/pam-device-auth.log`, finds no regular file there or cannot remove
mode bits beyond `0640`, it denies the login
(fail closed) and sends the reason to syslog (`authpriv`, tag
`pam-device-auth`), because sshd discards its stderr. This applies to the
authentication phase (`...; denying login (fail closed)`) and to the account
phase, `--pam-acct`, for every non-root user (`...; denying`; the helper exits
3, and the PAM module logs `acct_mgmt: helper exited 3 (infra failure) for user
<user> from IP <ip> — denying login (fail-closed)`). If you need everything in
one stream, point Journal's `ImportantLog` or a Fluentd tail at the file.

### What gets logged

Included: usernames, email addresses, IPs, roles, PAM events, verdict.

Not included: access tokens, refresh tokens, device codes, JWT payloads;
tokens never traverse the log path. The helper reads no password. When a
request to the identity provider fails, its answer goes into the log line with
at most 512 bytes.

### File perms rationale

`0640 root:adm` gives the `adm` group read access, which is the standard
Linux channel for log readers (syslog daemon, logwatch, journald
forwarders, etc.) without granting other services rights to read. This
matches `/var/log/auth.log` semantics on Debian/Ubuntu.

On a host without an `adm` group, the package (`pam-device-auth
--prepare-log` in postinst) does not change the owner of the log (`root:root`
when the package created it); the log is then readable only by root.

The helper checks the log every time it opens it: it must be a regular file,
and mode bits beyond `0640` are removed. A log with `0640` or a stricter mode
is not changed. A log it cannot open (for example immutable with
`chattr +i`), a path that is no regular file, or excess mode bits it cannot
remove (for example a `0644` log made append-only with `chattr +a`) deny
every non-root login; see [syslog](#syslog).

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
| Hard deny (sshd stops retrying) | `\[PAM\].*\(hard deny\)`; reason in `\[AUTH\].*(Access denied:\|does not resolve via NSS\|NSS lookup for)` | Role missing or revoked, `acr` not accepted after the device flow, no directory identity for the login name, or the SSSD lookup failed |
| Soft auth failure | `\[PAM\].*Authentication failed for user .* \(exit code: [0-9]+\)`; reason in the `[AUTH]` line before it | Device flow failed or timed out, token did not validate, config error |
| Client gone at the prompt | `\[AUTH\].*the SSH client went away at the prompt` | The SSH client closed the connection without answering the prompt; no login, no cached session |
| Helper timed out | `\[PAM\].*timed out after [0-9]+s` | Helper still ran 300 s after the OIDC step began; needs a `LoginGraceTime` of 300 s or more to occur |
| Login ended by sshd | sshd journal: `Timeout before authentication` | `LoginGraceTime` (default 120 s) passed before the approval; the helper log ends at `waiting for authorization` ([troubleshooting](troubleshooting.md#the-login-ends-after-two-minutes-timeout-before-authentication)) |
| IdP reachable but token invalid | `\[AUTH\].*(Token validation failed\|validation failed after refresh)` | Key rotation mid-session, clock skew, user name mismatch, MITM |
| IdP unreachable | `\[AUTH\].*(token refresh failed\|JWKS fetch\|Device code request failed\|OIDC Discovery failed\|timed out \(last failure)` | Network between PAM host and the identity provider broken, or the provider answers with errors |
| Config finding at login | `\[AUTH\].*config: (unknown key\|allowed_algorithms)` | A key the loader does not know or an unsupported algorithm entry; the login goes on, `--check` fails |
| Backup failed on enable | `FAIL: cannot back up /etc/pam.d/sshd to /etc/pam.d/sshd.original` on the stderr of `--enable` (not in the log) | `--enable` stopped before any write; the message names the cause and, without a pristine PAM config, the restore from the `openssh-server` package |
| Log unusable (fail-closed deny) | syslog `pam-device-auth: .*denying` or `\[PAM\].*helper exited 3 \(infra failure\)` | The helper cannot open the log, finds no regular file there or cannot remove mode bits beyond `0640`; every non-root login is denied |
| Metadata cache not writable | `\[AUTH\].*cache write to .* failed` | Discovery or JWKS cache under `/run/pam-device-auth/oidc/` could not be written; the live documents are used, each login fetches them again |
| Access revoked | `\[AUTH\].*access revoked for` | Cached login refused and its session removed: the refreshed token no longer carries the required role |
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

Before any file is unpacked, `preinst` refuses a platform outside the
supported list (Ubuntu 24.04 or later, Debian 13 or later, Rocky Linux 9 and
10, Fedora 44 or later): the install or upgrade fails with
`pam-device-auth: unsupported distribution "<ID> <VERSION_ID>" (supported: ubuntu >= 24.04, debian >= 13, rocky 9/10, fedora >= 44)`
and an installed version stays as it is.

On upgrade, `postinst`:

- preserves `/etc/pam-device-auth/config.json` and runs
  `pam-device-auth --migrate-config` on it: an `ldap` block without `profile`
  gets `"profile": "lldap"`, the original is kept as `config.json.pre-0.7.0`
  (see [INSTALL.md](../INSTALL.md#upgrade)); a missing `config.json` is an
  error
- rewrites `/etc/logrotate.d/pam-device-auth` (new perms if upgraded)
- in a drop-in with `LogLevel DEBUG1`, replaces that line with
  `LogLevel VERBOSE` plus `LogVerbose`, validated with `sshd -t`
- re-applies file perms (config 0600, log 0640 root:adm)
- if PAM is active (`/etc/pam.d/sshd` uses `pam_device_auth.so`; an
  `sshd.original` alone does not count), validates the sshd config with `sshd -t` and
  restarts `ssh.service` (Debian, Ubuntu) or `sshd.service` (Rocky Linux,
  Fedora)
- on fresh install: does **not** activate PAM automatically; run
  `pam-device-auth --enable` after configuring

Any failed step fails `postinst` with an `ERROR:` line that names the cause
and the step that completes the upgrade once it is fixed: `dpkg --configure
-a`, or `dnf reinstall ./pam-device-auth-<version>.x86_64.rpm` (`dnf
reinstall pam-device-auth` from a repository), because rpm does not run a
failed post-install script again.

### Via .deb or .rpm

```bash
sudo dpkg -i pam-device-auth_<version>_amd64.deb
# or, on Rocky Linux and Fedora:
sudo dnf install ./pam-device-auth-<version>.x86_64.rpm
```

Both packages come from the same nfpm manifest and run the same pre/postinstall
scripts, so upgrade behavior is identical.

### Safe-upgrade checklist

Before any upgrade on a host reachable only via SSH:

1. Keep a root SSH key session open in a second terminal. An open session
   survives a broken PAM module; a new root login does not need the OIDC step
   (`Match User root`), but it still runs the account and session stacks of
   `/etc/pam.d/sshd`
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
sudo systemctl restart ssh.service   # sshd.service on Rocky Linux and Fedora
```

(This is reversible at any time by re-running `pam-device-auth --enable`.)

## Failure modes and blast radius

| Failure | Effect | Recovery |
|---|---|---|
| Helper binary missing or corrupted | Every SSH login denied (`PAM_AUTH_ERR`) | `dpkg -i` / `dnf reinstall` redeploy |
| Config file syntactically broken | Every login denied, error logged each attempt | Fix JSON, no restart needed |
| Keycloak realm down | The cached login cannot refresh (the cached session is kept) and falls back to the device flow, which fails too | No action needed; self-heals when Keycloak returns |
| JWKS endpoint returns 500 | New tokens cannot be validated, existing cached sessions fail on refresh | No action needed |
| Host clock more than 60 s behind the IdP | The `iat` check rejects every token (`token iat in future`) | NTP |
| Host clock ahead of the IdP by more than the token lifetime plus 60 s | Every token counts as expired (`token expired`) | NTP |
| Log file disk full | The existing log still opens: the helper still authenticates; new log writes fail silently | logrotate should run; check free space on `/var` |
| Log cannot be opened, is no regular file, or has mode bits beyond `0640` that cannot be removed (missing `/var/log`, symlink, FIFO, `chattr +i`, `chattr +a` on a `0644` log, read-only filesystem, no space to create a missing log) | Every non-root login denied, in the auth phase and by `--pam-acct` (exit 3); the reason goes to syslog `authpriv`. root is unaffected | Fix the log file (`lsattr`, `chattr -a -i`, `ls -l`); the next login works |
| `/run/pam-device-auth` removed at runtime | Every user pushed back to device flow once (cache rebuilt on success) | `systemd-tmpfiles --create` to recreate |
| PAM module segfault | sshd refuses auth, logs SEGV in dmesg | `cp /etc/pam.d/sshd.original /etc/pam.d/sshd` via the root-key session, report bug |
| SSSD InfoPipe (ifp) down or `busctl` unreachable | Account-phase IP gate fails closed: every directory user denied at login, including key-only service accounts. root is unaffected (exempt from the gate) | Restore SSSD (`systemctl status sssd`, check `ifp` responder in sssd.conf); root-key session stays usable throughout |

## Root escape hatch

`/etc/ssh/sshd_config.d/10-pam-device-auth.conf` includes:

```
Match User root
    AuthenticationMethods publickey
    AuthorizedKeysFile .ssh/authorized_keys
```

Root logs in with its key alone, without the OIDC step, and the account phase
of the module returns success for root before it starts the helper or asks
SSSD. This is **by design**: an operator locked out by a directory or identity
provider outage must have a way back in. sshd still runs the account and
session stacks of `/etc/pam.d/sshd` for root, so a stack that names a module
which cannot be loaded stops new root logins too; that is why the package
refuses to be removed while the stack uses `pam_device_auth.so` without a
backup to restore. Keep the root SSH key safe, and do not change this block
without a documented alternative rescue path.

## Removing pam-device-auth

```bash
# remove (keeps config)
sudo apt remove pam-device-auth
# or on Rocky Linux and Fedora:
sudo dnf remove pam-device-auth

# purge (removes config, logs, cache; apt only, dnf has no separate purge)
sudo apt purge pam-device-auth
```

`prerm` refuses the removal while `/etc/pam.d/sshd` uses `pam_device_auth.so`
and no valid `/etc/pam.d/sshd.original` exists (non-empty, with an `auth` or
`@include` line, without `pam_device_auth.so`). Removing the module then would
leave sshd pointing at a missing `pam_device_auth.so`, so the package and sshd
stay as they are:

```text
pam-device-auth: /etc/pam.d/sshd uses pam_device_auth.so and no valid /etc/pam.d/sshd.original exists; restore /etc/pam.d/sshd from your distribution's openssh-server package, then remove pam-device-auth
```

Restore `/etc/pam.d/sshd` from the distribution's `openssh-server` package,
then remove pam-device-auth again.

`postrm` restores `/etc/pam.d/sshd` from the verified `sshd.original` (a failed
copy fails the removal and keeps the backup), drops the sshd override file,
removes the managed sudoers file (`/etc/sudoers.d/pam-device-auth`, including
any `NOPASSWD:ALL` grant it carried) so no leftover privilege escalation stays
behind, validates the sshd config with `sshd -t` and restarts
`ssh.service` or `sshd.service`. A removal or purge does that only when it
removed the drop-in or restored `/etc/pam.d/sshd`, so a host without either
(never set up or enabled) and a purge after a removal do not need sshd. A failing `sshd -t` or restart fails `postrm` with the sshd
error; fix the config and run `systemctl restart <unit>` (with dpkg, then run
the removal again). This runs the same way for `.deb` (dpkg) and `.rpm`
(dnf/rpm) removals. Directory users and groups live in LLDAP, not on the host;
uninstalling pam-device-auth does not touch them or SSSD's identity cache.

Because sssd stays configured, directory users still resolve after the
removal, while sshd is back on the distribution's settings. `postrm` prints
`sssd stays configured: directory users can log in over SSH with their directory password if sshd allows password authentication; review PasswordAuthentication and /etc/sssd/sssd.conf`
when `/etc/sssd/sssd.conf` exists.

## Package source of truth

Both `.deb` and `.rpm` build from the same `nfpm.yaml` manifest (see
[CONTRIBUTING.md](../CONTRIBUTING.md) for the release workflow). The `.deb`
is published to the APT repository at `apt.nk-it.cloud` (see
[INSTALL.md](../INSTALL.md)) and updated with the usual `apt upgrade`; the `.rpm`
is a GitHub release asset, installed with
`dnf install ./pam-device-auth-<version>.x86_64.rpm`.
