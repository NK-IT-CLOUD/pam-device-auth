# Troubleshooting

Symptom-first index. For each issue: likely cause and the commands to
confirm it.

First stop: `/var/log/pam-device-auth.log` (Go helper) and
`journalctl -u ssh -f` (PAM module via sshd; `-u sshd` on Rocky Linux and
Fedora). Both should be tailing during an auth attempt.

## Setup and package scripts

### `unsupported distribution "<ID> <VERSION_ID>" (supported: …)`

The host is not one of the supported platforms: Ubuntu 24.04 or later, Debian
13 or later, Rocky Linux 9 and 10, Fedora 44 or later, matched on `ID` and
`VERSION_ID` in `/etc/os-release`. Every other distribution is refused, also
one whose `ID_LIKE` names a supported one (AlmaLinux, CentOS and other RHEL
clones). The package pre-install script refuses before any file is unpacked
(an installed version stays as it is), and `--setup-ldap`, `--check` and
`--enable` exit 1 before they read the config.

```bash
grep -E '^(ID|VERSION_ID)=' /etc/os-release
```

### `config: ldap.profile is required ("lldap" or "ad")`

The `ldap` block has no `profile`. Set `"profile": "lldap"` for LLDAP or
`"profile": "ad"` for an Active Directory. The package sets `lldap` on install
and upgrade through `pam-device-auth --migrate-config` when the block has no
profile; run it by hand (`sudo pam-device-auth --migrate-config`) for a config
you copied onto the host afterwards. The original stays in
`config.json.pre-0.7.0`. If that file already exists, for example from the
package upgrade, `--migrate-config` refuses
(`backup /etc/pam-device-auth/config.json.pre-0.7.0 already exists; …`) and
changes nothing: set `"profile"` in `config.json` by hand instead, or move the
old backup away first.

### `--migrate-config failed` during a package upgrade

The post-install script stopped with
`ERROR: /usr/local/bin/pam-device-auth --migrate-config failed for /etc/pam-device-auth/config.json (reason above); …`.
The line above it starts with `FAIL:` and names the reason, for example
`backup /etc/pam-device-auth/config.json.pre-0.7.0 already exists; move it
away and run --migrate-config again`, an `ldap.profile` other than `lldap` or
`ad`, two keys that differ only in case, duplicate keys
(`the config loader would read more than ldap.profile differently after the migration …`,
for example a second `ldap` or `attributes` object, which the loader merges
and the rewrite would not), a config that is a symlink or not valid JSON. The
config is unchanged. Fix it, then finish the upgrade with
`sudo dpkg --configure -a` (Debian, Ubuntu) or
`sudo dnf reinstall ./pam-device-auth-<version>.x86_64.rpm` (Rocky Linux,
Fedora; `sudo dnf reinstall pam-device-auth` from a repository).

### Package upgrade fails at the sshd restart

With PAM active the post-install script runs `sshd -t` and restarts
`ssh.service` (`sshd.service` on Rocky Linux and Fedora). If either fails, the
script fails and prints the sshd error, so the new module is not left behind
an sshd that was never restarted. Fix the sshd config (`sudo sshd -t`), then
run the finish step the message names (`dpkg --configure -a`, or the `dnf
reinstall` above).

### Package removal is refused

```text
pam-device-auth: /etc/pam.d/sshd uses pam_device_auth.so and no valid /etc/pam.d/sshd.original exists; restore /etc/pam.d/sshd from your distribution's openssh-server package, then remove pam-device-auth
```

The removal would leave sshd pointing at a missing `pam_device_auth.so`.
`sshd.original` is missing, empty, has no `auth` or `@include` line, or itself
contains `pam_device_auth.so` (for example after a failed backup during an
`--enable` of 0.6.x, which only warned, or removed by hand later; `--enable`
of 0.7.0 refuses to activate without a valid backup). Restore `/etc/pam.d/sshd` from the distribution's `openssh-server`
package, check that it no longer names `pam_device_auth.so`, then remove
pam-device-auth again. On Debian and Ubuntu, extract it from the package file:

```bash
cd "$(mktemp -d)"
apt-get download openssh-server
dpkg-deb --fsys-tarfile openssh-server_*.deb | tar -xOf - ./etc/pam.d/sshd > sshd
sudo install -m 0644 -o root -g root sshd /etc/pam.d/sshd
```

On Rocky Linux and Fedora, extract it from the `openssh-server` RPM
(`dnf download` needs the `dnf-plugins-core` package on Rocky Linux, `cpio`
may have to be installed):

```bash
cd "$(mktemp -d)"
dnf download openssh-server
rpm2cpio openssh-server-*.rpm | cpio -i --quiet --to-stdout ./etc/pam.d/sshd > sshd
sudo install -m 0644 -o root -g root sshd /etc/pam.d/sshd
```

If a removal fails at `sshd -t` or the sshd restart, fix the sshd config, run
`sudo systemctl restart ssh.service` (`sshd.service` on Rocky Linux and
Fedora), and with dpkg run the removal again.

### `--setup-ldap` aborts with `FAIL:`

Every step of `--setup-ldap` is checked. The `FAIL:` line has three parts: the
failed command with its output (for example `apt-get update: …` when a
third-party repository or the proxy is unreachable, or `authselect select
sssd with-mkhomedir --force: …`), in parentheses what happened to
`/etc/sssd/sssd.conf` (`restored previous sssd.conf`, `removed the new
sssd.conf (none existed before)`, `… and restarted sssd` once sssd was running
on the new file, or `could NOT roll back sssd.conf: …`), and after
`still in place on the host:` the changes the abort does not undo (the
mkhomedir wiring, `sss` in `/etc/nsswitch.conf`, the sudoers and sshd drop-ins,
masked SSSD socket units, an enabled sssd). Failures before `sssd.conf` is
written (package index, package install, marking the packages, a missing
`sss_ssh_authorizedkeys`, `sssd_ifp` or login shell) write no configuration
file; packages installed so far stay installed. A failed
local-account migration keeps the new `sssd.conf` (`kept the new sssd.conf:
…`) and names the steps to finish by hand. Fix the cause and run
`--setup-ldap` again.

## Auth fails for every user

### InfoPipe/SSSD outage denies all directory users

The account-phase IP allowlist gate (`--pam-acct`) reads each directory
user's `clients` attribute from the SSSD InfoPipe (`ifp`) over D-Bus. This
gate is fail-closed: if the InfoPipe read errors for any reason (sssd down,
`ifp` responder not running, D-Bus unreachable), the login is denied, not
allowed. That applies to every directory user, including ones with no
`clients` value set, because the gate cannot tell "no restriction" apart
from "read failed" once the read itself fails.

Root never touches SSSD or InfoPipe, so root keeps working during an
outage. This is deliberate: it is the break-glass path back into the box.
Every other account, including non-root local ones, goes through the
InfoPipe read and is denied while it is down.

Confirm sssd and the InfoPipe responder are up:

```bash
sudo systemctl status sssd
sudo busctl --system tree org.freedesktop.sssd.infopipe
```

`pam-device-auth --check` reports InfoPipe health directly: an `[OK]` line
means it probed a resolvable directory user over busctl successfully; a
`[WARN]` line means the probe failed and explains whether the account-phase
gate is active (so this would already be locking out directory users) or
not yet enabled (so it would once you run `--enable`).

### `--setup-ldap` fails or sssd will not start ("[ifp]" section)

`--setup-ldap` renders an `[ifp]` responder block into `sssd.conf` because
the account-phase IP gate needs it. On Debian, Ubuntu, Rocky Linux and
Fedora, the `ifp` responder ships in a separate `sssd-dbus` package, not in the
base `sssd` package.
`--setup-ldap` installs `sssd-dbus` itself as part of its package step and
checks that `/usr/libexec/sssd/sssd_ifp` exists before it writes `sssd.conf`.
A failed install aborts the setup with the error of the package manager
(`apt-get install -y …: …` or `dnf install -y …: …`); a responder that is still
missing after the install aborts it with
`SSSD InfoPipe responder /usr/libexec/sssd/sssd_ifp: …; install the sssd-dbus package`.
Both happen before any configuration file is written. A package removed later (by hand, or as an
unneeded dependency) leaves `sssd.conf` referencing `[ifp]` with the package
missing. sssd then refuses to start.

Confirm the package is present and check sssd's own error:

```bash
dpkg -s sssd-dbus            # Debian/Ubuntu; expect "Status: install ok installed"
rpm -q sssd-dbus             # Rocky Linux, Fedora
sudo systemctl status sssd -l
sudo journalctl -u sssd -n 50 --no-pager
```

If the package is missing, install it and restart sssd:

```bash
sudo apt-get install sssd-dbus     # Debian/Ubuntu
sudo dnf install sssd-dbus         # Rocky Linux, Fedora
sudo systemctl restart sssd
```

On a Rocky Linux or Fedora host set up with release 0.5.10 or earlier, `sssd-dbus` is installed
only as a dependency, not as a package you asked for. `dnf remove pam-device-auth`
then removes it too, and the next restart of sssd fails with `Could not restart
critical service [ifp]`. Run `sudo dnf mark install sssd-dbus` (Fedora, dnf5:
`sudo dnf mark user sssd-dbus`) once, or re-run `--setup-ldap` from release 0.5.11
or later (Fedora: 0.6.1 or later), which marks it, so that removing the
package leaves it in place. `--check` reports a missing responder as a blocker.

### systemd is degraded: `sssd-nss.socket` (or `-pam`, `-ssh`) failed

`systemctl --failed` lists `sssd-nss.socket`, `sssd-pam.socket`,
`sssd-pam-priv.socket` or `sssd-ssh.socket`, and the journal says the responder
is "socket-activated but still mentioned in the services line". Debian and Ubuntu
enable these socket units by preset, while the sssd.conf of directory mode starts
the same responders from its `services` line. `--check` warns about it.
Re-running `sudo pam-device-auth --setup-ldap` (release 0.5.13 or later) masks
the conflicting sockets and clears the failed state. By hand:

```bash
sudo systemctl disable --now sssd-nss.socket sssd-pam.socket sssd-pam-priv.socket sssd-ssh.socket
sudo systemctl mask sssd-nss.socket sssd-pam.socket sssd-pam-priv.socket sssd-ssh.socket
sudo systemctl reset-failed 'sssd-*'
```

Logins are not affected; the sssd monitor runs the responders either way.

### Reading `--check` results

`[FAIL]` entries are activation blockers and make `--check` exit non-zero.
`[WARN]` entries are advisory: they do not block `--enable`, but each one must
match an intentional operating state. For example, a directory access-group
member without `sshPublicKey` is reported because that user cannot satisfy the
first factor; this is harmless when the account is deliberately keyless.

For a complete current output example, see
[Installation: Preflight check](../INSTALL.md#5-preflight-check).

### `FAIL: config error` on `--check`

Config path or JSON syntax. Confirm:

```bash
sudo -u root ls -l /etc/pam-device-auth/config.json   # expect 0600 root:root
sudo cat /etc/pam-device-auth/config.json | jq .      # expect valid JSON
```

### `FAIL: OIDC discovery failed`

- `issuer_url` typo, wrong realm, or trailing path included
- DNS / firewall blocks the helper from reaching Keycloak
- Realm disabled in Keycloak

Confirm with a manual fetch from the host:

```bash
curl -sSL https://sso.example.com/realms/myrealm/.well-known/openid-configuration | jq .issuer
```

The returned `issuer` field must **exactly** match `issuer_url` in
`config.json` (trailing-slash aside; the helper normalises that).

### `FAIL: OIDC issuer mismatch`

Discovery's `issuer` disagrees with `issuer_url`. Usually means Keycloak
is behind a reverse proxy that rewrites the host: Keycloak's
`KC_HOSTNAME` / `KC_HOSTNAME_URL` does not match the URL clients use.
Fix on the Keycloak side; `pam-device-auth` will not silently accept a
mismatched issuer.

### `Helper program timed out after 300s`

The PAM module killed the helper after 5 minutes. Usually means:

- Device-flow poll endpoint is unreachable mid-flow
- User scanned the QR but never confirmed in the browser

Check for partial writes in the helper log. Legitimate flows finish in
well under 300 s; `auth_timeout` default is 180 s.

## Auth fails for specific user

### `User <x> lacks required role: <role>`

The user's access token does not contain `required_role`. In Keycloak:

- **Users → <user> → Role mapping**: role present?
- If using groups: **Groups → <group> → Role mapping**: role mapped?
- If using a custom `role_claim`: decode the token and check the path
  literally

Verify with the `--debug` flag set in a one-off invocation context
(manual repro from a shell where `PAM_USER` and `PAM_RHOST` are set):

```bash
sudo PAM_USER=alice PAM_RHOST=198.51.100.2 pam-device-auth --debug
# logs will include: "Roles extracted: [...]"
```

### `Access denied: the token carries no authentication level (acr)`

`required_acr` is set, but the access token has no `acr` claim, so every login
is denied. In Keycloak, add the `acr` client scope to the client's default
scopes ([keycloak-setup.md](keycloak-setup.md), section 3).

### `Access denied: authentication level "<acr>" is not accepted`

The token's `acr` is not one of the values in `required_acr`. Either the sign-in
went through a flow that does not reach the expected level (the client's browser
flow override was removed or changed), or `required_acr` lists another value
than the flow reports. Decode the token (see
[keycloak-setup.md](keycloak-setup.md#inspect-a-real-access-token)) and compare
its `acr` with `required_acr`.

### Directory user denied at the account phase ("not in clients allowlist")

The account phase (`--pam-acct`) reads the `clients` attribute for the user
straight from SSSD's InfoPipe, over `busctl`, and runs on every login,
including key-only service accounts that never get an OIDC token. Look in
`/var/log/pam-device-auth.log` for a line naming the user, the source
host, and "not in clients allowlist" followed by the allowed list. This is
the only IP gate; since 0.5.7 no IP check runs during token validation.

```bash
sudo grep "not in clients allowlist" /var/log/pam-device-auth.log
```

Fix by adding the connecting IP or CIDR to the user's `clients` attribute
in LLDAP, then retry; there is no cache to clear here, each login reads
InfoPipe fresh.

### Service account cannot log in (no `sshPublicKey`)

Members of `service_account_groups` (`ldap` block in `config.json`) are a
key-only tier: no OIDC step, just a directory-served SSH key from
`sshPublicKey`. If that attribute is empty, sshd has nothing to offer for
publickey and the login fails before pam-device-auth is ever invoked.
`pam-device-auth --check` reports this per service group: a member with no
key shows as locked out of the key-only tier.

```bash
sudo -u root getent -s sss passwd <account>   # resolves at all?
sudo -u root sss_ssh_authorizedkeys <account> # empty output = no key served
```

Set `sshPublicKey` on the account in LLDAP and, if the change does not
show up immediately, see the SSSD cache note below.

### `Username mismatch: token=<x> ssh=<y>`

User opened the device-auth URL and authorised as a **different account**
than the SSH username. Exit 1, clear error printed. User must retry with
the matching Keycloak account.

### `getent -s sss passwd <user>` returns nothing

SSSD cannot resolve the user. Check the `ldap` block, that `--setup-ldap` ran,
and that the user is in the access group with `uidNumber`/`gidNumber` set. After
a uid/gid change the SSSD cache must be fully wiped (`sss_cache -E` is not
enough):

```bash
sudo systemctl stop sssd
sudo rm -f /var/lib/sss/db/*.ldb /var/lib/sss/mc/*
sudo systemctl start sssd
```

### New LLDAP group is not recognized

A group created in LLDAP without a POSIX `gidNumber` will not resolve
through NSS/SSSD as a Unix group at all, even though the group exists in
LDAP and the user is a member. `getent group <name>` and `id <user>` both
omit it, so anything keyed on the resolved Unix group, `access_group`,
`service_account_groups`, `admin_group`, `nopasswd_sudo_groups`, the sshd
`Match Group` block, and the `%groupname` sudoers rule, never matches.

```bash
getent group <name>       # empty if gidNumber is missing
id <user>                 # group absent from the list
```

Set a `gidNumber` on the group in LLDAP, then force a full SSSD cache wipe
(see the previous section); `sss_cache -E` alone is not enough to pick up
a newly added POSIX attribute on an existing group.

### Access revoked but the user still gets in

Removing a user from the access group is bounded by the SSSD cache
(`entry_cache_timeout`) and the OIDC token lifetime. Wipe the SSSD cache (above)
and the user's refresh-token cache to force immediate re-evaluation:

```bash
sudo rm -f /run/pam-device-auth/<user>.json  # force full device auth next login
```

## SSH-level symptoms

### Every login is denied and the auth log has no entries

If the helper cannot open `/var/log/pam-device-auth.log` (missing directory, a
symlink, an immutable file, a read-only filesystem, no space to create a
missing log) or finds a mode other than `0640` that it cannot correct (an
append-only file, a filesystem without `chmod`), it denies the login on
purpose: no audit log, no login. A log that already is `0640` is not changed,
so an append-only log with that mode works. An existing log on a full disk
still opens. sshd discards the helper's stderr, so
the reason goes to syslog (`authpriv`): `journalctl -t pam-device-auth` (or
`grep pam-device-auth /var/log/auth.log`) shows
`pam-device-auth: cannot open /var/log/pam-device-auth.log: ...; denying login (fail closed)`
or
`pam-device-auth: cannot set log file mode 0640: chmod /var/log/pam-device-auth.log: ...; denying login (fail closed)`.
The account phase (`--pam-acct`) denies every non-root user in the same case,
including key-only service accounts: syslog shows the same text ending in
`; denying`, and the PAM module logs
`acct_mgmt: helper exited 3 (infra failure) for user <user> from IP <ip> — denying login (fail-closed)`.
Check and fix the file, and the next login works:

```bash
sudo ls -l /var/log/pam-device-auth.log   # expect 0640 root:adm
sudo lsattr /var/log/pam-device-auth.log  # an "a" or "i" flag blocks it
sudo chattr -a -i /var/log/pam-device-auth.log
```

Root's key-only break-glass login is unaffected.

### Root cannot log in over SSH

If `root_login` is `"disabled"` in `config.json`, the sshd drop-in sets
`PermitRootLogin no` and root is refused on purpose. A file in
`/etc/ssh/sshd_config.d/` that sorts before `10-pam-device-auth.conf` and sets
`PermitRootLogin no` has the same effect. Check what sshd applies:
`sudo sshd -T -C user=root,host=h,addr=192.0.2.1 | grep permitrootlogin`.

To get root back, use a console, set `root_login` to `"key"` (or remove the field)
and run `--setup-ldap`, `--check` and `--enable`. `--check` warns when sshd refuses
root while `root_login` is `"key"`, so an override from another file shows up there.
If root is meant to log in only from some addresses (a `Match User root Address`
block), list them in `root_login_sources`; `--check` then judges root's policy
per address ([configuration reference](configuration-reference.md#root_login_sources)).

### sshd changes from `--setup-ldap` have no effect

`--setup-ldap` writes the sshd drop-in
(`/etc/ssh/sshd_config.d/10-pam-device-auth.conf`) and validates it with
`sshd -t`, but it does not restart or reload sshd. The running sshd
process keeps using whatever config it already loaded until `--enable`
runs (which restarts `ssh.service` on Debian and Ubuntu, `sshd.service` on
Rocky Linux and Fedora) or you reload sshd by hand. This is
why a fresh `--setup-ldap` run can look like it did nothing: the drop-in
is on disk and valid, sshd just has not picked it up yet.

```bash
sudo pam-device-auth --enable            # activates PAM and restarts sshd
# or, without touching PAM state:
sudo systemctl reload ssh.service        # sshd.service on Rocky Linux and Fedora
```

### `Permission denied (publickey,keyboard-interactive)` on known-good user

sshd is offering only keyboard-interactive or refusing the exchange.
Check sshd config:

```bash
sudo sshd -T | grep -E 'authenticationmethods|kbdinteractive|usepam|passwordauthentication'
```

Expected:

```
authenticationmethods publickey,keyboard-interactive:pam
kbdinteractiveauthentication yes
usepam yes
passwordauthentication no
```

The managed drop-in sets `MaxAuthTries 3`, so after the third failed
attempt sshd ends the connection; until then it loops back and the user
sees up to three device prompts.

### QR code is a garbled box of `?`

The SSH client escapes the UTF-8 block characters; the OpenSSH version of the
server does not matter. Known affected clients:

- Win32-OpenSSH (Microsoft Windows), every version
- portable OpenSSH < 10 built without libbsd, for example Termux

With `show_qr` unset, auto-detect hides the QR for these clients. The log
shows the detected client and the decision:

```bash
grep -E 'SSH client|QR not rendered' /var/log/pam-device-auth.log | tail -n 3
# 2026/10/13 09:12:01 [AUTH]   INFO  Directory: SSH client "OpenSSH_for_Windows_9.5", QR hidden (client)
```

A garbled QR therefore means `show_qr` is `true` (the line ends in
`(configured)`) or a client whose version auto-detect trusts. `SSH client
"unknown"` means no version line was found, for example because the drop-in
lost its `LogVerbose` line; the QR is then hidden for every client. A
`QR shown` line followed by
`Directory: QR not rendered, verification URL is <n> bytes (limit 84)` means
the URL is too long for a QR; only link and code appear.

Fixes, in order of preference:

1. Use PuTTY, a distribution OpenSSH (Ubuntu, Debian, Fedora, RHEL) or
   OpenSSH 10 or later on the client; they render the QR
2. Leave `show_qr` unset, so auto-detect decides per client
3. Never show the QR

Manual override in `config.json`:

```json
{ "show_qr": false }
```

Link and code are always displayed as text, with or without the QR.

### Device-auth URL never appears

The helper prints the URL to its stdout, which the PAM module buffers as
`PAM_TEXT_INFO`. On OpenSSH 10+ these are not flushed to the SSH
terminal until a `PAM_PROMPT` follows. If a user presses Enter before the
FLUSH prompt arrives, sshd may drop the info block.

Confirm the helper log shows `FLUSH:Authorize in browser` and the
subsequent `Token polling failed` on timeout.

## Cache / state issues

### Fast path broken, device auth every time

`/run/pam-device-auth` was deleted and not recreated:

```bash
sudo ls -ld /run/pam-device-auth         # expect 0700 root:root
cat /etc/tmpfiles.d/pam-device-auth.conf # expect "d /run/pam-device-auth 0700 root root -"
sudo systemd-tmpfiles --create           # recreate
```

After reboot this is recreated automatically.

### User can log in from any IP despite IP allowlist

The account-phase check treats an empty `clients` result as unrestricted, so
first find out whether the attribute is genuinely empty or SSSD is simply not
returning it. Read what SSSD exposes:

```bash
busctl call org.freedesktop.sssd.infopipe /org/freedesktop/sssd/infopipe \
  org.freedesktop.sssd.infopipe GetUserAttr sas <user> 1 clients
```

Three cases, in decreasing likelihood:

1. **Attribute genuinely unset in the directory**: the user has no `clients`
   value in LLDAP, so no restriction applies. Not a bug; design choice so admins
   can onboard without blocking everyone. See
   [ip-allowlist.md](ip-allowlist.md#4-failure-modes) to make the allowlist
   mandatory.
2. **SSSD is not exporting `clients`** (busctl returns empty but the value IS set
   in LLDAP): the InfoPipe export is misconfigured, so every user looks
   unrestricted. Confirm `/etc/sssd/sssd.conf` has
   `ldap_user_extra_attrs = clients:clients` in the `[domain/...]` section and
   `user_attributes = +clients` in the `[ifp]` section, then
   `systemctl restart sssd`. Re-running `sudo pam-device-auth --setup-ldap`
   renders both correctly.
3. **User is root**: root alone is exempt (break-glass) and never checked.
   Unsupported local non-root users fail closed at the InfoPipe lookup.

### `/var/log/pam-device-auth.log` missing / empty

```bash
sudo ls -l /var/log/pam-device-auth.log   # expect 0640 root:adm
# if 0644 or wrong owner, from an upgrade:
sudo chmod 0640 /var/log/pam-device-auth.log
sudo chown root:adm /var/log/pam-device-auth.log
```

The Go helper checks the mode every time it opens the log, sets `0640` when
the mode differs, and denies non-root logins when that fails (see
[Every login is denied and the auth log has no entries](#every-login-is-denied-and-the-auth-log-has-no-entries));
the C module uses `O_NOFOLLOW` and mode `0640`. logrotate creates new files
with `0640 root adm`.

## Observability

Every helper run logs a clear marker sequence. Grep:

```bash
sudo grep "Authentication attempt" /var/log/pam-device-auth.log   # PAM side
sudo grep "Auth OK\|Access denied\|failed"  /var/log/pam-device-auth.log  # Go side
```

The PAM side uses the `[PAM]` prefix; the Go side uses `[AUTH]`. Both append
to the same file.

## Escalation checklist

If the above doesn't resolve:

1. Reproduce with `PAM_DEVICE_AUTH_TIMEOUT=600` in the sshd environment
   (requires an env block in the sshd unit override).
2. Run `pam-device-auth --check` from the target host to pin down
   discovery vs. token-validation vs. role issues.
3. Decode an affected user's access token and attach the payload JSON to
   any bug report (redact `sub`, `sid`, `jti`).
4. Include `/var/log/pam-device-auth.log` for the affected time window
   and the PAM module's syslog entries (`grep pam_device_auth /var/log/auth.log`).

For security-sensitive reports, see [SECURITY.md](../SECURITY.md).
