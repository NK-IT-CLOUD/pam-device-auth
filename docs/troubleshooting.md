# Troubleshooting

Symptom-first index. For each issue: likely cause and the commands to
confirm it.

First stop: `/var/log/pam-device-auth.log` (Go helper) and
`journalctl -u ssh -f` (PAM module via sshd). Both should be tailing
during an auth attempt.

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
the account-phase IP gate needs it. On Debian, Ubuntu and the RHEL
family, the `ifp` responder ships in a separate `sssd-dbus` package, not in the
base `sssd` package.
`--setup-ldap` installs `sssd-dbus` itself as part of its
package step, so a failed or interrupted run (network hiccup during `apt
install`, package held back, `sssd.conf` edited by hand afterward pointing
at a host that later had the package removed) can leave `sssd.conf`
referencing `[ifp]` with the package missing. sssd then refuses to start.

Confirm the package is present and check sssd's own error:

```bash
dpkg -s sssd-dbus            # Debian/Ubuntu; expect "Status: install ok installed"
rpm -q sssd-dbus             # RHEL family
sudo systemctl status sssd -l
sudo journalctl -u sssd -n 50 --no-pager
```

If the package is missing, install it and restart sssd:

```bash
sudo apt-get install sssd-dbus     # Debian/Ubuntu
sudo dnf install sssd-dbus         # RHEL family
sudo systemctl restart sssd
```

On a RHEL-family host set up with release 0.5.10 or earlier, `sssd-dbus` is installed
only as a dependency, not as a package you asked for. `dnf remove pam-device-auth`
then removes it too, and the next restart of sssd fails with `Could not restart
critical service [ifp]`. Run `sudo dnf mark install sssd-dbus` once (or re-run
`--setup-ldap` from release 0.5.11 or later, which marks it) so that removing the
package leaves it in place. `--check` reports a missing responder as a blocker.

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
sudo PAM_USER=alice PAM_RHOST=10.0.20.2 pam-device-auth --debug
# logs will include: "Roles extracted: [...]"
```

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

If the helper cannot open `/var/log/pam-device-auth.log` (full disk, wrong
permissions, missing directory) it denies the login on purpose: no audit log,
no login. sshd discards the helper's stderr, so the reason goes to syslog:
`journalctl -t pam-device-auth` (or `grep pam-device-auth /var/log/auth.log`)
shows `cannot open /var/log/pam-device-auth.log: ...; denying login (fail
closed)`. Fix the log file and the next login works. Root's key-only break-glass
login is unaffected.

### Root cannot log in over SSH

If `root_login` is `"disabled"` in `config.json`, the sshd drop-in sets
`PermitRootLogin no` and root is refused on purpose. A file in
`/etc/ssh/sshd_config.d/` that sorts before `10-pam-device-auth.conf` and sets
`PermitRootLogin no` has the same effect. Check what sshd applies:
`sudo sshd -T -C user=root,host=h,addr=192.0.2.1 | grep permitrootlogin`.

To get root back, use a console, set `root_login` to `"key"` (or remove the field)
and run `--setup-ldap`, `--check` and `--enable`. `--check` warns when sshd refuses
root while `root_login` is `"key"`, so an override from another file shows up there.

### sshd changes from `--setup-ldap` have no effect

`--setup-ldap` writes the sshd drop-in
(`/etc/ssh/sshd_config.d/10-pam-device-auth.conf`) and validates it with
`sshd -t`, but it does not restart or reload sshd. The running sshd
process keeps using whatever config it already loaded until `--enable`
runs (which restarts `sshd.service`) or you reload sshd by hand. This is
why a fresh `--setup-ldap` run can look like it did nothing: the drop-in
is on disk and valid, sshd just has not picked it up yet.

```bash
sudo pam-device-auth --enable            # activates PAM and restarts sshd
# or, without touching PAM state:
sudo systemctl reload sshd
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

Non-Unicode-capable SSH client rendering the block characters. Known
affected clients:

- Win32-OpenSSH (Microsoft Windows): bug in `vis()`/stream decoding
- Termux default `less`

Fixes, in order of preference:

1. Use PuTTY / iTerm2 / Ubuntu SSH / mosh; they all render fine
2. Auto-detect does the right thing on OpenSSH 9.x servers with
   `LogLevel DEBUG1` set in `/etc/ssh/sshd_config.d/10-pam-device-auth.conf`
3. OpenSSH 10+ servers (Debian 13+) render QR for all clients regardless

Manual override in `config.json`:

```json
{ "show_qr": false }
```

Link + code are always displayed as text fallback.

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

The Go helper re-asserts `0640` on open; the C module uses `O_NOFOLLOW`
and mode `0640`. logrotate creates new files with `0640 root adm` after
the v0.3.5+ postinst.

## Observability

Every helper run logs a clear marker sequence. Grep:

```bash
sudo grep "Authentication attempt" /var/log/pam-device-auth.log   # PAM side
sudo grep "Auth OK\|Access denied\|failed"  /var/log/pam-device-auth.log  # Go side
```

The PAM side uses the `[PAM]` prefix; the Go side uses `[AUTH]`. The file
is append-only and shared between both.

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
