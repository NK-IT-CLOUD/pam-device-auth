# Directory mode setup (SSSD/LLDAP identity + OIDC SSH layer)

Identity, groups, home dir and the sudo password come from the directory (LLDAP
via SSSD/NSS, the NSS best practice). pam-device-auth is the **OIDC SSH-login layer**
on top. This is the only supported model, and the only one that works on
**OpenSSH 10.2+**, which refuses PAM for users `getpwnam` cannot resolve.

## Prerequisites (per host)

1. **Directory CA trusted**: if the directory uses a private CA, install its
   certificate on the host (Debian/Ubuntu: `/usr/local/share/ca-certificates/` and
   `update-ca-certificates`; RHEL family: `/etc/pki/ca-trust/source/anchors/` and
   `update-ca-trust`). Verify:
   `echo | openssl s_client -connect ldap.example.com:636 -CApath /etc/ssl/certs | grep 'Verify return'` gives `0 (ok)`.
2. **Network**: the host can reach the directory on its LDAPS port (636 for most
   servers, 6360 for LLDAP). Allow it in every firewall on the path.
3. **DNS**: the name in `ldap.uri` resolves and matches a name or IP in the
   directory certificate's subject alternative names.
4. **SSSD packages**: `sssd-ldap libnss-sss libpam-sss sssd-dbus` on Debian/Ubuntu,
   `sssd sssd-ldap sssd-tools sssd-dbus authselect oddjob-mkhomedir` on the RHEL
   family (`--setup-ldap` installs them if missing). `sssd-dbus` provides the SSSD
   InfoPipe (`ifp`) responder. Without it sssd does not start, because `--setup-ldap`
   enables `ifp` in `sssd.conf`; `--check` reports a missing responder as a blocker.

## LLDAP data model (one-time, central)

POSIX is served via LLDAP **custom attributes** (`posixAccount`). Numbering: **all
below 60000** (unprivileged LXC maps only 65536 uids; above that gives
`setresuid: Invalid argument`):

| Object | Attribute | Value |
|--------|-----------|-------|
| group `ssh-access` (or your `access_group`) | `gidNumber` | `6000` (login gate **and** users' primary group) |
| group `ssh-admin` (or your `admin_group`)   | `gidNumber` | `6001` (sudo, password-prompted) |
| group `ssh-service` (optional, `service_account_groups`) | `gidNumber` | `6002` (key-only login, no OIDC) |
| group `ssh-admin-nopasswd` (optional, `nopasswd_sudo_groups`) | `gidNumber` | `6003` (passwordless sudo) |
| each SSH user      | `uidNumber` | `10000+` (sequential) |
| each SSH user      | `gidNumber` | `6000` (primary = access group) |
| each SSH user      | `sshPublicKey` | the user's SSH public key, **required** (2FA: publickey factor, served to sshd via `sss_ssh_authorizedkeys`) |
| each SSH user      | `clients`   | allowed source IPs/CIDRs (optional; empty means unrestricted) |

Every LLDAP group used by pam-device-auth, including `service_account_groups` and
`nopasswd_sudo_groups`, needs a POSIX `gidNumber`. A group without one is dropped
by SSSD and will not resolve, even if membership looks correct in LLDAP.

Set the values in the LLDAP Admin UI, or send GraphQL mutations to the LLDAP API
as an administrator:
```graphql
mutation { updateGroup(group: {id: <gid>, insertAttributes: [{name:"gidNumber", value:["6000"]}]}) { ok } }
mutation { updateUser(user: {id:"<u>", insertAttributes: [{name:"uidNumber", value:["10001"]},{name:"gidNumber", value:["6000"]}]}) { ok } }
```
> **Tooling:** [lldap-cli](https://github.com/Zepmann/lldap-cli) (Zepmann) wraps the LLDAP
> GraphQL API (`schema` / `user` / `group` subcommands, `jq`+`curl`) and is the cleaner way
> to *create* the custom attributes and set `uidNumber`/`gidNumber`/`sshPublicKey`, manage
> membership and passwords, versus the raw mutations above.
> **Tested version:** LLDAP 0.6.3. Older versions were not re-verified for this
> release.
> Password change from a host works via the LDAP Password Modify exop (RFC 3062), which
> LLDAP implements, verified live (`Successfully (re)set password` in LLDAP's log).

## Group model

pam-device-auth has two independent group axes, configured in the `ldap` block of
`/etc/pam-device-auth/config.json`:

- **SSH auth tier**: `access_group` (members log in with SSH key + OIDC, the normal
  interactive path) and `service_account_groups` (members log in with SSH key only,
  no OIDC challenge, meant for automation/service accounts). A user needs to be in
  one of these to log in at all; the SSSD access filter ORs them together.
- **Sudo tier**: `admin_group` (members get sudo, prompted for their LLDAP password)
  and `nopasswd_sudo_groups` (members get `NOPASSWD:ALL`). These are opt-in and
  separate from the auth tier: a user can be sudo-capable without being in
  `access_group`, or vice versa.

Membership in `access_group` also has to line up with the OIDC side: it must be
Keycloak-federated so the token carries `required_role`. The IP allowlist (the
`clients` attribute) is read from the directory through the SSSD InfoPipe in the
PAM account phase and involves no token claim; see [ip-allowlist.md](ip-allowlist.md).

## Host setup

1. Place the config at `/etc/pam-device-auth/config.json` (start from
   `configs/config.json`): `required_role: ssh-access`,
   `sudo_role: ssh-admin`, and the `ldap` block (uri, base_dn,
   bind_dn as a read-only LLDAP account in `lldap_strict_readonly`, bind_password,
   access_group, admin_group, and optionally service_account_groups /
   nopasswd_sudo_groups). `chmod 600`.
2. `sudo pam-device-auth --setup-ldap`: installs the SSSD packages if missing,
   writes `/etc/sssd/sssd.conf` (rfc2307bis, ldaps, `auth_provider=ldap` for sudo,
   `ldap_access_filter` covering access_group and any service_account_groups, the
   `[ifp]` responder), nsswitch (`sss`), `pam_mkhomedir`,
   `/etc/sudoers.d/pam-device-auth` (`%admin_group` password sudo,
   `%nopasswd_sudo_groups` NOPASSWD), and restarts sssd. It does **not** restart
   sshd or touch the OIDC layer.
3. Verify: `getent -s sss passwd <user>` and `id <user>` resolve (access group
   primary, admin group secondary where applicable).
4. `sudo pam-device-auth --enable`: activates the OIDC SSH layer (pam_device_auth.so),
   copies the sshd PAM template, and restarts sshd.
5. `sudo pam-device-auth --check`: preflight covering config, OIDC, directory/SSSD,
   sshd factors, IP-pin posture, and InfoPipe health. Run it any time after setup to
   confirm the pieces line up, and again after any config or LLDAP change.

Login: `ssh <user>@host` triggers, on first connection or from a new IP, the OIDC
device flow; from a known IP it is a silent cached refresh (re-validated
server-side: role + IP allowlist). Service-account users skip OIDC entirely and
authenticate with the SSH key alone. `sudo` prompts for the LLDAP password unless
the user is in a `nopasswd_sudo_groups` group.

## IP allowlist (`clients` attribute)

The `clients` attribute is a per-user source-IP/CIDR allowlist, enforced on every
login, including key-only service accounts, by the PAM account phase. It reads
`clients` from the SSSD InfoPipe over D-Bus (`busctl`), not from the OIDC token.

- root alone is exempt: this is the break-glass path and never touches SSSD.
  Local non-root users are not exempt, preventing same-name local entries from
  bypassing directory IP policy.
- if a directory user has no `clients` attribute, the login is unrestricted.
- if the InfoPipe read fails for any reason, the gate fails closed and denies the
  login. This means an SSSD or InfoPipe outage denies all directory users, not
  just the ones with a `clients` value set.

`pam-device-auth --check` reports both the IP-pin posture and InfoPipe health, so
run it after setup to catch a missing `sssd-dbus` package or a misconfigured `ifp`
responder before it locks anyone out.

## Migration on existing hosts (IMPORTANT)

`nsswitch` resolves `passwd: files ... sss`: **`files` (local `/etc/passwd`) wins
before `sss` (directory).** So on a host that already has a **local** account with
the same name as a directory user (e.g. from the old `create_user` model, or a
hand-made account), the **local account shadows the directory one**:

- `getpwnam`/login returns the **local** uid, not the directory uid, so directory
  groups (the admin group) and central sudo do not apply; `/home/<u>` keeps its old
  ownership; the user lands in a split-brain state where SSH may work as the local
  user while LDAP-gated sudo is denied.
- `useradd <name>` is refused once the directory provides the name (a safety net
  against new collisions).

`--setup-ldap` automatically migrates each pre-existing collision after printing
the complete destructive scope. For every listed user it kills running processes,
removes the local passwd/shadow entry with `userdel` (without deleting the home),
and re-owns the home, mail spool and crontab to the directory uid/gid. Genuine
local-only accounts and same-uid entries are left untouched.

Review the warning carefully when running the command from a persistent root
session. The equivalent manual steps are:

```bash
# stop their sessions, then:
userdel <user>                              # remove the local /etc/passwd entry
chown -R <user>:ssh-access /home/<user>     # re-own home to the directory uid/gid
# (the directory uidNumber/gidNumber now resolve via SSSD)
```

A plain package update (`dpkg`) does not migrate accounts. Re-running
`--setup-ldap` does perform the automatic migration described above.

## Revocation SLA

Removing a user from `access_group` or from any group listed in
`service_account_groups` in LLDAP blocks new SSH logins: the account-phase
`pam_sss` access filter denies them once the **SSSD cache expires**
(`entry_cache_timeout = 600`, so up to 10 minutes). The OIDC role check is not
needed for the denial, so Keycloak group-to-token federation lag does not extend
it. Removing a user from `admin_group` or from any group in `nopasswd_sudo_groups`
revokes sudo only, on the same cache schedule, and does not affect login. For
immediate revocation: `sss_cache -E && systemctl restart sssd` on the host.
Existing sessions are not terminated. The `clients` IP allowlist is opt-in per
user (empty means unrestricted) and is not a substitute for group membership
control.

## Uninstall

Removing the package restores `/etc/pam.d/sshd`, removes the sshd drop-in, and
removes the managed sudoers file `/etc/sudoers.d/pam-device-auth`, so no NOPASSWD
grant is left behind. This applies to both `.deb` (dpkg) and `.rpm` (dnf/rpm)
installs.

## Troubleshooting

- **`setresuid <n>: Invalid argument`** on login: uidNumber is 65536 or higher on
  an LXC host. Set an in-range uidNumber (below 60000) in LLDAP.
- **Changed a uidNumber/gidNumber in LLDAP but the host still shows the old value**:
  `sss_cache -E` is not enough. Full wipe:
  `systemctl stop sssd; rm -f /var/lib/sss/db/*.ldb /var/lib/sss/mc/*; systemctl start sssd`.
  (New users do not need this.) Also remove the stale `/home/<user>` if the uid changed.
- **`getent -s sss passwd <user>` empty**: check CA trust, firewall (6360), and that
  the user has `uidNumber` and `gidNumber` (a posixAccount without gidNumber is
  dropped by SSSD, and the same applies to groups without a gidNumber).
- **sudo "Authentication failed"**: SSSD `auth_provider` must be `ldap`; the user
  enters their LLDAP password.
- **InfoPipe/account-phase denies everyone**: `sssd-dbus` is not installed,
  or the `[ifp]` section absent from `sssd.conf`. Check with
  `pam-device-auth --check` and `busctl status org.freedesktop.sssd.infopipe`.

## Notes: 2FA model and activation ordering

- `--setup-ldap` writes an sshd drop-in with **`AuthenticationMethods publickey,keyboard-interactive:pam`**
  (AND) plus **`AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys`**. Non-root login therefore
  requires both an SSH key (fetched centrally from LLDAP `sshPublicKey`) and OIDC: true
  2FA, no IP-only silent path. Service-account users (in `service_account_groups`) are the
  exception: they authenticate with the SSH key alone, no OIDC. The global default is now
  **`AuthorizedKeysFile none`**, so non-root local `authorized_keys` files are never consulted.
  Root stays key-only (break-glass), unless `root_login` is set to `disabled` (see the
  [configuration reference](configuration-reference.md#root_login)): a `Match User root` block in the drop-in restores
  `AuthorizedKeysFile .ssh/authorized_keys` for root only, so `/root/.ssh/authorized_keys`
  keeps working; root never uses OIDC/SSSD.
- **Activation ordering (avoid lockout)**: the AND drop-in takes effect on the next sshd restart
  (done by `--enable`). Populate `sshPublicKey` for every SSH user in LLDAP before that restart:
  a non-root user without a key in LLDAP cannot satisfy the publickey factor and is locked out
  (root unaffected). Order per host: keys in LLDAP first, then `--setup-ldap`, then `--enable`.
- Revoke a user: remove them from the access group in LLDAP (denies new logins and the SSSD
  access filter, within `entry_cache_timeout`). Removing `sshPublicKey` alone also blocks the
  publickey factor.
