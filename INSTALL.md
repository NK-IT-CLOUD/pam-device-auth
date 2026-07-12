# Install pam-device-auth

This guide takes a new host from an installed package to a verified two-factor
SSH login. pam-device-auth requires a working LDAP directory and OIDC provider;
it does not create those services for you.

For the overall login model, start with the [README](README.md). This guide
contains the complete host installation path and the required LLDAP/Keycloak
preparation.

## Before you start

You need:

- Ubuntu 24.04 or newer, Debian 13 or newer, or Rocky Linux 9 or 10, on amd64;
- OpenSSH 9.6 or newer;
- root access and a working root SSH key;
- network access from the host to LDAP and the OIDC provider;
- an LDAP access group, for example `ssh-access`;
- an optional LDAP sudo group, for example `ssh-admin`;
- `uidNumber`, `gidNumber` and `sshPublicKey` for every user who should SSH;
- a public OIDC client with Device Authorization enabled and matching roles.

Keep a root SSH session open in a second terminal throughout setup. Root uses a
local key and is the recovery path if the non-root SSH policy is misconfigured.

Check the server version with:

```bash
sshd -V
```

On unprivileged LXC containers, keep directory UIDs and GIDs below 65536.

## 1. Install the package

APT is the recommended installation method:

```bash
sudo install -d -m755 /etc/apt/keyrings
curl -fsSL https://apt.nk-it.cloud/gpg.key \
  | sudo gpg --batch --yes --dearmor -o /etc/apt/keyrings/nk-it-cloud.gpg
```

Verify the downloaded key before trusting the repository. The published
signing-key fingerprint is:

```text
A66E 54ED 9E75 BF3D E610 2ED5 AE60 35D7 D6D3 1EB4
```

```bash
gpg --show-keys --with-fingerprint /etc/apt/keyrings/nk-it-cloud.gpg
```

If the fingerprint does not match, stop here: delete
`/etc/apt/keyrings/nk-it-cloud.gpg` and do not add the repository. Otherwise
continue:

```bash
echo "deb [signed-by=/etc/apt/keyrings/nk-it-cloud.gpg] https://apt.nk-it.cloud/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/nk-it-cloud.list
sudo apt update
sudo apt install pam-device-auth
```

APT installs the SSSD integration packages as recommended dependencies. The
package deliberately does not activate PAM during installation, so an
unconfigured identity provider cannot lock you out.

To install a downloaded package instead:

```bash
sudo apt install ./pam-device-auth_<version>_amd64.deb
```

On Rocky Linux 9 or 10, install the RPM release asset instead:

```bash
sudo dnf install ./pam-device-auth-<version>.x86_64.rpm
```

## 2. Prepare the directory and OIDC provider

Before touching sshd, confirm that:

1. LDAP is reachable from the host. Prefer LDAPS and install the directory CA.
2. Every intended SSH user has a Unix UID, primary GID and valid SSH public key.
3. The access and sudo groups have Unix GIDs.
4. The OIDC client has Device Authorization enabled.
5. Tokens contain the required access role and, when used, the IP allowlist
   claim. Sudo authorization remains in the LDAP admin group.

For Keycloak, create a public client such as `ssh-server`, enable **Device
Authorization Grant**, disable client authentication, and disable the Standard,
Direct Access, Implicit and Service Account flows. Create the realm roles
`ssh-access` and `ssh-admin`, and keep the default `roles` client scope. When
Keycloak federates LDAP groups, assign the matching realm role to each imported
group under **Groups → Role mapping**. Tokens for access-group members must then
contain `ssh-access`. Mapping `ssh-admin` into the token keeps role reporting
consistent, but sudo itself is enforced by LDAP group membership through
`pam_sss` and `/etc/sudoers.d/pam-device-auth`.

The reference deployment is tested with LLDAP 0.6.3. Create these custom
attributes in **Attributes**:

| Schema | Attribute | Type | List | Value |
|---|---|---|---|---|
| Group | `gidNumber` | Integer | No | unique Unix group ID per group |
| User | `uidNumber` | Integer | No | unique Unix user ID |
| User | `gidNumber` | Integer | No | primary access-group ID |
| User | `sshPublicKey` | String | No | complete OpenSSH public key |
| User, optional | `clients` | String | Yes | allowed IPs/CIDRs |

Use LLDAP's built-in `uid` and `member` attributes. Groups remain
`groupOfNames`; SSSD uses `rfc2307bis`. `homeDirectory` and `loginShell` are not
required because `--setup-ldap` supplies them. Set `gidNumber` on every group
pam-device-auth references, not just the access and sudo groups: a group without
a `gidNumber` does not resolve through SSSD, so its members are locked out. That
includes the optional `service_account_groups` and `nopasswd_sudo_groups` groups
(see below). Set each user's primary `gidNumber` to the access-group ID.

For an optional source-IP restriction, set the multi-valued `clients` attribute
on the user in the directory. pam-device-auth reads it from SSSD in the PAM
account phase and denies logins from any address not on the list. A user without
a `clients` attribute is unrestricted. Only root is exempt; unsupported local
non-root users fail closed.
See [docs/ip-allowlist.md](docs/ip-allowlist.md).

## 3. Configure pam-device-auth

Create `/etc/pam-device-auth/config.json` with mode `0600`. This example uses
Keycloak and an LDAPS directory:

```bash
sudo install -m600 /dev/stdin /etc/pam-device-auth/config.json <<'JSON'
{
  "issuer_url": "https://sso.example.com/realms/myrealm",
  "client_id": "ssh-server",
  "required_role": "ssh-access",
  "sudo_role": "ssh-admin",
  "allowed_algorithms": ["RS256"],
  "ldap": {
    "uri": "ldaps://ldap.example.com:636",
    "base_dn": "dc=example,dc=com",
    "bind_dn": "uid=nss-ro,ou=people,dc=example,dc=com",
    "bind_password": "<read-only bind password>",
    "access_group": "ssh-access",
    "admin_group": "ssh-admin"
  }
}
JSON
```

Adjust `allowed_algorithms` to the signing algorithm used by your provider.

The LDAP bind password is stored in the root-only config and written to
`/etc/sssd/sssd.conf` for SSSD. Use a read-only directory account.

The common fields are summarized in the
[README configuration table](README.md#configuration).

## 4. Configure the host

Run:

```bash
sudo pam-device-auth --setup-ldap
```

This command configures SSSD, NSS, automatic home creation, sudo and the sshd
drop-in. It can be rerun after configuration changes, but always review its
local-account migration warning before continuing.

Important: if a local account has the same name but a different UID from a
directory user, `--setup-ldap` announces and automatically migrates it. Running
processes are terminated, the local passwd/shadow entry is removed, and the
home files, mail spool and crontab are preserved and re-owned. Genuine
local-only accounts and same-UID entries are not changed.

Do not activate SSH yet. First run the preflight.

## 5. Preflight check

```bash
sudo pam-device-auth --check
```

Representative output with example names and counts:

```text
Config OK: issuer=https://sso.example.com/realms/myrealm client=ssh-server role=ssh-access sudo_role=ssh-admin
OIDC:
  [OK]   discovery reachable (device=https://sso.example.com/realms/myrealm/protocol/openid-connect/auth/device)
  [OK]   issuer matches config
Directory (SSSD/NSS):
  [OK]   sss_ssh_authorizedkeys present (publickey factor source)
  [OK]   /etc/sssd/sssd.conf present
  [OK]   sssd service active
  [OK]   access group "ssh-access" resolves via NSS (2 member(s)); SSSD↔LDAP↔CA path OK
  [WARN] 1 of 2 member(s) have NO sshPublicKey; locked out of non-root login until set: no-key-user
SSH daemon:
  [OK]   AuthorizedKeysCommand → sss_ssh_authorizedkeys (directory key = factor 1)
  [OK]   non-root: publickey,keyboard-interactive:pam (2FA)
  [OK]   root: publickey only (break-glass)
  [OK]   non-root: AuthorizedKeysFile none (directory key is the only publickey source)

Activation: not yet enabled; run 'pam-device-auth --enable' once checks are green.

Critical checks passed; 1 warning(s); review the [WARN] items.
```

Interpret the result as follows:

- `[FAIL]` is a blocker. Fix it before activation.
- `[WARN]` is non-blocking but must match the intended state. A missing key is
  acceptable only for a user who is deliberately not allowed to SSH.
- `[OK]` confirms live host state, not only JSON syntax.

`--enable` runs the same preflight and refuses to activate when a blocker exists.

## 6. Activate and test

Make sure the root recovery session is still open, then activate:

```bash
sudo pam-device-auth --enable
```

The command backs up `/etc/pam.d/sshd`, enables the PAM module and restarts
sshd. If the backup fails, activation still proceeds with a loud
`[WARN] could not back up` message. Investigate before making further
changes, because the rollback copy for `--disable` is then missing.
Open a new terminal and test before closing the root session:

```bash
ssh <directory-user>@<host>
```

Expected behavior:

1. The directory SSH key is accepted.
2. A browser URL, code and optional QR code appear.
3. After approval, the shell opens.
4. A later login from the same IP normally uses silent refresh but still
   requires the SSH key.

Inside the session, verify identity and sudo:

```bash
id
getent -s sss passwd "$USER"
sudo -k
sudo id
```

Finally run `sudo pam-device-auth --check` again. It should report that
pam-device-auth is active and contain no unexplained warnings or failures.

## Upgrade

With the APT repository configured:

```bash
sudo apt update
sudo apt install --only-upgrade pam-device-auth
sudo pam-device-auth --check
```

Keep a root session open until a fresh non-root login succeeds. Package upgrades
preserve `config.json`, PAM configuration and the installed sshd drop-in.

An upgrade does not rewrite an existing
`/etc/ssh/sshd_config.d/10-pam-device-auth.conf`. Hosts installed before the
v0.5.4 `AuthorizedKeysFile none` hardening must run
`sudo pam-device-auth --setup-ldap` again. The preflight warns when the old
policy is still effective.

If the check fails, keep the root session open, fix the reported blocker and
rerun it before testing a new non-root session.

## Service accounts & sudo tiers

Two optional fields in the `ldap` block of `config.json` add narrower tiers on
top of the default access/admin groups. Both are opt-in: leave them unset and
behavior is unchanged.

- `service_account_groups`: a list of LLDAP groups whose members authenticate
  SSH with the directory `sshPublicKey` only. There is no OIDC device flow for
  these logins. Intended for automation/service accounts, not interactive
  users.
- `nopasswd_sudo_groups`: a list of LLDAP groups granted passwordless sudo
  (`NOPASSWD:ALL`) in the managed sudoers file, in addition to `ldap.admin_group`
  (which still authenticates with the directory password).

A service account is an ordinary LLDAP user with a directory `sshPublicKey`,
placed in a group listed under `service_account_groups`. Set it up exactly like
an interactive OIDC user, except the group tells pam-device-auth's sshd
`Match Group` clause to treat the login as key-only and skip the OIDC step.

**gidNumber prerequisite:** any group referenced in `service_account_groups` or
`nopasswd_sudo_groups` needs a POSIX `gidNumber`, the same as the access and
sudo groups described above. Without it, SSSD cannot resolve the group over
NSS: `getent group <name>` and `id <user>` silently omit it, and the sshd
`Match Group` clause and the sudoers rule then never match. Set `gidNumber` on
the group in LLDAP before referencing it in `config.json`.

A service account is single-factor by design: the directory key is the only
check. Keep `service_account_groups` membership small and treat the
corresponding private keys as sensitive credentials. `nopasswd_sudo_groups`
grants sudo without a password prompt, so keep that membership small as well.
`sudo pam-device-auth --check` reports both tiers alongside the existing
access/admin checks.

Uninstall removes the tool-managed sudoers file, rolling back the admin-group
rule and any `nopasswd_sudo_groups` rules together. See
[Uninstall](#uninstall).

## IP allowlist (`clients`)

The multi-valued `clients` attribute (set on a user in LLDAP, [step
2](#2-prepare-the-directory-and-oidc-provider)) pins that user to a list of
source IPs/CIDRs. Leave it unset for a user and their login is unrestricted.

The allowlist is enforced for every SSH login in the PAM **account** phase,
independent of the authentication method: this covers key-only service
accounts as well as interactive OIDC users. Because a service account's key is
the only factor it has, pinning `clients` on it is a compensating control and
is recommended for every entry in `service_account_groups`.

**root is exempt.** The account-phase gate never applies to root, and it never
depends on SSSD/InfoPipe, so an SSSD outage cannot lock out the local
break-glass key.

**Fail-closed:** the gate is enforced through the SSSD InfoPipe (`ifp`
responder), which `--setup-ldap` configures automatically (no extra package is
required, only `busctl` from systemd). The account phase reads `clients` for
every directory user, so if InfoPipe is unavailable the lookup fails and the
login is denied. This denies **every directory user** at the account phase,
whether or not `clients` is set, until InfoPipe is restored. Local and `root`
logins are exempt (root break-glass never touches SSSD/InfoPipe), so the
recovery path stays open during an outage.

`sudo pam-device-auth --check` reports InfoPipe health and lists which
directory members are IP-pinned versus unrestricted, warning on service
accounts that have no `clients` value.

## Uninstall

Remove the package while keeping configuration:

```bash
sudo apt remove pam-device-auth
```

Remove the package and its managed configuration completely:

```bash
sudo apt purge pam-device-auth
```

Removal restores the original PAM sshd configuration, removes the managed sshd
drop-in and the managed sudoers file (`/etc/sudoers.d/pam-device-auth`,
including any `nopasswd_sudo_groups` rules), and restarts sshd. It deliberately
does not undo directory-mode host configuration: `/etc/sssd/sssd.conf`, NSS
`sss` entries, pam_mkhomedir, directory identities and home directories
remain. Review and remove those separately only when decommissioning the host.

## Build from source

Building creates the same package used by the normal installation path:

```bash
sudo apt install build-essential libpam0g-dev golang-go
git clone https://github.com/NK-IT-CLOUD/pam-device-auth
cd pam-device-auth
make test
make deb
sudo apt install ./build/packages/pam-device-auth_<version>_amd64.deb
```

On Rocky Linux, install the equivalent build dependencies with
`sudo dnf install pam-devel gcc golang` and run `make rpm` instead of `make deb`.

Using the package is safer than copying the binary and PAM module by hand because
it also installs tmpfiles, log rotation, configuration templates and removal
hooks. Development details are in [CONTRIBUTING.md](CONTRIBUTING.md).

## Migrating from keycloak-ssh-auth

Installing pam-device-auth preserves the old
`/etc/keycloak-ssh-auth/keycloak-pam.json` as
`/etc/pam-device-auth/keycloak-pam.json.migrated` and removes obsolete package
integration files. The old `keycloak_url` plus `realm` settings become one full
issuer URL:

```json
{
  "issuer_url": "https://sso.example.com/realms/myrealm",
  "client_id": "ssh-server",
  "required_role": "ssh-access"
}
```

Complete the LDAP block and current optional settings using the
[README configuration table](README.md#configuration), then follow steps 4
through 6 above.

## Troubleshooting

Start with:

```bash
sudo pam-device-auth --check
sudo tail -f /var/log/pam-device-auth.log
sudo journalctl -u ssh -f
```

If the preflight is green but login still fails, capture the helper log and SSH
journal from the same attempt. Check that the SSH username matches the OIDC
username, the access token contains the required role, the directory key is
valid, the server clock is synchronized and the client IP is present in the
configured claim.

| Symptom | Check |
|---|---|
| `Permission denied (publickey,keyboard-interactive)` | valid `sshPublicKey`, access-group membership, and effective sshd policy |
| OIDC URL does not appear | `/var/log/pam-device-auth.log`, SSH journal, issuer reachability |
| Username mismatch | OIDC `preferred_username` must exactly match the SSH username |
| Browser authorization repeats | cache permissions, provider refresh-token lifetime, and client IP detection |
| Sudo denied | membership in `ldap.admin_group`, SSSD status, and directory password |

## Installed files

| Component | Path |
|---|---|
| Helper | `/usr/local/bin/pam-device-auth` |
| PAM module | `/usr/lib/security/pam_device_auth.so` |
| Main configuration | `/etc/pam-device-auth/config.json` |
| sshd drop-in | `/etc/ssh/sshd_config.d/10-pam-device-auth.conf` |
| Sudoers drop-in | `/etc/sudoers.d/pam-device-auth` |
| PAM backup | `/etc/pam.d/sshd.original` |
| Log | `/var/log/pam-device-auth.log` |
| Token cache | `/run/pam-device-auth/` |
