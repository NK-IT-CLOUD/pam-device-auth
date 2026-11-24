# Active Directory setup

pam-device-auth can take identities, groups, SSH keys and the source-IP
allowlist from an Active Directory. `--setup-ldap` writes the SSSD
configuration from the `ldap` block of `config.json` with `"profile": "ad"`;
`--check` and `--enable` work as with LLDAP. Every key is described in the
[configuration reference](configuration-reference.md#ldap).

## What the directory needs

- **A read-only service account** for SSSD's lookups, or a keytab for it (see
  [Transport and bind](#transport-and-bind)). It must be able to read
  `userAccountControl` and `accountExpires` of the users: without them every
  directory login is refused (see
  [Disabled and expired accounts](#disabled-and-expired-accounts)).
- **An attribute for the SSH public key** (`attributes.ssh_key`). AD has no
  standard one. A multi-valued attribute such as `sshPublicKey` from an
  OpenSSH-LPK schema extension holds one key per value; a single-valued
  attribute holds one key.
- **An attribute for the source-IP allowlist** (`attributes.clients`): one IP
  address or CIDR range per value. More than one allowed address needs a
  multi-valued attribute. A single-valued attribute such as
  `extensionAttribute1` … `15` or `msDS-cloudExtensionAttribute1` … `20` holds
  exactly one entry. A user without a value is unrestricted. A value that is
  neither an address nor a CIDR range is skipped, so a comma-separated list in
  one value matches nothing.
- **Groups** for login (`access_group`), sudo (`admin_group`) and optionally
  key-only service accounts (`service_account_groups`) and passwordless sudo
  (`nopasswd_sudo_groups`). Nested groups work, and groups may sit in any OU.
  SSSD matches a group by its pre-Windows 2000 name (`sAMAccountName`). Names
  in `config.json` must be bare group names (`[A-Za-z_][A-Za-z0-9_-]*`, no
  spaces, no `DOMAIN\`). SSSD reports AD names in lower case, so write them in
  lower case.
- **Login names.** The login name is the user's `sAMAccountName` (or the
  attribute in `attributes.username`), in lower case. The access token's
  `preferred_username` must be the same name: with Keycloak's LDAP federation,
  set *Username LDAP attribute* to `sAMAccountName`. Users must not be able to
  change that name at the identity provider
  ([keycloak-setup.md](keycloak-setup.md#user-names)).

### Who can write the key and the allowlist

Both attributes are security settings, so users must not be able to change
them on their own account. By default AD lets every user write the attributes
of the *Personal Information* property set on their own object. That set
includes `info` and `msDS-cloudExtensionAttribute1` … `20`, so with one of
these a user could replace their own SSH key or clear their allowlist.
Attributes from a schema extension belong to no property set unless you assign
one, so by default users cannot write them, and the service account can read
them only where its permissions cover them.

Check both directions before you enable the host: the user cannot change the
attributes, and the service account can read them. An allowlist the service
account cannot read looks empty to SSSD, and the user is then unrestricted.
To see what the service account reads:

    LDAPTLS_CACERT=/usr/local/share/ca-certificates/example-ad-ca.crt \
      ldapsearch -x -H ldaps://dc1.example.com -D svc-sssd@example.com -W \
      -b DC=example,DC=com '(sAMAccountName=alice)' sshPublicKey exampleSshClients

### A group as an account's primary group

An account may have the access group or a service group as its primary group,
for example a service account that is taken out of `Domain Users`. AD then
keeps the membership on the account (`primaryGroupID`) and drops the account
from the group's `member` attribute. Logins work as for every other member:
sshd (`Match Group`), SSSD (`simple_allow_groups`) and sudo count the primary
group.

`--check` sees less. Its member counts and its checks per member (SSH key,
allowlist, SSH factors, ID map) work on the members NSS lists, and SSSD lists
such an account only once the host has resolved it: when it refreshes a group,
it adds the accounts with that primary group from its own cache. A host that
has never seen the account leaves it out, so the same directory can show
`2 key-only` on one host and `3 key-only` on another. `--check` prints an
`[INFO]` line about this with profile `ad`. To make a host list an account,
resolve it, let the group expire and check again:

    id svc-backup
    sss_cache -G
    pam-device-auth --check

To look at one account directly:

    id svc-backup                          # the groups, the primary group first
    sss_ssh_authorizedkeys svc-backup      # the key sshd gets
    sshd -T -C user=svc-backup | grep -i '^authenticationmethods'
    busctl call org.freedesktop.sssd.infopipe /org/freedesktop/sssd/infopipe \
      org.freedesktop.sssd.infopipe GetUserAttr sas svc-backup 1 clients

## Transport and bind

pam-device-auth never binds in clear text. Pick one:

| Setup | `uri` | Bind | SSSD |
|---|---|---|---|
| DC with an LDAPS certificate | `ldaps://dc1.example.com` | service account password | LDAPS, `ldap_tls_reqcert = hard` |
| DC with a certificate, LDAP port only | `ldap://dc1.example.com` | service account password | StartTLS (`ldap_id_use_start_tls = true`), `ldap_tls_reqcert = hard`; no connection without TLS |
| DC with or without a certificate | `ldap://dc1.example.com` | keytab (`kerberos.keytab`) | GSSAPI with SASL sealing (`ldap_sasl_minssf = 56`), StartTLS off (`ldap_id_use_start_tls = false`) |

`ldap://` with a password always means StartTLS; there is no option to turn it
off. If the server does not offer StartTLS, SSSD stays offline and nothing
resolves; `--check` then fails on the access group and names StartTLS as a
possible cause. `--check` reports the transport it derived from the config
(`LDAPS`, `StartTLS` or `GSSAPI with SASL sealing`).

The keytab bind needs `ldap://`: it is protected by SASL sealing, not by TLS.
SSSD 2.10 and later use StartTLS by default, and AD and Samba refuse GSSAPI
sealing inside TLS, so `--setup-ldap` sets `ldap_id_use_start_tls = false` for
it. `--setup-ldap` and `--check` reject a keytab together with an `ldaps://`
URI.

GSSAPI builds the DC's service principal from the host in `uri`:
`ldap://dc1.example.com` means `ldap/dc1.example.com`. With a keytab, name the
DC in `uri` by that host name; `--setup-ldap` and `--check` reject an IP
address. The name must resolve on the host; an `/etc/hosts` entry is enough.

Put the DC's CA certificate on the host and name it in `ca_file` if it is not in
the system bundle. SSSD reads the file itself, so the user SSSD runs as must be
able to read it: on distributions where `sssd_be` runs as user `sssd`, a file
below the 0700 directory `/etc/pam-device-auth` is not readable. Put it in
`/usr/local/share/ca-certificates/` (Debian, Ubuntu) or
`/etc/pki/ca-trust/source/anchors/` (Rocky Linux, Fedora). `--check` verifies only that
`ca_file` is a regular file. Keep the bind password out of `config.json` with
`bind_password_file`: a regular file (no symlink) owned by root with mode 0600,
the password on one line, at most 4096 bytes. `bind_dn` may be a DN
(`CN=svc-sssd,OU=Service,DC=example,DC=com`), a UPN (`svc-sssd@example.com`) or
a down-level logon name (`EXAMPLE\svc-sssd`).

## Kerberos for sudo and passwd

With `"kerberos": {"realm": "EXAMPLE.COM", "kdc": "dc1.example.com", "kpasswd": "dc1.example.com"}`
SSSD checks sudo passwords and changes passwords against the KDC; the user
password never goes over LDAP. Without `kerberos`, sudo checks the password with
an LDAP bind over TLS and `passwd` on the host is not available (AD does not
implement the LDAP password modify operation); users change their password in AD.

SSSD takes the user's Kerberos principal from `userPrincipalName`, and AD
returns its realm part as the lower-case DNS domain (`alice@example.com`). With
`kerberos`, `--setup-ldap` therefore sets `krb5_use_enterprise_principal = true`
and `ldap_force_upper_case_realm = true`, as SSSD's own ad provider does: SSSD
treats the UPN as an enterprise principal and upper-cases the realm, so users
whose UPN suffix is the lower-case DNS domain authenticate for sudo and
`passwd`.

With `kerberos`, `--setup-ldap` also installs the SSSD Kerberos provider and the
SASL GSSAPI plugin (`sssd-krb5` and `libsasl2-modules-gssapi-mit` on Debian and
Ubuntu, `sssd-krb5` and `cyrus-sasl-gssapi` on Rocky Linux and Fedora). `--check`
reports the realm and the KDC and warns when the KDC name does not resolve.

For a keytab bind, create the keytab for the service account on a DC (Windows:
`ktpass`; Samba: `samba-tool domain exportkeytab`), copy it to the host as a
regular file owned by root with mode 0600 and set `kerberos.keytab`. `bind_dn`
is then the Kerberos principal with the realm in upper case, for example
`svc-sssd@EXAMPLE.COM`, and `bind_password` and `bind_password_file` must be
absent. `--check` fails when the keytab is not a root-only regular file.
Put the keytab outside /etc/pam-device-auth, for example /etc/krb5.sssd.keytab
(owner root, mode 0600); SSSD's ldap_child reads it also where the SSSD backend
runs as an unprivileged user. The keys in a keytab derive from the service
account's password: when the password changes, the keytab becomes invalid and
SSSD can no longer bind, so build a new one.

### Building a keytab without changing AD

MIT Kerberos `ktutil` builds the keytab from the service account's password,
without changing anything in AD. It needs the account's current key version
number, which AD publishes in `msDS-KeyVersionNumber`:

    LDAPTLS_CACERT=/usr/local/share/ca-certificates/example-ad-ca.crt \
      ldapsearch -x -H ldaps://dc1.example.com -D svc-sssd@example.com -W \
      -b DC=example,DC=com '(sAMAccountName=svc-sssd)' msDS-KeyVersionNumber

Without a certificate on the DC, get a ticket with `kinit svc-sssd@EXAMPLE.COM`
and query with `ldapsearch -Y GSSAPI -H ldap://dc1.example.com` instead of
`-x -H … -D … -W`. Then, with the key version from the result (here 2):

    ktutil
    ktutil:  addent -password -p svc-sssd@EXAMPLE.COM -k 2 -e aes256-cts-hmac-sha1-96 -f
    Password for svc-sssd@EXAMPLE.COM:
    ktutil:  wkt /etc/krb5.sssd.keytab
    ktutil:  quit
    chown root:root /etc/krb5.sssd.keytab
    chmod 600 /etc/krb5.sssd.keytab

`-p` is the principal from `bind_dn`, `-k` the key version. `-f` fetches the
salt from the KDC instead of deriving it from the principal name, so the host
must find the KDC for the realm (through the domain's DNS SRV records or a
`[realms]` entry in `/etc/krb5.conf`). The usage line of MIT krb5 1.21 is
`addent (-key | -password) -p principal -k kvno [-e enctype] [-f|-s salt]`.

## UIDs in containers

With `id_mapping` (default) SSSD derives UIDs and GIDs from the objectSid,
starting at 200000. An unprivileged container maps only 65536 IDs, and logins
fail with `setresuid: Invalid argument`. Set a range inside the container's map:

    "id_range": {"min": 10000, "max": 60000}

`min` must be at least 1000 and below `max`. The range is a single ID slice for
one domain; users and groups from trusted domains are not mapped. A user or
group whose RID (the last number of its objectSid) is `max - min` or higher
cannot be mapped then and does not resolve. Pick the range before the first
login: changing it later gives every user new IDs. `id_range` needs
`id_mapping`; with `"id_mapping": false` SSSD takes the `uidNumber` and
`gidNumber` attributes from AD instead.

`--check` fails when a member of the access group or a service account group
has a UID or primary GID outside the host's ID map, and warns about members
whose IDs it could not read.

## Example

    {
      "issuer_url": "https://sso.example.com/realms/example",
      "client_id": "ssh-server",
      "required_role": "ssh-access",
      "required_acr": ["3"],
      "ldap": {
        "profile": "ad",
        "uri": "ldaps://dc1.example.com",
        "ca_file": "/usr/local/share/ca-certificates/example-ad-ca.crt",
        "base_dn": "DC=example,DC=com",
        "bind_dn": "svc-sssd@example.com",
        "bind_password_file": "/etc/pam-device-auth/ldap.secret",
        "attributes": {"ssh_key": "sshPublicKey", "clients": "exampleSshClients"},
        "id_range": {"min": 10000, "max": 60000},
        "kerberos": {"realm": "EXAMPLE.COM", "kdc": "dc1.example.com", "kpasswd": "dc1.example.com"},
        "access_group": "ssh-access",
        "admin_group": "ssh-admin"
      }
    }

`sshPublicKey` and `exampleSshClients` stand for attributes from your schema
extension. `required_acr` matches the Keycloak setup in
[keycloak-setup.md](keycloak-setup.md#require-a-strong-factor-in-the-browser).

For a keytab bind over `ldap://`, replace the transport and bind lines:

    "uri": "ldap://dc1.example.com",
    "bind_dn": "svc-sssd@EXAMPLE.COM",
    "kerberos": {"realm": "EXAMPLE.COM", "kdc": "dc1.example.com", "kpasswd": "dc1.example.com",
                 "keytab": "/etc/krb5.sssd.keytab"},

and drop `bind_password_file` (and `ca_file` if the DC has no certificate).

Then:

    sudo pam-device-auth --setup-ldap
    getent -s sss passwd alice
    sudo pam-device-auth --check
    sudo pam-device-auth --enable

Lines of `--check` that belong to this setup, for the example above:

    Token policy: acr must be one of 3 (checked at login; the IdP must issue the acr claim)
    ...
      [OK]   ldap.uri is a single URI, transport LDAPS (no cleartext bind)
      [OK]   profile ad
      [OK]   login shell /bin/bash is executable
      [OK]   ldap.ca_file is a regular file: /usr/local/share/ca-certificates/example-ad-ca.crt
      [OK]   Kerberos realm EXAMPLE.COM, KDC dc1.example.com (sudo and passwd via krb5)
      [OK]   access group "ssh-access" resolves via NSS (2 member(s)); SSSD↔LDAP↔CA path OK
      [OK]   all 2 access-group member(s) have a valid sshPublicKey (publickey factor)
      [OK]   UIDs/GIDs of 2 directory user(s) exist in this host's ID map

With the keytab bind, the transport is `GSSAPI with SASL sealing` and the
access group line ends in `SSSD↔LDAP path OK (GSSAPI)`: no CA certificate is
involved.

## Disabled and expired accounts

Active Directory keeps a disabled or expired account in its groups and leaves
its key attribute in place, and a login with an SSH key never binds to the
directory. The group membership alone would let such an account in. The PAM
account phase therefore reads the account state of every non-root user, for
every kind of login (device flow, cached session, key-only service account),
and denies when the account is disabled, when its expiry time has come, or
when the state cannot be read:

| State in AD | Line in `/var/log/pam-device-auth.log` |
|---|---|
| Disabled (`ACCOUNTDISABLE`, value 2 in `userAccountControl`) | `pam-acct: user=<name> is disabled in the directory (userAccountControl <value>); deny` |
| `accountExpires` reached | `pam-acct: user=<name> expired in the directory on <time> (accountExpires); deny` |
| State not readable | `pam-acct: user=<name> account state read failed, fail-closed deny: <reason>` |

The client sees `Connection closed` after its key was accepted. The check
runs on a host with `"profile": "ad"` in the `ldap` block of `config.json`.
The account phase reads this one key of the block. When it cannot (the file
is not valid JSON, the block has no profile or an unknown one), it denies
every directory login with
`pam-acct: user=<name> cannot read ldap.profile from the config, fail-closed deny: <reason>`,
on LLDAP hosts as well; an invalid value in another key does not matter here.

- **Where the state comes from.** SSSD stores `userAccountControl` and
  `accountExpires` with the user as `adUserAccountControl` and
  `adAccountExpires`. The account phase reads them through the SSSD InfoPipe,
  like the allowlist. The bind account must be able to read the two
  attributes of the users. `--setup-ldap` lists both in
  `[ifp] user_attributes`; a host set up by a version before 0.9.0 needs no
  new run, because SSSD 2.9 to 2.12 hand out every cached attribute to root
  whether that list names it or not.
- **How fast a change applies.** Within SSSD's cache time, up to 10 minutes,
  as for a change of group membership. `sudo sss_cache -E` on the host applies
  it to the next login. With several domain controllers the change must also
  have replicated to the one the host asks (`ldap.uri`); until then that
  controller answers with the old state. Sessions that are already open stay
  open.
- **What it does not look at.** An account that AD locked after wrong
  passwords (`lockoutTime`) is not refused: that lock concerns the password,
  which an SSH login here never uses.
- **root and break-glass accounts** are local and are not asked about.

`--check` reads the state of the members of the access group and of every
service group and reports it under "IP allowlist (account-phase gate)":

| Line | Meaning |
|---|---|
| `[OK] group "<group>": account state read for <n> of <m> member(s), <k> refused at login: <name> is disabled in the directory (…); …` | Who is refused at login right now. No warning: a disabled account in a group is the directory's business. |
| `[WARN] group "<group>": <n> member(s) with an UNREADABLE account state; the account phase fails closed and will DENY their login: <names> (<reason>)` | SSSD has no state for these members: the bind account cannot read the two attributes of them, or the InfoPipe call failed (the reason is in the brackets). |

## What `--setup-ldap` writes for AD

The SSSD domain is named `nkit`, as with LLDAP. Compared with the LLDAP profile
it uses `ldap_schema = ad`, `ldap_referrals = false` and
`case_sensitive = false`, gates logins with SSSD's simple access provider
(`access_provider = simple`, `simple_allow_groups` = `access_group` and every
group in `service_account_groups`), maps the attributes from
`ldap.attributes`, and lists the account state for the InfoPipe next to the
allowlist (`[ifp] user_attributes` with `+clients`, `+adUserAccountControl`
and `+adAccountExpires`; see
[Disabled and expired accounts](#disabled-and-expired-accounts)).
`user_search_base` and `group_search_base` default to
`base_dn`. With `kerberos` it adds `krb5_use_enterprise_principal = true` and
`ldap_force_upper_case_realm = true` (see
[Kerberos for sudo and passwd](#kerberos-for-sudo-and-passwd)). The sudoers
drop-in, the sshd drop-in and the socket-unit handling are the same for both
profiles.

## Local accounts with the same name

`--setup-ldap` migrates a local account whose name also exists in AD with
another UID (local UIDs 1000 to 64999): it removes the local entry, keeps the
home directory, re-owns the files that belonged to the old IDs (home below
`/home`, mail spool, crontab) and puts the user back into its local groups
except the privileged ones (`sudo`, `admin`, `wheel`, `root`, `adm`, `shadow`,
`disk`, `staff`, `docker`, `lxd`, `incus`, `libvirt`). An account with running processes is skipped
with a warning; stop them and run `--setup-ldap` again. No process is killed.
`--check` lists each such account as a `[WARN]` with what `--setup-ldap` will do
(migrate, with the groups it keeps and the home it re-owns, or skip because of
running processes), as long as SSSD already resolves the AD users; see
[the migration section](ldap-directory-setup.md#migration-on-existing-hosts-important).

A local account listed in `break_glass_users` is never migrated, and its name
must not exist in AD: while it does, the account's logins are denied and
`--check` reports a blocker. AD compares names without regard to case, so an
AD account `BreakGlass` collides with the local `breakglass`. A host with
SSSD 2.9 or 2.10 can take up to four hours to notice an AD account that was
created after the local one was in use. See the
[configuration reference](configuration-reference.md#a-directory-account-of-the-same-name).
