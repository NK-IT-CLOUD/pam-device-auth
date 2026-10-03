# IP allowlist

Central, directory-controlled restriction on the source IPs each user may SSH
from. The list lives in one LLDAP attribute (`clients`, IP/CIDR values) and is
enforced in the PAM **account** phase for every login, OIDC users and key-only
service accounts alike.

`pam_device_auth.so`'s account-management hook (`pam_sm_acct_mgmt` in
`pam_device_auth.c`) runs `pam-device-auth --pam-acct`, which reads the `clients`
attribute directly from SSSD over D-Bus (InfoPipe) via `busctl`, independent of
any token. Because it runs in the account phase, it covers key-only service
accounts that never complete an OIDC device flow.

> Earlier versions also enforced the allowlist during the OIDC auth phase, from
> a JWT `clients` claim configured with `ip_claim`. That path was removed in
> 0.5.7: the account-phase gate already covers OIDC users, so the JWT check and
> its Keycloak mapper were redundant. A config that still carries `ip_claim`
> loads fine; the field is ignored.

See `cmd/pam-device-auth/acct.go` for the account-phase logic and
`cmd/pam-device-auth/main.go` (`matchesAllowedIP`) for the IP/CIDR matching.

**Only root is exempt.** Local non-root accounts are not a supported login tier
and fail closed at the InfoPipe lookup. This prevents a local `/etc/passwd`
entry with the same name as a directory identity from bypassing its IP policy.

**The check fails closed.** If the `clients` lookup for a directory user errors
(SSSD down, InfoPipe unreachable, D-Bus timeout), that login is denied, not
allowed. A busctl/InfoPipe outage therefore denies every directory-user login,
not just the ones that had an IP pin set. Run `pam-device-auth --check` before
rolling this out: it reports the IP-pin posture per group (how many members have
`clients` set) and SSSD InfoPipe health.

## Pipeline

```
┌──────────┐  "clients"   ┌──────────┐  InfoPipe (busctl)  ┌──────────┐
│  LLDAP   │  LDAP attr   │   SSSD   │  GetUserAttr        │  helper  │  match → allow
│  user    │─────────────▶│ (ifp)    │────────────────────▶│ (account │  miss  → deny (fail closed)
└──────────┘              └──────────┘                     │  phase)  │  read error → deny (fail closed)
                                                           └──────────┘
```

The account-phase check reads the LLDAP attribute literally named `clients`.

## Data model

| Layer | Element | Value |
|---|---|---|
| LLDAP | Custom attribute on user | `clients: [198.51.100.2, 192.0.2.0/24]` (multi-valued, string) |
| SSSD | InfoPipe `GetUserAttr` on `clients` | same values, read live via `busctl` |

The value may contain any mix of:

- Plain IPs (IPv4 or IPv6): `198.51.100.2`, `2001:db8::1`
- CIDR blocks: `198.51.100.0/24`, `2001:db8::/32`

Invalid entries are logged and skipped at match time; they neither grant nor
deny.

## 1. LLDAP side

Log in to LLDAP's admin UI (or use `lldap-cli`).

**Schema, Attributes, Add attribute**

| Field | Value |
|---|---|
| Name | `clients` |
| Type | String |
| List (multi-value) | Yes |
| User editable | No |
| Visible | Yes |

**Users, <user>, Edit**: set one value per line:

```
198.51.100.2
192.0.2.0/24
```

An empty attribute means no restriction for that user.

## 2. SSSD InfoPipe

The check needs the SSSD `ifp` responder, which `pam-device-auth --setup-ldap`
renders into `sssd.conf` automatically. The responder needs a package that is
not always installed by default:

- Debian/Ubuntu: `sssd-dbus` (installed by `--setup-ldap`, recommended by the `.deb`)
- RHEL family: `sssd-dbus` as well (installed by `--setup-ldap`)

No `config.json` entry controls the check; it is always active once
`pam-device-auth --enable` has installed the PAM module, for every directory
user. Run `pam-device-auth --check` to confirm InfoPipe is reachable before
relying on it.

## 3. Matching semantics

The matcher is `cmd/pam-device-auth/main.go :: matchesAllowedIP`, which walks the
list:

- plain IP: exact string equality against the sanitized client IP (`PAM_RHOST`)
- CIDR: `net.ParseCIDR` plus `network.Contains(net.ParseIP(clientIP))`
- entry that does not parse: skipped, logged, neither grants nor denies

A mix of IPv4 and IPv6 entries is fine; the helper parses both.

## 4. Failure modes

| Event | Result |
|---|---|
| `clients` present, client IP matches | Allow |
| `clients` present, client IP does NOT match | Deny (PAM account phase fails, login rejected) |
| `clients` absent (attribute unset in LLDAP) | Allow (a directory user with no allowlist is unrestricted by design) |
| SSSD/InfoPipe lookup fails (down, D-Bus unreachable, timeout) | Deny, fail closed. This denies every directory user, not only pinned ones, until InfoPipe recovers |
| User is root | Allow, exempt, never touches SSSD |
| Local-only non-root user | Deny, fail closed (unsupported login tier; no InfoPipe identity) |
| `clients` has malformed entries | Bad entries logged once per call, good entries still enforced |

The absent-attribute fallback is deliberate: an unpinned user is unrestricted. To
make the allowlist mandatory, set `clients` on every SSH-targeted user as an
organizational policy. Note that removing all values from the attribute makes it
absent again, which reverts that user to unrestricted, not to denied.

## 5. Operational notes

- Changes to the LLDAP attribute take effect immediately: the check reads live
  from SSSD/InfoPipe on every login, with no cache of its own.
- For emergency revocation, remove the user from the access group in LLDAP: the
  next login fails the SSSD access filter and is denied regardless of `clients`.
- CIDR blocks are expanded at match time. It is cheap arithmetic with no
  precomputed table, so lists up to a few dozen entries cost nothing measurable.
- Service accounts (members of a `service_account_groups` group) authenticate
  with an SSH key only, so the account-phase check is their only IP gate. Pin
  their `clients` attribute to restrict where a service account's key can be used
  from. `pam-device-auth --check` flags service-group members that have no
  `clients` set.
