# Keycloak setup

End-to-end Keycloak configuration for pam-device-auth. This guide produces
a client that supports:

- Device Authorization Grant (RFC 8628)
- Role gating (`required_role`, `sudo_role`)
- Standard `realm_access.roles` + `resource_access.<client>.roles`
  extraction

Tested against Keycloak 24.x and 25.x.

## Prerequisites

- A Keycloak realm with users (directly-managed or federated via LDAP)
- Admin access to the realm
- If using LDAP federation: an LDAP User Federation already wired in
  (the reference deployment uses LLDAP)

## 1 · Create the client

**Clients → Create client**

| Field | Value |
|---|---|
| Client type | OpenID Connect |
| Client ID | `ssh-server` *(matches `client_id` in config.json)* |
| Name | pam-device-auth SSH |

**Capability config** (next step):

| Setting | Value |
|---|---|
| Client authentication | **Off** *(public client, no secret)* |
| Authorization | Off |
| Authentication flow | Only **OAuth 2.0 Device Authorization Grant** is checked. All others (Standard, Direct access, Implicit, Service accounts) are **unchecked**. |

**Login settings** (next step): leave all URIs blank. Save.

### Verify

After save, the client's **Advanced** tab should show:

```
OAuth 2.0 Device Authorization Grant Enabled: On
```

and the `.well-known` document at
`https://<host>/realms/<realm>/.well-known/openid-configuration` should
advertise `device_authorization_endpoint`.

## 2 · Create the SSH roles

Two **realm-level** roles (recommended over client roles: simpler to
reason about and easier to compose with groups):

**Realm roles → Create role**

| Role | Purpose |
|---|---|
| `ssh-access` | Required for any SSH session. Missing = login denied. |
| `ssh-admin` | Grants sudo (the directory `ssh-admin` group, via `pam_sss`). Optional. |

Assign the roles to users directly or via **Groups → Role mapping**.
Group-based assignment is preferred for team-scale management.

### How extraction works

pam-device-auth reads roles from **both** of these paths and unions them:

- `realm_access.roles` → realm roles (default in the `roles` client scope)
- `resource_access.<client_id>.roles` → client roles

You do not need any custom mapper for this: Keycloak's default `roles`
client scope emits both. Confirm the `roles` scope is in the client's
**Default client scopes**.

## 3 · Client scopes

Default scopes should be: `profile`, `email`, `roles`. Remove `acr` and any
other default scope you don't need; it's not harmful, just clutter.

### `fullScopeAllowed`

Set `fullScopeAllowed: false` on the client (Advanced tab). This limits
tokens to roles explicitly mapped through scopes, so unrelated realm
roles are not exposed by accident.

## 4 · IP allowlist (no Keycloak mapper needed)

The `clients` source-IP allowlist is enforced directory-side: the PAM account
phase reads the `clients` attribute straight from SSSD's InfoPipe (via `busctl`)
for every login, including key-only service accounts, and fails closed if the
lookup fails. No Keycloak mapper and no JWT `clients` claim are involved.

Earlier versions also delivered the allowlist as a JWT claim and enforced it in
the OIDC auth phase (configured with `ip_claim`). That path was removed in 0.5.7
as redundant. If you set up the `clients` protocol mapper for an older release,
you can delete it; it no longer affects SSH access. See
[ip-allowlist.md](ip-allowlist.md) for the directory-side setup.

## 5 · Token lifetimes

Sensible defaults in **Realm settings → Sessions / Tokens**:

| Setting | Recommended | Why |
|---|---|---|
| `oauth2DeviceCodeLifespan` | 600 s (10 min) | Enough time to scan QR / read code, not so long that stale codes accumulate |
| `oauth2DevicePollingInterval` | 5 s | RFC 8628 default; Keycloak respects `interval` in the device-auth response |
| Access Token Lifespan | 900 s (15 min) | Must exceed the helper's `auth_timeout` + JWKS fetch overhead |
| SSO Session Idle | 30 min | Refresh-token validity for the cached fast path |
| SSO Session Max | 8 h | Hard upper bound for the cached fast path |

The helper does **not** use the ID token, only the access token, so ID
token lifetimes are irrelevant.

## 6 · (Recommended) LDAP federation

Keycloak's LDAP User Federation pulls users from LLDAP (or any RFC 4519
LDAP). Baseline config for LLDAP:

| Setting | Value |
|---|---|
| Vendor | Other |
| Connection URL | `ldap://lldap.example.com:3890` |
| Users DN | `ou=people,dc=example,dc=com` |
| Bind type | simple |
| Bind DN | `uid=keycloak-bind,ou=people,dc=example,dc=com` |
| Edit mode | `READ_ONLY` *(recommended: manage users in LLDAP)* |
| Username LDAP attribute | `uid` |
| UUID LDAP attribute | `uid` |
| User Object Classes | `person,inetOrgPerson` |

Mappers in **User Federation → <your-ldap> → Mappers** should include:

- `username`, `email`, `first name`, `last name` (auto-generated)
- `groups` (LDAP group ↔ Keycloak group sync, optional)

No mapper is needed for the IP allowlist: since 0.5.7 the `clients`
attribute never passes through Keycloak (see section 4).

### Sync

Run **Synchronize all users** once, then rely on the **Periodic changed
users sync** (default: every 24 h).

## 7 · Verify end-to-end

From a target host with pam-device-auth installed and configured:

```bash
sudo pam-device-auth --check
```

Expected output (abridged; example names and counts):

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
SSH daemon:
  [OK]   AuthorizedKeysCommand → sss_ssh_authorizedkeys (directory key = factor 1)
  [OK]   non-root: publickey,keyboard-interactive:pam (2FA)
  [OK]   root: publickey only (break-glass)
  [OK]   non-root: AuthorizedKeysFile none (directory key is the only publickey source)
```

The exact member count and optional key warnings depend on the directory. Any
`[FAIL]` is a blocker; `[WARN]` is advisory and must match the intended state.
See the [complete preflight example and interpretation](../INSTALL.md#5-preflight-check).

### Inspect a real access token

For a user who has just completed the device flow, grab the access token
from the helper log (debug level) or use `curl` against the device endpoint
from a workstation:

```bash
# Decode JWT payload
echo "<access_token>" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

Required fields present:

```json
{
  "iss": "https://sso.example.com/realms/myrealm",
  "azp": "ssh-server",
  "preferred_username": "alice",
  "exp": 1712345678,
  "realm_access": { "roles": ["ssh-access", "ssh-admin", "..."] }
}
```

The token no longer needs a `clients` claim: the source-IP allowlist is enforced
directory-side in the PAM account phase (see section 4).

## 8 · Common Keycloak pitfalls

| Symptom | Cause |
|---|---|
| `FAIL: OIDC discovery failed` | Wrong `issuer_url`: missing `/realms/<name>` suffix, or the realm is disabled. |
| `token audience does not include "ssh-server"` | Client authentication flipped to confidential, or audience mapper removed. Public clients normally emit `azp`; confirm `azp == client_id`. |
| `unknown key ID` errors after realm key rotation | JWKS cache inside Keycloak is stale, or the host's DNS is caching an old IdP endpoint. The helper caches the OIDC discovery document and the JWKS for 10 minutes in `/run/pam-device-auth/oidc/` (`discovery.json`, `jwks.json`). When a token's `kid` is not in the cached key set, it refetches the JWKS once live. A key removed at the IdP (revoked or rotated out) stays trusted from the cache for up to 10 minutes; clear the cache right after such a change with `rm -rf /run/pam-device-auth/oidc`. |
| Device flow URL opens Keycloak but the `Authorize` button does nothing | Device Authorization Grant is globally disabled at the realm level. Enable it under **Realm settings → Advanced**. |
| `required_role` fails despite the role being assigned | Role is a **client** role assigned to the wrong client, or `fullScopeAllowed=false` plus no scope mapping for that role. Fix: assign as realm role OR add an explicit client-scope mapping. |
| JWT rejected as `JWT header missing kid` | A key was added to the realm keystore without a `kid`. This was always invalid for our verifier; upgrade Keycloak or re-import the key. |

## 9 · Applying changes

After any change to the client, protocol mappers, or client scopes, restart
affected user sessions (**Users → select user → Sessions → Logout all
sessions**) to invalidate cached refresh tokens. Existing SSH sessions are
not affected; the change takes effect on the next login.
