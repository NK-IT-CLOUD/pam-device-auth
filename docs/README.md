# pam-device-auth documentation

Documentation for operators and developers. For quick install, see the project
[README](../README.md) and [INSTALL.md](../INSTALL.md).

## Index

| Doc | What it covers |
|---|---|
| [architecture.md](architecture.md) | Component layout, request/response flows, C↔Go IPC protocol, cache lifecycle |
| [configuration-reference.md](configuration-reference.md) | Every `config.json` field: type, default, meaning, validation, examples |
| [keycloak-setup.md](keycloak-setup.md) | Keycloak client, roles, mappers, token lifetimes, LLDAP federation |
| [ldap-directory-setup.md](ldap-directory-setup.md) | SSSD/LDAP host setup, local-account migration, revocation and 2FA activation order |
| [ip-allowlist.md](ip-allowlist.md) | End-to-end IP-allowlist pipeline (LLDAP → SSSD InfoPipe → PAM account phase) |
| [troubleshooting.md](troubleshooting.md) | Symptoms and fixes for common issues |
| [operations.md](operations.md) | Logs, rotation, monitoring, upgrades, failure modes |

## Scope

These docs assume Keycloak as the OIDC provider. Other providers (Authentik,
Okta, Auth0) are compatible (see `configs/config-*.json` for templates), but
are not covered here in depth.
