# Contributing

Contributions are welcome. This document covers the development workflow.

## Development setup

```bash
git clone https://github.com/NK-IT-CLOUD/pam-device-auth
cd pam-device-auth

# Prerequisites
# - Go 1.26.8 (security-pinned by go.mod)
# - GCC (for the C PAM module; the Go helper is CGO-free)
# - libpam0g-dev

# Ubuntu/Debian:
sudo apt install build-essential libpam0g-dev

# Rocky Linux/RHEL:
sudo dnf install gcc pam-devel

# Build everything
make build-all

# Run tests
make test
```

## Running tests

```bash
# All tests with race detector and coverage
make test

# Unit tests only
make test-unit

# View coverage
go tool cover -html=coverage.out
```

Tests use temporary directories, local HTTP test servers and command stubs where
privileged host behavior is involved. They do not modify production `/etc`
configuration, but some tests require local helper binaries and loopback sockets.

### Integration tests

Tests with the build tag `integration` need a real host: root, the installed
package and, for most of them, a host set up in directory mode (SSSD, `busctl`,
`sshd`). They read users and groups from the host's own config and skip what
the host does not provide. Build and run one on a test machine:

```bash
go test -c -tags integration -o pda-integration.test ./cmd/pam-device-auth
scp pda-integration.test root@host:/tmp/ && ssh root@host /tmp/pda-integration.test -test.v
```

The maintainers' CI runs them on its test hosts after every release-candidate
deploy, together with the unit tests as root (the ownership-guard tests skip
without root).

### Login tests

Tests with the build tag `login` drive real SSH logins against a host that runs
pam-device-auth in directory mode, as a fixed set of directory test users. They
check the outcome of every login and, with root access to the host, the reason the
host logged for each refusal.

```bash
PDA_LOGIN_HOST=<host> PDA_LOGIN_KEYDIR=<dir with one private key per test user> \
PDA_LOGIN_ROOT=root@<host> PDA_LOGIN_KNOWN_HOSTS=<pinned known_hosts, optional> \
  go test -tags login -run '^TestLogin' -v ./cmd/pam-device-auth
```

The directory needs these users (each with `uidNumber`, `gidNumber` and, where it
has one, an `sshPublicKey` whose private half is in the key directory) and three
groups that the test host lists in its config as `access_group`,
`service_account_groups` and `nopasswd_sudo_groups`:

| User | Setup | Expected |
|---|---|---|
| `ci-svc-ok` | member of the service group | logs in, no sudo |
| `ci-svc-sudo` | service group and the NOPASSWD group | logs in, `sudo -n` works |
| `ci-svc-ipallow` | service group, `clients` contains the test client's network | logs in |
| `ci-svc-ipdeny` | service group, `clients` does not contain the test client | refused by the source IP check |
| `ci-nogroup` | valid key, member of no access group | refused by the access filter |
| `ci-nokey` | service group, no `sshPublicKey` | refused (key factor) |
| `ci-badkey` | service group, unparseable `sshPublicKey` | refused (key factor) |
| `ci-oidc` | member of the access group, valid key | key accepted, then the device flow prompt appears |

The tests never use these accounts for anything else; give them no group that
grants access elsewhere. Failed logins arrive in quick succession from one address,
so on the test host exempt the client network from sshd's `PerSourcePenalties`
(`PerSourcePenaltyExemptList`), or sshd drops later attempts before they are
evaluated. The host's `--check` reports the deliberately broken users as warnings;
list substrings of the expected warnings, one per line, in
`/etc/pam-device-auth/ci-known-warnings` and the integration test accepts exactly
those. After a change in the directory, wipe the SSSD cache on the host
(stop sssd, delete `/var/lib/sss/db/*.ldb` and `/var/lib/sss/mc/*`, start sssd),
or the old value stays in effect for up to 10 minutes.

## Code style

- **Zero external Go dependencies**: pure Go stdlib, CGO-free (`CGO_ENABLED=0`). This is a security-sensitive PAM module; the dependency surface must stay minimal. The only native artifact is the C PAM shim (links `libpam`).
- Run `go fmt ./...` before committing
- Run `go vet ./...` to catch issues (`make lint`)
- Run `go mod verify` to verify the module cache
- Keep functions focused and testable

## Project structure

```
cmd/pam-device-auth/     Main binary: OIDC layer + directory-mode auth flow + --setup-ldap
internal/
  cache/                 Refresh token + IP cache (tmpfs)
  config/                Config loading + validation
  device/                Device Authorization Grant + token refresh
  discovery/             OIDC Discovery
  logger/                Structured logging
  qr/                    QR code encoder + terminal renderer
  sshclient/             SSH client version detection (QR auto-detect)
  token/                 JWKS fetch, JWT verification, role extraction
pam_device_auth.c        PAM module (C) with bidirectional pipes + FLUSH: batching protocol
configs/                 Default and provider-specific config templates
debian/                  Debian package metadata
```

## Wire protocol: C Module ↔ Go Binary

The C PAM module (`pam_device_auth.c`) communicates with the Go binary over stdin/stdout pipes. Two message prefixes control behavior (directory mode never prompts for a password, so there is no secret-input prefix):

| Prefix | Direction | PAM Message Type | Purpose |
|--------|-----------|-----------------|---------|
| `FLUSH:` | Go → C | `PAM_PROMPT_ECHO_ON` | Force display of buffered info messages |
| *(plain text)* | Go → C | `PAM_TEXT_INFO` | Informational output (link, code, QR, status) |

### Why FLUSH exists

OpenSSH 10+ buffers `PAM_TEXT_INFO` messages and only delivers them to the client when a prompt (`PAM_PROMPT_ECHO_ON` or `PAM_PROMPT_ECHO_OFF`) follows. Without a prompt, info messages are never displayed.

`FLUSH:` solves this by sending all accumulated info messages together with a visible prompt in a single batched `pam_conv()` call. The user sees the info text and a prompt like "Authorize in browser, then press Enter...". The `FLUSH:` prefix itself is stripped; only the text after it is shown.

### Batched conversation

The C module collects all `PAM_TEXT_INFO` messages until it encounters a `FLUSH:` line, then sends everything in one `pam_conv()` call. This eliminates the extra Enter presses that occurred when each message triggered a separate conversation round-trip.

```
Go binary stdout          C module                    SSH client
─────────────────────────────────────────────────────────────────
"--- Link: ... ---"       accumulate as TEXT_INFO
"--- Code: ... ---"       accumulate as TEXT_INFO
"[QR code lines]"         accumulate as TEXT_INFO
"FLUSH:Press Enter..."    send batch: [INFO,INFO,...,PROMPT]  →  display all + prompt
                          read response                      ←  user presses Enter
```

## Pull request process

1. Fork the repository and create a feature branch
2. Make your changes
3. Ensure all tests pass: `make test`
4. Ensure code is formatted: `make format`
5. Ensure no lint issues: `make lint`
6. Submit a pull request with a clear description of the change

## Development workflow

Fork the GitHub repository and submit pull requests there. The `main` branch on
GitHub reflects the latest published release. Release candidates pass the full
CI and test-host checks before a stable release is published.

## Reporting issues

Use GitHub Issues for bug reports and feature requests. For security vulnerabilities, see [SECURITY.md](SECURITY.md).
