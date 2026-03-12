# Build System

## Project Structure

```text
keycloak-ssh-auth/
├── cmd/keycloak-auth/            # Main Go application
├── configs/                      # Shipped SSH/PAM/JSON templates
├── debian/                       # Debian packaging hooks and metadata
├── docs/                         # Project documentation
├── internal/
│   ├── cache/                    # Refresh token cache
│   ├── config/                   # Config loading and validation
│   ├── device/                   # Device authorization grant flow
│   ├── discovery/                # OIDC discovery
│   ├── logger/                   # Structured logging
│   ├── token/                    # JWKS fetch and JWT validation
│   └── user/                     # Local user and sudoers management
├── scripts/                      # Versioning helpers
├── .gitea/workflows/ci.yaml      # CI pipeline
├── VERSION                       # Canonical project version
├── makefile                      # Build, test and packaging targets
└── pam_keycloak.c                # PAM module source
```

## Make Targets

```bash
make build        # Build the Go helper
make pam          # Build pam_keycloak.so
make build-all    # Build Go helper + PAM module
make test         # Run all Go tests with race detector + coverage
make test-unit    # Run tests for ./internal/...
make lint         # Run go vet
make format       # Run go fmt
make deb          # Build the Debian package
make release      # Build .deb and release tarball
make clean        # Remove build artifacts
make clean-all    # Remove build artifacts and release bundles
```

`make pam` now has an explicit target, so CI and fresh checkouts do not rely on a pre-existing `pam_keycloak.so`.

## Build Outputs

After a successful build, artifacts land in:

- `build/bin/keycloak-auth`
- `pam_keycloak.so`
- `build/packages/keycloak-ssh-auth_<version>_amd64.deb`
- `build/releases/keycloak-ssh-auth-<version>/`
- `build/releases/keycloak-ssh-auth-<version>.tar.gz`

## Version Workflow

The canonical version is stored in `VERSION`. The helper script keeps the following files aligned:

- `VERSION`
- `makefile`
- `debian/control`
- `cmd/keycloak-auth/main.go`

Usage:

```bash
./scripts/version.sh current
./scripts/version.sh bump patch
./scripts/version.sh bump minor
./scripts/version.sh bump major
./scripts/version.sh set 1.0.0
./scripts/version.sh tag
./scripts/version.sh release
```

`./scripts/version.sh release` will:

1. Bump the patch version
2. Ensure `CHANGELOG.md` has an `Unreleased` section
3. Insert a new release entry
4. Run `make clean` and `make release`
5. Commit the versioned files
6. Create an annotated git tag

The script does not publish a remote release entry. Release publication is handled outside the repo tooling.

## CI

The repository uses Gitea Actions via `.gitea/workflows/ci.yaml`.

The pipeline currently does:

```bash
make build
make pam
make test
make lint
```

## Packaging Notes

`make deb` stages files into `debian_build/` and then builds the package with `dpkg-deb`.

The Debian hooks:

- install the helper binary into `/usr/local/bin/`
- install the PAM module into `/usr/lib/security/`
- ship default templates under `/usr/share/keycloak-ssh-auth/config/`
- create logrotate and tmpfiles entries during `postinst`

The package preserves local config changes on upgrade by only installing the SSH and PAM templates on first install.

## Troubleshooting

If `go` is installed but not visible in a non-login shell, verify the binary path explicitly:

```bash
/usr/local/go/bin/go version
PATH=/usr/local/go/bin:$PATH make test
```

For PAM builds, ensure `gcc` and `libpam0g-dev` are installed:

```bash
sudo apt install build-essential libpam0g-dev
```
