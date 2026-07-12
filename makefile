# pam-device-auth Build System
VERSION=0.5.8
MODULE=github.com/NK-IT-CLOUD/pam-device-auth

# Directories
BUILD_DIR=build
BIN_DIR=$(BUILD_DIR)/bin
PACKAGES_DIR=$(BUILD_DIR)/packages
RELEASES_DIR=$(BUILD_DIR)/releases
DEB_DIR=debian_build

# Build flags
# -trimpath: strip absolute build-host paths from the binary
# -buildid=: clear Go's internal build ID so identical inputs produce
#            byte-identical output (reproducible-build hygiene, helps
#            SBOM correlation and detects supply-chain tampering)
GO_BUILD_FLAGS=-trimpath -ldflags "-X main.VERSION=$(VERSION) -buildid="
GO_TEST_FLAGS=-v -race -coverprofile=coverage.out -count=1

# PAM module
PAM_SRC=pam_device_auth.c
PAM_OBJ=pam_device_auth.o
PAM_SO=pam_device_auth.so
# The .so is loaded in-process by sshd and runs as root for every auth attempt,
# so harden the only native artifact: FORTIFY (needs -O2) + stack-protector +
# stack-clash + format-string warnings, and full RELRO/BIND_NOW + non-exec stack
# at link. (_FORTIFY_SOURCE=2 for broad toolchain compatibility; raise to 3 if
# the build gcc/glibc supports it.)
PAM_CFLAGS=-O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection -fPIC -Wall -Wextra -Wformat -Wformat-security
PAM_LDFLAGS=-shared -Wl,-z,relro,-z,now -Wl,-z,noexecstack -lpam

.PHONY: all build pam build-all test test-unit lint format clean clean-all deb rpm package-prep release install uninstall

all: clean build-all test

# Build Go binary only
# CGO_ENABLED=0: the helper is pure Go (no more libxcrypt), so build a fully
# static, dependency-free binary. The C PAM shim (pam_device_auth.so) is the
# only native artifact and is built separately by the `pam` target.
build:
	@echo "Building pam-device-auth $(VERSION)..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/pam-device-auth ./cmd/pam-device-auth/

pam: $(PAM_SO)
	@echo "PAM module ready."

$(PAM_OBJ): $(PAM_SRC)
	gcc $(PAM_CFLAGS) -c $(PAM_SRC) -o $(PAM_OBJ)

$(PAM_SO): $(PAM_OBJ)
	gcc $(PAM_LDFLAGS) -o $(PAM_SO) $(PAM_OBJ)

# Build binary + PAM module
build-all: build pam
	@echo "Build complete."

# Run all tests
test:
	@echo "Running tests..."
	go test $(GO_TEST_FLAGS) ./...

# Run unit tests only
test-unit:
	@echo "Running unit tests..."
	go test $(GO_TEST_FLAGS) ./internal/...

# Lint
lint:
	go vet ./...

# Format
format:
	go fmt ./...

# Prepare the staged, format-neutral inputs nfpm references (gzipped man page).
package-prep: build-all
	@mkdir -p $(BUILD_DIR)/man $(PACKAGES_DIR)
	cp man/pam-device-auth.8 $(BUILD_DIR)/man/pam-device-auth.8
	gzip -9nf $(BUILD_DIR)/man/pam-device-auth.8

# nfpm produces byte-deterministic packages from nfpm.yaml when
# SOURCE_DATE_EPOCH is set (pinned to the last commit time).
NFPM ?= nfpm

deb: package-prep
	@echo "Creating Debian package via nfpm..."
	export VERSION=$(VERSION); \
	export SOURCE_DATE_EPOCH=$$(git log -1 --format=%ct 2>/dev/null || echo 315532800); \
	$(NFPM) package --config nfpm.yaml --packager deb --target $(PACKAGES_DIR)/pam-device-auth_$(VERSION)_amd64.deb
	@echo "Package created: $(PACKAGES_DIR)/pam-device-auth_$(VERSION)_amd64.deb"

rpm: package-prep
	@echo "Creating RPM package via nfpm..."
	export VERSION=$(VERSION); \
	export SOURCE_DATE_EPOCH=$$(git log -1 --format=%ct 2>/dev/null || echo 315532800); \
	$(NFPM) package --config nfpm.yaml --packager rpm --target $(PACKAGES_DIR)/pam-device-auth-$(VERSION).x86_64.rpm
	@echo "Package created: $(PACKAGES_DIR)/pam-device-auth-$(VERSION).x86_64.rpm"

# Full release
release: clean build-all deb
	@echo "Creating release $(VERSION)..."
	@mkdir -p $(RELEASES_DIR)/pam-device-auth-$(VERSION)
	cp $(BIN_DIR)/pam-device-auth $(RELEASES_DIR)/pam-device-auth-$(VERSION)/
	cp $(PAM_SO) $(RELEASES_DIR)/pam-device-auth-$(VERSION)/
	# Explicit config list: never `cp -r configs` — configs/config-nkit.json
	# (internal, gitignored) may exist locally and must not enter a tarball.
	mkdir -p $(RELEASES_DIR)/pam-device-auth-$(VERSION)/configs
	cp configs/config.json configs/config-auth0.json configs/config-okta.json \
	  configs/config-authentik.json configs/10-pam-device-auth.conf \
	  configs/pam-sshd-device-auth configs/pam-sshd-device-auth-rhel \
	  $(RELEASES_DIR)/pam-device-auth-$(VERSION)/configs/
	cp README.md $(RELEASES_DIR)/pam-device-auth-$(VERSION)/
	cd $(RELEASES_DIR) && tar --sort=name --owner=0 --group=0 --numeric-owner \
	  --mtime="@$$(git -C $(CURDIR) log -1 --format=%ct 2>/dev/null || echo 0)" \
	  -czf pam-device-auth-$(VERSION).tar.gz pam-device-auth-$(VERSION)/
	@echo "Release: $(RELEASES_DIR)/pam-device-auth-$(VERSION).tar.gz"

# Install via dpkg
install: deb
	sudo dpkg -i $(PACKAGES_DIR)/pam-device-auth_$(VERSION)_amd64.deb

# Uninstall
uninstall:
	sudo dpkg -r pam-device-auth

# Clean
clean:
	rm -rf $(BUILD_DIR) $(DEB_DIR)
	rm -f $(PAM_OBJ) $(PAM_SO)
	rm -f coverage.out
	rm -f pam-device-auth

clean-all:
	rm -rf $(BUILD_DIR) $(DEB_DIR) $(RELEASES_DIR)
	rm -f $(PAM_OBJ) $(PAM_SO) coverage.out pam-device-auth
