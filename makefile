# pam-device-auth Build System
VERSION=0.3.5
MODULE=github.com/NK-IT-CLOUD/pam-device-auth

# Directories
BUILD_DIR=build
BIN_DIR=$(BUILD_DIR)/bin
PACKAGES_DIR=$(BUILD_DIR)/packages
RELEASES_DIR=$(BUILD_DIR)/releases
DEB_DIR=debian_build

# Build flags
GO_BUILD_FLAGS=-ldflags "-X main.VERSION=$(VERSION)"
GO_TEST_FLAGS=-v -race -coverprofile=coverage.out -count=1

# PAM module
PAM_SRC=pam_device_auth.c
PAM_OBJ=pam_device_auth.o
PAM_SO=pam_device_auth.so
PAM_CFLAGS=-Wall -Wextra -fPIC
PAM_LDFLAGS=-shared -lpam

.PHONY: all build pam build-all test test-unit lint format clean clean-all deb release install uninstall

all: clean build-all test

# Build Go binary only
build:
	@echo "Building pam-device-auth $(VERSION)..."
	@mkdir -p $(BIN_DIR)
	go build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/pam-device-auth ./cmd/pam-device-auth/

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

# Create Debian package
deb: build-all
	@echo "Creating Debian package..."
	@rm -rf $(DEB_DIR)
	@mkdir -p $(DEB_DIR)/DEBIAN
	@mkdir -p $(DEB_DIR)/usr/local/bin
	@mkdir -p $(DEB_DIR)/usr/lib/security
	@mkdir -p $(DEB_DIR)/usr/share/pam-device-auth/config
	@mkdir -p $(DEB_DIR)/etc/ssh/sshd_config.d
	cp debian/control $(DEB_DIR)/DEBIAN/
	cp debian/postinst $(DEB_DIR)/DEBIAN/
	cp debian/postrm $(DEB_DIR)/DEBIAN/
	chmod 755 $(DEB_DIR)/DEBIAN/postinst
	chmod 755 $(DEB_DIR)/DEBIAN/postrm
	cp $(BIN_DIR)/pam-device-auth $(DEB_DIR)/usr/local/bin/
	cp $(PAM_SO) $(DEB_DIR)/usr/lib/security/
	cp configs/config.json $(DEB_DIR)/usr/share/pam-device-auth/config/
	cp configs/10-pam-device-auth.conf $(DEB_DIR)/usr/share/pam-device-auth/config/
	cp configs/pam-sshd-device-auth $(DEB_DIR)/usr/share/pam-device-auth/config/
	@mkdir -p $(DEB_DIR)/usr/share/man/man8
	cp man/pam-device-auth.8 $(DEB_DIR)/usr/share/man/man8/
	gzip -9 $(DEB_DIR)/usr/share/man/man8/pam-device-auth.8
	chmod 755 $(DEB_DIR)/usr/local/bin/pam-device-auth
	chmod 755 $(DEB_DIR)/usr/lib/security/$(PAM_SO)
	@mkdir -p $(PACKAGES_DIR)
	dpkg-deb --build $(DEB_DIR) $(PACKAGES_DIR)/pam-device-auth_$(VERSION)_amd64.deb
	@echo "Package created: $(PACKAGES_DIR)/pam-device-auth_$(VERSION)_amd64.deb"

# Full release
release: clean build-all deb
	@echo "Creating release $(VERSION)..."
	@mkdir -p $(RELEASES_DIR)/pam-device-auth-$(VERSION)
	cp $(BIN_DIR)/pam-device-auth $(RELEASES_DIR)/pam-device-auth-$(VERSION)/
	cp $(PAM_SO) $(RELEASES_DIR)/pam-device-auth-$(VERSION)/
	cp -r configs $(RELEASES_DIR)/pam-device-auth-$(VERSION)/
	cp README.md $(RELEASES_DIR)/pam-device-auth-$(VERSION)/
	cd $(RELEASES_DIR) && tar -czf pam-device-auth-$(VERSION).tar.gz pam-device-auth-$(VERSION)/
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
