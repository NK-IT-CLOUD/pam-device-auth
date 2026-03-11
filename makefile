# keycloak-ssh-auth v0.4.0 Build System
VERSION=0.4.0
MODULE=git.server.nk-it.cloud/nk-dev/keycloak-ssh-auth

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
PAM_SRC=pam_keycloak.c
PAM_OBJ=pam_keycloak.o
PAM_SO=pam_keycloak.so

.PHONY: all build build-all test test-unit lint format clean clean-all deb release install uninstall

all: clean build-all test

# Build Go binary only
build:
	@echo "Building keycloak-auth $(VERSION)..."
	@mkdir -p $(BIN_DIR)
	go build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/keycloak-auth ./cmd/keycloak-auth/

# Build binary + PAM module
build-all: build
	@echo "Building PAM module..."
	gcc -fPIC -c $(PAM_SRC) -o $(PAM_OBJ)
	gcc -shared -o $(PAM_SO) $(PAM_OBJ) -lpam
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
	@mkdir -p $(DEB_DIR)/usr/share/keycloak-ssh-auth/config
	@mkdir -p $(DEB_DIR)/etc/ssh/sshd_config.d
	cp debian/control $(DEB_DIR)/DEBIAN/
	cp debian/postinst $(DEB_DIR)/DEBIAN/
	cp debian/postrm $(DEB_DIR)/DEBIAN/
	chmod 755 $(DEB_DIR)/DEBIAN/postinst
	chmod 755 $(DEB_DIR)/DEBIAN/postrm
	cp $(BIN_DIR)/keycloak-auth $(DEB_DIR)/usr/local/bin/
	cp $(PAM_SO) $(DEB_DIR)/usr/lib/security/
	cp configs/keycloak-pam.json $(DEB_DIR)/usr/share/keycloak-ssh-auth/config/
	cp configs/10-keycloak-auth.conf $(DEB_DIR)/usr/share/keycloak-ssh-auth/config/
	cp configs/pam-sshd-keycloak $(DEB_DIR)/usr/share/keycloak-ssh-auth/config/
	chmod 755 $(DEB_DIR)/usr/local/bin/keycloak-auth
	chmod 755 $(DEB_DIR)/usr/lib/security/$(PAM_SO)
	@mkdir -p $(PACKAGES_DIR)
	dpkg-deb --build $(DEB_DIR) $(PACKAGES_DIR)/keycloak-ssh-auth_$(VERSION)_amd64.deb
	@echo "Package created: $(PACKAGES_DIR)/keycloak-ssh-auth_$(VERSION)_amd64.deb"

# Full release
release: clean build-all deb
	@echo "Creating release $(VERSION)..."
	@mkdir -p $(RELEASES_DIR)/keycloak-ssh-auth-$(VERSION)
	cp $(BIN_DIR)/keycloak-auth $(RELEASES_DIR)/keycloak-ssh-auth-$(VERSION)/
	cp $(PAM_SO) $(RELEASES_DIR)/keycloak-ssh-auth-$(VERSION)/
	cp -r configs $(RELEASES_DIR)/keycloak-ssh-auth-$(VERSION)/
	cp README.md $(RELEASES_DIR)/keycloak-ssh-auth-$(VERSION)/
	cd $(RELEASES_DIR) && tar -czf keycloak-ssh-auth-$(VERSION).tar.gz keycloak-ssh-auth-$(VERSION)/
	@echo "Release: $(RELEASES_DIR)/keycloak-ssh-auth-$(VERSION).tar.gz"

# Install via dpkg
install: deb
	sudo dpkg -i $(PACKAGES_DIR)/keycloak-ssh-auth_$(VERSION)_amd64.deb

# Uninstall
uninstall:
	sudo dpkg -r keycloak-ssh-auth

# Clean
clean:
	rm -rf $(BUILD_DIR) $(DEB_DIR)
	rm -f $(PAM_OBJ) $(PAM_SO)
	rm -f coverage.out
	rm -f keycloak-auth

clean-all:
	rm -rf $(BUILD_DIR) $(DEB_DIR) $(RELEASES_DIR)
	rm -f $(PAM_OBJ) $(PAM_SO) coverage.out keycloak-auth
