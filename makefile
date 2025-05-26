# Keycloak SSH Authentication Build System
# =====================================

# Project information
BINARY_NAME=keycloak-auth
VERSION=0.2.5
PROJECT_NAME=keycloak-ssh-auth

# Build directories
BUILD_DIR=build
BIN_DIR=$(BUILD_DIR)/bin
PACKAGES_DIR=$(BUILD_DIR)/packages
RELEASES_DIR=$(BUILD_DIR)/releases
DEB_DIR=debian_build

# Test directories
TEST_DIR=test
UNIT_TEST_DIR=$(TEST_DIR)/unit
INTEGRATION_TEST_DIR=$(TEST_DIR)/integration
BENCHMARK_TEST_DIR=$(TEST_DIR)/benchmarks

# PAM Module settings
CC=gcc
CFLAGS=-fPIC -c -Wall -Wextra
LDFLAGS=-shared
LIBS=-lpam
PAM_MODULE=pam_keycloak.so

# Go build settings
GO_BUILD_FLAGS=-ldflags "-X main.VERSION=$(VERSION) -X main.BuildTime=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)"
GO_TEST_FLAGS=-v -race -coverprofile=coverage.out

# Colors for output
RED=\033[0;31m
GREEN=\033[0;32m
YELLOW=\033[1;33m
BLUE=\033[0;34m
NC=\033[0m # No Color

.PHONY: all build build-all clean test test-unit test-integration test-benchmark \
        deb release install uninstall help version deps lint format \
        docker docker-build docker-test

# Default target
all: clean deps build test

# Help target
help:
	@echo "$(BLUE)Keycloak SSH Authentication Build System$(NC)"
	@echo "========================================"
	@echo ""
	@echo "$(YELLOW)Available targets:$(NC)"
	@echo "  $(GREEN)build$(NC)              Build Go binary only"
	@echo "  $(GREEN)build-all$(NC)          Build Go binary and PAM module"
	@echo "  $(GREEN)test$(NC)               Run all tests"
	@echo "  $(GREEN)test-unit$(NC)          Run unit tests"
	@echo "  $(GREEN)test-integration$(NC)   Run integration tests"
	@echo "  $(GREEN)test-benchmark$(NC)     Run benchmark tests"
	@echo "  $(GREEN)deb$(NC)                Create Debian package"
	@echo "  $(GREEN)release$(NC)            Create release package"
	@echo "  $(GREEN)clean$(NC)              Clean build artifacts"
	@echo "  $(GREEN)deps$(NC)               Download dependencies"
	@echo "  $(GREEN)lint$(NC)               Run linters"
	@echo "  $(GREEN)format$(NC)             Format code"
	@echo "  $(GREEN)install$(NC)            Install package"
	@echo "  $(GREEN)uninstall$(NC)          Uninstall package"
	@echo "  $(GREEN)version$(NC)            Show version information"
	@echo ""
	@echo "$(YELLOW)Build directories:$(NC)"
	@echo "  $(BIN_DIR)         - Compiled binaries"
	@echo "  $(PACKAGES_DIR)    - Generated packages"
	@echo "  $(RELEASES_DIR)    - Release artifacts"

# Version information
version:
	@echo "$(BLUE)Project:$(NC) $(PROJECT_NAME)"
	@echo "$(BLUE)Version:$(NC) $(VERSION)"
	@echo "$(BLUE)Binary:$(NC)  $(BINARY_NAME)"

# Download dependencies
deps:
	@echo "$(YELLOW)Downloading dependencies...$(NC)"
	@go mod download
	@go mod verify

# Build Go binary only
build:
	@echo "$(YELLOW)Building Go binary...$(NC)"
	@mkdir -p $(BIN_DIR)
	@go build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/keycloak-auth
	@echo "$(GREEN)✓ Binary built: $(BIN_DIR)/$(BINARY_NAME)$(NC)"

# Build PAM module
$(PAM_MODULE): pam_keycloak.c
	@echo "$(YELLOW)Building PAM module...$(NC)"
	@$(CC) $(CFLAGS) pam_keycloak.c -o pam_keycloak.o
	@$(CC) $(LDFLAGS) -o $(PAM_MODULE) pam_keycloak.o $(LIBS)
	@rm -f pam_keycloak.o
	@echo "$(GREEN)✓ PAM module built: $(PAM_MODULE)$(NC)"

# Build everything
build-all: build $(PAM_MODULE)
	@echo "$(GREEN)✓ All components built successfully$(NC)"

# Test targets
test: test-unit test-integration
	@echo "$(GREEN)✓ All tests completed$(NC)"

test-unit:
	@echo "$(YELLOW)Running unit tests...$(NC)"
	@go test $(GO_TEST_FLAGS) ./...
	@echo "$(GREEN)✓ Unit tests passed$(NC)"

test-integration:
	@echo "$(YELLOW)Running integration tests...$(NC)"
	@if [ -f $(INTEGRATION_TEST_DIR)/test_version.sh ]; then \
		chmod +x $(INTEGRATION_TEST_DIR)/test_version.sh && \
		$(INTEGRATION_TEST_DIR)/test_version.sh; \
	else \
		echo "$(YELLOW)No integration tests found$(NC)"; \
	fi

test-benchmark:
	@echo "$(YELLOW)Running benchmark tests...$(NC)"
	@go test -bench=. -benchmem ./...
	@echo "$(GREEN)✓ Benchmark tests completed$(NC)"

# Code quality
lint:
	@echo "$(YELLOW)Running linters...$(NC)"
	@go vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "$(YELLOW)golangci-lint not installed, skipping$(NC)"; \
	fi
	@echo "$(GREEN)✓ Linting completed$(NC)"

format:
	@echo "$(YELLOW)Formatting code...$(NC)"
	@go fmt ./...
	@echo "$(GREEN)✓ Code formatted$(NC)"

# Package creation
deb: build-all
	@echo "$(YELLOW)Creating Debian package...$(NC)"
	@mkdir -p $(DEB_DIR)/DEBIAN
	@mkdir -p $(DEB_DIR)/usr/local/bin
	@mkdir -p $(DEB_DIR)/usr/share/keycloak-ssh-auth/config
	@mkdir -p $(DEB_DIR)/usr/share/keycloak-ssh-auth/templates
	@mkdir -p $(DEB_DIR)/etc/ssh/sshd_config.d
	@mkdir -p $(DEB_DIR)/usr/lib/security
	@mkdir -p $(PACKAGES_DIR)
	@cp debian/control $(DEB_DIR)/DEBIAN/
	@cp debian/postinst $(DEB_DIR)/DEBIAN/
	@cp debian/postrm $(DEB_DIR)/DEBIAN/
	@cp $(BIN_DIR)/$(BINARY_NAME) $(DEB_DIR)/usr/local/bin/
	@cp $(PAM_MODULE) $(DEB_DIR)/usr/lib/security/
	@cp configs/keycloak-pam.json $(DEB_DIR)/usr/share/keycloak-ssh-auth/config/
	@cp configs/10-keycloak-auth.conf $(DEB_DIR)/usr/share/keycloak-ssh-auth/config/
	@cp configs/pam-sshd-keycloak $(DEB_DIR)/usr/share/keycloak-ssh-auth/config/
	@cp internal/html/templates/*.html $(DEB_DIR)/usr/share/keycloak-ssh-auth/templates/
	@chmod 755 $(DEB_DIR)/DEBIAN/postinst
	@chmod 755 $(DEB_DIR)/DEBIAN/postrm
	@chmod 755 $(DEB_DIR)/usr/local/bin/$(BINARY_NAME)
	@chmod 755 $(DEB_DIR)/usr/lib/security/$(PAM_MODULE)
	@dpkg-deb --build $(DEB_DIR) $(PACKAGES_DIR)/$(PROJECT_NAME)_$(VERSION)_amd64.deb
	@echo "$(GREEN)✓ Debian package created: $(PACKAGES_DIR)/$(PROJECT_NAME)_$(VERSION)_amd64.deb$(NC)"

# Create release package
release: clean build-all deb
	@echo "$(YELLOW)Creating release package...$(NC)"
	@mkdir -p $(RELEASES_DIR)/$(VERSION)
	@cp $(BIN_DIR)/$(BINARY_NAME) $(RELEASES_DIR)/$(VERSION)/
	@cp $(PAM_MODULE) $(RELEASES_DIR)/$(VERSION)/
	@cp $(PACKAGES_DIR)/$(PROJECT_NAME)_$(VERSION)_amd64.deb $(RELEASES_DIR)/$(VERSION)/
	@cp README.md $(RELEASES_DIR)/$(VERSION)/
	@cp CHANGELOG.md $(RELEASES_DIR)/$(VERSION)/
	@cp LICENSE $(RELEASES_DIR)/$(VERSION)/
	@cd $(RELEASES_DIR) && tar -czf $(PROJECT_NAME)_$(VERSION)_linux_amd64.tar.gz $(VERSION)/
	@echo "$(GREEN)✓ Release package created: $(RELEASES_DIR)/$(PROJECT_NAME)_$(VERSION)_linux_amd64.tar.gz$(NC)"

# Installation targets
install: deb
	@echo "$(YELLOW)Installing package...$(NC)"
	@sudo dpkg -i $(PACKAGES_DIR)/$(PROJECT_NAME)_$(VERSION)_amd64.deb || \
		(sudo apt-get install -f && sudo dpkg -i $(PACKAGES_DIR)/$(PROJECT_NAME)_$(VERSION)_amd64.deb)
	@echo "$(GREEN)✓ Package installed successfully$(NC)"

uninstall:
	@echo "$(YELLOW)Uninstalling package...$(NC)"
	@sudo dpkg -r $(PROJECT_NAME) || echo "$(YELLOW)Package not installed$(NC)"
	@echo "$(GREEN)✓ Package uninstalled$(NC)"

# Clean targets
clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	@rm -rf $(BUILD_DIR)
	@rm -rf $(DEB_DIR)
	@rm -f $(PAM_MODULE)
	@rm -f pam_keycloak.o
	@rm -f coverage.out
	@echo "$(GREEN)✓ Clean completed$(NC)"

clean-all: clean
	@echo "$(YELLOW)Cleaning all artifacts including releases...$(NC)"
	@rm -f *.deb
	@rm -f *.tar.gz
	@echo "$(GREEN)✓ Deep clean completed$(NC)"
