BINARY_NAME=keycloak-auth
VERSION=0.2.4
BUILD_DIR=build
DEB_DIR=debian_build

# PAM Module settings
CC=gcc
CFLAGS=-fPIC -c
LDFLAGS=-shared
LIBS=-lpam
PAM_MODULE=pam_keycloak.so

.PHONY: all build clean deb

all: build $(PAM_MODULE)

# Build Go binary
build:
	@echo "Building Go binary..."
	mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/keycloak-auth

# Build PAM module
$(PAM_MODULE): pam_keycloak.c
	@echo "Building PAM module..."
	$(CC) $(CFLAGS) pam_keycloak.c -o pam_keycloak.o
	$(CC) $(LDFLAGS) -o $(PAM_MODULE) pam_keycloak.o $(LIBS)
	rm -f pam_keycloak.o

clean:
	@echo "Cleaning..."
	rm -f pam_keycloak.o $(PAM_MODULE)
	rm -rf $(BUILD_DIR)
	rm -rf $(DEB_DIR)

deb: build $(PAM_MODULE)
	@echo "Creating Debian package..."
	mkdir -p $(DEB_DIR)/DEBIAN
	mkdir -p $(DEB_DIR)/usr/local/bin
	mkdir -p $(DEB_DIR)/usr/share/keycloak-ssh-auth/config
	mkdir -p $(DEB_DIR)/usr/share/keycloak-ssh-auth/templates
	mkdir -p $(DEB_DIR)/etc/ssh/sshd_config.d
	mkdir -p $(DEB_DIR)/usr/lib/security
	cp debian/control $(DEB_DIR)/DEBIAN/
	cp debian/postinst $(DEB_DIR)/DEBIAN/
	cp debian/postrm $(DEB_DIR)/DEBIAN/
	cp $(BUILD_DIR)/$(BINARY_NAME) $(DEB_DIR)/usr/local/bin/
	cp $(PAM_MODULE) $(DEB_DIR)/usr/lib/security/
	cp configs/keycloak-pam.json $(DEB_DIR)/usr/share/keycloak-ssh-auth/config/
	cp configs/10-keycloak-auth.conf $(DEB_DIR)/usr/share/keycloak-ssh-auth/config/
	cp configs/pam-sshd-keycloak $(DEB_DIR)/usr/share/keycloak-ssh-auth/config/
	cp internal/html/templates/*.html $(DEB_DIR)/usr/share/keycloak-ssh-auth/templates/
	chmod 755 $(DEB_DIR)/DEBIAN/postinst
	chmod 755 $(DEB_DIR)/DEBIAN/postrm
	chmod 755 $(DEB_DIR)/usr/local/bin/$(BINARY_NAME)
	chmod 755 $(DEB_DIR)/usr/lib/security/pam_keycloak.so
	dpkg-deb --build $(DEB_DIR) keycloak-ssh-auth_$(VERSION)_amd64.deb
