# Keycloak SSH Authentication

A secure SSH authentication system that integrates with Keycloak SSO, providing centralized identity management and role-based access control for SSH connections.

## 🚀 Features

- **Single Sign-On (SSO)** authentication for SSH logins
- **Role-based access control** through Keycloak
- **Automatic user account creation** with proper permissions
- **Web-based authentication flow** with user-friendly templates
- **Comprehensive logging** and audit trails
- **Debian package** for easy installation
- **PAM module integration** for seamless SSH integration

## 📋 Table of Contents

- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)

## 🏗️ Architecture

The system consists of three main components:

1. **Go Binary (`keycloak-auth`)**: Handles the OAuth2/OIDC flow with Keycloak
2. **PAM Module (`pam_keycloak.so`)**: Integrates with SSH's authentication system
3. **Web Templates**: Provides user feedback during authentication

### Authentication Flow

```
SSH Client → SSH Server → PAM Module → Go Binary → Keycloak → User Browser
     ↑                                                              ↓
     └─────────────── Authentication Success ←─────────────────────┘
```

1. User attempts SSH connection
2. PAM module calls the Go binary
3. Go binary generates Keycloak authentication URL
4. User authenticates via web browser
5. Keycloak redirects back with authorization code
6. Go binary exchanges code for tokens and verifies user roles
7. If successful, user account is created/updated and SSH access granted

## 📋 Requirements

### System Requirements
- **OS**: Ubuntu 24.04+ or Debian 12+
- **Architecture**: amd64
- **Dependencies**:
  - `libc6`
  - `openssh-server`
  - `libpam-modules`

### Keycloak Requirements
- Keycloak server with OIDC client configured
- Client with Authorization Code Flow enabled
- PKCE (Proof Key for Code Exchange) support
- Required roles configured for SSH access

## 🔧 Installation

### Option 1: Debian Package (Recommended)

```bash
# Download the latest release
wget https://github.com/your-repo/keycloak-ssh-auth/releases/download/v0.2.3/keycloak-ssh-auth_0.2.3_amd64.deb

# Install the package
sudo dpkg -i keycloak-ssh-auth_0.2.3_amd64.deb

# Fix any dependency issues
sudo apt-get install -f
```

### Option 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/your-repo/keycloak-ssh-auth.git
cd keycloak-ssh-auth

# Build the project
make all

# Create Debian package
make deb

# Install the package
sudo dpkg -i keycloak-ssh-auth_0.2.3_amd64.deb
```

## ⚙️ Configuration

### 1. Keycloak Client Setup

Create a new OIDC client in Keycloak with the following settings:

- **Client ID**: `ssh-auth-client` (or your preferred name)
- **Client Protocol**: `openid-connect`
- **Access Type**: `confidential`
- **Valid Redirect URIs**: `http://YOUR_SERVER_IP:33499/callback`
- **Authorization Code Flow**: Enabled
- **PKCE**: Enabled

### 2. Application Configuration

Edit `/etc/keycloak-ssh-auth/keycloak-pam.json`:

```json
{
    "keycloak_url": "https://your-keycloak.example.com",
    "realm": "your-realm",
    "client_id": "ssh-auth-client",
    "client_secret": "your-client-secret",
    "required_role": "ssh-access",
    "callback_ip": "YOUR_SERVER_IP",
    "callback_port": "33499"
}
```

### 3. SSH Configuration

The installation automatically configures SSH, but you can verify:

**`/etc/ssh/sshd_config.d/10-keycloak-auth.conf`**:
```
ChallengeResponseAuthentication yes
KbdInteractiveAuthentication yes
PermitRootLogin no
UsePAM yes
PasswordAuthentication no
MaxAuthTries 1
AuthenticationMethods keyboard-interactive
```

### 4. Firewall Configuration

Ensure the callback port is accessible:

```bash
# UFW
sudo ufw allow 33499/tcp

# iptables
sudo iptables -A INPUT -p tcp --dport 33499 -j ACCEPT
```

## 🎯 Usage

### For End Users

1. **SSH Connection**: Connect normally to the server
   ```bash
   ssh username@your-server.com
   ```

2. **Web Authentication**: You'll receive a URL to open in your browser
   ```
   SSO Login erforderlich!
   Open the following Link:
   https://your-keycloak.example.com/realms/your-realm/protocol/openid-connect/auth?...
   ```

3. **Complete Authentication**: Log in through Keycloak in your browser

4. **SSH Access Granted**: Return to your terminal for SSH access

### For Administrators

#### View Logs
```bash
# Real-time monitoring
sudo tail -f /var/log/keycloak-ssh-auth.log

# View recent authentication attempts
sudo journalctl -u ssh -f
```

#### Test Configuration
```bash
# Test the binary directly
sudo /usr/local/bin/keycloak-auth --help

# Verify PAM configuration
sudo pamtester sshd username authenticate
```

#### User Management
The system automatically:
- Creates user accounts if they don't exist
- Adds users to the `sudo` group
- Configures NOPASSWD sudo access
- Sets up home directories with proper permissions

## 🛠️ Development

### Building

```bash
# Build Go binary only
make build

# Build PAM module only
make pam_keycloak.so

# Build everything
make all

# Clean build artifacts
make clean
```

### Project Structure

```
keycloak-ssh-auth/
├── cmd/keycloak-auth/          # Main Go application
│   └── main.go
├── internal/html/              # HTML templates and utilities
│   ├── template.go
│   └── templates/
├── configs/                    # Configuration files
├── debian/                     # Debian packaging
├── pam_keycloak.c             # PAM module source
├── makefile                   # Build configuration
├── go.mod                     # Go dependencies
└── README.md                  # This file
```

### Adding Features

1. **New HTML Templates**: Add to `internal/html/templates/`
2. **Configuration Options**: Update `Config` struct in `main.go`
3. **PAM Integration**: Modify `pam_keycloak.c`

## 🔍 Troubleshooting

### Common Issues

#### 1. Authentication Timeout
**Symptoms**: "authentication timeout after 3m0s"
**Solutions**:
- Check network connectivity to Keycloak
- Verify callback URL is accessible
- Ensure firewall allows callback port

#### 2. Role Verification Failed
**Symptoms**: "Role verification failed"
**Solutions**:
- Verify user has required role in Keycloak
- Check role name matches configuration
- Ensure client has role scope enabled

#### 3. Username Mismatch
**Symptoms**: "Username mismatch: SSH user 'X' != SSO user 'Y'"
**Solutions**:
- SSH with the same username as in Keycloak
- Configure username mapping in Keycloak
- Update user's preferred_username claim

#### 4. Configuration Errors
**Symptoms**: "could not read config file"
**Solutions**:
- Verify file exists: `/etc/keycloak-ssh-auth/keycloak-pam.json`
- Check file permissions (should be 600)
- Validate JSON syntax

### Debug Mode

Enable debug logging by setting environment variable:
```bash
export DEBUG_MODE=true
sudo -E /usr/local/bin/keycloak-auth
```

### Log Analysis

```bash
# Filter authentication attempts
grep "SSH Login Process Started" /var/log/keycloak-ssh-auth.log

# Check for errors
grep "ERROR\|FAILED" /var/log/keycloak-ssh-auth.log

# Monitor real-time
sudo tail -f /var/log/keycloak-ssh-auth.log | grep -E "(ERROR|SUCCESS|FAILED)"
```

## 🔒 Security Considerations

### Best Practices

1. **Secure Configuration**:
   - Store client secrets securely (600 permissions)
   - Use HTTPS for Keycloak URLs
   - Regularly rotate client secrets

2. **Network Security**:
   - Restrict callback port access to necessary IPs
   - Use VPN or private networks when possible
   - Monitor authentication logs

3. **User Management**:
   - Regularly audit user accounts and permissions
   - Implement proper role-based access control
   - Monitor sudo usage

4. **System Hardening**:
   - Keep system and dependencies updated
   - Use fail2ban for SSH protection
   - Implement proper log rotation

### Security Features

- **PKCE (Proof Key for Code Exchange)**: Prevents authorization code interception
- **State Parameter**: Prevents CSRF attacks
- **Token Validation**: Verifies JWT signatures and claims
- **Role-based Access**: Ensures only authorized users gain access
- **Secure Defaults**: Disables password authentication, limits auth attempts

## 🤝 Contributing

### Development Setup

1. **Prerequisites**:
   ```bash
   # Install Go 1.23+
   sudo apt install golang-1.23

   # Install build dependencies
   sudo apt install build-essential libpam0g-dev
   ```

2. **Clone and Build**:
   ```bash
   git clone https://github.com/your-repo/keycloak-ssh-auth.git
   cd keycloak-ssh-auth
   make all
   ```

3. **Testing**:
   ```bash
   # Run tests
   go test ./...

   # Test PAM module
   sudo make test-pam
   ```

### Submitting Changes

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/your-repo/keycloak-ssh-auth/issues)
- **Documentation**: [Wiki](https://github.com/your-repo/keycloak-ssh-auth/wiki)
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/keycloak-ssh-auth/discussions)

## 📊 Version History

- **v0.2.3** (Current): Improved error handling, better logging, security enhancements
- **v0.2.2**: Added role verification, user management improvements
- **v0.2.1**: Initial stable release with basic SSO functionality
- **v0.1.x**: Development versions

---

**Made with ❤️ for secure SSH authentication**
