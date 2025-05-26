# Build System Documentation

## 📁 Project Structure

```
keycloak-ssh-auth/
├── build/                          # Build artifacts (gitignored)
│   ├── bin/                        # Compiled binaries
│   ├── packages/                   # Generated packages (.deb, .rpm)
│   └── releases/                   # Release artifacts
├── cmd/                            # Main applications
│   └── keycloak-auth/              # Main Go application
├── configs/                        # Configuration templates
├── debian/                         # Debian packaging files
├── docs/                           # Documentation
├── internal/                       # Internal Go packages
│   ├── auth/                       # Authentication logic
│   ├── config/                     # Configuration management
│   ├── logger/                     # Logging utilities
│   └── user/                       # User management
├── scripts/                        # Build and utility scripts
├── test/                           # Test files
│   ├── unit/                       # Unit tests
│   ├── integration/                # Integration tests
│   └── benchmarks/                 # Benchmark tests
├── .github/workflows/              # GitHub Actions
├── makefile                        # Build system
├── VERSION                         # Current version
└── README.md                       # Project documentation
```

## 🔧 Build System

### Make Targets

#### Basic Build Commands
```bash
make help              # Show all available targets
make version           # Show version information
make deps              # Download Go dependencies
make build             # Build Go binary only
make build-all         # Build Go binary and PAM module
make clean             # Clean build artifacts
make clean-all         # Deep clean including releases
```

#### Testing Commands
```bash
make test              # Run all tests
make test-unit         # Run unit tests only
make test-integration  # Run integration tests
make test-benchmark    # Run benchmark tests
make lint              # Run code linters
make format            # Format Go code
```

#### Package Creation
```bash
make deb               # Create Debian package
make release           # Create complete release package
make install           # Install Debian package
make uninstall         # Uninstall package
```

### Build Directories

- **`build/bin/`**: Compiled Go binaries
- **`build/packages/`**: Generated packages (`.deb`, `.tar.gz`)
- **`build/releases/`**: Complete release artifacts with documentation

## 📦 Version Management

### Version Script Usage

```bash
# Show current version
./scripts/version.sh current

# Bump version
./scripts/version.sh bump patch    # 0.2.4 → 0.2.5
./scripts/version.sh bump minor    # 0.2.4 → 0.3.0
./scripts/version.sh bump major    # 0.2.4 → 1.0.0

# Set specific version
./scripts/version.sh set 1.0.0

# Create git tag
./scripts/version.sh tag

# Complete release process
./scripts/version.sh release
```

### Files Updated by Version Script

- `VERSION` - Version file
- `makefile` - VERSION variable
- `debian/control` - Package version
- `cmd/keycloak-auth/main.go` - VERSION constant
- `CHANGELOG.md` - New version entry

## 🚀 GitHub Release Process

### Prerequisites

1. Install GitHub CLI:
   ```bash
   # Ubuntu/Debian
   sudo apt install gh
   
   # Or download from https://cli.github.com/
   ```

2. Authenticate:
   ```bash
   gh auth login
   ```

### Release Commands

```bash
# Create GitHub release for current version
./scripts/github-release.sh create

# Create release for specific version
./scripts/github-release.sh create v0.2.5

# Upload additional files
./scripts/github-release.sh upload v0.2.4 extra-file.zip

# List releases
./scripts/github-release.sh list

# Delete release
./scripts/github-release.sh delete v0.2.4
```

## 🔄 Complete Release Workflow

### 1. Development to Release

```bash
# 1. Make your changes
git add .
git commit -m "Add new feature"

# 2. Run tests
make test

# 3. Create release (bumps version, builds, commits, tags)
./scripts/version.sh release

# 4. Push to GitHub
git push
git push origin v0.2.5

# 5. Create GitHub release
./scripts/github-release.sh create
```

### 2. Manual Release Process

```bash
# 1. Bump version
./scripts/version.sh bump patch

# 2. Update changelog manually
vim CHANGELOG.md

# 3. Build release
make release

# 4. Commit and tag
git add .
git commit -m "Release version 0.2.5"
./scripts/version.sh tag

# 5. Push to GitHub
git push
git push origin v0.2.5

# 6. Create GitHub release
./scripts/github-release.sh create
```

## 🧪 Testing

### Test Structure

- **Unit Tests**: `test/unit/` - Test individual functions
- **Integration Tests**: `test/integration/` - Test complete workflows
- **Benchmarks**: `test/benchmarks/` - Performance tests

### Running Tests

```bash
# All tests
make test

# Specific test types
make test-unit
make test-integration
make test-benchmark

# With coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## 📋 Configuration

### Build Configuration

Edit `makefile` to change:
- `VERSION` - Current version
- `BINARY_NAME` - Binary name
- `PROJECT_NAME` - Project name
- Build flags and options

### Version Configuration

Edit `VERSION` file or use version script:
```bash
echo "0.3.0" > VERSION
# or
./scripts/version.sh set 0.3.0
```

## 🔍 Troubleshooting

### Common Issues

1. **Build fails**: Check Go version and dependencies
   ```bash
   go version  # Should be 1.21+
   make deps
   ```

2. **PAM module build fails**: Install development packages
   ```bash
   sudo apt install build-essential libpam0g-dev
   ```

3. **GitHub release fails**: Check authentication
   ```bash
   gh auth status
   gh auth login
   ```

4. **Version mismatch**: Sync all version files
   ```bash
   ./scripts/version.sh set $(cat VERSION)
   ```

### Debug Mode

Enable verbose output:
```bash
make V=1 build          # Verbose make
go build -v ./...       # Verbose Go build
```

## 📈 CI/CD Integration

The project includes GitHub Actions workflows:

- **`.github/workflows/ci.yml`**: Automated testing and building
- Triggers on push to main/develop branches
- Runs tests on multiple Go versions
- Creates artifacts for releases
- Security scanning with Gosec

### Manual CI Commands

```bash
# Run same checks as CI
make deps
make lint
make test
make build-all
```

This build system provides a complete development and release workflow for the Keycloak SSH Authentication project.
