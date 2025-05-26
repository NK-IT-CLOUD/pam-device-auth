# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.4] - 2024-05-26

### Added
- **Modular Architecture**: Restructured codebase into separate packages
  - `internal/config/` - Configuration management
  - `internal/auth/` - Authentication logic
  - `internal/logger/` - Structured logging
  - `internal/user/` - User management
- **Environment Variable Support**: Override configuration with environment variables
  - `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, etc.
  - `DEBUG_MODE`, `AUTH_TIMEOUT`, `CREATE_USERS`, `ADD_TO_SUDO`
- **Enhanced Logging System**: Structured logging with debug mode
- **Comprehensive Testing**: Unit tests, integration tests, and benchmarks
- **GitHub Actions CI/CD**: Automated testing and building
- **Security Enhancements**: Better input validation and error handling
- **Performance Optimizations**: Improved HTTP client handling and resource management

### Changed
- **Improved Error Messages**: More detailed and user-friendly error messages
- **Better Configuration Validation**: Comprehensive validation of all config values
- **Enhanced Documentation**: Complete README with examples and troubleshooting
- **Code Quality**: Following Go best practices and conventions

### Fixed
- **Memory Leaks**: Better resource cleanup and management
- **Race Conditions**: Thread-safe operations where needed
- **Error Handling**: Proper error propagation and handling
- **Timeout Issues**: Better timeout configuration and handling

### Security
- **Input Validation**: Comprehensive validation of all user inputs
- **Environment Variables**: Secure handling of sensitive configuration data
- **Permission Management**: Improved file and directory permission handling
- **Command Injection Prevention**: Protection against command injection attacks

## [0.2.3] - 2024-03-05

### Added
- Role verification functionality
- User management improvements
- Enhanced error handling

### Changed
- Improved authentication flow
- Better logging output

### Fixed
- Various bug fixes and stability improvements

## [0.2.2] - 2024-02-15

### Added
- Basic SSO functionality
- PAM module integration
- Web-based authentication templates

### Changed
- Initial stable release structure

## [0.2.1] - 2024-02-01

### Added
- Initial release with basic Keycloak integration
- SSH authentication via OAuth2/OIDC
- Debian packaging

## [0.1.x] - Development Versions

### Added
- Development and testing versions
- Proof of concept implementations
