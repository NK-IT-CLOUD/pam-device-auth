module github.com/NK-IT-CLOUD/pam-device-auth

go 1.26

// Pin the latest Go release (1.27.3 as of 2026-11-08): govulncheck checks
// the stdlib of this toolchain, which serves the OIDC/JWKS fetch path
// (net/http, crypto/tls).
// GOTOOLCHAIN=auto (default on 1.21+) auto-downloads this toolchain at
// build time regardless of the runner's installed Go version.
toolchain go1.27.3
