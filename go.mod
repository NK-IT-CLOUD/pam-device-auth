module github.com/NK-IT-CLOUD/pam-device-auth

go 1.26

// Pin 1.26.5 (2026-07-07) to pick up the crypto/tls and os stdlib security
// fixes — crypto/tls is on the active OIDC/JWKS fetch path. Supersedes the
// 1.26.4 pin (crypto/x509 GO-2026-5037, net/textproto GO-2026-5039) and the
// earlier 1.26.3 crypto/tls + net/http fixes.
// GOTOOLCHAIN=auto (default on 1.21+) auto-downloads this toolchain at
// build time regardless of the runner's installed Go version.
toolchain go1.26.5
