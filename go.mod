module github.com/NK-IT-CLOUD/pam-device-auth

go 1.26

// Pin 1.26.4 to pick up the crypto/x509 + net/textproto stdlib fixes
// (GO-2026-5037 inefficient hostname parsing, GO-2026-5039 unescaped inputs
// in textproto errors — the latter reachable via the JWKS/token fetch path),
// on top of the earlier 1.26.3 crypto/tls + net/http fixes.
// GOTOOLCHAIN=auto (default on 1.21+) auto-downloads this toolchain at
// build time regardless of the runner's installed Go version.
toolchain go1.26.4
