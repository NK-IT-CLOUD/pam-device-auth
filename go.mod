module github.com/NK-IT-CLOUD/pam-device-auth

go 1.26

// Pin 1.26.9 (latest 1.26 patch as of 2026-10-09): govulncheck flags the
// 1.26.8 stdlib on the active OIDC/JWKS fetch path (GO-2026-6603,
// GO-2026-6605, GO-2026-6610, GO-2026-6611, GO-2026-6612, GO-2026-6613,
// GO-2026-6617 net/http, GO-2026-6608 net/textproto, GO-2026-6607
// crypto/tls), all fixed in 1.26.9.
// GOTOOLCHAIN=auto (default on 1.21+) auto-downloads this toolchain at
// build time regardless of the runner's installed Go version.
toolchain go1.26.9
