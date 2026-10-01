module github.com/NK-IT-CLOUD/pam-device-auth

go 1.26

// Pin 1.26.8 (latest 1.26 patch as of 2026-09-05): govulncheck flags the
// 1.26.5 stdlib on the active OIDC/JWKS fetch path (GO-2026-6218 net/url,
// GO-2026-6090 crypto/tls, GO-2026-5972 encoding/asn1, GO-2026-5026
// net/http idna), all fixed in 1.26.6+.
// GOTOOLCHAIN=auto (default on 1.21+) auto-downloads this toolchain at
// build time regardless of the runner's installed Go version.
toolchain go1.26.8
