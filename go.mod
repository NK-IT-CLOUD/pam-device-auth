module github.com/NK-IT-CLOUD/pam-device-auth

go 1.26

// Pin 1.26.2 to pick up crypto/x509 + crypto/tls stdlib fixes
// (GO-2026-4866, -4870, -4946, -4947). GOTOOLCHAIN=auto (default on 1.21+)
// auto-downloads this toolchain at build time regardless of the runner's
// installed Go version.
toolchain go1.26.2
