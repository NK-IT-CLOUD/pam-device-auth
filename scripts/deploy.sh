#!/usr/bin/env bash
# Build and deploy pam-device-auth to a target host.
#
# Usage:
#   ./scripts/deploy.sh                    # Build + deploy to default target
#   ./scripts/deploy.sh --target myhost    # Deploy to specific host
#   ./scripts/deploy.sh --build-only       # Only create .deb
#   ./scripts/deploy.sh --skip-build       # Deploy existing .deb
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(dirname "$SCRIPT_DIR")"
cd "$APP_DIR"

VERSION=$(cat VERSION)
DEB_FILE="build/packages/pam-device-auth_${VERSION}_amd64.deb"
TARGET="pam-device-auth-test"
BUILD=true
DEPLOY=true

while [ $# -gt 0 ]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --build-only) DEPLOY=false; shift ;;
        --skip-build) BUILD=false; shift ;;
        --help|-h)
            echo "Usage: $0 [--target HOST] [--build-only|--skip-build]"
            exit 0 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

if $BUILD; then
    echo "Building pam-device-auth ${VERSION}..."
    make clean && make build-all && make deb
fi

if $DEPLOY; then
    echo "Deploying to ${TARGET}..."
    scp "$DEB_FILE" "${TARGET}:/tmp/"
    ssh "$TARGET" "sudo dpkg -i /tmp/pam-device-auth_${VERSION}_amd64.deb"
    echo "Deployed pam-device-auth ${VERSION} to ${TARGET}"
fi
