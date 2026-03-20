#!/usr/bin/env bash
# Create a release: test, build, tag, upload.
#
# Usage:
#   ./scripts/release.sh              # Full release
#   ./scripts/release.sh --dry-run    # Show what would happen
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(dirname "$SCRIPT_DIR")"
cd "$APP_DIR"

VERSION=$(cat VERSION)
TAG="v${VERSION}"
DRY_RUN=false

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        --help|-h) echo "Usage: $0 [--dry-run]"; exit 0 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

echo "Release pam-device-auth ${VERSION}"

if git tag -l | grep -q "^${TAG}$"; then
    echo "ERROR: Tag ${TAG} already exists"
    exit 1
fi

if ! git diff --quiet; then
    echo "ERROR: Uncommitted changes. Commit first."
    exit 1
fi

if $DRY_RUN; then
    echo "[dry-run] Would: test -> build -> deb -> tag ${TAG}"
    exit 0
fi

echo "Running tests..."
make test

echo "Building..."
make clean && make build-all && make deb

git tag -a "$TAG" -m "Release ${VERSION}"
echo "Tagged ${TAG}"
echo ""
echo "Release ${VERSION} ready."
echo "Next: git push && git push origin ${TAG}"
