#!/usr/bin/env bash
# Bump version across all project files.
#
# Usage: ./scripts/bump-version.sh 1.1.0
set -euo pipefail

NEW_VERSION="${1:-}"
if [ -z "$NEW_VERSION" ]; then
    echo "Usage: $0 <new-version>"
    exit 1
fi

if [[ ! "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: Invalid version format. Use semantic versioning (e.g., 1.1.0)"
    exit 1
fi

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$APP_DIR"

OLD_VERSION=$(cat VERSION)
echo "Bumping ${OLD_VERSION} -> ${NEW_VERSION}"

echo "$NEW_VERSION" > VERSION
sed -i "s/^VERSION=.*/VERSION=$NEW_VERSION/" makefile
sed -i "s/^Version:.*/Version: $NEW_VERSION/" debian/control
sed -i "s/VERSION = \".*\"/VERSION = \"$NEW_VERSION\"/" cmd/pam-device-auth/main.go

echo "Version updated to ${NEW_VERSION}"
echo "Don't forget to update CHANGELOG.md"
