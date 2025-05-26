#!/bin/bash

# Version Management Script for Keycloak SSH Authentication
# ========================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="keycloak-ssh-auth"
CURRENT_VERSION_FILE="VERSION"
MAKEFILE="makefile"
DEBIAN_CONTROL="debian/control"
MAIN_GO="cmd/keycloak-auth/main.go"
CHANGELOG="CHANGELOG.md"

# Functions
print_usage() {
    echo -e "${BLUE}Version Management Script${NC}"
    echo "========================"
    echo ""
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  current                    Show current version"
    echo "  bump [major|minor|patch]   Bump version"
    echo "  set <version>              Set specific version"
    echo "  tag                        Create git tag for current version"
    echo "  release                    Create release (bump patch + tag + build)"
    echo ""
    echo "Examples:"
    echo "  $0 current"
    echo "  $0 bump patch"
    echo "  $0 set 1.0.0"
    echo "  $0 release"
}

get_current_version() {
    if [ -f "$CURRENT_VERSION_FILE" ]; then
        cat "$CURRENT_VERSION_FILE"
    else
        # Extract from makefile as fallback
        grep "^VERSION=" "$MAKEFILE" | cut -d'=' -f2
    fi
}

set_version() {
    local new_version="$1"
    
    if [[ ! "$new_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${RED}Error: Invalid version format. Use semantic versioning (e.g., 1.0.0)${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}Setting version to $new_version...${NC}"
    
    # Update VERSION file
    echo "$new_version" > "$CURRENT_VERSION_FILE"
    
    # Update makefile
    sed -i "s/^VERSION=.*/VERSION=$new_version/" "$MAKEFILE"
    
    # Update debian/control
    sed -i "s/^Version:.*/Version: $new_version/" "$DEBIAN_CONTROL"
    
    # Update main.go
    sed -i "s/VERSION = \".*\"/VERSION = \"$new_version\"/" "$MAIN_GO"
    
    echo -e "${GREEN}✓ Version updated to $new_version${NC}"
}

bump_version() {
    local bump_type="$1"
    local current_version=$(get_current_version)
    
    if [ -z "$current_version" ]; then
        echo -e "${RED}Error: Could not determine current version${NC}"
        exit 1
    fi
    
    # Parse version
    IFS='.' read -r major minor patch <<< "$current_version"
    
    case "$bump_type" in
        major)
            major=$((major + 1))
            minor=0
            patch=0
            ;;
        minor)
            minor=$((minor + 1))
            patch=0
            ;;
        patch)
            patch=$((patch + 1))
            ;;
        *)
            echo -e "${RED}Error: Invalid bump type. Use major, minor, or patch${NC}"
            exit 1
            ;;
    esac
    
    local new_version="$major.$minor.$patch"
    set_version "$new_version"
}

create_git_tag() {
    local version=$(get_current_version)
    local tag_name="v$version"
    
    echo -e "${YELLOW}Creating git tag $tag_name...${NC}"
    
    # Check if tag already exists
    if git tag -l | grep -q "^$tag_name$"; then
        echo -e "${RED}Error: Tag $tag_name already exists${NC}"
        exit 1
    fi
    
    # Create annotated tag
    git tag -a "$tag_name" -m "Release version $version"
    echo -e "${GREEN}✓ Git tag $tag_name created${NC}"
    
    echo -e "${YELLOW}To push the tag to remote, run:${NC}"
    echo "  git push origin $tag_name"
}

update_changelog() {
    local version="$1"
    local date=$(date +%Y-%m-%d)
    
    echo -e "${YELLOW}Updating CHANGELOG.md...${NC}"
    
    # Create backup
    cp "$CHANGELOG" "$CHANGELOG.bak"
    
    # Add new version entry
    sed -i "/^## \[Unreleased\]/a\\
\\
## [$version] - $date\\
\\
### Added\\
- New features and improvements\\
\\
### Changed\\
- Updates and modifications\\
\\
### Fixed\\
- Bug fixes and patches" "$CHANGELOG"
    
    echo -e "${GREEN}✓ CHANGELOG.md updated${NC}"
    echo -e "${YELLOW}Please edit CHANGELOG.md to add specific changes${NC}"
}

create_release() {
    echo -e "${BLUE}Creating release...${NC}"
    
    # Bump patch version
    bump_version patch
    local new_version=$(get_current_version)
    
    # Update changelog
    update_changelog "$new_version"
    
    # Build release
    echo -e "${YELLOW}Building release...${NC}"
    make clean
    make release
    
    # Commit changes
    echo -e "${YELLOW}Committing version changes...${NC}"
    git add .
    git commit -m "Release version $new_version"
    
    # Create tag
    create_git_tag
    
    echo -e "${GREEN}✓ Release $new_version created successfully!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Review the changes: git log --oneline -5"
    echo "2. Push changes: git push"
    echo "3. Push tag: git push origin v$new_version"
    echo "4. Create GitHub release with build/releases/$new_version/ artifacts"
}

# Main script
case "$1" in
    current)
        version=$(get_current_version)
        echo -e "${BLUE}Current version:${NC} $version"
        ;;
    bump)
        if [ -z "$2" ]; then
            echo -e "${RED}Error: Bump type required (major|minor|patch)${NC}"
            print_usage
            exit 1
        fi
        bump_version "$2"
        ;;
    set)
        if [ -z "$2" ]; then
            echo -e "${RED}Error: Version required${NC}"
            print_usage
            exit 1
        fi
        set_version "$2"
        ;;
    tag)
        create_git_tag
        ;;
    release)
        create_release
        ;;
    help|--help|-h)
        print_usage
        ;;
    *)
        echo -e "${RED}Error: Unknown command '$1'${NC}"
        print_usage
        exit 1
        ;;
esac
