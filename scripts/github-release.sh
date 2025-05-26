#!/bin/bash

# GitHub Release Script for Keycloak SSH Authentication
# ====================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_OWNER="Fu6gie"
REPO_NAME="keycloak-ssh-auth"
VERSION_FILE="VERSION"

print_usage() {
    echo -e "${BLUE}GitHub Release Script${NC}"
    echo "===================="
    echo ""
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  create [version]           Create GitHub release"
    echo "  upload <tag> <file>        Upload file to existing release"
    echo "  list                       List releases"
    echo "  delete <tag>               Delete release"
    echo ""
    echo "Prerequisites:"
    echo "  - GitHub CLI (gh) must be installed and authenticated"
    echo "  - Repository must be pushed to GitHub"
    echo ""
    echo "Examples:"
    echo "  $0 create                  # Create release for current version"
    echo "  $0 create v0.2.5           # Create release for specific version"
    echo "  $0 upload v0.2.4 file.deb # Upload file to release"
    echo "  $0 list                    # List all releases"
}

check_prerequisites() {
    # Check if gh CLI is installed
    if ! command -v gh &> /dev/null; then
        echo -e "${RED}Error: GitHub CLI (gh) is not installed${NC}"
        echo "Install it from: https://cli.github.com/"
        exit 1
    fi
    
    # Check if authenticated
    if ! gh auth status &> /dev/null; then
        echo -e "${RED}Error: GitHub CLI is not authenticated${NC}"
        echo "Run: gh auth login"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Prerequisites check passed${NC}"
}

get_current_version() {
    if [ -f "$VERSION_FILE" ]; then
        cat "$VERSION_FILE"
    else
        echo -e "${RED}Error: VERSION file not found${NC}"
        exit 1
    fi
}

generate_release_notes() {
    local version="$1"
    local tag_name="v$version"
    
    # Try to get changes from CHANGELOG.md
    if [ -f "CHANGELOG.md" ]; then
        # Extract changes for this version
        awk "/^## \[$version\]/{flag=1; next} /^## \[/{flag=0} flag" CHANGELOG.md > /tmp/release_notes.md
        
        if [ -s /tmp/release_notes.md ]; then
            echo "Release notes extracted from CHANGELOG.md"
            return 0
        fi
    fi
    
    # Fallback: generate from git commits
    local previous_tag=$(git tag --sort=-version:refname | head -2 | tail -1)
    if [ -n "$previous_tag" ]; then
        echo "## Changes since $previous_tag" > /tmp/release_notes.md
        echo "" >> /tmp/release_notes.md
        git log --pretty=format:"- %s" "$previous_tag..HEAD" >> /tmp/release_notes.md
    else
        echo "## Release $version" > /tmp/release_notes.md
        echo "" >> /tmp/release_notes.md
        echo "Initial release of Keycloak SSH Authentication" >> /tmp/release_notes.md
    fi
    
    echo "Release notes generated from git commits"
}

create_release() {
    local version="$1"
    
    if [ -z "$version" ]; then
        version=$(get_current_version)
    fi
    
    # Remove 'v' prefix if present
    version=${version#v}
    local tag_name="v$version"
    
    echo -e "${YELLOW}Creating GitHub release for version $version...${NC}"
    
    # Check if tag exists
    if ! git tag -l | grep -q "^$tag_name$"; then
        echo -e "${RED}Error: Git tag $tag_name does not exist${NC}"
        echo "Create the tag first with: git tag -a $tag_name -m 'Release $version'"
        exit 1
    fi
    
    # Generate release notes
    generate_release_notes "$version"
    
    # Create release
    gh release create "$tag_name" \
        --title "Release $version" \
        --notes-file /tmp/release_notes.md \
        --draft=false \
        --prerelease=false
    
    echo -e "${GREEN}✓ GitHub release $tag_name created${NC}"
    
    # Upload artifacts if they exist
    local release_dir="build/releases/$version"
    if [ -d "$release_dir" ]; then
        echo -e "${YELLOW}Uploading release artifacts...${NC}"
        
        # Upload Debian package
        if [ -f "build/packages/keycloak-ssh-auth_${version}_amd64.deb" ]; then
            gh release upload "$tag_name" "build/packages/keycloak-ssh-auth_${version}_amd64.deb"
            echo -e "${GREEN}✓ Uploaded Debian package${NC}"
        fi
        
        # Upload tarball
        if [ -f "build/releases/keycloak-ssh-auth_${version}_linux_amd64.tar.gz" ]; then
            gh release upload "$tag_name" "build/releases/keycloak-ssh-auth_${version}_linux_amd64.tar.gz"
            echo -e "${GREEN}✓ Uploaded source tarball${NC}"
        fi
    fi
    
    # Clean up
    rm -f /tmp/release_notes.md
    
    echo -e "${GREEN}✓ Release created successfully!${NC}"
    echo "View at: https://github.com/$REPO_OWNER/$REPO_NAME/releases/tag/$tag_name"
}

upload_file() {
    local tag="$1"
    local file="$2"
    
    if [ -z "$tag" ] || [ -z "$file" ]; then
        echo -e "${RED}Error: Tag and file required${NC}"
        print_usage
        exit 1
    fi
    
    if [ ! -f "$file" ]; then
        echo -e "${RED}Error: File $file does not exist${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}Uploading $file to release $tag...${NC}"
    gh release upload "$tag" "$file"
    echo -e "${GREEN}✓ File uploaded successfully${NC}"
}

list_releases() {
    echo -e "${BLUE}GitHub Releases:${NC}"
    gh release list
}

delete_release() {
    local tag="$1"
    
    if [ -z "$tag" ]; then
        echo -e "${RED}Error: Tag required${NC}"
        print_usage
        exit 1
    fi
    
    echo -e "${YELLOW}Deleting release $tag...${NC}"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        gh release delete "$tag" --yes
        echo -e "${GREEN}✓ Release deleted${NC}"
    else
        echo "Cancelled"
    fi
}

# Main script
check_prerequisites

case "$1" in
    create)
        create_release "$2"
        ;;
    upload)
        upload_file "$2" "$3"
        ;;
    list)
        list_releases
        ;;
    delete)
        delete_release "$2"
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
