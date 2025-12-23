#!/bin/sh

# Copyright (C) 2025 darkfiber-lab

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, version 3.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

# QuietRoom Build Script
# Builds server and client binaries for multiple platforms
# Usage: ./build.sh [PLATFORM] or ./build.sh -all

set -e  # Exit on error

# Color codes using tput for better compatibility
if command -v tput >/dev/null 2>&1 && [ -t 1 ]; then
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    BLUE=$(tput setaf 4)
    CYAN=$(tput setaf 6)
    NC=$(tput sgr0)
else
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    CYAN=""
    NC=""
fi

# Build configuration
VERSION="1.0.0"
BUILD_DIR="./build"
SERVER_SRC="quietroom_server.go"
CLIENT_SRC="quietroom_client.go"

# Supported platforms
PLATFORMS="
linux-amd64
linux-arm64
linux-arm
darwin-amd64
darwin-arm64
windows-amd64
windows-arm64
freebsd-amd64
openbsd-amd64
"

# Print colored message
print_msg() {
    color=$1
    shift
    printf "%s%s%s\n" "$color" "$@" "$NC"
}

# Print help message
print_help() {
    cat << EOF
${CYAN}╔════════════════════════════════════════════════════════════════╗
║                  QuietRoom Build Script v${VERSION}                  ║
╚════════════════════════════════════════════════════════════════╝${NC}

${GREEN}USAGE:${NC}
  ./build.sh [OPTION]

${GREEN}OPTIONS:${NC}
  ${YELLOW}-all${NC}              Build for all supported platforms
  ${YELLOW}-docker${NC}           Build Docker image for linux/amd64
  ${YELLOW}-docker-multi${NC}     Build multi-arch Docker images (amd64, arm64)
  ${YELLOW}-clean${NC}            Clean build directory
  ${YELLOW}-help${NC}             Show this help message

${GREEN}PLATFORMS:${NC}
  ${YELLOW}linux-amd64${NC}       Linux 64-bit (Intel/AMD)
  ${YELLOW}linux-arm64${NC}       Linux 64-bit (ARM) - Raspberry Pi 4/5, AWS Graviton
  ${YELLOW}linux-arm${NC}         Linux 32-bit (ARM) - Raspberry Pi 2/3
  ${YELLOW}darwin-amd64${NC}      macOS Intel
  ${YELLOW}darwin-arm64${NC}      macOS Apple Silicon (M1/M2/M3)
  ${YELLOW}windows-amd64${NC}     Windows 64-bit
  ${YELLOW}windows-arm64${NC}     Windows ARM64
  ${YELLOW}freebsd-amd64${NC}     FreeBSD 64-bit
  ${YELLOW}openbsd-amd64${NC}     OpenBSD 64-bit

${GREEN}EXAMPLES:${NC}
  ${CYAN}# Build for Linux 64-bit${NC}
  ./build.sh linux-amd64

  ${CYAN}# Build for macOS Apple Silicon${NC}
  ./build.sh darwin-arm64

  ${CYAN}# Build for all platforms${NC}
  ./build.sh -all

  ${CYAN}# Build Docker image${NC}
  ./build.sh -docker

  ${CYAN}# Clean build directory${NC}
  ./build.sh -clean

${GREEN}OUTPUT:${NC}
  Binaries are saved to: ${BLUE}${BUILD_DIR}/<platform>/${NC}

${GREEN}REQUIREMENTS:${NC}
  - Go 1.16 or higher
  - Docker (for Docker builds)

EOF
}

# Clean build directory
clean_build() {
    print_msg "$YELLOW" "🧹 Cleaning build directory..."
    rm -rf "$BUILD_DIR"
    print_msg "$GREEN" "✓ Build directory cleaned"
}

# Check if Go is installed
check_go() {
    if ! command -v go >/dev/null 2>&1; then
        print_msg "$RED" "✗ Error: Go is not installed"
        print_msg "$YELLOW" "  Please install Go from https://golang.org/dl/"
        exit 1
    fi
    
    GO_VERSION=$(go version | awk '{print $3}')
    print_msg "$CYAN" "📦 Using Go version: $GO_VERSION"
}

# Install dependencies from go.mod
install_deps() {
    print_msg "$YELLOW" "📦 Installing dependencies..."
    if go mod tidy && go mod download; then
        print_msg "$GREEN" "✓ Dependencies installed"
    else
        print_msg "$RED" "✗ Failed to install dependencies"
        exit 1
    fi
}

# Build for a specific platform
build_platform() {
    platform=$1
    
    # Validate platform
    valid=0
    for p in $PLATFORMS; do
        if [ "$p" = "$platform" ]; then
            valid=1
            break
        fi
    done
    if [ "$valid" -eq 0 ]; then
        print_msg "$RED" "✗ Unknown platform: $platform"
        return 1
    fi
    
    # Derive GOOS and GOARCH from platform
    GOOS=$(echo "$platform" | cut -d'-' -f1)
    GOARCH=$(echo "$platform" | cut -d'-' -f2)
    
    print_msg "$BLUE" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$CYAN" "🔨 Building for $platform (${GOOS}/${GOARCH})"
    
    # Create output directory
    OUT_DIR="${BUILD_DIR}/${platform}"
    mkdir -p "$OUT_DIR"
    
    # Set binary extensions
    SERVER_BIN="chat_server"
    CLIENT_BIN="chat_client"
    if [ "$GOOS" = "windows" ]; then
        SERVER_BIN="${SERVER_BIN}.exe"
        CLIENT_BIN="${CLIENT_BIN}.exe"
    fi
    
    # Build server
    print_msg "$YELLOW" "   Building server..."
    if CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build \
        -ldflags="-w -s -X main.Version=${VERSION}" \
        -o "${OUT_DIR}/${SERVER_BIN}" \
        "$SERVER_SRC"; then
        print_msg "$GREEN" "   ✓ Server built: ${OUT_DIR}/${SERVER_BIN}"
    else
        print_msg "$RED" "   ✗ Server build failed"
        return 1
    fi
    
    # Build client
    print_msg "$YELLOW" "   Building client..."
    if CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build \
        -ldflags="-w -s -X main.Version=${VERSION}" \
        -o "${OUT_DIR}/${CLIENT_BIN}" \
        "$CLIENT_SRC"; then
        print_msg "$GREEN" "   ✓ Client built: ${OUT_DIR}/${CLIENT_BIN}"
    else
        print_msg "$RED" "   ✗ Client build failed"
        return 1
    fi
    
    # Get binary sizes
    SERVER_SIZE=$(du -h "${OUT_DIR}/${SERVER_BIN}" | cut -f1)
    CLIENT_SIZE=$(du -h "${OUT_DIR}/${CLIENT_BIN}" | cut -f1)
    
    print_msg "$GREEN" "   📊 Server size: ${SERVER_SIZE}"
    print_msg "$GREEN" "   📊 Client size: ${CLIENT_SIZE}"
    print_msg "$GREEN" "✓ Build complete for $platform"
}

# Build all platforms
build_all() {
    print_msg "$CYAN" "╔════════════════════════════════════════════════════════════════╗"
    print_msg "$CYAN" "║          Building QuietRoom for All Platforms                 ║"
    print_msg "$CYAN" "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    
    success=0
    failed=0
    
    for platform in $PLATFORMS; do
        if build_platform "$platform"; then
            success=$(expr $success + 1)
        else
            failed=$(expr $failed + 1)
        fi
        echo ""
    done
    
    print_msg "$CYAN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$GREEN" "✓ Build Summary:"
    print_msg "$GREEN" "  Successful: $success"
    if [ $failed -gt 0 ]; then
        print_msg "$RED" "  Failed: $failed"
    fi
    print_msg "$CYAN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Build Docker image
build_docker() {
    print_msg "$CYAN" "🐳 Building Docker image for linux/amd64..."
    
    if ! command -v docker >/dev/null 2>&1; then
        print_msg "$RED" "✗ Error: Docker is not installed"
        exit 1
    fi
    
    docker build \
        --build-arg TARGETOS=linux \
        --build-arg TARGETARCH=amd64 \
        -t quietroom/server:latest \
        -t quietroom/server:${VERSION} \
        .
    
    print_msg "$GREEN" "✓ Docker image built: quietroom/server:latest"
    print_msg "$CYAN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$YELLOW" "To run the server:"
    print_msg "$CYAN" "  docker-compose up -d"
    print_msg "$YELLOW" "Or manually:"
    print_msg "$CYAN" "  docker run -d -p 37842:37842 -v \$(pwd)/logs:/app/logs quietroom/server:latest"
}

# Build multi-architecture Docker images
build_docker_multi() {
    print_msg "$CYAN" "🐳 Building multi-arch Docker images (amd64, arm64)..."
    
    if ! command -v docker >/dev/null 2>&1; then
        print_msg "$RED" "✗ Error: Docker is not installed"
        exit 1
    fi
    
    # Check if buildx is available
    if ! docker buildx version >/dev/null 2>&1; then
        print_msg "$RED" "✗ Error: Docker buildx is not available"
        print_msg "$YELLOW" "  Install with: docker buildx install"
        exit 1
    fi
    
    # Create builder instance if not exists
    docker buildx create --name quietroom-builder --use 2>/dev/null || true
    
    print_msg "$YELLOW" "Building for platforms: linux/amd64, linux/arm64..."
    
    docker buildx build \
        --platform linux/amd64,linux/arm64 \
        -t quietroom/server:latest \
        -t quietroom/server:${VERSION} \
        --push \
        .
    
    print_msg "$GREEN" "✓ Multi-arch Docker images built and pushed"
}

# Main script logic
main() {
    # No arguments - show help
    if [ $# -eq 0 ]; then
        print_help
        exit 0
    fi
    
    # Parse arguments
    case "$1" in
        -help|--help|-h)
            print_help
            exit 0
            ;;
        -clean|--clean)
            clean_build
            exit 0
            ;;
        -all|--all)
            check_go
            install_deps
            clean_build
            build_all
            exit 0
            ;;
        -docker|--docker)
            check_go
            install_deps
            build_docker
            exit 0
            ;;
        -docker-multi|--docker-multi)
            check_go
            install_deps
            build_docker_multi
            exit 0
            ;;
        *)
            # Try to build specific platform
            valid=0
            for p in $PLATFORMS; do
                if [ "$p" = "$1" ]; then
                    valid=1
                    break
                fi
            done
            if [ "$valid" -eq 1 ]; then
                check_go
                install_deps
                mkdir -p "$BUILD_DIR"
                build_platform "$1"
            else
                print_msg "$RED" "✗ Unknown option or platform: $1"
                echo ""
                print_msg "$YELLOW" "Run './build.sh -help' to see available options"
                exit 1
            fi
            ;;
    esac
}

# Run main function
main "$@"