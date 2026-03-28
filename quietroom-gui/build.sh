#!/bin/sh

# Copyright (C) 2026 darkfiber-lab

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, version 3.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# QuietRoom GUI Build Script
# Must be run from the quietroom-gui directory
# Usage: ./build.sh [PLATFORM] or ./build.sh -all

set -e

# Color codes
if command -v tput >/dev/null 2>&1 && [ -t 1 ]; then
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    BLUE=$(tput setaf 4)
    CYAN=$(tput setaf 6)
    NC=$(tput sgr0)
else
    RED="" GREEN="" YELLOW="" BLUE="" CYAN="" NC=""
fi

VERSION="1.2.1"
BUILD_DIR="./dist"
BINARY_NAME="quietroom_client_gui"

# Platforms Wails can realistically build for
PLATFORMS="
linux-amd64
linux-arm64
darwin-amd64
darwin-arm64
windows-amd64
"

print_msg() {
    color=$1; shift
    printf "%s%s%s\n" "$color" "$@" "$NC"
}

print_help() {
    cat << EOF
${CYAN}╔════════════════════════════════════════════════════════════════╗
║           QuietRoom GUI Build Script v${VERSION}                    ║
╚════════════════════════════════════════════════════════════════╝${NC}

${GREEN}USAGE:${NC}
  ./build.sh [OPTION]

${GREEN}OPTIONS:${NC}
  ${YELLOW}-all${NC}              Build for all supported platforms
  ${YELLOW}-dev${NC}              Start Wails dev server (hot reload)
  ${YELLOW}-clean${NC}            Clean dist directory
  ${YELLOW}-help${NC}             Show this help message

${GREEN}PLATFORMS:${NC}
  ${YELLOW}linux-amd64${NC}       Linux 64-bit (Intel/AMD)
  ${YELLOW}linux-arm64${NC}       Linux 64-bit (ARM) - Raspberry Pi 4/5
  ${YELLOW}darwin-amd64${NC}      macOS Intel
  ${YELLOW}darwin-arm64${NC}      macOS Apple Silicon (M1/M2/M3/M5)
  ${YELLOW}windows-amd64${NC}     Windows 64-bit

${GREEN}EXAMPLES:${NC}
  ${CYAN}# Development mode with hot reload${NC}
  ./build.sh -dev

  ${CYAN}# Build for current platform${NC}
  ./build.sh darwin-arm64

  ${CYAN}# Build for all platforms${NC}
  ./build.sh -all

  ${CYAN}# Clean dist directory${NC}
  ./build.sh -clean

${GREEN}OUTPUT:${NC}
  Binaries are saved to: ${BLUE}${BUILD_DIR}/<platform>/${NC}

${GREEN}RUNTIME REQUIREMENTS PER PLATFORM:${NC}
  ${YELLOW}Linux${NC}     libwebkit2gtk-4.0 must be installed on target machine
            Install: sudo apt install libwebkit2gtk-4.0-dev (Debian/Ubuntu)
                     sudo dnf install webkit2gtk3 (Fedora)
  ${YELLOW}macOS${NC}     WebKit is built in — no runtime deps
  ${YELLOW}Windows${NC}   WebView2 runtime required (ships with Win11 and Win10 updates)
            Installer: https://developer.microsoft.com/en-us/microsoft-edge/webview2/

${GREEN}CROSS-COMPILATION NOTE:${NC}
  Cross-compiling GUI apps is unreliable due to native WebKit/WebView2
  dependencies. For production builds, compile natively on each target
  platform or use a CI pipeline with platform-specific runners.

${GREEN}REQUIREMENTS:${NC}
  - Go 1.21 or higher
  - Node.js 18 or higher
  - Wails v2: go install github.com/wailsapp/wails/v2/cmd/wails@latest
  - Linux only: libgtk-3-dev libwebkit2gtk-4.0-dev

EOF
}

check_deps() {
    print_msg "$CYAN" "🔍 Checking dependencies..."

    if ! command -v go >/dev/null 2>&1; then
        print_msg "$RED" "✗ Go is not installed — https://go.dev/dl/"
        exit 1
    fi
    print_msg "$GREEN" "  ✓ Go $(go version | awk '{print $3}')"

    if ! command -v node >/dev/null 2>&1; then
        print_msg "$RED" "✗ Node.js is not installed — https://nodejs.org/"
        exit 1
    fi
    print_msg "$GREEN" "  ✓ Node.js $(node --version)"

    if ! command -v wails >/dev/null 2>&1; then
        print_msg "$RED" "✗ Wails is not installed"
        print_msg "$YELLOW" "  Install: go install github.com/wailsapp/wails/v2/cmd/wails@latest"
        exit 1
    fi
    print_msg "$GREEN" "  ✓ $(wails version 2>/dev/null || echo 'Wails installed')"

    # Install frontend deps if needed
    if [ ! -d "frontend/node_modules" ]; then
        print_msg "$YELLOW" "  Installing frontend dependencies..."
        cd frontend && npm install && cd ..
        print_msg "$GREEN" "  ✓ Frontend dependencies installed"
    fi
}

clean_dist() {
    print_msg "$YELLOW" "🧹 Cleaning dist directory..."
    rm -rf "$BUILD_DIR"
    rm -rf "build/bin"
    print_msg "$GREEN" "✓ Cleaned"
}

build_platform() {
    platform=$1

    # Validate
    valid=0
    for p in $PLATFORMS; do
        [ "$p" = "$platform" ] && valid=1 && break
    done
    if [ "$valid" -eq 0 ]; then
        print_msg "$RED" "✗ Unsupported platform: $platform"
        print_msg "$YELLOW" "  Supported: linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64"
        return 1
    fi

    GOOS=$(echo "$platform" | cut -d'-' -f1)
    GOARCH=$(echo "$platform" | cut -d'-' -f2)

    print_msg "$BLUE" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$CYAN" "🔨 Building GUI for $platform (${GOOS}/${GOARCH})"

    OUT_DIR="${BUILD_DIR}/${platform}"
    mkdir -p "$OUT_DIR"

    # Wails build
    # Wails does not support cross-compilation to Linux from non-Linux hosts
    if [ "$GOOS" = "linux" ]; then
        CURRENT_OS=$(uname -s | tr '[:upper:]' '[:lower:]')
        if [ "$CURRENT_OS" != "linux" ]; then
            print_msg "$YELLOW" "  ⚠  Skipping $platform — Wails Linux builds must run on a Linux host"
            print_msg "$YELLOW" "     Use a Linux machine or CI runner for this target"
            return 0
        fi
    fi

    if GOOS=$GOOS GOARCH=$GOARCH wails build \
        -o "$BINARY_NAME" \
        -ldflags "-X main.Version=${VERSION}" \
        -platform "${GOOS}/${GOARCH}"; then

        # Locate output — Wails may or may not append extensions depending on version
        SRC=""
        DEST=""
        if [ "$GOOS" = "darwin" ]; then
            # Wails names the .app bundle from wails.json name field, not -o flag
            # Try our name first, then fall back to the wails.json app name
            if [ -d "build/bin/${BINARY_NAME}.app" ]; then
                SRC="build/bin/${BINARY_NAME}.app"
                DEST="${OUT_DIR}/${BINARY_NAME}-${platform}-v${VERSION}.app"
            elif [ -d "build/bin/QuietRoom.app" ]; then
                SRC="build/bin/QuietRoom.app"
                DEST="${OUT_DIR}/${BINARY_NAME}-${platform}-v${VERSION}.app"
            elif [ -f "build/bin/${BINARY_NAME}" ]; then
                SRC="build/bin/${BINARY_NAME}"
                DEST="${OUT_DIR}/${BINARY_NAME}-${platform}-v${VERSION}"
            fi
        elif [ "$GOOS" = "windows" ]; then
            if [ -f "build/bin/${BINARY_NAME}.exe" ]; then
                SRC="build/bin/${BINARY_NAME}.exe"
                DEST="${OUT_DIR}/${BINARY_NAME}-${platform}-v${VERSION}.exe"
            elif [ -f "build/bin/${BINARY_NAME}" ]; then
                SRC="build/bin/${BINARY_NAME}"
                DEST="${OUT_DIR}/${BINARY_NAME}-${platform}-v${VERSION}.exe"
            fi
        else
            if [ -f "build/bin/${BINARY_NAME}" ]; then
                SRC="build/bin/${BINARY_NAME}"
                DEST="${OUT_DIR}/${BINARY_NAME}-${platform}-v${VERSION}"
            fi
        fi

        if [ -z "$SRC" ]; then
            print_msg "$RED" "Binary not found in build/bin/ — contents:"
            ls -la build/bin/ 2>/dev/null || print_msg "$RED" "  build/bin/ does not exist"
            return 1
        fi

        cp -r "$SRC" "$DEST"
        SIZE=$(du -sh "$DEST" | cut -f1)
        print_msg "$GREEN" "  Built: $DEST"
        print_msg "$GREEN" "  Size: $SIZE"

        if [ "$GOOS" = "darwin" ]; then
            ZIP="${OUT_DIR}/${BINARY_NAME}-${platform}-v${VERSION}.zip"
            cd "$OUT_DIR"
            zip -qr "$(basename "$ZIP")" "$(basename "$DEST")"
            cd - >/dev/null
            print_msg "$GREEN" "  Zipped: $ZIP"
        fi
    else
        print_msg "$RED" "✗ Wails build failed for $platform"
        return 1
    fi

    print_msg "$GREEN" "✓ Done: $platform"
}

build_all() {
    print_msg "$CYAN" "╔════════════════════════════════════════════════════════════════╗"
    print_msg "$CYAN" "║         Building QuietRoom GUI for All Platforms               ║"
    print_msg "$CYAN" "╚════════════════════════════════════════════════════════════════╝"
    print_msg "$YELLOW" "⚠  Cross-compilation may fail — see -help for details"
    echo ""

    success=0; failed=0

    for platform in $PLATFORMS; do
        if build_platform "$platform"; then
            success=$(expr $success + 1)
        else
            failed=$(expr $failed + 1)
            print_msg "$YELLOW" "  Skipping $platform and continuing..."
        fi
        echo ""
    done

    print_msg "$CYAN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_msg "$GREEN" "✓ Build Summary: $success succeeded"
    [ $failed -gt 0 ] && print_msg "$RED" "  $failed failed"
    print_msg "$CYAN" "  Output: $BUILD_DIR/"
}

main() {
    # Must be run from quietroom-gui directory
    if [ ! -f "wails.json" ]; then
        print_msg "$RED" "✗ Error: must be run from the quietroom-gui directory"
        print_msg "$YELLOW" "  cd quietroom-gui && ./build.sh"
        exit 1
    fi

    if [ $# -eq 0 ]; then
        print_help
        exit 0
    fi

    case "$1" in
        -help|--help|-h)
            print_help
            exit 0
            ;;
        -clean|--clean)
            clean_dist
            exit 0
            ;;
        -dev|--dev)
            print_msg "$CYAN" "🚀 Starting Wails dev server..."
            wails dev
            exit 0
            ;;
        -all|--all)
            check_deps
            clean_dist
            build_all
            exit 0
            ;;
        *)
            check_deps
            mkdir -p "$BUILD_DIR"
            build_platform "$1"
            exit 0
            ;;
    esac
}

main "$@"