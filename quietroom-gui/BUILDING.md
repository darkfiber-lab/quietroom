# Building QuietRoom GUI

This document covers how to set up a local development environment, run the app in development mode, and produce release builds for macOS, Windows, and Linux.

---

## Prerequisites

### Go

Version 1.21 or higher is required.

```bash
# macOS
brew install go

# Linux (Debian/Ubuntu)
sudo apt install golang-go

# Windows
# Download the installer from https://go.dev/dl/
```

Verify:

```bash
go version
```

### Node.js

Version 18 or higher is required by Wails at build time. It is not required at runtime.

```bash
# macOS
brew install node

# Linux
sudo apt install nodejs npm

# Windows
# Download from https://nodejs.org/
```

Verify:

```bash
node --version
npm --version
```

### Wails

```bash
go install github.com/wailsapp/wails/v2/cmd/wails@latest
```

Make sure `~/go/bin` is in your `PATH`:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

Add this to `~/.zshrc` or `~/.bashrc` to make it permanent.

Verify the installation:

```bash
wails doctor
```

This checks all dependencies and reports any missing system libraries.

### Linux only — system libraries

On Linux the Wails runtime depends on GTK3 and WebKit2GTK. Install them before building:

```bash
# Debian / Ubuntu
sudo apt install libgtk-3-dev libwebkit2gtk-4.0-dev

# Fedora
sudo dnf install gtk3-devel webkit2gtk3-devel

# Arch
sudo pacman -S gtk3 webkit2gtk
```

---

## Project structure

```
quietroom-gui/
├── main.go                  # Wails entry point
├── app.go                   # Go bindings exposed to the frontend
├── wails.json               # Wails project configuration
├── go.mod                   # Go module definition
├── build.sh                 # Build script
├── protocol/
│   ├── client.go            # TLS, DH key exchange, AES-GCM, packet framing
│   ├── messages.go          # Server message parsing and event dispatching
│   └── filetransfer.go      # File transfer state machine
└── frontend/
    ├── index.html           # Application shell
    ├── package.json         # Frontend dependencies
    ├── vite.config.js       # Vite build configuration
    ├── src/
    │   ├── main.js          # Entry point
    │   ├── app.js           # Main app controller, Wails event wiring
    │   ├── chat.js          # Message rendering, channel management
    │   ├── filetransfer.js  # File transfer UI
    │   └── settings.js      # Settings modal, profile management
    └── styles/
        └── main.css         # Full application stylesheet
```

---

## Development mode

Development mode runs the app with hot reload — changes to frontend files are reflected immediately without rebuilding. Go code changes require a restart.

```bash
cd quietroom-gui
wails dev
```

Or using the build script:

```bash
./build.sh -dev
```

The application window opens automatically. The Wails dev server also serves the frontend at `http://localhost:34115` which you can open in a browser for debugging, though some Go bindings won't be available outside the native window.

### Opening dev tools

Right-click anywhere in the app window and select **Inspect** to open the browser dev tools, or add this to `main.go` in the `options.App` struct to open them automatically on launch:

```go
Debug: options.Debug{
    OpenInspectorOnStartup: true,
},
```

---

## Installing frontend dependencies

If `frontend/node_modules` doesn't exist yet, install dependencies manually:

```bash
cd frontend
npm install
cd ..
```

The build script does this automatically if the directory is missing.

---

## Production builds

### Using the build script

The build script handles dependency checks, cleaning, and copying the output binary to the `dist/` directory.

```bash
cd quietroom-gui

# Build for your current platform
./build.sh darwin-arm64

# Build for all supported platforms
./build.sh -all

# Clean the dist directory
./build.sh -clean
```

### Supported platforms

| Platform | Notes |
|---|---|
| `darwin-arm64` | macOS Apple Silicon (M1/M2/M3/M5) |
| `darwin-amd64` | macOS Intel |
| `windows-amd64` | Windows 64-bit |
| `linux-amd64` | Must be built on a Linux host |
| `linux-arm64` | Must be built on a Linux host |

### Using Wails directly

```bash
# Build for the current platform
wails build

# Build for a specific platform
GOOS=darwin GOARCH=arm64 wails build -platform darwin/arm64

# Build with version info
wails build -ldflags "-X main.Version=1.2.1"
```

Wails places the output in `build/bin/`:

- **macOS** — `build/bin/QuietRoom.app` (the app bundle)
- **Windows** — `build/bin/quietroom_client_gui.exe`
- **Linux** — `build/bin/quietroom_client_gui`

---

## Output

The build script copies completed binaries to `dist/<platform>/` with version-stamped names:

```
dist/
  darwin-arm64/
    quietroom_client_gui-darwin-arm64-v1.2.1.app
    quietroom_client_gui-darwin-arm64-v1.2.1.zip   ← macOS zip for distribution
  windows-amd64/
    quietroom_client_gui-windows-amd64-v1.2.1.exe
  linux-amd64/
    quietroom_client_gui-linux-amd64-v1.2.1
```

---

## Cross-compilation notes

### macOS → Windows

Cross-compiling to Windows from macOS works with Wails as it uses the Go WebView2 bootstrap which doesn't require native libraries at build time. The resulting `.exe` requires WebView2 runtime on the target machine — this ships automatically with Windows 11 and recent Windows 10 updates.

### macOS → Linux

Wails does not support cross-compilation to Linux from non-Linux hosts. Linux builds must be performed natively on a Linux machine. For CI pipelines, use a Linux runner for Linux targets.

### macOS → macOS (Intel from Apple Silicon)

Building for `darwin-amd64` from an Apple Silicon Mac works natively via Rosetta and Go's cross-compilation support.

---

## Runtime requirements per platform

### macOS
No additional runtime dependencies. WebKit is built into macOS.

### Windows
WebView2 runtime is required. It ships with Windows 11 and Windows 10 version 1803 and later via Windows Update. For older systems or offline deployment, the WebView2 bootstrapper can be bundled:
```
https://developer.microsoft.com/en-us/microsoft-edge/webview2/
```

### Linux
The following libraries must be present on the target machine:

```bash
# Debian / Ubuntu
sudo apt install libwebkit2gtk-4.0

# Fedora
sudo dnf install webkit2gtk3

# Arch
sudo pacman -S webkit2gtk
```

---

## Versioning

The version string is injected at build time via ldflags. To update the version, edit the `VERSION` variable at the top of `build.sh`:

```sh
VERSION="1.2.1"
```

Or pass it directly to Wails:

```bash
wails build -ldflags "-X main.Version=1.2.1"
```

---

## Troubleshooting

**`wails: command not found`**
Add `$(go env GOPATH)/bin` to your PATH — see the Wails installation section above.

**`wails doctor` reports missing dependencies on Linux**
Install the GTK and WebKit development libraries listed in the Linux prerequisites section.

**Frontend changes not reflecting in dev mode**
Check the Vite dev server is running — Wails dev starts it automatically but it can fail if Node.js is not found. Run `cd frontend && npm run dev` manually to see the error.

**`go mod tidy` fails**
Make sure you have network access and that the Go module proxy is reachable. If working offline, ensure all dependencies are already in the module cache.

**Build succeeds but window doesn't open on Linux**
Ensure `libwebkit2gtk-4.0` is installed on the runtime machine, not just the build machine.
