# Changelog

## [Unreleased]

### Added
- **OpenSSF Best Practices badge** — QuietRoom meets the "passing" level and Baseline level 1; the badge is shown in the README. The README's contribution guidelines now state the pull-request process and that new functionality comes with tests.
- **Container deployment examples** in `deploy/`: a rootless Podman Quadlet unit run by an unprivileged `quietroom` system user (nothing runs as root; private user namespace, host network, read-only, no capabilities, resource limits, started at boot), a rootful variant for cgroup v1 hosts in `deploy/rootful/`, and an nftables egress guard that blocks every outbound connection from the server's user and keeps the service user away from cloud metadata services. Documented in SERVER_README.MD, "Running in a container"; the DOCKERFILE comments now cover Docker and Podman.

### ⚠ Changed
- **Container image runs as uid/gid 65532** instead of 1000. On most Linux hosts 1000 is the first login user, so a process escaping the container would have been that user; 65532 belongs to no account. Existing data volumes must be given to 65532 before upgrading (`chown -R 65532:65532` on the volume, or Podman's `:U` mount option); see SERVER_README.MD, "Running in a container".
- **No generated files in the repository** — the built GUI frontend (`quietroom-gui/frontend/dist/`, a minified bundle produced by Vite) is no longer committed; `wails build` and `wails dev` generate it. Only an empty `dist/.gitkeep` remains, so the GUI's Go code compiles on a fresh clone; the Vite config puts it back after each build. Stray `.DS_Store` files and Wails' `package.json.md5` are gone and ignored.

### Security
- **Dependency minimums raised** past versions with known vulnerabilities reported by OpenSSF Scorecard: the LLM bot now requires `requests` 2.33.0 or newer (netrc credential leak, TLS verification bypass in sessions, path handling in zipped files); the GUI uses `golang.org/x/net` 0.63.0, `golang.org/x/crypto` 0.59.0 and a fixed `gorilla/websocket` (weak random WebSocket mask key). The Go modules come in through Wails; the `govulncheck` scan in CI reports none of the affected code as reachable from QuietRoom.

---

## [3.1.0] - 2026-11-24

Compatible with 3.0 servers and clients (protocol 3). Update the server first: from 3.1 on, usernames with spaces are refused and names are unique regardless of case (see Changed).

### Added
- **CLI line mode** — without an interactive terminal (Plan 9, which has no raw mode, or with input or output redirected) the CLI reads plain lines and prints messages as they arrive instead of failing with "Failed to set raw terminal mode"; colours are off there and whenever `NO_COLOR` is set
- **CLI line editing** — cursor movement by character and word, Home/End, Delete, Ctrl+W/U/K, history of sent lines with ↑/↓, Ctrl+L to redraw; on Windows the classic console gets escape-sequence support enabled
- **LLM bot** — `ollama.think` setting for reasoning models: `false` (default, as before) answers directly, `true` lets the model reason first, `null` uses the model's default

### ⚠ Changed
- **Usernames** — spaces are no longer allowed (`bob smith` → `bob_smith`), and names are unique regardless of case: while `Alice` is online, nobody can join as `alice`. Members can be addressed in any case (`/msg alice` reaches `Alice`); lists and messages show each member's own spelling. Saved profiles with a space in the name must be changed.
- **Received files with a wrong hash are discarded** — if the data does not match the SHA-256 the sender announced, the file is deleted and the transfer reported as failed, instead of being saved with a warning

### Security
- **Hidden characters removed** — bidi controls (which can disguise `invoice‮gpj.exe` as `invoiceexe.jpg`) and zero-width characters are removed from chat text, DMs and file names by the server, and again by the clients. File names also lose all other Unicode format characters and C1 controls; emoji joiners are kept in text.

### Fixed
- **CLI input line** — editing a line long enough to wrap (for example with Backspace) printed the whole message again, and messages arriving while such a line was being typed left copies of it behind. The CLI now has a proper line editor (`lineedit/`) that tracks how many rows the input occupies, including wide characters and the terminal's deferred wrap at the last column. Arrow keys no longer insert `[A`, `[D` and similar text; transfer progress has its own line above the prompt instead of overwriting the input; multi-line messages keep their line breaks.
- **GUI notifications** — they were sent through scripting tools and came from the wrong application: Script Editor on macOS (a click opened Script Editor), Windows PowerShell on Windows (a PowerShell script was written to the temporary folder and run for every notification), and an unnamed sender without icon on Linux. They now use each system's notification service and come from QuietRoom, with its icon; a click brings QuietRoom forward and opens the conversation.
  - macOS: Wails (`UNUserNotificationCenter`); permission is asked once; bundle identifier `com.darkfiber-lab.quietroom` (was `com.wails.QuietRoom`)
  - Windows: Wails toast notifications, shown as "QuietRoom" rather than the executable's file name; registry entries left by older QuietRoom versions are removed
  - Linux: the freedesktop notification service on D-Bus directly (`internal/linuxnotify`), with app name, icon and the instant-message category; the window now has QuietRoom's icon too
  - The `beeep` library and its PowerShell, AppleScript and system-tray code are gone. If notifications cannot be shown, the chat says why once.
  - Notifications name the sender (and room), never message text or file names.
- **Server documentation** — `SERVER_README.MD` showed outdated build commands (`chat_server` from `server.go`); it now explains downloading and verifying a release or building `quietroom_server.go`, and the systemd example uses the right names
- **GUI sources** — `frontend/wailsjs/go/models.ts` has its license header again; a Wails post-build hook restores it after every build, and a test fails if it is missing. The Wails runtime bindings in the repository match Wails v2.13.0 again (the 3.0.0 release commit had reverted them; release binaries were not affected, as builds regenerate them)

---

## [3.0.0] - 2026-11-24

### ⚠ Breaking
- **Protocol 3** — the wire protocol was rebuilt. 3.x servers and clients do not talk to 2.x: update the server, the CLI and GUI clients and the Python connector together. The access file format is unchanged (the server certificate now uses ECDSA P-256 instead of RSA-4096); as always, the restart issues a new `quietroom_access.pem`.

### Added
- **Fast, reliable file transfers** — files of any size, with credit-based flow control (no fixed pauses), several transfers at once in each direction, and `/cancel <id>`. Chat stays responsive during transfers (chat is always sent before file data). Received data goes to a hidden `.part` file that is removed if a transfer fails. Locally a 200 MB file transfers in under a second.
- **Receive limit** — clients decline files above a configurable size (`max_receive_mb`, default 8 GB)
- **Room limits** — `max_rooms` (default 200) and `max_rooms_per_member` (default 20); empty rooms are removed
- **Message rate limit** — about 20 messages per second per member (bursts up to 60); flooding members are told and their excess messages dropped
- **Shared client library** — `client/` implements the protocol once for the CLI and the GUI
- **Tests** — protocol unit tests and fuzzing (`wire/`); integration tests with a real server, the client library, the CLI in a pseudo-terminal and the Python connector (`tests/integration/`); GUI backend tests (`quietroom-gui/app_test.go`); attack tests with hostile clients (`tests/attack/`): missing, forged and stale access keys, malformed frames, spoofed fields, hostile names, flow-control abuse, floods, reconnect races, slow readers, and a check that logs contain no member metadata. All run in CI with the race detector.
- **Silent to strangers** — the server no longer shows its certificate (or anything else) to connections without the access file. Clients send a one-time gate token, derived from the access key and the current time, in the TLS server name; without a valid token the server closes the connection without a reply. Scanners and `openssl s_client` see a closed connection. Client clocks must be within 5 minutes of the server's.
- **Python connector** — `on_presence` callback for members joining and leaving
- **LLM bot limits** — one request per user at a time, at most `max_concurrent_requests` (default 2) overall, and `max_requests_per_minute` (default 6) per user; backend errors no longer reveal the backend address to users; the README warns that `base_url` receives all prompts
- **Security policy** — `SECURITY.md`; vulnerabilities can be reported privately via GitHub's "Report a vulnerability"

### Changed
- **Framing** — every frame states its exact length (`| length | type | flags | padding length | payload | padding |`). The receiver never guesses where a frame ends, which removes the stream desynchronisation behind the old instability. Frames are padded to size classes (256 B … 64 KB) instead of 0–255 random bytes.
- **Typed messages** — control messages are JSON with explicit types; the server sets sender names and timestamps itself, so message text can no longer be mistaken for commands or system notices, and members cannot impersonate each other
- **Transfer IDs** — random 128-bit IDs instead of `sender_recipient_timestamp`
- **Decoys** — sent at random intervals (0.5–1.5 × the configured interval) instead of a fixed rhythm
- **Encryption** — the inner Diffie-Hellman + AES-GCM layer was removed: it protected the same two endpoints as TLS 1.3, which already provides forward secrecy. The server key is ECDSA P-256 (faster start and handshakes).
- **Slow members** — a member that stops reading is disconnected once its queue is full or a write times out (30 s), instead of silently losing messages
- **CLI** — asks for the username before connecting (and again if it is taken); the prompt shows the current room; no more local echo (your messages are shown as the server delivered them); UTF-8 input
- **Python connector** — no longer needs the `cryptography` package; file offers are declined automatically
- **Docker image** — the final image is built `FROM scratch` and contains only the static server binary (no OS packages, no shell); the preparation stage's base image is pinned by digest
- **Dependencies** — `golang.org/x/crypto` removed from the server and CLI: room passwords are hashed with PBKDF2-HMAC-SHA256 (600,000 iterations, random salt) from the Go standard library instead of bcrypt, and at most two hashes run at once. Remaining dependency: `golang.org/x/term` v0.47.0 (CLI input). Minimum Go version 1.26
- **LLM bot logging** — the log never contains message text, and contains no usernames unless `log_metadata` is enabled
- **GUI wording** — the connect screen says "Encrypted in transit · Access key only · Messages never stored" instead of "End-to-end encrypted": the server relays messages (by design), so end-to-end was not accurate
- **CI** — all GitHub Actions pinned to commit SHAs; workflow inputs passed via environment variables; checkouts no longer persist credentials; releases are published with the GitHub CLI instead of a third-party action; Wails CLI pinned to v2.13.0; `npm ci` instead of `npm install`; `go mod download` + `go mod verify` instead of `go mod tidy` during builds

### Fixed
- **Room passwords longer than 72 bytes** — bcrypt rejected them ("Error creating room password"); the full 256 bytes now work
- **File transfers** — `/decline` by a member who is not the recipient no longer cancels the transfer
- **Stream desynchronisation** — padding without a length field could swallow or leave behind bytes (for example when a decoy arrived within 10 ms, or TLS split a packet), corrupting every following message

---

## [2.1.1] - 2026-11-22

### Added
- **Security scanning in CI** — govulncheck (server, CLI client, GUI), Trivy (Docker image), zizmor (workflows) and OpenSSF Scorecard run on pushes, pull requests and weekly; results go to GitHub code scanning

### Changed
- **Build toolchain** — CLI, server and GUI builds use the latest Go 1.26 patch release (`GOTOOLCHAIN=local`) instead of the minimum Go version declared in `go.mod`
- **Docker image** — based on Alpine 3.24 without extra packages; the server binary now lives in `/usr/local/bin` (outside the data volume) so rebuilding the image updates the server; the health check was removed; the file documents a hardened `docker run` command (read-only filesystem, no capabilities, resource and log limits)

---

## [2.1.0] - 2026-11-22

### Added
- **Release verification** — every release includes `SHA256SUMS.txt` and a signed build provenance attestation (`gh attestation verify`); see "Verifying Downloads" in the README

### Changed
- **Logging** — participant metadata (joins/leaves, successful logins, DMs, file transfers, member IP addresses) is no longer logged by default, including server console output. New `log_metadata` setting (default `false`) re-enables it for debugging. Rejected connections are still logged with their IP address
- **Server certificate** — the server certificate now carries a random name per run instead of a fixed descriptive name
- **CI** — release workflow runs with read-only token permissions by default; only the job that publishes the release gets write access

---

## [2.0.0] - 2026-11-22

**Breaking:** clients now need the new `quietroom_access.pem`, which the server generates on every start. The server and all clients (CLI, GUI, Python connector) must be updated together; 1.x clients cannot connect to a 2.0 server.

### Added
- **Connection limits** — new `max_connections`, `max_connections_per_ip` and `max_new_connections_per_ip_per_minute` settings (defaults 100 / 10 / 30); connections over the limits are closed before the TLS handshake and summarised in the security log once a minute
- **GUI content security policy** — the GUI frontend runs with a restrictive CSP; inline event handlers were replaced with script listeners

### Changed
- **Room names** — must be `#` followed by 1–32 letters, digits, `_`, `-` or `.`
- **GUI file sending** — files can only be sent after choosing them in the native file picker
- **GUI links** — links in messages open in the system browser
- **GUI rendering** — room names, usernames and other server-provided text are always rendered as plain text
- **Server stability** — reworked client message queues and added a per-connection recovery handler so a problem with one connection cannot stop the server
- **Dependencies** — vite 8.1.6, nanoid 3.3.20 (frontend build tooling)
- **Access file** — the server now generates `quietroom_access.pem` on every start, replacing `chat_public.pem`. It contains the server certificate and a master access key that clients present during the TLS handshake (mutual TLS). The file is secret and must be distributed to participants only; a server restart issues a new file and invalidates the previous one
- **Clients** — CLI, GUI and the Python connector read `quietroom_access.pem` and show clear messages for an outdated or incomplete access file
- **Server key** — the server private key is kept in memory only and is no longer written to disk
- **Connection handling** — the initial handshake now has a timeout, and connection setup is more robust
- **Log files** — log files are created with owner-only permissions; existing log files are corrected on start
- **CI** — GUI build workflow runs with read-only token permissions

### Fixed
- **Room switching** — CLI and GUI switch to a room only after the server confirms the join; a refused join (invalid name or wrong password) no longer sends later messages to that room

---

[1.2.1] - 2026-03-28

- Updated .gitignore to upload icon files for the build

[1.2.0] - 2026-03-23

### Added

- **GUI client (quietroom-gui/)** — native desktop application built with Go and Wails, targeting macOS, Windows and Linux. Features a dark-themed interface with sidebar channel navigation, multi-room support, DM threads, file transfer UI with progress bar and hash verification, server profiles, settings panel, and sound notifications
- **Multi-room architecture** — clients can now join multiple rooms simultaneously and receive messages from all of them without leaving. Messages are routed via a [#roomname] prefix in the message body rather than server-side currentRoom tracking, allowing the GUI to switch between channels without generating join/leave noise
- **Room message prefix** — server now includes [#roomname] in broadcasts from rooms, enabling clients to correctly route incoming messages to the right channel regardless of which channel is currently viewed
- **/members command** — returns the member list for a specific room or the lobby. Password-protected rooms return access denied to non-members without confirming the room exists. Usage: /members #roomname or /members lobby
- **Updated /users command** — now returns all connected users globally regardless of which room they are in, rather than only users in the current context
- **Idle connection detection** — server now closes stale connections after 3 minutes of inactivity using an application-level idle checker, preventing hung usernames after ungraceful network disconnections
- **GUI server profiles** — connection settings (host, port, username, certificate path) can be saved as named profiles and selected from a dropdown on the login screen
- **GUI autocomplete** — Join Room and New DM dialogs fetch live room and user lists from the server when opened and offer autocomplete suggestions as you type
- **Python connector updates** — quietroom_connector.py updated to support the new routing protocol with send_room_message(), on_room_message(), on_system_message(), list_users(), list_members(), list_rooms(), joined_rooms property, and automatic keepalive when decoy traffic is disabled
- **GitHub Actions workflows** — CI/CD pipelines for building server, CLI client, and GUI client across all supported platforms on tag push or manual trigger
- **GUI build script** (quietroom-gui/build.sh) — standalone build script for the GUI with platform detection, dependency checking, and automatic zip packaging for macOS distribution

## [1.1.0] - 2026-02-28

### Added
- **QuietRoom Connector (`quietroom_connector.py`)** — a standalone Python library that implements the full QuietRoom protocol stack (TLS, Diffie-Hellman key exchange, AES-256-GCM, obfuscated packet framing) and exposes a clean callback-based interface for building automated clients; the connector maintains a persistent connection and registered username on the server for the lifetime of the process, supports `on_dm`, `on_message`, and `on_disconnect` callbacks, and provides thread-safe `send_dm`, `send_message`, `join_room`, and `leave_room` methods
- **LLM Bot (`quietroom_llm_bot.py`)** — a Python client built on top of the connector that routes incoming direct messages to a locally running language model; supports Ollama and any OpenAI-compatible inference server (LM Studio, vLLM, LocalAI, etc.) as pluggable backends, maintains per-sender conversation history with configurable depth and TTL-based expiry, splits long responses into multiple DMs automatically, and purges conversation history when a user disconnects from the server to prevent context leaking to a subsequent user who registers the same username


## [1.0.1] - 2026-02-27

### Security
- **Fixed critical small subgroup attack** — DH public keys are now validated to be within the range `(1, P-1)` on both client and server before the shared secret is computed; previously a malicious peer could force the session key to a known constant
- **Fixed arbitrary file read via `BEGIN_SEND`** — client now ignores the server-supplied file path entirely and only uses the path stored locally when the user issued the `/file` command; previously a malicious server could trigger transmission of any file readable by the client process
- **Fixed world-readable sensitive files** — `server_private.pem`, `chat_server.log`, and `security.log` are now created with `0600` permissions instead of `0644`
- **Fixed username race condition** — username uniqueness is now checked and registered atomically under the server lock before the join event is dispatched, preventing two clients from claiming the same username simultaneously

### Stability
- **Fixed data race on `client.rooms`** — all reads and writes to the rooms map are now consistently wrapped in `client.mu`, which was already present but not applied to this field
- **Fixed silent file size parse failures** — replaced `fmt.Sscanf` with `strconv.ParseInt` and explicit error handling in both client and server file transfer paths; malformed sizes now cancel the transfer rather than proceeding with a zero value
- **Fixed hanging prompt on server-initiated disconnect** — the reader goroutine now closes the shutdown channel when the connection is lost, causing the main loop to exit cleanly to the terminal instead of leaving the prompt active
- **Fixed potential double-close panic on shutdown** — all `close(client.shutdown)` call sites are now guarded with `sync.Once` to prevent a panic if the signal handler and the reader goroutine trigger shutdown concurrently
