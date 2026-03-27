# Changelog
[1.2.0] - 2026-03-23

### Added

GUI client (quietroom-gui/) — native desktop application built with Go and Wails, targeting macOS, Windows and Linux. Features a dark-themed interface with sidebar channel navigation, multi-room support, DM threads, file transfer UI with progress bar and hash verification, server profiles, settings panel, and sound notifications
Multi-room architecture — clients can now join multiple rooms simultaneously and receive messages from all of them without leaving. Messages are routed via a [#roomname] prefix in the message body rather than server-side currentRoom tracking, allowing the GUI to switch between channels without generating join/leave noise
Room message prefix — server now includes [#roomname] in broadcasts from rooms, enabling clients to correctly route incoming messages to the right channel regardless of which channel is currently viewed
/members command — returns the member list for a specific room or the lobby. Password-protected rooms return access denied to non-members without confirming the room exists. Usage: /members #roomname or /members lobby
Updated /users command — now returns all connected users globally regardless of which room they are in, rather than only users in the current context
Idle connection detection — server now closes stale connections after 3 minutes of inactivity using an application-level idle checker, preventing hung usernames after ungraceful network disconnections
GUI server profiles — connection settings (host, port, username, certificate path) can be saved as named profiles and selected from a dropdown on the login screen
GUI autocomplete — Join Room and New DM dialogs fetch live room and user lists from the server when opened and offer autocomplete suggestions as you type
Python connector updates — quietroom_connector.py updated to support the new routing protocol with send_room_message(), on_room_message(), on_system_message(), list_users(), list_members(), list_rooms(), joined_rooms property, and automatic keepalive when decoy traffic is disabled
GitHub Actions workflows — CI/CD pipelines for building server, CLI client, and GUI client across all supported platforms on tag push or manual trigger
GUI build script (quietroom-gui/build.sh) — standalone build script for the GUI with platform detection, dependency checking, and automatic zip packaging for macOS distribution

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