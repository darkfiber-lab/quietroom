# Changelog

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