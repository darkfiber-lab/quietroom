# Changelog

## [1.0.1] - 2025-12-23

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