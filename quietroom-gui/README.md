# QuietRoom GUI Client

A native desktop client for the QuietRoom encrypted chat server, built with Go and Wails. Provides a full graphical interface while maintaining the same end-to-end encryption, perfect forward secrecy, and traffic obfuscation as the CLI client.

Available for macOS, Windows, and Linux.

---

## Features

### Security
- **End-to-end encryption** — AES-256-GCM with per-session keys derived via Diffie-Hellman key exchange
- **Perfect forward secrecy** — each session generates a new DH keypair; past sessions cannot be decrypted if a key is later compromised
- **Certificate pinning** — the server's TLS certificate is compared byte-for-byte against the locally stored `chat_public.pem`; connections are refused if they don't match, blocking man-in-the-middle attacks
- **DH key validation** — small subgroup attack prevention on the key exchange
- **Decoy traffic** — configurable random padding packets sent at intervals to obscure communication patterns from traffic analysis

### Messaging
- **Lobby** — the default channel, visible to all users not currently in a room
- **Rooms** — create or join named rooms (`#roomname`), optionally password-protected
- **Multi-room** — join multiple rooms simultaneously and receive messages from all of them; switch between channels in the sidebar without leaving
- **Direct messages** — private encrypted DMs to any online user via the DM panel
- **Unread badges** — unread message counts shown in the sidebar for all channels

### User directory
- **Users button** — shows all users currently connected to the server with a one-click DM option
- **Members button** — shows members of the currently viewed channel (lobby or room); password-protected rooms are only visible to joined members

### File transfers
- Encrypted file transfers to any online user
- SHA-256 hash verification on receipt — the client reports whether the received file matches the sender's hash
- Progress bar shown inline during send and receive
- Files saved to a configurable download directory

### Interface
- Dark theme with cyan accent
- Sidebar channel navigation — lobby, joined rooms, and DM threads
- Autocomplete suggestions in the Join Room and New DM dialogs, populated from the live server data when the dialog opens
- Sound notifications for new messages and file transfer requests
- Server profiles — save multiple server configurations and switch between them from the login screen
- Settings panel — configure decoy traffic, sound notifications, download directory, and server profiles

---

## Getting started

### 1. Get the server certificate

Copy `chat_public.pem` from your QuietRoom server to the same directory as the application binary. This file is required to verify the server's identity. Without it the client will refuse to connect.

### 2. Launch the application

On macOS open `QuietRoom.app`. On Windows run `quietroom_client_gui.exe`. On Linux run the binary directly.

### 3. Configure a server profile

On the login screen, fill in the server host, port, username, and certificate file path. Click **Save as Profile** to store these for future sessions, or click **Connect** to connect immediately without saving.

Saved profiles appear in the dropdown at the top of the login screen and are pre-filled automatically on subsequent launches.

To manage profiles, click the **⚙ Settings** button on the login screen.

### 4. Connect

Click **Connect**. The client performs the TLS handshake, verifies the server certificate against the pinned copy, completes the DH key exchange, and logs in with the provided username. If the username is already taken on the server the connection is refused and an error is shown.

---

## Usage

### Sending messages

Type in the input bar at the bottom and press **Enter** or click **Send**. Messages are routed automatically to the channel currently selected in the sidebar.

### Joining a room

Click **+ Join Room** in the sidebar. Start typing a room name — existing rooms are suggested from the server as you type. Enter a password if the room is password-protected, then click **Join**.

To leave a room, click the **✕** button next to the room name in the sidebar.

### Direct messages

Click **+ New DM** in the sidebar or click the **DM** button next to a username in the Users or Members list. Type your message and press Enter.

### Sending a file

Click the **📎** button in the input bar. If you're in a DM thread the file will be offered to that user. If you're in a room or lobby you'll be prompted for the recipient's username. The recipient receives a file transfer request and must click **Accept** in the dialog that appears.

### Viewing online users

Click **👥 Users** in the topbar to see everyone currently connected to the server. Click **DM** next to any username to open a direct message thread.

### Viewing channel members

Click **👁 Members** in the topbar to see who is in the current channel. In the lobby this shows users who haven't joined any room. In a room it shows that room's members. For password-protected rooms, only joined members can see the member list.

---

## Settings

Open settings via the **⚙** button on the login screen or the settings button in the chat interface.

| Setting | Description |
|---|---|
| Server Profiles | Add, edit, or remove server connection profiles. Each profile stores host, port, username, and certificate path. Click Browse to locate the certificate file. |
| Decoy traffic | Sends random encrypted padding packets to the server at regular intervals to obscure traffic patterns. Enabled by default. |
| Decoy interval | How often (in seconds) decoy packets are sent. |
| Decoy min/max bytes | Size range for decoy payloads. |
| Sound notifications | Plays a system notification sound when a message or file transfer request arrives. |
| Download directory | Where received files are saved. Defaults to `~/Downloads/QuietRoom`. |

---

## Keyboard shortcuts

| Key | Action |
|---|---|
| Enter | Send message |
| Shift+Enter | Reserved for future multiline input |

---

## Security notes

- The client never stores messages on disk — all conversation history is held in memory for the duration of the session only
- Server profiles (host, port, username, certificate path) are stored in the OS config directory (`~/Library/Application Support/QuietRoom/config.json` on macOS, `~/.config/QuietRoom/config.json` on Linux, `%AppData%\QuietRoom\config.json` on Windows)
- The certificate file (`chat_public.pem`) is read from disk on each connection — it is never embedded in the application
- File transfers are relayed through the server, which means the server operator can see file contents in transit. This is an architectural limitation of the relay model and is documented behaviour.
