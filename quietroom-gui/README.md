# QuietRoom GUI Client

A native desktop client for the QuietRoom encrypted chat server, built with Go and Wails. It uses the same client implementation as the CLI (the shared [`client`](../client/) package), so both behave identically on the wire.

Available for macOS, Windows, and Linux.

---

## Features

### Security
- **End-to-end encryption** — direct messages, files and password rooms are encrypted between members (🔒); the server relays them without being able to read them. click **🔒 Verify** in a DM to compare safety numbers
- **TLS 1.3** — all traffic encrypted with ephemeral keys (forward secrecy)
- **Access key** — the client presents the master access key from `quietroom_access.pem` during the TLS handshake; the server refuses connections without it
- **Certificate pinning** — the server's TLS certificate is compared byte-for-byte against the one stored in `quietroom_access.pem`; connections are refused if they don't match, blocking man-in-the-middle attacks
- **Padding and decoy traffic** — messages are padded to size classes, and random cover messages at random intervals obscure communication patterns
- **Safe rendering** — everything from the server is shown as plain text under a content security policy; files can only be sent after picking them in the native file dialog

### Messaging
- **Lobby** — the default channel, visible to all users not currently in a room
- **Rooms** — create or join named rooms (`#roomname`); rooms with a password are end-to-end encrypted
- **Multi-room** — join multiple rooms simultaneously and receive messages from all of them; switch between channels in the sidebar without leaving
- **Direct messages** — end-to-end encrypted DMs to any online user via the DM panel
- **Unread badges** — unread message counts shown in the sidebar for all channels

### User directory
- **Users button** — shows all users currently connected to the server with a one-click DM option
- **Members button** — shows members of the currently viewed channel (lobby or room); password-protected rooms are only visible to joined members

### File transfers
- File transfers of any size to any online user, several at once, while chat stays responsive
- SHA-256 hash verification on receipt — a file that does not match the sender's hash is discarded, never saved
- Progress bar shown inline during send and receive
- Files saved to a configurable download directory

### Interface
- Dark theme with cyan accent
- Sidebar channel navigation — lobby, joined rooms, and DM threads
- Autocomplete suggestions in the Join Room and New DM dialogs, populated from the live server data when the dialog opens
- Desktop notifications with sound for new messages, DMs and file transfers, sent as QuietRoom itself; clicking one brings QuietRoom forward and opens that conversation. They say who wrote, never what (the operating system keeps a notification history). On macOS, QuietRoom asks for permission the first time
- Server profiles — save multiple server configurations and switch between them from the login screen
- Settings panel — configure decoy traffic, desktop notifications, download directory, and server profiles

---

## Getting started

### 1. Get the access file

Copy `quietroom_access.pem` from your QuietRoom server administrator to the same directory as the application binary (or select it in the server profile). It contains the server certificate, used to verify the server's identity, and the access key the server requires. Without it you cannot connect.

⚠️ The file is **secret** — anyone holding it can join the server. It is only valid until the server restarts; after a restart, get the new file.

### 2. Launch the application

On macOS open `QuietRoom.app`. On Windows run `quietroom_client_gui.exe`. On Linux run the binary directly.

### 3. Configure a server profile

On the login screen, fill in the server host, port, username, and certificate file path. Click **Save as Profile** to store these for future sessions, or click **Connect** to connect immediately without saving.

Saved profiles appear in the dropdown at the top of the login screen and are pre-filled automatically on subsequent launches.

To manage profiles, click the **⚙ Settings** button on the login screen.

### 4. Connect

Click **Connect**. The client performs the TLS handshake, verifies the server certificate against the pinned copy, and logs in with the provided username. If the username is already taken on the server the connection is refused and an error is shown.

---

## Usage

### Sending messages

Type in the input bar at the bottom and press **Enter** or click **Send**. Messages are routed automatically to the channel currently selected in the sidebar.

### Joining a room

Click **+ Join Room** in the sidebar. Start typing a room name — existing rooms are suggested from the server as you type. Enter a password if the room is password-protected, then click **Join**.

To leave a room, click the **✕** button next to the room name in the sidebar.

### Direct messages

Click **+ New DM** in the sidebar or click the **DM** button next to a username in the Users or Members list. Type your message and press Enter.

### Checking who you are talking to

In a DM, click **🔒 Verify** in the top bar. It shows two safety numbers, one for you and one for the other person. Compare them with that person over another channel (in person, by phone): if both of you see the same two numbers, nobody, not even the server, can read your direct messages and files. The numbers change whenever either of you reconnects.

### Sending a file

Open a DM with the person and click the **📎** button in the input bar, then pick the file. Files always go to one person, end-to-end encrypted, so the button only works in a DM. The recipient receives a file transfer request and must click **Accept** in the dialog that appears.

### No slash commands

The app has a button for every action, so it has no `/commands`: what you type is always sent as a message. If a message starts with `/`, the app reminds you once; press Enter again to send it as it is. The command-line client keeps its commands.

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
| Desktop notifications (with sound) | Shows a notification when a message, DM or file transfer arrives, through the system's own notification service (macOS Notification Center, Windows notifications, the Linux desktop's notification service over D-Bus). If notifications cannot be shown, the chat says why; on macOS, allow them under System Settings → Notifications → QuietRoom. |
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
- The access file (`quietroom_access.pem`) is read from disk on each connection — it is never embedded in the application
- File transfers are relayed through the server but end-to-end encrypted: the server operator sees neither the contents nor the file name, only the size rounded to 32 KiB. Messages in the lobby and in rooms without a password are readable by the server.
