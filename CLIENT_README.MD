# QuietRoom Client

A command-line chat client for QuietRoom: TLS 1.3 with the server's access key, flow-controlled file transfers, and customizable visual themes.

## Features

- 🔐 **TLS 1.3** - Forward secrecy; the access key from `quietroom_access.pem` is presented to the server
- 🔒 **Certificate Pinning** - Exact server verification prevents MITM attacks
- 🎨 **Customizable Colors** - Full theme configuration
- 🔔 **Sound Notifications** - Audio alerts for new messages (optional)
- 🕵️ **Traffic Padding** - Message lengths are hidden
- 🎭 **Decoy Traffic** - Hides communication patterns
- 💬 **Private Messaging** - Direct messages to other users
- 🚪 **Chat Rooms** - Join password-protected group conversations
- 📁 **File Transfers** - Any size, several at once, with SHA-256 verification
- 📋 **Multiple Servers** - Store and switch between server configurations

## Installation

### Prerequisites

- Go 1.26 or higher (only needed to build from source)
- Linux/Unix, macOS, or Windows
- `quietroom_access.pem` file from the server

### Building

```bash
go build -o chat_client client.go
```

Or run directly:

```bash
go run client.go
```

## Usage

### First Time Setup

1. **Obtain the access file:**
   - Get `quietroom_access.pem` from your server administrator (physical media recommended)
   - Place it in the same directory as the client
   - ⚠️ **Keep it secret** — it contains the access key; anyone holding it can join the server
   - ⚠️ **Verify authenticity** (compare fingerprint with administrator)
   - The file is only valid until the server restarts; after a restart you need the new one

2. **Configure the client:**
   - Edit `client_config.json` (created on first run)
   - Add server addresses, customize colors, enable features

3. **Connect:**
   ```bash
   ./chat_client
   ```

### Connecting to a Server

```bash
./chat_client
```

You'll see:
```
✓ Loaded server certificate and access key

Available servers:
  1. Default Server (localhost:37842)

Press Enter to connect, or enter custom address: 
Enter your username: Alice
Connecting to localhost:37842...
```

After successful connection:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                         WELCOME TO QUIETROOM
   localhost:37842 - TLS 1.3 + ACCESS KEY - logged in as Alice
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✓ Decoy traffic active
✓ Type /help for available commands
✓ Press Ctrl+C or type /quit to disconnect

> 
```

If the name is taken or invalid, the client asks again.

## Configuration

The client uses `client_config.json` for configuration. A default one is created on first run.

### Complete Configuration File: `client_config.json`

```json
{
  "servers": [
    {
      "name": "Default Server",
      "address": "localhost",
      "port": 37842
    }
  ],
  "theme": {
    "system_color": "bright_cyan",
    "username_color": "bright_yellow",
    "message_color": "white",
    "timestamp_color": "gray",
    "error_color": "bright_red"
  },
  "decoy_traffic": true,
  "decoy_interval_seconds": 30,
  "decoy_min_bytes": 100,
  "decoy_max_bytes": 500,
  "sound_notification": false,
  "download_dir": "downloads",
  "max_receive_mb": 8192
}
```

## Configuration Options

### Servers Configuration

#### `servers` (array of objects)
List of available servers to connect to.

**Server Object Properties:**

##### `name` (string)
- **Description**: Display name for the server
- **Example**: `"Default Server"`, `"Production"`, `"Home Server"`

##### `address` (string)
- **Description**: Server hostname or IP address
- **Example**: `"localhost"`, `"192.168.1.100"`, `"chat.example.com"`

##### `port` (integer)
- **Description**: Server port number
- **Default**: `37842`
- **Range**: `1-65535`
- **Example**: `37842`, `45123`

**Example Servers Configuration:**
```json
"servers": [
  {
    "name": "Home Server",
    "address": "192.168.1.100",
    "port": 37842
  },
  {
    "name": "Office Server",
    "address": "10.0.0.50",
    "port": 45123
  },
  {
    "name": "Remote Server",
    "address": "chat.mycompany.com",
    "port": 37842
  }
]
```

### Theme Configuration

#### `theme` (object)
Customize the color scheme of the chat interface.

##### `system_color` (string)
- **Description**: Color for system messages and prompts
- **Default**: `"bright_cyan"`
- **Used for**: Welcome messages, "✓" indicators, "> " prompt
- **Available colors**: See color palette below

##### `username_color` (string)
- **Description**: Color for usernames in chat messages
- **Default**: `"bright_yellow"`
- **Used for**: Highlighting who sent each message
- **Example**: `[15:04:05] Alice: Hello` ← "Alice" is colored

##### `message_color` (string)
- **Description**: Color for message text
- **Default**: `"white"`
- **Used for**: The actual message content
- **Example**: `[15:04:05] Alice: Hello` ← "Hello" is colored

##### `timestamp_color` (string)
- **Description**: Color for message timestamps
- **Default**: `"gray"`
- **Used for**: `[15:04:05]` portion of messages

##### `error_color` (string)
- **Description**: Color for error messages
- **Default**: `"bright_red"`
- **Used for**: "✗" error indicators, connection failures

**Color Palette:**

| Color Name | Example Use |
|------------|-------------|
| `red` | Errors, warnings |
| `green` | Success messages |
| `yellow` | Highlights |
| `blue` | Information |
| `magenta` | Special messages |
| `cyan` | System messages |
| `white` | Normal text |
| `gray` | Timestamps, muted text |
| `bright_red` | Critical errors |
| `bright_green` | Success indicators |
| `bright_yellow` | Usernames, highlights |
| `bright_blue` | Links, references |
| `bright_magenta` | Special highlights |
| `bright_cyan` | System prompts |

**Example Theme Configurations:**

**Dark Mode (Default):**
```json
"theme": {
  "system_color": "bright_cyan",
  "username_color": "bright_yellow",
  "message_color": "white",
  "timestamp_color": "gray",
  "error_color": "bright_red"
}
```

**Matrix Theme:**
```json
"theme": {
  "system_color": "bright_green",
  "username_color": "green",
  "message_color": "bright_green",
  "timestamp_color": "green",
  "error_color": "bright_red"
}
```

**Hacker Theme:**
```json
"theme": {
  "system_color": "bright_cyan",
  "username_color": "bright_magenta",
  "message_color": "cyan",
  "timestamp_color": "blue",
  "error_color": "bright_red"
}
```

**Professional Theme:**
```json
"theme": {
  "system_color": "blue",
  "username_color": "cyan",
  "message_color": "white",
  "timestamp_color": "gray",
  "error_color": "red"
}
```

### Traffic & Privacy Configuration

#### `decoy_traffic` (boolean)
- **Description**: Enable/disable decoy traffic generation
- **Default**: `true`
- **Purpose**: Hides when you're actually chatting vs. idle
- **Values**: `true` (enabled), `false` (disabled)
- **Bandwidth**: ~100-500 bytes every 30 seconds (minimal)

#### `decoy_interval_seconds` (integer)
- **Description**: Mean interval between decoy frames (each wait is random, 0.5–1.5 × this value)
- **Default**: `30`
- **Range**: `10` - `300` seconds recommended
- **Example**: `30` (every 30s), `60` (every minute), `120` (every 2 minutes)
- **Note**: Lower = better privacy, slightly higher bandwidth

#### `decoy_min_bytes` (integer)
- **Description**: Minimum decoy packet size
- **Default**: `100`
- **Range**: `50` - `1000` bytes
- **Purpose**: Makes decoys look like real messages

#### `decoy_max_bytes` (integer)
- **Description**: Maximum decoy packet size
- **Default**: `500`
- **Range**: `100` - `2000` bytes
- **Note**: Random size between min and max

### File Configuration

#### `download_dir` (string)
- **Description**: Folder where accepted files are saved
- **Default**: `"downloads"` (next to the client)

#### `max_receive_mb` (integer)
- **Description**: Largest file you accept, in MB; larger offers are declined automatically when you accept them
- **Default**: `8192` (8 GB)

### Sound Configuration

#### `sound_notification` (boolean)
- **Description**: Enable/disable sound alerts for new messages
- **Default**: `false` (disabled)
- **Values**: `true` (enabled), `false` (disabled)
- **Platform Support**:
  - **Windows**: Terminal bell
  - **macOS**: System Ping sound
  - **Linux**: PulseAudio, ALSA, speaker-test, or beep command

**Linux Sound Requirements:**

If sound doesn't work, install one of these:
```bash
# Ubuntu/Debian
sudo apt-get install pulseaudio-utils  # For paplay
sudo apt-get install alsa-utils        # For aplay
sudo apt-get install beep              # For beep command

# RHEL/CentOS/Fedora
sudo yum install pulseaudio-utils
sudo yum install alsa-utils
sudo yum install beep

# Arch Linux
sudo pacman -S pulseaudio alsa-utils beep

# Test sound
speaker-test -t sine -f 1000 -l 1
```

## Chat Commands

While connected, you can use these commands:

### General Commands
- `/help` - Show available commands
- `/quit` - Disconnect from server and exit

### Communication Commands
- `/msg <user> <message>` - Send private message to a user
  - Example: `/msg Alice Hey, how are you?`
  - Private messages are not logged by the server
  - Recipient must be online

### Room Commands
- `/join #room [password]` - Join or create a chat room
  - Example: `/join #general`
  - Example: `/join #private secretpassword`
  - Room names must start with `#`
  
- `/leave #room` - Leave a chat room
  - Example: `/leave #general`
  - Returns you to the lobby
  
- `/rooms` - List all active rooms
  - Shows room names, member counts
  - 🔒 indicates password-protected rooms
  
- `/users` - List all users online

- `/members <#room|lobby>` - List the members of a room or of the lobby
  - Password-protected rooms are only visible to their members

When you join a room, your messages go to that room (the prompt shows it, e.g. `#general > `) until you `/leave` it.

### File Transfer Commands
- `/file <user> <path>` - Offer a file to a user
  - Example: `/file Bob ~/Documents/report.pdf` (quote paths with spaces: `/file Bob "my file.pdf"`)
  - Both users must be online; any file size
  - Up to 4 transfers at once in each direction
  
- `/accept <transfer_id>` - Accept an incoming file
  - Files are saved to the `download_dir` folder (`downloads/` by default)
  
- `/decline <transfer_id>` - Decline an incoming file

- `/cancel <transfer_id>` - Stop a transfer in progress (sending or receiving), or withdraw an offer

## Security Features

### Connection Flow

1. **Load Access File**: Reads the server certificate and the access key from `quietroom_access.pem`
2. **TLS 1.3 Handshake**: Encrypted connection with ephemeral keys (forward secrecy); the client presents the access key
3. **Certificate Pinning**: Verifies the exact server certificate (prevents MITM)
4. **Login**: Sends the username; the server answers with a welcome or an error

### Forward Secrecy

- Each connection uses new temporary TLS keys
- Recorded traffic cannot be decrypted later, even if the access file is compromised

### Certificate Pinning

- Client verifies the **exact** server certificate byte-for-byte
- Prevents man-in-the-middle attacks even with compromised certificate authorities
- Connection refused if the certificate doesn't match

### Traffic Padding and Decoys

1. **TLS 1.3**: Full transport layer encryption
2. **Padding**: Every message is padded to a size class, so its length is hidden
3. **Decoy Traffic**: Random cover messages at random intervals mask when you chat

Network monitors see:
- ✅ Encrypted TLS traffic
- ❌ Cannot read message content or exact length
- ❌ Cannot tell when real messages are sent (with decoy traffic)

The server decrypts and relays messages (it is trusted by design) and never stores them.

## File Transfers

### Sending Files

1. Use the `/file` command:
   ```
   /file Bob presentation.pdf
   ```

2. Wait for recipient to accept:
   ```
   Computing file hash...
   *** File offer sent to Bob: presentation.pdf (1.2 MB) ***
   Transfer ID: 3f9c0a5e8b1d4c2a9e7f6b5d4c3a2b1e
   SHA-256: a1b2c3d4...
   Waiting for the recipient to accept... (/cancel 3f9c... to withdraw)
   ```

3. When accepted, the file is sent automatically, as fast as the recipient can receive it. You can keep chatting meanwhile:
   ```
   Bob accepted — sending presentation.pdf (1.2 MB)
   Sending presentation.pdf: 100.0% (1.2 MB of 1.2 MB)
   ✓ File sent: presentation.pdf (1.2 MB)
   ✓ Recipient should verify hash: a1b2c3d4...
   ```

### Receiving Files

1. You'll receive a transfer request:
   ```
   *** FILE TRANSFER REQUEST ***
   Sender: Alice
   File: presentation.pdf
   SHA-256: a1b2c3d4...
   Transfer ID: 3f9c0a5e8b1d4c2a9e7f6b5d4c3a2b1e
   
   To accept, type: /accept 3f9c0a5e8b1d4c2a9e7f6b5d4c3a2b1e
   To decline, type: /decline 3f9c0a5e8b1d4c2a9e7f6b5d4c3a2b1e
   ```

2. Accept the transfer:
   ```
   /accept 3f9c0a5e8b1d4c2a9e7f6b5d4c3a2b1e
   ```

3. File is received automatically:
   ```
   Receiving presentation.pdf (1.2 MB) from Alice
   Expected SHA-256: a1b2c3d4...
   ✓ File received: presentation.pdf (1.2 MB)
     Saved to: downloads/presentation.pdf
     SHA-256: a1b2c3d4...
   ✓ Hash verification PASSED - file integrity verified!
   ```

4. Find your file in the `downloads/` folder. While receiving, data goes to a hidden `.part` file that is removed if the transfer fails, so you never get a silently truncated file.

### File Transfer Security

- **Encrypted**: Files are encrypted during transmission
- **Hash Verification**: SHA-256 hash ensures file integrity
- **No Tampering**: Any modification will be detected
- **Recipient Approval**: Recipient must accept before transfer begins
- **Safe Names**: Directory parts are stripped from file names; existing files are never overwritten (a number is appended)

## Troubleshooting

### Cannot find quietroom_access.pem

**Problem**: `✗ Error: quietroom_access.pem not found!`

**Solution**: 
1. Copy `quietroom_access.pem` from the server administrator to the client directory
2. Ensure it's in the same directory as the client executable
3. Check file permissions: `ls -l quietroom_access.pem`
4. A `chat_public.pem` from an older server version no longer works

### Access denied

**Problem**: `✗ Access denied — the server rejected your access key`

**Causes & Solutions**:
1. **Outdated access file**: The server was restarted, which invalidates all access files — get the new `quietroom_access.pem`
2. **Wrong file**: Make sure the file came from this server

### Not a valid access file

**Problem**: `✗ Error loading access file: ... is not a valid access file`

**Solution**: The file must contain the server certificate *and* the access key. Get the complete `quietroom_access.pem` from your administrator.

### Different protocol version

**Problem**: `✗ the server speaks a different protocol version`

**Solution**: QuietRoom 3 clients need a QuietRoom 3 server (and vice versa). Update the server or the client so both run 3.x.

### Server closed the connection without answering

**Problem**: `✗ the server closed the connection without answering — your quietroom_access.pem is wrong or outdated ...`

**Causes & Solutions**:
1. **Server restarted**: Every restart generates new keys — get the new access file
2. **Clock off**: The connection token is tied to the current time; set this computer's clock correctly (within 5 minutes)
3. **Wrong file**: Make sure the access file came from this server

### Certificate does not match

**Problem**: `✗ Server certificate does not match your quietroom_access.pem`

**Causes & Solutions**:
1. **Wrong access file**: Verify you have the correct `quietroom_access.pem`
2. **Server restarted**: Every restart generates new keys — get the new access file
3. **MITM attack**: Possible man-in-the-middle attack - verify with administrator

### Connection refused

**Problem**: `✗ TLS connection failed: connection refused`

**Solutions**:
1. Check server is running
2. Verify correct server address and port
3. Test connectivity: `telnet <server> <port>` or `nc -zv <server> <port>`
4. Check if firewall is blocking outbound connections
5. Ensure server is accessible from your network

### Username rejected

**Problem**: `✗ Invalid username` or `✗ Username already taken`

**Causes**:
- Username contains invalid characters (only letters, numbers, `_`, `-`, `.` allowed; no spaces)
- Username is too long (max 32 characters)
- Username is empty
- Someone online already uses the name in any capitalisation (`alice` is taken while `Alice` is online)

**Solution**: Use a valid username with allowed characters, for example `bob_smith` instead of `bob smith`

### No sound notifications

**Problem**: `sound_notification: true` but no sound plays

**Solutions**:

**Linux:**
```bash
# Test if sound works
speaker-test -t sine -f 1000 -l 1

# Install audio packages
sudo apt-get install pulseaudio-utils alsa-utils beep
# or
sudo yum install pulseaudio-utils alsa-utils beep
```

**macOS:**
```bash
# Test system sound
afplay /System/Library/Sounds/Ping.aiff

# Check volume is not muted
```

**Windows:**
- Ensure system volume is not muted
- Check terminal supports bell character
- Use Windows Terminal or PowerShell for better support

### Colors not showing

**Problem**: Colors appear as escape codes like `[31m` or don't work

**Solutions**:
1. Use a modern terminal emulator
2. Windows: Use Windows Terminal, PowerShell, or WSL (not cmd.exe)
3. Set TERM environment variable:
   ```bash
   export TERM=xterm-256color
   ```
4. Update terminal emulator to latest version

### File transfer fails

**Problem**: `✗ File transfer of ... ended: <reason>`

**Solutions**:
1. `... disconnected`: one side left; send the file again once both are online
2. `offer expired`: the recipient did not accept within 5 minutes
3. `transfer stalled`: no data moved for 2 minutes (network trouble)
4. `cannot write file`: check write permissions and disk space in `download_dir`
5. `file is too large`: raise `max_receive_mb` if you want to accept it

### Hash verification failed

**Problem**: `✗ File transfer of <name> ended: SHA-256 mismatch, file discarded (expected …, got …)`

The received data did not match the hash the sender announced, so the client deleted it: nothing is saved to the download folder.

**Causes**:
- The file was modified on the sender's side while it was being sent
- A sender deliberately announcing a hash that does not match the content (TLS already protects the data in transit, so the network is not the cause)

**Solution**:
1. Ask the sender to resend the file without changing it during the transfer
2. If it happens again, treat the sender's file as suspicious

## Tips & Tricks

### Quick Connect

Create a shell alias for quick access:
```bash
# Add to ~/.bashrc or ~/.zshrc
alias quietroom='cd ~/quietroom && ./chat_client'
```

Then just type `quietroom` to connect!

### Multiple Identities

Run multiple clients with different usernames:
```bash
# Terminal 1
./chat_client
# Use username: Alice

# Terminal 2
./chat_client
# Use username: Bob
```

### Custom Server

Connect to a custom server directly:
```
Select server (1-1) or enter custom address: chat.example.com:37842
```

### Keyboard Shortcuts

The input line can be edited like a shell prompt. Long input wraps over several rows; messages that arrive while you type appear above it, and transfer progress is shown on its own line above the prompt.

| Key | Action |
|-----|--------|
| `←` `→` (`Ctrl+B` `Ctrl+F`) | Move one character |
| `Ctrl+←` `Ctrl+→` / `Alt+B` `Alt+F` | Move one word |
| `Home` `End` (`Ctrl+A` `Ctrl+E`) | Start / end of the line |
| `Backspace` / `Delete` (`Ctrl+D`) | Delete before / under the cursor |
| `Ctrl+W` / `Alt+Backspace` | Delete the word before the cursor |
| `Ctrl+U` / `Ctrl+K` | Delete to the start / end of the line |
| `↑` `↓` | Previous / next line you sent (last 100) |
| `Ctrl+L` | Clear the screen |
| `Ctrl+C` | Disconnect and exit |

Wide characters (Chinese, Japanese, Korean, most emoji) take two columns. Emoji built from several characters (such as 👨‍👩‍👧) are drawn differently by different terminals; if the cursor looks misplaced after one, `Ctrl+L` redraws the line.

### Line mode (no interactive terminal)

Line editing needs a terminal that supports raw input. Where there is none, the CLI switches to **line mode** by itself: you type a whole line and press Enter, and messages are printed as they arrive, without colours or a prompt. This happens:

- on **Plan 9**, which has no raw terminal mode;
- when input or output is **redirected** (pipes, files, scripts, `ssh` without a terminal);
- if switching the terminal to raw mode fails for any other reason (the CLI says so).

Everything else works the same, including commands and file transfers (only the progress line is left out). Colours are also switched off on Plan 9, when output is not a terminal, or when the `NO_COLOR` environment variable is set.

## Performance

### Resource Usage
- **Memory**: ~5-10 MB per connection
- **CPU**: <1% idle, ~2-5% during active chat
- **Network**: 
  - Without decoy: ~50 bytes per message + encryption overhead
  - With decoy: +100-500 bytes per interval

### Battery Impact (Laptops)
- Minimal impact (<1% battery drain per hour)
- Decoy traffic has negligible impact on battery life

## Privacy Considerations

### What's Encrypted
✅ All message content  
✅ Usernames (during transmission)  
✅ File contents  
✅ Message metadata

### What's Visible to Network Monitors
- Your IP address connecting to server IP
- Encrypted traffic volume (but not content)
- Connection timing (use decoy traffic to hide patterns)

### Recommendations
1. **Use VPN or Tor** for IP anonymity if needed
2. **Enable decoy traffic** to hide activity patterns
3. **Choose usernames carefully** - don't use real names if privacy is important
4. **Verify certificate fingerprint** before first connection
5. **Use secure channels** to obtain `quietroom_access.pem` (USB, in-person, etc.) and never share it with anyone outside the group

## Advanced Usage

### Verify Certificate Fingerprint

Before first use, verify the certificate with your administrator:

```bash
# SHA256 fingerprint of the server certificate (first block in the access file)
openssl x509 -in quietroom_access.pem -noout -fingerprint -sha256

# Display certificate details
openssl x509 -in quietroom_access.pem -text -noout
```

Compare the fingerprint with what your administrator provides.

### Running on Specific Network Interface

If you have multiple network interfaces:
```bash
# Bind to specific interface (requires code modification)
# Or use routing rules to force traffic through specific interface
```

### Persistent Connection

Keep the client running in background with screen/tmux:
```bash
# Using screen
screen -S quietroom
./chat_client
# Press Ctrl+A then D to detach

# Reattach later
screen -r quietroom

# Using tmux
tmux new -s quietroom
./chat_client
# Press Ctrl+B then D to detach

# Reattach later
tmux attach -t quietroom
```

## License

This project is licensed under the GNU Affero General Public License v3 (AGPL-3.0).

If you modify this software or run it as a network service, you are required
to make the complete corresponding source code available under the same license.

Commercial use as part of a proprietary product or service requires a separate
commercial license. Contact the author for details.

## Support

For issues, questions, or contributions, please open an issue on the project repository.
