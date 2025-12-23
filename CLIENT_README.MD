# QuietRoom Client

A command-line chat client with strong encryption, perfect forward secrecy, and customizable visual themes.

## Features

- 🔐 **End-to-End Encryption** - RSA + Diffie-Hellman + AES-256-GCM
- 🔑 **Perfect Forward Secrecy** - Ephemeral session keys
- 🔒 **Certificate Pinning** - Exact server verification prevents MITM attacks
- 🎨 **Customizable Colors** - Full theme configuration
- 🔔 **Sound Notifications** - Audio alerts for new messages (optional)
- 🕵️ **Traffic Obfuscation** - Evades Deep Packet Inspection
- 🎭 **Decoy Traffic** - Hides communication patterns
- 💬 **Private Messaging** - Direct messages to other users
- 🚪 **Chat Rooms** - Join password-protected group conversations
- 📁 **File Transfers** - Secure file sharing with hash verification
- 📋 **Multiple Servers** - Store and switch between server configurations

## Installation

### Prerequisites

- Go 1.16 or higher
- Linux/Unix, macOS, or Windows
- `chat_public.pem` file from the server

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

1. **Obtain the public certificate:**
   - Get `chat_public.pem` from your server administrator
   - Place it in the same directory as the client
   - ⚠️ **Verify authenticity** (compare fingerprint with administrator)

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
✓ Loaded RSA authentication key
✓ Initialized Diffie-Hellman parameters

Available servers:
  1. Default Server (localhost:37842)

Press Enter to connect, or enter custom address: 
```

After successful connection:
```
Connecting to localhost:37842...
✓ Secure TLS connection established
✓ Server authenticated via RSA signature
✓ Diffie-Hellman key exchange completed
✓ Perfect forward secrecy enabled

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    SECURE ENCRYPTED CHAT - localhost:37842 - E2E ENCRYPTED + PFS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✓ Decoy traffic active
✓ Traffic obfuscation active
✓ Type /help for available commands
✓ Press Ctrl+C to disconnect

Enter your username: Alice
Welcome to the chat, Alice!
Type /help for available commands. Type /quit to exit.

> 
```

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
  "sound_notification": false
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
- **Description**: How often to send decoy packets
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
  
- `/users` - List users in current location
  - Shows users in current room or lobby

### File Transfer Commands
- `/file <user> <filename>` - Send file to a user
  - Example: `/file Bob document.pdf`
  - Only specify the filename, not full path
  - Both users must be online
  - Maximum file size: 10MB
  
- `/accept <transfer_id>` - Accept incoming file transfer
  - Example: `/accept Alice_Bob_1234567890`
  - Files are saved to `downloads/` folder
  
- `/decline <transfer_id>` - Decline incoming file transfer
  - Example: `/decline Alice_Bob_1234567890`

## Security Features

### Connection Flow

1. **Load Public Certificate**: Verifies you have the server's certificate
2. **TLS Handshake**: Establishes encrypted TLS 1.3 connection
3. **Certificate Pinning**: Verifies exact certificate match (prevents MITM)
4. **Server Authentication**: RSA signature verification
5. **DH Key Exchange**: Generates ephemeral session keys
6. **Encrypted Chat**: All messages encrypted with session key

### Perfect Forward Secrecy

- Each connection generates new temporary keys
- Old messages cannot be decrypted even if the certificate is compromised later
- Keys are destroyed when you disconnect

### Certificate Pinning

- Client verifies the **exact** server certificate byte-for-byte
- Prevents man-in-the-middle attacks even with compromised certificate authorities
- Warning displayed if certificate doesn't match expected value

### Traffic Obfuscation

Your traffic is protected by multiple layers:
1. **TLS 1.3**: Full transport layer encryption
2. **Application Layer Obfuscation**: TLS-like packet structure with random padding
3. **Decoy Traffic**: Optional random encrypted data to mask patterns

Network monitors see:
- ✅ Encrypted TLS traffic (looks like HTTPS)
- ✅ Variable packet sizes
- ❌ Cannot determine what protocol it is
- ❌ Cannot read message content or length
- ❌ Cannot tell when real messages are sent (with decoy traffic)

## File Transfers

### Sending Files

1. Use the `/file` command:
   ```
   /file Bob presentation.pdf
   ```

2. Wait for recipient to accept:
   ```
   *** File transfer request sent to Bob ***
   Transfer ID: Alice_Bob_1702345678
   Waiting for recipient to accept...
   ```

3. When accepted, file is automatically sent:
   ```
   Computing file hash...
   Sending file: presentation.pdf (1.23 MB)
   SHA-256: a1b2c3d4...
   Progress: 100.0%
   ✓ File sent successfully
   ✓ Recipient should verify hash: a1b2c3d4...
   ```

### Receiving Files

1. You'll receive a transfer request:
   ```
   *** FILE TRANSFER REQUEST ***
   Sender: Alice
   File: presentation.pdf
   SHA-256: a1b2c3d4...
   Transfer ID: Alice_Bob_1702345678
   
   To accept, type: /accept Alice_Bob_1702345678
   To decline, type: /decline Alice_Bob_1702345678
   ```

2. Accept the transfer:
   ```
   /accept Alice_Bob_1702345678
   ```

3. File is received automatically:
   ```
   Receiving file: presentation.pdf (1.23 MB)
   Expected SHA-256: a1b2c3d4...
   Progress: 100.0%
   ✓ File received successfully (1.23 MB)
   SHA-256: a1b2c3d4...
   ✓ Hash verification PASSED - file integrity verified!
   ```

4. Find your file in the `downloads/` folder

### File Transfer Security

- **Encrypted**: Files are encrypted during transmission
- **Hash Verification**: SHA-256 hash ensures file integrity
- **No Tampering**: Any modification will be detected
- **Recipient Approval**: Recipient must accept before transfer begins

## Troubleshooting

### Cannot find chat_public.pem

**Problem**: `✗ Error: chat_public.pem not found!`

**Solution**: 
1. Copy `chat_public.pem` from server to client directory
2. Ensure it's in the same directory as the client executable
3. Check file permissions: `ls -l chat_public.pem`

### Server authentication failed

**Problem**: `✗ Server authentication failed - possible MITM attack!`

**Causes & Solutions**:
1. **Wrong certificate file**: Get correct `chat_public.pem` from administrator
2. **Server regenerated keys**: Server admin regenerated keys, get new certificate
3. **Actual MITM attack**: Someone is intercepting your connection - investigate before connecting

### Certificate does not match

**Problem**: `✗ peer certificate does not match the expected pinned certificate`

**Causes & Solutions**:
1. **Wrong certificate**: Verify you have the correct `chat_public.pem`
2. **Server changed**: Server administrator changed certificates
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

**Problem**: Connection drops after entering username

**Causes**:
- Username contains invalid characters (only letters, numbers, spaces, `_`, `-`, `.` allowed)
- Username is too long (max 32 characters)
- Username is empty or only whitespace

**Solution**: Use a valid username with allowed characters

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

**Problem**: File transfer interrupted or fails

**Solutions**:
1. Check both users are still connected
2. Ensure file is under 10MB
3. Verify you have write permissions in current directory
4. Check disk space available
5. Try with a smaller file to test

### Hash verification failed

**Problem**: `✗ Hash verification FAILED - file may be corrupted!`

**Causes**:
- Network transmission error
- File was modified during transfer
- Possible attack attempt

**Solution**:
1. Ask sender to resend the file
2. Check network stability
3. If problem persists, investigate security concerns

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

Most terminals support:
- `Ctrl+C` - Disconnect and exit
- `Ctrl+L` - Clear screen (terminal feature)
- `Up Arrow` - Recall previous message (terminal feature)
- `Ctrl+U` - Clear current line (terminal feature)

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
5. **Use secure channels** to obtain `chat_public.pem` (USB, in-person, etc.)

## Advanced Usage

### Verify Certificate Fingerprint

Before first use, verify the certificate with your administrator:

```bash
# SHA256 fingerprint
openssl x509 -in chat_public.pem -noout -fingerprint -sha256

# Display certificate details
openssl x509 -in chat_public.pem -text -noout
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

## Version

Current Version: 1.0.0

## License

This project is licensed under the GNU Affero General Public License v3 (AGPL-3.0).

If you modify this software or run it as a network service, you are required
to make the complete corresponding source code available under the same license.

Commercial use as part of a proprietary product or service requires a separate
commercial license. Contact the author for details.

## Support

For issues, questions, or contributions, please open an issue on the project repository.