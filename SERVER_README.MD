# Secure Chat Server

A self-hosted encrypted chat server: TLS 1.3 with forward secrecy, a shared access key that keeps outsiders out, padded traffic and decoys against traffic analysis.

## Features

- 🔐 **TLS 1.3 only** - Forward secrecy; clients pin the exact server certificate
- 🔑 **Access key (mutual TLS)** - Connections without the current access key are refused during the handshake
- 🕵️ **Traffic padding** - Every frame is padded to a size class, hiding message lengths
- 🎭 **Decoy Traffic** - Random cover frames at random intervals hide activity patterns
- 📁 **Flow-controlled file relay** - Files of any size; the server never stores them and buffers at most a few MB per transfer
- 📝 **Privacy-preserving Logging** - Security events are logged without recording participants (metadata logging is opt-in)
- 👥 **Multi-client Support** - Concurrent connections with thread-safe broadcasting

## Installation

### Prerequisites

- Go 1.26 or higher (only needed to build from source)
- Linux/Unix, macOS, or Windows

### Building

```bash
go build -o chat_server server.go
```

Or run directly:

```bash
go run server.go
```

## Usage

### First Time Setup

1. **Start the server:**
   ```bash
   ./chat_server
   ```

2. **Copy the access file to clients:**
   - The server generates `quietroom_access.pem` on every start
   - **Securely copy this file** to all client machines (physical media recommended)
   - ⚠️ **The file is SECRET** — it contains the master access key. Anyone holding it can join
   - ⚠️ **Never transmit the access file over insecure channels**
   - Restarting the server generates new keys and invalidates every previously distributed access file (this is intentional: a restart is how you revoke access)

### Starting the Server

```bash
./chat_server
```

You should see:
```
✓ Generated new server key and master access key (valid until server restart)
✓ Access file saved to: quietroom_access.pem
⚠ COPY quietroom_access.pem to client machines before connecting — it is SECRET, anyone holding it can join!
⚠ Restarting the server invalidates the previous access file.
✓ QuietRoom server (protocol 3) listening on port 37842 (TLS 1.3, access key required)
✓ Logging to: chat_server.log
✓ Security logging to: security.log
✓ Metadata logging off: logs contain no participant information
✓ Decoy traffic enabled (mean interval: 30s)
```

## Configuration

The server uses `server_config.json` for configuration. If it doesn't exist, a default one will be created.

### Configuration File: `server_config.json`

```json
{
  "port": 37842,
  "log_file": "chat_server.log",
  "security_log_file": "security.log",
  "decoy_traffic": true,
  "decoy_interval_seconds": 30,
  "decoy_min_bytes": 100,
  "decoy_max_bytes": 500,
  "max_connections": 100,
  "max_connections_per_ip": 10,
  "max_new_connections_per_ip_per_minute": 30,
  "max_rooms": 200,
  "max_rooms_per_member": 20,
  "log_metadata": false
}
```

### Configuration Options

#### `port` (integer)
- **Description**: TCP port the server listens on
- **Default**: `37842`
- **Recommended**: Use non-standard ports (30000-65535) to avoid automated scans
- **Example**: `37842`, `45123`, `52849`

#### `log_file` (string)
- **Description**: Path to general activity log file
- **Default**: `"chat_server.log"`
- **Logs**: Server errors. With `log_metadata` enabled also user joins/leaves, connection attempts, DMs and file transfers
- **Example**: `"chat_server.log"`, `"/var/log/chat/server.log"`

#### `security_log_file` (string)
- **Description**: Path to security events log file
- **Default**: `"security.log"`
- **Logs**: 
  - Rejected connections (no or wrong access key), with IP address
  - Connection limit summaries
  - Malformed frames and messages, flow-control violations (participant shown as `[member]` unless `log_metadata` is enabled)
  - Suspicious activity
- **Example**: `"security.log"`, `"/var/log/chat/security.log"`

#### `decoy_traffic` (boolean)
- **Description**: Enable/disable automatic decoy traffic generation
- **Default**: `true`
- **Purpose**: Hides activity patterns by sending random encrypted data
- **Values**: `true` (enabled), `false` (disabled)
- **Note**: Helps prevent traffic analysis attacks

#### `decoy_interval_seconds` (integer)
- **Description**: How often to send decoy packets (in seconds)
- **Default**: `30`
- **Range**: `10` - `300` recommended
- **Example**: `30` (every 30 seconds), `60` (every minute)
- **Note**: Lower values = more bandwidth but better obfuscation

#### `decoy_min_bytes` (integer)
- **Description**: Minimum size of decoy packets in bytes
- **Default**: `100`
- **Range**: `50` - `1000` recommended
- **Example**: `100`, `200`
- **Note**: Makes decoys look like real messages

#### `decoy_max_bytes` (integer)
- **Description**: Maximum size of decoy packets in bytes
- **Default**: `500`
- **Range**: `100` - `2000` recommended
- **Example**: `500`, `1000`
- **Note**: Random size between min and max for each decoy

#### `max_connections` (integer)
- **Description**: Maximum number of simultaneous connections to the server
- **Default**: `100`
- **Note**: Connections over the limit are closed immediately, before the TLS handshake

#### `max_connections_per_ip` (integer)
- **Description**: Maximum number of simultaneous connections from one IP address
- **Default**: `10`
- **Note**: If several participants connect from behind the same router (shared public IP), raise this value accordingly

#### `max_new_connections_per_ip_per_minute` (integer)
- **Description**: Maximum number of new connections accepted from one IP address per minute
- **Default**: `30`
- **Note**: Refused connections are summarised once a minute in the security log

#### `max_rooms` (integer)
- **Description**: Maximum number of rooms on the server
- **Default**: `200`
- **Note**: Empty rooms are removed automatically

#### `max_rooms_per_member` (integer)
- **Description**: Maximum number of rooms one member can be in at the same time
- **Default**: `20`

#### `log_metadata` (boolean)
- **Description**: Record information about participants in the logs: who joined and left, successful logins, DMs (sender → recipient), file transfers, and member IP addresses
- **Default**: `false`
- **Note**: Leave this off in normal operation. Logs are exactly the kind of record that can be seized or subpoenaed; with it off, logs contain no information about participants. Enable it only temporarily for debugging. The server prints a warning at startup while it is on.

Connections must complete the TLS handshake and log in within 15 seconds or they are closed. Members that send nothing for 3 minutes are disconnected (clients send keepalives automatically); members that stop reading are disconnected once their queue is full or a write times out (30 s).

Built-in limits (not configurable): messages up to 8 KB; about 20 messages per second per member (bursts up to 60); at most 4 file transfers per member in each direction; offers expire after 5 minutes, stalled transfers after 2 minutes.

Usernames are 1–32 letters, digits, spaces, `_`, `-` or `.`. Room names start with `#` followed by 1–32 letters, digits, `_`, `-` or `.`.

## Security Features

### Encryption and Access

1. **TLS 1.3 only**
   - Ephemeral key exchange per connection: forward secrecy
   - The server generates a new certificate (ECDSA P-256, random name) on every start; its private key is kept in memory only
   - The certificate is part of `quietroom_access.pem`; clients pin it exactly, preventing man-in-the-middle attacks

2. **Access Key (mutual TLS)**
   - Server generates a master access key (ECDSA P-256) on every startup, stored in `quietroom_access.pem`
   - Every client must present this key during the TLS handshake; connections without it are refused before any QuietRoom protocol code runs
   - Rejected connections are recorded in the security log
   - A server restart rotates the key and revokes all previously distributed access files

3. **Trusted server**
   - The server decrypts and relays messages and files (by design); it never stores them

### Protocol (version 3)

- Every frame states its exact length; the receiver never guesses where a frame ends, so the stream cannot get out of sync
- Control messages are typed JSON; the server sets sender names and timestamps itself, so members cannot impersonate each other
- File data flows in its own frames with credit-based flow control; chat is always sent before file data, so it stays responsive during transfers
- See the [`wire`](wire/) package for the specification

### Traffic Padding and Decoys

- Every frame is padded to a size class (256 B, 512 B, 1 KB, ... 64 KB), hiding the length of messages
- Decoy frames are sent at random intervals (0.5–1.5 × the configured interval) in both directions, hiding when real messages are sent
- Decoy sizes are configurable

## Log Files

By default (`log_metadata: false`) the logs contain no information about participants. Server output (including `docker logs`) follows the same rule.

### Security Log (`security.log`), default

```
[SECURITY] 2026/11/22 15:30:45 Server started (protocol 3)
[SECURITY] 2026/11/22 15:31:02 Rejected connection from 203.0.113.7:51544: tls: client didn't provide a certificate
[SECURITY] 2026/11/22 15:32:00 Refused 12 connection(s) over connection limits in the last minute
[SECURITY] 2026/11/22 15:33:10 Malformed frame from [member]: malformed frame: unknown type 0x7f
```

### With `log_metadata: true`

```
2026/11/22 15:30:46 User joined: Alice from 192.168.1.100:54321
2026/11/22 15:30:58 DM: Alice -> Bob
```

## Generated Files

- `quietroom_access.pem` - Access file: server certificate + master access key (⚠️ **SECRET** — distribute only to participants; replaced on every start)
- The server private key is kept in memory only and is never written to disk
- `server_private.pem` / `chat_public.pem` from older versions are no longer used and can be deleted
- `server_config.json` - Configuration file
- `chat_server.log` - General activity log
- `security.log` - Security events log

## Port Forwarding

If running behind a firewall/router, forward the configured port:

```bash
# Example: Forward port 37842
sudo iptables -A INPUT -p tcp --dport 37842 -j ACCEPT

# Or using firewalld
sudo firewall-cmd --permanent --add-port=37842/tcp
sudo firewall-cmd --reload
```

## Systemd Service (Linux)

Create `/etc/systemd/system/chat-server.service`:

```ini
[Unit]
Description=Secure Chat Server
After=network.target

[Service]
Type=simple
User=chatserver
WorkingDirectory=/opt/chat-server
ExecStart=/opt/chat-server/chat_server
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable chat-server
sudo systemctl start chat-server
```

## Troubleshooting

### Server won't start

**Problem**: `Error starting server: listen tcp :37842: bind: address already in use`

**Solution**: Port is already in use. Either:
1. Stop the other service using that port
2. Change `port` in `server_config.json`

### No clients can connect

**Problem**: Clients timeout when connecting

**Solution**: Check firewall rules:
```bash
# Linux
sudo iptables -L -n | grep 37842

# Check if server is listening
netstat -tulpn | grep 37842
```

### Failed authentication attempts in logs

**Problem**: `Rejected connection from ...` in the security log

**Solution**: 
1. `access key not recognised` / `client didn't provide a certificate` means a client without a valid access file tried to connect: ensure clients have the current `quietroom_access.pem` (a server restart replaces it)
2. `No valid hello` usually means an outdated client: QuietRoom 3 servers need QuietRoom 3 clients

## Security Best Practices

1. ✅ **Use non-standard ports** - Avoid common ports like 8080, 3000
2. ✅ **Distribute PEM files offline** - USB, in-person, encrypted email
3. ✅ **Monitor security logs** - Watch for suspicious activity
4. ✅ **Keep server updated** - Rebuild with latest Go version
5. ✅ **Use strong system security** - Firewall, SELinux/AppArmor
6. ✅ **Protect the access file** - It is written with mode 600; keep it that way
7. ✅ **Run as non-root user** - Create dedicated user account

## Performance

### Resource Usage

- **Memory**: ~10-20 MB base + ~1-2 MB per connected client
- **CPU**: Minimal when idle; file transfers are limited by network and disk, not the server
- **Memory per transfer**: at most about 4 MB buffered (flow control)
- **Network**: one decoy of 256–512 bytes per client per ~30 s in each direction

## License

This project is licensed under the GNU Affero General Public License v3 (AGPL-3.0).

If you modify this software or run it as a network service, you are required
to make the complete corresponding source code available under the same license.

Commercial use as part of a proprietary product or service requires a separate
commercial license. Contact the author for details.

## Support

For issues, questions, or contributions, please open an issue on the project repository.
