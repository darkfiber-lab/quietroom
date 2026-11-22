# Secure Chat Server

A military-grade encrypted chat server with end-to-end encryption, perfect forward secrecy, and advanced anti-surveillance features.

## Features

- 🔐 **RSA-4096 Authentication** - Server identity verification
- 🔑 **Diffie-Hellman Key Exchange** - Perfect forward secrecy with ephemeral keys
- 🛡️ **AES-256-GCM Encryption** - Military-grade encryption for all messages
- 🕵️ **Traffic Obfuscation** - TLS-like packet structure to evade Deep Packet Inspection
- 🎭 **Decoy Traffic** - Hides activity patterns from traffic analysis
- 📝 **Security Logging** - Detailed logs of all authentication attempts and security events
- 👥 **Multi-client Support** - Concurrent connections with thread-safe broadcasting

## Installation

### Prerequisites

- Go 1.16 or higher
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
✓ Initialized Diffie-Hellman parameters (2048-bit)
✓ Access file saved to: quietroom_access.pem
⚠ COPY quietroom_access.pem to client machines before connecting — it is SECRET, anyone holding it can join!
⚠ Restarting the server invalidates the previous access file.
✓ Encrypted chat server started on port 37842
✓ Logging to: chat_server.log
✓ Security logging to: security.log
✓ Decoy traffic enabled (interval: 30s)
✓ Traffic obfuscation active (TLS-like)
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
  "max_new_connections_per_ip_per_minute": 30
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
- **Logs**: User joins/leaves, connection attempts, general activity
- **Example**: `"chat_server.log"`, `"/var/log/chat/server.log"`

#### `security_log_file` (string)
- **Description**: Path to security events log file
- **Default**: `"security.log"`
- **Logs**: 
  - Failed authentication attempts
  - Decryption errors
  - Key exchange failures
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

Unauthenticated connections must complete the TLS handshake, key exchange and username within 15 seconds or they are closed.

Room names must start with `#` followed by 1–32 letters, digits, `_`, `-` or `.`.

## Security Features

### Encryption Layers

1. **RSA-4096 Authentication**
   - Server generates a 4096-bit RSA key pair on every startup (kept in memory only)
   - The server certificate is part of `quietroom_access.pem`, distributed to clients offline
   - Clients pin it exactly, preventing man-in-the-middle attacks

2. **Access Key (mutual TLS)**
   - Server generates a master access key (ECDSA P-256) on every startup, stored in `quietroom_access.pem`
   - Every client must present this key during the TLS handshake; connections without it are refused before any chat data is exchanged
   - Rejected connections are recorded in the security log
   - A server restart rotates the key and revokes all previously distributed access files

3. **Diffie-Hellman Key Exchange**
   - 2048-bit MODP Group (RFC 3526)
   - Ephemeral keys generated per session
   - Perfect forward secrecy - past sessions stay secure even if RSA key is compromised

4. **AES-256-GCM**
   - Session encryption using DH-derived keys
   - Authenticated encryption prevents tampering
   - 256-bit key strength

### Traffic Obfuscation

- **TLS-like Packet Structure**: Makes traffic appear as HTTPS to Deep Packet Inspection
- **Random Padding**: 0-255 bytes of random data per packet
- **Variable Message Sizes**: Hides actual message length

### Decoy Traffic

- Sends random encrypted packets at regular intervals
- Makes it impossible to determine when real messages are sent
- Configurable frequency and size

## Log Files

### General Log (`chat_server.log`)

```
2024/12/11 15:30:45 New connection attempt from 192.168.1.100:54321
2024/12/11 15:30:46 User joined: Alice from 192.168.1.100:54321
2024/12/11 15:31:20 User left: Alice from 192.168.1.100:54321
```

### Security Log (`security.log`)

```
[SECURITY] 2024/12/11 15:30:45 Server started with enhanced security features
[SECURITY] 2024/12/11 15:30:46 Diffie-Hellman key exchange completed with 192.168.1.100:54321
[SECURITY] 2024/12/11 15:30:46 Successful authentication: Alice from 192.168.1.100:54321
[SECURITY] 2024/12/11 15:31:00 Decryption error from Alice (192.168.1.100:54321): cipher: message authentication failed
[SECURITY] 2024/12/11 15:32:00 Failed key exchange: Invalid base64 from 192.168.1.200:12345
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

**Problem**: `[SECURITY] Failed key exchange: Decryption failed`

**Solution**: 
1. Ensure clients have the current `quietroom_access.pem` (a server restart replaces it)
2. `Rejected connection from ...: access key not recognised` / `client didn't provide a certificate` means a client without a valid access file tried to connect
3. Check for man-in-the-middle attacks

## Security Best Practices

1. ✅ **Use non-standard ports** - Avoid common ports like 8080, 3000
2. ✅ **Distribute PEM files offline** - USB, in-person, encrypted email
3. ✅ **Monitor security logs** - Watch for suspicious activity
4. ✅ **Keep server updated** - Rebuild with latest Go version
5. ✅ **Use strong system security** - Firewall, SELinux/AppArmor
6. ✅ **Restrict file permissions** - `chmod 600 server_private.pem`
7. ✅ **Run as non-root user** - Create dedicated user account

## Performance

### Resource Usage

- **Memory**: ~10-20 MB base + ~1-2 MB per connected client
- **CPU**: Minimal (<1% idle), ~5-10% during active encryption
- **Network**: ~100-500 bytes/30s per client (decoy traffic)

## License

This project is licensed under the GNU Affero General Public License v3 (AGPL-3.0).

If you modify this software or run it as a network service, you are required
to make the complete corresponding source code available under the same license.

Commercial use as part of a proprietary product or service requires a separate
commercial license. Contact the author for details.

## Support

For issues, questions, or contributions, please open an issue on the project repository.

## Version

Current Version: 1.0.0