# QuietRoom Connector

A Python library for building automated clients on top of a QuietRoom server. Handles the full protocol stack — TLS, Diffie-Hellman key exchange, AES-256-GCM encryption, and obfuscated packet framing — and exposes a clean callback-based interface.

The connector maintains a persistent connection for as long as it runs. The username it registers appears on the server from the moment `connect()` returns until `disconnect()` is called or the process exits.

---

## Requirements

```bash
pip install cryptography
```

Python 3.11 or higher. `chat_public.pem` must be copied from the server to the working directory.

---

## Quick start

```python
from quietroom_connector import QuietRoomConnector, ConnectorConfig

cfg = ConnectorConfig(
    server_host="myserver.local",
    server_port=37842,
    username="MyBot",
)

conn = QuietRoomConnector(cfg)
conn.on_dm(lambda sender, msg: print(f"DM from {sender}: {msg}"))
conn.connect()

conn.send_dm("alice", "Hello from the bot!")

import time
try:
    while conn.is_connected:
        time.sleep(1)
except KeyboardInterrupt:
    conn.disconnect()
```

---

## Configuration

All options are set via `ConnectorConfig`:

| Field | Type | Default | Description |
|---|---|---|---|
| `server_host` | str | `"localhost"` | Hostname or IP of the QuietRoom server |
| `server_port` | int | `37842` | Server port |
| `cert_file` | str | `"chat_public.pem"` | Path to the pinned server certificate |
| `username` | str | `"Bot"` | Username to register on the server |
| `decoy_traffic` | bool | `True` | Send random padding traffic at intervals |
| `decoy_interval` | int | `30` | Seconds between decoy bursts |
| `decoy_min_bytes` | int | `100` | Minimum decoy payload size |
| `decoy_max_bytes` | int | `500` | Maximum decoy payload size |
| `connect_timeout` | int | `30` | Socket timeout during initial connection |

---

## Callbacks

Callbacks are registered before calling `connect()` and fired from the internal receive thread. Keep callback implementations short and hand off heavy work to your own thread pool.

### `on_dm(callback)`

Fired when a direct message arrives addressed to the bot's username.

```python
def handle_dm(sender: str, message: str):
    print(f"{sender} says: {message}")

conn.on_dm(handle_dm)
```

Multiple callbacks can be registered and are fired in registration order.

---

### `on_message(callback)`

Fired for every decrypted text packet: DMs, room messages, and server notices. Use this to build a general-purpose client or full logger.

```python
conn.on_message(lambda text: print(f"RAW: {text}"))
```

---

### `on_disconnect(callback)`

Fired when the connection drops, whether cleanly or due to an error.

```python
def handle_disconnect(reason):
    if reason:
        print(f"Lost connection: {reason}")
    else:
        print("Disconnected cleanly")

conn.on_disconnect(handle_disconnect)
```

`reason` is `None` for a clean disconnect. It is an exception instance if the connection dropped unexpectedly.

---

## Sending

All send methods are thread-safe.

### `send_dm(recipient, text)`

Send a direct message to a specific user.

```python
conn.send_dm("alice", "Hello!")
```

### `send_message(text)`

Send a raw chat message to the lobby or the bot's current room.

```python
conn.send_message("Hello everyone")
```

### `join_room(room, password="")`

Join a room. Room names must start with `#`.

```python
conn.join_room("#general")
conn.join_room("#private", password="secret")
```

### `leave_room(room)`

Leave a room.

```python
conn.leave_room("#general")
```

---

## Connection lifecycle

```python
conn.connect()       # blocks until login complete, then starts background threads
conn.is_connected    # True while receive loop is running
conn.disconnect()    # graceful shutdown: sends /quit, closes socket
```

`disconnect()` is safe to call multiple times and from any thread.

---

## Error handling

| Exception | When raised |
|---|---|
| `FileNotFoundError` | `cert_file` not found at `connect()` time |
| `SecurityError` | Certificate mismatch or invalid DH key from server |
| `ConnectorError` | Handshake or login failure |
| `ConnectionLostError` | Server closed the connection mid-session |
| `OSError` | Network-level failure |

```python
from quietroom_connector import ConnectorError, SecurityError

try:
    conn.connect()
except SecurityError as e:
    print(f"Security check failed: {e}")
    sys.exit(1)
except ConnectorError as e:
    print(f"Could not connect: {e}")
    sys.exit(1)
```

---

## Full example: echo bot

```python
import time
import signal
from quietroom_connector import QuietRoomConnector, ConnectorConfig

cfg = ConnectorConfig(server_host="localhost", username="EchoBot")
conn = QuietRoomConnector(cfg)

conn.on_dm(lambda sender, msg: conn.send_dm(sender, f"Echo: {msg}"))
conn.on_disconnect(lambda reason: print("Disconnected:", reason))

signal.signal(signal.SIGINT, lambda s, f: conn.disconnect())

conn.connect()
print("Echo bot running. Ctrl+C to stop.")

while conn.is_connected:
    time.sleep(1)
```

---

## Security notes

- **Certificate pinning** - the connector compares the server's TLS certificate byte-for-byte against `chat_public.pem` and will refuse to connect if they do not match.
- **DH key validation** - the server's Diffie-Hellman public key is validated to be in the range `(1, P-1)` before computing the shared secret, blocking small subgroup attacks.
- **Decoy traffic** - when enabled, random padding packets are sent at intervals to obscure communication patterns.
- All session keys are held in memory only and never written to disk.
