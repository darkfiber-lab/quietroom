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
conn.on_room_message(lambda room, sender, msg: print(f"[{room}] {sender}: {msg}"))
conn.connect()

conn.send_dm("alice", "Hello!")
conn.join_room("#general")
conn.send_room_message("#general", "Hello room!")

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
| `keepalive_interval` | int | `60` | Seconds between keepalive packets when decoy traffic is disabled |
| `connect_timeout` | int | `30` | Socket timeout during initial connection |

### Keepalive behaviour

The server closes idle connections after approximately 3 minutes of no traffic. When `decoy_traffic=True` (the default), decoy packets sent at `decoy_interval` prevent this. When `decoy_traffic=False`, the connector automatically sends a minimal keepalive packet every `keepalive_interval` seconds instead. You do not need to manage this manually.

---

## Callbacks

Callbacks are registered before calling `connect()` and fired from the internal receive thread. Keep callback implementations short and hand off heavy work to your own thread pool.

### `on_dm(callback)`

Fired when a direct message arrives addressed to the connector's username.

```python
def handle_dm(sender: str, message: str):
    print(f"DM from {sender}: {message}")

conn.on_dm(handle_dm)
```

Multiple callbacks can be registered and are fired in registration order.

---

### `on_room_message(callback)`

Fired when a message arrives in a room the connector has joined. Does not fire for lobby messages.

```python
def handle_room_message(room: str, sender: str, message: str):
    print(f"[{room}] {sender}: {message}")

conn.on_room_message(handle_room_message)
```

---

### `on_system_message(callback)`

Fired for server notices and command responses — join/leave events, `/users` output, `/rooms` output, error messages, and anything else that is not a chat message or DM.

```python
def handle_system(text: str):
    print(f"Server: {text}")

conn.on_system_message(handle_system)
```

---

### `on_message(callback)`

Fired for every decrypted text packet without exception — DMs, room messages, lobby messages, and server notices. Use this for logging or building a general-purpose client.

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

`reason` is `None` for a clean disconnect and an exception instance if the connection dropped unexpectedly.

---

## Sending

All send methods are thread-safe.

### `send_message(text)`

Send a chat message to the lobby.

```python
conn.send_message("Hello lobby")
```

### `send_room_message(room, text)`

Send a message to a specific room. The room prefix is prepended automatically. You must have joined the room first.

```python
conn.join_room("#general")
conn.send_room_message("#general", "Hello room!")
```

Raises `ValueError` if `room` does not start with `#`.

### `send_dm(recipient, text)`

Send a direct message to a specific user.

```python
conn.send_dm("alice", "Hello!")
```

### `join_room(room, password="")`

Join a room. Room names must start with `#`. The room is tracked locally so `send_room_message()` can validate membership.

```python
conn.join_room("#general")
conn.join_room("#private", password="secret")
```

### `leave_room(room)`

Leave a room.

```python
conn.leave_room("#general")
```

### `list_users()`

Request the global online user list. The response arrives asynchronously via the `on_system_message` callback as a string starting with `Online Users`.

```python
conn.list_users()
```

### `list_members(room)`

Request the member list for a specific room or the lobby. Pass a `#roomname` or the string `"lobby"`. The response arrives asynchronously via `on_system_message` as a string starting with `Members of`. For password-protected rooms the server returns an access denied message if the connector is not a member.

```python
conn.list_members("#general")
conn.list_members("lobby")
```

### `list_rooms()`

Request the list of active rooms. The response arrives asynchronously via `on_system_message`.

```python
conn.list_rooms()
```

### `send_command(command)`

Send a raw command string for any server command not covered by the named methods.

```python
conn.send_command("/help")
```

---

## Connection lifecycle

```python
conn.connect()          # blocks until login complete, then starts background threads
conn.is_connected       # True while receive loop is running
conn.joined_rooms       # frozenset of rooms currently joined
conn.disconnect()       # graceful shutdown: sends /quit, closes socket
```

`disconnect()` is safe to call multiple times and from any thread.

`joined_rooms` is updated automatically as the connector joins and leaves rooms, including when join/leave confirmations arrive from the server.

---

## Error handling

| Exception | When raised |
|---|---|
| `FileNotFoundError` | `cert_file` not found at `connect()` time |
| `SecurityError` | Certificate mismatch or invalid DH key from server |
| `ConnectorError` | Handshake, login failure, or username already taken |
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

## Full example: room monitor bot

```python
import time
import signal
from quietroom_connector import QuietRoomConnector, ConnectorConfig

cfg = ConnectorConfig(server_host="localhost", username="Monitor")
conn = QuietRoomConnector(cfg)

def on_dm(sender, message):
    print(f"DM from {sender}: {message}")
    conn.send_dm(sender, f"Echo: {message}")

def on_room_msg(room, sender, message):
    print(f"[{room}] {sender}: {message}")

def on_system(text):
    print(f"[server] {text}")

def on_disconnect(reason):
    print("Disconnected:", reason or "clean")

conn.on_dm(on_dm)
conn.on_room_message(on_room_msg)
conn.on_system_message(on_system)
conn.on_disconnect(on_disconnect)

signal.signal(signal.SIGINT, lambda s, f: conn.disconnect())

conn.connect()
conn.join_room("#general")
conn.join_room("#random")

print(f"Monitor running. Joined rooms: {conn.joined_rooms}")
print("Ctrl+C to stop.")

while conn.is_connected:
    time.sleep(1)
```

---

## Security notes

- **Certificate pinning** — the connector compares the server's TLS certificate byte-for-byte against `chat_public.pem` and refuses to connect if they do not match, blocking man-in-the-middle attacks.
- **DH key validation** — the server's Diffie-Hellman public key is validated to be in the range `(1, P-1)` before computing the shared secret, blocking small subgroup attacks.
- **Room membership validation** — the server validates that the connector is a member of a room before routing messages to it. Sending to a room you have not joined returns an error and the message is not delivered.
- **Decoy traffic** — when enabled, random padding packets are sent at intervals to obscure communication patterns from traffic analysis.
- All session keys are held in memory only and never written to disk.