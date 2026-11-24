# QuietRoom Connector

A Python library for building automated clients on top of a QuietRoom server. Handles the full protocol stack (QuietRoom protocol 3: TLS 1.3 with the access key, framed and padded messages, decoys and keepalives) and exposes a clean callback-based interface. It uses only the Python standard library.

The connector maintains a persistent connection for as long as it runs. The username it registers appears on the server from the moment `connect()` returns until `disconnect()` is called or the process exits.

---

## Requirements

No packages to install: the connector uses only the Python standard library.

Python 3.11 or higher, and a QuietRoom 3 server. `quietroom_access.pem` must be copied from the server to the working directory. It is secret (it contains the access key) and is replaced every time the server restarts.

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
| `cert_file` | str | `"quietroom_access.pem"` | Path to the access file (pinned server certificate + access key) |
| `username` | str | `"Bot"` | Username to register on the server |
| `decoy_traffic` | bool | `True` | Send random padding traffic at intervals |
| `decoy_interval` | int | `30` | Mean seconds between decoys (each wait is random, 0.5–1.5 × this value) |
| `decoy_min_bytes` | int | `100` | Minimum decoy payload size |
| `decoy_max_bytes` | int | `500` | Maximum decoy payload size |
| `keepalive_interval` | int | `60` | Seconds between keepalive packets when decoy traffic is disabled |
| `connect_timeout` | int | `30` | Socket timeout during initial connection |

### Keepalive behaviour

The server closes idle connections after approximately 3 minutes of no traffic. When `decoy_traffic=True` (the default), decoy frames sent around every `decoy_interval` seconds prevent this. When `decoy_traffic=False`, the connector automatically sends a minimal keepalive frame every `keepalive_interval` seconds instead. You do not need to manage this manually.

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

### `on_presence(callback)`

Fired when a member joins or leaves the chat or a room. `room` is `None` when the member joined or left the chat itself.

```python
def handle_presence(event: str, user: str, room: str | None):
    print(f"{user} {event} {room or 'the chat'}")

conn.on_presence(handle_presence)
```

---

### `on_message(callback)`

Fired for every message without exception — DMs (including your own sent DMs), room and lobby messages (including your own), presence and server notices — rendered as one line of text, e.g. `[12:00:00] [#room] alice: hi`, `[DM from bob]: hello` or `*** carol left the chat ***`. Use this for logging or building a general-purpose client.

`on_dm` and `on_room_message` never fire for your own messages.

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

Run a slash command (`/msg`, `/join`, `/leave`, `/rooms`, `/users`, `/members`, `/help`, `/quit`). Plain text is sent to the lobby. Raises `ValueError` for unsupported or malformed commands.

```python
conn.send_command("/help")
```

### File transfers

The connector does not support file transfers. Offers to the connector are declined automatically, so senders are not left waiting.

---

## Connection lifecycle

```python
conn.connect()          # blocks until login complete, then starts background threads
conn.is_connected       # True while receive loop is running
conn.joined_rooms       # frozenset of rooms currently joined
conn.disconnect()       # graceful shutdown: sends quit, closes socket
```

`disconnect()` is safe to call multiple times and from any thread.

`joined_rooms` is updated when the server confirms a join or leave.

---

## Error handling

| Exception | When raised |
|---|---|
| `FileNotFoundError` | `cert_file` not found at `connect()` time |
| `SecurityError` | Certificate mismatch, invalid access file, or access key rejected by the server |
| `ConnectorError` | Login refused (username taken or invalid), or the server speaks another protocol version |
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

- **Gate token** — the TLS server name carries a one-time token derived from the access key, without which the server stays silent; the computer's clock must be within 5 minutes of the server's
- **Certificate pinning** — the connector compares the server's TLS certificate byte-for-byte against the certificate in `quietroom_access.pem` and refuses to connect if they do not match, blocking man-in-the-middle attacks.
- **TLS 1.3 only** — ephemeral keys per connection (forward secrecy); the connector presents the access key from `quietroom_access.pem`.
- **Strict framing** — every frame states its exact length; malformed frames end the connection instead of being guessed around.
- **Room membership validation** — the server validates that the connector is a member of a room before routing messages to it. Sending to a room you have not joined returns an error and the message is not delivered.
- **Padding and decoy traffic** — frames are padded to size classes, and random decoy frames at random intervals obscure communication patterns.
- The access key is loaded through a private temporary file that is deleted immediately; session keys are held in memory only.