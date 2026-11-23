#!/usr/bin/env python3
"""
Copyright (C) 2026 darkfiber-lab

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, version 3.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

quietroom_connector.py

A persistent connection client for QuietRoom (protocol 3). Handles TLS 1.3
with the access key, the framed message protocol and keepalives, and exposes
a callback-based interface for building bots, bridges and other automated
clients. Uses only the Python standard library.

Protocol notes
--------------
- Every frame is | length (4) | type (1) | flags (1) | padding length (2) |
  payload | padding |. Control frames carry one JSON message; decoy frames
  are discarded; data frames carry file transfers (not supported by the
  connector: file offers are declined automatically).
- The server closes connections that send nothing for 3 minutes. Decoy
  traffic (enabled by default) or a keepalive every 60 seconds prevents this.
- Room messages are sent with send_room_message(); you must have joined the
  room first.

Usage
-----
    from quietroom_connector import QuietRoomConnector, ConnectorConfig

    cfg = ConnectorConfig(server_host="myserver.local", username="MyBot")
    conn = QuietRoomConnector(cfg)

    conn.on_dm(lambda sender, msg: print(f"DM from {sender}: {msg}"))
    conn.on_room_message(lambda room, sender, msg: print(f"[{room}] {sender}: {msg}"))
    conn.on_system_message(lambda text: print(f"System: {text}"))

    conn.connect()
    conn.join_room("#general")
    conn.send_room_message("#general", "Hello room!")
    conn.send_message("Hello lobby!")

    # connection stays alive until conn.disconnect() or process exit
"""

import json
import logging
import os
import re
import secrets
import socket
import ssl
import struct
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

log = logging.getLogger("quietroom.connector")

PROTOCOL_VERSION = 3


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ConnectorError(Exception):
    """Raised for unrecoverable connector errors (config, setup, login)."""


class SecurityError(ConnectorError):
    """Raised when a security check fails (access file, certificate pin)."""


class ConnectionLostError(ConnectorError):
    """Raised when the server connection drops unexpectedly."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class ConnectorConfig:
    server_host: str = "localhost"
    server_port: int = 37842
    cert_file: str = "quietroom_access.pem"   # access file distributed by the server
    username: str = "Bot"

    # Decoy traffic: random cover frames at random intervals around
    # decoy_interval. Also keeps the connection alive.
    decoy_traffic: bool = True
    decoy_interval: int = 30        # mean seconds between decoys
    decoy_min_bytes: int = 100
    decoy_max_bytes: int = 500

    # Keepalive interval used when decoy_traffic is False
    keepalive_interval: int = 60

    # How long to wait for the server during connect and login
    connect_timeout: int = 30


# ---------------------------------------------------------------------------
# Parsed message types
# ---------------------------------------------------------------------------

@dataclass
class ChatMessage:
    """A chat message from the lobby or a room."""
    timestamp: str
    sender: str
    text: str
    room: Optional[str] = None   # None = lobby


@dataclass
class DirectMessage:
    """A direct message."""
    sender: str
    text: str


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------

FRAME_CONTROL = 0x01
FRAME_DECOY   = 0x02
FRAME_DATA    = 0x03

_MAX_FRAME = 64 * 1024
_MIN_FRAME = 256
_HEADER = 4  # type, flags, padding length (after the length field)


def _bucket(n: int) -> int:
    size = _MIN_FRAME
    while size < n:
        size *= 2
    return min(size, _MAX_FRAME)


def _encode_frame(frame_type: int, payload: bytes, min_size: int = 0) -> bytes:
    """Build a padded frame (see the protocol notes above)."""
    n = 4 + _HEADER + len(payload)
    if n > _MAX_FRAME:
        raise ValueError(f"payload too large: {len(payload)} bytes")
    size = _bucket(max(n, min_size))
    pad = size - n
    return struct.pack(">IBBH", size - 4, frame_type, 0, pad) + payload + bytes(pad)


def _encode_msg(msg: dict) -> bytes:
    return _encode_frame(FRAME_CONTROL, json.dumps(msg, separators=(",", ":")).encode())


def _read_exact(sock: ssl.SSLSocket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionLostError("Connection closed by server")
        buf += chunk
    return bytes(buf)


def _read_frame(sock: ssl.SSLSocket) -> tuple[int, bytes]:
    """Read exactly one frame. Returns (frame_type, payload)."""
    (length,) = struct.unpack(">I", _read_exact(sock, 4))
    if length < _HEADER or length > _MAX_FRAME - 4:
        raise ConnectorError(f"protocol error: frame length {length}")
    body = _read_exact(sock, length)
    frame_type, flags, pad = struct.unpack(">BBH", body[:4])
    if flags != 0 or pad > length - _HEADER or frame_type not in (FRAME_CONTROL, FRAME_DECOY, FRAME_DATA):
        raise ConnectorError("protocol error: malformed frame (is the server QuietRoom 3?)")
    return frame_type, body[_HEADER:length - pad]


ACCESS_FILE_NAME = "quietroom_access.pem"

_PEM_BLOCK_RE = re.compile(r"-----BEGIN ([A-Z ]+)-----.*?-----END \1-----", re.S)


def _load_access_bundle(path: str) -> tuple[bytes, str]:
    """
    Parse an access file: the pinned server certificate followed by the master
    access certificate and its private key.

    Returns (server_cert_der, access_cert_and_key_pem).
    """
    with open(path, "r", encoding="ascii") as f:
        text = f.read()

    certs: list[str] = []
    key: Optional[str] = None
    for m in _PEM_BLOCK_RE.finditer(text):
        kind, block = m.group(1), m.group(0) + "\n"
        if kind == "CERTIFICATE":
            certs.append(block)
        elif kind in ("PRIVATE KEY", "EC PRIVATE KEY") and key is None:
            key = block

    if len(certs) != 2 or key is None:
        raise SecurityError(
            f"'{path}' is not a valid access file (it must contain the server "
            f"certificate and the access key). Get the current {ACCESS_FILE_NAME} "
            "from your server administrator."
        )
    return ssl.PEM_cert_to_DER_cert(certs[0]), certs[1] + key


def _load_client_cert(ctx: ssl.SSLContext, cert_and_key_pem: str):
    """
    ssl.SSLContext.load_cert_chain only accepts file paths, so the access
    certificate and key are written to a private (0600) temp file that is
    removed immediately after loading.
    """
    fd, tmp_path = tempfile.mkstemp(prefix=".qr_access_", suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(cert_and_key_pem)
        ctx.load_cert_chain(tmp_path)
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Callback type aliases
# ---------------------------------------------------------------------------

OnDMCallback            = Callable[[str, str], None]        # (sender, message)
OnRoomMessageCallback   = Callable[[str, str, str], None]   # (room, sender, message)
OnMessageCallback       = Callable[[str], None]             # (text) — every message, rendered as text
OnSystemMessageCallback = Callable[[str], None]             # (text) — server notices only
OnPresenceCallback      = Callable[[str, str, Optional[str]], None]  # (event "joined"/"left", user, room or None)
OnDisconnectCallback    = Callable[[Optional[Exception]], None]


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------

class QuietRoomConnector:
    """
    Persistent QuietRoom connection.

    Maintains an open TLS socket and background receive loop for the lifetime
    of the object. Callers register callbacks and use send_* methods to
    interact with the server.

    Thread safety
    -------------
    All send_*() methods are safe to call from any thread.
    Callbacks are invoked from the internal receive thread — keep them short
    or hand off work to your own thread pool to avoid blocking the receive loop.

    Own messages
    ------------
    The server echoes your own chat and room messages back; callbacks do not
    receive them (on_message still does).
    """

    def __init__(self, config: ConnectorConfig):
        self._cfg = config
        self._sock: Optional[ssl.SSLSocket] = None
        self._server_cert_der: Optional[bytes] = None
        self._access_pem: Optional[str] = None
        self._send_lock = threading.Lock()
        self._shutdown = threading.Event()
        self._shutdown_once = threading.Lock()
        self._did_shutdown = False

        self._joined_rooms: set[str] = set()
        self._rooms_lock = threading.Lock()

        self._dm_callbacks:             list[OnDMCallback]            = []
        self._room_message_callbacks:   list[OnRoomMessageCallback]   = []
        self._message_callbacks:        list[OnMessageCallback]       = []
        self._system_message_callbacks: list[OnSystemMessageCallback] = []
        self._presence_callbacks:       list[OnPresenceCallback]      = []
        self._disconnect_callbacks:     list[OnDisconnectCallback]    = []

        self._recv_thread:  Optional[threading.Thread] = None
        self._noise_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Public: callback registration
    # ------------------------------------------------------------------

    def on_dm(self, callback: OnDMCallback) -> "QuietRoomConnector":
        """
        Register a callback for incoming direct messages.
        Signature: callback(sender: str, message: str)
        Returns self for chaining.
        """
        self._dm_callbacks.append(callback)
        return self

    def on_room_message(self, callback: OnRoomMessageCallback) -> "QuietRoomConnector":
        """
        Register a callback for messages received in a room.
        Signature: callback(room: str, sender: str, message: str)
        Only fires for rooms — lobby messages do not trigger this callback.
        Returns self for chaining.
        """
        self._room_message_callbacks.append(callback)
        return self

    def on_message(self, callback: OnMessageCallback) -> "QuietRoomConnector":
        """
        Register a callback for ALL messages (chat, DMs, presence, notices),
        rendered as one line of text in the classic format, e.g.
        "[12:00:00] alice: hi" or "*** bob left the chat ***". Useful for logging.
        Signature: callback(text: str)
        Returns self for chaining.
        """
        self._message_callbacks.append(callback)
        return self

    def on_system_message(self, callback: OnSystemMessageCallback) -> "QuietRoomConnector":
        """
        Register a callback for server notices and command responses —
        /users, /rooms and /members output, errors, and join/leave notices.
        Signature: callback(text: str)
        Returns self for chaining.
        """
        self._system_message_callbacks.append(callback)
        return self

    def on_presence(self, callback: OnPresenceCallback) -> "QuietRoomConnector":
        """
        Register a callback for members joining or leaving the chat or a room.
        Signature: callback(event: "joined" | "left", user: str, room: str | None)
        room is None when the member joined or left the chat itself.
        Returns self for chaining.
        """
        self._presence_callbacks.append(callback)
        return self

    def on_disconnect(self, callback: OnDisconnectCallback) -> "QuietRoomConnector":
        """
        Register a callback fired when the connection drops.
        Signature: callback(reason: Exception | None)
        reason is None for a clean disconnect, an exception otherwise.
        Returns self for chaining.
        """
        self._disconnect_callbacks.append(callback)
        return self

    # ------------------------------------------------------------------
    # Public: connection lifecycle
    # ------------------------------------------------------------------

    def connect(self):
        """
        Establish the TLS connection, log in, and start the background
        receive loop. Blocks until login is complete.

        Raises:
            FileNotFoundError — access file not found
            SecurityError     — invalid access file, key rejected, certificate mismatch
            ConnectorError    — login refused (e.g. username taken) or protocol mismatch
            OSError           — network error during connect
        """
        self._validate_cert_file()
        self._sock = self._tls_connect()
        try:
            self._login()
        except (OSError, ConnectionLostError) as e:
            # In TLS 1.3 a rejected access key surfaces on the first read.
            msg = str(e).lower()
            if ("alert" in msg and "certificate" in msg) or isinstance(e, ConnectionLostError):
                raise SecurityError(
                    f"Access denied — the server rejected the access key. "
                    f"'{self._cfg.cert_file}' is wrong or outdated "
                    "(the server may have been restarted)."
                ) from e
            raise

        self._recv_thread = threading.Thread(target=self._receive_loop, name="qr-recv", daemon=True)
        self._recv_thread.start()
        self._noise_thread = threading.Thread(target=self._noise_loop, name="qr-noise", daemon=True)
        self._noise_thread.start()

        log.info("Connected to %s:%d as '%s'", self._cfg.server_host, self._cfg.server_port, self._cfg.username)

    def disconnect(self, reason: Optional[Exception] = None):
        """
        Gracefully disconnect: send quit, close the socket, stop threads.
        Safe to call multiple times.
        """
        with self._shutdown_once:
            if self._did_shutdown:
                return
            self._did_shutdown = True

        self._shutdown.set()
        with self._rooms_lock:
            self._joined_rooms.clear()

        if self._sock:
            try:
                self._send({"t": "quit"})
            except Exception:
                pass
            try:
                self._sock.close()
            except Exception:
                pass

        self._fire_disconnect(reason)
        log.info("Disconnected from server")

    @property
    def is_connected(self) -> bool:
        """True if the socket is open and the receive loop is running."""
        return (
            self._sock is not None
            and not self._shutdown.is_set()
            and self._recv_thread is not None
            and self._recv_thread.is_alive()
        )

    @property
    def joined_rooms(self) -> frozenset[str]:
        """The rooms this connector is in (as confirmed by the server)."""
        with self._rooms_lock:
            return frozenset(self._joined_rooms)

    # ------------------------------------------------------------------
    # Public: sending
    # ------------------------------------------------------------------

    def send_message(self, text: str):
        """Send a chat message to the lobby. Thread-safe."""
        self._send({"t": "chat", "text": text})

    def send_room_message(self, room: str, text: str):
        """
        Send a message to a room you have joined. Thread-safe.
        Raises ValueError if room does not start with #.
        """
        if not room.startswith("#"):
            raise ValueError(f"Room name must start with #, got: {room!r}")
        self._send({"t": "chat", "room": room, "text": text})

    def send_dm(self, recipient: str, text: str):
        """Send a direct message to a specific user. Thread-safe."""
        self._send({"t": "dm", "to": recipient, "text": text})

    def join_room(self, room: str, password: str = ""):
        """
        Join or create a room. room must start with #. joined_rooms is
        updated when the server confirms the join.
        """
        if not room.startswith("#"):
            raise ValueError(f"Room name must start with #, got: {room!r}")
        msg = {"t": "join", "room": room}
        if password:
            msg["password"] = password
        self._send(msg)

    def leave_room(self, room: str):
        """Leave a chat room."""
        if not room.startswith("#"):
            raise ValueError(f"Room name must start with #, got: {room!r}")
        self._send({"t": "leave", "room": room})

    def list_users(self):
        """Request the online user list; the answer arrives via on_system_message ('Online Users ...')."""
        self._send({"t": "users"})

    def list_members(self, room: str):
        """
        Request the member list for a #room or 'lobby'; the answer arrives via
        on_system_message ('Members of ...'). Password rooms are only visible
        to their members.
        """
        self._send({"t": "members", "room": room})

    def list_rooms(self):
        """Request the list of active rooms; the answer arrives via on_system_message."""
        self._send({"t": "rooms"})

    def send_command(self, command: str):
        """
        Run a slash command (/msg, /join, /leave, /rooms, /users, /members,
        /help, /quit). Plain text is sent to the lobby. File transfers are
        not supported by the connector.
        """
        command = command.strip()
        if not command.startswith("/"):
            self.send_message(command)
            return
        parts = command.split(None, 2)
        name = parts[0][1:].lower()
        args = parts[1:]
        if name == "msg" and len(args) == 2:
            self.send_dm(args[0], args[1])
        elif name == "join" and args:
            self.join_room(args[0], args[1] if len(args) > 1 else "")
        elif name == "leave" and args:
            self.leave_room(args[0])
        elif name in ("rooms", "users", "help"):
            self._send({"t": name})
        elif name == "members" and args:
            self.list_members(args[0])
        elif name == "quit":
            self.disconnect()
        else:
            raise ValueError(f"Unsupported or malformed command: {command!r}")

    # ------------------------------------------------------------------
    # Internal: TLS + cert pinning
    # ------------------------------------------------------------------

    def _validate_cert_file(self):
        if not os.path.exists(self._cfg.cert_file):
            raise FileNotFoundError(
                f"Access file '{self._cfg.cert_file}' not found. "
                f"Copy {ACCESS_FILE_NAME} from the server."
            )
        self._server_cert_der, self._access_pem = _load_access_bundle(self._cfg.cert_file)

    def _tls_connect(self) -> ssl.SSLSocket:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # manual pinning below
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        _load_client_cert(ctx, self._access_pem)  # master access key (mutual TLS)

        raw = socket.create_connection(
            (self._cfg.server_host, self._cfg.server_port),
            timeout=self._cfg.connect_timeout,
        )
        tls_sock = ctx.wrap_socket(raw, server_hostname=self._cfg.server_host)

        # Certificate pinning — compare raw DER bytes
        if tls_sock.getpeercert(binary_form=True) != self._server_cert_der:
            tls_sock.close()
            raise SecurityError(
                "Server certificate does not match the access file — either the server was "
                "restarted (get the new file) or the connection is being intercepted (possible MITM)"
            )
        log.debug("TLS established and certificate pinned")
        return tls_sock

    # ------------------------------------------------------------------
    # Internal: login
    # ------------------------------------------------------------------

    def _login(self):
        self._sock.settimeout(self._cfg.connect_timeout)
        self._send({"t": "hello", "v": PROTOCOL_VERSION, "user": self._cfg.username})
        while True:
            frame_type, payload = _read_frame(self._sock)
            if frame_type != FRAME_CONTROL:
                continue
            msg = json.loads(payload)
            if msg.get("t") == "error":
                self._sock.close()
                raise ConnectorError(msg.get("text", "login refused"))
            if msg.get("t") == "welcome":
                break
        self._sock.settimeout(None)
        log.debug("Login complete as '%s'", self._cfg.username)

    # ------------------------------------------------------------------
    # Internal: send
    # ------------------------------------------------------------------

    def _send(self, msg: dict):
        frame = _encode_msg(msg)
        with self._send_lock:
            self._sock.sendall(frame)

    # ------------------------------------------------------------------
    # Internal: receive loop
    # ------------------------------------------------------------------

    def _receive_loop(self):
        reason: Optional[Exception] = None
        try:
            while not self._shutdown.is_set():
                try:
                    frame_type, payload = _read_frame(self._sock)
                except (ConnectorError, OSError) as e:
                    if not self._shutdown.is_set():
                        reason = e
                        log.error("Connection lost: %s", e)
                    break
                if frame_type != FRAME_CONTROL:
                    continue  # decoys; file data is not supported
                try:
                    msg = json.loads(payload)
                except ValueError as e:
                    reason = ConnectorError(f"protocol error: {e}")
                    break
                if isinstance(msg, dict):
                    self._dispatch(msg)
        finally:
            if not self._did_shutdown:
                self.disconnect(reason)

    def _call(self, callbacks, *args):
        for cb in callbacks:
            try:
                cb(*args)
            except Exception:
                log.exception("callback raised")

    def _dispatch(self, msg: dict):
        t = msg.get("t")
        me = self._cfg.username
        if t == "chat":
            room, sender, text = msg.get("room") or None, msg.get("from", ""), msg.get("text", "")
            prefix = f"[{room}] " if room else ""
            self._call(self._message_callbacks, f"[{msg.get('time', '')}] {prefix}{sender}: {text}")
            if sender != me and room:
                self._call(self._room_message_callbacks, room, sender, text)
        elif t == "dm":
            sender, text = msg.get("from", ""), msg.get("text", "")
            if sender == me:
                self._call(self._message_callbacks, f"[DM to {msg.get('to', '')}]: {text}")
            else:
                self._call(self._message_callbacks, f"[DM from {sender}]: {text}")
                self._call(self._dm_callbacks, sender, text)
        elif t in ("joined", "left"):
            user, room = msg.get("user", ""), msg.get("room") or None
            if user == me and room:
                with self._rooms_lock:
                    if t == "joined":
                        self._joined_rooms.add(room)
                    else:
                        self._joined_rooms.discard(room)
            where = room if room else "the chat"
            text = f"*** {user} {t} {where} ***"
            self._call(self._message_callbacks, text)
            self._call(self._system_message_callbacks, text)
            self._call(self._presence_callbacks, t, user, room)
        elif t in ("info", "error"):
            text = msg.get("text", "")
            self._call(self._message_callbacks, text)
            self._call(self._system_message_callbacks, text)
        elif t == "file_offer":
            # Files are not supported: decline so the sender is not left waiting.
            try:
                self._send({"t": "file_decline", "id": msg.get("id", "")})
            except OSError:
                pass

    def _fire_disconnect(self, reason: Optional[Exception]):
        self._call(self._disconnect_callbacks, reason)

    # ------------------------------------------------------------------
    # Internal: decoys and keepalive
    # ------------------------------------------------------------------

    def _noise_loop(self):
        """
        Sends decoy frames at random intervals (0.5x-1.5x decoy_interval) when
        decoy traffic is enabled, otherwise a small keepalive frame every
        keepalive_interval, so the server does not drop the idle connection.
        """
        while not self._shutdown.is_set():
            if self._cfg.decoy_traffic:
                mean = max(1, self._cfg.decoy_interval)
                wait = mean / 2 + secrets.randbelow(mean * 1000 + 1) / 1000
                size = self._cfg.decoy_min_bytes + secrets.randbelow(
                    max(1, self._cfg.decoy_max_bytes - self._cfg.decoy_min_bytes + 1))
            else:
                wait, size = self._cfg.keepalive_interval, 0
            if self._shutdown.wait(timeout=min(wait, 60)):
                break
            frame = _encode_frame(FRAME_DECOY, secrets.token_bytes(16), size)
            try:
                with self._send_lock:
                    self._sock.sendall(frame)
            except Exception:
                break
