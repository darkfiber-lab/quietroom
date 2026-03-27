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

A persistent connection client for the QuietRoom encrypted chat protocol.
Handles TLS, Diffie-Hellman key exchange, AES-256-GCM encryption, and the
obfuscated packet framing. Exposes a clean callback-based interface for
building bots, bridges, or any other automated client on top.

Protocol notes
--------------
- Room messages are routed by a [#roomname] prefix in the message body.
  The server validates sender membership before broadcasting and strips
  the prefix before delivery, so recipients never see it.
- The server closes idle connections after ~3 minutes of no traffic.
  Decoy traffic (enabled by default) prevents this. If you disable decoy
  traffic, the connector sends a minimal keepalive packet every 60 seconds
  automatically.
- Lobby messages carry no prefix. Any text sent via send_message() without
  a room prefix goes to the lobby.

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

import hashlib
import logging
import os
import re
import secrets
import socket
import ssl
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

log = logging.getLogger("quietroom.connector")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ConnectorError(Exception):
    """Raised for unrecoverable connector errors (config, setup)."""


class SecurityError(ConnectorError):
    """Raised when a security check fails (cert pin, DH validation)."""


class ConnectionLostError(ConnectorError):
    """Raised when the server connection drops unexpectedly."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class ConnectorConfig:
    server_host: str = "localhost"
    server_port: int = 37842
    cert_file: str = "chat_public.pem"
    username: str = "Bot"

    # Decoy traffic — mirrors the Go client behaviour to avoid traffic analysis.
    # Also serves as a keepalive — the server closes idle connections after
    # ~3 minutes. If decoy_traffic is False, a minimal keepalive is sent
    # automatically every 60 seconds instead.
    decoy_traffic: bool = True
    decoy_interval: int = 30        # seconds between decoy bursts
    decoy_min_bytes: int = 100
    decoy_max_bytes: int = 500

    # Keepalive interval used when decoy_traffic is False
    keepalive_interval: int = 60

    # How long to wait for the server during handshake
    connect_timeout: int = 30


# ---------------------------------------------------------------------------
# Parsed message types
# ---------------------------------------------------------------------------

@dataclass
class ChatMessage:
    """A parsed timestamped chat message from the lobby or a room."""
    timestamp: str
    sender: str
    text: str
    room: Optional[str] = None   # None = lobby


@dataclass
class DirectMessage:
    """A parsed direct message."""
    sender: str
    text: str


# ---------------------------------------------------------------------------
# DH + AES-256-GCM — protocol crypto layer
# ---------------------------------------------------------------------------

# RFC 3526 2048-bit MODP group — must match server
_DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_DH_G = 2


def _dh_generate_keypair() -> tuple[int, int]:
    private = secrets.randbelow(_DH_P - 2) + 1
    public = pow(_DH_G, private, _DH_P)
    return private, public


def _dh_validate_public(pub: int) -> bool:
    """Reject trivial and small-subgroup values."""
    return 1 < pub < (_DH_P - 1)


def _dh_shared_secret(private: int, other_public: int) -> bytes:
    shared = pow(other_public, private, _DH_P)
    raw = shared.to_bytes((shared.bit_length() + 7) // 8, "big")
    return hashlib.sha256(raw).digest()


def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def _aes_gcm_decrypt(key: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if len(data) < 12:
        raise ValueError("Ciphertext too short")
    return AESGCM(key).decrypt(data[:12], data[12:], None)


# ---------------------------------------------------------------------------
# Packet framing
# ---------------------------------------------------------------------------

PKT_MESSAGE = 0x01
PKT_DECOY   = 0x02
PKT_FILE    = 0x03

_MAX_PACKET_DATA = 32768


def _make_packet(msg_type: int, data: bytes) -> bytes:
    padding = secrets.token_bytes(secrets.randbelow(256))
    return struct.pack(">BH", msg_type, len(data)) + data + padding


def _read_exact(sock: ssl.SSLSocket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionLostError("Connection closed by server")
        buf += chunk
    return buf


def _read_packet(sock: ssl.SSLSocket) -> tuple[int, bytes]:
    """Read one obfuscated packet. Returns (msg_type, payload)."""
    header = _read_exact(sock, 3)
    msg_type, data_len = struct.unpack(">BH", header)

    if data_len > _MAX_PACKET_DATA:
        raise ValueError(f"Oversized packet: {data_len} bytes")

    data = _read_exact(sock, data_len)

    # Drain padding with a short deadline
    sock.settimeout(0.01)
    try:
        sock.recv(1024)
    except (socket.timeout, ssl.SSLWantReadError, OSError):
        pass
    finally:
        sock.settimeout(None)

    return msg_type, data


# ---------------------------------------------------------------------------
# Message parsing
# ---------------------------------------------------------------------------

# [15:04:05] username: text  (lobby)
# [15:04:05] [#roomname] username: text  (room)
_CHAT_RE = re.compile(
    r"^\[(\d{2}:\d{2}:\d{2})\] (?:\[(#\S+)\] )?(.+?): (.+)$",
    re.DOTALL,
)

# [DM from username]: text
_DM_RE = re.compile(r"^\[DM from ([^\]]+)\]:\s*(.*)", re.DOTALL)

# [DM to username]: text  (echo of our own DM)
_DM_SELF_RE = re.compile(r"^\[DM to ([^\]]+)\]:\s*(.*)", re.DOTALL)


def _parse_message(text: str) -> Optional[ChatMessage]:
    m = _CHAT_RE.match(text)
    if m:
        return ChatMessage(
            timestamp=m.group(1),
            room=m.group(2),      # None if lobby message
            sender=m.group(3).strip(),
            text=m.group(4).strip(),
        )
    return None


def _parse_dm(text: str) -> Optional[DirectMessage]:
    m = _DM_RE.match(text)
    if m:
        return DirectMessage(sender=m.group(1).strip(), text=m.group(2).strip())
    return None


def _is_system_message(text: str) -> bool:
    """
    Returns True for server notices, join/leave events, command responses
    and anything else that isn't a chat message or DM.
    """
    if _CHAT_RE.match(text):
        return False
    if _DM_RE.match(text):
        return False
    if _DM_SELF_RE.match(text):
        return False
    return True


# ---------------------------------------------------------------------------
# Callback type aliases
# ---------------------------------------------------------------------------

OnDMCallback          = Callable[[str, str], None]          # (sender, message)
OnRoomMessageCallback = Callable[[str, str, str], None]     # (room, sender, message)
OnMessageCallback     = Callable[[str], None]               # (raw_text) — all messages
OnSystemMessageCallback = Callable[[str], None]             # (text) — server notices only
OnDisconnectCallback  = Callable[[Optional[Exception]], None]


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

    Room routing
    ------------
    The server routes outgoing messages based on a [#roomname] prefix in the
    message body. Use send_room_message() to send to a room — it prepends the
    prefix automatically. Use send_message() for lobby messages.

    You must have joined a room with join_room() before sending to it.
    The server validates membership and will return an error if you attempt
    to send to a room you have not joined.
    """

    def __init__(self, config: ConnectorConfig):
        self._cfg = config
        self._sock: Optional[ssl.SSLSocket] = None
        self._session_key: Optional[bytes] = None
        self._send_lock = threading.Lock()
        self._shutdown = threading.Event()
        self._shutdown_once = threading.Lock()
        self._did_shutdown = False

        # Track joined rooms for validation
        self._joined_rooms: set[str] = set()
        self._rooms_lock = threading.Lock()

        # Registered callbacks
        self._dm_callbacks:           list[OnDMCallback]           = []
        self._room_message_callbacks: list[OnRoomMessageCallback]  = []
        self._message_callbacks:      list[OnMessageCallback]      = []
        self._system_message_callbacks: list[OnSystemMessageCallback] = []
        self._disconnect_callbacks:   list[OnDisconnectCallback]   = []

        # Background threads
        self._recv_thread:  Optional[threading.Thread] = None
        self._decoy_thread: Optional[threading.Thread] = None
        self._keepalive_thread: Optional[threading.Thread] = None

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
        Register a callback for ALL decrypted text packets including DMs,
        room messages, lobby messages, and server notices. Useful for logging.
        Signature: callback(text: str)
        Returns self for chaining.
        """
        self._message_callbacks.append(callback)
        return self

    def on_system_message(self, callback: OnSystemMessageCallback) -> "QuietRoomConnector":
        """
        Register a callback for server notices and command responses —
        join/leave events, /users output, /rooms output, error messages, etc.
        Signature: callback(text: str)
        Returns self for chaining.
        """
        self._system_message_callbacks.append(callback)
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
        Establish the TLS connection, perform the DH key exchange, log in,
        and start the background receive loop. Blocks until login is complete.

        Raises:
            FileNotFoundError     — cert_file not found
            SecurityError         — certificate mismatch or DH validation failure
            ConnectorError        — handshake or login failure
            OSError               — network error during connect
        """
        self._validate_cert_file()
        self._sock = self._tls_connect()
        self._perform_dh_exchange()
        self._login()

        self._recv_thread = threading.Thread(
            target=self._receive_loop,
            name="qr-recv",
            daemon=True,
        )
        self._recv_thread.start()

        if self._cfg.decoy_traffic:
            self._decoy_thread = threading.Thread(
                target=self._decoy_loop,
                name="qr-decoy",
                daemon=True,
            )
            self._decoy_thread.start()
            log.debug("Decoy traffic started (interval: %ds)", self._cfg.decoy_interval)
        else:
            # No decoy traffic — start a minimal keepalive to prevent the
            # server's idle checker from closing the connection
            self._keepalive_thread = threading.Thread(
                target=self._keepalive_loop,
                name="qr-keepalive",
                daemon=True,
            )
            self._keepalive_thread.start()
            log.debug(
                "Keepalive started (interval: %ds) — decoy traffic disabled",
                self._cfg.keepalive_interval,
            )

        log.info(
            "Connected to %s:%d as '%s'",
            self._cfg.server_host,
            self._cfg.server_port,
            self._cfg.username,
        )

    def disconnect(self, reason: Optional[Exception] = None):
        """
        Gracefully disconnect: send /quit, close the socket, stop threads.
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
                self._send_message("/quit")
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
        """The set of rooms this connector is currently joined to."""
        with self._rooms_lock:
            return frozenset(self._joined_rooms)

    # ------------------------------------------------------------------
    # Public: sending
    # ------------------------------------------------------------------

    def send_message(self, text: str):
        """
        Send a chat message to the lobby.
        Thread-safe. Raises OSError if the connection is lost.
        """
        self._send_message(text)

    def send_room_message(self, room: str, text: str):
        """
        Send a message to a specific room.
        The room prefix [#roomname] is prepended automatically.
        The server validates that this connector is a member of the room
        before routing — join_room() must have been called first.

        Thread-safe. Raises OSError if the connection is lost.
        Raises ValueError if room does not start with #.
        """
        if not room.startswith("#"):
            raise ValueError(f"Room name must start with #, got: {room!r}")
        self._send_message(f"[{room}] {text}")

    def send_dm(self, recipient: str, text: str):
        """
        Send a direct message to a specific user.
        Thread-safe. Raises OSError if the connection is lost.
        """
        self._send_message(f"/msg {recipient} {text}")

    def join_room(self, room: str, password: str = ""):
        """
        Join a chat room. room must start with #.
        The room is tracked locally so send_room_message() can validate it.
        """
        if not room.startswith("#"):
            raise ValueError(f"Room name must start with #, got: {room!r}")
        cmd = f"/join {room}"
        if password:
            cmd += f" {password}"
        self._send_message(cmd)
        with self._rooms_lock:
            self._joined_rooms.add(room)
        log.debug("Joined room %s", room)

    def leave_room(self, room: str):
        """Leave a chat room."""
        if not room.startswith("#"):
            raise ValueError(f"Room name must start with #, got: {room!r}")
        self._send_message(f"/leave {room}")
        with self._rooms_lock:
            self._joined_rooms.discard(room)
        log.debug("Left room %s", room)

    def list_users(self):
        """
        Request the global online user list from the server.
        The response arrives asynchronously via the on_system_message callback
        as a string starting with 'Online Users'.
        """
        self._send_message("/users")

    def list_members(self, room: str):
        """
        Request the member list for a room or the lobby.
        room should be a #roomname or the string 'lobby'.
        The response arrives asynchronously via the on_system_message callback
        as a string starting with 'Members of'.

        For password-protected rooms the server will return an access denied
        message if this connector is not a member.
        """
        self._send_message(f"/members {room}")

    def list_rooms(self):
        """
        Request the list of active rooms from the server.
        The response arrives asynchronously via the on_system_message callback.
        """
        self._send_message("/rooms")

    def send_command(self, command: str):
        """
        Send a raw command string. Use this for any server command not
        covered by the named methods above.
        """
        self._send_message(command)

    # ------------------------------------------------------------------
    # Internal: TLS + cert pinning
    # ------------------------------------------------------------------

    def _validate_cert_file(self):
        if not os.path.exists(self._cfg.cert_file):
            raise FileNotFoundError(
                f"Certificate file '{self._cfg.cert_file}' not found. "
                "Copy chat_public.pem from the server."
            )

    def _tls_connect(self) -> ssl.SSLSocket:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # manual pinning below

        raw = socket.create_connection(
            (self._cfg.server_host, self._cfg.server_port),
            timeout=self._cfg.connect_timeout,
        )
        tls_sock = ctx.wrap_socket(raw, server_hostname=self._cfg.server_host)

        # Certificate pinning — compare raw DER bytes
        peer_der = tls_sock.getpeercert(binary_form=True)
        with open(self._cfg.cert_file, "rb") as f:
            pinned_der = ssl.PEM_cert_to_DER_cert(f.read().decode())

        if peer_der != pinned_der:
            tls_sock.close()
            raise SecurityError(
                "Peer certificate does not match pinned certificate — possible MITM attack"
            )

        log.debug("TLS established and certificate pinned")
        tls_sock.settimeout(None)
        return tls_sock

    # ------------------------------------------------------------------
    # Internal: DH key exchange
    # ------------------------------------------------------------------

    def _perform_dh_exchange(self):
        sock = self._sock

        # Read server DH public key
        (srv_pub_len,) = struct.unpack(">I", _read_exact(sock, 4))
        if srv_pub_len > 4096:
            raise ConnectorError("Server DH key too large")
        srv_pub_bytes = _read_exact(sock, srv_pub_len)

        # Read RSA-PSS signature
        (sig_len,) = struct.unpack(">I", _read_exact(sock, 4))
        if sig_len > 4096:
            raise ConnectorError("Server signature too large")
        signature = _read_exact(sock, sig_len)

        # Verify signature against pinned certificate
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509 import load_pem_x509_certificate

        with open(self._cfg.cert_file, "rb") as f:
            cert = load_pem_x509_certificate(f.read())

        try:
            cert.public_key().verify(
                signature,
                srv_pub_bytes,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except Exception as e:
            raise SecurityError(f"Server authentication failed: {e}")

        log.debug("Server RSA-PSS signature verified")

        # Validate server DH public key — small subgroup attack prevention
        srv_pub = int.from_bytes(srv_pub_bytes, "big")
        if not _dh_validate_public(srv_pub):
            raise SecurityError("Server sent invalid DH public key")

        # Generate our keypair and send to server
        my_priv, my_pub = _dh_generate_keypair()
        my_pub_bytes = my_pub.to_bytes((my_pub.bit_length() + 7) // 8, "big")
        sock.sendall(struct.pack(">I", len(my_pub_bytes)))
        sock.sendall(my_pub_bytes)

        self._session_key = _dh_shared_secret(my_priv, srv_pub)
        log.debug("DH key exchange complete")

    # ------------------------------------------------------------------
    # Internal: login handshake
    # ------------------------------------------------------------------

    def _login(self):
        # Server sends "Enter your username:" prompt — read and discard
        _read_packet(self._sock)

        # Send our username
        self._send_message(self._cfg.username)

        # Read welcome message
        _, data = _read_packet(self._sock)
        welcome = self._decrypt(data)

        # Check for username taken error
        if "already taken" in welcome:
            self._sock.close()
            raise ConnectorError(welcome.strip())

        log.debug("Server: %s", welcome.strip())

        # Read help text
        _read_packet(self._sock)

        log.debug("Login complete as '%s'", self._cfg.username)

    # ------------------------------------------------------------------
    # Internal: encryption
    # ------------------------------------------------------------------

    def _encrypt(self, text: str) -> bytes:
        return _aes_gcm_encrypt(self._session_key, text.encode())

    def _decrypt(self, data: bytes) -> str:
        return _aes_gcm_decrypt(self._session_key, data).decode(errors="replace")

    # ------------------------------------------------------------------
    # Internal: send
    # ------------------------------------------------------------------

    def _send_message(self, text: str):
        encrypted = self._encrypt(text)
        packet = _make_packet(PKT_MESSAGE, encrypted)
        with self._send_lock:
            self._sock.sendall(packet)

    # ------------------------------------------------------------------
    # Internal: receive loop
    # ------------------------------------------------------------------

    def _receive_loop(self):
        reason: Optional[Exception] = None
        try:
            while not self._shutdown.is_set():
                try:
                    msg_type, data = _read_packet(self._sock)
                except (ConnectionLostError, OSError) as e:
                    if not self._shutdown.is_set():
                        reason = e
                        log.error("Connection lost: %s", e)
                    break
                except ValueError as e:
                    log.warning("Bad packet: %s", e)
                    continue

                if msg_type == PKT_DECOY:
                    continue
                if msg_type == PKT_FILE:
                    log.debug("File transfer packet received (ignored by connector)")
                    continue

                try:
                    text = self._decrypt(data)
                except Exception as e:
                    log.warning("Decryption error: %s", e)
                    continue

                text = text.strip()
                if not text:
                    continue

                self._dispatch(text)

        finally:
            if not self._did_shutdown:
                self.disconnect(reason)

    def _dispatch(self, text: str):
        """
        Parse and route a decrypted server message to the appropriate callbacks.

        Priority order:
          1. on_message fires for everything
          2. DMs → on_dm
          3. Room messages → on_room_message
          4. Everything else → on_system_message
        """

        # 1. Raw message — fires for everything
        for cb in self._message_callbacks:
            try:
                cb(text)
            except Exception:
                log.exception("on_message callback raised")

        # 2. Direct message
        dm = _parse_dm(text)
        if dm:
            for cb in self._dm_callbacks:
                try:
                    cb(dm.sender, dm.text)
                except Exception:
                    log.exception("on_dm callback raised")
            return

        # 3. Timestamped chat message (lobby or room)
        msg = _parse_message(text)
        if msg:
            if msg.room is not None:
                # Room message
                for cb in self._room_message_callbacks:
                    try:
                        cb(msg.room, msg.sender, msg.text)
                    except Exception:
                        log.exception("on_room_message callback raised")
            # Lobby messages have no dedicated callback beyond on_message
            return

        # 4. Own DM echo — [DM to username]: text
        if _DM_SELF_RE.match(text):
            # Suppress from system messages — it's just our own send confirmation
            return

        # 5. Server notice / command response / join+leave event
        for cb in self._system_message_callbacks:
            try:
                cb(text)
            except Exception:
                log.exception("on_system_message callback raised")

        # Also track room joins/leaves from system messages to keep
        # joined_rooms in sync with the server's actual state
        self._track_room_events(text)

    def _track_room_events(self, text: str):
        """
        Parse server join/leave notices to keep joined_rooms accurate.
        The server sends these when another user joins/leaves a room the
        connector is in, but we also use them to catch our own join/leave
        confirmations so the local set stays correct even if join_room()
        was called via send_command().
        """
        # "Joined room #roomname" or "Created and joined room #roomname"
        m = re.match(r"(?:Created and )?[Jj]oined room (#\S+)", text)
        if m:
            with self._rooms_lock:
                self._joined_rooms.add(m.group(1))
            return

        # "Left room #roomname - returned to lobby"
        m = re.match(r"[Ll]eft room (#\S+)", text)
        if m:
            with self._rooms_lock:
                self._joined_rooms.discard(m.group(1))

    def _fire_disconnect(self, reason: Optional[Exception]):
        for cb in self._disconnect_callbacks:
            try:
                cb(reason)
            except Exception:
                log.exception("on_disconnect callback raised")

    # ------------------------------------------------------------------
    # Internal: decoy traffic
    # ------------------------------------------------------------------

    def _decoy_loop(self):
        while not self._shutdown.is_set():
            self._shutdown.wait(timeout=self._cfg.decoy_interval)
            if self._shutdown.is_set():
                break
            size = self._cfg.decoy_min_bytes + secrets.randbelow(
                max(1, self._cfg.decoy_max_bytes - self._cfg.decoy_min_bytes)
            )
            packet = _make_packet(PKT_DECOY, secrets.token_bytes(size))
            with self._send_lock:
                try:
                    self._sock.sendall(packet)
                except Exception:
                    break

    # ------------------------------------------------------------------
    # Internal: keepalive (used when decoy traffic is disabled)
    # ------------------------------------------------------------------

    def _keepalive_loop(self):
        """
        Sends a minimal decoy packet at keepalive_interval to prevent the
        server's idle checker from closing the connection. Only runs when
        decoy_traffic is False.
        """
        while not self._shutdown.is_set():
            self._shutdown.wait(timeout=self._cfg.keepalive_interval)
            if self._shutdown.is_set():
                break
            # Send a single small decoy packet — just enough to reset the
            # server's idle timer without generating meaningful traffic
            packet = _make_packet(PKT_DECOY, secrets.token_bytes(16))
            with self._send_lock:
                try:
                    self._sock.sendall(packet)
                    log.debug("Keepalive sent")
                except Exception:
                    break