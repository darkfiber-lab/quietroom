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

A persistent connection client for QuietRoom (protocol 4). Handles TLS 1.3
with the access key, the framed message protocol, end-to-end encryption and
keepalives, and exposes a callback-based interface for building bots, bridges
and other automated clients. Needs the 'cryptography' package (50.0.2 or later)
for the end-to-end encryption; everything else is the standard library.

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
- Direct messages and password rooms are end-to-end encrypted: the server
  relays ciphertext it cannot read. The lobby and rooms without a password
  are not. safety_numbers() returns the numbers to compare with another
  member (see /verify in the QuietRoom clients).

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

import base64
import hashlib
import hmac
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

PROTOCOL_VERSION = 4


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
        raise ConnectorError("protocol error: malformed frame (is the server QuietRoom 4?)")
    return frame_type, body[_HEADER:length - pad]


ACCESS_FILE_NAME = "quietroom_access.pem"

_PEM_BLOCK_RE = re.compile(r"-----BEGIN ([A-Z ]+)-----.*?-----END \1-----", re.S)


# Gate: the server stays silent unless the ClientHello carries a fresh gate
# token as its server name (see wire/gate.go in the QuietRoom repository).
GATE_NONCE_LEN = 12
GATE_MAC_LEN = 16


def _gate_key(access_key_der: bytes) -> bytes:
    return hmac.new(access_key_der, b"quietroom gate v1", hashlib.sha256).digest()


def _gate_token(gate_key: bytes, now: Optional[float] = None) -> str:
    minute = int(time.time() if now is None else now) // 60
    nonce = secrets.token_bytes(GATE_NONCE_LEN)
    mac = hmac.new(gate_key, minute.to_bytes(8, "big", signed=True) + nonce, hashlib.sha256).digest()
    return (nonce + mac[:GATE_MAC_LEN]).hex()


def _pem_body(block: str) -> bytes:
    lines = [l for l in block.strip().splitlines() if not l.startswith("-----")]
    return base64.b64decode("".join(lines))


def _load_access_bundle(path: str) -> tuple[bytes, str, bytes]:
    """
    Parse an access file: the pinned server certificate followed by the master
    access certificate and its private key.

    Returns (server_cert_der, access_cert_and_key_pem, gate_key).
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
    return ssl.PEM_cert_to_DER_cert(certs[0]), certs[1] + key, _gate_key(_pem_body(key))


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
# End-to-end encryption (protocol 4)
# ---------------------------------------------------------------------------
#
# Mirrors the Go package e2e (see docs/E2E_DESIGN.md): every key is created
# per connection and kept in memory only. Direct messages and room keys travel
# on pairwise channels (X25519 + a KDF chain per direction); password rooms
# use one sending chain per member, signed with Ed25519. Requires the
# 'cryptography' package (50.0.2 or later).

try:
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    _CRYPTO_ERROR: Optional[str] = None
except ImportError as _e:  # pragma: no cover - reported on connect()
    _CRYPTO_ERROR = (
        "QuietRoom 4 encrypts direct messages and password rooms end to end and needs the "
        f"'cryptography' package, version 50.0.2 or later (pip install 'cryptography>=50.0.2'): {_e}"
    )

_L_PAIR      = b"QuietRoom v4 pair"
_L_PAIR_AAD  = b"QuietRoom v4 pair message"
_L_ROOM_SALT = b"QuietRoom v4 room salt"
_L_ROOM_VF   = b"QuietRoom v4 room verifier"
_L_ROOM_AUTH = b"QuietRoom v4 room auth"
_L_PROOF     = b"QuietRoom v4 room member"
_L_ROOM_AAD  = b"QuietRoom v4 room message"
_L_ROOM_SIG  = b"QuietRoom v4 room signature"

_KEY_LEN = 32
_MAX_PADDED = 32 * 1024
_MAX_SKIP = 1024
_MAX_STORED = 256
_NONCE0 = bytes(12)


class DecryptError(Exception):
    """A message did not authenticate (wrong key, tampered, replayed)."""


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s, max_len: int) -> bytes:
    if not isinstance(s, str) or len(s) > (max_len + 2) // 3 * 4:
        raise DecryptError("field too long")
    try:
        b = base64.b64decode(s, validate=True)
    except ValueError as e:
        raise DecryptError(str(e)) from e
    if len(b) > max_len:
        raise DecryptError("field too long")
    return b


def _pack(*fields: bytes) -> bytes:
    return b"".join(struct.pack(">I", len(f)) + f for f in fields)


def _u32(v: int) -> bytes:
    return struct.pack(">I", v)


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _hkdf(secret: bytes, info: bytes, length: int = _KEY_LEN) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(secret)


def _pad(b: bytes) -> bytes:
    size = 64
    while size < len(b) + 1:
        size *= 2
    if size > _MAX_PADDED:
        raise ValueError("message too large to encrypt")
    return b + b"\x80" + bytes(size - len(b) - 1)


def _unpad(b: bytes) -> bytes:
    s = b.rstrip(b"\x00")
    if not s or s[-1] != 0x80:
        raise DecryptError("bad padding")
    return s[:-1]


def _seal_once(key: bytes, plain: bytes, aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(_NONCE0, plain, aad)


def _open_once(key: bytes, ct: bytes, aad: bytes) -> bytes:
    try:
        return ChaCha20Poly1305(key).decrypt(_NONCE0, ct, aad)
    except InvalidTag as e:
        raise DecryptError("authentication failed") from e


def _step(ck: bytes) -> tuple[bytes, bytes]:
    return _hmac(ck, b"\x01"), _hmac(ck, b"\x02")


class _RecvChain:
    """Receiving KDF chain tolerating dropped and reordered messages."""

    def __init__(self, ck: bytes, n: int = 0):
        self.ck, self.n = ck, n
        self.skipped: dict[int, bytes] = {}

    def key(self, n: int):
        if n < self.n:
            if n not in self.skipped:
                raise DecryptError("replayed or too old")
            return self.skipped[n], lambda: self.skipped.pop(n, None)
        if n - self.n > _MAX_SKIP:
            raise DecryptError("too far ahead")
        ck, keys = self.ck, []
        for _ in range(self.n, n):
            mk, ck = _step(ck)
            keys.append(mk)
        mk, nck = _step(ck)

        def commit():
            for i, k in enumerate(keys):
                self.skipped[self.n + i] = k
            while len(self.skipped) > _MAX_STORED:
                self.skipped.pop(min(self.skipped))
            self.ck, self.n = nck, n + 1
        return mk, commit


class PublicKeys:
    """A member's session public keys (X25519 and Ed25519)."""

    def __init__(self, kx: bytes, sk: bytes):
        self.kx, self.sk = kx, sk

    @classmethod
    def parse(cls, kx, sk) -> "PublicKeys":
        k, s = _unb64(kx, _KEY_LEN), _unb64(sk, _KEY_LEN)
        if len(k) != _KEY_LEN or len(s) != _KEY_LEN:
            raise DecryptError("invalid public key")
        return cls(k, s)


class Identity:
    """This connection's session keys."""

    def __init__(self):
        self._kx = X25519PrivateKey.generate()
        self._sk = Ed25519PrivateKey.generate()
        raw = (Encoding.Raw, PublicFormat.Raw)
        self.public = PublicKeys(self._kx.public_key().public_bytes(*raw), self._sk.public_key().public_bytes(*raw))

    def pair(self, peer: PublicKeys) -> "Pair":
        return Pair(self, peer)

    def sign(self, data: bytes) -> bytes:
        return self._sk.sign(data)


class Pair:
    """Encrypted channel to one member: direct messages, file offers, room keys."""

    def __init__(self, me: Identity, peer: PublicKeys):
        if peer.kx == me.public.kx:
            raise DecryptError("cannot open a channel to ourselves")
        try:
            shared = me._kx.exchange(X25519PublicKey.from_public_bytes(peer.kx))
        except ValueError as e:  # low-order point
            raise DecryptError("invalid public key") from e
        lo, hi = (me.public, peer) if me.public.kx <= peer.kx else (peer, me.public)
        okm = _hkdf(shared, _pack(_L_PAIR, lo.kx, lo.sk, hi.kx, hi.sk), 2 * _KEY_LEN)
        lo_to_hi, hi_to_lo = okm[:_KEY_LEN], okm[_KEY_LEN:]
        self_first = lo is me.public
        self.me, self.peer = me.public, peer
        self._send_ck = lo_to_hi if self_first else hi_to_lo
        self._send_n = 0
        self._recv = _RecvChain(hi_to_lo if self_first else lo_to_hi)
        self._lock = threading.Lock()

    @staticmethod
    def _aad(kind: str, frm: PublicKeys, to: PublicKeys, n: int) -> bytes:
        return _pack(_L_PAIR_AAD, kind.encode(), frm.kx, to.kx, _u32(n))

    def seal(self, kind: str, plain: bytes) -> tuple[int, bytes]:
        padded = _pad(plain)
        with self._lock:
            mk, self._send_ck = _step(self._send_ck)
            n = self._send_n
            self._send_n += 1
        return n, _seal_once(mk, padded, self._aad(kind, self.me, self.peer, n))

    def open(self, kind: str, n: int, ct: bytes) -> bytes:
        with self._lock:
            mk, commit = self._recv.key(n)
            plain = _unpad(_open_once(mk, ct, self._aad(kind, self.peer, self.me, n)))
            commit()
            return plain


def safety_number(user: str, pub: PublicKeys) -> str:
    """A member's 30-digit safety number for one session (see /verify)."""
    keys = pub.kx + pub.sk
    h = hashlib.sha512(_pack(b"QuietRoom v4 safety number", user.lower().encode(), keys)).digest()
    for _ in range(5200):
        h = hashlib.sha512(h + keys).digest()
    return " ".join(f"{int.from_bytes(h[i * 5:i * 5 + 5], 'big') % 100000:05d}" for i in range(6))


class RoomSecret:
    """What a room password yields. The password never leaves this process."""

    def __init__(self, room: str, password: str):
        salt = hashlib.sha256(_pack(_L_ROOM_SALT, room.encode())).digest()
        secret = Argon2id(salt=salt, length=_KEY_LEN, iterations=3, lanes=4,
                          memory_cost=64 * 1024).derive(password.encode())
        self.room = room
        self.verifier = _hkdf(secret, _L_ROOM_VF)
        self._auth = _hkdf(secret, _L_ROOM_AUTH)

    def proof(self, user: str, pub: PublicKeys) -> bytes:
        return _hmac(self._auth, _pack(_L_PROOF, self.room.encode(), user.lower().encode(), pub.kx, pub.sk))

    def check(self, user: str, pub: PublicKeys, proof: bytes) -> bool:
        return hmac.compare_digest(self.proof(user, pub), proof)


def _room_aad(room: str, frm: PublicKeys, kid: int, n: int) -> bytes:
    return _pack(_L_ROOM_AAD, room.encode(), frm.kx, _u32(kid), _u32(n))


def _room_sig_input(room: str, kid: int, n: int, ct: bytes) -> bytes:
    return _pack(_L_ROOM_SIG, room.encode(), _u32(kid), _u32(n), ct)


class _Sender:
    """Our sending chain in one password room."""

    def __init__(self, room: str):
        self.room = room
        self.kid = int.from_bytes(secrets.token_bytes(4), "big")
        self.ck, self.n = secrets.token_bytes(_KEY_LEN), 0

    def seal(self, me: Identity, plain: bytes) -> tuple[int, int, bytes, bytes]:
        mk, self.ck = _step(self.ck)
        n = self.n
        self.n += 1
        ct = _seal_once(mk, _pad(plain), _room_aad(self.room, me.public, self.kid, n))
        return self.kid, n, ct, me.sign(_room_sig_input(self.room, self.kid, n, ct))


class _Receiver:
    """Another member's sending chain in one password room."""

    def __init__(self, room: str, frm: PublicKeys, kid: int, ck: bytes, n: int):
        self.room, self.frm, self.kid = room, frm, kid
        self._chain = _RecvChain(ck, n)

    def open(self, kid: int, n: int, ct: bytes, sig: bytes) -> bytes:
        if kid != self.kid:
            raise DecryptError("unknown key id")
        try:
            Ed25519PublicKey.from_public_bytes(self.frm.sk).verify(sig, _room_sig_input(self.room, kid, n, ct))
        except (InvalidSignature, ValueError) as e:
            raise DecryptError("bad signature") from e
        mk, commit = self._chain.key(n)
        plain = _unpad(_open_once(mk, ct, _room_aad(self.room, self.frm, kid, n)))
        commit()
        return plain


class _Member:
    def __init__(self):
        self.recv: Optional[_Receiver] = None
        self.sent_kid: Optional[int] = None


class _SecureRoom:
    def __init__(self, name: str, secret: RoomSecret):
        self.name, self.secret = name, secret
        self.sender = _Sender(name)
        self.members: dict[str, _Member] = {}
        self.pending: dict[str, list[dict]] = {}
        self.refused: set[str] = set()


def _hidden(c: int) -> bool:
    """Characters that change how text displays without being visible (as in
    wire.CleanText): bidi controls and zero-width characters."""
    return (0x202A <= c <= 0x202E or 0x2066 <= c <= 0x2069 or c in (0x200E, 0x200F, 0x061C)
            or c in (0x200B, 0x2060, 0xFEFF, 0x180E) or 0x2061 <= c <= 0x2064)


def _clean_text(s: str) -> str:
    """Remove control characters (except newline and tab) and hidden ones."""
    return "".join(ch for ch in s if ch in "\n\t" or not (
        ord(ch) < 32 or ord(ch) == 127 or 0x80 <= ord(ch) < 0xA0 or ch == "\ufffd" or _hidden(ord(ch))))


_MAX_CIPHER_B64 = (32 * 1024 + 16 + 2) // 3 * 4
_PEER_WAIT = 3.0


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
        self._gate_key: bytes = b""
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

        # End-to-end encryption state, guarded by _e2e_lock.
        self._id: Optional["Identity"] = None
        self._e2e_lock = threading.RLock()
        self._peer_added = threading.Condition(self._e2e_lock)
        self._peers: dict[str, tuple[str, "PublicKeys", "Pair"]] = {}  # by lower-case name
        self._secure_rooms: dict[str, "_SecureRoom"] = {}
        self._joining: dict[str, "RoomSecret"] = {}
        self._sent: dict[tuple, str] = {}  # our encrypted messages until echoed

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
        if _CRYPTO_ERROR:
            raise ConnectorError(_CRYPTO_ERROR)
        self._validate_cert_file()
        self._id = Identity()
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
        Send a message to a room you have joined (end-to-end encrypted in
        password rooms). Thread-safe.
        Raises ValueError if room does not start with #.
        """
        if not room.startswith("#"):
            raise ValueError(f"Room name must start with #, got: {room!r}")
        text = text.strip()
        if not text:
            return
        with self._e2e_lock:
            r = self._secure_rooms.get(room)
            if r is not None:
                kid, n, ct, sig = r.sender.seal(self._id, json.dumps({"text": text}).encode())
                self._remember((room, kid, n), text)
                self._send({"t": "chat", "room": room, "kid": kid, "n": n, "ct": _b64(ct), "sig": _b64(sig)})
                return
            if room in self._joining:
                raise ConnectorError(f"still joining {room}; try again in a moment")
        self._send({"t": "chat", "room": room, "text": text})

    def send_dm(self, recipient: str, text: str):
        """Send an end-to-end encrypted direct message. Thread-safe."""
        text = text.strip()
        if not text:
            return
        if recipient.lower() == self._cfg.username.lower():
            self._call(self._message_callbacks, f"[DM to {recipient}]: {text}")
            return
        with self._e2e_lock:
            peer = self._wait_peer(recipient)
            if peer is None:
                notice = f"User '{recipient}' is not online."
                self._call(self._message_callbacks, notice)
                self._call(self._system_message_callbacks, notice)
                return
            name, _, pair = peer
            n, ct = pair.seal("dm", json.dumps({"text": text}).encode())
            self._remember((name.lower(), 0, n), text)
            self._send({"t": "dm", "to": name, "n": n, "ct": _b64(ct)})

    def join_room(self, room: str, password: str = ""):
        """
        Join or create a room. room must start with #. With a password the
        room is end-to-end encrypted; the password never leaves this process
        (deriving the keys takes a moment). joined_rooms is updated when the
        server confirms the join.
        """
        if not room.startswith("#"):
            raise ValueError(f"Room name must start with #, got: {room!r}")
        password = password.strip()
        msg = {"t": "join", "room": room}
        if password:
            secret = RoomSecret(room, password)
            with self._e2e_lock:
                self._joining[room] = secret
            msg["vf"] = _b64(secret.verifier)
        self._send(msg)

    def safety_numbers(self, user: str) -> tuple[str, str]:
        """
        Return (ours, theirs): the safety numbers of this session and of
        another member's. If the other member sees the same two numbers,
        nobody (the server included) has substituted keys between you.
        Raises ConnectorError if the member is not online.
        """
        with self._e2e_lock:
            peer = self._peers.get(user.lower())
        if peer is None:
            raise ConnectorError(f"User '{user}' is not online.")
        return safety_number(self._cfg.username, self._id.public), safety_number(peer[0], peer[1])

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
        self._server_cert_der, self._access_pem, self._gate_key = _load_access_bundle(self._cfg.cert_file)

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
        try:
            # The server name carries the gate token, not the host name.
            tls_sock = ctx.wrap_socket(raw, server_hostname=_gate_token(self._gate_key))
        except (ConnectionResetError, BrokenPipeError, ssl.SSLEOFError) as e:
            raw.close()
            raise SecurityError(
                "The server closed the connection without answering: the access file is wrong "
                "or outdated (the server may have been restarted), or this computer's clock is "
                "off by more than 5 minutes"
            ) from e

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
        pub = self._id.public
        self._send({"t": "hello", "v": PROTOCOL_VERSION, "user": self._cfg.username,
                    "kx": _b64(pub.kx), "sk": _b64(pub.sk)})
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
            room, sender = msg.get("room") or None, msg.get("from", "")
            if msg.get("ct"):
                self._secure_chat(msg)
                return
            if room and room in self._secure_rooms:
                return  # a password room carries only encrypted messages
            self._deliver_chat(room, sender, msg.get("text", ""), msg.get("time", ""))
        elif t == "dm":
            self._dm(msg)
        elif t == "peer":
            self._add_peer(msg.get("user", ""), msg.get("kx"), msg.get("sk"))
        elif t == "rhello":
            self._room_hello(msg)
        elif t == "rkey":
            self._room_key(msg)
        elif t in ("joined", "left"):
            user, room = msg.get("user", ""), msg.get("room") or None
            if user == me and room:
                with self._rooms_lock:
                    if t == "joined":
                        self._joined_rooms.add(room)
                    else:
                        self._joined_rooms.discard(room)
            if t == "joined" and room is None and user != me:
                self._add_peer(user, msg.get("kx"), msg.get("sk"))
            elif t == "joined" and room and user == me:
                self._joined_secure(room, bool(msg.get("locked")))
            elif t == "left" and room is None and user != me:
                with self._e2e_lock:
                    self._peers.pop(user.lower(), None)
            elif t == "left" and room and user == me:
                with self._e2e_lock:
                    self._secure_rooms.pop(room, None)
            elif t == "left" and room:
                self._member_left(room, user)
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

    def _deliver_chat(self, room: Optional[str], sender: str, text: str, ts: str):
        prefix = f"[{room}] " if room else ""
        self._call(self._message_callbacks, f"[{ts}] {prefix}{sender}: {text}")
        if sender != self._cfg.username and room:
            self._call(self._room_message_callbacks, room, sender, text)

    # ------------------------------------------------------------------
    # Internal: end-to-end encryption
    # ------------------------------------------------------------------

    def _remember(self, key: tuple, text: str):
        self._sent[key] = text
        while len(self._sent) > 1024:
            self._sent.pop(next(iter(self._sent)))

    def _add_peer(self, name: str, kx, sk):
        if not name or name.lower() == self._cfg.username.lower():
            return
        try:
            pub = PublicKeys.parse(kx, sk)
            pair = self._id.pair(pub)
        except DecryptError:
            return
        with self._e2e_lock:
            self._peers[name.lower()] = (name, pub, pair)
            self._peer_added.notify_all()

    def _wait_peer(self, name: str):
        """Return a member's session, waiting briefly for their keys (they
        arrive with their join notice). Caller holds _e2e_lock."""
        deadline = time.monotonic() + _PEER_WAIT
        on_receive_thread = threading.current_thread() is self._recv_thread
        while True:
            peer = self._peers.get(name.lower())
            remaining = deadline - time.monotonic()
            if peer is not None or on_receive_thread or remaining <= 0 or self._shutdown.is_set():
                return peer
            self._peer_added.wait(remaining)

    def _open_pair(self, sender: str, kind: str, msg: dict) -> bytes:
        with self._e2e_lock:
            peer = self._peers.get(sender.lower())
        if peer is None:
            raise DecryptError("unknown sender")
        n = msg.get("n", 0)
        if not isinstance(n, int) or not 0 <= n < 2 ** 32:
            raise DecryptError("bad counter")
        return peer[2].open(kind, n, _unb64(msg.get("ct", ""), _MAX_CIPHER_B64))

    @staticmethod
    def _text_of(plain: bytes) -> Optional[str]:
        """Text of a decrypted message, cleaned like the server cleans plain
        text (it cannot clean what it cannot read)."""
        try:
            text = json.loads(plain).get("text", "")
        except (ValueError, AttributeError):
            return None
        if not isinstance(text, str):
            return None
        text = _clean_text(text).strip()
        return text if text and len(text.encode()) <= 8 * 1024 else None

    def _dm(self, msg: dict):
        sender, me = msg.get("from", ""), self._cfg.username
        if sender == me:
            with self._e2e_lock:
                text = self._sent.pop((msg.get("to", "").lower(), 0, msg.get("n", 0)), None)
            if text is not None:
                self._call(self._message_callbacks, f"[DM to {msg.get('to', '')}]: {text}")
            return
        try:
            text = self._text_of(self._open_pair(sender, "dm", msg))
        except DecryptError:
            notice = f"A direct message from {sender} could not be decrypted and was dropped."
            self._call(self._message_callbacks, notice)
            self._call(self._system_message_callbacks, notice)
            return
        if text is None:
            return
        self._call(self._message_callbacks, f"[DM from {sender}]: {text}")
        self._call(self._dm_callbacks, sender, text)

    def _send_room_key(self, r: "_SecureRoom", name: str, member: "_Member"):
        """Give a verified member our current sending key. Caller holds _e2e_lock."""
        peer = self._peers.get(name.lower())
        if peer is None:
            return
        body = {"room": r.name, "proof": _b64(r.secret.proof(self._cfg.username, self._id.public)),
                "kid": r.sender.kid, "ck": _b64(r.sender.ck), "n": r.sender.n}
        n, ct = peer[2].seal("rkey", json.dumps(body).encode())
        self._send({"t": "rkey", "to": peer[0], "n": n, "ct": _b64(ct)})
        member.sent_kid = r.sender.kid

    def _joined_secure(self, room: str, locked: bool):
        """Set up a password room we just joined. A room joined with a password
        that turns out to be open (or a server pretending so) is left at once,
        so nothing meant to be private goes out in the clear."""
        notice = None
        with self._e2e_lock:
            secret = self._joining.pop(room, None)
            if not locked:
                if secret is not None:
                    notice = (f"⚠ {room} already exists as an open room, without a password: its messages "
                              "would not be end-to-end encrypted. Left it again; choose another name.")
                    self._send({"t": "leave", "room": room})
            elif secret is None:
                notice = f"⚠ Joined {room} without its password, so its keys are missing. Left it again."
                self._send({"t": "leave", "room": room})
            else:
                self._secure_rooms[room] = _SecureRoom(room, secret)
                self._send({"t": "rhello", "room": room,
                            "proof": _b64(secret.proof(self._cfg.username, self._id.public))})
        if notice:
            self._call(self._message_callbacks, notice)
            self._call(self._system_message_callbacks, notice)

    def _member_left(self, room: str, user: str):
        with self._e2e_lock:
            r = self._secure_rooms.get(room)
            if r is None:
                return
            key = user.lower()
            member = r.members.pop(key, None)
            r.pending.pop(key, None)
            r.refused.discard(key)
            if member is None or member.sent_kid is None:
                return
            # They held our key: switch to a new one for everyone else.
            r.sender = _Sender(room)
            for k, other in r.members.items():
                peer = self._peers.get(k)
                if peer is not None:
                    self._send_room_key(r, peer[0], other)

    def _room_hello(self, msg: dict):
        notice = None
        with self._e2e_lock:
            r = self._secure_rooms.get(msg.get("room", ""))
            peer = self._peers.get(msg.get("from", "").lower())
            if r is None or peer is None:
                return
            name, pub, _ = peer
            try:
                proof = _unb64(msg.get("proof", ""), _KEY_LEN)
            except DecryptError:
                proof = b""
            if r.secret.check(name, pub, proof):
                member = r.members.setdefault(name.lower(), _Member())
                if member.sent_kid != r.sender.kid:  # repeated hellos get no new copies
                    self._send_room_key(r, name, member)
            elif name.lower() not in r.refused:
                r.refused.add(name.lower())
                notice = (f"⚠ {name} is in {r.name} but could not prove the room password: "
                          "they get no keys and cannot read the room.")
        if notice:
            self._call(self._message_callbacks, notice)
            self._call(self._system_message_callbacks, notice)

    def _room_key(self, msg: dict):
        sender = msg.get("from", "")
        try:
            body = json.loads(self._open_pair(sender, "rkey", msg))
            ck, proof = _unb64(body["ck"], _KEY_LEN), _unb64(body["proof"], _KEY_LEN)
            kid, n, room = body["kid"], body["n"], body["room"]
        except (DecryptError, ValueError, KeyError, TypeError):
            return
        if not (isinstance(kid, int) and isinstance(n, int) and isinstance(room, str) and len(ck) == _KEY_LEN):
            return
        with self._e2e_lock:
            r = self._secure_rooms.get(room)
            peer = self._peers.get(sender.lower())
            if r is None or peer is None or not r.secret.check(peer[0], peer[1], proof):
                return
            key = peer[0].lower()
            member = r.members.setdefault(key, _Member())
            member.recv = _Receiver(room, peer[1], kid, ck, n)
            if member.sent_kid != r.sender.kid:
                self._send_room_key(r, peer[0], member)
            retry = r.pending.pop(key, [])
        for m in retry:
            self._secure_chat(m)

    def _secure_chat(self, msg: dict):
        room, sender = msg.get("room", ""), msg.get("from", "")
        kid, n = msg.get("kid", 0), msg.get("n", 0)
        if sender == self._cfg.username:
            with self._e2e_lock:
                text = self._sent.pop((room, kid, n), None)
            if text is not None:
                self._deliver_chat(room, sender, text, msg.get("time", ""))
            return
        try:
            ct, sig = _unb64(msg.get("ct", ""), _MAX_CIPHER_B64), _unb64(msg.get("sig", ""), 64)
        except DecryptError:
            return
        with self._e2e_lock:
            r = self._secure_rooms.get(room)
            if r is None:
                return
            key = sender.lower()
            member = r.members.get(key)
            if member is None or member.recv is None or member.recv.kid != kid:
                queue = r.pending.setdefault(key, [])
                if len(queue) < 64:
                    queue.append(msg)  # their key is on its way
                return
            try:
                plain = member.recv.open(kid, n, ct, sig)
            except DecryptError:
                plain = None
        if plain is None:
            notice = f"A message from {sender} in {room} could not be verified and was dropped."
            self._call(self._message_callbacks, notice)
            self._call(self._system_message_callbacks, notice)
            return
        text = self._text_of(plain)
        if text is not None:
            self._deliver_chat(room, sender, text, msg.get("time", ""))

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
