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

Usage:
    from quietroom_connector import QuietRoomConnector, ConnectorConfig

    cfg = ConnectorConfig(server_host="myserver.local", username="MyBot")
    conn = QuietRoomConnector(cfg)
    conn.on_dm(lambda sender, msg: print(f"DM from {sender}: {msg}"))
    conn.connect()
    conn.send_dm("alice", "Hello!")
    # connection stays alive until conn.disconnect() or process exit
"""

import hashlib
import logging
import os
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

    # Decoy traffic — mirrors the Go client behaviour to avoid traffic analysis
    decoy_traffic: bool = True
    decoy_interval: int = 30        # seconds between decoy bursts
    decoy_min_bytes: int = 100
    decoy_max_bytes: int = 500

    # How long to wait for the server during handshake
    connect_timeout: int = 30


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

# Packet type constants
PKT_MESSAGE = 0x01   # encrypted chat message
PKT_DECOY   = 0x02   # decoy / padding traffic
PKT_FILE    = 0x03   # file transfer data

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
# Connector
# ---------------------------------------------------------------------------

# Callback type aliases (for documentation clarity)
OnDMCallback      = Callable[[str, str], None]   # (sender, message)
OnMessageCallback = Callable[[str], None]         # (raw_text)
OnDisconnectCallback = Callable[[Optional[Exception]], None]  # (reason or None)


class QuietRoomConnector:
    """
    Persistent QuietRoom connection.

    Maintains an open TLS socket and background receive loop for the lifetime
    of the object. Callers register callbacks and use send_* methods to
    interact with the server.

    Thread safety: send_dm() and send_message() are safe to call from any
    thread. Callbacks are invoked from the internal receive thread — keep them
    short or hand off to your own thread pool.
    """

    def __init__(self, config: ConnectorConfig):
        self._cfg = config
        self._sock: Optional[ssl.SSLSocket] = None
        self._session_key: Optional[bytes] = None
        self._send_lock = threading.Lock()
        self._shutdown = threading.Event()
        self._shutdown_once = threading.Lock()
        self._did_shutdown = False

        # Registered callbacks
        self._dm_callbacks:         list[OnDMCallback]      = []
        self._message_callbacks:    list[OnMessageCallback] = []
        self._disconnect_callbacks: list[OnDisconnectCallback] = []

        # Background threads
        self._recv_thread:  Optional[threading.Thread] = None
        self._decoy_thread: Optional[threading.Thread] = None

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

    def on_message(self, callback: OnMessageCallback) -> "QuietRoomConnector":
        """
        Register a callback for ALL decrypted text messages (including DMs,
        room messages, and server notices). Useful for logging or building
        a general-purpose client on top.
        Signature: callback(text: str)
        Returns self for chaining.
        """
        self._message_callbacks.append(callback)
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
            FileNotFoundError   — cert_file not found
            SecurityError       — certificate mismatch or DH validation failure
            ConnectorError      — handshake or login failure
            OSError             — network error during connect
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

    # ------------------------------------------------------------------
    # Public: sending
    # ------------------------------------------------------------------

    def send_dm(self, recipient: str, text: str):
        """
        Send a direct message to a specific user.
        Thread-safe. Raises OSError if the connection is lost.
        """
        self._send_message(f"/msg {recipient} {text}")

    def send_message(self, text: str):
        """
        Send a raw chat message (lobby or current room).
        Thread-safe. Raises OSError if the connection is lost.
        """
        self._send_message(text)

    def join_room(self, room: str, password: str = ""):
        """
        Join a chat room. room must start with #.
        """
        cmd = f"/join {room}"
        if password:
            cmd += f" {password}"
        self._send_message(cmd)

    def leave_room(self, room: str):
        """Leave a chat room."""
        self._send_message(f"/leave {room}")

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

        # Validate server DH public key
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
        """Route a decrypted message to the appropriate callbacks."""
        # Fire raw message callbacks first
        for cb in self._message_callbacks:
            try:
                cb(text)
            except Exception:
                log.exception("on_message callback raised")

        # Parse DMs and fire DM callbacks
        dm = _parse_dm(text)
        if dm:
            sender, message = dm
            for cb in self._dm_callbacks:
                try:
                    cb(sender, message)
                except Exception:
                    log.exception("on_dm callback raised")

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


# ---------------------------------------------------------------------------
# DM parsing
# ---------------------------------------------------------------------------

import re

_DM_RE = re.compile(r"^\[DM from ([^\]]+)\]:\s*(.*)", re.DOTALL)


def _parse_dm(text: str) -> Optional[tuple[str, str]]:
    m = _DM_RE.match(text)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return None
