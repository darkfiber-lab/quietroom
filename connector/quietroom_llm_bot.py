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

quietroom_llm_bot.py

LLM integration layer for QuietRoom. Sits on top of QuietRoomConnector and
routes incoming direct messages to a local language model, maintaining
per-sender conversation history across the session.

Requires: quietroom_connector.py in the same directory.
Install:  pip install cryptography requests openai

Usage:
    python3 quietroom_llm_bot.py
    python3 quietroom_llm_bot.py --backend ollama --model mistral
    python3 quietroom_llm_bot.py --config production.json
"""

import json
import logging
import os
import re
import sys
import threading
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from quietroom_connector import (
    QuietRoomConnector,
    ConnectorConfig,
    ConnectorError,
    SecurityError,
)

# Fired by server when a user fully disconnects from the chat
_LEFT_RE = re.compile(r"^\*\*\*\s+(\S+)\s+left the chat\s+\*\*\*$")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("llm_bot.log"),
    ],
)
log = logging.getLogger("quietroom.llm_bot")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class OllamaConfig:
    base_url: str = "http://localhost:11434"
    model: str = "llama3"
    timeout: int = 120


@dataclass
class OpenAIConfig:
    base_url: str = "http://localhost:8080/v1"
    api_key: str = "not-needed"
    model: str = "gpt-3.5-turbo"
    timeout: int = 120


@dataclass
class BotConfig:
    # Passed through to ConnectorConfig
    server_host: str = "localhost"
    server_port: int = 37842
    cert_file: str = "chat_public.pem"
    username: str = "LLMBot"
    decoy_traffic: bool = True
    decoy_interval: int = 30
    decoy_min_bytes: int = 100
    decoy_max_bytes: int = 500

    # LLM backend selection
    llm_backend: str = "ollama"
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    openai: OpenAIConfig = field(default_factory=OpenAIConfig)

    # Conversation history
    max_history_per_user: int = 20
    history_ttl_seconds: int = 3600

    # System prompt
    system_prompt: str = (
        "You are a helpful assistant connected to a private encrypted chat server. "
        "Keep your responses concise and clear. "
        "You are speaking directly with the person who sent you a private message."
    )

    # Long responses are split into chunks of this length
    max_message_length: int = 400

    def to_connector_config(self) -> ConnectorConfig:
        return ConnectorConfig(
            server_host=self.server_host,
            server_port=self.server_port,
            cert_file=self.cert_file,
            username=self.username,
            decoy_traffic=self.decoy_traffic,
            decoy_interval=self.decoy_interval,
            decoy_min_bytes=self.decoy_min_bytes,
            decoy_max_bytes=self.decoy_max_bytes,
        )


def load_config(path: str = "bot_config.json") -> BotConfig:
    if not os.path.exists(path):
        cfg = BotConfig()
        d = {
            "server_host": cfg.server_host,
            "server_port": cfg.server_port,
            "cert_file": cfg.cert_file,
            "username": cfg.username,
            "decoy_traffic": cfg.decoy_traffic,
            "decoy_interval": cfg.decoy_interval,
            "decoy_min_bytes": cfg.decoy_min_bytes,
            "decoy_max_bytes": cfg.decoy_max_bytes,
            "llm_backend": cfg.llm_backend,
            "ollama": {
                "base_url": cfg.ollama.base_url,
                "model": cfg.ollama.model,
                "timeout": cfg.ollama.timeout,
            },
            "openai": {
                "base_url": cfg.openai.base_url,
                "api_key": cfg.openai.api_key,
                "model": cfg.openai.model,
                "timeout": cfg.openai.timeout,
            },
            "max_history_per_user": cfg.max_history_per_user,
            "history_ttl_seconds": cfg.history_ttl_seconds,
            "system_prompt": cfg.system_prompt,
            "max_message_length": cfg.max_message_length,
        }
        with open(path, "w") as f:
            json.dump(d, f, indent=2)
        log.info("Created default %s — edit before running.", path)
        return cfg

    with open(path) as f:
        d = json.load(f)

    cfg = BotConfig(
        server_host=d.get("server_host", "localhost"),
        server_port=d.get("server_port", 37842),
        cert_file=d.get("cert_file", "chat_public.pem"),
        username=d.get("username", "LLMBot"),
        decoy_traffic=d.get("decoy_traffic", True),
        decoy_interval=d.get("decoy_interval", 30),
        decoy_min_bytes=d.get("decoy_min_bytes", 100),
        decoy_max_bytes=d.get("decoy_max_bytes", 500),
        llm_backend=d.get("llm_backend", "ollama"),
        max_history_per_user=d.get("max_history_per_user", 20),
        history_ttl_seconds=d.get("history_ttl_seconds", 3600),
        system_prompt=d.get("system_prompt", BotConfig.system_prompt),
        max_message_length=d.get("max_message_length", 400),
    )

    if "ollama" in d:
        o = d["ollama"]
        cfg.ollama = OllamaConfig(
            base_url=o.get("base_url", "http://localhost:11434"),
            model=o.get("model", "llama3"),
            timeout=o.get("timeout", 120),
        )
    if "openai" in d:
        o = d["openai"]
        cfg.openai = OpenAIConfig(
            base_url=o.get("base_url", "http://localhost:8080/v1"),
            api_key=o.get("api_key", "not-needed"),
            model=o.get("model", "gpt-3.5-turbo"),
            timeout=o.get("timeout", 120),
        )

    return cfg


# ---------------------------------------------------------------------------
# LLM backends
# ---------------------------------------------------------------------------

class LLMBackend(ABC):
    """
    Abstract base class for LLM backends.
    Implement generate() and name to add a new backend.
    """

    @abstractmethod
    def generate(self, messages: list[dict]) -> str:
        """
        Generate a response.

        Args:
            messages: [{"role": "system"|"user"|"assistant", "content": str}, ...]

        Returns:
            The model's reply as a plain string.

        Raises:
            RuntimeError on any inference failure.
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for logging."""
        ...


class OllamaBackend(LLMBackend):
    """
    Ollama local inference server (https://ollama.com).
    Start with: ollama serve && ollama pull <model>
    """

    def __init__(self, cfg: OllamaConfig):
        self._cfg = cfg
        try:
            import requests
            self._requests = requests
        except ImportError:
            raise RuntimeError("pip install requests  (required for Ollama backend)")

    @property
    def name(self) -> str:
        return f"Ollama({self._cfg.model})"

    def generate(self, messages: list[dict]) -> str:
        url = f"{self._cfg.base_url.rstrip('/')}/api/chat"
        try:
            resp = self._requests.post(
                url,
                json={"model": self._cfg.model, "messages": messages, "stream": False},
                timeout=self._cfg.timeout,
            )
            resp.raise_for_status()
            return resp.json()["message"]["content"].strip()
        except self._requests.exceptions.ConnectionError:
            raise RuntimeError(
                f"Cannot reach Ollama at {self._cfg.base_url}. Is 'ollama serve' running?"
            )
        except self._requests.exceptions.Timeout:
            raise RuntimeError(f"Ollama timed out after {self._cfg.timeout}s")
        except (KeyError, ValueError) as e:
            raise RuntimeError(f"Unexpected Ollama response: {e}")


class OpenAICompatibleBackend(LLMBackend):
    """
    OpenAI-compatible API backend.
    Works with OpenAI, LM Studio, vLLM, LocalAI, text-generation-webui, etc.
    Set base_url to the server's /v1 endpoint.
    """

    def __init__(self, cfg: OpenAIConfig):
        self._cfg = cfg
        try:
            from openai import OpenAI
            self._client = OpenAI(base_url=cfg.base_url, api_key=cfg.api_key)
        except ImportError:
            raise RuntimeError("pip install openai  (required for OpenAI-compatible backend)")

    @property
    def name(self) -> str:
        return f"OpenAI-compatible({self._cfg.model} @ {self._cfg.base_url})"

    def generate(self, messages: list[dict]) -> str:
        try:
            resp = self._client.chat.completions.create(
                model=self._cfg.model,
                messages=messages,
                timeout=self._cfg.timeout,
            )
            return resp.choices[0].message.content.strip()
        except Exception as e:
            raise RuntimeError(f"OpenAI-compatible backend error: {e}")


def build_backend(cfg: BotConfig) -> LLMBackend:
    backend = cfg.llm_backend.lower()
    if backend == "ollama":
        return OllamaBackend(cfg.ollama)
    elif backend in ("openai", "openai-compatible"):
        return OpenAICompatibleBackend(cfg.openai)
    else:
        raise ValueError(
            f"Unknown llm_backend '{cfg.llm_backend}'. Choose 'ollama' or 'openai'."
        )


# ---------------------------------------------------------------------------
# Conversation history
# ---------------------------------------------------------------------------

@dataclass
class _ConversationHistory:
    messages: deque = field(default_factory=deque)
    last_active: float = field(default_factory=time.time)

    def add(self, role: str, content: str, max_len: int):
        self.messages.append({"role": role, "content": content})
        while len(self.messages) > max_len:
            self.messages.popleft()
        self.last_active = time.time()

    def to_list(self) -> list[dict]:
        return list(self.messages)

    def is_expired(self, ttl: int) -> bool:
        return (time.time() - self.last_active) > ttl


class HistoryManager:
    def __init__(self, max_per_user: int, ttl_seconds: int):
        self._max = max_per_user
        self._ttl = ttl_seconds
        self._histories: dict[str, _ConversationHistory] = {}
        self._lock = threading.Lock()

    def get(self, sender: str) -> list[dict]:
        with self._lock:
            if sender not in self._histories:
                return []
            return self._histories[sender].to_list()

    def add(self, sender: str, role: str, content: str):
        with self._lock:
            if sender not in self._histories:
                self._histories[sender] = _ConversationHistory()
            self._histories[sender].add(role, content, self._max)

    def clear(self, sender: str) -> bool:
        with self._lock:
            if sender in self._histories:
                del self._histories[sender]
                log.info("Cleared history for '%s'", sender)
                return True
            return False

    def purge_expired(self):
        with self._lock:
            expired = [s for s, h in self._histories.items() if h.is_expired(self._ttl)]
            for s in expired:
                del self._histories[s]
                log.info("Purged expired history for '%s'", s)


# ---------------------------------------------------------------------------
# Response chunking
# ---------------------------------------------------------------------------

def chunk_response(text: str, max_len: int) -> list[str]:
    if len(text) <= max_len:
        return [text]

    chunks, current = [], ""
    for sentence in re.split(r'(?<=[.!?])\s+', text):
        if len(current) + len(sentence) + 1 <= max_len:
            current = (current + " " + sentence).strip() if current else sentence
        else:
            if current:
                chunks.append(current)
            while len(sentence) > max_len:
                chunks.append(sentence[:max_len])
                sentence = sentence[max_len:]
            current = sentence
    if current:
        chunks.append(current)
    return chunks


# ---------------------------------------------------------------------------
# LLM Bot
# ---------------------------------------------------------------------------

class LLMBot:
    """
    Routes incoming DMs to an LLM and replies via the connector.
    Room messages are ignored. Each sender gets isolated conversation history.
    """

    def __init__(self, connector: QuietRoomConnector, cfg: BotConfig, llm: LLMBackend):
        self._conn = connector
        self._cfg = cfg
        self._llm = llm
        self._history = HistoryManager(cfg.max_history_per_user, cfg.history_ttl_seconds)
        self._shutdown = threading.Event()

        # Register callbacks on the connector
        self._conn.on_dm(self._handle_dm)
        self._conn.on_disconnect(self._handle_disconnect)
        self._conn.on_message(self._handle_system_message)

    def _handle_disconnect(self, reason: Optional[Exception]):
        log.info("Connector disconnected: %s", reason or "clean shutdown")
        self._shutdown.set()
    
    def _handle_system_message(self, text: str):
        m = _LEFT_RE.match(text.strip())
        if m:
            username = m.group(1)
            if self._history.clear(username):
                log.info(
                    "User '%s' left — conversation history purged to prevent context leak",
                    username,
                )

    def _handle_dm(self, sender: str, message: str):
        """Callback fired by the connector for every incoming DM."""
        log.info("DM from '%s': %s", sender, message[:80])

        if message.strip().lower() == "!reset":
            self._history.clear(sender)
            self._conn.send_dm(sender, "Conversation history cleared.")
            return

        if message.strip().lower() == "!help":
            self._conn.send_dm(
                sender,
                "Commands: !reset (clear history) | !help (this message). "
                "Otherwise just chat normally.",
            )
            return

        # Build full message list for this request
        history = self._history.get(sender)
        messages = [{"role": "system", "content": self._cfg.system_prompt}]
        messages.extend(history)
        messages.append({"role": "user", "content": message})

        # Run LLM in a thread — the connector's receive loop must not block
        threading.Thread(
            target=self._generate_and_reply,
            args=(sender, message, messages),
            daemon=True,
            name=f"llm-{sender}",
        ).start()

    def _generate_and_reply(self, sender: str, original: str, messages: list[dict]):
        try:
            reply = self._llm.generate(messages)
        except RuntimeError as e:
            log.error("LLM error for '%s': %s", sender, e)
            self._conn.send_dm(sender, f"[Error: {e}]")
            return

        if not reply:
            log.warning("LLM returned empty response for '%s'", sender)
            return

        # Commit exchange to history only after a successful round trip
        self._history.add(sender, "user", original)
        self._history.add(sender, "assistant", reply)

        chunks = chunk_response(reply, self._cfg.max_message_length)
        log.info("Replying to '%s' in %d chunk(s)", sender, len(chunks))
        for i, chunk in enumerate(chunks):
            self._conn.send_dm(sender, chunk)
            if i < len(chunks) - 1:
                time.sleep(0.1)

    def _reaper_loop(self):
        while not self._shutdown.is_set():
            self._shutdown.wait(timeout=300)
            if not self._shutdown.is_set():
                self._history.purge_expired()

    def run_until_disconnected(self):
        """Block the calling thread until the connector disconnects."""
        threading.Thread(
            target=self._reaper_loop, daemon=True, name="history-reaper"
        ).start()
        log.info(
            "LLM bot running as '%s' using %s. Send a DM to interact.",
            self._cfg.username,
            self._llm.name,
        )
        self._shutdown.wait()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    import argparse
    import signal

    parser = argparse.ArgumentParser(description="QuietRoom LLM Bot")
    parser.add_argument("--config", default="bot_config.json")
    parser.add_argument("--backend", choices=["ollama", "openai"])
    parser.add_argument("--model")
    parser.add_argument("--username")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    cfg = load_config(args.config)
    if args.backend:
        cfg.llm_backend = args.backend
    if args.model:
        if cfg.llm_backend == "ollama":
            cfg.ollama.model = args.model
        else:
            cfg.openai.model = args.model
    if args.username:
        cfg.username = args.username

    log.info("Initialising LLM backend: %s", cfg.llm_backend)
    try:
        llm = build_backend(cfg)
    except (RuntimeError, ValueError) as e:
        log.error("Backend init failed: %s", e)
        sys.exit(1)
    log.info("LLM backend ready: %s", llm.name)

    connector = QuietRoomConnector(cfg.to_connector_config())
    bot = LLMBot(connector, cfg, llm)

    def _shutdown(sig, frame):
        log.info("Shutting down...")
        connector.disconnect()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        log.info("Connecting to %s:%d", cfg.server_host, cfg.server_port)
        connector.connect()
    except (ConnectorError, SecurityError, OSError) as e:
        log.error("Connection failed: %s", e)
        sys.exit(1)

    bot.run_until_disconnected()
    log.info("Bot stopped.")


if __name__ == "__main__":
    main()
