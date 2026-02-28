# QuietRoom LLM Bot

An LLM integration layer for QuietRoom built on top of `quietroom_connector`. Users who send a direct message to the bot's username receive a response from a locally running language model. Room messages are ignored. Each sender gets their own isolated conversation history that persists for the session.

---

## Requirements

```bash
pip install cryptography requests openai
```

- Python 3.11 or higher
- `quietroom_connector.py` in the same directory
- `chat_public.pem` copied from the server
- A running local LLM inference server (Ollama or any OpenAI-compatible server)

---

## Setup

### 1. Get the server certificate

Copy `chat_public.pem` from the QuietRoom server into the working directory.

### 2. Generate the config file

Run once with no arguments to generate `bot_config.json`:

```bash
python3 quietroom_llm_bot.py
```

The bot exits after writing the config. Edit before running again.

### 3. Edit bot_config.json

```json
{
  "server_host": "localhost",
  "server_port": 37842,
  "cert_file": "chat_public.pem",
  "username": "LLMBot",
  "llm_backend": "ollama",
  "ollama": {
    "base_url": "http://localhost:11434",
    "model": "llama3",
    "timeout": 120
  },
  "openai": {
    "base_url": "http://localhost:8080/v1",
    "api_key": "not-needed",
    "model": "gpt-3.5-turbo",
    "timeout": 120
  },
  "max_history_per_user": 20,
  "history_ttl_seconds": 3600,
  "system_prompt": "You are a helpful assistant on a private encrypted chat server. Keep responses concise.",
  "max_message_length": 400,
  "decoy_traffic": true,
  "decoy_interval": 30,
  "decoy_min_bytes": 100,
  "decoy_max_bytes": 500
}
```

Key fields:

| Field | Description |
|---|---|
| `server_host` | Hostname or IP of the QuietRoom server |
| `username` | Name the bot appears as in the chat |
| `llm_backend` | `"ollama"` or `"openai"` |
| `system_prompt` | Persona and instructions given to the model on every request |
| `max_history_per_user` | Maximum messages retained per sender (both sides count) |
| `history_ttl_seconds` | History discarded after this many seconds of inactivity |
| `max_message_length` | Replies longer than this are split into multiple DMs |

### 4. Start your LLM server

**Ollama:**
```bash
ollama serve
ollama pull llama3
```

**OpenAI-compatible (LM Studio, vLLM, LocalAI, etc.):**

Start your server and set `openai.base_url` to its `/v1` endpoint. The `api_key` field is ignored by most local servers but must be present.

### 5. Run the bot

```bash
python3 quietroom_llm_bot.py
```

---

## Command-line options

```
--config PATH       Path to config file (default: bot_config.json)
--backend BACKEND   Override llm_backend: ollama or openai
--model NAME        Override the model name
--username NAME     Override the bot username
--debug             Enable debug-level logging
```

Examples:

```bash
python3 quietroom_llm_bot.py --backend ollama --model mistral
python3 quietroom_llm_bot.py --username Assistant --debug
python3 quietroom_llm_bot.py --config production.json
```

---

## Usage

Once running, any user on the server can interact with the bot by sending a direct message:

```
/msg LLMBot What is the capital of France?
```

The bot responds via DM. Room messages are never answered.

### Bot commands

| Command | Effect |
|---|---|
| `!reset` | Clears your conversation history with the bot |
| `!help` | Shows available commands |

---

## Conversation history

Each sender gets an independent context window. The full exchange history is included in every LLM request, giving the model awareness of prior messages in the conversation.

History is bounded by `max_history_per_user` (default 20 messages). Once the limit is reached, the oldest messages are dropped. History is also discarded after `history_ttl_seconds` of inactivity (default 1 hour). It is held in memory only and lost on restart.

---

## Adding a new LLM backend

Subclass `LLMBackend`, implement `name` and `generate()`, then add a branch in `build_backend()`:

```python
class MyBackend(LLMBackend):

    @property
    def name(self) -> str:
        return "MyBackend"

    def generate(self, messages: list[dict]) -> str:
        # messages: [{"role": "system"|"user"|"assistant", "content": str}, ...]
        # call your inference server and return the reply as a plain string
        # raise RuntimeError on failure
        ...
```

In `build_backend()`:

```python
elif backend == "mybackend":
    return MyBackend(cfg)
```

Set `"llm_backend": "mybackend"` in config.

---

## Architecture

The bot is intentionally separated from the protocol layer:

```
quietroom_connector.py        quietroom_llm_bot.py
──────────────────────        ────────────────────
QuietRoomConnector            LLMBot
  TLS + DH + AES-GCM    <-->    on_dm callback
  persistent socket             HistoryManager
  send_dm()                     LLMBackend
  on_dm(callback)               chunk_response()
```

`QuietRoomConnector` owns the connection and knows nothing about LLMs. `LLMBot` owns the inference logic and knows nothing about the protocol. Other automated clients can be built on top of the connector independently.

---

## Logging

Logs go to stdout and `llm_bot.log`. Entries include connection events, incoming DMs (truncated to 80 chars), LLM errors, reply chunk counts, and history reaper activity. Room messages and decoy packets appear only at debug level.

---

## Security notes

- Certificate pinning and DH key validation are handled by the connector and inherited automatically.
- The bot never responds to room messages and cannot be triggered without a deliberate DM.
- Conversation histories are held in memory only and never written to disk.
- The system prompt is not visible to users.
