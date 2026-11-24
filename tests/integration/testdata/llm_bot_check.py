"""Runs the LLM bot with a fake backend against a test server (see llm_bot_test.go).

Usage: llm_bot_check.py <connector dir> <host> <port> <access file> <work dir>
Prints READY once connected; runs until stdin is closed.
"""
import os
import sys
import time

sys.path.insert(0, os.path.abspath(sys.argv[1]))
access = os.path.abspath(sys.argv[4])
os.chdir(sys.argv[5])  # the bot writes llm_bot.log to the working directory
from quietroom_connector import QuietRoomConnector  # noqa: E402
from quietroom_llm_bot import BotConfig, LLMBackend, LLMBot  # noqa: E402


class FakeLLM(LLMBackend):
    name = "fake"

    def generate(self, messages):
        text = messages[-1]["content"]
        time.sleep(1.5)
        if text == "fail":
            raise ConnectionError("backend at http://10.0.0.9:11434 refused")
        return "answer: " + text


cfg = BotConfig(server_host=sys.argv[2], server_port=int(sys.argv[3]), cert_file=access,
                username="llmbot", decoy_interval=1,
                max_concurrent_requests=1, max_requests_per_minute=4)
conn = QuietRoomConnector(cfg.to_connector_config())
bot = LLMBot(conn, cfg, FakeLLM())
conn.connect()
print("READY", flush=True)
sys.stdin.read()
conn.disconnect()
