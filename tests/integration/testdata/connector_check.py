"""Drives the Python connector against a test server (see connector_test.go).

Usage: connector_check.py <connector dir> <host> <port> <access file>
Prints one line per checkpoint; the Go test asserts on them.
"""
import sys
import threading

sys.path.insert(0, sys.argv[1])
from quietroom_connector import ConnectorConfig, QuietRoomConnector, ConnectorError  # noqa: E402

host, port, access = sys.argv[2], int(sys.argv[3]), sys.argv[4]
got_dm = threading.Event()
got_room = threading.Event()
got_secure = threading.Event()
got_users = threading.Event()
presence = []


def say(line):
    print(line, flush=True)


cfg = ConnectorConfig(server_host=host, server_port=port, cert_file=access, username="pybot",
                      decoy_interval=1)
conn = QuietRoomConnector(cfg)
conn.on_dm(lambda s, m: (say(f"DM {s}: {m}"), conn.send_dm(s, "echo: " + m), got_dm.set()))
def on_room(room, sender, text):
    if room == "#pysecret":
        say(f"SECURE {sender}: {text}")
        conn.send_room_message(room, "secure echo: " + text)
        got_secure.set()
    else:
        say(f"ROOM {room} {sender}: {text}")
        got_room.set()


conn.on_room_message(on_room)
conn.on_system_message(lambda t: got_users.set() if t.startswith("Online Users") else None)
conn.on_presence(lambda e, u, r: presence.append((e, u, r)))
conn.connect()
say("CONNECTED")

conn.join_room("#py")
conn.list_users()
assert got_users.wait(10), "no user list"
say("USERS OK")
conn.send_message("hello from python")
assert got_dm.wait(20), "no DM"
assert got_room.wait(20), "no room message"
say("JOINED " + ",".join(sorted(conn.joined_rooms)))

# End-to-end encryption interoperates with the Go client: safety numbers
# agree, and a password room works in both directions.
ours, theirs = conn.safety_numbers("alice")
say(f"SAFETY {ours} / {theirs}")
conn.join_room("#pysecret", "py-and-go")
assert got_secure.wait(30), "no message in the password room"
say("SECURE OK")

# Duplicate name is refused with a clear error.
dup = QuietRoomConnector(ConnectorConfig(server_host=host, server_port=port, cert_file=access, username="pybot"))
try:
    dup.connect()
    say("DUPLICATE ACCEPTED")
except ConnectorError as e:
    say("DUPLICATE REFUSED " + str(e))

# Stay connected past several decoys, then leave.
threading.Event().wait(3)
say("PRESENCE " + ";".join(f"{e}:{u}:{r}" for e, u, r in presence))
conn.disconnect()
say("DONE")
