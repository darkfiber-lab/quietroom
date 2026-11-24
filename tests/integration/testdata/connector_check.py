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
got_users = threading.Event()
presence = []


def say(line):
    print(line, flush=True)


cfg = ConnectorConfig(server_host=host, server_port=port, cert_file=access, username="pybot",
                      decoy_interval=1)
conn = QuietRoomConnector(cfg)
conn.on_dm(lambda s, m: (say(f"DM {s}: {m}"), conn.send_dm(s, "echo: " + m), got_dm.set()))
conn.on_room_message(lambda r, s, m: (say(f"ROOM {r} {s}: {m}"), got_room.set()))
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
