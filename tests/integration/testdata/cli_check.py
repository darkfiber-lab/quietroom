"""Drives the CLI client in a pseudo-terminal like a person would.

Usage: cli_check.py <cli binary> <work dir> <host:port>
The Go test (cli_test.go) plays the other member, "alice".
"""
import fcntl
import os
import pty
import re
import select
import struct
import sys
import termios
import time

binary, workdir, addr = sys.argv[1], sys.argv[2], sys.argv[3]
COLS, ROWS = 40, 24  # narrow, so typed lines wrap
ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")
raw_out = bytearray()
clean = ""
pos = 0


def say(line):
    print(line, flush=True)


pid, fd = pty.fork()
if pid == 0:
    os.chdir(workdir)
    os.execv(binary, [binary])
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))


def pump(timeout):
    global clean
    r, _, _ = select.select([fd], [], [], timeout)
    if r:
        try:
            data = os.read(fd, 65536)
        except OSError:
            return False
        if not data:
            return False
        raw_out.extend(data)
        clean = ANSI.sub(b"", bytes(raw_out)).decode("utf-8", "replace").replace("\r", "")
    return True


def expect(pattern, timeout=20):
    """Wait for a regex in the output after the last match; returns the match."""
    global pos
    deadline = time.time() + timeout
    rx = re.compile(pattern)
    while True:
        m = rx.search(clean, pos)
        if m:
            pos = m.end()
            return m
        if time.time() > deadline:
            say("TIMEOUT waiting for " + pattern)
            say("OUTPUT:\n" + clean[-3000:])
            sys.exit(1)
        if not pump(0.2):
            time.sleep(0.05)


def type_line(text):
    os.write(fd, text.encode() + b"\r")


expect(r"Press Enter to connect")
type_line(addr)
expect(r"Enter your username:")
type_line("clio")
expect(r"WELCOME TO QUIETROOM")
say("WELCOME")

expect(r"alice: hi clio")
say("LOBBY OK")

type_line("/join #cli")
expect(r"Created and joined room #cli")
say("JOINED")
expect(r"\*\*\* alice joined #cli \*\*\*")
type_line("hello room")
expect(r"\[#cli\] You: hello room")
say("ROOM OK")

expect(r"\[DM\] alice: dm to cli")
type_line("/msg alice dm back")
expect(r"\[DM to alice\] You: dm back")
say("DM OK")

m = expect(r"Transfer ID: ([0-9a-f]{32})")
type_line("/accept " + m.group(1))
expect(r"Hash verification PASSED")
say("RECEIVE OK")

path = os.path.join(workdir, "from cli.txt")
with open(path, "w") as f:
    f.write("sent from the CLI\n" * 1000)
type_line('/file alice "' + path + '"')
expect(r"File offer sent to alice")
expect(r"File sent: from cli.txt")
say("SEND OK")

expect(r"evil-marker")
end = raw_out.find(b"evil-marker")
# The printed message starts after the editor clears its input area
# (ESC[J); from there only colour codes may appear.
line = raw_out[raw_out.rfind(b"\x1b[J", 0, end) + 3:end]
if re.search(rb"\x1b(?!\[[0-9;]*m)", bytes(line)) or b"\x07" in line:
    say("ESCAPE INJECTED " + repr(bytes(line)))
    sys.exit(1)
say("SANITIZED OK " + repr(bytes(line)))

# Type a line long enough to wrap, one key at a time, while a message
# arrives; then edit it with backspace (this used to duplicate the line).
long_msg = "this is a long message that wraps across the rows of a narrow terminal"
for ch in long_msg:
    os.write(fd, ch.encode())
    time.sleep(0.005)
    pump(0)
say("TYPED")
expect(r"alice: while you type")
for _ in range(8):
    os.write(fd, b"\x7f")
    time.sleep(0.02)
    pump(0)
os.write(fd, b"\x1b[D\x1b[C")  # arrow keys must not insert text
type_line("END")
expect(re.escape("You: " + long_msg[:-8] + "END"))
say("TYPING OK")

type_line("/bogus")
expect(r"Unknown command: /bogus")
type_line("/quit")
expect(r"Disconnected from server")
_, status = os.waitpid(pid, 0)
while pump(0.2):
    pass
with open(os.path.join(workdir, "screen.raw"), "wb") as f:
    f.write(raw_out)
say("EXIT %d" % os.waitstatus_to_exitcode(status))
