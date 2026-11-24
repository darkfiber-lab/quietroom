// Copyright (C) 2026 darkfiber-lab

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package integration

import (
	"bufio"
	"context"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/darkfiber-lab/quietroom/client"
)

// TestPythonConnector runs the Python connector against the server and
// talks to it from a Go member.
func TestPythonConnector(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	s := start(t)
	alice := s.Join(t, "alice")
	alice.C.Join("#py", "")
	alice.Wait("join", wait, func(e client.Event) bool { return e.Kind == client.EvJoined && e.Self && e.Room == "#py" })

	host, port, _ := net.SplitHostPort(s.Addr)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-I", filepath.Join("testdata", "connector_check.py"),
		filepath.Join("..", "..", "connector"), host, port, s.AccessFile)
	stdout, _ := cmd.StdoutPipe()
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 100)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	expect := func(prefix string) string {
		t.Helper()
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					cmd.Wait()
					t.Fatalf("connector exited before %q; stderr:\n%s", prefix, stderr.String())
				}
				t.Logf("python: %s", l)
				if strings.HasPrefix(l, prefix) {
					return l
				}
			case <-ctx.Done():
				t.Fatalf("timed out waiting for %q", prefix)
			}
		}
	}

	expect("CONNECTED")
	alice.Wait("pybot joins #py", wait, func(e client.Event) bool { return e.Kind == client.EvJoined && e.User == "pybot" && e.Room == "#py" })
	expect("USERS OK")
	alice.Wait("lobby message", wait, chatFrom("pybot", "hello from python"))

	alice.C.DM("pybot", "ping")
	e := alice.Wait("echo", wait, func(e client.Event) bool { return e.Kind == client.EvDM && e.From == "pybot" })
	if e.Text != "echo: ping" {
		t.Fatalf("echo: %q", e.Text)
	}
	alice.C.Chat("#py", "room hello")
	if l := expect("DM "); l != "DM alice: ping" {
		t.Fatalf("dm line: %q", l)
	}
	if l := expect("ROOM "); l != "ROOM #py alice: room hello" {
		t.Fatalf("room line: %q", l)
	}
	if l := expect("JOINED "); l != "JOINED #py" {
		t.Fatalf("joined rooms: %q", l)
	}
	if l := expect("DUPLICATE "); !strings.Contains(l, "REFUSED") || !strings.Contains(l, "already taken") {
		t.Fatalf("duplicate: %q", l)
	}
	if l := expect("PRESENCE "); !strings.Contains(l, "joined:pybot:#py") {
		t.Fatalf("presence: %q", l)
	}
	expect("DONE")
	alice.Wait("pybot left", wait, func(e client.Event) bool { return e.Kind == client.EvLeft && e.User == "pybot" && e.Room == "" })
	if err := cmd.Wait(); err != nil {
		t.Fatalf("connector: %v\n%s", err, stderr.String())
	}
	s.CheckOutput(t)
}
