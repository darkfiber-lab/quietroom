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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/darkfiber-lab/quietroom/client"
	"github.com/darkfiber-lab/quietroom/lineedit/vt"
)

// TestCLI runs the real CLI client in a pseudo-terminal against the server;
// the Go member "alice" chats, DMs and exchanges files with it.
func TestCLI(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a pseudo-terminal")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	work := t.TempDir()
	cli := filepath.Join(work, "quietroom_client")
	build := exec.Command("go", "build", "-o", cli, "quietroom_client.go")
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building CLI: %v\n%s", err, out)
	}

	s := start(t)
	data, _ := os.ReadFile(s.AccessFile)
	os.WriteFile(filepath.Join(work, client.AccessFileName), data, 0600)
	os.WriteFile(filepath.Join(work, "client_config.json"), []byte(`{"servers":[{"name":"test","address":"127.0.0.1","port":1}],"decoy_traffic":true,"decoy_interval_seconds":2,"decoy_min_bytes":100,"decoy_max_bytes":500}`), 0600)

	alice := s.Join(t, "alice")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-I", filepath.Join("testdata", "cli_check.py"), cli, work, s.Addr)
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
	expect := func(want string) {
		t.Helper()
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					cmd.Wait()
					t.Fatalf("CLI driver exited before %q; stderr:\n%s", want, stderr.String())
				}
				t.Logf("cli: %s", l)
				if strings.HasPrefix(l, "TIMEOUT") || strings.HasPrefix(l, "ESCAPE INJECTED") {
					for l := range lines {
						t.Log(l)
					}
					t.Fatalf("CLI check failed")
				}
				if l == want || strings.HasPrefix(l, want+" ") {
					return
				}
			case <-ctx.Done():
				t.Fatalf("timed out waiting for %q", want)
			}
		}
	}

	expect("WELCOME")
	alice.Wait("clio joined", wait, func(e client.Event) bool { return e.Kind == client.EvJoined && e.User == "clio" })
	alice.C.Chat("", "hi clio")
	expect("LOBBY OK")

	expect("JOINED")
	alice.C.Join("#cli", "")
	alice.Wait("join", wait, func(e client.Event) bool { return e.Kind == client.EvJoined && e.Self && e.Room == "#cli" })
	alice.Wait("room message", wait, func(e client.Event) bool {
		return e.Kind == client.EvChat && e.From == "clio" && e.Room == "#cli" && e.Text == "hello room"
	})
	expect("ROOM OK")

	alice.C.DM("clio", "dm to cli")
	alice.Wait("dm back", wait, func(e client.Event) bool { return e.Kind == client.EvDM && e.From == "clio" && e.Text == "dm back" })
	expect("DM OK")

	p, _ := makeFile(t, alice.Dir, "to cli.bin", 3<<20+7)
	if _, err := alice.C.OfferFile("clio", p); err != nil {
		t.Fatal(err)
	}
	alice.Wait("sent", wait, func(e client.Event) bool { return e.Kind == client.EvFileComplete })
	expect("RECEIVE OK")
	if _, err := os.Stat(filepath.Join(work, "downloads", "to cli.bin")); err != nil {
		t.Fatalf("CLI did not save the file: %v", err)
	}

	o := alice.Wait("offer from CLI", wait, func(e client.Event) bool { return e.Kind == client.EvFileOffer })
	alice.C.AcceptFile(o.Transfer.ID)
	got := alice.Wait("file from CLI", wait, func(e client.Event) bool { return e.Kind == client.EvFileComplete || e.Kind == client.EvFileFailed })
	if !got.Transfer.OK || got.Transfer.Name != "from cli.txt" {
		t.Fatalf("file from CLI: %+v %s", got.Transfer, got.Text)
	}
	expect("SEND OK")

	// Terminal escape sequences from other members must not reach the screen.
	alice.C.Chat("", "\x1b[2J\x1b]0;pwned\x07 evil-marker")
	expect("SANITIZED OK")

	expect("TYPED")
	alice.C.Chat("#cli", "while you type")
	const typed = "this is a long message that wraps across the rows of a narrow END"
	alice.Wait("edited message", wait, func(e client.Event) bool {
		return e.Kind == client.EvChat && e.From == "clio" && e.Text == typed
	})
	expect("TYPING OK")

	expect("EXIT 0")
	alice.Wait("clio left", wait, func(e client.Event) bool { return e.Kind == client.EvLeft && e.User == "clio" && e.Room == "" })
	if err := cmd.Wait(); err != nil {
		t.Fatalf("driver: %v\n%s", err, stderr.String())
	}

	// Replay everything the CLI wrote through a terminal emulator of the
	// same size and check what was on screen.
	raw, err := os.ReadFile(filepath.Join(work, "screen.raw"))
	if err != nil {
		t.Fatal(err)
	}
	scr := vt.New(40, 24)
	scr.Write(raw)
	transcript := scr.LogicalLines()
	count := func(sub string) int {
		n := 0
		for _, l := range transcript {
			n += strings.Count(l, sub)
		}
		return n
	}
	if n := count("#cli > this is"); n != 0 {
		t.Errorf("%d stale copies of the typed line left on screen:\n%s", n, strings.Join(transcript, "\n"))
	}
	if n := count("You: this is a long message"); n != 1 {
		t.Errorf("sent message shown %d times:\n%s", n, strings.Join(transcript, "\n"))
	}
	if n := count("alice: while you type"); n != 1 {
		t.Errorf("incoming message shown %d times:\n%s", n, strings.Join(transcript, "\n"))
	}

	s.CheckOutput(t)
}

// TestCLILineMode runs the CLI without a terminal (stdin and stdout are
// pipes). It must fall back to plain line input and uncoloured output, as
// on Plan 9 where raw terminal mode does not exist.
func TestCLILineMode(t *testing.T) {
	work := t.TempDir()
	cli := filepath.Join(work, "quietroom_client")
	build := exec.Command("go", "build", "-o", cli, "quietroom_client.go")
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building CLI: %v\n%s", err, out)
	}
	s := start(t)
	data, _ := os.ReadFile(s.AccessFile)
	os.WriteFile(filepath.Join(work, client.AccessFileName), data, 0600)
	os.WriteFile(filepath.Join(work, "client_config.json"), []byte(`{"servers":[{"name":"test","address":"127.0.0.1","port":1}],"decoy_traffic":false}`), 0600)
	alice := s.Join(t, "alice")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, cli)
	cmd.Dir = work
	cmd.Env = append(os.Environ(), "TERM=xterm-256color") // colours must stay off anyway
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	var all strings.Builder
	lines := make(chan string, 100)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	expect := func(sub string) {
		t.Helper()
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatalf("CLI exited before %q; output:\n%s", sub, all.String())
				}
				all.WriteString(l + "\n")
				if strings.Contains(l, sub) {
					return
				}
			case <-ctx.Done():
				t.Fatalf("timed out waiting for %q; output:\n%s", sub, all.String())
			}
		}
	}

	io := func(s string) { stdin.Write([]byte(s + "\n")) }
	io(s.Addr)
	io("piper")
	expect("WELCOME TO QUIETROOM")
	alice.Wait("piper joined", wait, func(e client.Event) bool { return e.Kind == client.EvJoined && e.User == "piper" })
	alice.C.Chat("", "hello pipe")
	expect("alice: hello pipe")
	io("hello from a pipe")
	alice.Wait("message", wait, chatFrom("piper", "hello from a pipe"))
	expect("You: hello from a pipe")
	io("/msg alice private")
	alice.Wait("dm", wait, func(e client.Event) bool { return e.Kind == client.EvDM && e.From == "piper" && e.Text == "private" })
	io("/quit")
	expect("Disconnected from server")
	if err := cmd.Wait(); err != nil {
		t.Fatalf("CLI: %v\n%s", err, all.String())
	}
	if strings.Contains(all.String(), "\x1b") {
		t.Fatalf("escape sequences in line mode output:\n%q", all.String())
	}
	alice.Wait("piper left", wait, func(e client.Event) bool { return e.Kind == client.EvLeft && e.User == "piper" && e.Room == "" })
}
