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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/darkfiber-lab/quietroom/client"
	"github.com/darkfiber-lab/quietroom/tests/testserver"
)

// TestLLMBotLimits runs the LLM bot with a fake backend and checks its abuse
// limits (one request per user, a global cap, a per-user rate) and that its
// log holds neither message text nor usernames.
func TestLLMBotLimits(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	s := start(t)
	alice := s.Join(t, "alice")
	bob := s.Join(t, "bob")

	work := t.TempDir()
	host, port, _ := net.SplitHostPort(s.Addr)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-I", filepath.Join("testdata", "llm_bot_check.py"),
		filepath.Join("..", "..", "connector"), host, port, s.AccessFile, work)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	// The bot also logs to stdout; wait for the READY line.
	ready := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if sc.Text() == "READY" {
				ready <- true
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			cmd.Wait()
			t.Fatalf("bot exited before connecting:\n%s", stderr.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("bot did not connect within 30s:\n%s", stderr.String())
	}

	reply := func(m *testserver.Member, what, prefix string) {
		t.Helper()
		m.Wait(what, 20*time.Second, func(e client.Event) bool {
			return e.Kind == client.EvDM && e.From == "llmbot" && strings.HasPrefix(e.Text, prefix)
		})
	}

	// A normal question.
	alice.C.DM("llmbot", "hello secret-phrase")
	reply(alice, "answer", "answer: hello secret-phrase")

	// A second message while the first is being answered is refused.
	alice.C.DM("llmbot", "q2")
	time.Sleep(300 * time.Millisecond)
	alice.C.DM("llmbot", "q3")
	reply(alice, "per-user refusal", "Still working on your previous message")
	reply(alice, "answer q2", "answer: q2")

	// While bob's request runs, the global cap (1 here) refuses alice.
	bob.C.DM("llmbot", "b1")
	time.Sleep(300 * time.Millisecond)
	alice.C.DM("llmbot", "q4")
	reply(alice, "global refusal", "I'm busy answering others")
	reply(bob, "answer b1", "answer: b1")

	// alice has used her 4 messages this minute: one warning, then silence.
	alice.C.DM("llmbot", "q5")
	reply(alice, "rate warning", "Slow down")
	alice.C.DM("llmbot", "q6")
	if e, ok := alice.TryWait(3*time.Second, func(e client.Event) bool { return e.Kind == client.EvDM && e.From == "llmbot" }); ok {
		t.Fatalf("bot answered over the rate limit: %q", e.Text)
	}

	// Backend failures reach the user without internals.
	bob.C.DM("llmbot", "fail")
	bob.Wait("error", 20*time.Second, func(e client.Event) bool {
		if e.Kind != client.EvDM || e.From != "llmbot" {
			return false
		}
		if strings.Contains(e.Text, "10.0.0.9") {
			t.Errorf("backend details sent to the user: %q", e.Text)
		}
		return strings.HasPrefix(e.Text, "[Error:")
	})

	stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("bot: %v\n%s", err, stderr.String())
	}
	logData, err := os.ReadFile(filepath.Join(work, "llm_bot.log"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-phrase", "alice", "bob", "q2", "answer:"} {
		if strings.Contains(string(logData), secret) {
			t.Errorf("bot log contains %q:\n%s", secret, logData)
		}
	}
	s.CheckOutput(t)
}
