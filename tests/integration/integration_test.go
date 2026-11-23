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

// Package integration tests the client library against a real server:
// chat, rooms, DMs and file transfers, including large, concurrent and
// interrupted transfers.
package integration

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/darkfiber-lab/quietroom/client"
	"github.com/darkfiber-lab/quietroom/tests/testserver"
	"github.com/darkfiber-lab/quietroom/wire"
)

var bin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "quietroom-it-")
	if err != nil {
		panic(err)
	}
	bin, err = testserver.Build(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "building server:", err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

const wait = 15 * time.Second

func start(t *testing.T) *testserver.Server {
	return testserver.Start(t, bin, testserver.Config{})
}

func chatFrom(from, text string) func(client.Event) bool {
	return func(e client.Event) bool { return e.Kind == client.EvChat && e.From == from && e.Text == text }
}

func TestLoginAndPresence(t *testing.T) {
	s := start(t)
	alice := s.Join(t, "alice")
	alice.Wait("own join", wait, func(e client.Event) bool { return e.Kind == client.EvJoined && e.Self && e.Room == "" })
	bob := s.Join(t, "bob")
	alice.Wait("bob joined", wait, func(e client.Event) bool { return e.Kind == client.EvJoined && e.User == "bob" && e.Room == "" })

	_, err := s.TryJoin(t, "bob")
	var le *client.LoginError
	if !errors.As(err, &le) || le.Code != wire.CodeUsernameTaken {
		t.Fatalf("duplicate login: err = %v", err)
	}
	if _, err := s.TryJoin(t, "<script>"); err == nil {
		t.Fatal("invalid username accepted")
	}

	bob.C.Close()
	alice.Wait("bob left", wait, func(e client.Event) bool { return e.Kind == client.EvLeft && e.User == "bob" && e.Room == "" })
	// The name is free again.
	s.Join(t, "bob")
	s.CheckOutput(t)
}

func TestLobbyChatOrderAndEcho(t *testing.T) {
	s := start(t)
	alice := s.Join(t, "alice")
	bob := s.Join(t, "bob")
	const n = 500
	go func() {
		for i := 0; i < n; i++ {
			alice.C.Chat("", fmt.Sprintf("msg %d", i))
			if i%50 == 49 {
				time.Sleep(3 * time.Second) // stay within the rate limit
			}
		}
	}()
	for i := 0; i < n; i++ {
		e := bob.Wait(fmt.Sprintf("message %d", i), wait, testserver.Kind(client.EvChat))
		if e.Text != fmt.Sprintf("msg %d", i) || e.From != "alice" || e.Self || e.Time == "" {
			t.Fatalf("message %d: got %+v", i, e)
		}
	}
	e := alice.Wait("own echo", wait, chatFrom("alice", "msg 0"))
	if !e.Self {
		t.Fatal("own message not marked Self")
	}
	s.CheckOutput(t)
}

func TestRateLimit(t *testing.T) {
	s := start(t)
	alice := s.Join(t, "alice")
	for i := 0; i < 200; i++ {
		alice.C.Chat("", "flood")
	}
	alice.Wait("rate limit error", wait, func(e client.Event) bool { return e.Kind == client.EvError && e.Code == wire.CodeRateLimited })
	s.CheckOutput(t)
}

func TestRooms(t *testing.T) {
	s := start(t)
	alice := s.Join(t, "alice")
	bob := s.Join(t, "bob")
	carol := s.Join(t, "carol")

	alice.C.Join("#dev", "")
	e := alice.Wait("join confirmation", wait, func(e client.Event) bool { return e.Kind == client.EvJoined && e.Self && e.Room == "#dev" })
	if !e.Created {
		t.Fatal("room creation not flagged")
	}
	bob.C.Join("#dev", "")
	bob.Wait("join", wait, func(e client.Event) bool { return e.Kind == client.EvJoined && e.Self && e.Room == "#dev" })
	alice.Wait("bob joined #dev", wait, func(e client.Event) bool { return e.Kind == client.EvJoined && e.User == "bob" && e.Room == "#dev" })

	alice.C.Chat("#dev", "room only")
	bob.Wait("room message", wait, func(e client.Event) bool { return e.Kind == client.EvChat && e.Room == "#dev" && e.Text == "room only" })
	carol.C.Chat("#dev", "intruder")
	carol.Wait("not a member", wait, testserver.Text(client.EvError, "not a member of #dev"))
	carol.C.Request(wire.THelp, "") // sync point
	carol.Wait("help", wait, testserver.Text(client.EvInfo, "Available Commands"))
	if _, ok := carol.TryWait(time.Second, func(e client.Event) bool { return e.Kind == client.EvChat && e.Text == "room only" }); ok {
		t.Fatal("non-member received a room message")
	}

	carol.C.Request(wire.TRooms, "")
	carol.Wait("room list", wait, testserver.Text(client.EvInfo, "#dev (2 users)"))
	carol.C.Request(wire.TMembers, "#dev")
	m := carol.Wait("members", wait, testserver.Text(client.EvInfo, "Members of #dev (2)"))
	if !strings.Contains(m.Text, "alice") || !strings.Contains(m.Text, "bob") {
		t.Fatalf("members: %q", m.Text)
	}

	// Leaving: the room disappears when empty.
	alice.C.Leave("#dev")
	alice.Wait("left", wait, func(e client.Event) bool { return e.Kind == client.EvLeft && e.Self && e.Room == "#dev" })
	bob.Wait("alice left", wait, func(e client.Event) bool { return e.Kind == client.EvLeft && e.User == "alice" && e.Room == "#dev" })
	bob.C.Leave("#dev")
	bob.Wait("left", wait, func(e client.Event) bool { return e.Kind == client.EvLeft && e.Self && e.Room == "#dev" })
	carol.C.Request(wire.TRooms, "")
	carol.Wait("no rooms", wait, testserver.Text(client.EvInfo, "No active rooms"))
	s.CheckOutput(t)
}

func TestPasswordRoom(t *testing.T) {
	s := start(t)
	alice := s.Join(t, "alice")
	eve := s.Join(t, "eve")
	alice.C.Join("#vault", "correct horse")
	alice.Wait("created", wait, func(e client.Event) bool { return e.Kind == client.EvJoined && e.Self && e.Room == "#vault" })

	eve.C.Join("#vault", "")
	eve.Wait("password required", wait, testserver.Text(client.EvError, "password-protected"))
	eve.C.Join("#vault", "wrong")
	eve.Wait("wrong password", wait, testserver.Text(client.EvError, "Incorrect password"))
	eve.C.Request(wire.TMembers, "#vault")
	eve.Wait("hidden members", wait, testserver.Text(client.EvError, "access denied"))
	eve.C.Join("#vault", "correct horse")
	eve.Wait("joined", wait, func(e client.Event) bool { return e.Kind == client.EvJoined && e.Self && e.Room == "#vault" })
	s.CheckOutput(t)
}

func TestRoomLimits(t *testing.T) {
	s := testserver.Start(t, bin, testserver.Config{MaxRooms: 3, MaxRoomsPerMember: 2})
	alice := s.Join(t, "alice")
	bob := s.Join(t, "bob")
	for _, r := range []string{"#a", "#b"} {
		alice.C.Join(r, "")
		alice.Wait("join "+r, wait, func(e client.Event) bool { return e.Kind == client.EvJoined && e.Self && e.Room == r })
	}
	alice.C.Join("#c", "")
	alice.Wait("per-member limit", wait, testserver.Text(client.EvError, "too many rooms"))
	bob.C.Join("#c", "")
	bob.Wait("join #c", wait, func(e client.Event) bool { return e.Kind == client.EvJoined && e.Self && e.Room == "#c" })
	bob.C.Join("#d", "")
	bob.Wait("server limit", wait, testserver.Text(client.EvError, "Too many rooms on this server"))
	s.CheckOutput(t)
}

func TestDM(t *testing.T) {
	s := start(t)
	alice := s.Join(t, "alice")
	bob := s.Join(t, "bob")
	carol := s.Join(t, "carol")
	alice.C.DM("bob", "secret: ] [DM from x]: fake")
	e := bob.Wait("dm", wait, testserver.Kind(client.EvDM))
	if e.From != "alice" || e.To != "bob" || e.Text != "secret: ] [DM from x]: fake" || e.Self {
		t.Fatalf("dm: %+v", e)
	}
	e = alice.Wait("dm echo", wait, testserver.Kind(client.EvDM))
	if !e.Self || e.To != "bob" {
		t.Fatalf("dm echo: %+v", e)
	}
	alice.C.DM("nobody", "x")
	alice.Wait("offline", wait, testserver.Text(client.EvError, "not online"))
	carol.C.Request(wire.THelp, "")
	carol.Wait("help", wait, testserver.Text(client.EvInfo, "Available Commands"))
	if _, ok := carol.TryWait(time.Second, testserver.Kind(client.EvDM)); ok {
		t.Fatal("third party received a DM")
	}
	s.CheckOutput(t)
}

func TestCommands(t *testing.T) {
	s := start(t)
	alice := s.Join(t, "alice")
	bob := s.Join(t, "bob")
	if err := alice.C.Command("/msg bob hello   there", ""); err != nil {
		t.Fatal(err)
	}
	bob.Wait("dm via command", wait, func(e client.Event) bool { return e.Kind == client.EvDM && e.Text == "hello   there" })
	alice.C.Command("/join #x", "")
	alice.Wait("join via command", wait, func(e client.Event) bool { return e.Kind == client.EvJoined && e.Self && e.Room == "#x" })
	alice.C.Command("in the room", "#x")
	alice.Wait("room chat via command", wait, func(e client.Event) bool { return e.Kind == client.EvChat && e.Room == "#x" })
	alice.C.Command("/users", "")
	alice.Wait("users", wait, testserver.Text(client.EvInfo, "Online Users (2)"))
	if err := alice.C.Command("/bogus", ""); err == nil {
		t.Fatal("unknown command accepted")
	}
	s.CheckOutput(t)
}

// ── File transfers ──────────────────────────────────────────────────

func makeFile(t *testing.T, dir, name string, size int) (string, string) {
	t.Helper()
	p := filepath.Join(dir, name)
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1<<20)
	for left := size; left > 0; {
		n := len(buf)
		if left < n {
			n = left
		}
		rand.Read(buf[:n])
		f.Write(buf[:n])
		h.Write(buf[:n])
		left -= n
	}
	return p, hex.EncodeToString(h.Sum(nil))
}

func offerAndAccept(t *testing.T, from, to *testserver.Member, path string) string {
	t.Helper()
	if _, err := from.C.OfferFile(to.Name, path); err != nil {
		t.Fatal(err)
	}
	offer := to.Wait("offer", wait, testserver.Kind(client.EvFileOffer))
	if offer.Transfer.Peer != from.Name || offer.Transfer.Name != filepath.Base(path) {
		t.Fatalf("offer: %+v", offer.Transfer)
	}
	from.Wait("offered", wait, testserver.Kind(client.EvFileOffered))
	if err := to.C.AcceptFile(offer.Transfer.ID); err != nil {
		t.Fatal(err)
	}
	return offer.Transfer.ID
}

func checkReceived(t *testing.T, e client.Event, wantSum string, size int) {
	t.Helper()
	tr := e.Transfer
	if e.Kind != client.EvFileComplete || !tr.OK || tr.ActualSHA256 != wantSum {
		t.Fatalf("receive: kind %v, %+v, %s", e.Kind, tr, e.Text)
	}
	info, err := os.Stat(tr.Path)
	if err != nil || info.Size() != int64(size) {
		t.Fatalf("saved file: %v, %v", info, err)
	}
	// No partial files left behind.
	parts, _ := filepath.Glob(filepath.Join(filepath.Dir(tr.Path), ".*.part"))
	if len(parts) != 0 {
		t.Fatalf("partial files left: %v", parts)
	}
}

func done(e client.Event) bool {
	return e.Kind == client.EvFileComplete || e.Kind == client.EvFileFailed
}

func TestFileTransferSizes(t *testing.T) {
	s := start(t)
	alice := s.Join(t, "alice")
	bob := s.Join(t, "bob")
	for _, size := range []int{1, wire.DataChunk - 1, wire.DataChunk, wire.DataChunk + 1, wire.InitialWindow, wire.InitialWindow + 1, 3*wire.InitialWindow + 12345} {
		p, sum := makeFile(t, alice.Dir, fmt.Sprintf("f%d.bin", size), size)
		offerAndAccept(t, alice, bob, p)
		checkReceived(t, bob.Wait("complete", wait, done), sum, size)
		e := alice.Wait("sent", wait, done)
		if e.Kind != client.EvFileComplete {
			t.Fatalf("sender: %+v %s", e.Transfer, e.Text)
		}
	}
	s.CheckOutput(t)
}

func TestLargeFileWithChat(t *testing.T) {
	size := 200 << 20
	if testing.Short() {
		size = 20 << 20
	}
	s := start(t)
	alice := s.Join(t, "alice")
	bob := s.Join(t, "bob")
	p, sum := makeFile(t, alice.Dir, "big.bin", size)

	begin := time.Now()
	offerAndAccept(t, alice, bob, p)

	// Chat in both directions stays responsive while the file flows.
	var worst time.Duration
	for i := 0; i < 10; i++ {
		text := fmt.Sprintf("ping %d", i)
		sent := time.Now()
		alice.C.Chat("", text)
		bob.Wait(text, wait, chatFrom("alice", text))
		if d := time.Since(sent); d > worst {
			worst = d
		}
		time.Sleep(50 * time.Millisecond)
	}
	checkReceived(t, bob.Wait("complete", 5*time.Minute, done), sum, size)
	elapsed := time.Since(begin)
	t.Logf("%d MB in %s (%.1f MB/s); worst chat latency during transfer: %s",
		size>>20, elapsed.Round(time.Millisecond), float64(size)/(1<<20)/elapsed.Seconds(), worst.Round(time.Millisecond))
	if worst > 2*time.Second {
		t.Errorf("chat latency during transfer: %s", worst)
	}
	s.CheckOutput(t)
}

func TestConcurrentTransfers(t *testing.T) {
	s := start(t)
	alice := s.Join(t, "alice")
	bob := s.Join(t, "bob")
	carol := s.Join(t, "carol")

	type job struct {
		from, to *testserver.Member
		path     string
		sum      string
		size     int
	}
	var jobs []job
	for i := 0; i < 3; i++ {
		p, sum := makeFile(t, alice.Dir, fmt.Sprintf("a%d.bin", i), 5<<20+i)
		jobs = append(jobs, job{alice, bob, p, sum, 5<<20 + i})
	}
	p, sum := makeFile(t, carol.Dir, "c.bin", 7<<20)
	jobs = append(jobs, job{carol, bob, p, sum, 7 << 20})

	// Offer everything, then accept everything: the transfers run in parallel.
	for _, j := range jobs {
		if _, err := j.from.C.OfferFile(j.to.Name, j.path); err != nil {
			t.Fatal(err)
		}
	}
	for range jobs {
		o := bob.Wait("offer", wait, testserver.Kind(client.EvFileOffer))
		if err := bob.C.AcceptFile(o.Transfer.ID); err != nil {
			t.Fatal(err)
		}
	}
	got := map[string]client.Event{}
	for len(got) < len(jobs) {
		e := bob.Wait("completion", 2*time.Minute, done)
		got[e.Transfer.Name] = e
	}
	for _, j := range jobs {
		checkReceived(t, got[filepath.Base(j.path)], j.sum, j.size)
	}
	s.CheckOutput(t)
}

func TestTransferLimits(t *testing.T) {
	s := start(t)
	alice := s.Join(t, "alice")
	bob := s.Join(t, "bob")
	p, _ := makeFile(t, alice.Dir, "x.bin", 10)
	for i := 0; i < 4; i++ {
		alice.C.OfferFile("bob", p)
		alice.Wait("offered", wait, testserver.Kind(client.EvFileOffered))
	}
	alice.C.OfferFile("bob", p)
	alice.Wait("limit", wait, func(e client.Event) bool {
		return e.Kind == client.EvFileFailed && strings.Contains(e.Text, "Too many file transfers")
	})
	alice.C.OfferFile("nobody", p)
	alice.Wait("offline", wait, func(e client.Event) bool {
		return e.Kind == client.EvFileFailed && strings.Contains(e.Text, "not online")
	})
	alice.C.OfferFile("alice", p)
	alice.Wait("self", wait, func(e client.Event) bool {
		return e.Kind == client.EvFileFailed && strings.Contains(e.Text, "yourself")
	})
	_ = bob
	s.CheckOutput(t)
}

func TestDeclineAndReceiveLimit(t *testing.T) {
	s := start(t)
	alice := s.Join(t, "alice")
	bob := s.Join(t, "bob", func(c *client.Config) { c.MaxReceive = 1000 })
	p, _ := makeFile(t, alice.Dir, "x.bin", 10)
	alice.C.OfferFile("bob", p)
	o := bob.Wait("offer", wait, testserver.Kind(client.EvFileOffer))
	bob.C.DeclineFile(o.Transfer.ID)
	alice.Wait("declined", wait, func(e client.Event) bool {
		return e.Kind == client.EvFileFailed && strings.Contains(e.Text, "declined")
	})

	big, _ := makeFile(t, alice.Dir, "big.bin", 5000)
	alice.C.OfferFile("bob", big)
	o = bob.Wait("offer", wait, testserver.Kind(client.EvFileOffer))
	if err := bob.C.AcceptFile(o.Transfer.ID); err == nil {
		t.Fatal("file above the receive limit accepted")
	}
	alice.Wait("auto-declined", wait, func(e client.Event) bool {
		return e.Kind == client.EvFileFailed && strings.Contains(e.Text, "declined")
	})
	s.CheckOutput(t)
}

// interruptSize is large enough that a transfer is still running when the
// test interrupts it right after it starts.
const interruptSize = 512 << 20

func TestTransferInterruptions(t *testing.T) {
	if testing.Short() {
		t.Skip("needs large files")
	}
	s := start(t)

	t.Run("sender cancels", func(t *testing.T) {
		alice := s.Join(t, "alice1")
		bob := s.Join(t, "bob1")
		p, _ := makeFile(t, alice.Dir, "x.bin", interruptSize)
		id := offerAndAccept(t, alice, bob, p)
		alice.Wait("streaming", wait, testserver.Kind(client.EvFileStarted))
		alice.C.CancelFile(id)
		e := bob.Wait("cancelled", wait, done)
		if e.Kind != client.EvFileFailed {
			t.Fatalf("recipient: %v", e.Kind)
		}
		assertNoPartial(t, bob.Dir)
	})

	t.Run("recipient cancels", func(t *testing.T) {
		alice := s.Join(t, "alice2")
		bob := s.Join(t, "bob2")
		p, _ := makeFile(t, alice.Dir, "x.bin", interruptSize)
		id := offerAndAccept(t, alice, bob, p)
		alice.Wait("streaming", wait, testserver.Kind(client.EvFileStarted))
		bob.C.CancelFile(id)
		e := alice.Wait("cancelled", wait, done)
		if e.Kind != client.EvFileFailed {
			t.Fatalf("sender: %v", e.Kind)
		}
		assertNoPartial(t, bob.Dir)
	})

	t.Run("recipient disconnects", func(t *testing.T) {
		alice := s.Join(t, "alice3")
		bob := s.Join(t, "bob3")
		p, _ := makeFile(t, alice.Dir, "x.bin", interruptSize)
		offerAndAccept(t, alice, bob, p)
		alice.Wait("streaming", wait, testserver.Kind(client.EvFileStarted))
		bob.C.Close()
		e := alice.Wait("failed", wait, done)
		if e.Kind != client.EvFileFailed || !strings.Contains(e.Text, "disconnected") {
			t.Fatalf("sender: %v %q", e.Kind, e.Text)
		}
		assertNoPartial(t, bob.Dir)
	})

	t.Run("sender disconnects", func(t *testing.T) {
		alice := s.Join(t, "alice4")
		bob := s.Join(t, "bob4")
		p, _ := makeFile(t, alice.Dir, "x.bin", interruptSize)
		offerAndAccept(t, alice, bob, p)
		alice.Wait("streaming", wait, testserver.Kind(client.EvFileStarted))
		alice.C.Close()
		e := bob.Wait("failed", wait, done)
		if e.Kind != client.EvFileFailed {
			t.Fatalf("recipient: %v", e.Kind)
		}
		assertNoPartial(t, bob.Dir)
	})

	t.Run("third party cannot interfere", func(t *testing.T) {
		alice := s.Join(t, "alice5")
		bob := s.Join(t, "bob5")
		eve := s.Join(t, "eve5")
		p, sum := makeFile(t, alice.Dir, "x.bin", 3<<20)
		alice.C.OfferFile("bob5", p)
		o := bob.Wait("offer", wait, testserver.Kind(client.EvFileOffer))
		// Eve learns the ID somehow and tries everything with it.
		eve.C.Command("/accept "+o.Transfer.ID, "") // unknown locally: fails client-side
		for _, m := range []wire.Msg{
			{T: wire.TFileAccept, ID: o.Transfer.ID, Bytes: wire.InitialWindow},
			{T: wire.TFileDecline, ID: o.Transfer.ID},
			{T: wire.TFileCancel, ID: o.Transfer.ID},
			{T: wire.TFileCredit, ID: o.Transfer.ID, Bytes: wire.CreditStep},
		} {
			sendRaw(t, eve, m)
		}
		eve.Wait("refused", wait, testserver.Text(client.EvError, "not for you"))
		bob.C.AcceptFile(o.Transfer.ID)
		checkReceived(t, bob.Wait("complete", wait, done), sum, 3<<20)
	})
	s.CheckOutput(t)
}

// sendRaw sends a control message the client library would never send.
func sendRaw(t *testing.T, m *testserver.Member, msg wire.Msg) {
	t.Helper()
	if err := m.C.SendMsg(msg); err != nil {
		t.Fatal(err)
	}
}

func assertNoPartial(t *testing.T, dir string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, _ := os.ReadDir(dir)
		var left []string
		for _, e := range entries {
			left = append(left, e.Name())
		}
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("files left in download dir: %v", left)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestManyMembers(t *testing.T) {
	s := start(t)
	const n = 40
	members := make([]*testserver.Member, n)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m, err := s.TryJoin(t, fmt.Sprintf("m%02d", i))
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = err
			}
			members[i] = m
		}(i)
	}
	wg.Wait()
	if firstErr != nil {
		t.Fatal(firstErr)
	}
	members[0].C.Chat("", "hello everyone")
	for _, m := range members {
		m.Wait("broadcast", wait, chatFrom("m00", "hello everyone"))
	}
	s.CheckOutput(t)
}
