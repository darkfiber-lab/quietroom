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

package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/darkfiber-lab/quietroom/client"
	"github.com/darkfiber-lab/quietroom/tests/testserver"
)

// The GUI backend (App) is driven exactly as the frontend drives it, against
// a real server, and the events it would send to the frontend are checked.

type uiEvent struct {
	name string
	data map[string]interface{}
}

type recorder struct {
	t       *testing.T
	ch      chan uiEvent
	backlog []uiEvent
}

func (r *recorder) emit(_ context.Context, name string, data ...interface{}) {
	ev := uiEvent{name: name, data: map[string]interface{}{}}
	if len(data) > 0 {
		switch d := data[0].(type) {
		case map[string]interface{}:
			ev.data = d
		case map[string]string:
			for k, v := range d {
				ev.data[k] = v
			}
		}
	}
	r.ch <- ev
}

// wait returns the first event with this name whose data matches all of
// want (string comparison); other events are kept for later waits.
func (r *recorder) wait(name string, want map[string]string) uiEvent {
	r.t.Helper()
	match := func(e uiEvent) bool {
		if e.name != name {
			return false
		}
		for k, v := range want {
			if fmt.Sprint(e.data[k]) != v {
				return false
			}
		}
		return true
	}
	for i, e := range r.backlog {
		if match(e) {
			r.backlog = append(r.backlog[:i], r.backlog[i+1:]...)
			return e
		}
	}
	deadline := time.After(20 * time.Second)
	for {
		select {
		case e := <-r.ch:
			if match(e) {
				return e
			}
			r.backlog = append(r.backlog, e)
		case <-deadline:
			r.t.Fatalf("timed out waiting for frontend event %q %v (seen: %v)", name, want, r.backlog)
		}
	}
}

func makeFile(t *testing.T, dir, name string, size int) string {
	t.Helper()
	data := make([]byte, size)
	rand.Read(data)
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGUIBackend(t *testing.T) {
	binDir := t.TempDir()
	bin, err := testserver.Build(binDir)
	if err != nil {
		t.Fatal(err)
	}
	s := testserver.Start(t, bin, testserver.Config{})
	alice := s.Join(t, "alice")
	const wait = 20 * time.Second

	rec := &recorder{t: t, ch: make(chan uiEvent, 10000)}
	downloads := t.TempDir()
	a := &App{
		ctx:  context.Background(),
		emit: rec.emit,
		config: AppConfig{
			DownloadDir:   downloads,
			DecoyEnabled:  true,
			DecoyInterval: 1,
			DecoyMinBytes: 100,
			DecoyMaxBytes: 500,
		},
	}
	host, portStr, _ := net.SplitHostPort(s.Addr)
	port, _ := strconv.Atoi(portStr)

	// Connection errors are reported, not hidden.
	if err := a.ConnectCustom(host, port, filepath.Join(t.TempDir(), "missing.pem"), "gui"); err == nil {
		t.Fatal("connected without an access file")
	}
	if err := a.ConnectCustom(host, port, s.AccessFile, "alice"); err == nil || !strings.Contains(err.Error(), "already taken") {
		t.Fatalf("duplicate name: %v", err)
	}

	if err := a.ConnectCustom(host, port, s.AccessFile, "gui"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Disconnect)
	rec.wait("connected", map[string]string{"username": "gui"})
	if !a.IsConnected() || a.GetUsername() != "gui" {
		t.Fatal("not connected")
	}
	alice.Wait("gui joined", wait, func(e client.Event) bool { return e.Kind == client.EvJoined && e.User == "gui" })
	rec.wait("user_joined", map[string]string{"username": "gui"})

	// Lobby chat both ways.
	alice.C.Chat("", "hello gui")
	rec.wait("message", map[string]string{"username": "alice", "text": "hello gui", "room": "", "isOwn": "false"})
	if err := a.SendMessage("hello alice"); err != nil {
		t.Fatal(err)
	}
	alice.Wait("lobby message", wait, func(e client.Event) bool {
		return e.Kind == client.EvChat && e.From == "gui" && e.Text == "hello alice"
	})
	rec.wait("message", map[string]string{"username": "gui", "text": "hello alice", "isOwn": "true"})

	// Rooms: the current room changes only on the server's confirmation.
	a.JoinRoom("guiroom", "")
	rec.wait("room_joined", map[string]string{"username": "gui", "room": "#guiroom", "locked": "false"})
	if a.GetCurrentRoom() != "#guiroom" {
		t.Fatalf("current room = %q", a.GetCurrentRoom())
	}
	alice.C.Join("#guiroom", "")
	rec.wait("room_joined", map[string]string{"username": "alice", "room": "#guiroom"})
	a.SendMessage("in the room")
	alice.Wait("room message", wait, func(e client.Event) bool {
		return e.Kind == client.EvChat && e.Room == "#guiroom" && e.Text == "in the room"
	})
	a.JoinRoom("#locked", "pw")
	rec.wait("room_joined", map[string]string{"username": "gui", "room": "#locked", "locked": "true"})
	alice.C.Join("#locked", "wrong")
	alice.Wait("refused", wait, func(e client.Event) bool { return e.Kind == client.EvError })
	a.SetCurrentRoom("#guiroom")

	// Lists, in the text format the frontend parses.
	a.RequestUserList()
	e := rec.wait("system_message", nil)
	if !strings.HasPrefix(fmt.Sprint(e.data["text"]), "Online Users (2):") {
		t.Fatalf("user list: %q", e.data["text"])
	}
	a.RequestMemberList("#guiroom")
	e = rec.wait("system_message", nil)
	if txt := fmt.Sprint(e.data["text"]); !strings.HasPrefix(txt, "Members of #guiroom (2):") || !strings.Contains(txt, "alice") {
		t.Fatalf("member list: %q", txt)
	}
	a.RequestRoomList()
	e = rec.wait("system_message", nil)
	if txt := fmt.Sprint(e.data["text"]); !strings.Contains(txt, "#guiroom (2 users)") || !strings.Contains(txt, "#locked 🔒") {
		t.Fatalf("room list: %q", txt)
	}

	// DMs both ways.
	a.SendDM("alice", "psst")
	alice.Wait("dm", wait, func(e client.Event) bool { return e.Kind == client.EvDM && e.From == "gui" && e.Text == "psst" })
	rec.wait("dm", map[string]string{"partner": "alice", "username": "You", "text": "psst", "isOwn": "true"})
	alice.C.DM("gui", "hey")
	rec.wait("dm", map[string]string{"partner": "alice", "username": "alice", "text": "hey", "isOwn": "false"})

	// Commands typed into the input box.
	if err := a.SendCommand("/msg alice via command"); err != nil {
		t.Fatal(err)
	}
	alice.Wait("dm via command", wait, func(e client.Event) bool { return e.Kind == client.EvDM && e.Text == "via command" })
	secret := makeFile(t, t.TempDir(), "secret.txt", 10)
	if err := a.SendCommand("/file alice " + secret); err == nil {
		t.Fatal("/file from the input box must be refused (files only via the picker)")
	}

	// Sending a file: only a path chosen with the picker is accepted.
	toSend := makeFile(t, t.TempDir(), "report.bin", 2<<20+3)
	if err := a.InitiateFileTransfer("alice", toSend); err == nil {
		t.Fatal("file sent without using the picker")
	}
	a.pickedSendPath = toSend // what PickFileToSend records
	if err := a.InitiateFileTransfer("alice", toSend); err != nil {
		t.Fatal(err)
	}
	o := alice.Wait("offer", wait, func(e client.Event) bool { return e.Kind == client.EvFileOffer })
	alice.C.AcceptFile(o.Transfer.ID)
	rec.wait("file_progress", map[string]string{"filename": "report.bin", "done": "true"})
	got := alice.Wait("received", wait, func(e client.Event) bool { return e.Kind == client.EvFileComplete || e.Kind == client.EvFileFailed })
	if !got.Transfer.OK {
		t.Fatalf("alice: %+v %s", got.Transfer, got.Text)
	}

	// Receiving a file.
	p := makeFile(t, alice.Dir, "photo.jpg", 5<<20+11)
	alice.C.OfferFile("gui", p)
	req := rec.wait("file_request", map[string]string{"filename": "photo.jpg", "senderName": "alice"})
	if err := a.AcceptFileTransfer(fmt.Sprint(req.data["transferID"])); err != nil {
		t.Fatal(err)
	}
	rec.wait("file_start", map[string]string{"filename": "photo.jpg"})
	done := rec.wait("file_complete", map[string]string{"filename": "photo.jpg", "hashMatch": "true"})
	if path := fmt.Sprint(done.data["downloadPath"]); filepath.Dir(path) != downloads {
		t.Fatalf("saved to %s", path)
	} else if info, err := os.Stat(path); err != nil || info.Size() != 5<<20+11 {
		t.Fatalf("saved file: %v %v", info, err)
	}

	// Declining.
	alice.C.OfferFile("gui", p)
	req = rec.wait("file_request", nil)
	a.DeclineFileTransfer(fmt.Sprint(req.data["transferID"]))
	alice.Wait("declined", wait, func(e client.Event) bool {
		return e.Kind == client.EvFileFailed && strings.Contains(e.Text, "declined")
	})

	// Cancelling a running transfer.
	big := makeFile(t, alice.Dir, "big.bin", 256<<20)
	alice.C.OfferFile("gui", big)
	req = rec.wait("file_request", map[string]string{"filename": "big.bin"})
	id := fmt.Sprint(req.data["transferID"])
	a.AcceptFileTransfer(id)
	rec.wait("file_start", map[string]string{"filename": "big.bin"})
	a.CancelFileTransfer(id)
	rec.wait("file_failed", map[string]string{"filename": "big.bin"})
	alice.Wait("cancelled", wait, func(e client.Event) bool { return e.Kind == client.EvFileFailed && e.Transfer.Name == "big.bin" })
	entries, _ := os.ReadDir(downloads)
	for _, en := range entries {
		if strings.HasSuffix(en.Name(), ".part") {
			t.Fatalf("partial file left: %s", en.Name())
		}
	}

	// Leaving and disconnecting.
	a.LeaveRoom("#guiroom")
	rec.wait("room_left", map[string]string{"username": "gui", "room": "#guiroom"})
	if a.GetCurrentRoom() != "" {
		t.Fatalf("current room after leave = %q", a.GetCurrentRoom())
	}
	alice.C.Close()
	rec.wait("user_left", map[string]string{"username": "alice"})
	a.Disconnect()
	rec.wait("disconnected", nil)
	if a.IsConnected() {
		t.Fatal("still connected")
	}
	s.CheckOutput(t)
}
