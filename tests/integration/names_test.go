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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/darkfiber-lab/quietroom/client"
	"github.com/darkfiber-lab/quietroom/wire"
)

// TestUsernameRules: names are unique regardless of case and may not
// contain spaces; members are addressed case-insensitively and shown with
// their own spelling.
func TestUsernameRules(t *testing.T) {
	s := start(t)
	alice := s.Join(t, "Alice")
	bob := s.Join(t, "bob")

	for _, name := range []string{"alice", "ALICE", "Bob"} {
		_, err := s.TryJoin(t, name)
		var le *client.LoginError
		if !errors.As(err, &le) || le.Code != wire.CodeUsernameTaken {
			t.Errorf("%q while Alice and bob are online: %v", name, err)
		}
	}
	_, err := s.TryJoin(t, "bob smith")
	var le *client.LoginError
	if !errors.As(err, &le) || le.Code != wire.CodeInvalidUsername || !strings.Contains(le.Text, "no spaces") {
		t.Errorf("name with a space: %v", err)
	}

	// DMs and files reach the member under any capitalisation, and are
	// labelled with the member's own spelling.
	bob.C.DM("aLiCe", "hi")
	e := alice.Wait("dm", wait, func(e client.Event) bool { return e.Kind == client.EvDM && e.From == "bob" })
	if e.To != "Alice" || e.Text != "hi" {
		t.Fatalf("dm: %+v", e)
	}
	p := filepath.Join(bob.Dir, "x.txt")
	os.WriteFile(p, []byte("data"), 0600)
	bob.C.OfferFile("ALICE", p)
	o := bob.Wait("offered", wait, func(e client.Event) bool { return e.Kind == client.EvFileOffered })
	if o.Transfer.Peer != "Alice" {
		t.Errorf("offer peer = %q, want Alice", o.Transfer.Peer)
	}
	alice.Wait("offer", wait, func(e client.Event) bool { return e.Kind == client.EvFileOffer })

	bob.C.Request(wire.TUsers, "")
	e = bob.Wait("users", wait, func(e client.Event) bool { return e.Kind == client.EvInfo && strings.HasPrefix(e.Text, "Online Users") })
	if !strings.Contains(e.Text, "Alice") || strings.Contains(e.Text, "alice") {
		t.Errorf("user list does not show the real spelling: %q", e.Text)
	}

	// After Alice leaves, the name (in any case) is free again.
	alice.C.Close()
	bob.Wait("left", wait, func(e client.Event) bool { return e.Kind == client.EvLeft && e.User == "Alice" && e.Room == "" })
	s.Join(t, "alice")
	s.CheckOutput(t)
}

// TestHiddenCharactersRemoved: bidi overrides and zero-width characters
// never reach other members, in chat text, DMs or file names.
func TestHiddenCharactersRemoved(t *testing.T) {
	s := start(t)
	alice := s.Join(t, "alice")
	bob := s.Join(t, "bob")

	alice.C.Chat("", "pay to ‮dlrow‬ now​!")
	e := bob.Wait("chat", wait, func(e client.Event) bool { return e.Kind == client.EvChat && e.From == "alice" })
	if e.Text != "pay to dlrow now!" {
		t.Errorf("chat text = %q", e.Text)
	}
	alice.C.DM("bob", "multi\nline ⁦text⁩ 👨‍👩‍👧")
	e = bob.Wait("dm", wait, func(e client.Event) bool { return e.Kind == client.EvDM && e.From == "alice" })
	if e.Text != "multi\nline text 👨‍👩‍👧" {
		t.Errorf("dm text = %q", e.Text)
	}
	// Text that is only hidden characters is not sent at all.
	alice.C.Chat("", "‮​")
	alice.C.Chat("", "marker")
	e = bob.Wait("next chat", wait, func(e client.Event) bool { return e.Kind == client.EvChat && e.From == "alice" })
	if e.Text != "marker" {
		t.Errorf("empty message was relayed: %q", e.Text)
	}

	p := filepath.Join(alice.Dir, "invoice‮gpj.exe")
	if err := os.WriteFile(p, []byte("MZ"), 0600); err != nil {
		t.Skipf("file system refuses the name: %v", err)
	}
	alice.C.OfferFile("bob", p)
	o := bob.Wait("offer", wait, func(e client.Event) bool { return e.Kind == client.EvFileOffer })
	if o.Transfer.Name != "invoicegpj.exe" {
		t.Fatalf("offered name = %q", o.Transfer.Name)
	}
	bob.C.AcceptFile(o.Transfer.ID)
	done := bob.Wait("received", wait, func(e client.Event) bool { return e.Kind == client.EvFileComplete || e.Kind == client.EvFileFailed })
	if done.Kind != client.EvFileComplete || filepath.Base(done.Transfer.Path) != "invoicegpj.exe" {
		t.Fatalf("saved as %q (%s)", done.Transfer.Path, done.Text)
	}
	s.CheckOutput(t)
}
