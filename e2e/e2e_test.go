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

package e2e

import (
	"bytes"
	"strings"
	"testing"
)

func mustID(t *testing.T) *Identity {
	t.Helper()
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func pairs(t *testing.T) (a, b *Pair, ida, idb *Identity) {
	t.Helper()
	ida, idb = mustID(t), mustID(t)
	a, err := ida.NewPair(idb.Public())
	if err != nil {
		t.Fatal(err)
	}
	b, err = idb.NewPair(ida.Public())
	if err != nil {
		t.Fatal(err)
	}
	return a, b, ida, idb
}

func TestPairRoundTripBothDirections(t *testing.T) {
	a, b, _, _ := pairs(t)
	for i := 0; i < 5; i++ {
		n, ct, err := a.Seal("dm", []byte("hello bob"))
		if err != nil || n != uint32(i) {
			t.Fatalf("seal %d: n=%d err=%v", i, n, err)
		}
		got, err := b.Open("dm", n, ct)
		if err != nil || string(got) != "hello bob" {
			t.Fatalf("open %d: %q %v", i, got, err)
		}
		n, ct, _ = b.Seal("dm", []byte("hi alice"))
		if got, err := a.Open("dm", n, ct); err != nil || string(got) != "hi alice" {
			t.Fatalf("reply %d: %q %v", i, got, err)
		}
	}
}

func TestPairRejectsTamperReplayTypeAndStranger(t *testing.T) {
	a, b, _, _ := pairs(t)
	n, ct, _ := a.Seal("dm", []byte("secret"))

	bad := append([]byte{}, ct...)
	bad[3] ^= 1
	if _, err := b.Open("dm", n, bad); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	if _, err := b.Open("rkey", n, ct); err == nil {
		t.Fatal("message accepted under another wire type")
	}
	if _, err := b.Open("dm", n+1, ct); err == nil {
		t.Fatal("message accepted under another counter")
	}
	// The failures above must not have disturbed the channel.
	if got, err := b.Open("dm", n, ct); err != nil || string(got) != "secret" {
		t.Fatalf("genuine message after failures: %q %v", got, err)
	}
	if _, err := b.Open("dm", n, ct); err == nil {
		t.Fatal("replay accepted")
	}

	// A third member (or the server) with its own keys cannot read it.
	mallory := mustID(t)
	m, _ := mallory.NewPair(a.self)
	n2, ct2, _ := a.Seal("dm", []byte("again"))
	if _, err := m.Open("dm", n2, ct2); err == nil {
		t.Fatal("stranger decrypted a pair message")
	}
}

func TestPairOutOfOrderAndSkip(t *testing.T) {
	a, b, _, _ := pairs(t)
	type msg struct {
		n  uint32
		ct []byte
	}
	var msgs []msg
	for i := 0; i < 10; i++ {
		n, ct, _ := a.Seal("dm", []byte{byte('0' + i)})
		msgs = append(msgs, msg{n, ct})
	}
	order := []int{2, 0, 9, 1, 5, 3}
	for _, i := range order {
		got, err := b.Open("dm", msgs[i].n, msgs[i].ct)
		if err != nil || got[0] != byte('0'+i) {
			t.Fatalf("message %d: %q %v", i, got, err)
		}
	}
	// Too far ahead is refused.
	for i := 0; i < MaxSkip+2; i++ {
		a.Seal("dm", nil)
	}
	n, ct, _ := a.Seal("dm", []byte("far"))
	if _, err := b.Open("dm", n, ct); err == nil {
		t.Fatal("counter beyond MaxSkip accepted")
	}
}

func TestPairMismatchedKeysFail(t *testing.T) {
	// The server hands alice a substituted key for bob: alice and bob end up
	// on different channels, and nothing decrypts.
	ida, idb, server := mustID(t), mustID(t), mustID(t)
	aliceToFake, _ := ida.NewPair(server.Public())
	bobFromAlice, _ := idb.NewPair(ida.Public())
	n, ct, _ := aliceToFake.Seal("dm", []byte("hi"))
	if _, err := bobFromAlice.Open("dm", n, ct); err == nil {
		t.Fatal("decrypted across substituted keys")
	}
	if SafetyNumber("bob", server.Public()) == SafetyNumber("bob", idb.Public()) {
		t.Fatal("substituted key has the same safety number")
	}
}

func TestSafetyNumberFormat(t *testing.T) {
	id := mustID(t)
	s := SafetyNumber("Alice", id.Public())
	if len(s) != 35 || strings.Count(s, " ") != 5 {
		t.Fatalf("unexpected format %q", s)
	}
	if s != SafetyNumber("alice", id.Public()) {
		t.Fatal("safety number depends on name case")
	}
}

func TestPadding(t *testing.T) {
	for _, n := range []int{0, 1, 62, 63, 64, 1000, 8192, MaxPadded - 1} {
		p, err := pad(bytes.Repeat([]byte{0}, n))
		if err != nil {
			t.Fatalf("pad %d: %v", n, err)
		}
		if len(p)&(len(p)-1) != 0 || len(p) < minPadded {
			t.Fatalf("pad %d gave %d bytes", n, len(p))
		}
		u, err := unpad(p)
		if err != nil || len(u) != n {
			t.Fatalf("unpad %d: %d %v", n, len(u), err)
		}
	}
	if _, err := pad(make([]byte, MaxPadded)); err == nil {
		t.Fatal("oversized plaintext padded")
	}
	if _, err := unpad(make([]byte, 64)); err == nil {
		t.Fatal("all-zero block unpadded")
	}
}

func TestParsePublicKeys(t *testing.T) {
	id := mustID(t)
	kx, sk := id.Public().Encode()
	p, err := ParsePublicKeys(kx, sk)
	if err != nil || !p.Equal(id.Public()) {
		t.Fatalf("round trip: %v", err)
	}
	for _, c := range [][2]string{{"", sk}, {kx, ""}, {"!!", sk}, {kx, Encode(make([]byte, 31))}, {Encode(make([]byte, 64)), sk}} {
		if _, err := ParsePublicKeys(c[0], c[1]); err == nil {
			t.Fatalf("accepted %q %q", c[0], c[1])
		}
	}
	// A low-order X25519 point yields an all-zero secret and is refused.
	zero := Encode(make([]byte, 32))
	if p, err := ParsePublicKeys(zero, sk); err == nil {
		if _, err := id.NewPair(p); err == nil {
			t.Fatal("low-order key accepted for a channel")
		}
	}
}

func TestRoomFlow(t *testing.T) {
	ida, idb := mustID(t), mustID(t)
	rs := DeriveRoom("#team", "correct horse battery staple")
	if !bytes.Equal(rs.Verifier, DeriveRoom("#team", "correct horse battery staple").Verifier) {
		t.Fatal("verifier not deterministic")
	}
	if bytes.Equal(rs.Verifier, DeriveRoom("#team", "wrong").Verifier) || bytes.Equal(rs.Verifier, DeriveRoom("#other", "correct horse battery staple").Verifier) {
		t.Fatal("verifier ignores password or room")
	}

	proof := rs.Proof("Alice", ida.Public())
	if !rs.CheckProof("alice", ida.Public(), proof) {
		t.Fatal("valid proof refused")
	}
	if rs.CheckProof("alice", idb.Public(), proof) || rs.CheckProof("bob", ida.Public(), proof) {
		t.Fatal("proof not bound to member")
	}
	if DeriveRoom("#team", "wrong").CheckProof("alice", ida.Public(), proof) {
		t.Fatal("proof checks with the wrong password")
	}

	send, _ := NewSender("#team")
	for i := 0; i < 3; i++ { // messages before bob joined
		send.Seal(ida, []byte("old"))
	}
	recv, err := NewReceiver("#team", ida.Public(), send.Key())
	if err != nil {
		t.Fatal(err)
	}
	kid, n, ct, sig, _ := send.Seal(ida, []byte("hello room"))
	if n != 3 {
		t.Fatalf("counter %d", n)
	}
	if got, err := recv.Open(kid, n, ct, sig); err != nil || string(got) != "hello room" {
		t.Fatalf("open: %q %v", got, err)
	}

	// Forged signature, wrong key ID, other room, other sender: refused.
	kid, n, ct, sig, _ = send.Seal(ida, []byte("x"))
	badSig := append([]byte{}, sig...)
	badSig[0] ^= 1
	if _, err := recv.Open(kid, n, ct, badSig); err == nil {
		t.Fatal("bad signature accepted")
	}
	if _, err := recv.Open(kid+1, n, ct, sig); err == nil {
		t.Fatal("wrong key id accepted")
	}
	other, _ := NewReceiver("#elsewhere", ida.Public(), send.Key())
	if _, err := other.Open(kid, n, ct, sig); err == nil {
		t.Fatal("message accepted in another room")
	}
	// Bob holds alice's chain key, so he could compute the ciphertext, but
	// without alice's signing key the message is refused.
	impostor := &Sender{room: "#team", kid: send.kid, c: send.c}
	ikid, in, ict, isig, _ := impostor.Seal(idb, []byte("I am alice"))
	if _, err := recv.Open(ikid, in, ict, isig); err == nil {
		t.Fatal("member forged a message from another member")
	}
	if got, err := recv.Open(kid, n, ct, sig); err != nil || string(got) != "x" {
		t.Fatalf("genuine message after forgeries: %q %v", got, err)
	}
}

func TestFileStream(t *testing.T) {
	key, _ := NewFileKey()
	data := bytes.Repeat([]byte("0123456789"), PlainChunk/10*2+77)
	size := int64(len(data))
	chunks := int((size + PlainChunk - 1) / PlainChunk)
	if CipherSize(size) != int64(chunks*CipherChunk) {
		t.Fatal("CipherSize mismatch")
	}
	s, _ := NewFileSealer(key)
	var cts [][]byte
	for i := 0; i < chunks; i++ {
		end := (i + 1) * PlainChunk
		if end > len(data) {
			end = len(data)
		}
		ct, err := s.Seal(data[i*PlainChunk:end], i == chunks-1)
		if err != nil || len(ct) != CipherChunk {
			t.Fatalf("seal chunk %d: %v", i, err)
		}
		cts = append(cts, ct)
	}
	open := func(order []int, lastAt int) ([]byte, error) {
		o, _ := NewFileOpener(key)
		var out []byte
		for j, i := range order {
			p, err := o.Open(cts[i], j == lastAt)
			if err != nil {
				return nil, err
			}
			out = append(out, p...)
		}
		return out[:min(len(out), len(data))], nil
	}
	got, err := open([]int{0, 1, 2}, 2)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := open([]int{1, 0, 2}, 2); err == nil {
		t.Fatal("reordered chunks accepted")
	}
	if _, err := open([]int{0, 1}, 1); err == nil {
		t.Fatal("truncated file accepted as complete")
	}
	wrong, _ := NewFileKey()
	o, _ := NewFileOpener(wrong)
	if _, err := o.Open(cts[0], false); err == nil {
		t.Fatal("wrong key decrypted")
	}
}
