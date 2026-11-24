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

package attack

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/darkfiber-lab/quietroom/client"
	"github.com/darkfiber-lab/quietroom/tests/testserver"
	"github.com/darkfiber-lab/quietroom/wire"
)

const sha = "0000000000000000000000000000000000000000000000000000000000000000"

// forgeAccessCert copies the subject and validity of the real access
// certificate onto an attacker-owned key.
func forgeAccessCert(t *testing.T, real tls.Certificate) tls.Certificate {
	t.Helper()
	orig, err := x509.ParseCertificate(real.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: orig.SerialNumber, Subject: orig.Subject,
		NotBefore: orig.NotBefore, NotAfter: orig.NotAfter,
		KeyUsage: orig.KeyUsage, ExtKeyUsage: orig.ExtKeyUsage,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestAccessKeyRequired: only holders of the current access file get in.
func TestAccessKeyRequired(t *testing.T) {
	s := start(t, testserver.Config{})

	if info, err := os.Stat(s.AccessFile); err != nil {
		t.Fatal(err)
	} else if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("access file mode = %o, want 600", mode)
	}

	t.Run("no client certificate", func(t *testing.T) {
		if !rejected(dialTLS(s, s.ServerCert, nil)) {
			t.Fatal("server accepted a session without an access key")
		}
	})
	t.Run("forged access certificate", func(t *testing.T) {
		if !rejected(dialTLS(s, s.ServerCert, []tls.Certificate{forgeAccessCert(t, s.Access)})) {
			t.Fatal("server accepted a forged access certificate")
		}
	})
	t.Run("access file from another server run", func(t *testing.T) {
		other := start(t, testserver.Config{})
		if !rejected(dialTLS(s, s.ServerCert, []tls.Certificate{other.Access})) {
			t.Fatal("server accepted the access key of a different run")
		}
		// A client with the stale file is stopped at the gate and gets a
		// clear message.
		if _, err := client.Dial(client.Config{Addr: s.Addr, AccessFile: other.AccessFile, Username: "stale"}); err == nil ||
			!strings.Contains(err.Error(), "wrong or outdated") {
			t.Fatalf("client with a stale access file: %v", err)
		}
	})
	t.Run("plain TCP garbage", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", s.Addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		expectClosed(t, conn, 10*time.Second)
	})
	t.Run("valid access key", func(t *testing.T) {
		m := s.Join(t, uniqueName("member"))
		m.C.Request(wire.THelp, "")
		m.Wait("help", 15*time.Second, testserver.Text(client.EvInfo, "Available Commands"))
	})
	healthy(t, s)
}

// TestGateSilentToStrangers: without a valid gate token the server closes
// the connection without sending anything, so scanners never see its
// certificate or any TLS alert.
func TestGateSilentToStrangers(t *testing.T) {
	s := start(t, testserver.Config{})
	other := start(t, testserver.Config{})
	now := time.Now()

	t.Run("valid token gets a TLS reply", func(t *testing.T) {
		if n, _ := serverReply(t, s, clientHello(t, wire.GateToken(s.GateKey, now))); n == 0 {
			t.Fatal("server did not answer a valid ClientHello")
		}
	})
	cases := map[string][]byte{
		"nothing at all":                  nil,
		"http request":                    []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		"ClientHello without server name": clientHello(t, ""),
		"ClientHello with a host name":    clientHello(t, "example.com"),
		"random token":                    clientHello(t, strings.Repeat("ab", wire.GateTokenLen/2)),
		"token of another server":         clientHello(t, wire.GateToken(other.GateKey, now)),
		"expired token":                   clientHello(t, wire.GateToken(s.GateKey, now.Add(-20*time.Minute))),
		"token from the future":           clientHello(t, wire.GateToken(s.GateKey, now.Add(20*time.Minute))),
		"oversize record header":          {22, 3, 1, 0xff, 0xff},
		"TLS alert record":                {21, 3, 3, 0, 2, 2, 40},
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) { silent(t, s, payload) })
	}
	t.Run("replayed token", func(t *testing.T) {
		hello := clientHello(t, wire.GateToken(s.GateKey, now))
		if n, _ := serverReply(t, s, hello); n == 0 {
			t.Fatal("first use refused")
		}
		silent(t, s, hello)
		silent(t, s, hello)
	})
	t.Run("standard TLS client", func(t *testing.T) {
		// What a scanner or openssl s_client does: the handshake fails
		// without the server's certificate ever arriving.
		var seen bool
		_, err := dialTLSName(s, s.ServerCert, nil, "")
		cfg := &tls.Config{InsecureSkipVerify: true, VerifyConnection: func(tls.ConnectionState) error { seen = true; return nil }}
		conn, err2 := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", s.Addr, cfg)
		if err == nil || err2 == nil || seen {
			if conn != nil {
				conn.Close()
			}
			t.Fatalf("handshake without a token: %v / %v (certificate seen: %v)", err, err2, seen)
		}
	})
	t.Run("clock skew within limits", func(t *testing.T) {
		conn, err := dialTLSName(s, s.ServerCert, []tls.Certificate{s.Access}, wire.GateToken(s.GateKey, now.Add(-4*time.Minute)))
		if rejected(conn, err) {
			t.Fatal("token from 4 minutes ago refused")
		}
	})
	t.Run("slow ClientHello", func(t *testing.T) {
		// Dribbling the ClientHello byte by byte is cut off by the
		// handshake timeout, not held open forever.
		conn, err := net.DialTimeout("tcp", s.Addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.Write([]byte{22, 3, 1, 0x40, 0x00})
		start := time.Now()
		expectClosed(t, conn, 30*time.Second)
		if d := time.Since(start); d < 5*time.Second {
			t.Fatalf("closed after only %s", d)
		}
	})
	healthy(t, s)
}

// TestSilentPeersDropped: peers that connect and say nothing are dropped
// after the handshake timeout, with or without a valid access key.
func TestSilentPeersDropped(t *testing.T) {
	t.Parallel()
	s := start(t, testserver.Config{})
	var wg sync.WaitGroup
	check := func(name string, conn net.Conn) {
		defer wg.Done()
		defer conn.Close()
		start := time.Now()
		expectClosed(t, conn, 30*time.Second)
		t.Logf("%s dropped after %s", name, time.Since(start).Round(time.Second))
	}
	tcp, err := net.DialTimeout("tcp", s.Addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r := rawSession(t, s) // valid TLS, never sends hello
	wg.Add(2)
	go check("silent TCP", tcp)
	go check("TLS without hello", r.conn)
	wg.Wait()
	healthy(t, s)
}

// TestMalformedFrames: broken frames before and after login end that
// connection only.
func TestMalformedFrames(t *testing.T) {
	s := start(t, testserver.Config{})
	bystander := s.Join(t, "bystander")
	cases := map[string][]byte{
		"length 0":            {0, 0, 0, 0},
		"length 4 GB":         frame(0xFFFFFFFF, wire.FrameControl, 0, 0, nil),
		"length over max":     frame(wire.MaxFrame, wire.FrameControl, 0, 0, make([]byte, 64)),
		"padding over frame":  frame(10, wire.FrameControl, 0, 9, make([]byte, 6)),
		"unknown frame type":  frame(4, 0x7f, 0, 0, nil),
		"flags set":           frame(4, wire.FrameControl, 0x80, 0, nil),
		"not JSON":            controlFrame([]byte("hello there")),
		"JSON without type":   controlFrame([]byte(`{"user":"x"}`)),
		"JSON array":          controlFrame([]byte(`[1,2,3]`)),
		"invalid UTF-8":       controlFrame([]byte("{\"t\":\"chat\",\"text\":\"\xff\xfe\"}")),
		"wrong field type":    controlFrame([]byte(`{"t":"chat","size":"big"}`)),
		"truncated frame":     frame(1000, wire.FrameControl, 0, 0, make([]byte, 10)),
		"data frame as hello": frame(4+16, wire.FrameData, 0, 0, make([]byte, 16)),
	}
	for name, b := range cases {
		t.Run("before login/"+name, func(t *testing.T) {
			r := rawSession(t, s)
			r.write(b)
			if name == "truncated frame" {
				r.conn.CloseWrite()
			}
			expectClosed(t, r.conn, 20*time.Second)
		})
		t.Run("after login/"+name, func(t *testing.T) {
			r := rawLogin(t, s, uniqueName("fuzz"))
			r.write(b)
			if name == "truncated frame" {
				r.conn.CloseWrite()
			}
			if name == "data frame as hello" {
				// A data frame for an unknown transfer is ignored, not fatal.
				r.send(wire.Msg{T: wire.THelp})
				r.waitFor("help", func(m wire.Msg) bool { return strings.Contains(m.Text, "Available Commands") })
				return
			}
			expectClosed(t, r.conn, 20*time.Second)
		})
	}

	t.Run("wrong protocol version", func(t *testing.T) {
		r := rawSession(t, s)
		r.send(wire.Msg{T: wire.THello, V: 2, User: "old"})
		m := r.next(10 * time.Second)
		if m.T != wire.TError || m.Code != wire.CodeVersion {
			t.Fatalf("got %+v", m)
		}
		expectClosed(t, r.conn, 10*time.Second)
	})
	t.Run("request before hello", func(t *testing.T) {
		r := rawSession(t, s)
		r.send(wire.Msg{T: wire.TChat, Text: "skip login"})
		expectClosed(t, r.conn, 10*time.Second)
	})
	t.Run("unknown message type", func(t *testing.T) {
		r := rawLogin(t, s, uniqueName("u"))
		r.send(wire.Msg{T: "make_admin"})
		r.waitFor("error", func(m wire.Msg) bool { return m.T == wire.TError && strings.Contains(m.Text, "Unknown request") })
	})

	// The bystander never saw any of it.
	bystander.C.Request(wire.THelp, "")
	bystander.Wait("help", 15*time.Second, testserver.Text(client.EvInfo, "Available Commands"))
	healthy(t, s)
}

// TestHostileUsernames: names that could inject markup, escapes or
// confusables are refused, and names are unique.
func TestHostileUsernames(t *testing.T) {
	s := start(t, testserver.Config{})
	for name, user := range map[string]string{
		"empty":            "",
		"spaces only":      "   ",
		"leading space":    " admin",
		"control char":     "ab\x07cd",
		"newline":          "ab\ncd",
		"too long":         strings.Repeat("a", 33),
		"html":             "<b>x</b>",
		"non-ascii":        "ädmin",
		"ansi escape":      "\x1b[31mred",
		"zero-width space": "ad​min",
	} {
		t.Run(name, func(t *testing.T) {
			r := rawSession(t, s)
			r.send(wire.Msg{T: wire.THello, V: wire.Version, User: user})
			m := r.next(10 * time.Second)
			if m.T != wire.TError || m.Code != wire.CodeInvalidUsername {
				t.Fatalf("got %+v", m)
			}
			expectClosed(t, r.conn, 10*time.Second)
		})
	}
	t.Run("duplicate", func(t *testing.T) {
		name := uniqueName("taken")
		rawLogin(t, s, name)
		r := rawSession(t, s)
		r.send(wire.Msg{T: wire.THello, V: wire.Version, User: name})
		if m := r.next(10 * time.Second); m.T != wire.TError || m.Code != wire.CodeUsernameTaken {
			t.Fatalf("got %+v", m)
		}
	})
	healthy(t, s)
}

// TestSpoofing: fields a client sends about itself are never trusted.
func TestSpoofing(t *testing.T) {
	s := start(t, testserver.Config{})
	mallory := rawLogin(t, s, "mallory")
	alice := s.Join(t, "alice")

	mallory.send(wire.Msg{T: wire.TChat, From: "alice", User: "alice", Time: "00:00:00", Text: "I am alice"})
	e := alice.Wait("chat", 15*time.Second, testserver.Text(client.EvChat, "I am alice"))
	if e.From != "mallory" || e.Time == "00:00:00" {
		t.Fatalf("spoofed chat: %+v", e)
	}
	mallory.send(wire.Msg{T: wire.TDM, To: "alice", From: "admin", Text: "trust me"})
	e = alice.Wait("dm", 15*time.Second, testserver.Kind(client.EvDM))
	if e.From != "mallory" {
		t.Fatalf("spoofed DM sender: %+v", e)
	}
	// Presence and transfer messages are server-only.
	for _, m := range []wire.Msg{
		{T: wire.TJoined, User: "admin", Room: "#x"},
		{T: wire.TWelcome, User: "alice"},
		{T: wire.TFileOffered, ID: strings.Repeat("ab", 16)},
		{T: wire.TFileDone, ID: strings.Repeat("ab", 16)},
	} {
		mallory.send(m)
		mallory.waitFor("refusal of "+m.T, func(r wire.Msg) bool { return r.T == wire.TError && strings.Contains(r.Text, "Unknown request") })
	}
	healthy(t, s)
}

// TestRoomAbuse: hostile room names, password rooms and membership checks.
func TestRoomAbuse(t *testing.T) {
	s := start(t, testserver.Config{})
	alice := s.Join(t, "alice")
	eve := rawLogin(t, s, "eve")

	for _, room := range []string{"#<script>alert(1)</script>", "#" + strings.Repeat("r", 33), "#ünïcode", "#a\x1b[2J", "#", "noprefix", ""} {
		eve.send(wire.Msg{T: wire.TJoin, Room: room})
		eve.waitFor("invalid room", func(m wire.Msg) bool { return m.T == wire.TError && strings.Contains(m.Text, "Invalid room name") })
	}
	eve.send(wire.Msg{T: wire.TJoin, Room: "#x", Password: strings.Repeat("p", wire.MaxPasswordBytes+1)})
	eve.waitFor("long password", func(m wire.Msg) bool { return m.T == wire.TError && strings.Contains(m.Text, "Password too long") })

	alice.C.Join("#vault", "correct horse")
	alice.Wait("joined", 15*time.Second, func(e client.Event) bool { return e.Kind == client.EvJoined && e.Self && e.Room == "#vault" })
	eve.send(wire.Msg{T: wire.TChat, Room: "#vault", Text: "let me in"})
	eve.waitFor("not a member", func(m wire.Msg) bool { return m.T == wire.TError && strings.Contains(m.Text, "not a member of #vault") })
	eve.send(wire.Msg{T: wire.TLeave, Room: "#vault"})
	eve.waitFor("not in room", func(m wire.Msg) bool { return m.T == wire.TError && strings.Contains(m.Text, "not in room") })

	alice.C.Chat("#vault", "the-secret-payload")
	eve.send(wire.Msg{T: wire.THelp}) // sync point
	for {
		m := eve.next(15 * time.Second)
		if strings.Contains(m.Text, "the-secret-payload") {
			t.Fatal("non-member received a password-room message")
		}
		if m.T == wire.TInfo && strings.Contains(m.Text, "Available Commands") {
			break
		}
	}
	healthy(t, s)
}

// sha256 hex of n zero bytes is not needed: the server does not verify file
// content, only sizes and flow control. Recipients verify hashes.

// offerRaw makes sender offer a file of size bytes to recipient and has the
// recipient accept with the given window. Returns the transfer ID.
func offerRaw(t *testing.T, sender, recipient *raw, size, window int64) [wire.IDLen]byte {
	t.Helper()
	sender.send(wire.Msg{T: wire.TFileOffer, Ref: "1", To: recipient.name, Name: "f.bin", Size: size, SHA256: sha})
	offer := recipient.waitFor("offer", func(m wire.Msg) bool { return m.T == wire.TFileOffer })
	sender.waitFor("offered", func(m wire.Msg) bool { return m.T == wire.TFileOffered })
	recipient.send(wire.Msg{T: wire.TFileAccept, ID: offer.ID, Bytes: window})
	sender.waitFor("accept", func(m wire.Msg) bool { return m.T == wire.TFileAccept })
	id, _ := wire.ParseID(offer.ID)
	return id
}

func dataFrame(id [wire.IDLen]byte, n int) []byte {
	f, err := wire.EncodeData(id, make([]byte, n))
	if err != nil {
		panic(err)
	}
	return f
}

func cancelled(reason string) func(wire.Msg) bool {
	return func(m wire.Msg) bool { return m.T == wire.TFileCancel && strings.Contains(m.Text, reason) }
}

// TestTransferAbuse: a malicious sender or recipient can only break its own
// transfer, never the server or anyone else's transfer.
func TestTransferAbuse(t *testing.T) {
	s := start(t, testserver.Config{})

	t.Run("sender exceeds credit", func(t *testing.T) {
		a, b := rawLogin(t, s, uniqueName("a")), rawLogin(t, s, uniqueName("b"))
		id := offerRaw(t, a, b, 10<<20, 64<<10)
		a.write(dataFrame(id, wire.DataChunk))
		a.write(dataFrame(id, wire.DataChunk))
		a.write(dataFrame(id, 64<<10-2*wire.DataChunk+1)) // one byte over the window
		a.waitFor("cancel", cancelled("exceeded flow-control credit"))
		b.waitFor("cancel", cancelled("exceeded flow-control credit"))
	})
	t.Run("sender sends more than announced", func(t *testing.T) {
		a, b := rawLogin(t, s, uniqueName("a")), rawLogin(t, s, uniqueName("b"))
		id := offerRaw(t, a, b, 100, wire.InitialWindow)
		a.write(dataFrame(id, 101))
		b.waitFor("cancel", cancelled("more data than announced"))
	})
	t.Run("early file_end", func(t *testing.T) {
		a, b := rawLogin(t, s, uniqueName("a")), rawLogin(t, s, uniqueName("b"))
		id := offerRaw(t, a, b, 1000, wire.InitialWindow)
		a.write(dataFrame(id, 10))
		a.send(wire.Msg{T: wire.TFileEnd, ID: wire.IDString(id)})
		b.waitFor("cancel", cancelled("incomplete"))
	})
	t.Run("data before acceptance", func(t *testing.T) {
		a, b := rawLogin(t, s, uniqueName("a")), rawLogin(t, s, uniqueName("b"))
		a.send(wire.Msg{T: wire.TFileOffer, Ref: "1", To: b.name, Name: "f.bin", Size: 100, SHA256: sha})
		offered := a.waitFor("offered", func(m wire.Msg) bool { return m.T == wire.TFileOffered })
		id, _ := wire.ParseID(offered.ID)
		a.write(dataFrame(id, 10))
		b.waitFor("cancel", cancelled("before acceptance"))
	})
	t.Run("recipient over-grants credit", func(t *testing.T) {
		a, b := rawLogin(t, s, uniqueName("a")), rawLogin(t, s, uniqueName("b"))
		id := offerRaw(t, a, b, 100<<20, wire.InitialWindow)
		b.send(wire.Msg{T: wire.TFileCredit, ID: wire.IDString(id), Bytes: wire.MaxWindow})
		a.waitFor("cancel", cancelled("invalid flow-control credit"))
	})
	t.Run("oversized initial window", func(t *testing.T) {
		a, b := rawLogin(t, s, uniqueName("a")), rawLogin(t, s, uniqueName("b"))
		a.send(wire.Msg{T: wire.TFileOffer, Ref: "1", To: b.name, Name: "f.bin", Size: 100, SHA256: sha})
		offer := b.waitFor("offer", func(m wire.Msg) bool { return m.T == wire.TFileOffer })
		b.send(wire.Msg{T: wire.TFileAccept, ID: offer.ID, Bytes: 1 << 40})
		a.waitFor("cancel", cancelled("invalid flow-control window"))
	})
	t.Run("third party injects data", func(t *testing.T) {
		a, b, e := rawLogin(t, s, uniqueName("a")), rawLogin(t, s, uniqueName("b")), rawLogin(t, s, uniqueName("e"))
		id := offerRaw(t, a, b, 100, wire.InitialWindow)
		e.write(dataFrame(id, 50)) // eve knows the ID: dropped, not relayed
		a.write(dataFrame(id, 100))
		a.send(wire.Msg{T: wire.TFileEnd, ID: wire.IDString(id)})
		a.waitFor("done", func(m wire.Msg) bool { return m.T == wire.TFileDone })
		// Bob received exactly the sender's 100 bytes, then file_end.
		got := 0
		b.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		for {
			f, err := wire.Read(b.conn)
			if err != nil {
				t.Fatal(err)
			}
			if f.Type == wire.FrameData {
				_, d, _ := wire.SplitData(f.Payload)
				got += len(d)
				continue
			}
			if f.Type == wire.FrameControl {
				if m, _ := wire.DecodeMsg(f.Payload); m.T == wire.TFileEnd {
					break
				}
			}
		}
		if got != 100 {
			t.Fatalf("recipient got %d bytes, want 100", got)
		}
	})
	t.Run("hostile offers", func(t *testing.T) {
		a, b := rawLogin(t, s, uniqueName("a")), rawLogin(t, s, uniqueName("b"))
		for _, m := range []wire.Msg{
			{Name: "..", Size: 1, SHA256: sha},
			{Name: "f", Size: 0, SHA256: sha},
			{Name: "f", Size: -5, SHA256: sha},
			{Name: "f", Size: 1, SHA256: "nothex"},
		} {
			m.T, m.Ref, m.To = wire.TFileOffer, "r", b.name
			a.send(m)
			a.waitFor("refusal", func(r wire.Msg) bool { return r.T == wire.TError && r.Ref == "r" })
		}
		a.send(wire.Msg{T: wire.TFileOffer, Ref: "p", To: b.name, Name: "../../etc/passwd", Size: 1, SHA256: sha})
		offer := b.waitFor("offer", func(m wire.Msg) bool { return m.T == wire.TFileOffer })
		if offer.Name != "passwd" {
			t.Fatalf("path not stripped: %q", offer.Name)
		}
	})
	t.Run("offer flood", func(t *testing.T) {
		a, b := rawLogin(t, s, uniqueName("a")), rawLogin(t, s, uniqueName("b"))
		for i := 0; i < 10; i++ {
			a.send(wire.Msg{T: wire.TFileOffer, Ref: "f", To: b.name, Name: "f", Size: 1, SHA256: sha})
		}
		a.waitFor("limit", func(m wire.Msg) bool {
			return m.T == wire.TError && strings.Contains(m.Text, "Too many file transfers")
		})
	})
	healthy(t, s)
}

// TestReconnectRace: members connecting, chatting and dropping while
// broadcasts go out (the crash fixed in 2.0.0, H-1).
func TestReconnectRace(t *testing.T) {
	s := start(t, testserver.Config{})
	chatter := rawLogin(t, s, "chatter")
	stop := make(chan struct{})
	var bg sync.WaitGroup
	bg.Add(2)
	go func() {
		defer bg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(60 * time.Millisecond): // within the rate limit
			}
			if chatter.write(mustMsg(wire.Msg{T: wire.TChat, Text: "noise"})) != nil {
				return
			}
		}
	}()
	go func() { // drain the chatter's copies
		defer bg.Done()
		for {
			if _, err := chatter.tryNext(time.Minute); err != nil {
				return
			}
		}
	}()

	const workers, rounds = 20, 5
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				conn, err := dialTLS(s, s.ServerCert, []tls.Certificate{s.Access})
				if err != nil {
					t.Error(err)
					return
				}
				name := uniqueName("flap")
				conn.Write(mustMsg(wire.Msg{T: wire.THello, V: wire.Version, User: name}))
				conn.Write(mustMsg(wire.Msg{T: wire.TJoin, Room: "#race"}))
				conn.Write(mustMsg(wire.Msg{T: wire.TChat, Room: "#race", Text: "hello"}))
				conn.Write(mustMsg(wire.Msg{T: wire.TChat, Text: "hello lobby"}))
				conn.Close() // abrupt, no quit
			}
		}()
	}
	wg.Wait()
	close(stop)
	chatter.conn.Close()
	bg.Wait()
	healthy(t, s)
}

// TestSlowReader: a member that never reads cannot stall the others, and
// is eventually disconnected instead of silently losing messages.
func TestSlowReader(t *testing.T) {
	s := start(t, testserver.Config{})
	sloth := rawLogin(t, s, "sloth") // never reads again
	talkers := make([]*raw, 3)
	for i := range talkers {
		talkers[i] = rawLogin(t, s, uniqueName("talker"))
		go func(r *raw) {
			for {
				if _, err := r.tryNext(time.Minute); err != nil {
					return
				}
			}
		}(talkers[i])
	}
	listener := s.Join(t, "listener")
	payload := strings.Repeat("x", wire.MaxTextBytes)
	// The sloth is dropped once its queue overflows or a write to it times
	// out (30 s), whichever comes first.
	dropped := false
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) && !dropped {
		for _, r := range talkers {
			r.write(mustMsg(wire.Msg{T: wire.TChat, Text: payload}))
		}
		time.Sleep(50 * time.Millisecond)
		_, dropped = listener.TryWait(time.Millisecond, func(e client.Event) bool { return e.Kind == client.EvLeft && e.User == "sloth" })
	}
	if !dropped {
		t.Fatal("a member that never reads was not disconnected")
	}
	listener.C.DM("listener", "still-alive")
	if _, ok := listener.TryWait(15*time.Second, testserver.Text(client.EvDM, "still-alive")); !ok {
		t.Fatal("other members stalled behind a slow reader")
	}
	_ = sloth
	healthy(t, s)
}

// TestFlood: a member flooding messages is rate limited; others see only a
// bounded share of the flood.
func TestFlood(t *testing.T) {
	s := start(t, testserver.Config{})
	flooder := rawLogin(t, s, "flooder")
	watcher := s.Join(t, "watcher")
	msg := mustMsg(wire.Msg{T: wire.TChat, Text: "spam"})
	start := time.Now()
	for i := 0; i < 5000; i++ {
		if flooder.write(msg) != nil {
			break
		}
	}
	elapsed := time.Since(start)
	flooder.waitFor("rate limit", func(m wire.Msg) bool { return m.T == wire.TError && m.Code == wire.CodeRateLimited })
	time.Sleep(time.Second)
	got := 0
	for {
		if _, ok := watcher.TryWait(200*time.Millisecond, testserver.Text(client.EvChat, "spam")); !ok {
			break
		}
		got++
	}
	max := 60 + int((elapsed+time.Second).Seconds()*20) + 5
	t.Logf("flood of 5000 in %s; watcher received %d (max %d)", elapsed.Round(time.Millisecond), got, max)
	if got > max {
		t.Fatalf("watcher received %d flood messages, limit is about %d", got, max)
	}
	healthy(t, s)
}

// TestConnectionLimits: per-IP concurrency and rate limits apply before TLS.
func TestConnectionLimits(t *testing.T) {
	s := start(t, testserver.Config{MaxConnectionsPerIP: 3, MaxNewConnPerIPPerMin: 6})
	refused := func(conn net.Conn) bool {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := conn.Read(make([]byte, 1))
		return err != nil && !isTimeout(err)
	}
	dial := func() net.Conn {
		t.Helper()
		conn, err := net.DialTimeout("tcp", s.Addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	var held []net.Conn
	for i := 0; i < 3; i++ {
		c := dial()
		if refused(c) {
			t.Fatalf("connection %d refused below the limit", i+1)
		}
		held = append(held, c)
	}
	if c := dial(); !refused(c) {
		t.Fatal("4th concurrent connection from one IP was not refused")
	} else {
		c.Close()
	}
	for _, c := range held {
		c.Close()
	}
	time.Sleep(500 * time.Millisecond)
	m := s.Join(t, uniqueName("ok")) // 4 of 6 per minute
	m.C.Close()
	time.Sleep(500 * time.Millisecond)
	for i := 0; i < 2; i++ { // 6 of 6
		c := dial()
		if refused(c) {
			t.Fatal("connection refused below the rate limit")
		}
		c.Close()
	}
	if c := dial(); !refused(c) {
		t.Fatal("connection over the per-minute rate limit was not refused")
	} else {
		c.Close()
	}
	if !s.Running() {
		t.Fatalf("server died:\n%s", s.Output())
	}
}

// TestLogsWithoutMetadata: with log_metadata off (the default), the logs
// record nothing about members: no names, rooms, DMs, files or addresses.
func TestLogsWithoutMetadata(t *testing.T) {
	s := start(t, testserver.Config{})
	a := s.Join(t, "zorro_private")
	b := s.Join(t, "zelda_private")
	a.C.Join("#hideout", "")
	a.Wait("joined", 15*time.Second, func(e client.Event) bool { return e.Kind == client.EvJoined && e.Self && e.Room == "#hideout" })
	a.C.DM("zelda_private", "meet-at-noon")
	b.Wait("dm", 15*time.Second, testserver.Text(client.EvDM, "meet-at-noon"))
	p := a.Dir + "/plans.txt"
	os.WriteFile(p, []byte("x"), 0600)
	a.C.OfferFile("zelda_private", p)
	b.Wait("offer", 15*time.Second, testserver.Kind(client.EvFileOffer))
	r := rawLogin(t, s, "zack_private")
	r.write(frame(4, 0x7f, 0, 0, nil)) // malformed frame: logged as a security event
	expectClosed(t, r.conn, 10*time.Second)
	a.C.Close()
	b.C.Close()
	time.Sleep(300 * time.Millisecond)
	s.Stop()

	logs := s.ReadLog("chat_server.log") + s.ReadLog("security.log")
	if !strings.Contains(logs, "Malformed frame from [member]") {
		t.Errorf("security event not logged:\n%s", logs)
	}
	for _, secret := range []string{"zorro", "zelda", "zack", "hideout", "meet-at-noon", "plans.txt", "127.0.0.1"} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs contain %q with log_metadata off:\n%s", secret, logs)
		}
	}
}
