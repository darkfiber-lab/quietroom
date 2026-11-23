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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// forgeAccessCert creates a self-signed certificate that copies the subject
// and validity of the real access certificate, with an attacker-owned key.
func forgeAccessCert(t *testing.T, real tls.Certificate) tls.Certificate {
	t.Helper()
	orig, err := x509.ParseCertificate(real.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: orig.SerialNumber,
		Subject:      orig.Subject,
		NotBefore:    orig.NotBefore,
		NotAfter:     orig.NotAfter,
		KeyUsage:     orig.KeyUsage,
		ExtKeyUsage:  orig.ExtKeyUsage,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestAccessKeyRequired: only holders of the current access file get in.
func TestAccessKeyRequired(t *testing.T) {
	s := startServer(t, serverConfig{})

	if info, err := os.Stat(filepath.Join(s.dir, accessFileName)); err != nil {
		t.Fatal(err)
	} else if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("access file mode = %o, want 600", mode)
	}

	t.Run("no client certificate", func(t *testing.T) {
		if !handshakeRejected(s.dialTLS(nil)) {
			t.Fatal("server accepted a TLS session without an access key")
		}
	})

	t.Run("forged access certificate", func(t *testing.T) {
		forged := forgeAccessCert(t, s.access)
		if !handshakeRejected(s.dialTLS([]tls.Certificate{forged})) {
			t.Fatal("server accepted a forged access certificate")
		}
	})

	t.Run("access file from another server run", func(t *testing.T) {
		other := startServer(t, serverConfig{})
		if !handshakeRejected(s.dialTLS([]tls.Certificate{other.access})) {
			t.Fatal("server accepted the access key of a different run")
		}
		// The client side notices too: the pinned server certificate of
		// the stale file does not match.
		stale := *other
		stale.addr = s.addr
		if conn, err := stale.dialTLS([]tls.Certificate{other.access}); err == nil {
			conn.Close()
			t.Fatal("client accepted a server certificate that does not match its access file")
		}
	})

	t.Run("plain TCP garbage", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", s.addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		expectClosed(t, conn, 10*time.Second)
	})

	t.Run("valid access key", func(t *testing.T) {
		m := s.login(t, uniqueName("member"))
		m.sendText("/help")
		m.expect("Available Commands")
	})

	s.assertHealthy()
}

// TestHandshakeTimeout: a peer that connects and stays silent is dropped.
func TestHandshakeTimeout(t *testing.T) {
	t.Parallel()
	s := startServer(t, serverConfig{})
	conn, err := net.DialTimeout("tcp", s.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	expectClosed(t, conn, 30*time.Second)
	t.Logf("silent connection closed after %s", time.Since(start).Round(time.Second))
	s.assertHealthy()
}

// TestDHKeyValidation: invalid or oversized DH public keys end the session.
func TestDHKeyValidation(t *testing.T) {
	s := startServer(t, serverConfig{})
	p := dhPrime
	cases := map[string][]byte{
		"zero":       {},
		"one":        big.NewInt(1).Bytes(),
		"p-1":        new(big.Int).Sub(p, big.NewInt(1)).Bytes(),
		"p":          p.Bytes(),
		"p+1":        new(big.Int).Add(p, big.NewInt(1)).Bytes(),
		"all ones":   bytesOf(0xff, 256),
		"4096 bytes": bytesOf(0x01, 4096),
	}
	for name, pub := range cases {
		t.Run(name, func(t *testing.T) {
			conn, err := s.dialTLS([]tls.Certificate{s.access})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := s.readServerDH(conn); err != nil {
				t.Fatal(err)
			}
			sendDHPublic(conn, pub)
			expectClosed(t, conn, 10*time.Second)
		})
	}

	t.Run("oversized length", func(t *testing.T) {
		conn, err := s.dialTLS([]tls.Certificate{s.access})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := s.readServerDH(conn); err != nil {
			t.Fatal(err)
		}
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], 0xFFFFFFF0) // would be a 4 GB allocation
		conn.Write(n[:])
		expectClosed(t, conn, 10*time.Second)
	})

	s.assertHealthy()
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// TestUsernameValidation: hostile usernames are refused, names are unique.
func TestUsernameValidation(t *testing.T) {
	s := startServer(t, serverConfig{})
	bad := map[string]string{
		"empty":            "   ",
		"control char":     "ab\x07cd",
		"newline":          "ab\ncd",
		"too long":         strings.Repeat("a", 33),
		"html":             "<b>x</b>",
		"non-ascii":        "ädmin",
		"ansi escape":      "\x1b[31mred",
		"zero-width space": "ad​min",
	}
	for name, username := range bad {
		t.Run(name, func(t *testing.T) {
			m := s.session(t)
			m.expect("Enter your username")
			m.sendText(username)
			expectClosed(t, m.conn, 10*time.Second)
		})
	}

	t.Run("duplicate", func(t *testing.T) {
		name := uniqueName("taken")
		s.login(t, name)
		m := s.session(t)
		m.expect("Enter your username")
		m.sendText(name)
		m.expect("Username already taken")
		expectClosed(t, m.conn, 10*time.Second)
	})

	s.assertHealthy()
}

// TestMalformedPackets: garbage from an authenticated member is survived,
// and the member's session keeps working afterwards.
func TestMalformedPackets(t *testing.T) {
	s := startServer(t, serverConfig{})
	m := s.login(t, uniqueName("fuzz"))
	stillWorks := func() {
		t.Helper()
		m.sendText("/help")
		m.expect("Available Commands")
	}

	m.writePacket(0x01, bytesOf(0x41, 200)) // undecryptable text
	m.writePacket(0x01, []byte{1, 2})       // shorter than a nonce
	m.writePacket(0x01, nil)                // empty
	m.writePacket(0x7f, bytesOf(0x00, 64))  // unknown packet type
	m.writePacket(0x03, bytesOf(0x42, 300)) // undecryptable file data
	stillWorks()

	// File stream messages without a transfer are ignored.
	m.writePacket(0x03, m.seal([]byte("FILE_START|evil.bin|1000")))
	m.writePacket(0x03, m.seal([]byte("FILE_START|../../etc/passwd|-5")))
	m.writePacket(0x03, m.seal(bytesOf(0x00, 4000)))
	m.writePacket(0x03, m.seal([]byte("FILE_END")))
	stillWorks()

	// Declared length above the server's packet limit: dropped, stream kept.
	big := make([]byte, 3+40000+1)
	big[0] = 0x01
	binary.BigEndian.PutUint16(big[1:3], 40000)
	m.conn.Write(big)
	stillWorks()

	// A truncated packet followed by a disconnect.
	t.Run("truncated", func(t *testing.T) {
		v := s.login(t, uniqueName("trunc"))
		hdr := []byte{0x01, 0x10, 0x00, 1, 2, 3}
		v.conn.Write(hdr)
		v.conn.Close()
	})

	s.assertHealthy()
}

// TestCommandAbuse: room, DM and file-transfer commands cannot be used to
// inject content, read other rooms or hijack other members' transfers.
func TestCommandAbuse(t *testing.T) {
	s := startServer(t, serverConfig{})
	alice := s.login(t, uniqueName("alice"))
	bob := s.login(t, uniqueName("bob"))
	eve := s.login(t, uniqueName("eve"))

	// ── invalid room names ──
	{
		for _, room := range []string{
			"#<script>alert(1)</script>",
			"#" + strings.Repeat("r", 33),
			"#ünïcode",
			"#a\x1b[2J",
			"#",
		} {
			eve.sendText("/join " + room)
			eve.expect("Invalid room name")
		}
		eve.sendText("/join noprefix")
		eve.expect("must start with #")
	}

	// ── password room ──
	{
		alice.sendText("/join #vault correct-horse")
		alice.expect("Created and joined room #vault")

		eve.sendText("/join #vault")
		eve.expect("password-protected")
		eve.sendText("/join #vault wrong")
		eve.expect("Incorrect password")
		eve.sendText("/members #vault")
		eve.expect("Room not found or access denied")

		eve.sendText("[#vault] let me in")
		eve.expect("You are not a member of #vault")

		alice.sendText("[#vault] the-secret-payload")
		alice.expect("the-secret-payload")
		// Eve must not see it; a sync message proves her queue is drained.
		eve.sendText("/help")
		if got, err := eve.waitFor("the-secret-payload", 3*time.Second); err == nil {
			t.Fatalf("non-member received a message from a password room: %q", got)
		}
	}

	// ── file transfer hijack ──
	{
		hash := hex.EncodeToString(sha256Sum([]byte("data")))
		alice.sendText("/file " + bob.name + " report.pdf " + hash)
		req := bob.expect("FILE TRANSFER REQUEST")
		id := regexp.MustCompile(`Transfer ID: (\S+)`).FindStringSubmatch(req)
		if id == nil {
			t.Fatalf("no transfer ID in %q", req)
		}
		alice.expect("File transfer request sent")

		eve.sendText("/accept " + id[1])
		eve.expect("This transfer is not for you")
		eve.sendText("/decline " + id[1])
		eve.expect("This transfer is not for you")

		// The intended recipient can still accept.
		bob.sendText("/accept " + id[1])
		bob.expect("File transfer accepted")
		alice.expect("BEGIN_SEND|report.pdf|" + hash)

		// A third party's stream messages do not reach Bob.
		eve.writePacket(0x03, eve.seal([]byte("FILE_START|malware.exe|4")))
		eve.writePacket(0x03, eve.seal([]byte("EVIL")))

		alice.writePacket(0x03, alice.seal([]byte("FILE_START|report.pdf|4")))
		alice.writePacket(0x03, alice.seal([]byte("data")))
		alice.writePacket(0x03, alice.seal([]byte("FILE_END")))

		var stream []string
		for len(stream) < 3 {
			typ, msg, err := bob.next(15 * time.Second)
			if err != nil {
				t.Fatalf("file stream: %v (got %q)", err, stream)
			}
			if typ == 0x03 {
				stream = append(stream, msg)
			}
		}
		want := []string{"FILE_START|report.pdf|4|" + hash, "data", "FILE_END"}
		for i := range want {
			if stream[i] != want[i] {
				t.Fatalf("file stream = %q, want %q", stream, want)
			}
		}
	}

	// ── bad file requests ──
	{
		eve.sendText("/file nobody x.txt " + strings.Repeat("a", 64))
		eve.expect("is not online")
		eve.sendText("/file " + eve.name + " x.txt " + strings.Repeat("a", 64))
		eve.expect("cannot send files to yourself")
		eve.sendText("/file " + bob.name + " x.txt nothex")
		eve.expect("Invalid hash format")
		eve.sendText("/accept no_such_id")
		eve.expect("not found")
	}

	s.assertHealthy()
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// TestReconnectRace: members connecting, chatting and dropping at the same
// time as broadcasts go out (the crash fixed in 2.0.0, H-1).
func TestReconnectRace(t *testing.T) {
	s := startServer(t, serverConfig{})
	chatter := s.login(t, uniqueName("chatter"))
	stop := make(chan struct{})
	var bg sync.WaitGroup
	bg.Add(2)
	go func() { // keep broadcasting
		defer bg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if chatter.writePacket(0x01, chatter.seal([]byte("noise"))) != nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	go func() { // drain the chatter's own copies
		defer bg.Done()
		for {
			if _, _, err := chatter.next(time.Minute); err != nil {
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
				m := s.login(t, uniqueName("flap"))
				m.sendText("/join #race")
				m.sendText("[#race] hello")
				m.sendText("hello lobby")
				m.conn.Close() // abrupt disconnect, no /quit
			}
		}()
	}
	wg.Wait()
	close(stop)
	chatter.close()
	bg.Wait()
	s.assertHealthy()
}

// TestSlowReader: a member that never reads cannot stall the others.
func TestSlowReader(t *testing.T) {
	s := startServer(t, serverConfig{})
	sloth := s.login(t, uniqueName("sloth"))
	_ = sloth // logged in, never reads again

	talker := s.login(t, uniqueName("talker"))
	listener := s.login(t, uniqueName("listener"))
	go func() {
		for {
			if _, _, err := talker.next(time.Minute); err != nil {
				return
			}
		}
	}()
	payload := strings.Repeat("x", 1000)
	for i := 0; i < 6000; i++ {
		if err := talker.writePacket(0x01, talker.seal([]byte(payload))); err != nil {
			t.Fatal(err)
		}
	}
	talker.sendText("/msg " + listener.name + " still-alive")
	if _, err := listener.waitFor("still-alive", 30*time.Second); err != nil {
		t.Fatalf("other members stalled behind a slow reader: %v", err)
	}
	s.assertHealthy()
}

// TestConnectionLimits: per-IP concurrency and rate limits apply before TLS.
func TestConnectionLimits(t *testing.T) {
	s := startServer(t, serverConfig{MaxConnectionsPerIP: 3, MaxNewConnPerIPPerMin: 6})

	refused := func(conn net.Conn) bool {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := conn.Read(make([]byte, 1))
		return err != nil && !isTimeout(err)
	}
	dial := func() net.Conn {
		t.Helper()
		conn, err := net.DialTimeout("tcp", s.addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}

	// Three silent connections hold every per-IP slot (new: 3/6).
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

	// Free the slots; a member can log in again (new: 4/6).
	for _, c := range held {
		c.Close()
	}
	time.Sleep(500 * time.Millisecond)
	m := s.login(t, uniqueName("ok"))
	m.close()
	time.Sleep(500 * time.Millisecond)

	// Rate limit: two more are admitted (6/6), the next is refused.
	for i := 0; i < 2; i++ {
		c := dial()
		if refused(c) {
			t.Fatalf("connection refused below the rate limit")
		}
		c.Close()
	}
	if c := dial(); !refused(c) {
		t.Fatal("connection over the per-minute rate limit was not refused")
	} else {
		c.Close()
	}

	select {
	case <-s.exited:
		t.Fatalf("server died:\n%s", s.output.String())
	default:
	}
}

// TestLogsWithoutMetadata: with log_metadata off (the default), the logs
// record nothing about members: no names, rooms, DMs or addresses.
func TestLogsWithoutMetadata(t *testing.T) {
	s := startServer(t, serverConfig{})
	a := s.login(t, "zorro_private")
	b := s.login(t, "zelda_private")
	a.sendText("/join #hideout")
	a.expect("Created and joined room #hideout")
	a.sendText("/msg zelda_private meet-at-noon")
	b.expect("meet-at-noon")
	hash := hex.EncodeToString(sha256Sum([]byte("x")))
	a.sendText("/file zelda_private plans.txt " + hash)
	b.expect("FILE TRANSFER REQUEST")
	a.writePacket(0x01, bytesOf(0x41, 100)) // decryption error is logged
	a.sendText("/help")
	a.expect("Available Commands")
	a.close()
	b.close()
	time.Sleep(500 * time.Millisecond)
	s.stop()

	logs := s.readLog("chat_server.log") + s.readLog("security.log")
	for _, secret := range []string{"zorro", "zelda", "hideout", "meet-at-noon", "plans.txt", "127.0.0.1"} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs contain %q with log_metadata off:\n%s", secret, logs)
		}
	}
}
