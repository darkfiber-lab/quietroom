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

// Package attack runs hostile clients against a real QuietRoom server
// process: missing or forged access keys, malformed frames and messages,
// spoofed fields, flow-control abuse, connection floods and reconnect races.
// Every test ends by checking that the server is still alive and still
// serves legitimate members.
//
// Run: go test -count=1 ./tests/attack/
// Set QUIETROOM_RACE=1 to build the server with the race detector; any
// reported data race fails the run.
package attack

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/darkfiber-lab/quietroom/tests/testserver"
	"github.com/darkfiber-lab/quietroom/wire"
)

var bin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "quietroom-attack-")
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

func start(t *testing.T, cfg testserver.Config) *testserver.Server {
	return testserver.Start(t, bin, cfg)
}

// healthy checks that the server survived and still admits a member.
func healthy(t *testing.T, s *testserver.Server) {
	t.Helper()
	s.CheckOutput(t)
	m := s.Join(t, uniqueName("probe"))
	m.C.Close()
}

// ── Raw connections ─────────────────────────────────────────────────

// dialTLS connects with the given client certificates and pins the server
// certificate like the real clients do.
func dialTLS(s *testserver.Server, pin *x509.Certificate, certs []tls.Certificate) (*tls.Conn, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // replaced by the exact pin below
		Certificates:       certs,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 || !bytes.Equal(raw[0], pin.Raw) {
				return errors.New("server certificate does not match pin")
			}
			return nil
		},
	}
	return tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", s.Addr, cfg)
}

// rejected reports whether the server refuses the TLS session: the
// handshake fails or the first read returns an error (TLS 1.3 reports a
// rejected client certificate after the client's handshake completes).
func rejected(conn *tls.Conn, err error) bool {
	if err != nil {
		return true
	}
	defer conn.Close()
	conn.Write(mustMsg(wire.Msg{T: wire.THello, V: wire.Version, User: uniqueName("x")}))
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, rerr := wire.Read(conn)
	return rerr != nil && !isTimeout(rerr)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// raw is a hand-driven protocol session for sending what real clients never would.
type raw struct {
	t    *testing.T
	name string
	conn *tls.Conn
}

// rawSession opens a TLS session with the valid access key, without login.
func rawSession(t *testing.T, s *testserver.Server) *raw {
	t.Helper()
	conn, err := dialTLS(s, s.ServerCert, []tls.Certificate{s.Access})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := &raw{t: t, conn: conn}
	t.Cleanup(func() { conn.Close() })
	return r
}

// rawLogin opens a session and logs in.
func rawLogin(t *testing.T, s *testserver.Server, name string) *raw {
	t.Helper()
	r := rawSession(t, s)
	r.name = name
	r.send(wire.Msg{T: wire.THello, V: wire.Version, User: name})
	m := r.next(15 * time.Second)
	if m.T != wire.TWelcome {
		t.Fatalf("login %s: got %+v", name, m)
	}
	return r
}

func mustMsg(m wire.Msg) []byte {
	f, err := wire.EncodeMsg(m)
	if err != nil {
		panic(err)
	}
	return f
}

func (r *raw) send(m wire.Msg) {
	r.t.Helper()
	if _, err := r.conn.Write(mustMsg(m)); err != nil {
		r.t.Fatalf("send %s: %v", m.T, err)
	}
}

func (r *raw) write(b []byte) error {
	_, err := r.conn.Write(b)
	return err
}

// frame builds a frame by hand: length, type, flags, padding length, body.
func frame(length uint32, typ, flags byte, pad uint16, body []byte) []byte {
	b := make([]byte, 8, 8+len(body))
	binary.BigEndian.PutUint32(b, length)
	b[4], b[5] = typ, flags
	binary.BigEndian.PutUint16(b[6:], pad)
	return append(b, body...)
}

// controlFrame wraps an arbitrary payload in a valid control frame.
func controlFrame(payload []byte) []byte {
	f, err := wire.Encode(wire.FrameControl, payload)
	if err != nil {
		panic(err)
	}
	return f
}

// next returns the next control message, skipping decoys and data.
func (r *raw) next(timeout time.Duration) wire.Msg {
	r.t.Helper()
	m, err := r.tryNext(timeout)
	if err != nil {
		r.t.Fatalf("%s: read: %v", r.name, err)
	}
	return m
}

func (r *raw) tryNext(timeout time.Duration) (wire.Msg, error) {
	r.conn.SetReadDeadline(time.Now().Add(timeout))
	for {
		f, err := wire.Read(r.conn)
		if err != nil {
			return wire.Msg{}, err
		}
		if f.Type != wire.FrameControl {
			continue
		}
		return wire.DecodeMsg(f.Payload)
	}
}

// waitFor reads until a message matches.
func (r *raw) waitFor(what string, pred func(wire.Msg) bool) wire.Msg {
	r.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		m, err := r.tryNext(time.Until(deadline))
		if err != nil {
			r.t.Fatalf("%s: waiting for %s: %v", r.name, what, err)
		}
		if pred(m) {
			return m
		}
	}
}

// expectClosed checks that the server closes the connection.
func expectClosed(t *testing.T, conn net.Conn, within time.Duration) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(within))
	buf := make([]byte, 4096)
	for {
		_, err := conn.Read(buf)
		if err == nil {
			continue
		}
		if isTimeout(err) {
			t.Fatalf("server kept the connection open for more than %s", within)
		}
		return
	}
}

var nameSeq struct {
	sync.Mutex
	n int
}

func uniqueName(prefix string) string {
	nameSeq.Lock()
	defer nameSeq.Unlock()
	nameSeq.n++
	return fmt.Sprintf("%s%d", prefix, nameSeq.n)
}
