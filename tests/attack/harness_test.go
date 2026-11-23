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
// process: missing or forged access keys, protocol abuse, malformed input,
// connection floods and reconnect races. Every test ends by checking that the
// server is still alive and still serves legitimate members.
//
// Run: go test -count=1 ./tests/attack/
// Set QUIETROOM_RACE=1 to build the server with the race detector; any
// reported data race fails the run.
package attack

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const accessFileName = "quietroom_access.pem"

// serverBinary is built once by TestMain.
var serverBinary string

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	dir, err := os.MkdirTemp("", "quietroom-attack-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "temp dir:", err)
		return 1
	}
	defer os.RemoveAll(dir)

	serverBinary = filepath.Join(dir, "quietroom_server")
	args := []string{"build"}
	if os.Getenv("QUIETROOM_RACE") == "1" {
		args = append(args, "-race")
	}
	args = append(args, "-o", serverBinary, "quietroom_server.go")
	cmd := exec.Command("go", args...)
	cmd.Dir = filepath.Join("..", "..")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "building server:", err)
		return 1
	}
	return m.Run()
}

// ── Server process ──────────────────────────────────────────────────────

type serverConfig struct {
	Port                  int  `json:"port"`
	DecoyTraffic          bool `json:"decoy_traffic"`
	DecoyInterval         int  `json:"decoy_interval_seconds"`
	MaxConnections        int  `json:"max_connections,omitempty"`
	MaxConnectionsPerIP   int  `json:"max_connections_per_ip,omitempty"`
	MaxNewConnPerIPPerMin int  `json:"max_new_connections_per_ip_per_minute,omitempty"`
	LogMetadata           bool `json:"log_metadata"`
}

type server struct {
	t      *testing.T
	dir    string
	addr   string
	cmd    *exec.Cmd
	output *syncBuffer
	exited chan struct{}

	serverCert *x509.Certificate
	access     tls.Certificate
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startServer runs a fresh server process in its own directory. High
// connection limits are used unless the config says otherwise, because all
// test connections come from 127.0.0.1.
func startServer(t *testing.T, cfg serverConfig) *server {
	t.Helper()
	dir := t.TempDir()
	cfg.Port = freePort(t)
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 1000
	}
	if cfg.MaxConnectionsPerIP == 0 {
		cfg.MaxConnectionsPerIP = 1000
	}
	if cfg.MaxNewConnPerIPPerMin == 0 {
		cfg.MaxNewConnPerIPPerMin = 100000
	}
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(dir, "server_config.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	s := &server{
		t:      t,
		dir:    dir,
		addr:   fmt.Sprintf("127.0.0.1:%d", cfg.Port),
		output: &syncBuffer{},
		exited: make(chan struct{}),
	}
	s.cmd = exec.Command(serverBinary)
	s.cmd.Dir = dir
	s.cmd.Stdout = s.output
	s.cmd.Stderr = s.output
	if err := s.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		s.cmd.Wait()
		close(s.exited)
	}()
	t.Cleanup(s.stop)

	// The access file is written once the listener is bound.
	deadline := time.Now().Add(60 * time.Second)
	for {
		if bundle, err := os.ReadFile(filepath.Join(dir, accessFileName)); err == nil {
			s.serverCert, s.access, err = parseAccessBundle(bundle)
			if err != nil {
				t.Fatalf("access file: %v", err)
			}
			break
		}
		select {
		case <-s.exited:
			t.Fatalf("server exited during startup:\n%s", s.output.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start:\n%s", s.output.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return s
}

func (s *server) stop() {
	select {
	case <-s.exited:
	default:
		s.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-s.exited:
		case <-time.After(10 * time.Second):
			s.cmd.Process.Kill()
			<-s.exited
		}
	}
	if out := s.output.String(); strings.Contains(out, "DATA RACE") {
		s.t.Errorf("server reported a data race:\n%s", out)
	}
}

// assertHealthy checks that the server process is running, logged no panic
// or data race, and still admits a legitimate member.
func (s *server) assertHealthy() {
	s.t.Helper()
	select {
	case <-s.exited:
		s.t.Fatalf("server process died:\n%s", s.output.String())
	default:
	}
	out := s.output.String()
	for _, bad := range []string{"panic:", "DATA RACE", "fatal error:"} {
		if strings.Contains(out, bad) {
			s.t.Fatalf("server output contains %q:\n%s", bad, out)
		}
	}
	c := s.login(s.t, uniqueName("probe"))
	c.close()
}

func (s *server) readLog(name string) string {
	data, _ := os.ReadFile(filepath.Join(s.dir, name))
	return string(data)
}

func parseAccessBundle(data []byte) (*x509.Certificate, tls.Certificate, error) {
	var certs []*pem.Block
	var key *pem.Block
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		switch b.Type {
		case "CERTIFICATE":
			certs = append(certs, b)
		case "PRIVATE KEY":
			key = b
		}
	}
	if len(certs) != 2 || key == nil {
		return nil, tls.Certificate{}, errors.New("expected 2 certificates and 1 private key")
	}
	serverCert, err := x509.ParseCertificate(certs[0].Bytes)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	access, err := tls.X509KeyPair(pem.EncodeToMemory(certs[1]), pem.EncodeToMemory(key))
	return serverCert, access, err
}

// ── Client side ─────────────────────────────────────────────────────────

// dialTLS connects with the given client certificates (none, forged, valid)
// and pins the server certificate like the real clients do.
func (s *server) dialTLS(certs []tls.Certificate) (*tls.Conn, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // replaced by the exact pin below
		Certificates:       certs,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 || !bytes.Equal(raw[0], s.serverCert.Raw) {
				return errors.New("server certificate does not match pin")
			}
			return nil
		},
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", s.addr, cfg)
	if err != nil {
		return nil, err
	}
	// In TLS 1.3 the server verifies the client certificate after the
	// client's handshake completes; a rejection arrives on the first read.
	return conn, nil
}

// handshakeRejected reports whether the server refuses the TLS session:
// either the handshake fails or the first read returns an error/EOF.
func handshakeRejected(conn *tls.Conn, err error) bool {
	if err != nil {
		return true
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, rerr := conn.Read(make([]byte, 1))
	return rerr != nil && !isTimeout(rerr)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

var dhPrime = func() *big.Int {
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
	return p
}()

// readServerDH reads the server's DH public key and verifies its signature
// against the pinned server certificate.
func (s *server) readServerDH(conn net.Conn) (*big.Int, error) {
	readBlock := func() ([]byte, error) {
		var n uint32
		if err := binary.Read(conn, binary.BigEndian, &n); err != nil {
			return nil, err
		}
		if n > 4096 {
			return nil, fmt.Errorf("block too large: %d", n)
		}
		b := make([]byte, n)
		_, err := io.ReadFull(conn, b)
		return b, err
	}
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	pub, err := readBlock()
	if err != nil {
		return nil, fmt.Errorf("server DH key: %w", err)
	}
	sig, err := readBlock()
	if err != nil {
		return nil, fmt.Errorf("server DH signature: %w", err)
	}
	rsaKey, ok := s.serverCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("server key is not RSA")
	}
	h := sha256.Sum256(pub)
	if err := rsa.VerifyPSS(rsaKey, crypto.SHA256, h[:], sig, nil); err != nil {
		return nil, fmt.Errorf("server DH signature invalid: %w", err)
	}
	return new(big.Int).SetBytes(pub), nil
}

func sendDHPublic(conn net.Conn, pub []byte) error {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(pub)))
	if _, err := conn.Write(n[:]); err != nil {
		return err
	}
	_, err := conn.Write(pub)
	return err
}

// member is an authenticated, logged-in test client.
type member struct {
	t    *testing.T
	name string
	conn *tls.Conn
	gcm  cipher.AEAD
	buf  []byte
}

// session performs TLS with the valid access key and the DH exchange.
func (s *server) session(t *testing.T) *member {
	t.Helper()
	conn, err := s.dialTLS([]tls.Certificate{s.access})
	if err != nil {
		t.Fatalf("dial with valid access key: %v", err)
	}
	serverPub, err := s.readServerDH(conn)
	if err != nil {
		conn.Close()
		t.Fatalf("DH exchange: %v", err)
	}
	priv, err := rand.Int(rand.Reader, new(big.Int).Sub(dhPrime, big.NewInt(1)))
	if err != nil {
		t.Fatal(err)
	}
	pub := new(big.Int).Exp(big.NewInt(2), priv, dhPrime)
	if err := sendDHPublic(conn, pub.Bytes()); err != nil {
		t.Fatal(err)
	}
	secret := sha256.Sum256(new(big.Int).Exp(serverPub, priv, dhPrime).Bytes())
	block, _ := aes.NewCipher(secret[:])
	gcm, _ := cipher.NewGCM(block)
	m := &member{t: t, conn: conn, gcm: gcm, buf: make([]byte, 70000)}
	t.Cleanup(m.close)
	return m
}

// login completes the username step and waits for the welcome message.
func (s *server) login(t *testing.T, name string) *member {
	t.Helper()
	m := s.session(t)
	m.expect("Enter your username")
	m.sendText(name)
	m.expect("Welcome to the chat, " + name)
	m.name = name
	return m
}

func (m *member) close() { m.conn.Close() }

// writePacket sends one obfuscated packet: type, length, data, padding.
// Padding is never empty, so the server's padding drain cannot swallow the
// start of the next packet.
func (m *member) writePacket(typ byte, data []byte) error {
	pad := make([]byte, 1+int(randByte())%64)
	pkt := make([]byte, 3, 3+len(data)+len(pad))
	pkt[0] = typ
	binary.BigEndian.PutUint16(pkt[1:3], uint16(len(data)))
	pkt = append(pkt, data...)
	pkt = append(pkt, pad...)
	_, err := m.conn.Write(pkt)
	return err
}

func randByte() byte {
	var b [1]byte
	rand.Read(b[:])
	return b[0]
}

func (m *member) seal(plain []byte) []byte {
	nonce := make([]byte, m.gcm.NonceSize())
	rand.Read(nonce)
	return m.gcm.Seal(nonce, nonce, plain, nil)
}

func (m *member) sendText(text string) {
	m.t.Helper()
	if err := m.writePacket(0x01, m.seal([]byte(text))); err != nil {
		m.t.Fatalf("send %q: %v", text, err)
	}
}

// next returns the next decrypted message (type 0x01 or 0x03). The server
// writes each packet in a single TLS record, and a tls.Conn read never
// crosses a record boundary, so one read is one packet.
func (m *member) next(timeout time.Duration) (byte, string, error) {
	deadline := time.Now().Add(timeout)
	for {
		m.conn.SetReadDeadline(deadline)
		n, err := m.conn.Read(m.buf)
		if err != nil {
			return 0, "", err
		}
		if n < 3 {
			return 0, "", fmt.Errorf("short packet (%d bytes)", n)
		}
		typ := m.buf[0]
		l := int(binary.BigEndian.Uint16(m.buf[1:3]))
		if 3+l > n {
			return 0, "", fmt.Errorf("packet spans records (%d > %d)", 3+l, n)
		}
		if typ == 0x02 { // decoy
			continue
		}
		data := m.buf[3 : 3+l]
		ns := m.gcm.NonceSize()
		if len(data) < ns {
			return 0, "", errors.New("ciphertext too short")
		}
		plain, err := m.gcm.Open(nil, data[:ns], data[ns:], nil)
		if err != nil {
			return 0, "", fmt.Errorf("decrypt: %w", err)
		}
		return typ, string(plain), nil
	}
}

// expect reads messages until one contains want.
func (m *member) expect(want string) string {
	m.t.Helper()
	got, err := m.waitFor(want, 15*time.Second)
	if err != nil {
		m.t.Fatalf("%s: waiting for %q: %v (seen: %q)", m.name, want, err, got)
	}
	return got
}

func (m *member) waitFor(want string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	var seen []string
	for {
		_, msg, err := m.next(time.Until(deadline))
		if err != nil {
			return strings.Join(seen, " | "), err
		}
		if strings.Contains(msg, want) {
			return msg, nil
		}
		seen = append(seen, msg)
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
