/*
Copyright (C) 2026 darkfiber-lab

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, version 3.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

*/

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/darkfiber-lab/quietroom/e2e"
	"github.com/darkfiber-lab/quietroom/wire"
)

type ServerConfig struct {
	Port            int    `json:"port"`
	LogFile         string `json:"log_file"`
	SecurityLogFile string `json:"security_log_file"`
	DecoyTraffic    bool   `json:"decoy_traffic"`
	DecoyInterval   int    `json:"decoy_interval_seconds"`
	DecoyMinBytes   int    `json:"decoy_min_bytes"`
	DecoyMaxBytes   int    `json:"decoy_max_bytes"`

	// Connection limits, enforced before the TLS handshake. 0 = default.
	MaxConnections        int `json:"max_connections"`
	MaxConnectionsPerIP   int `json:"max_connections_per_ip"`
	MaxNewConnPerIPPerMin int `json:"max_new_connections_per_ip_per_minute"`

	// Room limits. 0 = default.
	MaxRooms          int `json:"max_rooms"`
	MaxRoomsPerMember int `json:"max_rooms_per_member"`

	// LogMetadata records who connected, joined, left, sent DMs or files, and
	// member IP addresses. Off by default: routine logs then contain no
	// information about participants. Enable only temporarily for debugging.
	LogMetadata bool `json:"log_metadata"`
}

const (
	defaultMaxConnections        = 100
	defaultMaxConnectionsPerIP   = 10
	defaultMaxNewConnPerIPPerMin = 30
	defaultMaxRooms              = 200
	defaultMaxRoomsPerMember     = 20
)

const accessFile = "quietroom_access.pem"

const (
	// handshakeTimeout bounds the unauthenticated phase of a connection
	// (TLS handshake and hello).
	handshakeTimeout = 15 * time.Second
	// idleTimeout drops members that send nothing (clients send keepalives).
	idleTimeout = 3 * time.Minute
	// writeTimeout drops members that stop reading.
	writeTimeout = 30 * time.Second

	ctrlQueueLen = 1024 // control frames per member; overflow disconnects
	bulkQueueLen = 512  // file data frames per member (bounded by flow control)

	maxTransfersPerMember = 4 // in each direction
	offerTTL              = 5 * time.Minute
	stallTimeout          = 2 * time.Minute

	// Message rate per member: a token bucket.
	rateBurst  = 60.0
	ratePerSec = 20.0
)

// ── Connection limiter ─────────────────────────────────────────────

// connLimiter caps concurrent connections (total and per IP) and the rate of
// new connections per IP, so unauthenticated peers cannot exhaust the server.
type connLimiter struct {
	mu           sync.Mutex
	total        int
	perIP        map[string]*ipUsage
	dropped      int
	maxTotal     int
	maxPerIP     int
	maxRatePerIP int
}

type ipUsage struct {
	active      int
	windowStart time.Time
	count       int
}

func pick(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func newConnLimiter(cfg ServerConfig) *connLimiter {
	return &connLimiter{
		perIP:        make(map[string]*ipUsage),
		maxTotal:     pick(cfg.MaxConnections, defaultMaxConnections),
		maxPerIP:     pick(cfg.MaxConnectionsPerIP, defaultMaxConnectionsPerIP),
		maxRatePerIP: pick(cfg.MaxNewConnPerIPPerMin, defaultMaxNewConnPerIPPerMin),
	}
}

func (l *connLimiter) admit(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	u := l.perIP[ip]
	if u == nil {
		u = &ipUsage{windowStart: now}
		l.perIP[ip] = u
	}
	if now.Sub(u.windowStart) >= time.Minute {
		u.windowStart = now
		u.count = 0
	}
	if l.total >= l.maxTotal || u.active >= l.maxPerIP || u.count >= l.maxRatePerIP {
		l.dropped++
		return false
	}
	u.count++
	u.active++
	l.total++
	return true
}

func (l *connLimiter) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if u := l.perIP[ip]; u != nil {
		u.active--
	}
}

// sweep forgets idle IPs and returns how many connections were refused since
// the last sweep.
func (l *connLimiter) sweep() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, u := range l.perIP {
		if u.active <= 0 && time.Since(u.windowStart) >= time.Minute {
			delete(l.perIP, ip)
		}
	}
	dropped := l.dropped
	l.dropped = 0
	return dropped
}

// ── Members, rooms, transfers ──────────────────────────────────────

type Client struct {
	conn     net.Conn
	username string
	ipAddr   string
	kx, sk   string // session public keys (base64), relayed to other members

	ctrl     chan []byte   // control frames, written first
	bulk     chan []byte   // file data and file_end frames
	done     chan struct{} // closed once when the member is gone
	doneOnce sync.Once

	rooms map[string]bool // guarded by Server.mu

	rateMu     sync.Mutex
	tokens     float64
	lastRefill time.Time
	lastNotice time.Time
}

// kill ends the member's connection. Safe to call more than once and from
// any goroutine; the reader loop then cleans up.
func (c *Client) kill() {
	c.doneOnce.Do(func() {
		close(c.done)
		c.conn.Close()
	})
}

// send queues a control frame without blocking. A member whose queue is full
// has stopped reading and is disconnected rather than silently losing
// messages.
func (c *Client) send(frame []byte) {
	select {
	case <-c.done:
		return
	default:
	}
	select {
	case c.ctrl <- frame:
	default:
		c.kill()
	}
}

// sendOptional queues a frame that may be dropped (decoys).
func (c *Client) sendOptional(frame []byte) {
	select {
	case c.ctrl <- frame:
	default:
	}
}

// sendBulk queues a file frame without blocking; false if the queue is full.
func (c *Client) sendBulk(frame []byte) bool {
	select {
	case <-c.done:
		return false
	default:
	}
	select {
	case c.bulk <- frame:
		return true
	default:
		return false
	}
}

func (c *Client) writer() {
	write := func(f []byte) bool {
		c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := c.conn.Write(f); err != nil {
			c.kill()
			return false
		}
		return true
	}
	for {
		select {
		case f := <-c.ctrl:
			if !write(f) {
				return
			}
			continue
		case <-c.done:
			return
		default:
		}
		select {
		case f := <-c.ctrl:
			if !write(f) {
				return
			}
		case f := <-c.bulk:
			if !write(f) {
				return
			}
		case <-c.done:
			return
		}
	}
}

// allow spends cost tokens from the member's message budget.
func (c *Client) allow(cost float64) bool {
	c.rateMu.Lock()
	defer c.rateMu.Unlock()
	now := time.Now()
	c.tokens += now.Sub(c.lastRefill).Seconds() * ratePerSec
	if c.tokens > rateBurst {
		c.tokens = rateBurst
	}
	c.lastRefill = now
	if c.tokens < cost {
		return false
	}
	c.tokens -= cost
	return true
}

type Room struct {
	name     string
	members  map[*Client]bool
	verifier []byte // SHA-256 of the room verifier; nil for an open room
}

// locked reports an end-to-end encrypted (password) room. The server never
// sees the password: clients derive a verifier from it (see e2e.DeriveRoom)
// and the server only compares verifiers, keeping a hash of the first.
func (r *Room) locked() bool { return r.verifier != nil }

func hashVerifier(vf []byte) []byte {
	h := sha256.Sum256(vf)
	return h[:]
}

type transfer struct {
	id        [wire.IDLen]byte
	idStr     string
	sender    *Client
	recipient *Client
	size      int64 // encrypted bytes to be sent
	accepted  bool
	credit    int64 // bytes the sender may still send
	sent      int64
	created   time.Time
	activity  time.Time
}

type Server struct {
	mu        sync.Mutex // members, usernames, rooms
	clients   map[*Client]bool
	usernames map[string]*Client // by wire.UsernameKey
	rooms     map[string]*Room

	tmu       sync.Mutex // transfers
	transfers map[string]*transfer

	tlsCert       tls.Certificate
	accessCertRaw []byte // DER of the access certificate clients must present
	accessBundle  []byte // contents of quietroom_access.pem for this run
	tlsConfig     *tls.Config
	gateKey       []byte // checks the gate token before TLS (see wire/gate.go)
	gateMu        sync.Mutex
	gateSeen      map[string]time.Time // nonce -> expiry, against replays
	limiter       *connLimiter
	config        ServerConfig

	logger         *log.Logger
	securityLogger *log.Logger

	listener net.Listener
	shutdown chan struct{}
	wg       sync.WaitGroup
}

// ── Keys and access file ───────────────────────────────────────────

type sessionKeys struct {
	tlsCert       tls.Certificate
	accessCertRaw []byte
	accessBundle  []byte // PEM contents of quietroom_access.pem
	gateKey       []byte
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// generateSessionKeys creates a fresh server identity and master access key
// for this server run, plus the access bundle contents. Nothing is reused
// across restarts by design: a restart invalidates every previously issued
// bundle. The server private key is kept in memory only; the bundle is written
// by main() once the listener is up, so a failed start never replaces the
// access file of a server that is already running.
func generateSessionKeys() (*sessionKeys, error) {
	now := time.Now()

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serverSerial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	// The certificate is visible to anyone who connects, so it carries a
	// random name per run instead of anything that identifies the service.
	nameBytes := make([]byte, 8)
	if _, err := rand.Read(nameBytes); err != nil {
		return nil, err
	}
	serverTmpl := &x509.Certificate{
		SerialNumber:          serverSerial,
		Subject:               pkix.Name{CommonName: hex.EncodeToString(nameBytes)},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, serverTmpl, &serverKey.PublicKey, serverKey)
	if err != nil {
		return nil, err
	}
	serverCert, err := x509.ParseCertificate(serverDER)
	if err != nil {
		return nil, err
	}

	accessKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	accessSerial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	accessTmpl := &x509.Certificate{
		SerialNumber:          accessSerial,
		Subject:               pkix.Name{CommonName: "QuietRoom Access"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	accessDER, err := x509.CreateCertificate(rand.Reader, accessTmpl, accessTmpl, &accessKey.PublicKey, accessKey)
	if err != nil {
		return nil, err
	}
	accessKeyDER, err := x509.MarshalPKCS8PrivateKey(accessKey)
	if err != nil {
		return nil, err
	}

	var bundle bytes.Buffer
	for _, b := range []*pem.Block{
		{Type: "CERTIFICATE", Bytes: serverDER},
		{Type: "CERTIFICATE", Bytes: accessDER},
		{Type: "PRIVATE KEY", Bytes: accessKeyDER},
	} {
		if err := pem.Encode(&bundle, b); err != nil {
			return nil, err
		}
	}
	return &sessionKeys{
		accessBundle: bundle.Bytes(),
		tlsCert: tls.Certificate{
			Certificate: [][]byte{serverDER},
			PrivateKey:  serverKey,
			Leaf:        serverCert,
		},
		accessCertRaw: accessDER,
		gateKey:       wire.GateKey(accessKeyDER),
	}, nil
}

// writeFileAtomic writes data to a temp file in the same directory and renames
// it into place, so a crash never leaves a truncated file behind.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// verifyAccessCert is the TLS VerifyPeerCertificate hook: the client must
// present exactly the master access certificate generated for this run.
func (s *Server) verifyAccessCert(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 || subtle.ConstantTimeCompare(rawCerts[0], s.accessCertRaw) != 1 {
		return errors.New("access key not recognised")
	}
	return nil
}

// ── Setup and logging ──────────────────────────────────────────────

func loadConfig() ServerConfig {
	config := ServerConfig{
		Port:            37842,
		LogFile:         "chat_server.log",
		SecurityLogFile: "security.log",
		DecoyTraffic:    true,
		DecoyInterval:   30,
		DecoyMinBytes:   100,
		DecoyMaxBytes:   500,

		MaxConnections:        defaultMaxConnections,
		MaxConnectionsPerIP:   defaultMaxConnectionsPerIP,
		MaxNewConnPerIPPerMin: defaultMaxNewConnPerIPPerMin,
		MaxRooms:              defaultMaxRooms,
		MaxRoomsPerMember:     defaultMaxRoomsPerMember,

		LogMetadata: false,
	}
	data, err := os.ReadFile("server_config.json")
	if err != nil {
		configData, _ := json.MarshalIndent(config, "", "  ")
		os.WriteFile("server_config.json", configData, 0644)
		fmt.Println("✓ Created default server_config.json")
		return config
	}
	if err := json.Unmarshal(data, &config); err != nil {
		fmt.Println("⚠ Error parsing config, using defaults:", err)
		return config
	}
	fmt.Println("✓ Loaded server configuration")
	return config
}

func NewServer() (*Server, error) {
	config := loadConfig()
	config.MaxRooms = pick(config.MaxRooms, defaultMaxRooms)
	config.MaxRoomsPerMember = pick(config.MaxRoomsPerMember, defaultMaxRoomsPerMember)
	if config.DecoyInterval <= 0 {
		config.DecoyInterval = 30
	}

	// Repair log files created with a broken mode by earlier versions.
	os.Chmod(config.LogFile, 0600)
	os.Chmod(config.SecurityLogFile, 0600)
	logFile, err := os.OpenFile(config.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	secLogFile, err := os.OpenFile(config.SecurityLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}

	keys, err := generateSessionKeys()
	if err != nil {
		return nil, err
	}
	fmt.Println("✓ Generated new server key and master access key (valid until server restart)")

	s := &Server{
		clients:        make(map[*Client]bool),
		usernames:      make(map[string]*Client),
		rooms:          make(map[string]*Room),
		transfers:      make(map[string]*transfer),
		tlsCert:        keys.tlsCert,
		accessCertRaw:  keys.accessCertRaw,
		accessBundle:   keys.accessBundle,
		gateKey:        keys.gateKey,
		gateSeen:       make(map[string]time.Time),
		limiter:        newConnLimiter(config),
		config:         config,
		logger:         log.New(logFile, "", log.LstdFlags),
		securityLogger: log.New(secLogFile, "[SECURITY] ", log.LstdFlags),
		shutdown:       make(chan struct{}),
	}
	s.tlsConfig = &tls.Config{
		Certificates:          []tls.Certificate{s.tlsCert},
		MinVersion:            tls.VersionTLS13,
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: s.verifyAccessCert,
	}
	s.logSecurity("Server started (protocol %d)", wire.Version)
	return s, nil
}

// maxGateNonces bounds the replay cache. Only valid tokens are stored, so
// only access-file holders can fill it.
const maxGateNonces = 100000

// gate reads the ClientHello and checks its gate token before anything is
// sent. On failure the caller closes the connection without a reply, so
// the server never shows its certificate (or anything else) to strangers.
func (s *Server) gate(conn net.Conn) (net.Conn, error) {
	record, name, err := wire.ReadClientHello(conn)
	if err != nil {
		return nil, fmt.Errorf("no TLS ClientHello: %v", err)
	}
	if name == "" {
		return nil, errors.New("no gate token")
	}
	now := time.Now()
	nonce, ok := wire.CheckGate(s.gateKey, name, now)
	if !ok {
		return nil, errors.New("invalid or expired gate token")
	}
	s.gateMu.Lock()
	defer s.gateMu.Unlock()
	if exp, seen := s.gateSeen[nonce]; seen && now.Before(exp) {
		return nil, errors.New("replayed gate token")
	}
	if len(s.gateSeen) >= maxGateNonces/2 {
		for n, exp := range s.gateSeen {
			if now.After(exp) {
				delete(s.gateSeen, n)
			}
		}
	}
	if len(s.gateSeen) >= maxGateNonces {
		return nil, errors.New("gate replay cache full")
	}
	s.gateSeen[nonce] = now.Add(wire.GateLifetime)
	return &prefixConn{Conn: conn, r: io.MultiReader(bytes.NewReader(record), conn)}, nil
}

// prefixConn replays the bytes read by the gate before the rest of the stream.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }

func (s *Server) logSecurity(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	s.securityLogger.Println(msg)
	fmt.Printf("[SECURITY] %s\n", msg)
}

// memberPlaceholder replaces participant details in logs when metadata
// logging is off.
const memberPlaceholder = "[member]"

// logMeta writes to the general log only when metadata logging is enabled.
// Use it for anything that reveals participants or their activity.
func (s *Server) logMeta(format string, args ...interface{}) {
	if s.config.LogMetadata {
		s.logger.Printf(format, args...)
	}
}

// peer returns addr for logs when metadata logging is enabled, otherwise a
// placeholder. Use it for connections that already presented a valid access key.
func (s *Server) peer(addr string) string {
	if s.config.LogMetadata {
		return addr
	}
	return memberPlaceholder
}

// member identifies a joined client in logs when metadata logging is enabled.
func (s *Server) member(c *Client) string {
	if s.config.LogMetadata {
		return fmt.Sprintf("%s (%s)", c.username, c.ipAddr)
	}
	return memberPlaceholder
}

// ── Sending helpers ────────────────────────────────────────────────

func now() string { return time.Now().Format("15:04:05") }

func encode(m wire.Msg) []byte {
	f, err := wire.EncodeMsg(m)
	if err != nil {
		// Only possible for oversized messages, which the handlers prevent.
		f, _ = wire.EncodeMsg(wire.Msg{T: wire.TError, Text: "internal error: message too large"})
	}
	return f
}

func (s *Server) to(c *Client, m wire.Msg) { c.send(encode(m)) }

func (s *Server) info(c *Client, text string) { s.to(c, wire.Msg{T: wire.TInfo, Text: text}) }

func (s *Server) fail(c *Client, text string) { s.to(c, wire.Msg{T: wire.TError, Text: text}) }

// broadcastAll sends to every member. Caller must hold s.mu.
func (s *Server) broadcastAll(m wire.Msg) {
	f := encode(m)
	for c := range s.clients {
		c.send(f)
	}
}

// broadcastRoom sends to the members of a room. Caller must hold s.mu.
func (s *Server) broadcastRoom(r *Room, m wire.Msg) {
	f := encode(m)
	for c := range r.members {
		c.send(f)
	}
}

// ── Connection handling ────────────────────────────────────────────

func (s *Server) handleClient(conn net.Conn) {
	defer conn.Close()
	ipAddr := conn.RemoteAddr().String()

	// Backstop: a bug while handling one member must never take down the
	// whole server (which, with per-run keys, would lock everyone out).
	var joined *Client
	defer func() {
		if r := recover(); r != nil {
			s.logSecurity("Recovered from internal error while handling %s: %v", s.peer(ipAddr), r)
		}
		if joined != nil {
			s.removeClient(joined)
		}
	}()

	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	gated, err := s.gate(conn)
	if err != nil {
		s.logSecurity("Rejected connection from %s: %v", ipAddr, err)
		return
	}
	tlsConn := tls.Server(gated, s.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		s.logSecurity("Rejected connection from %s: %v", ipAddr, err)
		return
	}
	conn = tlsConn

	// Login: the first frame must be hello.
	reject := func(code, text string) {
		conn.Write(encode(wire.Msg{T: wire.TError, Code: code, Text: text}))
		time.Sleep(100 * time.Millisecond) // let the error reach the client
	}
	var hello wire.Msg
	for {
		f, err := wire.Read(conn)
		if err != nil {
			s.logSecurity("No valid hello from %s: %v", s.peer(ipAddr), err)
			return
		}
		if f.Type == wire.FrameDecoy {
			continue
		}
		if f.Type != wire.FrameControl {
			s.logSecurity("Protocol violation before login from %s", s.peer(ipAddr))
			return
		}
		hello, err = wire.DecodeMsg(f.Payload)
		if err != nil || hello.T != wire.THello {
			s.logSecurity("Protocol violation before login from %s", s.peer(ipAddr))
			reject(wire.CodeProtocol, "Expected hello")
			return
		}
		break
	}
	if hello.V != wire.Version {
		reject(wire.CodeVersion, fmt.Sprintf("This server speaks protocol %d; please update your QuietRoom client.", wire.Version))
		return
	}
	username := hello.User
	if !wire.ValidUsername(username) {
		s.logSecurity("Invalid username from %s", s.peer(ipAddr))
		reject(wire.CodeInvalidUsername, "Invalid username: "+wire.UsernameRules)
		return
	}
	if _, err := e2e.ParsePublicKeys(hello.KX, hello.SK); err != nil {
		s.logSecurity("Invalid session keys from %s", s.peer(ipAddr))
		reject(wire.CodeProtocol, "Invalid session keys")
		return
	}

	c := &Client{
		conn:       conn,
		username:   username,
		ipAddr:     ipAddr,
		kx:         hello.KX,
		sk:         hello.SK,
		ctrl:       make(chan []byte, ctrlQueueLen),
		bulk:       make(chan []byte, bulkQueueLen),
		done:       make(chan struct{}),
		rooms:      make(map[string]bool),
		tokens:     rateBurst,
		lastRefill: time.Now(),
	}
	s.mu.Lock()
	if _, taken := s.usernames[wire.UsernameKey(username)]; taken {
		s.mu.Unlock()
		reject(wire.CodeUsernameTaken, "Username already taken. Please reconnect with a different name.")
		return
	}
	s.usernames[wire.UsernameKey(username)] = c
	s.clients[c] = true
	joined = c
	s.to(c, wire.Msg{T: wire.TWelcome, User: username, V: wire.Version})
	// Session keys of everyone already online, then ours to everyone, so
	// members can encrypt to each other right away.
	for other := range s.clients {
		if other != c {
			s.to(c, wire.Msg{T: wire.TPeer, User: other.username, KX: other.kx, SK: other.sk})
		}
	}
	s.broadcastAll(wire.Msg{T: wire.TJoined, User: username, KX: c.kx, SK: c.sk})
	s.mu.Unlock()
	conn.SetDeadline(time.Time{})

	s.logMeta("User joined: %s from %s", username, ipAddr)
	go c.writer()
	if s.config.DecoyTraffic {
		go s.sendDecoys(c)
	}

	for {
		conn.SetReadDeadline(time.Now().Add(idleTimeout))
		f, err := wire.Read(conn)
		if err != nil {
			if errors.Is(err, wire.ErrFrame) {
				s.logSecurity("Malformed frame from %s: %v", s.member(c), err)
			}
			return
		}
		switch f.Type {
		case wire.FrameDecoy:
		case wire.FrameData:
			s.relayData(c, f.Payload)
		case wire.FrameControl:
			m, err := wire.DecodeMsg(f.Payload)
			if err != nil {
				s.logSecurity("Malformed message from %s: %v", s.member(c), err)
				return
			}
			if m.T == wire.TQuit {
				return
			}
			s.dispatch(c, m)
		}
	}
}

// messageCost is the rate-limit cost of a message type. Flow-control
// messages are free: their volume is bounded by the transfer itself.
func messageCost(t string) float64 {
	switch t {
	case wire.TFileAccept, wire.TFileCredit, wire.TFileEnd, wire.TFileCancel, wire.TFileDecline:
		return 0
	case wire.TRoomKey:
		// Members hand out room keys to each other when someone joins or
		// leaves: one per member, so they must not exhaust the budget.
		return 0.1
	case wire.TJoin, wire.TFileOffer:
		return 2
	}
	return 1
}

func (s *Server) dispatch(c *Client, m wire.Msg) {
	if cost := messageCost(m.T); cost > 0 && !c.allow(cost) {
		c.rateMu.Lock()
		notify := time.Since(c.lastNotice) > 5*time.Second
		if notify {
			c.lastNotice = time.Now()
		}
		c.rateMu.Unlock()
		if notify {
			s.to(c, wire.Msg{T: wire.TError, Code: wire.CodeRateLimited, Text: "You are sending too fast; some messages were dropped."})
		}
		return
	}
	switch m.T {
	case wire.TChat:
		s.handleChat(c, m)
	case wire.TDM:
		s.handleDM(c, m)
	case wire.TJoin:
		s.handleJoin(c, m)
	case wire.TLeave:
		s.handleLeave(c, m)
	case wire.TRoomHello:
		s.handleRoomHello(c, m)
	case wire.TRoomKey:
		s.handleRoomKey(c, m)
	case wire.TRooms:
		s.handleRooms(c)
	case wire.TUsers:
		s.handleUsers(c)
	case wire.TMembers:
		s.handleMembers(c, m)
	case wire.THelp:
		s.info(c, wire.HelpText)
	case wire.TFileOffer:
		s.handleOffer(c, m)
	case wire.TFileAccept:
		s.handleAccept(c, m)
	case wire.TFileCredit:
		s.handleCredit(c, m)
	case wire.TFileDecline:
		s.handleDecline(c, m)
	case wire.TFileCancel:
		s.handleCancel(c, m)
	case wire.TFileEnd:
		s.handleEnd(c, m)
	default:
		s.fail(c, fmt.Sprintf("Unknown request: %s", m.T))
	}
}

// removeClient takes a member out of every room and transfer.
func (s *Server) removeClient(c *Client) {
	c.kill()
	s.mu.Lock()
	if !s.clients[c] {
		s.mu.Unlock()
		return
	}
	delete(s.clients, c)
	delete(s.usernames, wire.UsernameKey(c.username))
	for name := range c.rooms {
		if r := s.rooms[name]; r != nil {
			delete(r.members, c)
			if len(r.members) == 0 {
				delete(s.rooms, name)
			} else {
				s.broadcastRoom(r, wire.Msg{T: wire.TLeft, User: c.username, Room: name})
			}
		}
	}
	s.broadcastAll(wire.Msg{T: wire.TLeft, User: c.username})
	s.mu.Unlock()

	s.tmu.Lock()
	for id, t := range s.transfers {
		if t.sender == c || t.recipient == c {
			delete(s.transfers, id)
			other := t.recipient
			if other == c {
				other = t.sender
			}
			s.to(other, wire.Msg{T: wire.TFileCancel, ID: id, Text: c.username + " disconnected"})
		}
	}
	s.tmu.Unlock()
	s.logMeta("User left: %s from %s", c.username, c.ipAddr)
}

func (s *Server) sendDecoys(c *Client) {
	mean := time.Duration(s.config.DecoyInterval) * time.Second
	for {
		// Random interval between 0.5x and 1.5x the configured mean, so
		// decoys do not form a recognisable fixed rhythm.
		jitter, _ := rand.Int(rand.Reader, big.NewInt(int64(mean)+1))
		wait := mean/2 + time.Duration(jitter.Int64())
		select {
		case <-c.done:
			return
		case <-s.shutdown:
			return
		case <-time.After(wait):
		}
		size := s.config.DecoyMinBytes
		if span := s.config.DecoyMaxBytes - s.config.DecoyMinBytes; span > 0 {
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(span)+1))
			size += int(n.Int64())
		}
		noise := make([]byte, 32)
		rand.Read(noise)
		if f, err := wire.EncodeSize(wire.FrameDecoy, noise, size); err == nil {
			c.sendOptional(f)
		}
	}
}

// ── Chat ───────────────────────────────────────────────────────────

// cleanText removes control and hidden characters (see wire.CleanText).
func cleanText(t string) (string, bool) {
	t = strings.TrimSpace(wire.CleanText(t))
	return t, t != "" && len(t) <= wire.MaxTextBytes
}

// validCipher checks the size of an encrypted field (base64).
func validCipher(ct string) bool { return ct != "" && len(ct) <= wire.MaxCipherText }

func (s *Server) handleChat(c *Client, m wire.Msg) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var r *Room
	if m.Room != "" {
		r = s.rooms[m.Room]
		if r == nil || !c.rooms[m.Room] {
			s.fail(c, fmt.Sprintf("You are not a member of %s", m.Room))
			return
		}
	}
	if r != nil && r.locked() {
		// End-to-end encrypted: relay as is. Members check the signature.
		if !validCipher(m.CT) || m.Sig == "" || len(m.Sig) > wire.MaxSigField || m.Text != "" {
			s.fail(c, "Invalid encrypted message")
			return
		}
		s.broadcastRoom(r, wire.Msg{T: wire.TChat, From: c.username, Room: m.Room, KID: m.KID, N: m.N, CT: m.CT, Sig: m.Sig, Time: now()})
		return
	}
	if m.CT != "" {
		s.fail(c, "Encrypted messages are only for password rooms")
		return
	}
	text, ok := cleanText(m.Text)
	if !ok {
		if text != "" {
			s.fail(c, fmt.Sprintf("Message too long (max %d bytes)", wire.MaxTextBytes))
		}
		return
	}
	out := wire.Msg{T: wire.TChat, From: c.username, Room: m.Room, Text: text, Time: now()}
	if r == nil {
		s.broadcastAll(out)
		return
	}
	s.broadcastRoom(r, out)
}

// handleDM relays an end-to-end encrypted direct message. The sender gets a
// delivery notice without the ciphertext (it shows its own copy).
func (s *Server) handleDM(c *Client, m wire.Msg) {
	if !validCipher(m.CT) || m.Text != "" {
		s.fail(c, "Invalid encrypted message")
		return
	}
	s.mu.Lock()
	target := s.usernames[wire.UsernameKey(m.To)]
	s.mu.Unlock()
	if target == nil {
		s.fail(c, fmt.Sprintf("User '%s' is not online.", m.To))
		return
	}
	if target == c {
		s.fail(c, "You cannot send a direct message to yourself.")
		return
	}
	t := now()
	target.send(encode(wire.Msg{T: wire.TDM, From: c.username, To: target.username, N: m.N, CT: m.CT, Time: t}))
	s.to(c, wire.Msg{T: wire.TDM, From: c.username, To: target.username, N: m.N, Time: t})
	s.logMeta("DM: %s -> %s", c.username, target.username)
}

// handleRoomHello relays a member's proof of the room password to the other
// members, who answer with their room keys if it checks out.
func (s *Server) handleRoomHello(c *Client, m wire.Msg) {
	if m.Proof == "" || len(m.Proof) > wire.MaxKeyField {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rooms[m.Room]
	if r == nil || !r.locked() || !c.rooms[m.Room] {
		return
	}
	out := encode(wire.Msg{T: wire.TRoomHello, From: c.username, Room: m.Room, Proof: m.Proof})
	for other := range r.members {
		if other != c {
			other.send(out)
		}
	}
}

// handleRoomKey relays an encrypted room key to a member sharing a password
// room with the sender.
func (s *Server) handleRoomKey(c *Client, m wire.Msg) {
	if !validCipher(m.CT) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	target := s.usernames[wire.UsernameKey(m.To)]
	if target == nil || target == c {
		return
	}
	shared := false
	for name := range c.rooms {
		if r := s.rooms[name]; r != nil && r.locked() && target.rooms[name] {
			shared = true
			break
		}
	}
	if !shared {
		return
	}
	target.send(encode(wire.Msg{T: wire.TRoomKey, From: c.username, N: m.N, CT: m.CT}))
}

func (s *Server) handleJoin(c *Client, m wire.Msg) {
	name := m.Room
	if !wire.ValidRoomName(name) {
		s.fail(c, fmt.Sprintf("Invalid room name. Use # followed by 1-%d letters, digits, '_', '-' or '.' (e.g., #general)", wire.MaxRoomNameLen))
		return
	}
	var vf []byte
	if m.VF != "" {
		b, err := e2e.Decode(m.VF, e2e.KeyLen)
		if err != nil || len(b) != e2e.KeyLen {
			s.fail(c, "Invalid room verifier")
			return
		}
		vf = hashVerifier(b)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rooms[name]
	switch {
	case c.rooms[name]:
		s.info(c, fmt.Sprintf("You are already in %s", name))
		return
	case len(c.rooms) >= s.config.MaxRoomsPerMember:
		s.fail(c, fmt.Sprintf("You are in too many rooms (max %d)", s.config.MaxRoomsPerMember))
		return
	case r == nil && len(s.rooms) >= s.config.MaxRooms:
		s.fail(c, "Too many rooms on this server")
		return
	case r != nil && r.locked() && vf == nil:
		s.fail(c, "This room is password-protected. Usage: /join "+name+" <password>")
		return
	case r != nil && r.locked() && subtle.ConstantTimeCompare(vf, r.verifier) != 1:
		s.fail(c, "Incorrect password for room "+name)
		return
	}
	created := false
	if r == nil {
		r = &Room{name: name, members: make(map[*Client]bool), verifier: vf}
		s.rooms[name] = r
		created = true
	}
	r.members[c] = true
	c.rooms[name] = true
	s.broadcastRoom(r, wire.Msg{T: wire.TJoined, User: c.username, Room: name, Created: created, Locked: r.locked()})
}

func (s *Server) handleLeave(c *Client, m wire.Msg) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rooms[m.Room]
	if r == nil || !c.rooms[m.Room] {
		s.fail(c, fmt.Sprintf("You are not in room %s", m.Room))
		return
	}
	left := wire.Msg{T: wire.TLeft, User: c.username, Room: m.Room}
	s.broadcastRoom(r, left) // includes the leaving member
	delete(r.members, c)
	delete(c.rooms, m.Room)
	if len(r.members) == 0 {
		delete(s.rooms, m.Room)
	}
}

func (s *Server) handleRooms(c *Client) {
	s.mu.Lock()
	names := make([]string, 0, len(s.rooms))
	for name := range s.rooms {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	if len(names) == 0 {
		b.WriteString("No active rooms. Use /join #roomname to create one.")
	} else {
		b.WriteString("Active Rooms:\n")
		for _, name := range names {
			r := s.rooms[name]
			locked := ""
			if r.locked() {
				locked = " 🔒"
			}
			fmt.Fprintf(&b, "  %s%s (%d users)\n", name, locked, len(r.members))
		}
	}
	s.mu.Unlock()
	s.info(c, strings.TrimRight(b.String(), "\n"))
}

func (s *Server) handleUsers(c *Client) {
	s.mu.Lock()
	names := make([]string, 0, len(s.usernames))
	for _, u := range s.usernames {
		names = append(names, u.username)
	}
	s.mu.Unlock()
	sort.Strings(names)
	s.info(c, fmt.Sprintf("Online Users (%d):\n  %s", len(names), strings.Join(names, "\n  ")))
}

func (s *Server) handleMembers(c *Client, m wire.Msg) {
	target := m.Room
	var names []string
	s.mu.Lock()
	if strings.EqualFold(target, "lobby") {
		target = "lobby"
		for other := range s.clients {
			if len(other.rooms) == 0 {
				names = append(names, other.username)
			}
		}
	} else {
		r := s.rooms[target]
		// Password rooms are only visible to their members.
		if r == nil || (r.locked() && !c.rooms[target]) {
			s.mu.Unlock()
			s.fail(c, "Room not found or access denied.")
			return
		}
		for other := range r.members {
			names = append(names, other.username)
		}
	}
	s.mu.Unlock()
	sort.Strings(names)
	s.info(c, fmt.Sprintf("Members of %s (%d):\n  %s", target, len(names), strings.Join(names, "\n  ")))
}

// ── File transfers ─────────────────────────────────────────────────

// cancelTransfer removes a transfer and tells both parties. Caller holds s.tmu.
func (s *Server) cancelTransfer(t *transfer, reason string) {
	delete(s.transfers, t.idStr)
	m := wire.Msg{T: wire.TFileCancel, ID: t.idStr, Text: reason}
	s.to(t.sender, m)
	s.to(t.recipient, m)
}

func (s *Server) handleOffer(c *Client, m wire.Msg) {
	failRef := func(text string) {
		s.to(c, wire.Msg{T: wire.TError, Ref: m.Ref, Text: text})
	}
	if len(m.Ref) > 32 {
		return
	}
	// The name, real size and hash travel encrypted in CT; Size is the
	// number of encrypted bytes, whole chunks only.
	switch {
	case m.Size <= 0 || m.Size%wire.DataChunk != 0:
		failRef("Invalid file size.")
		return
	case !validCipher(m.CT):
		failRef("Invalid file offer.")
		return
	}
	s.mu.Lock()
	target := s.usernames[wire.UsernameKey(m.To)]
	s.mu.Unlock()
	if target == nil {
		failRef(fmt.Sprintf("User '%s' is not online.", m.To))
		return
	}
	if target == c {
		failRef("You cannot send files to yourself.")
		return
	}
	id, err := wire.NewID()
	if err != nil {
		failRef("Internal error.")
		return
	}

	s.tmu.Lock()
	outgoing, incoming := 0, 0
	for _, t := range s.transfers {
		if t.sender == c {
			outgoing++
		}
		if t.recipient == target {
			incoming++
		}
	}
	if outgoing >= maxTransfersPerMember {
		s.tmu.Unlock()
		failRef(fmt.Sprintf("Too many file transfers in progress (max %d).", maxTransfersPerMember))
		return
	}
	if incoming >= maxTransfersPerMember {
		s.tmu.Unlock()
		failRef(fmt.Sprintf("%s has too many file transfers in progress.", m.To))
		return
	}
	t := &transfer{
		id: id, idStr: wire.IDString(id), sender: c, recipient: target,
		size: m.Size, created: time.Now(), activity: time.Now(),
	}
	s.transfers[t.idStr] = t
	s.tmu.Unlock()

	s.to(target, wire.Msg{T: wire.TFileOffer, ID: t.idStr, From: c.username, Size: t.size, N: m.N, CT: m.CT})
	s.to(c, wire.Msg{T: wire.TFileOffered, Ref: m.Ref, ID: t.idStr, To: target.username, Size: t.size})
	s.logMeta("File transfer offered: %s -> %s (%d bytes encrypted)", c.username, target.username, t.size)
}

// lookup returns a transfer by ID. Caller holds s.tmu.
func (s *Server) lookup(id string) *transfer {
	if len(id) != 2*wire.IDLen {
		return nil
	}
	return s.transfers[id]
}

func (s *Server) handleAccept(c *Client, m wire.Msg) {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	t := s.lookup(m.ID)
	switch {
	case t == nil:
		s.fail(c, "Transfer ID not found or expired.")
	case t.recipient != c:
		s.fail(c, "This transfer is not for you.")
	case t.accepted:
		s.fail(c, "Transfer already accepted.")
	case m.Bytes <= 0 || m.Bytes > wire.MaxWindow:
		s.cancelTransfer(t, "invalid flow-control window")
	default:
		t.accepted = true
		t.credit = m.Bytes
		t.activity = time.Now()
		s.to(t.sender, wire.Msg{T: wire.TFileAccept, ID: t.idStr, Bytes: m.Bytes})
		s.logMeta("File transfer accepted: %s -> %s", t.sender.username, c.username)
	}
}

func (s *Server) handleCredit(c *Client, m wire.Msg) {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	t := s.lookup(m.ID)
	if t == nil || t.recipient != c || !t.accepted {
		return // stale credit after a cancel: ignore
	}
	if m.Bytes <= 0 || t.credit+m.Bytes > wire.MaxWindow {
		s.cancelTransfer(t, "invalid flow-control credit")
		return
	}
	t.credit += m.Bytes
	t.activity = time.Now()
	s.to(t.sender, wire.Msg{T: wire.TFileCredit, ID: t.idStr, Bytes: m.Bytes})
}

func (s *Server) handleDecline(c *Client, m wire.Msg) {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	t := s.lookup(m.ID)
	switch {
	case t == nil:
		s.fail(c, "Transfer ID not found or expired.")
	case t.recipient != c:
		s.fail(c, "This transfer is not for you.")
	case t.accepted:
		s.fail(c, "Transfer already running; use /cancel.")
	default:
		delete(s.transfers, t.idStr)
		s.to(t.sender, wire.Msg{T: wire.TFileDecline, ID: t.idStr, User: c.username})
	}
}

func (s *Server) handleCancel(c *Client, m wire.Msg) {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	t := s.lookup(m.ID)
	if t == nil {
		return // already finished: nothing to do
	}
	if t.sender != c && t.recipient != c {
		s.fail(c, "This transfer is not yours.")
		return
	}
	delete(s.transfers, t.idStr)
	other := t.recipient
	if other == c {
		other = t.sender
	}
	s.to(other, wire.Msg{T: wire.TFileCancel, ID: t.idStr, Text: "cancelled by " + c.username})
}

func (s *Server) handleEnd(c *Client, m wire.Msg) {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	t := s.lookup(m.ID)
	if t == nil || t.sender != c || !t.accepted {
		return
	}
	if t.sent != t.size {
		s.cancelTransfer(t, "incomplete transfer")
		return
	}
	delete(s.transfers, t.idStr)
	// file_end travels with the data, so the recipient sees it after the
	// last chunk.
	if !t.recipient.sendBulk(encode(wire.Msg{T: wire.TFileEnd, ID: t.idStr})) {
		s.to(t.sender, wire.Msg{T: wire.TFileCancel, ID: t.idStr, Text: "recipient too slow"})
		s.to(t.recipient, wire.Msg{T: wire.TFileCancel, ID: t.idStr, Text: "transfer failed"})
		return
	}
	s.to(c, wire.Msg{T: wire.TFileDone, ID: t.idStr})
	s.logMeta("File transfer completed: %s -> %s", c.username, t.recipient.username)
}

// relayData forwards a data frame within the granted credit.
func (s *Server) relayData(c *Client, payload []byte) {
	id, data, err := wire.SplitData(payload)
	if err != nil {
		return
	}
	s.tmu.Lock()
	defer s.tmu.Unlock()
	t := s.transfers[wire.IDString(id)]
	if t == nil || t.sender != c {
		return // stale data after a cancel, or not the sender's: drop
	}
	n := int64(len(data))
	switch {
	case !t.accepted:
		s.cancelTransfer(t, "data before acceptance")
		return
	case n > t.credit:
		s.logSecurity("Flow-control violation by %s", s.member(c))
		s.cancelTransfer(t, "sender exceeded flow-control credit")
		return
	case t.sent+n > t.size:
		s.cancelTransfer(t, "sender sent more data than announced")
		return
	}
	frame, err := wire.EncodeData(id, data)
	if err != nil {
		return
	}
	if !t.recipient.sendBulk(frame) {
		s.cancelTransfer(t, "recipient too slow")
		return
	}
	t.credit -= n
	t.sent += n
	t.activity = time.Now()
}

// ── Housekeeping ───────────────────────────────────────────────────

func (s *Server) housekeeping() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	sweeps := 0
	for {
		select {
		case <-s.shutdown:
			return
		case <-ticker.C:
		}
		s.tmu.Lock()
		for _, t := range s.transfers {
			switch {
			case !t.accepted && time.Since(t.created) > offerTTL:
				s.cancelTransfer(t, "offer expired (not accepted within 5 minutes)")
			case t.accepted && time.Since(t.activity) > stallTimeout:
				s.cancelTransfer(t, "transfer stalled")
			}
		}
		s.tmu.Unlock()
		if sweeps++; sweeps%4 == 0 {
			if dropped := s.limiter.sweep(); dropped > 0 {
				s.logSecurity("Refused %d connection(s) over connection limits in the last minute", dropped)
			}
		}
	}
}

func (s *Server) Shutdown() {
	fmt.Println("\n✓ Shutting down server gracefully...")
	close(s.shutdown)
	if s.listener != nil {
		s.listener.Close()
	}
	s.mu.Lock()
	for c := range s.clients {
		s.info(c, "*** Server is shutting down. Goodbye! ***")
	}
	clients := make([]*Client, 0, len(s.clients))
	for c := range s.clients {
		clients = append(clients, c)
	}
	s.mu.Unlock()
	time.Sleep(200 * time.Millisecond) // let the goodbye go out
	for _, c := range clients {
		c.kill()
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	s.logger.Println("Server shutdown completed")
	s.logSecurity("Server shutdown completed")
	fmt.Println("✓ Server stopped")
}

func main() {
	server, err := NewServer()
	if err != nil {
		fmt.Println("Error creating server:", err)
		return
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		server.Shutdown()
		os.Exit(0)
	}()
	go server.housekeeping()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", server.config.Port))
	if err != nil {
		fmt.Println("Error starting server:", err)
		return
	}
	server.listener = listener
	defer listener.Close()

	if err := writeFileAtomic(accessFile, server.accessBundle, 0600); err != nil {
		fmt.Printf("Error writing %s: %v\n", accessFile, err)
		return
	}
	fmt.Printf("✓ Access file saved to: %s\n", accessFile)
	fmt.Printf("⚠ COPY %s to client machines before connecting — it is SECRET, anyone holding it can join!\n", accessFile)
	fmt.Println("⚠ Restarting the server invalidates the previous access file.")
	fmt.Printf("✓ QuietRoom server (protocol %d) listening on port %d (TLS 1.3, access key required, silent to strangers)\n", wire.Version, server.config.Port)
	fmt.Printf("✓ Logging to: %s\n", server.config.LogFile)
	fmt.Printf("✓ Security logging to: %s\n", server.config.SecurityLogFile)
	if server.config.LogMetadata {
		fmt.Println("⚠ Metadata logging is ON: logs record participants, DMs, file transfers and IP addresses")
	} else {
		fmt.Println("✓ Metadata logging off: logs contain no participant information")
	}
	if server.config.DecoyTraffic {
		fmt.Printf("✓ Decoy traffic enabled (mean interval: %ds)\n", server.config.DecoyInterval)
	}
	fmt.Println("✓ Press Ctrl+C for graceful shutdown")
	fmt.Println()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-server.shutdown:
				return
			default:
				fmt.Println("Error accepting connection:", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}
		host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			host = conn.RemoteAddr().String()
		}
		if !server.limiter.admit(host) {
			conn.Close() // refused before the TLS handshake: no crypto work done
			continue
		}
		server.wg.Add(1)
		go func(conn net.Conn, host string) {
			defer server.wg.Done()
			defer server.limiter.release(host)
			server.handleClient(conn)
		}(conn, host)
	}
}
