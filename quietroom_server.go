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
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
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
	"strings"
	"sync"
	"syscall"
	"time"
	"strconv"

	"golang.org/x/crypto/bcrypt"
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
	MaxConnections         int `json:"max_connections"`
	MaxConnectionsPerIP    int `json:"max_connections_per_ip"`
	MaxNewConnPerIPPerMin  int `json:"max_new_connections_per_ip_per_minute"`

	// LogMetadata records who connected, joined, left, sent DMs or files, and
	// member IP addresses. Off by default: routine logs then contain no
	// information about participants. Enable only temporarily for debugging.
	LogMetadata bool `json:"log_metadata"`
}

const (
	defaultMaxConnections        = 100
	defaultMaxConnectionsPerIP   = 10
	defaultMaxNewConnPerIPPerMin = 30
)

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

func newConnLimiter(cfg ServerConfig) *connLimiter {
	pick := func(v, def int) int {
		if v <= 0 {
			return def
		}
		return v
	}
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

type Client struct {
	conn        net.Conn
	username    string
	outgoing    chan []byte   // never closed; senders select on done instead
	done        chan struct{} // closed once when the client leaves
	doneOnce    sync.Once
	sessionKey  []byte
	gcm         cipher.AEAD
	ipAddr      string
	lastActive  time.Time
	mu          sync.Mutex
	rooms       map[string]bool
	currentRoom string
}

type Room struct {
	name         string
	members      map[*Client]bool
	passwordHash string // bcrypt hash of password, empty if no password
	mu           sync.RWMutex
}

type FileTransfer struct {
	sender       *Client
	recipient    *Client
	filename     string
	filesize     int64
	accepted     bool
	data         chan []byte
	done         chan bool
	expectedHash string // SHA-256 hash of file
}

type Server struct {
	clients        map[*Client]bool
	mu             sync.RWMutex
	join           chan *Client
	leave          chan *Client
	privateKey     *rsa.PrivateKey
	tlsCert        tls.Certificate
	accessCertRaw  []byte // DER of the master access certificate clients must present
	accessBundle   []byte // contents of quietroom_access.pem for this run
	limiter        *connLimiter
	dhParams       *DHParams
	config         ServerConfig
	logger         *log.Logger
	securityLogger *log.Logger
	usernames      map[string]*Client
	rooms          map[string]*Room
	roomsMu        sync.RWMutex
	fileTransfers  map[string]*FileTransfer
	transfersMu    sync.RWMutex
	listener       net.Listener
	shutdown       chan bool
	wg             sync.WaitGroup
}

type DHParams struct {
	P *big.Int
	G *big.Int
}

type ObfuscatedPacket struct {
	Type byte
	Data []byte
}

func initDHParams() *DHParams {
	pHex := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
	p := new(big.Int)
	p.SetString(pHex, 16)
	g := big.NewInt(2)
	return &DHParams{P: p, G: g}
}

func generateDHKeyPair(params *DHParams) (*big.Int, *big.Int, error) {
	privateKey, err := rand.Int(rand.Reader, new(big.Int).Sub(params.P, big.NewInt(1)))
	if err != nil {
		return nil, nil, err
	}
	publicKey := new(big.Int).Exp(params.G, privateKey, params.P)
	return privateKey, publicKey, nil
}

func computeDHSharedSecret(privateKey, otherPublicKey, p *big.Int) []byte {
	sharedSecret := new(big.Int).Exp(otherPublicKey, privateKey, p)
	secretBytes := sharedSecret.Bytes()
	hash := sha256.Sum256(secretBytes)
	return hash[:]
}

func sha256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func randomInt(max int64) int64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(max))
	return n.Int64()
}

// accessFile is the secret bundle distributed to clients. It holds, in order:
// the server certificate (for pinning), the master access certificate and the
// master access private key (presented by clients via mutual TLS).
const accessFile = "quietroom_access.pem"

// handshakeTimeout bounds the unauthenticated phase of a connection
// (TLS handshake, DH exchange and username).
const handshakeTimeout = 15 * time.Second

type sessionKeys struct {
	privateKey    *rsa.PrivateKey
	tlsCert       tls.Certificate
	accessCertRaw []byte
	accessBundle  []byte // PEM contents of quietroom_access.pem
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

	serverKey, err := rsa.GenerateKey(rand.Reader, 4096)
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
		SerialNumber: serverSerial,
		Subject: pkix.Name{
			CommonName: hex.EncodeToString(nameBytes),
		},
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
		privateKey: serverKey,
		tlsCert: tls.Certificate{
			Certificate: [][]byte{serverDER},
			PrivateKey:  serverKey,
			Leaf:        serverCert,
		},
		accessCertRaw: accessDER,
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
	logger := log.New(logFile, "", log.LstdFlags)
	securityLogger := log.New(secLogFile, "[SECURITY] ", log.LstdFlags)

	keys, err := generateSessionKeys()
	if err != nil {
		return nil, err
	}
	privateKey := keys.privateKey

	fmt.Println("✓ Generated new server key and master access key (valid until server restart)")

	dhParams := initDHParams()
	fmt.Println("✓ Initialized Diffie-Hellman parameters (2048-bit)")

	server := &Server{
		tlsCert:        keys.tlsCert,
		accessCertRaw:  keys.accessCertRaw,
		accessBundle:   keys.accessBundle,
		limiter:        newConnLimiter(config),
		clients:        make(map[*Client]bool),
		join:           make(chan *Client),
		leave:          make(chan *Client),
		privateKey:     privateKey,
		dhParams:       dhParams,
		config:         config,
		logger:         logger,
		securityLogger: securityLogger,
		usernames:      make(map[string]*Client),
		rooms:          make(map[string]*Room),
		fileTransfers:  make(map[string]*FileTransfer),
		shutdown:       make(chan bool),
	}

	server.logSecurity("Server started with enhanced security features")
	return server, nil
}

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

// logSecurityMeta writes a security event that identifies a participant
// only when metadata logging is enabled.
func (s *Server) logSecurityMeta(format string, args ...interface{}) {
	if s.config.LogMetadata {
		s.logSecurity(format, args...)
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

func (s *Server) run() {
	for {
		select {
		case <-s.shutdown:
			return
		case client := <-s.join:
			s.mu.Lock()
			s.clients[client] = true
			s.mu.Unlock()
			joinMsg := fmt.Sprintf("*** %s joined the chat ***", client.username)
			s.broadcastToLobby(joinMsg)
			s.logMeta("User joined: %s from %s", client.username, client.ipAddr)
			s.logSecurityMeta("Successful authentication: %s from %s", client.username, client.ipAddr)
			if s.config.DecoyTraffic {
				go s.sendDecoyTraffic(client)
			}
		case client := <-s.leave:
			s.mu.Lock()
			if s.clients[client] {
				delete(s.clients, client)
				delete(s.usernames, client.username)
				client.markDone()
			}
			s.mu.Unlock()
			s.roomsMu.Lock()
			client.mu.Lock()
			for roomName := range client.rooms {
				if room, exists := s.rooms[roomName]; exists {
					room.mu.Lock()
					delete(room.members, client)
					room.mu.Unlock()
				}
			}
			client.mu.Unlock()
			s.roomsMu.Unlock()

			// Clean up pending file transfers involving this client
			s.transfersMu.Lock()
			for id, transfer := range s.fileTransfers {
				if transfer.sender == client || transfer.recipient == client {
					if transfer.sender == client && transfer.recipient != nil {
						s.sendToClient(transfer.recipient, "*** File transfer cancelled: sender disconnected ***")
					} else if transfer.recipient == client && transfer.sender != nil {
						s.sendToClient(transfer.sender, "*** File transfer cancelled: recipient disconnected ***")
					}
					delete(s.fileTransfers, id)
				}
			}
			s.transfersMu.Unlock()

			leaveMsg := fmt.Sprintf("*** %s left the chat ***", client.username)
			s.broadcastToLobby(leaveMsg)
			s.logMeta("User left: %s from %s", client.username, client.ipAddr)
		}
	}
}

func (s *Server) sendDecoyTraffic(client *Client) {
	ticker := time.NewTicker(time.Duration(s.config.DecoyInterval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.shutdown:
			return
		case <-ticker.C:
			s.mu.RLock()
			_, exists := s.clients[client]
			s.mu.RUnlock()
			if !exists {
				return
			}
			size := s.config.DecoyMinBytes + int(randomInt(int64(s.config.DecoyMaxBytes-s.config.DecoyMinBytes)))
			decoyData := make([]byte, size)
			rand.Read(decoyData)
			packet := s.createObfuscatedPacket(0x02, decoyData)
			if client.send(packet) {
				client.mu.Lock()
				client.lastActive = time.Now()
				client.mu.Unlock()
			}
		}
	}
}

// markDone signals that the client has left. Safe to call more than once.
func (c *Client) markDone() {
	c.doneOnce.Do(func() { close(c.done) })
}

// send queues a packet without blocking. It returns false if the client has
// left or its queue is full. It never panics: outgoing is never closed.
func (c *Client) send(packet []byte) bool {
	select {
	case <-c.done:
		return false
	default:
	}
	select {
	case c.outgoing <- packet:
		return true
	case <-c.done:
		return false
	default:
		return false
	}
}

// sendWait queues a packet, waiting up to timeout for queue space. Used for
// file data, where dropping a chunk would corrupt the transfer.
func (c *Client) sendWait(packet []byte, timeout time.Duration) bool {
	select {
	case <-c.done:
		return false
	default:
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case c.outgoing <- packet:
		return true
	case <-c.done:
		return false
	case <-timer.C:
		return false
	}
}

// fileDataTimeout bounds how long a sender waits for a slow recipient's queue.
const fileDataTimeout = 30 * time.Second

func (s *Server) broadcastToLobby(msg string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for client := range s.clients {
		encrypted, err := client.encrypt([]byte(msg))
		if err != nil {
			continue
		}
		packet := s.createObfuscatedPacket(0x01, encrypted)
		if client.send(packet) {
			client.mu.Lock()
			client.lastActive = time.Now()
			client.mu.Unlock()
		}
	}
}

func (s *Server) createObfuscatedPacket(msgType byte, data []byte) []byte {
	paddingSize := int(randomInt(256))
	padding := make([]byte, paddingSize)
	rand.Read(padding)
	packet := make([]byte, 3+len(data)+paddingSize)
	packet[0] = msgType
	binary.BigEndian.PutUint16(packet[1:3], uint16(len(data)))
	copy(packet[3:], data)
	copy(packet[3+len(data):], padding)
	return packet
}

func (c *Client) encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := c.gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (c *Client) decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := c.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertextBytes := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := c.gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// Updated readObfuscatedPacket - handles oversized packets gracefully
func readObfuscatedPacket(conn net.Conn) (*ObfuscatedPacket, error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	msgType := header[0]
	dataLen := binary.BigEndian.Uint16(header[1:3])

	const maxPacketDataSize = 32768 // Large safe limit

	if dataLen > maxPacketDataSize {
		// Drain the oversized data to keep stream in sync
		dummy := make([]byte, dataLen)
		io.ReadFull(conn, dummy)

		// Drain padding
		conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		padding := make([]byte, 1024)
		conn.Read(padding)
		conn.SetReadDeadline(time.Time{})

		return nil, fmt.Errorf("oversized packet dropped (%d bytes)", dataLen)
	}

	data := make([]byte, dataLen)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	padding := make([]byte, 1024)
	conn.Read(padding)
	conn.SetReadDeadline(time.Time{})

	return &ObfuscatedPacket{Type: msgType, Data: data}, nil
}

func (s *Server) handleClient(conn net.Conn) {
	defer conn.Close()
	defer s.wg.Done()

	ipAddr := conn.RemoteAddr().String()

	// Backstop: a bug while handling one client must never take down the
	// whole server (which, with per-run keys, would lock everyone out).
	var joined *Client
	defer func() {
		if r := recover(); r != nil {
			s.logSecurity("Recovered from internal error while handling %s: %v", s.peer(ipAddr), r)
			if joined != nil {
				s.leave <- joined
			}
		}
	}()
	s.logMeta("New connection attempt from %s", ipAddr)

	// Complete the TLS handshake (including access key verification) up
	// front, and bound the whole unauthenticated phase with a deadline.
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		s.logSecurity("Rejected connection from %s: %v", ipAddr, err)
		return
	}

	dhPrivate, dhPublic, err := generateDHKeyPair(s.dhParams)
	if err != nil {
		s.logSecurity("Failed DH key generation for %s: %v", s.peer(ipAddr), err)
		return
	}
	dhPubBytes := dhPublic.Bytes()
	signature, err := rsa.SignPSS(rand.Reader, s.privateKey, crypto.SHA256, sha256Hash(dhPubBytes), nil)
	if err != nil {
		s.logSecurity("Failed to sign DH public key for %s: %v", s.peer(ipAddr), err)
		return
	}
	dhPubLen := make([]byte, 4)
	binary.BigEndian.PutUint32(dhPubLen, uint32(len(dhPubBytes)))
	conn.Write(dhPubLen)
	conn.Write(dhPubBytes)
	sigLen := make([]byte, 4)
	binary.BigEndian.PutUint32(sigLen, uint32(len(signature)))
	conn.Write(sigLen)
	conn.Write(signature)
	var clientDHPubLen uint32
	if err := binary.Read(conn, binary.BigEndian, &clientDHPubLen); err != nil {
		s.logSecurity("Failed to read client DH pub len from %s: %v", s.peer(ipAddr), err)
		return
	}
	const maxDHPubKeySize = 4096
	if clientDHPubLen > maxDHPubKeySize {
		s.logSecurity("DoS attempt from %s: DH key size %d exceeds maximum %d", s.peer(ipAddr), clientDHPubLen, maxDHPubKeySize)
		return
	}
	clientDHPubBytes := make([]byte, clientDHPubLen)
	if _, err := io.ReadFull(conn, clientDHPubBytes); err != nil {
		s.logSecurity("Failed to read client DH pub from %s: %v", s.peer(ipAddr), err)
		return
	}
	clientDHPub := new(big.Int).SetBytes(clientDHPubBytes)

	one := big.NewInt(1)
	pMinusOne := new(big.Int).Sub(s.dhParams.P, one)
	if clientDHPub.Cmp(one) <= 0 || clientDHPub.Cmp(pMinusOne) >= 0 {
		s.logSecurity("Invalid DH public key from %s (small subgroup attack attempt)", s.peer(ipAddr))
		return
	}

	sharedSecret := computeDHSharedSecret(dhPrivate, clientDHPub, s.dhParams.P)
	s.logSecurityMeta("Diffie-Hellman key exchange completed with %s", ipAddr)
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		s.logSecurity("Failed to create cipher for %s: %v", s.peer(ipAddr), err)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		s.logSecurity("Failed to create GCM for %s: %v", s.peer(ipAddr), err)
		return
	}
	client := &Client{
		conn:        conn,
		outgoing:    make(chan []byte, 4096),
		done:        make(chan struct{}),
		sessionKey:  sharedSecret,
		gcm:         gcm,
		ipAddr:      ipAddr,
		lastActive:  time.Now(),
		rooms:       make(map[string]bool),
		currentRoom: "",
	}
	welcomeMsg, _ := client.encrypt([]byte("Enter your username: "))
	welcomePacket := s.createObfuscatedPacket(0x01, welcomeMsg)
	conn.Write(welcomePacket)
	usernamePacket, err := readObfuscatedPacket(conn)
	if err != nil {
		s.logSecurity("Failed to read username packet from %s: %v", s.peer(ipAddr), err)
		return
	}
	usernameEnc := usernamePacket.Data
	usernameBytes, err := client.decrypt(usernameEnc)
	if err != nil {
		s.logSecurity("Failed username decryption from %s: %v", s.peer(ipAddr), err)
		return
	}
	username := strings.TrimSpace(string(usernameBytes))
	if username == "" {
		s.logSecurity("Empty username from %s", s.peer(ipAddr))
		return
	}
	const maxUsernameLength = 32
	if len(username) > maxUsernameLength {
		s.logSecurity("Username too long (%d chars) from %s", len(username), s.peer(ipAddr))
		return
	}
	for _, ch := range username {
		if ch < 32 || ch == 127 {
			s.logSecurity("Username contains control character (0x%02X) from %s", ch, s.peer(ipAddr))
			return
		}
	}
	if strings.TrimSpace(username) == "" {
		s.logSecurity("Username is all whitespace from %s", s.peer(ipAddr))
		return
	}
	for _, ch := range username {
		isValid := (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == ' ' || ch == '_' || ch == '-' || ch == '.'
		if !isValid {
			s.logSecurity("Username contains invalid character '%c' (0x%04X) from %s", ch, ch, s.peer(ipAddr))
			return
		}
	}
	s.mu.Lock()
	if _, taken := s.usernames[username]; taken {
		s.mu.Unlock()
		errMsg, _ := client.encrypt([]byte("*** Username already taken. Please reconnect with a different name. ***"))
		conn.Write(s.createObfuscatedPacket(0x01, errMsg))
		time.Sleep(500 * time.Millisecond)
		return
	}
	s.usernames[username] = client
	s.mu.Unlock()
	conn.SetDeadline(time.Time{})
	client.username = username
	joined = client
	s.join <- client
	go func() {
		for {
			select {
			case packet := <-client.outgoing:
				conn.Write(packet)
			case <-client.done:
				return
			}
		}
	}()
	welcomeText, _ := client.encrypt([]byte(fmt.Sprintf("Welcome to the chat, %s!", client.username)))
	conn.Write(s.createObfuscatedPacket(0x01, welcomeText))
	helpText, _ := client.encrypt([]byte("Type /help for available commands. Type /quit to exit.\n"))
	conn.Write(s.createObfuscatedPacket(0x01, helpText))
	for {
		packet, err := readObfuscatedPacket(conn)
		if err != nil {
			if strings.Contains(err.Error(), "oversized packet dropped") {
				s.logger.Printf("Dropped oversized packet from %s", s.member(client))
				continue
			}
			s.logMeta("Connection error from %s: %v", client.username, err)
			break
		}
		client.mu.Lock()
    	client.lastActive = time.Now()
    	client.mu.Unlock()
		
		if packet.Type == 0x02 {
			continue
		}
		if packet.Type == 0x03 {
			s.handleFileData(client, packet.Data)
			continue
		}
		textBytes, err := client.decrypt(packet.Data)
		if err != nil {
			s.logSecurity("Decryption error from %s: %v", s.member(client), err)
			continue
		}
		text := strings.TrimSpace(string(textBytes))
		if text == "" {
			continue
		}
		if text == "/quit" {
			break
		}
		if strings.HasPrefix(text, "/") {
			handled := s.handleCommand(client, text)
			if handled {
				continue
			}
		}
		// Parse optional [#roomname] routing prefix from message
		targetRoom := ""
		cleanText := text
		if strings.HasPrefix(text, "[#") {
			closeBracket := strings.Index(text, "] ")
			if closeBracket != -1 {
				candidate := text[1:closeBracket]
				if strings.HasPrefix(candidate, "#") {
					targetRoom = candidate
					cleanText = text[closeBracket+2:]
				}
			}
		}

		if targetRoom == "" {
			msg := fmt.Sprintf("[%s] %s: %s", time.Now().Format("15:04:05"), client.username, cleanText)
			s.broadcastToLobby(msg)
		} else {
			client.mu.Lock()
			isMember := client.rooms[targetRoom]
			client.mu.Unlock()

			if !isMember {
				s.sendToClient(client, fmt.Sprintf("*** You are not a member of %s ***", targetRoom))
				continue
			}

			s.roomsMu.RLock()
			room, exists := s.rooms[targetRoom]
			s.roomsMu.RUnlock()

			if !exists {
				s.sendToClient(client, fmt.Sprintf("*** Room %s does not exist ***", targetRoom))
				continue
			}

			msg := fmt.Sprintf("[%s] [%s] %s: %s", time.Now().Format("15:04:05"), targetRoom, client.username, cleanText)
			s.broadcastToRoom(room, msg)
		}
	}
	s.leave <- client
}

func (s *Server) handleCommand(client *Client, text string) bool {
	parts := strings.Fields(text)
	if len(parts) == 0 {
		return false
	}
	command := strings.ToLower(parts[0])
	switch command {
	case "/help":
		s.sendHelp(client)
		return true
	case "/msg":
		s.handlePrivateMessage(client, parts)
		return true
	case "/join":
		return s.handleJoinRoom(client, parts)
	case "/leave":
		return s.handleLeaveRoom(client, parts)
	case "/rooms":
		s.handleListRooms(client)
		return true
	case "/users":
		s.handleListUsers(client)
		return true
	case "/members":
		s.handleListMembers(client, parts)
		return true
	case "/file":
		s.handleFileTransferInit(client, parts)
		return true
	case "/accept":
		s.handleFileAccept(client, parts)
		return true
	case "/decline":
		s.handleFileDecline(client, parts)
		return true
	default:
		s.sendToClient(client, fmt.Sprintf("Unknown command: %s. Type /help for available commands.", command))
		return true
	}
}

func (s *Server) sendHelp(client *Client) {
	help := `
Available Commands:
  /help           				- Show this help message
  /msg <user> <msg> 			- Send private message to a user
  /join <#room> [pw] 			- Join a chat room (with optional password)
  /leave <#room>    			- Leave a chat room
  /rooms          				- List all available rooms
  /users            			- List all users currently online
  /members <#room|lobby> 		- List members of a room or the lobby
  /file <user> <path/filename> 	- Send file to a user
  /accept <id>      			- Accept incoming file transfer
  /decline <id>     			- Decline incoming file transfer
  /quit             			- Disconnect from server

Room names must start with # (e.g., #general, #random)
Private messages are not logged and only sent if recipient is online.
File transfers require both parties to be online and recipient must accept.
For /file command, specify only the filename (e.g., document.pdf), not full path.
`
	s.sendToClient(client, help)
}

func (s *Server) handlePrivateMessage(client *Client, parts []string) {
	if len(parts) < 3 {
		s.sendToClient(client, "Usage: /msg <username> <message>")
		return
	}
	targetUser := parts[1]
	message := strings.Join(parts[2:], " ")
	s.mu.RLock()
	targetClient, exists := s.usernames[targetUser]
	s.mu.RUnlock()
	if !exists {
		s.sendToClient(client, fmt.Sprintf("User '%s' is not online.", targetUser))
		return
	}
	dmMsg := fmt.Sprintf("[DM from %s]: %s", client.username, message)
	s.sendToClient(targetClient, dmMsg)
	s.sendToClient(client, fmt.Sprintf("[DM to %s]: %s", targetUser, message))
	s.logMeta("DM: %s -> %s", client.username, targetUser)
}

func (s *Server) handleJoinRoom(client *Client, parts []string) bool {
	if len(parts) < 2 {
		s.sendToClient(client, "Usage: /join <#room> [password]")
		return true
	}
	roomName := parts[1]
	if !strings.HasPrefix(roomName, "#") {
		s.sendToClient(client, "Room names must start with # (e.g., #general)")
		return true
	}
	if !validRoomName(roomName) {
		s.sendToClient(client, fmt.Sprintf("Invalid room name. Use # followed by 1-%d letters, digits, '_', '-' or '.' (e.g., #general)", maxRoomNameLength))
		return true
	}

	password := ""
	if len(parts) > 2 {
		password = strings.TrimSpace(strings.Join(parts[2:], " "))
	}

	s.roomsMu.Lock()
	room, exists := s.rooms[roomName]
	if !exists {
		room = &Room{
			name:    roomName,
			members: make(map[*Client]bool),
		}

		if password != "" {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				s.roomsMu.Unlock()
				s.sendToClient(client, "Error creating room password.")
				return true
			}
			room.passwordHash = string(hashedPassword)
		}

		s.rooms[roomName] = room
		s.sendToClient(client, fmt.Sprintf("Created and joined room %s", roomName))
	} else {
		if room.passwordHash != "" {
			if password == "" {
				s.roomsMu.Unlock()
				s.sendToClient(client, "This room is password-protected. Usage: /join "+roomName+" <password>")
				return true
			}

			err := bcrypt.CompareHashAndPassword([]byte(room.passwordHash), []byte(password))
			if err != nil {
				s.roomsMu.Unlock()
				s.sendToClient(client, "Incorrect password for room "+roomName)
				return true
			}
		}
		s.sendToClient(client, fmt.Sprintf("Joined room %s", roomName))
	}

	room.mu.Lock()
	room.members[client] = true
	room.mu.Unlock()
	client.mu.Lock()
	client.rooms[roomName] = true
	client.currentRoom = roomName
	client.mu.Unlock()
	s.roomsMu.Unlock()
	s.broadcastToRoom(room, fmt.Sprintf("*** %s joined %s ***", client.username, roomName))
	return true
}

const maxRoomNameLength = 32

// validRoomName accepts "#" followed by 1-32 ASCII letters, digits, '_', '-' or '.'.
func validRoomName(name string) bool {
	if !strings.HasPrefix(name, "#") {
		return false
	}
	body := name[1:]
	if len(body) == 0 || len(body) > maxRoomNameLength {
		return false
	}
	for _, ch := range body {
		ok := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.'
		if !ok {
			return false
		}
	}
	return true
}

func (s *Server) handleLeaveRoom(client *Client, parts []string) bool {
	if len(parts) < 2 {
		s.sendToClient(client, "Usage: /leave <#room>")
		return true
	}
	roomName := parts[1]
	s.roomsMu.RLock()
	room, exists := s.rooms[roomName]
	s.roomsMu.RUnlock()
	client.mu.Lock()
	isMember := client.rooms[roomName]
	client.mu.Unlock()
	if !exists || !isMember {
		s.sendToClient(client, fmt.Sprintf("You are not in room %s", roomName))
		return true
	}
	room.mu.Lock()
	delete(room.members, client)
	room.mu.Unlock()
	client.mu.Lock()
	delete(client.rooms, roomName)
	if client.currentRoom == roomName {
		client.currentRoom = ""
	}
	client.mu.Unlock()
	s.sendToClient(client, fmt.Sprintf("Left room %s - returned to lobby", roomName))
	s.broadcastToRoom(room, fmt.Sprintf("*** %s left %s ***", client.username, roomName))
	return true
}

func (s *Server) handleListRooms(client *Client) {
	s.roomsMu.RLock()
	defer s.roomsMu.RUnlock()
	if len(s.rooms) == 0 {
		s.sendToClient(client, "No active rooms. Use /join #roomname to create one.")
		return
	}
	var roomList strings.Builder
	roomList.WriteString("Active Rooms:\n")
	for name, room := range s.rooms {
		room.mu.RLock()
		memberCount := len(room.members)
		locked := ""
		if room.passwordHash != "" {
			locked = " 🔒"
		}
		room.mu.RUnlock()
		roomList.WriteString(fmt.Sprintf("  %s%s (%d users)\n", name, locked, memberCount))
	}
	s.sendToClient(client, roomList.String())
}

func (s *Server) handleListUsers(client *Client) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var names []string
	for c := range s.clients {
		names = append(names, c.username)
	}

	msg := fmt.Sprintf("Online Users (%d):\n  %s", len(names), strings.Join(names, "\n  "))
	s.sendToClient(client, msg)
}

func (s *Server) handleListMembers(client *Client, parts []string) {
	if len(parts) < 2 {
		s.sendToClient(client, "Usage: /members <#roomname|lobby>")
		return
	}

	target := strings.ToLower(parts[1])

	// Lobby members
	if target == "lobby" {
		s.mu.RLock()
		defer s.mu.RUnlock()
		var names []string
		for c := range s.clients {
			c.mu.Lock()
			inNoRooms := len(c.rooms) == 0
			c.mu.Unlock()
			if inNoRooms {
				names = append(names, c.username)
			}
		}
		msg := fmt.Sprintf("Members of lobby (%d):\n  %s", len(names), strings.Join(names, "\n  "))
		s.sendToClient(client, msg)
		return
	}

	// Room members
	roomName := parts[1] // preserve original case for room lookup
	if !strings.HasPrefix(roomName, "#") {
		s.sendToClient(client, "Usage: /members <#roomname|lobby>")
		return
	}

	s.roomsMu.RLock()
	room, exists := s.rooms[roomName]
	s.roomsMu.RUnlock()

	if !exists {
		s.sendToClient(client, "Room not found or access denied.")
		return
	}

	// Password-protected room — check membership
	room.mu.RLock()
	isPasswordProtected := room.passwordHash != ""
	room.mu.RUnlock()

	if isPasswordProtected {
		client.mu.Lock()
		isMember := client.rooms[roomName]
		client.mu.Unlock()
		if !isMember {
			// Do not confirm room exists
			s.sendToClient(client, "Room not found or access denied.")
			return
		}
	}

	room.mu.RLock()
	var names []string
	for member := range room.members {
		names = append(names, member.username)
	}
	room.mu.RUnlock()

	msg := fmt.Sprintf("Members of %s (%d):\n  %s", roomName, len(names), strings.Join(names, "\n  "))
	s.sendToClient(client, msg)
}

func (s *Server) handleFileTransferInit(client *Client, parts []string) {
	if len(parts) < 4 {
		s.sendToClient(client, "Usage: /file <username> <path/filename>")
		return
	}
	targetUser := parts[1]
	filename := parts[2]
	expectedHash := parts[3]

	baseFilename := filepath.Base(filename)

	s.mu.RLock()
	targetClient, exists := s.usernames[targetUser]
	s.mu.RUnlock()
	if !exists {
		s.sendToClient(client, fmt.Sprintf("User '%s' is not online.", targetUser))
		return
	}
	if targetClient == client {
		s.sendToClient(client, "You cannot send files to yourself.")
		return
	}

	if len(expectedHash) != 64 {
		s.sendToClient(client, "Invalid hash format. SHA-256 hash must be 64 hex characters.")
		return
	}
	if _, err := hex.DecodeString(expectedHash); err != nil {
		s.sendToClient(client, "Invalid hash format. Must be valid hexadecimal.")
		return
	}

	transferID := fmt.Sprintf("%s_%s_%d", client.username, targetUser, time.Now().UnixNano())
	transfer := &FileTransfer{
		sender:       client,
		recipient:    targetClient,
		filename:     baseFilename,
		accepted:     false,
		data:         make(chan []byte, 100),
		done:         make(chan bool),
		expectedHash: expectedHash,
	}
	s.transfersMu.Lock()
	s.fileTransfers[transferID] = transfer
	s.transfersMu.Unlock()

	recipientMsg := fmt.Sprintf(
		"*** FILE TRANSFER REQUEST ***\n"+
			"Sender: %s\n"+
			"File: %s\n"+
			"SHA-256: %s\n"+
			"Transfer ID: %s\n"+
			"\n"+
			"To accept, type: /accept %s\n"+
			"To decline, type: /decline %s",
		client.username, baseFilename, expectedHash, transferID, transferID, transferID)
	s.sendToClient(targetClient, recipientMsg)
	senderMsg := fmt.Sprintf(
		"*** File transfer request sent to %s ***\n"+
			"Transfer ID: %s\n"+
			"Waiting for recipient to accept...",
		targetUser, transferID)
	s.sendToClient(client, senderMsg)

	s.logMeta("File transfer initiated: %s -> %s (File: %s, ID: %s)", client.username, targetUser, baseFilename, transferID)

	go func() {
		time.Sleep(5 * time.Minute)
		s.transfersMu.Lock()
		if transfer, exists := s.fileTransfers[transferID]; exists {
			if !transfer.accepted {
				delete(s.fileTransfers, transferID)
				s.sendToClient(client, "*** File transfer expired (not accepted within 5 minutes). ***")
			}
		}
		s.transfersMu.Unlock()
	}()
}

func (s *Server) handleFileAccept(client *Client, parts []string) {
	if len(parts) < 2 {
		s.sendToClient(client, "Usage: /accept <transfer_id>")
		return
	}
	transferID := parts[1]
	s.transfersMu.RLock()
	transfer, exists := s.fileTransfers[transferID]
	s.transfersMu.RUnlock()
	if !exists {
		s.sendToClient(client, "Transfer ID not found or expired.")
		return
	}
	if transfer.recipient != client {
		s.sendToClient(client, "This transfer is not for you.")
		return
	}

	// Check if sender is still online
	s.mu.RLock()
	_, senderOnline := s.clients[transfer.sender]
	s.mu.RUnlock()
	if !senderOnline {
		s.sendToClient(client, "*** Error: Sender is no longer online. Transfer cancelled. ***")
		s.transfersMu.Lock()
		delete(s.fileTransfers, transferID)
		s.transfersMu.Unlock()
		return
	}

	s.transfersMu.Lock() // read under the lock by the sender's handleFileData
	transfer.accepted = true
	s.transfersMu.Unlock()
	s.sendToClient(client, "*** File transfer accepted. Waiting for file stream... ***")
	confirmMsg := fmt.Sprintf("*** %s accepted your file transfer (ID: %s). ***", client.username, transferID)
	s.sendToClient(transfer.sender, confirmMsg)
	time.Sleep(100 * time.Millisecond)

	beginMsg := fmt.Sprintf("BEGIN_SEND|%s|%s", transfer.filename, transfer.expectedHash)
	encrypted, err := transfer.sender.encrypt([]byte(beginMsg))
	if err != nil {
		s.logger.Printf("Error encrypting BEGIN_SEND: %v", err)
		return
	}
	packet := s.createObfuscatedPacket(0x01, encrypted)
	transfer.sender.send(packet)
	s.logMeta("File transfer accepted: %s -> %s (ID: %s)", transfer.sender.username, transfer.recipient.username, transferID)

	go func(id string) {
		time.Sleep(10 * time.Minute)
		s.transfersMu.Lock()
		if _, stillExists := s.fileTransfers[id]; stillExists {
			delete(s.fileTransfers, id)
			s.sendToClient(transfer.sender, "*** File transfer timed out after 10 minutes ***")
			s.sendToClient(transfer.recipient, "*** File transfer timed out ***")
		}
		s.transfersMu.Unlock()
	}(transferID)
}

func (s *Server) handleFileDecline(client *Client, parts []string) {
	if len(parts) < 2 {
		s.sendToClient(client, "Usage: /decline <transfer_id>")
		return
	}
	transferID := parts[1]
	// Only the recipient may decline: check before removing the transfer,
	// so other members cannot cancel transfers that are not theirs.
	s.transfersMu.Lock()
	transfer, exists := s.fileTransfers[transferID]
	forOther := exists && transfer.recipient != client
	if exists && !forOther {
		delete(s.fileTransfers, transferID)
	}
	s.transfersMu.Unlock()
	if !exists {
		s.sendToClient(client, "Transfer ID not found or expired.")
		return
	}
	if forOther {
		s.sendToClient(client, "This transfer is not for you.")
		return
	}
	s.sendToClient(client, "*** File transfer declined. ***")
	s.sendToClient(transfer.sender, fmt.Sprintf("*** %s declined the file transfer (ID: %s). ***", client.username, transferID))
	s.logMeta("File transfer declined: %s -> %s (ID: %s)", transfer.sender.username, transfer.recipient.username, transferID)
}

func (s *Server) sendToClient(client *Client, message string) {
	encrypted, err := client.encrypt([]byte(message))
	if err != nil {
		return
	}
	packet := s.createObfuscatedPacket(0x01, encrypted)
	client.send(packet)
}

func (s *Server) broadcastToRoom(room *Room, message string) {
	room.mu.RLock()
	defer room.mu.RUnlock()
	for client := range room.members {
		s.sendToClient(client, message)
	}
}

func (s *Server) handleFileData(client *Client, encryptedData []byte) {
	data, err := client.decrypt(encryptedData)
	if err != nil {
		return
	}
	dataStr := string(data)
	if strings.HasPrefix(dataStr, "FILE_START|") {
		parts := strings.Split(dataStr, "|")
		if len(parts) == 3 {
			filename := filepath.Base(parts[1])
			filesizeStr := parts[2]
			s.transfersMu.RLock()
			var activeTransfer *FileTransfer
			for _, transfer := range s.fileTransfers {
				if transfer.sender == client && transfer.accepted {
					activeTransfer = transfer
					break
				}
			}
			s.transfersMu.RUnlock()
			if activeTransfer != nil {
				activeTransfer.filename = filename
				size, err := strconv.ParseInt(filesizeStr, 10, 64)
				if err != nil || size <= 0 {
					s.sendToClient(client, "*** File transfer cancelled: invalid file size ***")
					s.transfersMu.Lock()
					for id, t := range s.fileTransfers {
						if t == activeTransfer {
							delete(s.fileTransfers, id)
							break
						}
					}
					s.transfersMu.Unlock()
					return
				}
				activeTransfer.filesize = size
				msg := fmt.Sprintf("FILE_START|%s|%s|%s", filename, filesizeStr, activeTransfer.expectedHash)
				encrypted, _ := activeTransfer.recipient.encrypt([]byte(msg))
				packet := s.createObfuscatedPacket(0x03, encrypted)
				activeTransfer.recipient.sendWait(packet, fileDataTimeout)
				s.logMeta("File transfer stream started: %s -> %s (%s, %s bytes)", client.username, activeTransfer.recipient.username, filename, filesizeStr)
			}
		}
		return
	}
	if dataStr == "FILE_END" {
		// Find and remove the transfer under the lock, then send without it,
		// so a slow recipient never stalls other transfers.
		var finished *FileTransfer
		s.transfersMu.Lock()
		for id, transfer := range s.fileTransfers {
			if transfer.sender == client {
				finished = transfer
				delete(s.fileTransfers, id)
				break
			}
		}
		s.transfersMu.Unlock()
		if finished != nil {
			encrypted, _ := finished.recipient.encrypt([]byte("FILE_END"))
			packet := s.createObfuscatedPacket(0x03, encrypted)
			finished.recipient.sendWait(packet, fileDataTimeout)
			s.sendToClient(finished.sender, "*** File transfer stream completed. ***")
			s.sendToClient(finished.recipient, "*** File transfer stream completed. Check hash! ***")
			s.logMeta("File transfer completed: %s -> %s", client.username, finished.recipient.username)
		}
		return
	}
	s.transfersMu.RLock()
	var activeTransfer *FileTransfer
	for _, transfer := range s.fileTransfers {
		if transfer.sender == client && transfer.accepted {
			activeTransfer = transfer
			break
		}
	}
	s.transfersMu.RUnlock()
	if activeTransfer != nil {
		encrypted, err := activeTransfer.recipient.encrypt(data)
		if err != nil {
			return
		}
		packet := s.createObfuscatedPacket(0x03, encrypted)
		activeTransfer.recipient.sendWait(packet, fileDataTimeout)
	}
}

func (s *Server) Shutdown() {
	fmt.Println("\n✓ Shutting down server gracefully...")

	close(s.shutdown)

	if s.listener != nil {
		s.listener.Close()
	}

	s.mu.Lock()
	for client := range s.clients {
		s.sendToClient(client, "*** Server is shutting down. Goodbye! ***")
		client.conn.Close()
	}
	s.mu.Unlock()

	s.wg.Wait()

	s.logger.Println("Server shutdown completed")
	s.logSecurity("Server shutdown completed")
	fmt.Println("✓ Server stopped")
}

func (s *Server) startIdleChecker() {
    go func() {
        ticker := time.NewTicker(60 * time.Second)
        defer ticker.Stop()
        for {
            select {
            case <-s.shutdown:
                return
            case <-ticker.C:
                if dropped := s.limiter.sweep(); dropped > 0 {
                    s.logSecurity("Refused %d connection(s) over connection limits in the last minute", dropped)
                }
                s.mu.RLock()
                stale := []*Client{}
                for client := range s.clients {
                    client.mu.Lock()
                    idle := time.Since(client.lastActive)
                    client.mu.Unlock()
                    if idle > 3*time.Minute {
                        stale = append(stale, client)
                    }
                }
                s.mu.RUnlock()

                for _, client := range stale {
                    s.logSecurity(
                        "Closing stale connection for %s (idle %.0fs)",
                        s.member(client),
                        time.Since(client.lastActive).Seconds(),
                    )
                    client.conn.Close()
                }
            }
        }
    }()
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

	go server.run()
	server.startIdleChecker()

	tlsConfig := &tls.Config{
		Certificates:          []tls.Certificate{server.tlsCert},
		MinVersion:            tls.VersionTLS13,
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: server.verifyAccessCert,
	}

	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", server.config.Port), tlsConfig)
	if err != nil {
		fmt.Println("Error starting TLS server:", err)
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

	fmt.Printf("✓ Encrypted chat server started on port %d (TLS enabled)\n", server.config.Port)
	fmt.Printf("✓ Logging to: %s\n", server.config.LogFile)
	fmt.Printf("✓ Security logging to: %s\n", server.config.SecurityLogFile)
	if server.config.LogMetadata {
		fmt.Println("⚠ Metadata logging is ON: logs record participants, DMs, file transfers and IP addresses")
	} else {
		fmt.Println("✓ Metadata logging off: logs contain no participant information")
	}
	if server.config.DecoyTraffic {
		fmt.Printf("✓ Decoy traffic enabled (interval: %ds)\n", server.config.DecoyInterval)
	}
	fmt.Println("✓ Full TLS transport security active")
	fmt.Println("✓ Traffic obfuscation active (TLS-like)")
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
		if tlsConn, ok := conn.(*tls.Conn); ok {
			if tcpConn, ok := tlsConn.NetConn().(*net.TCPConn); ok {
				tcpConn.SetKeepAlive(true)
				tcpConn.SetKeepAlivePeriod(30 * time.Second)
			}
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
			defer server.limiter.release(host)
			server.handleClient(conn)
		}(conn, host)
	}
}
