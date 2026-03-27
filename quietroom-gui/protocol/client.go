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

package protocol

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// RFC 3526 2048-bit MODP group
const dhPHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"

// Packet type constants
const (
	PktMessage  = 0x01
	PktDecoy    = 0x02
	PktFile     = 0x03
	MaxDataSize = 32768
)

// Event types emitted to the app layer
type EventType string

const (
	EvtMessage          EventType = "message"
	EvtUserJoined       EventType = "user_joined"
	EvtUserLeft         EventType = "user_left"
	EvtRoomJoined       EventType = "room_joined"
	EvtRoomLeft         EventType = "room_left"
	EvtPrivateMessage   EventType = "private_message"
	EvtFileRequest      EventType = "file_request"
	EvtFileStart        EventType = "file_start"
	EvtFileChunk        EventType = "file_chunk"
	EvtFileEnd          EventType = "file_end"
	EvtFileBeginSend    EventType = "file_begin_send"
	EvtSystemMessage    EventType = "system_message"
	EvtConnected        EventType = "connected"
	EvtDisconnected     EventType = "disconnected"
	EvtLoginPrompt      EventType = "login_prompt"
	EvtError            EventType = "error"
)

// Event carries a parsed server event to the app layer
type Event struct {
	Type    EventType
	Room    string // populated for room-scoped events
	Sender  string // for messages and DMs
	Text    string // message body or system text
	Payload interface{} // type-specific data
}

// FileRequestPayload carries file transfer request details
type FileRequestPayload struct {
	TransferID   string
	Filename     string
	ExpectedHash string
	SenderName   string
}

// FileStartPayload carries file transfer metadata
type FileStartPayload struct {
	Filename     string
	Filesize     int64
	ExpectedHash string
}

// EventHandler is called for every inbound event
type EventHandler func(Event)

// DHParams holds the Diffie-Hellman group parameters
type DHParams struct {
	P *big.Int
	G *big.Int
}

func initDHParams() *DHParams {
	p := new(big.Int)
	p.SetString(dhPHex, 16)
	return &DHParams{P: p, G: big.NewInt(2)}
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

// Client manages a single connection to a QuietRoom server
type Client struct {
	conn       net.Conn
	gcm        cipher.AEAD
	sessionKey []byte
	dhParams   *DHParams

	sendMu   sync.Mutex
	handler  EventHandler
	shutdown chan struct{}
	once     sync.Once

	username    string
	currentRoom string
}

// NewClient creates a new unconnected client
func NewClient(handler EventHandler) *Client {
	return &Client{
		dhParams: initDHParams(),
		handler:  handler,
		shutdown: make(chan struct{}),
	}
}

// Connect establishes a TLS connection, performs DH exchange, and logs in
func (c *Client) Connect(host string, port int, certFile string, username string) error {
	c.username = username

	// Load pinned certificate
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read cert file: %w", err)
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	// Parse the pinned cert for byte comparison
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block from cert file")
	}
	pinnedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse pinned certificate: %w", err)
	}

	// Extract RSA public key from pinned cert for DH signature verification
	rsaPubKey, ok := pinnedCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate does not contain an RSA public key")
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no peer certificate")
			}
			peerCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("failed to parse peer certificate: %w", err)
			}
			if peerCert.Raw == nil || pinnedCert.Raw == nil {
				return fmt.Errorf("certificate comparison failed")
			}
			if string(peerCert.Raw) != string(pinnedCert.Raw) {
				return fmt.Errorf("certificate does not match pinned certificate — possible MITM attack")
			}
			return nil
		},
		MinVersion: tls.VersionTLS13,
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS connection failed: %w", err)
	}
	c.conn = conn

	// DH key exchange
	if err := c.performDHExchange(rsaPubKey); err != nil {
		conn.Close()
		return err
	}

	// Login
	if err := c.login(username); err != nil {
		conn.Close()
		return err
	}

	// Start receive loop
	go c.receiveLoop()

	c.handler(Event{Type: EvtConnected, Text: addr})
	return nil
}

func (c *Client) performDHExchange(rsaPubKey *rsa.PublicKey) error {
	// Read server DH public key length
	var serverDHPubLen uint32
	if err := binary.Read(c.conn, binary.BigEndian, &serverDHPubLen); err != nil {
		return fmt.Errorf("failed to read server DH pub len: %w", err)
	}
	if serverDHPubLen > 4096 {
		return fmt.Errorf("server DH key too large: %d", serverDHPubLen)
	}

	serverDHPubBytes := make([]byte, serverDHPubLen)
	if _, err := io.ReadFull(c.conn, serverDHPubBytes); err != nil {
		return fmt.Errorf("failed to read server DH pub: %w", err)
	}

	// Read signature
	var sigLen uint32
	if err := binary.Read(c.conn, binary.BigEndian, &sigLen); err != nil {
		return fmt.Errorf("failed to read signature length: %w", err)
	}
	if sigLen > 4096 {
		return fmt.Errorf("signature too large: %d", sigLen)
	}

	signature := make([]byte, sigLen)
	if _, err := io.ReadFull(c.conn, signature); err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}

	// Verify RSA-PSS signature
	hash := sha256Hash(serverDHPubBytes)
	if err := rsa.VerifyPSS(rsaPubKey, crypto.SHA256, hash, signature, nil); err != nil {
		return fmt.Errorf("server authentication failed: %w", err)
	}

	// Validate server DH public key — small subgroup attack prevention
	serverDHPub := new(big.Int).SetBytes(serverDHPubBytes)
	one := big.NewInt(1)
	pMinusOne := new(big.Int).Sub(c.dhParams.P, one)
	if serverDHPub.Cmp(one) <= 0 || serverDHPub.Cmp(pMinusOne) >= 0 {
		return fmt.Errorf("invalid server DH public key")
	}

	// Generate our keypair
	dhPrivate, dhPublic, err := generateDHKeyPair(c.dhParams)
	if err != nil {
		return fmt.Errorf("failed to generate DH keypair: %w", err)
	}

	// Send our public key
	dhPubBytes := dhPublic.Bytes()
	dhPubLen := make([]byte, 4)
	binary.BigEndian.PutUint32(dhPubLen, uint32(len(dhPubBytes)))
	c.conn.Write(dhPubLen)
	c.conn.Write(dhPubBytes)

	// Compute shared secret and set up AES-GCM
	sharedSecret := computeDHSharedSecret(dhPrivate, serverDHPub, c.dhParams.P)
	c.sessionKey = sharedSecret

	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}
	c.gcm = gcm
	return nil
}

func (c *Client) login(username string) error {
	// Read the "Enter your username:" prompt
	packet, err := c.readPacket()
	if err != nil {
		return fmt.Errorf("failed to read login prompt: %w", err)
	}
	_, err = c.decrypt(packet.Data)
	if err != nil {
		return fmt.Errorf("failed to decrypt login prompt: %w", err)
	}

	// Send username
	if err := c.SendText(username); err != nil {
		return fmt.Errorf("failed to send username: %w", err)
	}

	// Read welcome
	packet, err = c.readPacket()
	if err != nil {
		return fmt.Errorf("failed to read welcome: %w", err)
	}
	welcomeText, err := c.decrypt(packet.Data)
	if err != nil {
		return fmt.Errorf("failed to decrypt welcome: %w", err)
	}

	// Check for username taken error
	if strings.Contains(string(welcomeText), "already taken") {
		c.conn.Close()
		return fmt.Errorf("%s", strings.TrimSpace(string(welcomeText)))
	}

	// Read help text
	_, err = c.readPacket()
	if err != nil {
		return fmt.Errorf("failed to read help text: %w", err)
	}

	return nil
}

// Disconnect cleanly disconnects from the server
func (c *Client) Disconnect() {
	c.once.Do(func() {
		c.SendText("/quit")
		close(c.shutdown)
		if c.conn != nil {
			c.conn.Close()
		}
	})
}

// SendText sends an encrypted text message
func (c *Client) SendText(text string) error {
	encrypted, err := c.encrypt([]byte(text))
	if err != nil {
		return err
	}
	packet := c.makePacket(PktMessage, encrypted)
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	_, err = c.conn.Write(packet)
	return err
}

// SendDecoy sends a random decoy packet
func (c *Client) SendDecoy(size int) error {
	data := make([]byte, size)
	rand.Read(data)
	packet := c.makePacket(PktDecoy, data)
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	_, err := c.conn.Write(packet)
	return err
}

// IsConnected returns true if the connection is active
func (c *Client) IsConnected() bool {
	select {
	case <-c.shutdown:
		return false
	default:
		return c.conn != nil
	}
}

// --- Packet framing ---

type packet struct {
	Type byte
	Data []byte
}

func (c *Client) makePacket(msgType byte, data []byte) []byte {
	paddingSize, _ := rand.Int(rand.Reader, big.NewInt(256))
	padding := make([]byte, paddingSize.Int64())
	rand.Read(padding)

	pkt := make([]byte, 3+len(data)+len(padding))
	pkt[0] = msgType
	binary.BigEndian.PutUint16(pkt[1:3], uint16(len(data)))
	copy(pkt[3:], data)
	copy(pkt[3+len(data):], padding)
	return pkt
}

func (c *Client) readPacket() (*packet, error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return nil, err
	}

	msgType := header[0]
	dataLen := binary.BigEndian.Uint16(header[1:3])

	if dataLen > MaxDataSize {
		// Drain and discard
		dummy := make([]byte, dataLen)
		io.ReadFull(c.conn, dummy)
		return nil, fmt.Errorf("oversized packet dropped (%d bytes)", dataLen)
	}

	data := make([]byte, dataLen)
	if _, err := io.ReadFull(c.conn, data); err != nil {
		return nil, err
	}

	// Drain padding
	c.conn.SetDeadline(time.Now().Add(10 * time.Millisecond))
	padding := make([]byte, 1024)
	c.conn.Read(padding)
	c.conn.SetDeadline(time.Time{})

	return &packet{Type: msgType, Data: data}, nil
}

// --- Encryption ---

func (c *Client) encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return c.gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (c *Client) decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := c.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return c.gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
}

// --- Receive loop ---

func (c *Client) receiveLoop() {
	defer func() {
		c.handler(Event{Type: EvtDisconnected})
	}()

	for {
		select {
		case <-c.shutdown:
			return
		default:
		}

		pkt, err := c.readPacket()
		if err != nil {
			select {
			case <-c.shutdown:
				return
			default:
				if strings.Contains(err.Error(), "oversized packet dropped") {
					continue
				}
				c.handler(Event{Type: EvtError, Text: err.Error()})
				return
			}
		}

		switch pkt.Type {
		case PktDecoy:
			// ignore
		case PktFile:
			data, err := c.decrypt(pkt.Data)
			if err != nil {
				continue
			}
			c.dispatchFileEvent(data)
		case PktMessage:
			data, err := c.decrypt(pkt.Data)
			if err != nil {
				continue
			}
			c.dispatchMessageEvent(string(data))
		}
	}
}
