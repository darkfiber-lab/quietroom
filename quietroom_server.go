/*
Copyright (C) 2025 darkfiber-lab

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
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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
}

type Client struct {
	conn        net.Conn
	username    string
	outgoing    chan []byte
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

func loadConfig() ServerConfig {
	config := ServerConfig{
		Port:            37842,
		LogFile:         "chat_server.log",
		SecurityLogFile: "security.log",
		DecoyTraffic:    true,
		DecoyInterval:   30,
		DecoyMinBytes:   100,
		DecoyMaxBytes:   500,
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
	logFile, err := os.OpenFile(config.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	secLogFile, err := os.OpenFile(config.SecurityLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	logger := log.New(logFile, "", log.LstdFlags)
	securityLogger := log.New(secLogFile, "[SECURITY] ", log.LstdFlags)

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes}
	privFile, err := os.Create("server_private.pem")
	if err != nil {
		return nil, err
	}
	defer privFile.Close()
	if err := pem.Encode(privFile, privateKeyPEM); err != nil {
		return nil, err
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Self-Hosted Chat Server",
			Organization: []string{"Private Chat"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	certPEM := &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	pubFile, err := os.Create("chat_public.pem")
	if err != nil {
		return nil, err
	}
	defer pubFile.Close()
	if err := pem.Encode(pubFile, certPEM); err != nil {
		return nil, err
	}

	fmt.Println("✓ Generated RSA key pair and self-signed TLS certificate")
	fmt.Println("✓ Public certificate saved to: chat_public.pem")
	fmt.Println("⚠ COPY chat_public.pem to client machines before connecting!")

	dhParams := initDHParams()
	fmt.Println("✓ Initialized Diffie-Hellman parameters (2048-bit)")

	server := &Server{
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

func (s *Server) run() {
	for {
		select {
		case <-s.shutdown:
			return
		case client := <-s.join:
			s.mu.Lock()
			s.clients[client] = true
			s.usernames[client.username] = client
			s.mu.Unlock()
			joinMsg := fmt.Sprintf("*** %s joined the chat ***", client.username)
			s.broadcastToLobby(joinMsg)
			s.logger.Printf("User joined: %s from %s", client.username, client.ipAddr)
			s.logSecurity("Successful authentication: %s from %s", client.username, client.ipAddr)
			if s.config.DecoyTraffic {
				go s.sendDecoyTraffic(client)
			}
		case client := <-s.leave:
			s.mu.Lock()
			if s.clients[client] {
				delete(s.clients, client)
				delete(s.usernames, client.username)
				close(client.outgoing)
			}
			s.mu.Unlock()
			s.roomsMu.Lock()
			for roomName := range client.rooms {
				if room, exists := s.rooms[roomName]; exists {
					room.mu.Lock()
					delete(room.members, client)
					room.mu.Unlock()
				}
			}
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
			s.logger.Printf("User left: %s from %s", client.username, client.ipAddr)
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
			select {
			case client.outgoing <- packet:
				client.mu.Lock()
				client.lastActive = time.Now()
				client.mu.Unlock()
			default:
			}
		}
	}
}

func (s *Server) broadcastToLobby(msg string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for client := range s.clients {
		if client.currentRoom == "" {
			encrypted, err := client.encrypt([]byte(msg))
			if err != nil {
				continue
			}
			packet := s.createObfuscatedPacket(0x01, encrypted)
			select {
			case client.outgoing <- packet:
				client.mu.Lock()
				client.lastActive = time.Now()
				client.mu.Unlock()
			default:
			}
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
	s.logger.Printf("New connection attempt from %s", ipAddr)
	dhPrivate, dhPublic, err := generateDHKeyPair(s.dhParams)
	if err != nil {
		s.logSecurity("Failed DH key generation for %s: %v", ipAddr, err)
		return
	}
	dhPubBytes := dhPublic.Bytes()
	signature, err := rsa.SignPSS(rand.Reader, s.privateKey, crypto.SHA256, sha256Hash(dhPubBytes), nil)
	if err != nil {
		s.logSecurity("Failed to sign DH public key for %s: %v", ipAddr, err)
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
		s.logSecurity("Failed to read client DH pub len from %s: %v", ipAddr, err)
		return
	}
	const maxDHPubKeySize = 4096
	if clientDHPubLen > maxDHPubKeySize {
		s.logSecurity("DoS attempt from %s: DH key size %d exceeds maximum %d", ipAddr, clientDHPubLen, maxDHPubKeySize)
		return
	}
	clientDHPubBytes := make([]byte, clientDHPubLen)
	if _, err := io.ReadFull(conn, clientDHPubBytes); err != nil {
		s.logSecurity("Failed to read client DH pub from %s: %v", ipAddr, err)
		return
	}
	clientDHPub := new(big.Int).SetBytes(clientDHPubBytes)
	sharedSecret := computeDHSharedSecret(dhPrivate, clientDHPub, s.dhParams.P)
	s.logSecurity("Diffie-Hellman key exchange completed with %s", ipAddr)
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		s.logSecurity("Failed to create cipher for %s: %v", ipAddr, err)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		s.logSecurity("Failed to create GCM for %s: %v", ipAddr, err)
		return
	}
	client := &Client{
		conn:        conn,
		outgoing:    make(chan []byte, 4096),
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
		s.logSecurity("Failed to read username packet from %s: %v", ipAddr, err)
		return
	}
	usernameEnc := usernamePacket.Data
	usernameBytes, err := client.decrypt(usernameEnc)
	if err != nil {
		s.logSecurity("Failed username decryption from %s: %v", ipAddr, err)
		return
	}
	username := strings.TrimSpace(string(usernameBytes))
	if username == "" {
		s.logSecurity("Empty username from %s", ipAddr)
		return
	}
	const maxUsernameLength = 32
	if len(username) > maxUsernameLength {
		s.logSecurity("Username too long (%d chars) from %s", len(username), ipAddr)
		return
	}
	for _, ch := range username {
		if ch < 32 || ch == 127 {
			s.logSecurity("Username contains control character (0x%02X) from %s", ch, ipAddr)
			return
		}
	}
	if strings.TrimSpace(username) == "" {
		s.logSecurity("Username is all whitespace from %s", ipAddr)
		return
	}
	for _, ch := range username {
		isValid := (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == ' ' || ch == '_' || ch == '-' || ch == '.'
		if !isValid {
			s.logSecurity("Username contains invalid character '%c' (0x%04X) from %s", ch, ch, ipAddr)
			return
		}
	}
	client.username = username
	s.join <- client
	go func() {
		for packet := range client.outgoing {
			conn.Write(packet)
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
				s.logger.Printf("Dropped oversized packet from %s", client.username)
				continue
			}
			s.logger.Printf("Connection error from %s: %v", client.username, err)
			break
		}
		if packet.Type == 0x02 {
			continue
		}
		if packet.Type == 0x03 {
			s.handleFileData(client, packet.Data)
			continue
		}
		textBytes, err := client.decrypt(packet.Data)
		if err != nil {
			s.logSecurity("Decryption error from %s (%s): %v", client.username, ipAddr, err)
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
		msg := fmt.Sprintf("[%s] %s: %s", time.Now().Format("15:04:05"), client.username, text)
		if client.currentRoom == "" {
			s.broadcastToLobby(msg)
		} else {
			s.roomsMu.RLock()
			if room, exists := s.rooms[client.currentRoom]; exists {
				s.broadcastToRoom(room, msg)
			}
			s.roomsMu.RUnlock()
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
  /help           - Show this help message
  /msg <user> <msg> - Send private message to a user
  /join <#room> [pw] - Join a chat room (with optional password)
  /leave <#room>    - Leave a chat room
  /rooms          - List all available rooms
  /users          - List users in current room or online
  /file <user> <filename> <sha256_hash> - Send file to a user (only filename, no paths)
  /accept <id>      - Accept incoming file transfer
  /decline <id>     - Decline incoming file transfer
  /quit           - Disconnect from server

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
	s.logger.Printf("DM: %s -> %s", client.username, targetUser)
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
	client.rooms[roomName] = true
	client.currentRoom = roomName
	s.roomsMu.Unlock()
	s.broadcastToRoom(room, fmt.Sprintf("*** %s joined %s ***", client.username, roomName))
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
	if !exists || !client.rooms[roomName] {
		s.sendToClient(client, fmt.Sprintf("You are not in room %s", roomName))
		return true
	}
	room.mu.Lock()
	delete(room.members, client)
	room.mu.Unlock()
	delete(client.rooms, roomName)
	if client.currentRoom == roomName {
		client.currentRoom = ""
	}
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
	var userList strings.Builder
	if client.currentRoom != "" {
		userList.WriteString(fmt.Sprintf("Users in %s:\n", client.currentRoom))
		s.roomsMu.RLock()
		if room, exists := s.rooms[client.currentRoom]; exists {
			room.mu.RLock()
			for member := range room.members {
				userList.WriteString(fmt.Sprintf("  %s\n", member.username))
			}
			room.mu.RUnlock()
		}
		s.roomsMu.RUnlock()
	} else {
		userList.WriteString("Online Users (Lobby):\n")
		for c := range s.clients {
			if c.currentRoom == "" {
				userList.WriteString(fmt.Sprintf("  %s\n", c.username))
			}
		}
	}
	s.sendToClient(client, userList.String())
}

func (s *Server) handleFileTransferInit(client *Client, parts []string) {
	if len(parts) < 4 {
		s.sendToClient(client, "Usage: /file <username> <filename> <sha256_hash>")
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

	s.logger.Printf("File transfer initiated: %s -> %s (File: %s, ID: %s)", client.username, targetUser, baseFilename, transferID)

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

	transfer.accepted = true
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
	transfer.sender.outgoing <- packet
	s.logger.Printf("File transfer accepted: %s -> %s (ID: %s)", transfer.sender.username, transfer.recipient.username, transferID)

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
	s.transfersMu.Lock()
	transfer, exists := s.fileTransfers[transferID]
	if exists {
		delete(s.fileTransfers, transferID)
	}
	s.transfersMu.Unlock()
	if !exists {
		s.sendToClient(client, "Transfer ID not found or expired.")
		return
	}
	if transfer.recipient != client {
		s.sendToClient(client, "This transfer is not for you.")
		return
	}
	s.sendToClient(client, "*** File transfer declined. ***")
	s.sendToClient(transfer.sender, fmt.Sprintf("*** %s declined the file transfer (ID: %s). ***", client.username, transferID))
	s.logger.Printf("File transfer declined: %s -> %s (ID: %s)", transfer.sender.username, transfer.recipient.username, transferID)
}

func (s *Server) sendToClient(client *Client, message string) {
	encrypted, err := client.encrypt([]byte(message))
	if err != nil {
		return
	}
	packet := s.createObfuscatedPacket(0x01, encrypted)
	select {
	case client.outgoing <- packet:
	default:
	}
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
				fmt.Sscanf(filesizeStr, "%d", &activeTransfer.filesize)
				msg := fmt.Sprintf("FILE_START|%s|%s|%s", filename, filesizeStr, activeTransfer.expectedHash)
				encrypted, _ := activeTransfer.recipient.encrypt([]byte(msg))
				packet := s.createObfuscatedPacket(0x03, encrypted)
				activeTransfer.recipient.outgoing <- packet
				s.logger.Printf("File transfer stream started: %s -> %s (%s, %s bytes)", client.username, activeTransfer.recipient.username, filename, filesizeStr)
			}
		}
		return
	}
	if dataStr == "FILE_END" {
		s.transfersMu.Lock()
		for id, transfer := range s.fileTransfers {
			if transfer.sender == client {
				encrypted, _ := transfer.recipient.encrypt([]byte("FILE_END"))
				packet := s.createObfuscatedPacket(0x03, encrypted)
				transfer.recipient.outgoing <- packet
				s.sendToClient(transfer.sender, "*** File transfer stream completed. ***")
				s.sendToClient(transfer.recipient, "*** File transfer stream completed. Check hash! ***")
				delete(s.fileTransfers, id)
				s.logger.Printf("File transfer completed: %s -> %s", client.username, transfer.recipient.username)
				break
			}
		}
		s.transfersMu.Unlock()
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
		activeTransfer.recipient.outgoing <- packet
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

	cert, err := tls.LoadX509KeyPair("chat_public.pem", "server_private.pem")
	if err != nil {
		fmt.Println("Error loading TLS certificate/key:", err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", server.config.Port), tlsConfig)
	if err != nil {
		fmt.Println("Error starting TLS server:", err)
		return
	}

	server.listener = listener
	defer listener.Close()

	fmt.Printf("✓ Encrypted chat server started on port %d (TLS enabled)\n", server.config.Port)
	fmt.Printf("✓ Logging to: %s\n", server.config.LogFile)
	fmt.Printf("✓ Security logging to: %s\n", server.config.SecurityLogFile)
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
				continue
			}
		}
		server.wg.Add(1)
		go server.handleClient(conn)
	}
}
