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
	"bufio"
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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"
)

type ClientConfig struct {
	Servers           []ServerInfo `json:"servers"`
	Theme             Theme        `json:"theme"`
	DecoyTraffic      bool         `json:"decoy_traffic"`
	DecoyInterval     int          `json:"decoy_interval_seconds"`
	DecoyMinBytes     int          `json:"decoy_min_bytes"`
	DecoyMaxBytes     int          `json:"decoy_max_bytes"`
	SoundNotification bool         `json:"sound_notification"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type Theme struct {
	SystemColor    string `json:"system_color"`
	UsernameColor  string `json:"username_color"`
	MessageColor   string `json:"message_color"`
	TimestampColor string `json:"timestamp_color"`
	ErrorColor     string `json:"error_color"`
}

type Client struct {
	conn       net.Conn
	sessionKey []byte
	gcm        cipher.AEAD
	config     ClientConfig
	mu         sync.Mutex
	stopDecoy  chan bool
	username   string
	shutdown   chan bool

	pendingTransfer *FileTransferState
	transferMu      sync.Mutex

	lastSentMsg string
	lastSentMu  sync.Mutex

	// Input handling
	inputBuffer string
	inputMu     sync.Mutex
	promptText  string
}

type FileTransferState struct {
	transferID  string
	filename    string
	filesize    int64
	isReceiving bool
	progress    int64
}

type DHParams struct {
	P *big.Int
	G *big.Int
}

type ObfuscatedPacket struct {
	Type byte
	Data []byte
}

var colors = map[string]string{
	"reset":          "\033[0m",
	"red":            "\033[31m",
	"green":          "\033[32m",
	"yellow":         "\033[33m",
	"blue":           "\033[34m",
	"magenta":        "\033[35m",
	"cyan":           "\033[36m",
	"white":          "\033[37m",
	"gray":           "\033[90m",
	"bright_red":     "\033[91m",
	"bright_green":   "\033[92m",
	"bright_yellow":  "\033[93m",
	"bright_blue":    "\033[94m",
	"bright_magenta": "\033[95m",
	"bright_cyan":    "\033[96m",
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

func (c *Client) colorize(color, text string) string {
	if code, ok := colors[color]; ok {
		return code + text + colors["reset"]
	}
	return text
}

func (c *Client) clearScreen() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

func (c *Client) printSeparator() {
	fmt.Println(c.colorize("gray", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
}

func (c *Client) playNotificationSound() {
	if !c.config.SoundNotification {
		return
	}

	go func() {
		if runtime.GOOS == "windows" {
			fmt.Print("\a")
		} else if runtime.GOOS == "darwin" {
			exec.Command("afplay", "/System/Library/Sounds/Ping.aiff").Run()
		} else {
			if err := exec.Command("paplay", "/usr/share/sounds/freedesktop/stereo/message.oga").Run(); err == nil {
				return
			}
			if err := exec.Command("aplay", "/usr/share/sounds/alsa/Front_Center.wav").Run(); err == nil {
				return
			}
			cmd := exec.Command("speaker-test", "-t", "sine", "-f", "1000", "-l", "1")
			cmd.Start()
			time.Sleep(100 * time.Millisecond)
			cmd.Process.Kill()
			if err := exec.Command("beep", "-f", "800", "-l", "100").Run(); err == nil {
				return
			}
			fmt.Print("\a")
		}
	}()
}

// Redraw the current prompt and input buffer
func (c *Client) redrawInputLine() {
	c.inputMu.Lock()
	currentInput := c.inputBuffer
	c.inputMu.Unlock()

	fmt.Print("\r\033[K") // Clear line
	fmt.Print(c.colorize(c.config.Theme.SystemColor, c.promptText))
	fmt.Print(currentInput)
}

// Print message and restore input line
func (c *Client) printMessageSafe(msg string) {
	c.playNotificationSound()

	// Clear current line first
	fmt.Print("\r\033[K")

	// Print the message(s) - handle multi-line properly
	lines := strings.Split(msg, "\n")
	for i, line := range lines {
		sanitized := sanitizeText(line)

		// Don't print empty lines at the end
		if sanitized == "" && i == len(lines)-1 {
			continue
		}

		if sanitized == "" {
			fmt.Println()
			continue
		}

		// Ensure we're at the start of the line before printing
		fmt.Print("\r")

		// Check for different message formats
		if strings.HasPrefix(sanitized, "***") {
			fmt.Println(c.colorize(c.config.Theme.SystemColor, sanitized))
		} else if strings.Contains(sanitized, "]") && strings.Contains(sanitized, ":") {
			// This looks like a timestamped message
			parts := strings.SplitN(sanitized, "]", 2)
			if len(parts) == 2 {
				timestamp := parts[0] + "]"
				rest := parts[1]
				userMsg := strings.SplitN(strings.TrimSpace(rest), ":", 2)
				if len(userMsg) == 2 {
					username := userMsg[0]
					message := userMsg[1]
					fmt.Print(c.colorize(c.config.Theme.TimestampColor, timestamp) + " ")
					fmt.Print(c.colorize(c.config.Theme.UsernameColor, username) + ":")
					fmt.Println(c.colorize(c.config.Theme.MessageColor, message))
					continue
				}
			}
			// If it didn't parse as a message, just print it
			fmt.Println(c.colorize(c.config.Theme.SystemColor, sanitized))
		} else {
			// Regular system message
			fmt.Println(c.colorize(c.config.Theme.SystemColor, sanitized))
		}
	}

	// Restore the input line
	c.redrawInputLine()
}

func (c *Client) printMessage(msg string) {
	c.playNotificationSound()

	if strings.Contains(msg, "\n") {
		lines := strings.Split(msg, "\n")
		for _, line := range lines {
			sanitized := sanitizeText(line)
			if sanitized != "" {
				if strings.HasPrefix(sanitized, "***") {
					fmt.Println(c.colorize(c.config.Theme.SystemColor, sanitized))
				} else if strings.Contains(sanitized, "]") && strings.Contains(sanitized, ":") {
					parts := strings.SplitN(sanitized, "]", 2)
					if len(parts) == 2 {
						timestamp := parts[0] + "]"
						rest := parts[1]
						userMsg := strings.SplitN(strings.TrimSpace(rest), ":", 2)
						if len(userMsg) == 2 {
							username := userMsg[0]
							message := userMsg[1]
							fmt.Print(c.colorize(c.config.Theme.TimestampColor, timestamp) + " ")
							fmt.Print(c.colorize(c.config.Theme.UsernameColor, username) + ":")
							fmt.Println(c.colorize(c.config.Theme.MessageColor, message))
							continue
						}
					}
					fmt.Println(c.colorize(c.config.Theme.SystemColor, sanitized))
				} else {
					fmt.Println(c.colorize(c.config.Theme.SystemColor, sanitized))
				}
			} else {
				fmt.Println()
			}
		}
		return
	}

	msg = sanitizeText(msg)

	if strings.HasPrefix(msg, "***") {
		fmt.Println(c.colorize(c.config.Theme.SystemColor, msg))
	} else if strings.Contains(msg, "]") && strings.Contains(msg, ":") {
		parts := strings.SplitN(msg, "]", 2)
		if len(parts) == 2 {
			timestamp := parts[0] + "]"
			rest := parts[1]

			userMsg := strings.SplitN(strings.TrimSpace(rest), ":", 2)
			if len(userMsg) == 2 {
				username := userMsg[0]
				message := userMsg[1]

				fmt.Print(c.colorize(c.config.Theme.TimestampColor, timestamp) + " ")
				fmt.Print(c.colorize(c.config.Theme.UsernameColor, username) + ":")
				fmt.Println(c.colorize(c.config.Theme.MessageColor, message))
			} else {
				fmt.Println(c.colorize(c.config.Theme.SystemColor, msg))
			}
		} else {
			fmt.Println(c.colorize(c.config.Theme.SystemColor, msg))
		}
	} else {
		fmt.Println(c.colorize(c.config.Theme.SystemColor, msg))
	}
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

func (c *Client) createObfuscatedPacket(msgType byte, data []byte) []byte {
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

func readObfuscatedPacket(conn net.Conn) (*ObfuscatedPacket, error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	msgType := header[0]
	dataLen := binary.BigEndian.Uint16(header[1:3])

	const maxPacketDataSize = 4096
	if dataLen > maxPacketDataSize {
		return nil, fmt.Errorf("packet data too large: %d bytes (max %d)", dataLen, maxPacketDataSize)
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

func randomInt(max int64) int64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(max))
	return n.Int64()
}

func sanitizeText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
}

func (c *Client) sendDecoyTraffic() {
	ticker := time.NewTicker(time.Duration(c.config.DecoyInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopDecoy:
			return
		case <-c.shutdown:
			return
		case <-ticker.C:
			size := c.config.DecoyMinBytes + int(randomInt(int64(c.config.DecoyMaxBytes-c.config.DecoyMinBytes)))
			decoyData := make([]byte, size)
			rand.Read(decoyData)

			packet := c.createObfuscatedPacket(0x02, decoyData)
			c.conn.Write(packet)
		}
	}
}

func loadPublicKey(filename string) (*rsa.PublicKey, error) {
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %v", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %v", err)
		}
		rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("certificate does not contain an RSA public key")
		}
		return rsaPub, nil
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return rsaPub, nil
}

func loadConfig() ClientConfig {
	config := ClientConfig{
		Servers: []ServerInfo{
			{Name: "Default Server", Address: "localhost", Port: 37842},
		},
		Theme: Theme{
			SystemColor:    "bright_cyan",
			UsernameColor:  "bright_yellow",
			MessageColor:   "white",
			TimestampColor: "gray",
			ErrorColor:     "bright_red",
		},
		DecoyTraffic:      true,
		DecoyInterval:     30,
		DecoyMinBytes:     100,
		DecoyMaxBytes:     500,
		SoundNotification: false,
	}

	data, err := os.ReadFile("client_config.json")
	if err != nil {
		configData, _ := json.MarshalIndent(config, "", "  ")
		os.WriteFile("client_config.json", configData, 0644)
		return config
	}

	if err := json.Unmarshal(data, &config); err != nil {
		fmt.Println("⚠ Error parsing config, using defaults")
		return config
	}

	return config
}

func computeFileHash(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Patched sendFile with better flow control and error handling
func (c *Client) sendFile(filePath string) {
	cleanPath := filePath

	c.transferMu.Lock()
	if c.pendingTransfer != nil && c.pendingTransfer.filename != "" {
		cleanPath = c.pendingTransfer.filename
		c.pendingTransfer.filename = ""
	}
	c.transferMu.Unlock()

	cleanPath = filepath.Clean(cleanPath)

	fileInfo, err := os.Stat(cleanPath)
	if err != nil {
		c.printMessageSafe("✗ Error: Cannot access file: " + err.Error())
		return
	}

	if fileInfo.IsDir() {
		c.printMessageSafe("✗ Error: Cannot send directories")
		return
	}

	const maxFileSize = 100 * 1024 * 1024 // 100MB limit (adjust as needed)
	if fileInfo.Size() > maxFileSize {
		c.printMessageSafe(fmt.Sprintf("✗ Error: File too large (max 100MB, file is %.2fMB)", float64(fileInfo.Size())/1024/1024))
		return
	}

	c.printMessageSafe("Computing file hash...")
	fileHash, err := computeFileHash(cleanPath)
	if err != nil {
		c.printMessageSafe("✗ Error computing file hash: " + err.Error())
		return
	}

	file, err := os.Open(cleanPath)
	if err != nil {
		c.printMessageSafe("✗ Error opening file: " + err.Error())
		return
	}
	defer file.Close()

	filename := fileInfo.Name()
	filesize := fileInfo.Size()

	metadata := fmt.Sprintf("FILE_START|%s|%d", filename, filesize)
	encrypted, _ := c.encrypt([]byte(metadata))
	packet := c.createObfuscatedPacket(0x03, encrypted)

	c.mu.Lock()
	_, writeErr := c.conn.Write(packet)
	c.mu.Unlock()
	if writeErr != nil {
		c.printMessageSafe("✗ Network error: cannot start transfer")
		return
	}

	time.Sleep(100 * time.Millisecond)

	c.printMessageSafe(fmt.Sprintf("Sending file: %s (%.2f KB)", filename, float64(filesize)/1024))
	c.printMessageSafe(fmt.Sprintf("SHA-256: %s", fileHash))

	const chunkSize = 3900
	buffer := make([]byte, chunkSize)
	var totalSent int64

	for {
		n, err := file.Read(buffer)
		if n > 0 {
			chunk := buffer[:n]
			encrypted, err := c.encrypt(chunk)
			if err != nil {
				c.printMessageSafe("✗ Encryption error during transfer")
				return
			}

			packet := c.createObfuscatedPacket(0x03, encrypted)

			c.mu.Lock()
			_, writeErr := c.conn.Write(packet)
			c.mu.Unlock()

			if writeErr != nil {
				c.printMessageSafe("✗ Network error during transfer: " + writeErr.Error())
				c.printMessageSafe("✗ File transfer aborted")
				return
			}

			time.Sleep(30 * time.Millisecond) // Increased for better backpressure

			totalSent += int64(n)
			progress := float64(totalSent) / float64(filesize) * 100

			fmt.Print("\r\033[K")
			fmt.Printf("Progress: %.1f%% ", progress)
			if progress >= 100.0 || n == 0 {
				fmt.Println()
				c.redrawInputLine()
			}
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			c.printMessageSafe("\n✗ Error reading file: " + err.Error())
			return
		}
	}

	time.Sleep(100 * time.Millisecond)

	endMarker := "FILE_END"
	encrypted, _ = c.encrypt([]byte(endMarker))
	packet = c.createObfuscatedPacket(0x03, encrypted)

	c.mu.Lock()
	_, writeErr = c.conn.Write(packet)
	c.mu.Unlock()
	if writeErr != nil {
		c.printMessageSafe("✗ Network error sending FILE_END")
		return
	}

	time.Sleep(100 * time.Millisecond)

	c.printMessageSafe("✓ File sent successfully")
	c.printMessageSafe("✓ Recipient should verify hash: " + fileHash)
}

func main() {
	config := loadConfig()

	client := &Client{
		config:     config,
		stopDecoy:  make(chan bool),
		shutdown:   make(chan bool),
		promptText: "> ",
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n✓ Shutting down client gracefully...")
		close(client.shutdown)
		if client.conn != nil {
			client.conn.Close()
		}
		os.Exit(0)
	}()

	client.clearScreen()

	if _, err := os.Stat("chat_public.pem"); os.IsNotExist(err) {
		fmt.Println(client.colorize(config.Theme.ErrorColor, "✗ Error: chat_public.pem not found!"))
		fmt.Println(client.colorize(config.Theme.SystemColor, "Please copy the public key file from the server to this directory."))
		os.Exit(1)
	}

	publicKey, err := loadPublicKey("chat_public.pem")
	if err != nil {
		fmt.Println(client.colorize(config.Theme.ErrorColor, "✗ Error loading public key: "+err.Error()))
		os.Exit(1)
	}

	fmt.Println(client.colorize(config.Theme.SystemColor, "✓ Loaded RSA authentication key"))

	dhParams := initDHParams()
	fmt.Println(client.colorize(config.Theme.SystemColor, "✓ Initialized Diffie-Hellman parameters"))

	fmt.Println()
	fmt.Println(client.colorize(config.Theme.SystemColor, "Available servers:"))

	if len(config.Servers) == 1 {
		srv := config.Servers[0]
		fmt.Printf("  1. %s (%s:%d)\n", srv.Name, srv.Address, srv.Port)
	} else {
		for i, srv := range config.Servers {
			fmt.Printf("  %d. %s (%s:%d)\n", i+1, srv.Name, srv.Address, srv.Port)
		}
	}

	fmt.Println()
	if len(config.Servers) == 1 {
		fmt.Print(client.colorize(config.Theme.SystemColor, "Press Enter to connect, or enter custom address: "))
	} else {
		fmt.Print(client.colorize(config.Theme.SystemColor, "Select server (1-"+fmt.Sprintf("%d", len(config.Servers))+") or enter custom address: "))
	}

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		os.Exit(1)
	}

	input := strings.TrimSpace(scanner.Text())
	var serverAddr string

	var selection int
	if _, err := fmt.Sscanf(input, "%d", &selection); err == nil && selection > 0 && selection <= len(config.Servers) {
		srv := config.Servers[selection-1]
		serverAddr = fmt.Sprintf("%s:%d", srv.Address, srv.Port)
	} else if input != "" {
		serverAddr = input
	} else {
		serverAddr = fmt.Sprintf("%s:%d", config.Servers[0].Address, config.Servers[0].Port)
	}

	fmt.Println(client.colorize(config.Theme.SystemColor, "Connecting to "+serverAddr+"..."))

	certPEM, err := os.ReadFile("chat_public.pem")
	if err != nil {
		fmt.Println(client.colorize(config.Theme.ErrorColor, "✗ Failed to read chat_public.pem: "+err.Error()))
		os.Exit(1)
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(certPEM); !ok {
		fmt.Println(client.colorize(config.Theme.ErrorColor, "✗ Failed to parse chat_public.pem as a valid certificate"))
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		RootCAs:            certPool,
		InsecureSkipVerify: true,

		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no peer certificate presented")
			}

			peerCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("failed to parse peer certificate: %v", err)
			}

			pinnedPEM, err := os.ReadFile("chat_public.pem")
			if err != nil {
				return fmt.Errorf("failed to read pinned certificate: %v", err)
			}
			pinnedBlock, _ := pem.Decode(pinnedPEM)
			if pinnedBlock == nil {
				return fmt.Errorf("failed to decode pinned certificate PEM")
			}
			pinnedCert, err := x509.ParseCertificate(pinnedBlock.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse pinned certificate: %v", err)
			}

			if !bytes.Equal(peerCert.Raw, pinnedCert.Raw) {
				return fmt.Errorf("peer certificate does not match the expected pinned certificate")
			}

			return nil
		},
	}

	conn, err := tls.Dial("tcp", serverAddr, tlsConfig)
	if err != nil {
		fmt.Println(client.colorize(config.Theme.ErrorColor, "✗ TLS connection failed: "+err.Error()))
		os.Exit(1)
	}
	defer conn.Close()

	client.conn = conn

	fmt.Println(client.colorize(config.Theme.SystemColor, "✓ Secure TLS connection established"))

	var serverDHPubLen uint32
	if err := binary.Read(conn, binary.BigEndian, &serverDHPubLen); err != nil {
		fmt.Println(client.colorize(config.Theme.ErrorColor, "✗ DH exchange failed"))
		os.Exit(1)
	}

	const maxDHPubKeySize = 4096
	if serverDHPubLen > maxDHPubKeySize {
		fmt.Println(client.colorize(config.Theme.ErrorColor, "✗ DH exchange failed: key size too large (possible DoS attack)"))
		os.Exit(1)
	}

	serverDHPubBytes := make([]byte, serverDHPubLen)
	if _, err := io.ReadFull(conn, serverDHPubBytes); err != nil {
		fmt.Println(client.colorize(config.Theme.ErrorColor, "✗ DH exchange failed"))
		os.Exit(1)
	}

	var sigLen uint32
	if err := binary.Read(conn, binary.BigEndian, &sigLen); err != nil {
		fmt.Println(client.colorize(config.Theme.ErrorColor, "✗ Signature verification failed"))
		os.Exit(1)
	}

	const maxRSASignatureSize = 4096
	if sigLen > maxRSASignatureSize {
		fmt.Println(client.colorize(config.Theme.ErrorColor, "✗ Signature verification failed: signature too large (possible DoS attack)"))
		os.Exit(1)
	}

	signature := make([]byte, sigLen)
	if _, err := io.ReadFull(conn, signature); err != nil {
		fmt.Println(client.colorize(config.Theme.ErrorColor, "✗ Signature verification failed"))
		os.Exit(1)
	}

	hash := sha256.Sum256(serverDHPubBytes)
	if err := rsa.VerifyPSS(publicKey, crypto.SHA256, hash[:], signature, nil); err != nil {
		fmt.Println(client.colorize(config.Theme.ErrorColor, "✗ Server authentication failed - possible MITM attack!"))
		os.Exit(1)
	}

	fmt.Println(client.colorize(config.Theme.SystemColor, "✓ Server authenticated via RSA signature"))

	serverDHPub := new(big.Int).SetBytes(serverDHPubBytes)

	dhPrivate, dhPublic, err := generateDHKeyPair(dhParams)
	if err != nil {
		fmt.Println(client.colorize(config.Theme.ErrorColor, "✗ DH key generation failed"))
		os.Exit(1)
	}

	clientDHPubBytes := dhPublic.Bytes()
	clientDHPubLen := make([]byte, 4)
	binary.BigEndian.PutUint32(clientDHPubLen, uint32(len(clientDHPubBytes)))
	conn.Write(clientDHPubLen)
	conn.Write(clientDHPubBytes)

	sharedSecret := computeDHSharedSecret(dhPrivate, serverDHPub, dhParams.P)

	fmt.Println(client.colorize(config.Theme.SystemColor, "✓ Diffie-Hellman key exchange completed"))
	fmt.Println(client.colorize(config.Theme.SystemColor, "✓ Perfect forward secrecy enabled"))

	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		fmt.Println(client.colorize(config.Theme.ErrorColor, "✗ Cipher setup failed"))
		os.Exit(1)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println(client.colorize(config.Theme.ErrorColor, "✗ GCM setup failed"))
		os.Exit(1)
	}

	client.sessionKey = sharedSecret
	client.gcm = gcm

	client.clearScreen()
	client.printSeparator()
	fmt.Println(client.colorize(config.Theme.SystemColor, "                         WELCOME TO QUIETROOM"))
	fmt.Println(client.colorize(config.Theme.SystemColor, "    SECURE ENCRYPTED CHAT - "+serverAddr+" - E2E ENCRYPTED + PFS"))
	client.printSeparator()
	fmt.Println()

	if client.config.DecoyTraffic {
		go client.sendDecoyTraffic()
		fmt.Println(client.colorize(config.Theme.SystemColor, "✓ Decoy traffic active"))
	}

	fmt.Println(client.colorize(config.Theme.SystemColor, "✓ Traffic obfuscation active"))

	if client.config.SoundNotification {
		fmt.Println(client.colorize(config.Theme.SystemColor, "✓ Sound notifications enabled"))
	}

	fmt.Println(client.colorize(config.Theme.SystemColor, "✓ Type /help for available commands"))
	fmt.Println(client.colorize(config.Theme.SystemColor, "✓ Press Ctrl+C or type /quit to disconnect"))
	fmt.Println()

	done := make(chan bool)

	// Reader goroutine - handles incoming messages
	go func() {
		var receivingFile bool
		var outFile *os.File
		var expectedSize int64
		var receivedSize int64
		var receivedHash = sha256.New()
		var expectedHash string

		for {
			select {
			case <-client.shutdown:
				done <- true
				return
			default:
			}

			packet, err := readObfuscatedPacket(conn)
			if err != nil {
				done <- true
				return
			}

			if packet.Type == 0x02 {
				continue
			}

			if packet.Type == 0x03 {
				msg, err := client.decrypt(packet.Data)
				if err != nil {
					continue
				}

				msgStr := string(msg)

				if strings.HasPrefix(msgStr, "FILE_START|") {
					parts := strings.Split(msgStr, "|")
					if len(parts) >= 3 {
						filename := filepath.Base(parts[1])
						fmt.Sscanf(parts[2], "%d", &expectedSize)

						if len(parts) == 4 {
							expectedHash = parts[3]
						}

						os.MkdirAll("downloads", 0755)

						downloadPath := fmt.Sprintf("downloads/%s", filename)

						if _, err := os.Stat(downloadPath); err == nil {
							ext := ""
							name := filename
							if idx := strings.LastIndex(filename, "."); idx != -1 {
								name = filename[:idx]
								ext = filename[idx:]
							}

							counter := 1
							for {
								downloadPath = fmt.Sprintf("downloads/%s%d%s", name, counter, ext)
								if _, err := os.Stat(downloadPath); os.IsNotExist(err) {
									break
								}
								counter++
							}

							client.mu.Lock()
							client.printMessageSafe(fmt.Sprintf("File already exists. Saving as: %s", downloadPath))
							client.mu.Unlock()
						}

						outFile, err = os.Create(downloadPath)
						if err != nil {
							client.mu.Lock()
							client.printMessageSafe(fmt.Sprintf("✗ Error creating file: %s", err.Error()))
							client.mu.Unlock()
							continue
						}

						receivingFile = true
						receivedSize = 0
						receivedHash.Reset()
						client.mu.Lock()
						client.printMessageSafe(fmt.Sprintf("Receiving file: %s (%.2f KB)", filename, float64(expectedSize)/1024))
						if expectedHash != "" {
							client.printMessageSafe(fmt.Sprintf("Expected SHA-256: %s", expectedHash))
						}
						client.mu.Unlock()
					}
					continue
				}

				if msgStr == "FILE_END" {
					if outFile != nil {
						outFile.Close()

						actualHash := hex.EncodeToString(receivedHash.Sum(nil))
						client.mu.Lock()
						client.printMessageSafe(fmt.Sprintf("✓ File received successfully (%.2f KB)", float64(receivedSize)/1024))
						client.printMessageSafe(fmt.Sprintf("SHA-256: %s", actualHash))

						if expectedHash != "" {
							if actualHash == expectedHash {
								client.printMessageSafe("✓ Hash verification PASSED - file integrity verified!")
							} else {
								client.printMessageSafe("✗ Hash verification FAILED - file may be corrupted!")
								client.printMessageSafe(fmt.Sprintf("Expected: %s", expectedHash))
								client.printMessageSafe(fmt.Sprintf("Got:      %s", actualHash))
							}
						} else {
							client.printMessageSafe("⚠ No expected hash provided - cannot verify integrity")
						}
						client.mu.Unlock()
						outFile = nil
					}
					receivingFile = false
					receivedSize = 0
					expectedHash = ""
					continue
				}

				if receivingFile && outFile != nil {
					_, err := outFile.Write(msg)
					if err == nil {
						receivedHash.Write(msg)
						receivedSize += int64(len(msg))
						if expectedSize > 0 {
							progress := float64(receivedSize) / float64(expectedSize) * 100
							if int(progress*10)%10 == 0 || receivedSize == expectedSize {
								fmt.Print("\r\033[K")
								if receivedSize == expectedSize {
									fmt.Printf("Progress: 100.0%% \n")
									client.redrawInputLine()
								} else {
									fmt.Printf("Progress: %.1f%% ", progress)
								}
							}
						}
					}
				}
				continue
			}

			msg, err := client.decrypt(packet.Data)
			if err != nil {
				continue
			}

			msgStr := string(msg)

			if strings.HasPrefix(msgStr, "BEGIN_SEND|") {
				parts := strings.Split(msgStr, "|")
				if len(parts) >= 2 {
					filePath := parts[1]
					filePath = filepath.Clean(filePath)

					client.transferMu.Lock()
					if client.pendingTransfer != nil && client.pendingTransfer.filename != "" {
						filePath = client.pendingTransfer.filename
					}
					client.transferMu.Unlock()

					if len(parts) == 3 {
						expectedHash = parts[2]
					}

					client.mu.Lock()
					client.printMessageSafe("Starting file transfer...")
					client.mu.Unlock()
					go client.sendFile(filePath)
				}
				continue
			}

			client.mu.Lock()
			client.lastSentMu.Lock()
			isOwnMessage := false
			if client.lastSentMsg != "" && strings.Contains(msgStr, client.lastSentMsg) {
				isOwnMessage = true
				client.lastSentMsg = ""
			}
			client.lastSentMu.Unlock()

			if !isOwnMessage {
				client.printMessageSafe(msgStr)
			}
			client.mu.Unlock()
		}
	}()

	// Put terminal in raw mode for proper character-by-character input
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("Failed to set raw mode:", err)
		os.Exit(1)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	// Input handling with raw terminal mode
	inputChan := make(chan string)
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				close(inputChan)
				return
			}

			b := buf[0]

			if b == 13 || b == 10 { // Enter
				client.inputMu.Lock()
				text := client.inputBuffer
				client.inputBuffer = ""
				client.inputMu.Unlock()

				fmt.Print("\r\033[K")
				if text != "" {
					inputChan <- text
				} else {
					fmt.Print(client.colorize(client.config.Theme.SystemColor, client.promptText))
				}
			} else if b == 127 || b == 8 { // Backspace
				client.inputMu.Lock()
				if len(client.inputBuffer) > 0 {
					client.inputBuffer = client.inputBuffer[:len(client.inputBuffer)-1]
				}
				client.inputMu.Unlock()
				client.redrawInputLine()
			} else if b == 3 { // Ctrl+C
				term.Restore(int(os.Stdin.Fd()), oldState)
				fmt.Println("\n✓ Shutting down client gracefully...")
				close(client.shutdown)
				if client.conn != nil {
					client.conn.Close()
				}
				os.Exit(0)
			} else if b >= 32 && b < 127 { // Printable characters
				client.inputMu.Lock()
				client.inputBuffer += string(b)
				client.inputMu.Unlock()
				fmt.Print(string(b))
			}
		}
	}()

	// Display initial prompt
	fmt.Print(client.colorize(config.Theme.SystemColor, client.promptText))

	// Message sender loop
	for {
		select {
		case text, ok := <-inputChan:
			if !ok {
				goto cleanup
			}

			originalText := text

			if strings.HasPrefix(text, "/file ") {
				parts := strings.SplitN(text, " ", 3)

				if len(parts) >= 3 {
					targetUser := parts[1]
					filePath := strings.TrimSpace(parts[2])

					if (strings.HasPrefix(filePath, "\"") && strings.HasSuffix(filePath, "\"")) ||
						(strings.HasPrefix(filePath, "'") && strings.HasSuffix(filePath, "'")) {
						filePath = filePath[1 : len(filePath)-1]
					}

					absPath, err := filepath.Abs(filePath)
					if err != nil {
						client.printMessageSafe("✗ Error: Invalid file path: " + err.Error())
						continue
					}

					cleanPath := filepath.Clean(absPath)

					if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
						client.printMessageSafe("✗ Error: File not found: " + cleanPath)
						continue
					}

					fileHash, err := computeFileHash(cleanPath)
					if err != nil {
						client.printMessageSafe("✗ Error: Cannot access file: " + err.Error())
						continue
					}

					basename := filepath.Base(cleanPath)
					text = fmt.Sprintf("/file %s %s %s", targetUser, basename, fileHash)

					client.transferMu.Lock()
					if client.pendingTransfer == nil {
						client.pendingTransfer = &FileTransferState{}
					}
					client.pendingTransfer.filename = cleanPath
					client.transferMu.Unlock()
				} else {
					client.printMessageSafe("✗ Usage: /file <username> <filepath>")
					client.printMessageSafe("   Tip: Use quotes for paths with spaces")
					continue
				}
			}

			encrypted, err := client.encrypt([]byte(text))
			if err != nil {
				client.printMessageSafe("✗ Encryption error")
				continue
			}

			packet := client.createObfuscatedPacket(0x01, encrypted)
			_, err = conn.Write(packet)
			if err != nil {
				client.printMessageSafe("✗ Send error")
				goto cleanup
			}

			// Show local echo for regular messages (not commands)
			if !strings.HasPrefix(originalText, "/") && strings.TrimSpace(originalText) != "" {
				// Display our own message locally
				timestamp := time.Now().Format("15:04:05")
				localMsg := fmt.Sprintf("[%s] You: %s", timestamp, originalText)

				fmt.Print("\r\033[K")
				fmt.Println(client.colorize(client.config.Theme.SystemColor, localMsg))

				// Mark message to suppress server echo
				client.lastSentMu.Lock()
				client.lastSentMsg = originalText
				client.lastSentMu.Unlock()
			}

			if strings.TrimSpace(text) == "/quit" {
				goto cleanup
			}

			// Redraw prompt after sending
			client.redrawInputLine()

		case <-client.shutdown:
			goto cleanup
		}
	}

cleanup:
	term.Restore(int(os.Stdin.Fd()), oldState)
	close(client.stopDecoy)
	<-done

	fmt.Println()
	client.printSeparator()
	fmt.Println(client.colorize(config.Theme.SystemColor, "Disconnected from server"))
}
