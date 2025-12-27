package android
// Package chat provides a secure chat client for Android binding.
package chat

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
    "path/filepath"
    "strings"
    "sync"
    "time"
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
    conn            net.Conn
    sessionKey      []byte
    gcm             cipher.AEAD
    config          ClientConfig
    mu              sync.Mutex
    stopDecoy       chan bool
    shutdown        chan bool
    username        string
    receiveChan     chan string // Exported for receiving messages
    pendingTransfer *FileTransferState
    transferMu      sync.Mutex
    lastSentMsg     string
    lastSentMu      sync.Mutex
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

var colors = map[string]string{ // Retained for message formatting; Android will parse these
    "reset":          "[reset]",
    "red":            "[red]",
    "green":          "[green]",
    "yellow":         "[yellow]",
    "blue":           "[blue]",
    "magenta":        "[magenta]",
    "cyan":           "[cyan]",
    "white":          "[white]",
    "gray":           "[gray]",
    "bright_red":     "[bright_red]",
    "bright_green":   "[bright_green]",
    "bright_yellow":  "[bright_yellow]",
    "bright_blue":    "[bright_blue]",
    "bright_magenta": "[bright_magenta]",
    "bright_cyan":    "[bright_cyan]",
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

func (c *Client) colorize(color, text string) string { // Modified to use tags for Android parsing
    if code, ok := colors[color]; ok {
        return code + text + colors["reset"]
    }
    return text
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
            c.mu.Lock()
            c.conn.Write(packet)
            c.mu.Unlock()
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

// NewClient creates a new chat client.
func NewClient() *Client {
    config := loadConfig()
    return &Client{
        config:      config,
        stopDecoy:   make(chan bool),
        shutdown:    make(chan bool),
        receiveChan: make(chan string),
    }
}

// Connect establishes a connection to the server.
func (c *Client) Connect(serverAddr string) string { // Returns status message
    if _, err := os.Stat("chat_public.pem"); os.IsNotExist(err) {
        return "✗ Error: chat_public.pem not found!"
    }

    publicKey, err := loadPublicKey("chat_public.pem")
    if err != nil {
        return "✗ Error loading public key: " + err.Error()
    }

    dhParams := initDHParams()

    certPEM, err := os.ReadFile("chat_public.pem")
    if err != nil {
        return "✗ Failed to read chat_public.pem: " + err.Error()
    }

    certPool := x509.NewCertPool()
    if ok := certPool.AppendCertsFromPEM(certPEM); !ok {
        return "✗ Failed to parse chat_public.pem as a valid certificate"
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
        return "✗ TLS connection failed: " + err.Error()
    }
    c.conn = conn

    var serverDHPubLen uint32
    if err := binary.Read(conn, binary.BigEndian, &serverDHPubLen); err != nil {
        return "✗ DH exchange failed"
    }

    const maxDHPubKeySize = 4096
    if serverDHPubLen > maxDHPubKeySize {
        return "✗ DH exchange failed: key size too large"
    }

    serverDHPubBytes := make([]byte, serverDHPubLen)
    if _, err := io.ReadFull(conn, serverDHPubBytes); err != nil {
        return "✗ DH exchange failed"
    }

    var sigLen uint32
    if err := binary.Read(conn, binary.BigEndian, &sigLen); err != nil {
        return "✗ Signature verification failed"
    }

    const maxRSASignatureSize = 4096
    if sigLen > maxRSASignatureSize {
        return "✗ Signature verification failed: signature too large"
    }

    signature := make([]byte, sigLen)
    if _, err := io.ReadFull(conn, signature); err != nil {
        return "✗ Signature verification failed"
    }

    hash := sha256.Sum256(serverDHPubBytes)
    if err := rsa.VerifyPSS(publicKey, crypto.SHA256, hash[:], signature, nil); err != nil {
        return "✗ Server authentication failed - possible MITM attack!"
    }

    serverDHPub := new(big.Int).SetBytes(serverDHPubBytes)

    dhPrivate, dhPublic, err := generateDHKeyPair(dhParams)
    if err != nil {
        return "✗ DH key generation failed"
    }

    clientDHPubBytes := dhPublic.Bytes()
    clientDHPubLen := make([]byte, 4)
    binary.BigEndian.PutUint32(clientDHPubLen, uint32(len(clientDHPubBytes)))
    conn.Write(clientDHPubLen)
    conn.Write(clientDHPubBytes)

    sharedSecret := computeDHSharedSecret(dhPrivate, serverDHPub, dhParams.P)

    block, err := aes.NewCipher(sharedSecret)
    if err != nil {
        return "✗ Cipher setup failed"
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "✗ GCM setup failed"
    }

    c.sessionKey = sharedSecret
    c.gcm = gcm

    if c.config.DecoyTraffic {
        go c.sendDecoyTraffic()
    }

    go c.readMessages()

    return "✓ Connected successfully to " + serverAddr
}

// Send sends a message or command.
func (c *Client) Send(text string) string {
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
            fileHash, err := computeFileHash(filePath)
            if err != nil {
                return "✗ Error: Cannot access file: " + err.Error()
            }
            basename := filepath.Base(filePath)
            text = fmt.Sprintf("/file %s %s %s", targetUser, basename, fileHash)
            c.transferMu.Lock()
            if c.pendingTransfer == nil {
                c.pendingTransfer = &FileTransferState{}
            }
            c.pendingTransfer.filename = filePath
            c.transferMu.Unlock()
        } else {
            return "✗ Usage: /file <username> <filepath>"
        }
    }

    encrypted, err := c.encrypt([]byte(text))
    if err != nil {
        return "✗ Encryption error"
    }

    packet := c.createObfuscatedPacket(0x01, encrypted)
    c.mu.Lock()
    _, err = c.conn.Write(packet)
    c.mu.Unlock()
    if err != nil {
        return "✗ Send error"
    }

    // Local echo for non-commands
    if !strings.HasPrefix(originalText, "/") && strings.TrimSpace(originalText) != "" {
        timestamp := time.Now().Format("15:04:05")
        localMsg := fmt.Sprintf("[%s] You: %s", timestamp, originalText)
        c.receiveChan <- c.colorize(c.config.Theme.SystemColor, localMsg)
        c.lastSentMu.Lock()
        c.lastSentMsg = originalText
        c.lastSentMu.Unlock()
    }

    if strings.TrimSpace(text) == "/quit" {
        c.Close()
    }

    return ""
}

// SendFile sends a file (called from Android after file pick).
func (c *Client) SendFile(filePath string) string {
    c.transferMu.Lock()
    if c.pendingTransfer != nil {
        c.pendingTransfer.filename = filePath
    }
    c.transferMu.Unlock()

    fileInfo, err := os.Stat(filePath)
    if err != nil {
        return "✗ Error: Cannot access file: " + err.Error()
    }

    if fileInfo.IsDir() {
        return "✗ Error: Cannot send directories"
    }

    const maxFileSize = 100 * 1024 * 1024
    if fileInfo.Size() > maxFileSize {
        return fmt.Sprintf("✗ Error: File too large (max 100MB, file is %.2fMB)", float64(fileInfo.Size())/1024/1024)
    }

    fileHash, err := computeFileHash(filePath)
    if err != nil {
        return "✗ Error computing file hash: " + err.Error()
    }

    file, err := os.Open(filePath)
    if err != nil {
        return "✗ Error opening file: " + err.Error()
    }
    defer file.Close()

    filename := fileInfo.Name()
    filesize := fileInfo.Size()

    metadata := fmt.Sprintf("FILE_START|%s|%d", filename, filesize)
    encrypted, _ := c.encrypt([]byte(metadata))
    packet := c.createObfuscatedPacket(0x03, encrypted)

    c.mu.Lock()
    _, err = c.conn.Write(packet)
    c.mu.Unlock()
    if err != nil {
        return "✗ Network error: cannot start transfer"
    }

    time.Sleep(100 * time.Millisecond)

    c.receiveChan <- fmt.Sprintf("Sending file: %s (%.2f KB)", filename, float64(filesize)/1024)
    c.receiveChan <- fmt.Sprintf("SHA-256: %s", fileHash)

    const chunkSize = 3900
    buffer := make([]byte, chunkSize)
    var totalSent int64

    for {
        n, err := file.Read(buffer)
        if n > 0 {
            chunk := buffer[:n]
            encrypted, err := c.encrypt(chunk)
            if err != nil {
                return "✗ Encryption error during transfer"
            }

            packet := c.createObfuscatedPacket(0x03, encrypted)

            c.mu.Lock()
            _, err = c.conn.Write(packet)
            c.mu.Unlock()
            if err != nil {
                return "✗ Network error during transfer: " + err.Error()
            }

            time.Sleep(30 * time.Millisecond)

            totalSent += int64(n)
            progress := float64(totalSent) / float64(filesize) * 100
            c.receiveChan <- fmt.Sprintf("Progress: %.1f%%", progress)
        }

        if err == io.EOF {
            break
        }
        if err != nil {
            return "✗ Error reading file: " + err.Error()
        }
    }

    time.Sleep(100 * time.Millisecond)

    endMarker := "FILE_END"
    encrypted, _ = c.encrypt([]byte(endMarker))
    packet = c.createObfuscatedPacket(0x03, encrypted)

    c.mu.Lock()
    _, err = c.conn.Write(packet)
    c.mu.Unlock()
    if err != nil {
        return "✗ Network error sending FILE_END"
    }

    c.receiveChan <- "✓ File sent successfully"
    c.receiveChan <- "✓ Recipient should verify hash: " + fileHash

    return ""
}

// Receive returns the channel for incoming messages.
func (c *Client) Receive() chan string {
    return c.receiveChan
}

// Close closes the client.
func (c *Client) Close() {
    close(c.stopDecoy)
    close(c.shutdown)
    if c.conn != nil {
        c.conn.Close()
    }
}

func (c *Client) readMessages() {
    var receivingFile bool
    var outFile *os.File
    var expectedSize int64
    var receivedSize int64
    var receivedHash = sha256.New()
    var expectedHash string

    for {
        select {
        case <-c.shutdown:
            return
        default:
        }

        packet, err := readObfuscatedPacket(c.conn)
        if err != nil {
            c.receiveChan <- "✗ Read error: " + err.Error()
            return
        }

        if packet.Type == 0x02 {
            continue
        }

        if packet.Type == 0x03 {
            msg, err := c.decrypt(packet.Data)
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
                    downloadPath := filepath.Join("downloads", filename)

                    if _, err := os.Stat(downloadPath); err == nil {
                        ext := filepath.Ext(filename)
                        name := strings.TrimSuffix(filename, ext)
                        counter := 1
                        for {
                            downloadPath = filepath.Join("downloads", fmt.Sprintf("%s%d%s", name, counter, ext))
                            if _, err := os.Stat(downloadPath); os.IsNotExist(err) {
                                break
                            }
                            counter++
                        }
                        c.receiveChan <- fmt.Sprintf("File already exists. Saving as: %s", downloadPath)
                    }

                    outFile, err = os.Create(downloadPath)
                    if err != nil {
                        c.receiveChan <- fmt.Sprintf("✗ Error creating file: %s", err.Error())
                        continue
                    }

                    receivingFile = true
                    receivedSize = 0
                    receivedHash.Reset()
                    c.receiveChan <- fmt.Sprintf("Receiving file: %s (%.2f KB)", filename, float64(expectedSize)/1024)
                    if expectedHash != "" {
                        c.receiveChan <- fmt.Sprintf("Expected SHA-256: %s", expectedHash)
                    }
                }
                continue
            }

            if msgStr == "FILE_END" {
                if outFile != nil {
                    outFile.Close()

                    actualHash := hex.EncodeToString(receivedHash.Sum(nil))
                    c.receiveChan <- fmt.Sprintf("✓ File received successfully (%.2f KB)", float64(receivedSize)/1024)
                    c.receiveChan <- fmt.Sprintf("SHA-256: %s", actualHash)

                    if expectedHash != "" {
                        if actualHash == expectedHash {
                            c.receiveChan <- "✓ Hash verification PASSED - file integrity verified!"
                        } else {
                            c.receiveChan <- "✗ Hash verification FAILED - file may be corrupted!"
                            c.receiveChan <- fmt.Sprintf("Expected: %s", expectedHash)
                            c.receiveChan <- fmt.Sprintf("Got:      %s", actualHash)
                        }
                    } else {
                        c.receiveChan <- "⚠ No expected hash provided - cannot verify integrity"
                    }
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
                        c.receiveChan <- fmt.Sprintf("Progress: %.1f%%", progress)
                    }
                }
            }
            continue
        }

        msg, err := c.decrypt(packet.Data)
        if err != nil {
            continue
        }

        msgStr := string(msg)

        if strings.HasPrefix(msgStr, "BEGIN_SEND|") {
            parts := strings.Split(msgStr, "|")
            if len(parts) >= 2 {
                filePath := parts[1]
                c.transferMu.Lock()
                if c.pendingTransfer != nil && c.pendingTransfer.filename != "" {
                    filePath = c.pendingTransfer.filename
                }
                c.transferMu.Unlock()

                if len(parts) == 3 {
                    expectedHash = parts[2]
                }

                c.receiveChan <- "Starting file transfer..."
                go func() {
                    status := c.SendFile(filePath)
                    if status != "" {
                        c.receiveChan <- status
                    }
                }()
            }
            continue
        }

        c.lastSentMu.Lock()
        isOwnMessage := false
        if c.lastSentMsg != "" && strings.Contains(msgStr, c.lastSentMsg) {
            isOwnMessage = true
            c.lastSentMsg = ""
        }
        c.lastSentMu.Unlock()

        if !isOwnMessage {
            // Apply color tags and send to channel
            if strings.HasPrefix(msgStr, "***") {
                c.receiveChan <- c.colorize(c.config.Theme.SystemColor, msgStr)
            } else if strings.Contains(msgStr, "]") && strings.Contains(msgStr, ":") {
                parts := strings.SplitN(msgStr, "]", 2)
                if len(parts) == 2 {
                    timestamp := parts[0] + "]"
                    rest := parts[1]
                    userMsg := strings.SplitN(strings.TrimSpace(rest), ":", 2)
                    if len(userMsg) == 2 {
                        username := userMsg[0]
                        message := userMsg[1]
                        colored := c.colorize(c.config.Theme.TimestampColor, timestamp) + " " +
                            c.colorize(c.config.Theme.UsernameColor, username) + ":" +
                            c.colorize(c.config.Theme.MessageColor, message)
                        c.receiveChan <- colored
                        continue
                    }
                }
                c.receiveChan <- c.colorize(c.config.Theme.SystemColor, msgStr)
            } else {
                c.receiveChan <- c.colorize(c.config.Theme.SystemColor, msgStr)
            }
        }
    }
}