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

// Package client is the QuietRoom protocol 4 client used by the CLI and GUI.
// It owns the connection, chat messages, end-to-end encryption and file
// transfers (with flow control); the user interface only renders Events and
// calls methods.
package client

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/darkfiber-lab/quietroom/e2e"
	"github.com/darkfiber-lab/quietroom/wire"
)

// AccessFileName is the default name of the access file.
const AccessFileName = "quietroom_access.pem"

// DefaultMaxReceive is the largest incoming file accepted unless configured.
const DefaultMaxReceive = 8 << 30 // 8 GiB

// Config configures a connection.
type Config struct {
	Addr        string // host:port
	AccessFile  string // path to quietroom_access.pem
	Username    string
	DownloadDir string // where accepted files are saved
	MaxReceive  int64  // largest incoming file to accept; 0 = DefaultMaxReceive

	Decoys        bool          // send random cover traffic
	DecoyInterval time.Duration // mean interval (randomised ±50%)
	DecoyMin      int           // decoy size range in bytes
	DecoyMax      int

	DialTimeout time.Duration // 0 = 20 s

	// OnEvent receives every event. Calls never overlap, but they come from
	// the client's goroutines: keep the handler short and non-blocking.
	OnEvent func(Event)
}

// Kind identifies an event.
type Kind int

const (
	EvChat         Kind = iota // From, Room ("" = lobby), Text, Time, Self
	EvDM                       // From, To, Text, Time, Self (sent by us)
	EvJoined                   // User, Room ("" = joined the chat), Self, Created, Locked
	EvLeft                     // User, Room ("" = left the chat), Self
	EvInfo                     // Text: help, lists, confirmations
	EvError                    // Text, Code: a refused request
	EvFileOffer                // Transfer: someone offers us a file
	EvFileOffered              // Transfer: our offer reached the recipient
	EvFileStarted              // Transfer: accepted, data is flowing
	EvFileProgress             // Transfer.Done
	EvFileComplete             // Transfer: Path, ActualSHA256, OK (always true for received files: a hash mismatch is EvFileFailed)
	EvFileFailed               // Transfer, Text: declined, cancelled or failed
	EvDisconnected             // Text: reason
)

// Event is delivered to Config.OnEvent.
type Event struct {
	Kind     Kind
	From     string
	To       string
	User     string
	Room     string
	Text     string
	Time     string
	Code     string
	Self     bool
	Created  bool
	Locked   bool      // EvJoined: a password room, end-to-end encrypted
	Transfer *Transfer // a snapshot; safe to keep
}

// Transfer describes a file transfer.
type Transfer struct {
	ID           string
	Outgoing     bool
	Peer         string // the other member
	Name         string
	Size         int64
	SHA256       string // as announced by the sender
	Done         int64  // bytes sent or received
	Path         string // local path (source, or saved file)
	ActualSHA256 string // computed on receipt
	OK           bool   // received file matches SHA256
}

// ErrClosed is returned when the connection is gone.
var ErrClosed = errors.New("not connected")

// Client is one connection to a server.
type Client struct {
	cfg  Config
	conn *tls.Conn
	user string

	ctrl chan []byte // control frames: always sent before bulk frames
	bulk chan []byte // file data frames
	done chan struct{}

	closeOnce sync.Once
	closeWhy  string
	wg        sync.WaitGroup

	emitMu sync.Mutex

	smu sync.Mutex // end-to-end encryption state
	sec *secureState

	mu     sync.Mutex
	refSeq int
	offers map[string]*outgoing // our offers awaiting an ID, by ref
	out    map[string]*outgoing // our transfers, by ID
	in     map[string]*incoming // transfers to us, by ID
}

// Access is a parsed access file.
type Access struct {
	ServerCert *x509.Certificate // pinned server certificate
	Cert       tls.Certificate   // access certificate and private key
	GateKey    []byte            // key for the pre-TLS gate token
}

// TLSConfig returns a client configuration that presents the access key,
// pins the server certificate and carries a fresh gate token. Call it for
// every connection: a token is valid once.
func (a *Access) TLSConfig() *tls.Config {
	pinned := a.ServerCert.Raw
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{a.Cert},
		ServerName:         wire.GateToken(a.GateKey, time.Now()),
		InsecureSkipVerify: true, // replaced by the exact pin below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 || !bytes.Equal(raw[0], pinned) {
				return errPin
			}
			return nil
		},
	}
}

// LoadAccess parses an access file: the pinned server certificate, the
// access certificate and its private key.
func LoadAccess(path string) (*Access, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read access file: %w", err)
	}
	var certs []*pem.Block
	var key *pem.Block
	for rest := data; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		switch b.Type {
		case "CERTIFICATE":
			certs = append(certs, b)
		case "PRIVATE KEY", "EC PRIVATE KEY":
			if key == nil {
				key = b
			}
		}
	}
	if len(certs) != 2 || key == nil {
		return nil, fmt.Errorf("%s is not a valid access file (it must contain the server certificate and the access key) — get the current %s from your server administrator", path, AccessFileName)
	}
	serverCert, err := x509.ParseCertificate(certs[0].Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid server certificate in access file: %w", err)
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(certs[1]), pem.EncodeToMemory(key))
	if err != nil {
		return nil, fmt.Errorf("invalid access key: %w", err)
	}
	return &Access{ServerCert: serverCert, Cert: pair, GateKey: wire.GateKey(key.Bytes)}, nil
}

var errPin = errors.New("server certificate does not match the pinned certificate")

// describe turns TLS and protocol failures into messages for users.
func describe(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case errors.Is(err, errPin) || strings.Contains(msg, errPin.Error()):
		return fmt.Errorf("server certificate does not match your %s — either the server was restarted (get the new file) or someone is intercepting the connection (possible MITM)", AccessFileName)
	case strings.Contains(msg, "remote error: tls") && strings.Contains(msg, "certificate"):
		return fmt.Errorf("access denied — the server rejected your access key; your %s is wrong or outdated (the server may have been restarted)", AccessFileName)
	case errors.Is(err, wire.ErrFrame):
		return fmt.Errorf("the server speaks a different protocol version (QuietRoom 4 clients need a QuietRoom 4 server)")
	}
	return err
}

// silentClose reports whether the handshake failed because the server
// closed the connection without a reply, which is how its gate answers an
// unknown or outdated access file.
func silentClose(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	msg := err.Error()
	return errors.Is(err, io.EOF) || strings.Contains(msg, "connection reset by peer") || strings.Contains(msg, "broken pipe")
}

// LoginError is returned by Dial when the server refuses the login.
type LoginError struct {
	Code string
	Text string
}

func (e *LoginError) Error() string { return e.Text }

// Dial connects, authenticates with the access key and logs in.
func Dial(cfg Config) (*Client, error) {
	if cfg.OnEvent == nil {
		cfg.OnEvent = func(Event) {}
	}
	if cfg.MaxReceive <= 0 {
		cfg.MaxReceive = DefaultMaxReceive
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 20 * time.Second
	}
	if cfg.DownloadDir == "" {
		cfg.DownloadDir = "downloads"
	}
	user := strings.TrimSpace(cfg.Username)
	if !wire.ValidUsername(user) {
		return nil, &LoginError{Code: wire.CodeInvalidUsername, Text: "Invalid username: " + wire.UsernameRules}
	}

	access, err := LoadAccess(cfg.AccessFile)
	if err != nil {
		return nil, err
	}
	id, err := e2e.NewIdentity()
	if err != nil {
		return nil, fmt.Errorf("cannot create session keys: %w", err)
	}
	kx, sk := id.Public().Encode()
	tlsCfg := access.TLSConfig()
	dialer := &net.Dialer{Timeout: cfg.DialTimeout, KeepAlive: 30 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", cfg.Addr, tlsCfg)
	if err != nil {
		if silentClose(err) {
			return nil, fmt.Errorf("the server closed the connection without answering — your %s is wrong or outdated (the server may have been restarted), or this computer's clock is off by more than %d minutes", AccessFileName, wire.GateSkew)
		}
		return nil, fmt.Errorf("TLS connection failed: %w", describe(err))
	}

	// Login: hello -> welcome | error. In TLS 1.3 a rejected access key
	// surfaces on this first read.
	conn.SetDeadline(time.Now().Add(cfg.DialTimeout))
	hello, _ := wire.EncodeMsg(wire.Msg{T: wire.THello, V: wire.Version, User: user, KX: kx, SK: sk})
	if _, err := conn.Write(hello); err != nil {
		conn.Close()
		return nil, describe(err)
	}
	for {
		f, err := wire.Read(conn)
		if err != nil {
			conn.Close()
			return nil, describe(err)
		}
		if f.Type != wire.FrameControl {
			continue
		}
		m, err := wire.DecodeMsg(f.Payload)
		if err != nil {
			conn.Close()
			return nil, describe(err)
		}
		if m.T == wire.TError {
			conn.Close()
			return nil, &LoginError{Code: m.Code, Text: m.Text}
		}
		if m.T == wire.TWelcome {
			break
		}
	}
	conn.SetDeadline(time.Time{})

	c := &Client{
		cfg:    cfg,
		conn:   conn,
		user:   user,
		ctrl:   make(chan []byte, 256),
		bulk:   make(chan []byte, 8),
		done:   make(chan struct{}),
		sec:    newSecureState(id),
		offers: make(map[string]*outgoing),
		out:    make(map[string]*outgoing),
		in:     make(map[string]*incoming),
	}
	c.wg.Add(3)
	go c.writer()
	go c.reader()
	go c.keepalive()
	return c, nil
}

// Username returns the name we are logged in as.
func (c *Client) Username() string { return c.user }

// Done is closed when the connection ends.
func (c *Client) Done() <-chan struct{} { return c.done }

func (c *Client) emit(e Event) {
	c.emitMu.Lock()
	defer c.emitMu.Unlock()
	c.cfg.OnEvent(e)
}

// shutdown closes the connection once, recording why.
func (c *Client) shutdown(why string) {
	c.closeOnce.Do(func() {
		c.closeWhy = why
		close(c.done)
		c.conn.Close()
	})
}

// Close disconnects politely and waits for the client's goroutines.
func (c *Client) Close() {
	if frame, err := wire.EncodeMsg(wire.Msg{T: wire.TQuit}); err == nil {
		select {
		case c.ctrl <- frame:
			// Give the writer a moment to flush the quit message.
			select {
			case <-c.done:
			case <-time.After(200 * time.Millisecond):
			}
		case <-c.done:
		}
	}
	c.shutdown("disconnected")
	c.wg.Wait()
}

func (c *Client) writer() {
	defer c.wg.Done()
	write := func(frame []byte) bool {
		c.conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
		if _, err := c.conn.Write(frame); err != nil {
			c.shutdown("connection lost: " + err.Error())
			return false
		}
		return true
	}
	for {
		// Control frames first, so chat never waits behind file data.
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

func (c *Client) sendFrame(frame []byte) error {
	select {
	case c.ctrl <- frame:
		return nil
	case <-c.done:
		return ErrClosed
	}
}

func (c *Client) send(m wire.Msg) error {
	frame, err := wire.EncodeMsg(m)
	if err != nil {
		return err
	}
	return c.sendFrame(frame)
}

func randBetween(lo, hi int) int {
	if hi <= lo {
		return lo
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
	if err != nil {
		return lo
	}
	return lo + int(n.Int64())
}

// keepalive sends decoy frames: at random intervals around DecoyInterval when
// decoys are enabled, and at least every 60 s so the server does not drop an
// idle but healthy connection.
func (c *Client) keepalive() {
	defer c.wg.Done()
	mean := 60 * time.Second
	if c.cfg.Decoys && c.cfg.DecoyInterval > 0 && c.cfg.DecoyInterval < mean {
		mean = c.cfg.DecoyInterval
	}
	for {
		wait := time.Duration(randBetween(int(mean/2/time.Millisecond), int(mean*3/2/time.Millisecond))) * time.Millisecond
		if !c.cfg.Decoys && wait > 60*time.Second {
			wait = 60 * time.Second
		}
		select {
		case <-c.done:
			return
		case <-time.After(wait):
		}
		size := 0
		if c.cfg.Decoys {
			size = randBetween(c.cfg.DecoyMin, c.cfg.DecoyMax)
		}
		noise := make([]byte, randBetween(0, 64))
		rand.Read(noise)
		frame, err := wire.EncodeSize(wire.FrameDecoy, noise, size)
		if err != nil {
			continue
		}
		select {
		case c.ctrl <- frame:
		default: // queue busy: real traffic is flowing anyway
		}
	}
}

// ── Requests ────────────────────────────────────────────────────────

// SendMsg sends a raw control message. Low level: the other methods are
// the normal API; this exists for tools and tests.
func (c *Client) SendMsg(m wire.Msg) error { return c.send(m) }

// Chat sends a message to the lobby (room "") or a room we are in. Messages
// to password rooms are end-to-end encrypted.
func (c *Client) Chat(room, text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	if len(text) > wire.MaxTextBytes {
		return fmt.Errorf("message too long (max %d bytes)", wire.MaxTextBytes)
	}
	if room != "" {
		c.smu.Lock()
		r := c.sec.rooms[room]
		_, joining := c.sec.joining[room]
		if r != nil {
			defer c.smu.Unlock()
			return c.sendSecureChat(r, text)
		}
		c.smu.Unlock()
		if joining {
			return fmt.Errorf("still joining %s; try again in a moment", room)
		}
	}
	return c.send(wire.Msg{T: wire.TChat, Room: room, Text: text})
}

// DM sends an end-to-end encrypted private message.
func (c *Client) DM(to, text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	if len(text) > wire.MaxTextBytes {
		return fmt.Errorf("message too long (max %d bytes)", wire.MaxTextBytes)
	}
	return c.sendDM(to, text)
}

// Join joins or creates a room. With a password the room is end-to-end
// encrypted: the password never leaves this computer (deriving the keys
// takes a moment). Success is reported by an EvJoined event with Self set;
// a refusal by EvError.
func (c *Client) Join(room, password string) error {
	password = strings.TrimSpace(password)
	if len(password) > wire.MaxPasswordBytes {
		return fmt.Errorf("password too long (max %d bytes)", wire.MaxPasswordBytes)
	}
	m := wire.Msg{T: wire.TJoin, Room: room}
	if password != "" {
		if !wire.ValidRoomName(room) {
			return c.send(m) // let the server explain the naming rules
		}
		m.VF = c.prepareJoin(room, password)
	}
	return c.send(m)
}

// Leave leaves a room.
func (c *Client) Leave(room string) error {
	return c.send(wire.Msg{T: wire.TLeave, Room: room})
}

// Request asks for help, rooms, users or members (room "#x" or "lobby");
// the answer arrives as EvInfo.
func (c *Client) Request(kind, room string) error {
	switch kind {
	case wire.THelp, wire.TRooms, wire.TUsers, wire.TMembers:
	default:
		return fmt.Errorf("unknown request %q", kind)
	}
	return c.send(wire.Msg{T: kind, Room: room})
}

// Command runs a slash command or, for plain text, sends a chat message to
// room ("" = lobby). /file hashes the file first, so it can take a while.
func (c *Client) Command(line, room string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	if !strings.HasPrefix(line, "/") {
		return c.Chat(room, line)
	}
	cmd, err := wire.ParseCommand(line)
	if err != nil {
		return err
	}
	switch cmd.Name {
	case "help":
		return c.Request(wire.THelp, "")
	case "rooms":
		return c.Request(wire.TRooms, "")
	case "users":
		return c.Request(wire.TUsers, "")
	case "members":
		return c.Request(wire.TMembers, cmd.Args[0])
	case "msg":
		return c.DM(cmd.Args[0], cmd.Rest)
	case "verify":
		text, err := c.VerifyText(cmd.Args[0])
		if err != nil {
			return err
		}
		c.emit(Event{Kind: EvInfo, Text: text})
		return nil
	case "join":
		return c.Join(cmd.Args[0], cmd.Rest)
	case "leave":
		return c.Leave(cmd.Args[0])
	case "file":
		_, err := c.OfferFile(cmd.Args[0], cmd.Rest)
		return err
	case "accept":
		return c.AcceptFile(cmd.Args[0])
	case "decline":
		return c.DeclineFile(cmd.Args[0])
	case "cancel":
		return c.CancelFile(cmd.Args[0])
	case "quit":
		c.Close()
		return nil
	}
	return fmt.Errorf("Unknown command: /%s", cmd.Name)
}

// ── Receiving ───────────────────────────────────────────────────────

func (c *Client) reader() {
	defer c.wg.Done()
	defer func() {
		c.failAll("connection closed")
		why := c.closeWhy
		if why == "" {
			why = "connection lost"
		}
		c.emit(Event{Kind: EvDisconnected, Text: why})
	}()
	for {
		f, err := wire.Read(c.conn)
		if err != nil {
			reason := "connection to server lost"
			if errors.Is(err, wire.ErrFrame) {
				reason = "protocol error: " + err.Error()
			}
			c.shutdown(reason)
			return
		}
		switch f.Type {
		case wire.FrameDecoy:
		case wire.FrameData:
			c.handleData(f.Payload)
		case wire.FrameControl:
			m, err := wire.DecodeMsg(f.Payload)
			if err != nil {
				c.shutdown("protocol error: " + err.Error())
				return
			}
			c.handleMsg(m)
		}
	}
}

func (c *Client) handleMsg(m wire.Msg) {
	switch m.T {
	case wire.TChat:
		if m.CT != "" {
			c.handleSecureChat(m)
			return
		}
		if m.Room != "" && c.IsSecureRoom(m.Room) {
			return // a password room carries only encrypted messages
		}
		// The server already cleans text; cleaning again protects against
		// a server that does not.
		c.emit(Event{Kind: EvChat, From: m.From, Room: m.Room, Text: wire.CleanText(m.Text), Time: m.Time, Self: m.From == c.user})
	case wire.TDM:
		c.handleDM(m)
	case wire.TPeer:
		c.addPeer(m.User, m.KX, m.SK)
	case wire.TRoomHello:
		c.handleRoomHello(m)
	case wire.TRoomKey:
		c.handleRoomKey(m)
	case wire.TJoined:
		self := m.User == c.user
		locked := m.Locked
		if m.Room == "" && !self {
			c.addPeer(m.User, m.KX, m.SK)
		}
		if m.Room != "" && self {
			var leave bool
			var note string
			locked, leave, note = c.joinedSecure(m.Room, m.Locked)
			if note != "" {
				kind := EvInfo
				if leave {
					kind = EvError
				}
				c.emit(Event{Kind: kind, Text: note})
			}
			if leave {
				c.send(wire.Msg{T: wire.TLeave, Room: m.Room})
			}
		}
		c.emit(Event{Kind: EvJoined, User: m.User, Room: m.Room, Self: self, Created: m.Created, Locked: locked})
	case wire.TLeft:
		self := m.User == c.user
		switch {
		case m.Room == "" && !self:
			c.removePeer(m.User)
		case m.Room != "" && self:
			c.leftSecure(m.Room)
		case m.Room != "":
			c.memberLeft(m.Room, m.User)
		}
		c.emit(Event{Kind: EvLeft, User: m.User, Room: m.Room, Self: self})
	case wire.TInfo:
		c.emit(Event{Kind: EvInfo, Text: m.Text})
	case wire.TError:
		if m.Ref != "" && c.failOffer(m.Ref, m.Text) {
			return
		}
		c.emit(Event{Kind: EvError, Text: m.Text, Code: m.Code})
	case wire.TFileOffer:
		c.handleOffer(m)
	case wire.TFileOffered:
		c.handleOffered(m)
	case wire.TFileAccept, wire.TFileCredit:
		c.handleCredit(m)
	case wire.TFileDecline:
		c.finishOut(m.ID, false, m.User+" declined the file")
	case wire.TFileCancel:
		reason := m.Text
		if reason == "" {
			reason = "transfer cancelled"
		}
		c.finishOut(m.ID, false, reason)
		c.finishIn(m.ID, reason)
	case wire.TFileEnd:
		c.completeIn(m.ID)
	case wire.TFileDone:
		c.finishOut(m.ID, true, "")
	}
}

func nowClock() string { return time.Now().Format("15:04:05") }
