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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/darkfiber-lab/quietroom/client"
	"github.com/darkfiber-lab/quietroom/wire"
	"github.com/gen2brain/beeep"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// ServerProfile stores a saved server configuration
type ServerProfile struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	CertFile string `json:"cert_file"`
	Username string `json:"username"`
}

// AppConfig is persisted to disk
type AppConfig struct {
	Profiles      []ServerProfile `json:"profiles"`
	LastProfile   int             `json:"last_profile"`
	SoundEnabled  bool            `json:"sound_enabled"`
	DecoyEnabled  bool            `json:"decoy_enabled"`
	DecoyInterval int             `json:"decoy_interval"`
	DecoyMinBytes int             `json:"decoy_min_bytes"`
	DecoyMaxBytes int             `json:"decoy_max_bytes"`
	DownloadDir   string          `json:"download_dir"`
	MaxReceiveMB  int64           `json:"max_receive_mb"`
}

func defaultConfig() AppConfig {
	home, _ := os.UserHomeDir()
	return AppConfig{
		Profiles: []ServerProfile{
			{
				Name:     "Default Server",
				Host:     "localhost",
				Port:     37842,
				CertFile: "quietroom_access.pem",
				Username: "User",
			},
		},
		LastProfile:   0,
		SoundEnabled:  true,
		DecoyEnabled:  true,
		DecoyInterval: 30,
		DecoyMinBytes: 100,
		DecoyMaxBytes: 500,
		DownloadDir:   filepath.Join(home, "Downloads", "QuietRoom"),
	}
}

// App is the main application struct exposed to Wails
type App struct {
	ctx    context.Context
	config AppConfig

	client      *client.Client
	clientMu    sync.RWMutex
	connected   bool
	username    string
	currentRoom string

	pickedSendPath string // last path chosen via PickFileToSend
	pickMu         sync.Mutex

	// emit sends an event to the frontend (replaced in tests).
	emit func(ctx context.Context, name string, data ...interface{})
}

// NewApp creates the application instance
func NewApp() *App {
	return &App{emit: runtime.EventsEmit}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.config = a.loadConfig()
}

func (a *App) shutdown(ctx context.Context) {
	a.clientMu.RLock()
	c := a.client
	a.clientMu.RUnlock()
	if c != nil {
		c.Close()
	}
}

// ─────────────────────────────────────────────
// Config management
// ─────────────────────────────────────────────

func (a *App) configPath() string {
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "QuietRoom", "config.json")
}

func (a *App) loadConfig() AppConfig {
	path := a.configPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return defaultConfig()
	}
	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return defaultConfig()
	}
	if cfg.DownloadDir == "" {
		home, _ := os.UserHomeDir()
		cfg.DownloadDir = filepath.Join(home, "Downloads", "QuietRoom")
	}
	return cfg
}

func (a *App) saveConfig() error {
	path := a.configPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(a.config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// GetConfig returns the current config to the frontend
func (a *App) GetConfig() AppConfig {
	return a.config
}

// SaveConfig saves updated config from the frontend
func (a *App) SaveConfig(cfg AppConfig) error {
	a.config = cfg
	return a.saveConfig()
}

// ─────────────────────────────────────────────
// Connection
// ─────────────────────────────────────────────

// Connect establishes a connection using the given profile index
func (a *App) Connect(profileIndex int) error {
	if profileIndex < 0 || profileIndex >= len(a.config.Profiles) {
		return fmt.Errorf("invalid profile index")
	}
	p := a.config.Profiles[profileIndex]
	if err := a.dial(p.Host, p.Port, p.CertFile, p.Username); err != nil {
		return err
	}
	a.config.LastProfile = profileIndex
	a.saveConfig()
	return nil
}

// ConnectCustom connects to a server with explicitly provided parameters
func (a *App) ConnectCustom(host string, port int, certFile string, username string) error {
	return a.dial(host, port, certFile, username)
}

func (a *App) dial(host string, port int, certFile string, username string) error {
	a.Disconnect()

	maxReceive := a.config.MaxReceiveMB << 20
	c, err := client.Dial(client.Config{
		Addr:          net.JoinHostPort(host, strconv.Itoa(port)),
		AccessFile:    certFile,
		Username:      username,
		DownloadDir:   a.config.DownloadDir,
		MaxReceive:    maxReceive,
		Decoys:        a.config.DecoyEnabled,
		DecoyInterval: time.Duration(a.config.DecoyInterval) * time.Second,
		DecoyMin:      a.config.DecoyMinBytes,
		DecoyMax:      a.config.DecoyMaxBytes,
		OnEvent:       a.handleEvent,
	})
	if err != nil {
		return err
	}

	a.clientMu.Lock()
	a.client = c
	a.connected = true
	a.username = c.Username()
	a.currentRoom = ""
	a.clientMu.Unlock()

	// Emitted here so the frontend receives it after the Connect promise resolved
	a.emit(a.ctx, "connected", map[string]interface{}{
		"address":  fmt.Sprintf("%s:%d", host, port),
		"username": c.Username(),
	})
	return nil
}

// Disconnect disconnects from the current server
func (a *App) Disconnect() {
	a.clientMu.Lock()
	c := a.client
	a.client = nil
	a.connected = false
	a.clientMu.Unlock()
	if c != nil {
		c.Close()
	}
}

// IsConnected returns whether the client is connected
func (a *App) IsConnected() bool {
	a.clientMu.RLock()
	defer a.clientMu.RUnlock()
	return a.connected && a.client != nil
}

func (a *App) current() (*client.Client, error) {
	a.clientMu.RLock()
	defer a.clientMu.RUnlock()
	if a.client == nil {
		return nil, fmt.Errorf("not connected")
	}
	return a.client, nil
}

// ─────────────────────────────────────────────
// Messaging
// ─────────────────────────────────────────────

// SendMessage sends a text message to the lobby or current room
func (a *App) SendMessage(text string) error {
	c, err := a.current()
	if err != nil {
		return err
	}
	return c.Chat(a.GetCurrentRoom(), text)
}

// SendDM sends a direct message to a specific user
func (a *App) SendDM(recipient string, message string) error {
	c, err := a.current()
	if err != nil {
		return err
	}
	return c.DM(recipient, message)
}

// JoinRoom joins a room with optional password. The current room changes
// only when the server confirms the join (our own room_joined event).
func (a *App) JoinRoom(room string, password string) error {
	if !strings.HasPrefix(room, "#") {
		room = "#" + room
	}
	c, err := a.current()
	if err != nil {
		return err
	}
	return c.Join(room, password)
}

func (a *App) SetCurrentRoom(room string) {
	a.clientMu.Lock()
	a.currentRoom = room
	a.clientMu.Unlock()
}

// LeaveRoom leaves the specified room
func (a *App) LeaveRoom(room string) error {
	c, err := a.current()
	if err != nil {
		return err
	}
	if err := c.Leave(room); err != nil {
		return err
	}
	a.clientMu.Lock()
	if a.currentRoom == room {
		a.currentRoom = ""
	}
	a.clientMu.Unlock()
	return nil
}

func (a *App) request(kind, room string) error {
	c, err := a.current()
	if err != nil {
		return err
	}
	return c.Request(kind, room)
}

// ListRooms requests the room list from the server
func (a *App) ListRooms() error { return a.request(wire.TRooms, "") }

// ListUsers requests the user list from the server
func (a *App) ListUsers() error { return a.request(wire.TUsers, "") }

// RequestRoomList requests the room list (answered as a system message)
func (a *App) RequestRoomList() error { return a.request(wire.TRooms, "") }

// RequestUserList requests the user list
func (a *App) RequestUserList() error { return a.request(wire.TUsers, "") }

// RequestMemberList requests the members of a room or "lobby"
func (a *App) RequestMemberList(target string) error { return a.request(wire.TMembers, target) }

// SendCommand runs a slash command typed by the user.
func (a *App) SendCommand(cmd string) error {
	c, err := a.current()
	if err != nil {
		return err
	}
	// Files are only sent after picking them in the native dialog, so
	// frontend content can never name an arbitrary local file.
	if parsed, perr := wire.ParseCommand(cmd); perr == nil && parsed.Name == "file" {
		return fmt.Errorf("use the Send File button to send files")
	}
	return c.Command(cmd, a.GetCurrentRoom())
}

// ─────────────────────────────────────────────
// File transfers
// ─────────────────────────────────────────────

// PickFileToSend opens a native file picker for choosing a file to send.
// Only a path chosen here can be passed to InitiateFileTransfer, so the
// frontend can never name an arbitrary local file on its own.
func (a *App) PickFileToSend() (string, error) {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select file to send",
	})
	if err != nil {
		return "", err
	}
	a.pickMu.Lock()
	a.pickedSendPath = path
	a.pickMu.Unlock()
	return path, nil
}

// PickFile opens a native file picker (used to choose the access file).
func (a *App) PickFile() (string, error) {
	return runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select access file",
	})
}

// InitiateFileTransfer offers the picked file to a member.
func (a *App) InitiateFileTransfer(recipient string, filePath string) error {
	a.pickMu.Lock()
	allowed := filePath != "" && filePath == a.pickedSendPath
	a.pickedSendPath = ""
	a.pickMu.Unlock()
	if !allowed {
		return fmt.Errorf("file must be selected with the file picker")
	}
	c, err := a.current()
	if err != nil {
		return err
	}
	_, err = c.OfferFile(recipient, filePath)
	return err
}

// AcceptFileTransfer accepts an incoming file transfer
func (a *App) AcceptFileTransfer(transferID string) error {
	c, err := a.current()
	if err != nil {
		return err
	}
	return c.AcceptFile(transferID)
}

// DeclineFileTransfer declines an incoming file transfer
func (a *App) DeclineFileTransfer(transferID string) error {
	c, err := a.current()
	if err != nil {
		return err
	}
	return c.DeclineFile(transferID)
}

// CancelFileTransfer stops a running transfer in either direction
func (a *App) CancelFileTransfer(transferID string) error {
	c, err := a.current()
	if err != nil {
		return err
	}
	return c.CancelFile(transferID)
}

// ─────────────────────────────────────────────
// Protocol events -> frontend events
// ─────────────────────────────────────────────

func (a *App) handleEvent(e client.Event) {
	ts := e.Time
	if ts == "" {
		ts = time.Now().Format("15:04:05")
	}
	switch e.Kind {
	case client.EvDisconnected:
		a.clientMu.Lock()
		a.connected = false
		a.clientMu.Unlock()
		a.emit(a.ctx, "disconnected", nil)

	case client.EvChat:
		a.emit(a.ctx, "message", map[string]interface{}{
			"timestamp": ts,
			"username":  e.From,
			"text":      e.Text,
			"room":      e.Room,
			"isOwn":     e.Self,
		})
		if !e.Self {
			a.notify("New message from " + e.From)
		}

	case client.EvDM:
		partner, name := e.From, e.From
		if e.Self {
			partner, name = e.To, "You"
		}
		a.emit(a.ctx, "dm", map[string]interface{}{
			"timestamp": ts,
			"username":  name,
			"text":      e.Text,
			"partner":   partner,
			"isOwn":     e.Self,
		})
		if !e.Self {
			a.notify("DM from " + e.From)
		}

	case client.EvInfo, client.EvError:
		a.emit(a.ctx, "system_message", map[string]interface{}{
			"timestamp": ts,
			"text":      e.Text,
		})

	case client.EvJoined:
		if e.Room == "" {
			a.emit(a.ctx, "user_joined", map[string]string{"username": e.User})
			return
		}
		if e.Self {
			a.clientMu.Lock()
			a.currentRoom = e.Room // server confirmed our own join
			a.clientMu.Unlock()
		}
		a.emit(a.ctx, "room_joined", map[string]string{"username": e.User, "room": e.Room})

	case client.EvLeft:
		if e.Room == "" {
			a.emit(a.ctx, "user_left", map[string]string{"username": e.User})
			return
		}
		if e.Self {
			a.clientMu.Lock()
			if a.currentRoom == e.Room {
				a.currentRoom = ""
			}
			a.clientMu.Unlock()
		}
		a.emit(a.ctx, "room_left", map[string]string{"username": e.User, "room": e.Room})

	case client.EvFileOffer:
		t := e.Transfer
		a.emit(a.ctx, "file_request", map[string]interface{}{
			"transferID":   t.ID,
			"filename":     t.Name,
			"filesize":     t.Size,
			"expectedHash": t.SHA256,
			"senderName":   t.Peer,
		})
		a.notify("File transfer request from " + t.Peer)

	case client.EvFileStarted:
		t := e.Transfer
		if !t.Outgoing {
			a.emit(a.ctx, "file_start", map[string]interface{}{
				"filename":     t.Name,
				"filesize":     t.Size,
				"expectedHash": t.SHA256,
			})
		}

	case client.EvFileProgress:
		t := e.Transfer
		pct := float64(t.Done) / float64(t.Size) * 100
		if t.Outgoing {
			a.emit(a.ctx, "file_progress", map[string]interface{}{
				"filename":   t.Name,
				"bytesSent":  t.Done,
				"totalBytes": t.Size,
				"percent":    pct,
				"done":       false,
			})
		} else {
			a.emit(a.ctx, "file_receive_progress", map[string]interface{}{
				"filename": t.Name,
				"received": t.Done,
				"total":    t.Size,
				"percent":  pct,
			})
		}

	case client.EvFileComplete:
		t := e.Transfer
		if t.Outgoing {
			a.emit(a.ctx, "file_progress", map[string]interface{}{
				"filename":   t.Name,
				"bytesSent":  t.Size,
				"totalBytes": t.Size,
				"percent":    100,
				"done":       true,
				"hash":       t.SHA256,
			})
			return
		}
		a.emit(a.ctx, "file_complete", map[string]interface{}{
			"filename":     t.Name,
			"downloadPath": t.Path,
			"actualHash":   t.ActualSHA256,
			"expectedHash": t.SHA256,
			"hashMatch":    t.OK,
		})
		a.notify("File received: " + t.Name) // a hash mismatch arrives as EvFileFailed

	case client.EvFileFailed:
		name := ""
		if e.Transfer != nil {
			name = e.Transfer.Name
		}
		a.emit(a.ctx, "file_failed", map[string]interface{}{
			"filename": name,
			"reason":   e.Text,
		})
	}
}

// ─────────────────────────────────────────────
// Sound notifications
// ─────────────────────────────────────────────

func (a *App) notify(message string) {
	if !a.config.SoundEnabled {
		return
	}
	go func() {
		beeep.Notify("QuietRoom", message, "")
		if goruntime.GOOS == "darwin" {
			exec.Command("afplay", "/System/Library/Sounds/Ping.aiff").Run()
		}
	}()
}

// ─────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────

// GetUsername returns the currently connected username
func (a *App) GetUsername() string {
	a.clientMu.RLock()
	defer a.clientMu.RUnlock()
	return a.username
}

// GetCurrentRoom returns the currently active room
func (a *App) GetCurrentRoom() string {
	a.clientMu.RLock()
	defer a.clientMu.RUnlock()
	return a.currentRoom
}

// OpenDownloadDir opens the download directory in the OS file manager
func (a *App) OpenDownloadDir() {
	runtime.BrowserOpenURL(a.ctx, "file://"+a.config.DownloadDir)
}
