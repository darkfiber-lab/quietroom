
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
	goruntime "runtime"
    "os/exec"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"quietroom-gui/protocol"

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
	Profiles         []ServerProfile `json:"profiles"`
	LastProfile      int             `json:"last_profile"`
	SoundEnabled     bool            `json:"sound_enabled"`
	DecoyEnabled     bool            `json:"decoy_enabled"`
	DecoyInterval    int             `json:"decoy_interval"`
	DecoyMinBytes    int             `json:"decoy_min_bytes"`
	DecoyMaxBytes    int             `json:"decoy_max_bytes"`
	DownloadDir      string          `json:"download_dir"`
}

func defaultConfig() AppConfig {
	home, _ := os.UserHomeDir()
	return AppConfig{
		Profiles: []ServerProfile{
			{
				Name:     "Default Server",
				Host:     "localhost",
				Port:     37842,
				CertFile: "chat_public.pem",
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

	client      *protocol.Client
	clientMu    sync.RWMutex
	connected   bool
	username    string
	currentRoom string

	// File receive state
	fileReceive   *protocol.FileReceiveState
	fileReceiveMu sync.Mutex

	// Pending file send state (path stored while waiting for BEGIN_SEND)
	pendingFilePath string
	pendingFileMu   sync.Mutex

	decoyStop chan struct{}
}

// NewApp creates the application instance
func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.config = a.loadConfig()
}

func (a *App) shutdown(ctx context.Context) {
	a.clientMu.RLock()
	client := a.client
	a.clientMu.RUnlock()
	if client != nil {
		client.Disconnect()
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

	a.clientMu.Lock()
	if a.client != nil {
		a.client.Disconnect()
		a.client = nil
	}
	a.clientMu.Unlock()

	profile := a.config.Profiles[profileIndex]
	client := protocol.NewClient(a.handleProtocolEvent)

	if err := client.Connect(profile.Host, profile.Port, profile.CertFile, profile.Username); err != nil {
		return err
	}

	a.clientMu.Lock()
	a.client = client
	a.connected = true
	a.username = profile.Username
	a.currentRoom = ""
	a.clientMu.Unlock()

	a.config.LastProfile = profileIndex
	a.saveConfig()

	if a.config.DecoyEnabled {
		a.startDecoy()
	}

	return nil
}

// ConnectCustom connects to a server with explicitly provided parameters
func (a *App) ConnectCustom(host string, port int, certFile string, username string) error {
	a.clientMu.Lock()
	if a.client != nil {
		a.client.Disconnect()
		a.client = nil
	}
	a.clientMu.Unlock()

	client := protocol.NewClient(a.handleProtocolEvent)
	if err := client.Connect(host, port, certFile, username); err != nil {
		return err
	}

	a.clientMu.Lock()
	a.client = client
	a.connected = true
	a.username = username
	a.currentRoom = ""
	a.clientMu.Unlock()

	if a.config.DecoyEnabled {
		a.startDecoy()
	}
	// Emit connected event explicitly from here so the frontend
    // receives it after Connect() has returned and the JS promise resolved
    runtime.EventsEmit(a.ctx, "connected", map[string]interface{}{
        "address":  fmt.Sprintf("%s:%d", host, port),
        "username": username,
    })

	return nil
}

// Disconnect disconnects from the current server
func (a *App) Disconnect() {
	a.stopDecoy()
	a.clientMu.Lock()
	client := a.client
	a.client = nil
	a.connected = false
	a.clientMu.Unlock()
	if client != nil {
		client.Disconnect()
	}
}

// IsConnected returns whether the client is connected
func (a *App) IsConnected() bool {
	a.clientMu.RLock()
	defer a.clientMu.RUnlock()
	return a.connected && a.client != nil && a.client.IsConnected()
}

// ─────────────────────────────────────────────
// Messaging
// ─────────────────────────────────────────────

// SendMessage sends a text message to the lobby or current room
func (a *App) SendMessage(text string) error {
	a.clientMu.RLock()
	currentRoom := a.currentRoom
	a.clientMu.RUnlock()
	if currentRoom != "" {
		text = fmt.Sprintf("[%s] %s", currentRoom, text)
	}
	return a.sendText(text)
}

// SendDM sends a direct message to a specific user
func (a *App) SendDM(recipient string, message string) error {
	return a.sendText(fmt.Sprintf("/msg %s %s", recipient, message))
}

// JoinRoom joins a room with optional password
func (a *App) JoinRoom(room string, password string) error {
	if !strings.HasPrefix(room, "#") {
		room = "#" + room
	}
	cmd := fmt.Sprintf("/join %s", room)
	if password != "" {
		cmd += " " + password
	}
	if err := a.sendText(cmd); err != nil {
		return err
	}
	// Only update currentRoom — do not send any leave/join for routing
	a.clientMu.Lock()
	a.currentRoom = room
	a.clientMu.Unlock()
	return nil
}


func (a *App) SetCurrentRoom(room string) {
    a.clientMu.Lock()
    a.currentRoom = room
    a.clientMu.Unlock()
}

// LeaveRoom leaves the specified room
func (a *App) LeaveRoom(room string) error {
    if err := a.sendText(fmt.Sprintf("/leave %s", room)); err != nil {
        return err
    }
    a.clientMu.Lock()
    if a.currentRoom == room {
        a.currentRoom = ""
    }
    a.clientMu.Unlock()
    return nil
}

// ListRooms requests the room list from the server
func (a *App) ListRooms() error {
	return a.sendText("/rooms")
}

// ListUsers requests the user list from the server
func (a *App) ListUsers() error {
	return a.sendText("/users")
}

// SendCommand sends a raw command string (for advanced use)
func (a *App) SendCommand(cmd string) error {
	return a.sendText(cmd)
}

func (a *App) sendText(text string) error {
	a.clientMu.RLock()
	client := a.client
	a.clientMu.RUnlock()
	if client == nil {
		return fmt.Errorf("not connected")
	}
	return client.SendText(text)
}

// ─────────────────────────────────────────────
// File transfers
// ─────────────────────────────────────────────

// InitiateFileTransfer starts the file transfer handshake
func (a *App) InitiateFileTransfer(recipient string, filePath string) error {
	hash, err := protocol.ComputeFileHash(filePath)
	if err != nil {
		return fmt.Errorf("cannot hash file: %w", err)
	}

	basename := filepath.Base(filePath)
	cmd := fmt.Sprintf("/file %s %s %s", recipient, basename, hash)

	a.pendingFileMu.Lock()
	a.pendingFilePath = filePath
	a.pendingFileMu.Unlock()

	return a.sendText(cmd)
}

// AcceptFileTransfer accepts an incoming file transfer
func (a *App) AcceptFileTransfer(transferID string) error {
	return a.sendText(fmt.Sprintf("/accept %s", transferID))
}

// DeclineFileTransfer declines an incoming file transfer
func (a *App) DeclineFileTransfer(transferID string) error {
	return a.sendText(fmt.Sprintf("/decline %s", transferID))
}

// PickFile opens a native file picker and returns the selected path
func (a *App) PickFile() (string, error) {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select file to send",
	})
	if err != nil {
		return "", err
	}
	return path, nil
}

// ─────────────────────────────────────────────
// Protocol event handler
// ─────────────────────────────────────────────

func (a *App) handleProtocolEvent(evt protocol.Event) {
	switch evt.Type {

	case protocol.EvtConnected:
		// Handled by ConnectCustom directly — do nothing here
		// runtime.EventsEmit(a.ctx, "connected", map[string]interface{}{
		// 	"address": evt.Text,
		// 	"username": a.username,
		// })

	case protocol.EvtDisconnected:
		a.clientMu.Lock()
		a.connected = false
		a.clientMu.Unlock()
		a.stopDecoy()
		runtime.EventsEmit(a.ctx, "disconnected", nil)

	case protocol.EvtError:
		runtime.EventsEmit(a.ctx, "error", map[string]string{"message": evt.Text})

	case protocol.EvtMessage:
		if msg, ok := evt.Payload.(protocol.ChatMessage); ok {
			runtime.EventsEmit(a.ctx, "message", map[string]interface{}{
				"timestamp": msg.Timestamp,
				"username":  msg.Username,
				"text":      msg.Text,
				"room":      msg.Room,
				"isOwn":     msg.IsOwn,
			})
			if !msg.IsOwn {
				a.notify("New message from " + msg.Username)
			}
		}

	case protocol.EvtPrivateMessage:
		if msg, ok := evt.Payload.(protocol.ChatMessage); ok {
			// Derive the conversation partner from sender or the __self__ prefix
			partner := evt.Sender
			if strings.HasPrefix(partner, "__self__") {
				partner = strings.TrimPrefix(partner, "__self__")
			}
			runtime.EventsEmit(a.ctx, "dm", map[string]interface{}{
				"timestamp": msg.Timestamp,
				"username":  msg.Username,
				"text":      msg.Text,
				"partner":   partner,
				"isOwn":     msg.IsOwn,
			})
			if !msg.IsOwn {
				a.notify("DM from " + msg.Username)
			}
		}

	case protocol.EvtSystemMessage:
		if msg, ok := evt.Payload.(protocol.ChatMessage); ok {
			runtime.EventsEmit(a.ctx, "system_message", map[string]interface{}{
				"timestamp": msg.Timestamp,
				"text":      msg.Text,
			})
		}

	case protocol.EvtUserJoined:
		runtime.EventsEmit(a.ctx, "user_joined", map[string]string{
			"username": evt.Sender,
		})

	case protocol.EvtUserLeft:
		runtime.EventsEmit(a.ctx, "user_left", map[string]string{
			"username": evt.Sender,
		})

	case protocol.EvtRoomJoined:
		runtime.EventsEmit(a.ctx, "room_joined", map[string]string{
			"username": evt.Sender,
			"room":     evt.Room,
		})

	case protocol.EvtRoomLeft:
		runtime.EventsEmit(a.ctx, "room_left", map[string]string{
			"username": evt.Sender,
			"room":     evt.Room,
		})

	case protocol.EvtFileRequest:
		if payload, ok := evt.Payload.(protocol.FileRequestPayload); ok {
			runtime.EventsEmit(a.ctx, "file_request", map[string]string{
				"transferID":   payload.TransferID,
				"filename":     payload.Filename,
				"expectedHash": payload.ExpectedHash,
				"senderName":   payload.SenderName,
			})
			a.notify("File transfer request from " + payload.SenderName)
		}

	case protocol.EvtFileBeginSend:
		// Server confirmed accept — start sending the file
		a.pendingFileMu.Lock()
		filePath := a.pendingFilePath
		a.pendingFilePath = ""
		a.pendingFileMu.Unlock()

		if filePath == "" {
			runtime.EventsEmit(a.ctx, "error", map[string]string{
				"message": "Received BEGIN_SEND with no pending file",
			})
			return
		}

		go func() {
			a.clientMu.RLock()
			client := a.client
			a.clientMu.RUnlock()
			if client == nil {
				return
			}

			err := client.SendFile(filePath, func(p protocol.FileTransferProgress) {
				runtime.EventsEmit(a.ctx, "file_progress", map[string]interface{}{
					"filename":   p.Filename,
					"bytesSent":  p.BytesSent,
					"totalBytes": p.TotalBytes,
					"percent":    p.Percent,
					"done":       p.Done,
					"hash":       p.Hash,
				})
			})
			if err != nil {
				runtime.EventsEmit(a.ctx, "error", map[string]string{
					"message": "File transfer failed: " + err.Error(),
				})
			}
		}()

	case protocol.EvtFileStart:
		if payload, ok := evt.Payload.(protocol.FileStartPayload); ok {
			state, err := protocol.NewFileReceiveState(payload, a.config.DownloadDir)
			if err != nil {
				runtime.EventsEmit(a.ctx, "error", map[string]string{
					"message": "Cannot prepare file receive: " + err.Error(),
				})
				return
			}
			a.fileReceiveMu.Lock()
			a.fileReceive = state
			a.fileReceiveMu.Unlock()
			runtime.EventsEmit(a.ctx, "file_start", map[string]interface{}{
				"filename":     payload.Filename,
				"filesize":     payload.Filesize,
				"expectedHash": payload.ExpectedHash,
			})
		}

	case protocol.EvtFileChunk:
		if data, ok := evt.Payload.([]byte); ok {
			a.fileReceiveMu.Lock()
			state := a.fileReceive
			a.fileReceiveMu.Unlock()
			if state != nil {
				if err := state.Write(data); err != nil {
					runtime.EventsEmit(a.ctx, "error", map[string]string{
						"message": "Error writing received file: " + err.Error(),
					})
				} else {
					pct := 0.0
					if state.Filesize > 0 {
						pct = float64(state.ReceivedSize) / float64(state.Filesize) * 100
					}
					runtime.EventsEmit(a.ctx, "file_receive_progress", map[string]interface{}{
						"filename": state.Filename,
						"received": state.ReceivedSize,
						"total":    state.Filesize,
						"percent":  pct,
					})
				}
			}
		}

	case protocol.EvtFileEnd:
		a.fileReceiveMu.Lock()
		state := a.fileReceive
		a.fileReceive = nil
		a.fileReceiveMu.Unlock()
		if state != nil {
			actualHash, hashMatch, _ := state.Finish()
			runtime.EventsEmit(a.ctx, "file_complete", map[string]interface{}{
				"filename":     state.Filename,
				"downloadPath": state.DownloadPath,
				"actualHash":   actualHash,
				"expectedHash": state.ExpectedHash,
				"hashMatch":    hashMatch,
			})
			if hashMatch {
				a.notify("File received: " + state.Filename)
			} else {
				a.notify("File received but hash FAILED: " + state.Filename)
			}
		}
	}
}

// ─────────────────────────────────────────────
// Decoy traffic
// ─────────────────────────────────────────────

func (a *App) startDecoy() {
	a.stopDecoy()
	stop := make(chan struct{})
	a.decoyStop = stop

	go func() {
		ticker := time.NewTicker(time.Duration(a.config.DecoyInterval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				a.clientMu.RLock()
				client := a.client
				a.clientMu.RUnlock()
				if client == nil {
					return
				}
				size := a.config.DecoyMinBytes + rand.Intn(
					max(1, a.config.DecoyMaxBytes-a.config.DecoyMinBytes),
				)
				client.SendDecoy(size)
			}
		}
	}()
}

func (a *App) stopDecoy() {
	if a.decoyStop != nil {
		close(a.decoyStop)
		a.decoyStop = nil
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// GetUsername returns the currently connected username
func (a *App) GetUsername() string {
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

// GetRooms sends /rooms and returns the result as a string for the frontend to parse
func (a *App) RequestRoomList() error {
    return a.sendText("/rooms")
}

// func (a *App) SwitchRoom(room string) {
//     a.clientMu.Lock()
//     a.currentRoom = room
//     a.clientMu.Unlock()

//     if room == "" {
//         // Switching back to lobby — leave all rooms
//         a.sendText("/leave")
//     } else {
//         // Re-join the room to make it active on the server side
//         a.sendText(fmt.Sprintf("/join %s", room))
//     }
// }

func (a *App) RequestUserList() error {
    return a.sendText("/users")
}

func (a *App) RequestMemberList(target string) error {
    cmd := fmt.Sprintf("/members %s", target)
    return a.sendText(cmd)
}