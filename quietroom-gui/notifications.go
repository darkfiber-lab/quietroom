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

package main

import (
	"fmt"
	"os/exec"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// Desktop notifications use the operating system's own notification
// service, so they come from QuietRoom itself (its name and icon), and
// clicking one brings QuietRoom to the front and opens the conversation:
//
//   - macOS and Windows: Wails (UNUserNotificationCenter; Windows toast
//     notifications), see notifications_wails.go. macOS needs the bundle
//     identifier from build/darwin/Info.plist and asks the user once.
//   - Linux: the freedesktop notification service on D-Bus, see
//     notifications_linux.go and internal/linuxnotify.
//
// There is deliberately no fallback to scripting tools (AppleScript,
// PowerShell, notify-send): those make the notification come from Script
// Editor or PowerShell. If notifications cannot be shown, the chat says why
// once; on macOS the sound still plays.
//
// The text never includes message content or file names, only who sent
// something (and the room), because operating systems keep notifications in
// their own history.

// notificationBackend is the platform's notification service.
type notificationBackend interface {
	// authorize asks for permission if the platform needs it.
	authorize() (bool, error)
	// send shows a notification; channel is reported back when clicked.
	send(id, message, channel string) error
}

type notifier struct {
	mu       sync.Mutex
	backend  notificationBackend // nil until set up (or if unavailable)
	allowed  bool                // the user permits notifications
	reported bool                // the user was told why notifications fail
	nextID   atomic.Uint64
}

// setupNotifications runs once the window exists.
func (a *App) setupNotifications() {
	b, err := newNotificationBackend(a)
	if err != nil {
		a.notificationProblem(err)
		return
	}
	a.notes.mu.Lock()
	a.notes.backend = b
	a.notes.mu.Unlock()
	if a.config.SoundEnabled {
		go a.authorizeNotifications()
	}
}

// authorizeNotifications asks for permission unless it was given already.
// On macOS the first call shows the system's permission prompt.
func (a *App) authorizeNotifications() bool {
	a.notes.mu.Lock()
	b := a.notes.backend
	a.notes.mu.Unlock()
	if b == nil {
		return false
	}
	ok, err := b.authorize()
	a.notes.mu.Lock()
	a.notes.allowed = ok && err == nil
	a.notes.mu.Unlock()
	switch {
	case err != nil:
		a.notificationProblem(err)
	case !ok:
		a.notificationProblem(fmt.Errorf("not allowed — enable them for QuietRoom in the system notification settings"))
	}
	return ok && err == nil
}

// notificationProblem tells the user once why notifications do not appear.
func (a *App) notificationProblem(err error) {
	a.notes.mu.Lock()
	defer a.notes.mu.Unlock()
	if a.notes.reported || a.ctx == nil {
		return
	}
	a.notes.reported = true
	a.emit(a.ctx, "system_message", map[string]interface{}{
		"text": "Desktop notifications are unavailable: " + err.Error(),
	})
}

// notify shows a desktop notification (if enabled in the settings).
// channel is the conversation to open when it is clicked: "__lobby__",
// a room name or "__dm__<name>"; "" only brings the window forward.
func (a *App) notify(message, channel string) {
	if !a.config.SoundEnabled {
		return
	}
	go func() {
		a.notes.mu.Lock()
		b, allowed := a.notes.backend, a.notes.allowed
		a.notes.mu.Unlock()
		if b != nil && allowed {
			err := b.send(fmt.Sprintf("quietroom-%d", a.notes.nextID.Add(1)), message, channel)
			if err == nil {
				return
			}
			a.notificationProblem(err)
		}
		if goruntime.GOOS == "darwin" {
			exec.Command("afplay", "/System/Library/Sounds/Ping.aiff").Run()
		}
	}()
}

// openConversation brings the window forward and opens the conversation of
// a clicked notification.
func (a *App) openConversation(channel string) {
	runtime.WindowUnminimise(a.ctx)
	runtime.WindowShow(a.ctx)
	a.emit(a.ctx, "notification_clicked", map[string]interface{}{"channel": channel})
}

// isQuietRoomExe reports whether a Windows notification registration
// belongs to a QuietRoom GUI executable: release builds
// (quietroom_client_gui-…exe) and local builds (QuietRoom.exe,
// quietroom_client_gui.exe). Used to clean up after older versions.
func isQuietRoomExe(name string) bool {
	l := strings.ToLower(name)
	return strings.HasSuffix(l, ".exe") && (strings.HasPrefix(l, "quietroom_client_gui") || l == "quietroom.exe")
}
