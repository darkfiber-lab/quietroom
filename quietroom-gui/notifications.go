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
	"sync"
	"sync/atomic"

	"github.com/gen2brain/beeep"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// Desktop notifications use the operating system's own notification
// service through Wails, so they come from QuietRoom itself: its name and
// icon, and clicking one brings QuietRoom to the front and opens the
// conversation. On macOS this needs the bundle identifier from
// build/darwin/Info.plist and the user's permission, which is requested
// once. The text never includes message content or file names, only who
// sent something (and the room), because operating systems keep
// notifications in their own history.
//
// Elsewhere, if the native route fails, the beeep library is the fallback.
// On macOS it is never used: it goes through AppleScript, so notifications
// would come from Script Editor (wrong icon, and a click opens Script
// Editor).

type notifier struct {
	mu          sync.Mutex
	initialized bool // Wails notifications set up
	allowed     bool // the user permits notifications
	reported    bool // the user was told why notifications do not work
	nextID      atomic.Uint64
}

// setupNotifications runs once the window exists.
func (a *App) setupNotifications() {
	if err := runtime.InitializeNotifications(a.ctx); err != nil {
		a.notificationProblem(err)
		return
	}
	runtime.OnNotificationResponse(a.ctx, a.notificationClicked)
	a.notes.mu.Lock()
	a.notes.initialized = true
	a.notes.mu.Unlock()
	if a.config.SoundEnabled {
		go a.authorizeNotifications()
	}
}

// authorizeNotifications asks for permission unless it was given already.
// On macOS the first call shows the system's permission prompt.
func (a *App) authorizeNotifications() bool {
	a.notes.mu.Lock()
	initialized := a.notes.initialized
	a.notes.mu.Unlock()
	if !initialized {
		return false
	}
	ok, err := runtime.CheckNotificationAuthorization(a.ctx)
	if err == nil && !ok {
		ok, err = runtime.RequestNotificationAuthorization(a.ctx)
	}
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
		native := a.notes.initialized && a.notes.allowed
		a.notes.mu.Unlock()
		if native {
			err := runtime.SendNotification(a.ctx, runtime.NotificationOptions{
				ID:    fmt.Sprintf("quietroom-%d", a.notes.nextID.Add(1)),
				Title: "QuietRoom",
				Body:  message,
				Data:  map[string]interface{}{"channel": channel},
			})
			if err == nil {
				return // the system plays its notification sound
			}
			a.notificationProblem(err)
		}
		if goruntime.GOOS == "darwin" {
			// No AppleScript fallback (see above): just the sound.
			exec.Command("afplay", "/System/Library/Sounds/Ping.aiff").Run()
			return
		}
		beeep.Notify("QuietRoom", message, "")
	}()
}

// notificationClicked brings the window forward and opens the conversation.
func (a *App) notificationClicked(result runtime.NotificationResult) {
	if result.Error != nil {
		return
	}
	runtime.WindowUnminimise(a.ctx)
	runtime.WindowShow(a.ctx)
	channel, _ := result.Response.UserInfo["channel"].(string)
	a.emit(a.ctx, "notification_clicked", map[string]interface{}{"channel": channel})
}
