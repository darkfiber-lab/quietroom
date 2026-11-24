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

//go:build linux

package main

import (
	"bytes"
	_ "embed"
	"os"
	"path/filepath"

	"github.com/godbus/dbus/v5"

	"quietroom-gui/internal/linuxnotify"
)

// appIconPNG is the 256×256 application icon, used for notifications and
// for the window (Linux has no icon in the binary otherwise).
//
//go:embed icon/quietroom-256.png
var appIconPNG []byte

func linuxWindowIcon() []byte { return appIconPNG }

// linuxNotifications uses the freedesktop notification service directly
// (see internal/linuxnotify for why not Wails).
type linuxNotifications struct{ n *linuxnotify.Notifier }

func newNotificationBackend(a *App) (notificationBackend, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, err
	}
	n, err := linuxnotify.New(conn, "QuietRoom", iconFile(), a.openConversation)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &linuxNotifications{n: n}, nil
}

func (l *linuxNotifications) authorize() (bool, error) { return true, nil }

func (l *linuxNotifications) send(_, message, channel string) error {
	return l.n.Send("QuietRoom", message, channel)
}

// iconFile writes the application icon where the notification service can
// read it (~/.cache/QuietRoom/icon.png) and returns its path, or "".
func iconFile() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	p := filepath.Join(dir, "QuietRoom", "icon.png")
	if cur, err := os.ReadFile(p); err == nil && bytes.Equal(cur, appIconPNG) {
		return p
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return ""
	}
	if err := os.WriteFile(p, appIconPNG, 0644); err != nil {
		return ""
	}
	return p
}
