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
	"context"
	"testing"
	"time"
)

func TestIsQuietRoomExe(t *testing.T) {
	for name, want := range map[string]bool{
		"quietroom_client_gui-windows-amd64-v3.0.0.exe": true,
		"QUIETROOM_CLIENT_GUI-windows-arm64-v3.1.0.EXE": true,
		"quietroom_client_gui.exe":                      true,
		"QuietRoom.exe":                                 true,
		"QuietRoomHelper.exe":                           false,
		"quietroom_client_gui-linux-amd64-v3.0.0":       false,
		"slack.exe": false,
		"":          false,
	} {
		if got := isQuietRoomExe(name); got != want {
			t.Errorf("isQuietRoomExe(%q) = %v", name, got)
		}
	}
}

// fakeBackend records notifications.
type fakeBackend struct {
	allow bool
	sent  chan [2]string
}

func (f *fakeBackend) authorize() (bool, error) { return f.allow, nil }
func (f *fakeBackend) send(_, message, channel string) error {
	f.sent <- [2]string{message, channel}
	return nil
}

func TestNotifyUsesBackend(t *testing.T) {
	rec := &recorder{t: t, ch: make(chan uiEvent, 10)}
	a := &App{ctx: context.Background(), emit: rec.emit, config: AppConfig{SoundEnabled: true}}
	fb := &fakeBackend{allow: true, sent: make(chan [2]string, 4)}
	a.notes.backend = fb
	if !a.authorizeNotifications() {
		t.Fatal("not authorized")
	}
	a.notify("Direct message from bob", "__dm__bob")
	select {
	case got := <-fb.sent:
		if got != [2]string{"Direct message from bob", "__dm__bob"} {
			t.Fatalf("sent %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing sent")
	}

	// Disabled in the settings: nothing is sent.
	a.config.SoundEnabled = false
	a.notify("x", "")
	select {
	case got := <-fb.sent:
		t.Fatalf("sent %q while disabled", got)
	case <-time.After(200 * time.Millisecond):
	}

	// Refused permission is reported once in the chat.
	b := &App{ctx: context.Background(), emit: rec.emit}
	b.notes.backend = &fakeBackend{allow: false}
	b.authorizeNotifications()
	b.authorizeNotifications()
	rec.wait("system_message", map[string]string{"text": "Desktop notifications are unavailable: not allowed — enable them for QuietRoom in the system notification settings"})
	select {
	case e := <-rec.ch:
		t.Fatalf("reported twice: %+v", e)
	case <-time.After(200 * time.Millisecond):
	}
}
