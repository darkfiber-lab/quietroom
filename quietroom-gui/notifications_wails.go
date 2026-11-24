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

//go:build !linux

package main

import "github.com/wailsapp/wails/v2/pkg/runtime"

// wailsNotifications uses Wails' notifications: UNUserNotificationCenter on
// macOS, toast notifications on Windows.
type wailsNotifications struct{ a *App }

// linuxWindowIcon is only needed on Linux.
func linuxWindowIcon() []byte { return nil }

func newNotificationBackend(a *App) (notificationBackend, error) {
	if err := runtime.InitializeNotifications(a.ctx); err != nil {
		return nil, err
	}
	runtime.OnNotificationResponse(a.ctx, func(r runtime.NotificationResult) {
		if r.Error != nil {
			return
		}
		channel, _ := r.Response.UserInfo["channel"].(string)
		a.openConversation(channel)
	})
	afterWailsNotificationsInit()
	return &wailsNotifications{a: a}, nil
}

func (w *wailsNotifications) authorize() (bool, error) {
	ok, err := runtime.CheckNotificationAuthorization(w.a.ctx)
	if err == nil && !ok {
		ok, err = runtime.RequestNotificationAuthorization(w.a.ctx)
	}
	return ok, err
}

func (w *wailsNotifications) send(id, message, channel string) error {
	return runtime.SendNotification(w.a.ctx, runtime.NotificationOptions{
		ID:    id,
		Title: "QuietRoom",
		Body:  message,
		Data:  map[string]interface{}{"channel": channel},
	})
}
