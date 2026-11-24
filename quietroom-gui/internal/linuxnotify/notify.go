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

// Package linuxnotify sends desktop notifications through the freedesktop
// notification service on D-Bus (GNOME, KDE, Xfce, dunst, mako, …).
//
// It replaces Wails' Linux notifications, which name the sender after the
// executable file (for example "quietroom_client_gui-linux-amd64-v3.0.0"),
// send no icon, and create a configuration directory named after the
// executable on every version. Here the sender is the application's name,
// the notification carries its icon and the instant-message category, and
// clicking it reports which conversation to open.
package linuxnotify

import (
	"fmt"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
)

const (
	service = "org.freedesktop.Notifications"
	path    = dbus.ObjectPath("/org/freedesktop/Notifications")

	// maxPending bounds the clicks remembered for notifications the
	// server never reports as closed.
	maxPending = 200
)

// Notifier sends notifications and reports clicks.
type Notifier struct {
	conn    *dbus.Conn
	appName string
	icon    string // absolute path of a PNG, or ""
	onClick func(data string)

	actions bool // the server supports clicking (the "actions" capability)
	markup  bool // the server interprets body markup

	mu      sync.Mutex
	pending map[uint32]string // notification ID -> data for the click
	order   []uint32
	signals chan *dbus.Signal
}

// New connects a notifier to the notification service reachable over conn.
// appName is shown as the sender; icon is an absolute path to an image (or
// ""); onClick is called with the data of a clicked notification.
func New(conn *dbus.Conn, appName, icon string, onClick func(data string)) (*Notifier, error) {
	n := &Notifier{conn: conn, appName: appName, icon: icon, onClick: onClick, pending: map[uint32]string{}}
	var caps []string
	if err := conn.Object(service, path).Call(service+".GetCapabilities", 0).Store(&caps); err != nil {
		return nil, fmt.Errorf("no desktop notification service: %w", err)
	}
	for _, c := range caps {
		switch c {
		case "actions":
			n.actions = true
		case "body-markup":
			n.markup = true
		}
	}
	for _, member := range []string{"ActionInvoked", "NotificationClosed"} {
		if err := conn.AddMatchSignal(
			dbus.WithMatchObjectPath(path),
			dbus.WithMatchInterface(service),
			dbus.WithMatchMember(member),
		); err != nil {
			return nil, fmt.Errorf("subscribing to %s: %w", member, err)
		}
	}
	n.signals = make(chan *dbus.Signal, 16)
	conn.Signal(n.signals)
	go n.listen()
	return n, nil
}

// Send shows a notification. data is passed to onClick if it is clicked.
func (n *Notifier) Send(summary, body, data string) error {
	if n.markup {
		body = escape(body)
	}
	var actions []string
	if n.actions {
		// "default" is the click on the notification itself; most servers
		// show no button for it.
		actions = []string{"default", "Open"}
	}
	hints := map[string]dbus.Variant{
		"category":      dbus.MakeVariant("im.received"),
		"desktop-entry": dbus.MakeVariant("quietroom"),
		"urgency":       dbus.MakeVariant(byte(1)), // normal
	}
	if n.icon != "" {
		hints["image-path"] = dbus.MakeVariant(n.icon)
	}
	var id uint32
	err := n.conn.Object(service, path).Call(service+".Notify", 0,
		n.appName, uint32(0), n.icon, summary, body, actions, hints, int32(-1),
	).Store(&id)
	if err != nil {
		return fmt.Errorf("sending notification: %w", err)
	}
	if n.actions {
		n.mu.Lock()
		n.pending[id] = data
		n.order = append(n.order, id)
		for len(n.order) > maxPending {
			delete(n.pending, n.order[0])
			n.order = n.order[1:]
		}
		n.mu.Unlock()
	}
	return nil
}

// Close stops listening for clicks.
func (n *Notifier) Close() {
	n.conn.RemoveSignal(n.signals)
	close(n.signals)
}

func (n *Notifier) listen() {
	for sig := range n.signals {
		if sig.Path != path || len(sig.Body) < 2 {
			continue
		}
		id, ok := sig.Body[0].(uint32)
		if !ok {
			continue
		}
		n.mu.Lock()
		data, known := n.pending[id]
		delete(n.pending, id)
		n.mu.Unlock()
		if !known {
			continue // not ours, or already handled
		}
		if sig.Name == service+".ActionInvoked" {
			if action, _ := sig.Body[1].(string); action == "default" && n.onClick != nil {
				n.onClick(data)
			}
		}
	}
}

// escape protects text for servers that interpret a subset of HTML.
func escape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
