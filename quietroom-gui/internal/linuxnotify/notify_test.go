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

package linuxnotify

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// The tests run a private D-Bus daemon with a fake notification server, so
// they need dbus-daemon (Linux, or Homebrew's dbus on macOS). Set
// QUIETROOM_REQUIRE_DBUS=1 to fail instead of skipping without it.

func startBus(t *testing.T) string {
	t.Helper()
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		if os.Getenv("QUIETROOM_REQUIRE_DBUS") != "" {
			t.Fatal("dbus-daemon not found")
		}
		t.Skip("dbus-daemon not installed")
	}
	dir, err := os.MkdirTemp("/tmp", "qrbus") // short: socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	cfg := filepath.Join(dir, "bus.conf")
	os.WriteFile(cfg, []byte(`<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:dir=`+dir+`</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>`), 0600)
	cmd := exec.Command(daemon, "--config-file="+cfg, "--print-address=1", "--nofork", "--nopidfile")
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	addr, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatalf("dbus-daemon: %v", err)
	}
	return strings.TrimSpace(addr)
}

type call struct {
	App, Icon, Summary, Body string
	Actions                  []string
	Hints                    map[string]dbus.Variant
}

// fakeServer implements the methods of org.freedesktop.Notifications.
type fakeServer struct {
	caps  []string
	mu    sync.Mutex
	calls []call
	next  uint32
}

func (f *fakeServer) GetCapabilities() ([]string, *dbus.Error) { return f.caps, nil }

func (f *fakeServer) Notify(app string, replaces uint32, icon, summary, body string, actions []string, hints map[string]dbus.Variant, timeout int32) (uint32, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{app, icon, summary, body, actions, hints})
	f.next++
	return f.next, nil
}

func serve(t *testing.T, addr string, caps []string) (*fakeServer, *dbus.Conn) {
	t.Helper()
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	f := &fakeServer{caps: caps}
	if err := conn.Export(f, path, service); err != nil {
		t.Fatal(err)
	}
	if reply, err := conn.RequestName(service, dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("owning %s: %v %v", service, reply, err)
	}
	return f, conn
}

func client(t *testing.T, addr string, onClick func(string)) *Notifier {
	t.Helper()
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	n, err := New(conn, "QuietRoom", "/opt/quietroom/icon.png", onClick)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(n.Close)
	return n
}

func TestSendAndClick(t *testing.T) {
	addr := startBus(t)
	fake, server := serve(t, addr, []string{"actions", "body", "body-markup"})
	clicks := make(chan string, 4)
	n := client(t, addr, func(data string) { clicks <- data })

	if err := n.Send("QuietRoom", "Direct message from <bob> & co", "__dm__bob"); err != nil {
		t.Fatal(err)
	}
	if err := n.Send("QuietRoom", "New message from alice in #ops", "#ops"); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	got := fake.calls[0]
	fake.mu.Unlock()
	if got.App != "QuietRoom" || got.Icon != "/opt/quietroom/icon.png" || got.Summary != "QuietRoom" {
		t.Errorf("sender/icon/summary: %+v", got)
	}
	if got.Body != "Direct message from &lt;bob&gt; &amp; co" {
		t.Errorf("body not escaped for a markup server: %q", got.Body)
	}
	if !reflect.DeepEqual(got.Actions, []string{"default", "Open"}) {
		t.Errorf("actions: %q", got.Actions)
	}
	for k, want := range map[string]interface{}{"category": "im.received", "desktop-entry": "quietroom", "urgency": byte(1), "image-path": "/opt/quietroom/icon.png"} {
		if v, ok := got.Hints[k]; !ok || v.Value() != want {
			t.Errorf("hint %s = %v, want %v", k, v, want)
		}
	}

	emit := func(member string, body ...interface{}) {
		if err := server.Emit(path, service+"."+member, body...); err != nil {
			t.Fatal(err)
		}
	}
	emit("ActionInvoked", uint32(99), "default") // not ours
	emit("ActionInvoked", uint32(2), "default")
	select {
	case d := <-clicks:
		if d != "#ops" {
			t.Fatalf("clicked data = %q", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("click not reported")
	}
	emit("ActionInvoked", uint32(2), "default") // already handled
	emit("NotificationClosed", uint32(1), uint32(2))
	emit("ActionInvoked", uint32(1), "default") // closed before the click
	select {
	case d := <-clicks:
		t.Fatalf("unexpected click %q", d)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestServerWithoutActionsOrMarkup(t *testing.T) {
	addr := startBus(t)
	fake, _ := serve(t, addr, []string{"body"})
	n := client(t, addr, nil)
	if err := n.Send("QuietRoom", "a <b> c", "x"); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.calls[0].Actions) != 0 || fake.calls[0].Body != "a <b> c" {
		t.Fatalf("got %+v", fake.calls[0])
	}
}

func TestNoNotificationService(t *testing.T) {
	addr := startBus(t)
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := New(conn, "QuietRoom", "", nil); err == nil {
		t.Fatal("New succeeded without a notification service")
	}
}

func TestPendingBounded(t *testing.T) {
	addr := startBus(t)
	serve(t, addr, []string{"actions"})
	n := client(t, addr, nil)
	for i := 0; i < maxPending+50; i++ {
		n.Send("QuietRoom", "x", "y")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.pending) != maxPending {
		t.Fatalf("%d pending clicks remembered", len(n.pending))
	}
}
