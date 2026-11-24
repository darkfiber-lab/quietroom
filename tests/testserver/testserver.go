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

// Package testserver builds the QuietRoom server and runs real instances
// for integration and attack tests. Test support only.
package testserver

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/darkfiber-lab/quietroom/client"
)

// Build compiles the server into dir. QUIETROOM_RACE=1 adds the race detector.
func Build(dir string) (string, error) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	bin := filepath.Join(dir, "quietroom_server")
	args := []string{"build"}
	if os.Getenv("QUIETROOM_RACE") == "1" {
		args = append(args, "-race")
	}
	args = append(args, "-o", bin, "quietroom_server.go")
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return bin, cmd.Run()
}

// Config is written to server_config.json. Zero limits are raised to values
// suitable for tests, where every connection comes from 127.0.0.1.
type Config struct {
	Port                  int  `json:"port"`
	DecoyTraffic          bool `json:"decoy_traffic"`
	DecoyInterval         int  `json:"decoy_interval_seconds,omitempty"`
	MaxConnections        int  `json:"max_connections,omitempty"`
	MaxConnectionsPerIP   int  `json:"max_connections_per_ip,omitempty"`
	MaxNewConnPerIPPerMin int  `json:"max_new_connections_per_ip_per_minute,omitempty"`
	MaxRooms              int  `json:"max_rooms,omitempty"`
	MaxRoomsPerMember     int  `json:"max_rooms_per_member,omitempty"`
	LogMetadata           bool `json:"log_metadata"`
}

// Server is a running server process.
type Server struct {
	t          testing.TB
	Dir        string
	Addr       string
	AccessFile string
	ServerCert *x509.Certificate
	Access     tls.Certificate
	GateKey    []byte

	cmd    *exec.Cmd
	output *syncBuffer
	exited chan struct{}
	stop   sync.Once
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func freePort(t testing.TB) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// Start runs a fresh server in its own directory and waits for its access file.
func Start(t testing.TB, bin string, cfg Config) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg.Port = freePort(t)
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 1000
	}
	if cfg.MaxConnectionsPerIP == 0 {
		cfg.MaxConnectionsPerIP = 1000
	}
	if cfg.MaxNewConnPerIPPerMin == 0 {
		cfg.MaxNewConnPerIPPerMin = 100000
	}
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(dir, "server_config.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{
		t:          t,
		Dir:        dir,
		Addr:       fmt.Sprintf("127.0.0.1:%d", cfg.Port),
		AccessFile: filepath.Join(dir, client.AccessFileName),
		output:     &syncBuffer{},
		exited:     make(chan struct{}),
	}
	s.cmd = exec.Command(bin)
	s.cmd.Dir = dir
	s.cmd.Stdout = s.output
	s.cmd.Stderr = s.output
	if err := s.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		s.cmd.Wait()
		close(s.exited)
	}()
	t.Cleanup(s.Stop)

	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := os.Stat(s.AccessFile); err == nil {
			a, err := client.LoadAccess(s.AccessFile)
			if err != nil {
				t.Fatalf("access file: %v", err)
			}
			s.ServerCert, s.Access, s.GateKey = a.ServerCert, a.Cert, a.GateKey
			return s
		}
		select {
		case <-s.exited:
			t.Fatalf("server exited during startup:\n%s", s.output.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start:\n%s", s.output.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Output returns the server's stdout and stderr so far.
func (s *Server) Output() string { return s.output.String() }

// Running reports whether the process is alive.
func (s *Server) Running() bool {
	select {
	case <-s.exited:
		return false
	default:
		return true
	}
}

// Stop terminates the server and fails the test on a reported data race.
func (s *Server) Stop() {
	s.stop.Do(func() {
		if s.Running() {
			s.cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-s.exited:
			case <-time.After(10 * time.Second):
				s.cmd.Process.Kill()
				<-s.exited
			}
		}
		if out := s.output.String(); strings.Contains(out, "DATA RACE") {
			s.t.Errorf("server reported a data race:\n%s", out)
		}
	})
}

// CheckOutput fails the test if the server panicked, raced or died.
func (s *Server) CheckOutput(t testing.TB) {
	t.Helper()
	if !s.Running() {
		t.Fatalf("server process died:\n%s", s.Output())
	}
	out := s.Output()
	for _, bad := range []string{"panic:", "DATA RACE", "fatal error:", "Recovered from internal error"} {
		if strings.Contains(out, bad) {
			t.Fatalf("server output contains %q:\n%s", bad, out)
		}
	}
}

// ReadLog returns a log file from the server directory.
func (s *Server) ReadLog(name string) string {
	data, _ := os.ReadFile(filepath.Join(s.Dir, name))
	return string(data)
}

// ── Members ─────────────────────────────────────────────────────────

// Member is a logged-in client whose events are collected for assertions.
type Member struct {
	t      testing.TB
	Name   string
	C      *client.Client
	events chan client.Event
	Dir    string

	backlog []client.Event // received but not yet matched by a Wait
}

// Join logs a member in with the real client library.
func (s *Server) Join(t testing.TB, name string, opts ...func(*client.Config)) *Member {
	t.Helper()
	m, err := s.TryJoin(t, name, opts...)
	if err != nil {
		t.Fatalf("login %s: %v", name, err)
	}
	return m
}

// TryJoin is Join without failing the test.
func (s *Server) TryJoin(t testing.TB, name string, opts ...func(*client.Config)) (*Member, error) {
	m := &Member{t: t, Name: name, events: make(chan client.Event, 100000), Dir: t.TempDir()}
	cfg := client.Config{
		Addr:        s.Addr,
		AccessFile:  s.AccessFile,
		Username:    name,
		DownloadDir: m.Dir,
		OnEvent: func(e client.Event) {
			select {
			case m.events <- e:
			default:
				panic("test event buffer full")
			}
		},
	}
	for _, o := range opts {
		o(&cfg)
	}
	c, err := client.Dial(cfg)
	if err != nil {
		return nil, err
	}
	m.C = c
	t.Cleanup(c.Close)
	return m, nil
}

// Wait returns the first event matching pred, failing the test on timeout.
func (m *Member) Wait(what string, timeout time.Duration, pred func(client.Event) bool) client.Event {
	m.t.Helper()
	e, ok := m.TryWait(timeout, pred)
	if !ok {
		m.t.Fatalf("%s: timed out waiting for %s", m.Name, what)
	}
	return e
}

// TryWait is Wait without failing the test. Events that do not match are
// kept for later waits, so waiting for one thing never loses another.
func (m *Member) TryWait(timeout time.Duration, pred func(client.Event) bool) (client.Event, bool) {
	for i, e := range m.backlog {
		if pred(e) {
			m.backlog = append(m.backlog[:i], m.backlog[i+1:]...)
			return e, true
		}
	}
	deadline := time.After(timeout)
	for {
		select {
		case e := <-m.events:
			if pred(e) {
				return e, true
			}
			m.backlog = append(m.backlog, e)
		case <-deadline:
			return client.Event{}, false
		}
	}
}

// Kind matches events of one kind.
func Kind(k client.Kind) func(client.Event) bool {
	return func(e client.Event) bool { return e.Kind == k }
}

// Text matches events of one kind containing text.
func Text(k client.Kind, text string) func(client.Event) bool {
	return func(e client.Event) bool { return e.Kind == k && strings.Contains(e.Text, text) }
}
