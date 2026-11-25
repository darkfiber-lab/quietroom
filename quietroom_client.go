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
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/darkfiber-lab/quietroom/client"
	"github.com/darkfiber-lab/quietroom/lineedit"
	"github.com/darkfiber-lab/quietroom/wire"
	"golang.org/x/term"
)

type ClientConfig struct {
	Servers           []ServerInfo `json:"servers"`
	Theme             Theme        `json:"theme"`
	DecoyTraffic      bool         `json:"decoy_traffic"`
	DecoyInterval     int          `json:"decoy_interval_seconds"`
	DecoyMinBytes     int          `json:"decoy_min_bytes"`
	DecoyMaxBytes     int          `json:"decoy_max_bytes"`
	SoundNotification bool         `json:"sound_notification"`
	DownloadDir       string       `json:"download_dir"`
	MaxReceiveMB      int64        `json:"max_receive_mb"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type Theme struct {
	SystemColor    string `json:"system_color"`
	UsernameColor  string `json:"username_color"`
	MessageColor   string `json:"message_color"`
	TimestampColor string `json:"timestamp_color"`
	ErrorColor     string `json:"error_color"`
}

var colors = map[string]string{
	"reset":          "\033[0m",
	"red":            "\033[31m",
	"green":          "\033[32m",
	"yellow":         "\033[33m",
	"blue":           "\033[34m",
	"magenta":        "\033[35m",
	"cyan":           "\033[36m",
	"white":          "\033[37m",
	"gray":           "\033[90m",
	"bright_red":     "\033[91m",
	"bright_green":   "\033[92m",
	"bright_yellow":  "\033[93m",
	"bright_blue":    "\033[94m",
	"bright_magenta": "\033[95m",
	"bright_cyan":    "\033[96m",
}

const legacyAccessFile = "chat_public.pem"

// UI is the terminal front end. All output after login goes through the
// line editor, which keeps what the user is typing intact below it.
//
// Without an interactive terminal (Plan 9, where raw mode is unavailable, or
// when input or output is redirected) the CLI runs in line mode instead:
// lines are read as typed and output is printed as it arrives, without
// line editing or colours.
type UI struct {
	config ClientConfig
	c      *client.Client

	lineMode bool // no line editor: read whole lines, print plainly
	noColor  bool

	outMu  sync.Mutex
	ed     *lineedit.Editor
	ready  bool     // the input line is on screen (or line mode started)
	queued []string // output that arrived before the input line was drawn

	roomMu      sync.Mutex
	currentRoom string
}

func (u *UI) colorize(color, text string) string {
	if u.noColor {
		return text
	}
	if code, ok := colors[color]; ok {
		return code + text + colors["reset"]
	}
	return text
}

// sanitizeText removes control characters (including terminal escape
// sequences) and hidden characters such as bidi overrides from text
// received from the server.
func sanitizeText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, wire.CleanText(s))
}

// terminalWidth reports the width of the terminal (80 if unknown).
func terminalWidth() int {
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		return w
	}
	return 80
}

// output shows lines above the input line.
func (u *UI) output(lines []string) {
	u.outMu.Lock()
	defer u.outMu.Unlock()
	if !u.ready {
		u.queued = append(u.queued, lines...)
		return
	}
	if u.lineMode {
		for _, l := range lines {
			fmt.Println(l)
		}
		return
	}
	u.ed.Print(strings.Join(lines, "\n"))
}

// print shows text (one or more lines) in one colour.
func (u *UI) print(color string, text string) {
	var lines []string
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		lines = append(lines, u.colorize(color, sanitizeText(line)))
	}
	u.output(lines)
}

// printChat renders one chat line with timestamp and name colors.
func (u *UI) printChat(ts, prefix, name, text string) {
	t := u.config.Theme
	line := u.colorize(t.TimestampColor, "["+sanitizeText(ts)+"]") + " "
	if prefix != "" {
		line += u.colorize(t.SystemColor, sanitizeText(prefix)) + " "
	}
	// Multi-line messages keep their line breaks, indented under the name.
	parts := strings.Split(text, "\n")
	line += u.colorize(t.UsernameColor, sanitizeText(name)) + ": " + u.colorize(t.MessageColor, sanitizeText(parts[0]))
	lines := []string{line}
	for _, p := range parts[1:] {
		lines = append(lines, "    "+u.colorize(t.MessageColor, sanitizeText(p)))
	}
	u.output(lines)
}

// progress shows a transfer's progress on the status line above the input;
// an empty text removes it.
func (u *UI) progress(text string) {
	u.outMu.Lock()
	defer u.outMu.Unlock()
	if u.ready && !u.lineMode { // line mode: only the final result is shown
		if text != "" {
			text = u.colorize(u.config.Theme.SystemColor, sanitizeText(text))
		}
		u.ed.SetStatus(text)
	}
}

// start draws the input line and shows output that arrived before it.
func (u *UI) start() {
	u.outMu.Lock()
	defer u.outMu.Unlock()
	u.ready = true
	if u.lineMode {
		for _, l := range u.queued {
			fmt.Println(l)
		}
		u.queued = nil
		return
	}
	u.ed.Start()
	if len(u.queued) > 0 {
		u.ed.Print(strings.Join(u.queued, "\n"))
		u.queued = nil
	}
}

func (u *UI) notify() {
	if !u.config.SoundNotification {
		return
	}
	go func() {
		switch runtime.GOOS {
		case "darwin":
			exec.Command("afplay", "/System/Library/Sounds/Ping.aiff").Run()
		case "linux":
			if exec.Command("paplay", "/usr/share/sounds/freedesktop/stereo/message.oga").Run() == nil {
				return
			}
			if exec.Command("aplay", "/usr/share/sounds/alsa/Front_Center.wav").Run() == nil {
				return
			}
			fmt.Print("\a")
		default:
			fmt.Print("\a")
		}
	}()
}

func (u *UI) room() string {
	u.roomMu.Lock()
	defer u.roomMu.Unlock()
	return u.currentRoom
}

func (u *UI) setRoom(r string) {
	u.roomMu.Lock()
	u.currentRoom = r
	u.roomMu.Unlock()
	prompt := "> "
	if r != "" {
		prompt = r + " > "
	}
	u.outMu.Lock()
	u.ed.SetPrompt(u.colorize(u.config.Theme.SystemColor, prompt))
	u.outMu.Unlock()
}

func formatBytes(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	case n < 1<<30:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
}

// onEvent renders protocol events. Calls never overlap.
func (u *UI) onEvent(e client.Event) {
	th := u.config.Theme
	switch e.Kind {
	case client.EvChat:
		name := e.From
		if e.Self {
			name = "You"
		} else {
			u.notify()
		}
		prefix := ""
		if e.Room != "" {
			prefix = "[" + e.Room + "]"
		}
		u.printChat(e.Time, prefix, name, e.Text)
	case client.EvDM:
		if e.Self {
			u.printChat(e.Time, "[DM to "+e.To+"]", "You", e.Text)
		} else {
			u.notify()
			u.printChat(e.Time, "[DM]", e.From, e.Text)
		}
	case client.EvJoined:
		switch {
		case e.Room == "" && e.Self:
		case e.Room == "":
			u.print(th.SystemColor, fmt.Sprintf("*** %s joined the chat ***", e.User))
		case e.Self:
			u.setRoom(e.Room)
			verb := "Joined"
			if e.Created {
				verb = "Created and joined"
			}
			u.print(th.SystemColor, fmt.Sprintf("%s room %s — messages now go to %s (/leave %s to return to the lobby)", verb, e.Room, e.Room, e.Room))
			if e.Locked {
				u.print(th.SystemColor, "🔒 "+e.Room+" is end-to-end encrypted: only members who know the password can read it, not the server.")
			}
		default:
			u.print(th.SystemColor, fmt.Sprintf("*** %s joined %s ***", e.User, e.Room))
		}
	case client.EvLeft:
		switch {
		case e.Room == "":
			u.print(th.SystemColor, fmt.Sprintf("*** %s left the chat ***", e.User))
		case e.Self:
			if u.room() == e.Room {
				u.setRoom("")
			}
			u.print(th.SystemColor, fmt.Sprintf("Left room %s - returned to lobby", e.Room))
		default:
			u.print(th.SystemColor, fmt.Sprintf("*** %s left %s ***", e.User, e.Room))
		}
	case client.EvInfo:
		u.print(th.SystemColor, e.Text)
	case client.EvError:
		u.print(th.ErrorColor, "✗ "+e.Text)
	case client.EvFileOffer:
		t := e.Transfer
		u.notify()
		u.print(th.SystemColor, fmt.Sprintf("*** FILE TRANSFER REQUEST ***\nSender: %s\nFile: %s (%s)\nSHA-256: %s\nTransfer ID: %s\n\nTo accept, type: /accept %s\nTo decline, type: /decline %s",
			t.Peer, t.Name, formatBytes(t.Size), t.SHA256, t.ID, t.ID, t.ID))
	case client.EvFileOffered:
		t := e.Transfer
		u.print(th.SystemColor, fmt.Sprintf("*** File offer sent to %s: %s (%s) ***\nTransfer ID: %s\nSHA-256: %s\nWaiting for the recipient to accept... (/cancel %s to withdraw)",
			t.Peer, t.Name, formatBytes(t.Size), t.ID, t.SHA256, t.ID))
	case client.EvFileStarted:
		t := e.Transfer
		if t.Outgoing {
			u.print(th.SystemColor, fmt.Sprintf("%s accepted — sending %s (%s)", t.Peer, t.Name, formatBytes(t.Size)))
		} else {
			u.print(th.SystemColor, fmt.Sprintf("Receiving %s (%s) from %s\nExpected SHA-256: %s", t.Name, formatBytes(t.Size), t.Peer, t.SHA256))
		}
	case client.EvFileProgress:
		t := e.Transfer
		verb := "Receiving"
		if t.Outgoing {
			verb = "Sending"
		}
		pct := float64(t.Done) / float64(t.Size) * 100
		u.progress(fmt.Sprintf("%s %s: %.1f%% (%s of %s)", verb, t.Name, pct, formatBytes(t.Done), formatBytes(t.Size)))
	case client.EvFileComplete:
		t := e.Transfer
		u.progress("")
		if t.Outgoing {
			u.print(th.SystemColor, fmt.Sprintf("✓ File sent: %s (%s)\n✓ Recipient should verify hash: %s", t.Name, formatBytes(t.Size), t.SHA256))
			return
		}
		// Files whose hash does not match arrive as EvFileFailed instead.
		u.notify()
		u.print(th.SystemColor, fmt.Sprintf("✓ File received: %s (%s)\n  Saved to: %s\n  SHA-256: %s\n✓ Hash verification PASSED - file integrity verified!", t.Name, formatBytes(t.Size), t.Path, t.ActualSHA256))
	case client.EvFileFailed:
		u.progress("")
		name := "file"
		if e.Transfer != nil {
			name = e.Transfer.Name
		}
		u.print(th.ErrorColor, fmt.Sprintf("✗ File transfer of %s ended: %s", name, e.Text))
	case client.EvDisconnected:
		u.print(th.ErrorColor, "*** Disconnected: "+e.Text+" ***")
	}
}

func loadConfig() ClientConfig {
	config := ClientConfig{
		Servers: []ServerInfo{
			{Name: "Default Server", Address: "localhost", Port: 37842},
		},
		Theme: Theme{
			SystemColor:    "bright_cyan",
			UsernameColor:  "bright_yellow",
			MessageColor:   "white",
			TimestampColor: "gray",
			ErrorColor:     "bright_red",
		},
		DecoyTraffic:      true,
		DecoyInterval:     30,
		DecoyMinBytes:     100,
		DecoyMaxBytes:     500,
		SoundNotification: false,
		DownloadDir:       "downloads",
		MaxReceiveMB:      8192,
	}
	data, err := os.ReadFile("client_config.json")
	if err != nil {
		configData, _ := json.MarshalIndent(config, "", "  ")
		os.WriteFile("client_config.json", configData, 0644)
		return config
	}
	if err := json.Unmarshal(data, &config); err != nil {
		fmt.Println("⚠ Error parsing config, using defaults")
	}
	if config.DownloadDir == "" {
		config.DownloadDir = "downloads"
	}
	return config
}

func (u *UI) clearScreen() {
	if u.lineMode || runtime.GOOS == "plan9" {
		return
	}
	cmd := exec.Command("clear")
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func main() {
	config := loadConfig()
	u := &UI{config: config}
	u.lineMode = !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd()))
	// Colours only on terminals that understand ANSI sequences
	// (NO_COLOR: https://no-color.org).
	u.noColor = os.Getenv("NO_COLOR") != "" || runtime.GOOS == "plan9" || !term.IsTerminal(int(os.Stdout.Fd()))
	u.ed = lineedit.New(os.Stdout, terminalWidth)
	u.ed.SetPrompt(u.colorize(config.Theme.SystemColor, "> "))
	th := config.Theme
	fail := func(msg string) {
		fmt.Println(u.colorize(th.ErrorColor, "✗ "+msg))
		os.Exit(1)
	}

	u.clearScreen()

	if _, err := os.Stat(client.AccessFileName); os.IsNotExist(err) {
		if _, err := os.Stat(legacyAccessFile); err == nil {
			fmt.Println(u.colorize(th.SystemColor, legacyAccessFile+" is from an older server version and no longer works."))
		}
		fail(client.AccessFileName + " not found! Copy it from your server administrator to this directory.")
	}
	if _, err := client.LoadAccess(client.AccessFileName); err != nil {
		fail("Error loading access file: " + err.Error())
	}
	fmt.Println(u.colorize(th.SystemColor, "✓ Loaded server certificate and access key"))

	fmt.Println()
	fmt.Println(u.colorize(th.SystemColor, "Available servers:"))
	for i, srv := range config.Servers {
		fmt.Printf("  %d. %s (%s:%d)\n", i+1, srv.Name, srv.Address, srv.Port)
	}
	fmt.Println()
	if len(config.Servers) == 1 {
		fmt.Print(u.colorize(th.SystemColor, "Press Enter to connect, or enter custom address: "))
	} else {
		fmt.Print(u.colorize(th.SystemColor, fmt.Sprintf("Select server (1-%d) or enter custom address: ", len(config.Servers))))
	}
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		os.Exit(1)
	}
	input := strings.TrimSpace(scanner.Text())
	var serverAddr string
	var selection int
	if _, err := fmt.Sscanf(input, "%d", &selection); err == nil && selection > 0 && selection <= len(config.Servers) {
		srv := config.Servers[selection-1]
		serverAddr = fmt.Sprintf("%s:%d", srv.Address, srv.Port)
	} else if input != "" {
		serverAddr = input
	} else if len(config.Servers) > 0 {
		serverAddr = fmt.Sprintf("%s:%d", config.Servers[0].Address, config.Servers[0].Port)
	} else {
		fail("No server configured")
	}

	var c *client.Client
	for c == nil {
		fmt.Print(u.colorize(th.SystemColor, "Enter your username: "))
		if !scanner.Scan() {
			os.Exit(1)
		}
		name := strings.TrimSpace(scanner.Text())
		fmt.Println(u.colorize(th.SystemColor, "Connecting to "+serverAddr+"..."))
		var err error
		c, err = client.Dial(client.Config{
			Addr:          serverAddr,
			AccessFile:    client.AccessFileName,
			Username:      name,
			DownloadDir:   config.DownloadDir,
			MaxReceive:    config.MaxReceiveMB << 20,
			Decoys:        config.DecoyTraffic,
			DecoyInterval: time.Duration(config.DecoyInterval) * time.Second,
			DecoyMin:      config.DecoyMinBytes,
			DecoyMax:      config.DecoyMaxBytes,
			OnEvent:       u.onEvent,
		})
		if err != nil {
			var le *client.LoginError
			if errors.As(err, &le) && (le.Code == wire.CodeUsernameTaken || le.Code == wire.CodeInvalidUsername) {
				fmt.Println(u.colorize(th.ErrorColor, "✗ "+le.Text))
				continue
			}
			fail(err.Error())
		}
	}
	u.c = c

	u.clearScreen()
	sep := u.colorize("gray", strings.Repeat("━", 78))
	fmt.Println(sep)
	fmt.Println(u.colorize(th.SystemColor, "                         WELCOME TO QUIETROOM"))
	fmt.Println(u.colorize(th.SystemColor, "   "+serverAddr+" - TLS 1.3 + ACCESS KEY - logged in as "+c.Username()))
	fmt.Println(sep)
	fmt.Println()
	if config.DecoyTraffic {
		fmt.Println(u.colorize(th.SystemColor, "✓ Decoy traffic active"))
	}
	fmt.Println(u.colorize(th.SystemColor, "🔒 Direct messages, files and password rooms are end-to-end encrypted (/verify <user> to check)"))
	fmt.Println(u.colorize(th.SystemColor, "✓ Type /help for available commands"))
	fmt.Println(u.colorize(th.SystemColor, "✓ Press Ctrl+C or type /quit to disconnect"))
	fmt.Println()

	restore := func() {}
	if !u.lineMode {
		oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			// For example on Plan 9: fall back to plain line input.
			u.lineMode = true
			fmt.Println(u.colorize(th.SystemColor, "✓ Line editing unavailable here ("+err.Error()+"): using plain line input"))
		} else {
			lineedit.EnableTerminalOutput(os.Stdout) // escape sequences on Windows consoles
			restore = func() { term.Restore(int(os.Stdin.Fd()), oldState) }
		}
	}
	u.start()

	// finish removes the input line before leaving raw mode.
	finish := func() {
		u.outMu.Lock()
		if u.ready && !u.lineMode {
			u.ed.Clear()
			u.ready = false
		}
		u.outMu.Unlock()
		restore()
	}
	var quitting sync.Once
	quit := func(code int) {
		quitting.Do(func() {})
		finish()
		c.Close()
		fmt.Println(u.colorize("gray", strings.Repeat("━", 78)))
		fmt.Println(u.colorize(th.SystemColor, "Disconnected from server"))
		os.Exit(code)
	}
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		quit(0)
	}()
	go func() {
		<-c.Done()
		time.Sleep(100 * time.Millisecond) // let the disconnect event print
		stopped := true
		quitting.Do(func() { stopped = false })
		if stopped {
			return // the user quit: quit() exits
		}
		finish()
		os.Exit(1)
	}()

	lines := make(chan string)
	if u.lineMode {
		// The same scanner as for the login prompts: it may already hold
		// input that was read ahead.
		go func() {
			for scanner.Scan() {
				lines <- scanner.Text()
			}
			close(lines)
		}()
	} else {
		go u.readKeys(lines, quit)
	}

	for text := range lines {
		text = strings.TrimSpace(text)
		if text == "/quit" {
			quit(0)
		}
		if strings.HasPrefix(strings.ToLower(text), "/file ") {
			u.print(th.SystemColor, "Computing file hash...")
			go func(line string) {
				if err := c.Command(line, ""); err != nil {
					u.print(th.ErrorColor, "✗ "+err.Error())
				}
			}(text)
			continue
		}
		if err := c.Command(text, u.room()); err != nil {
			u.print(th.ErrorColor, "✗ "+err.Error())
		}
	}
	quit(0)
}

// readKeys feeds keystrokes to the line editor and passes on entered lines.
func (u *UI) readKeys(lines chan<- string, quit func(int)) {
	buf := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			close(lines)
			return
		}
		u.outMu.Lock()
		events := u.ed.Feed(buf[:n])
		u.outMu.Unlock()
		for _, ev := range events {
			switch ev.Kind {
			case lineedit.Interrupt:
				quit(0)
			case lineedit.Line:
				if strings.TrimSpace(ev.Text) != "" {
					lines <- ev.Text
				}
			}
		}
	}
}
