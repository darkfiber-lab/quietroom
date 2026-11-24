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

// Package lineedit is the CLI's input line editor for raw-mode terminals.
//
// The editor owns the bottom of the screen: an optional status line (for
// example transfer progress) and the prompt with the text being typed,
// which may wrap over several rows. Output printed with Print appears above
// that area without disturbing the input.
//
// To redraw, the editor moves the cursor to the first row of its area,
// clears everything below and draws again. It computes how many rows the
// area occupies by simulating the terminal's line wrapping (including the
// deferred wrap at the last column and wide characters), so wrapped input
// is cleared completely instead of leaving copies behind.
package lineedit

import (
	"bytes"
	"fmt"
	"io"
	"unicode"
	"unicode/utf8"
)

// EventKind tells what the user did.
type EventKind int

const (
	// Line is a submitted line (Enter); Text holds it.
	Line EventKind = iota
	// Interrupt is Ctrl+C.
	Interrupt
)

// Event is returned by Feed.
type Event struct {
	Kind EventKind
	Text string
}

// MaxHistory is how many submitted lines Up and Down can recall.
const MaxHistory = 100

// Editor edits one line of input. It is not safe for concurrent use: the
// caller serialises all terminal output through one lock.
type Editor struct {
	out   io.Writer
	width func() int
	w     bytes.Buffer // output of the current operation, written at once

	prompt string // may contain ANSI colour sequences
	status string // shown above the prompt when not empty

	buf []rune
	pos int // cursor index into buf

	history []string
	hidx    int // index into history while browsing; len(history) otherwise
	draft   []rune

	// What is on screen, needed to clear it again.
	drawn     bool
	cursorRow int // rows from the top of the area to the cursor
	drawnCols int
	drawnText []rune // visible runes of the area as drawn
	drawnCur  int    // cursor index into drawnText

	// Input decoding state, kept across Feed calls.
	pend []byte // incomplete UTF-8 sequence
	esc  []byte // escape sequence in progress
}

// New returns an editor writing to out. width reports the terminal width in
// columns; it is called on every redraw, so resizes are picked up.
func New(out io.Writer, width func() int) *Editor {
	return &Editor{out: out, width: width}
}

// Text returns the current input.
func (e *Editor) Text() string { return string(e.buf) }

// Cursor returns the cursor position as an index into the input's runes.
func (e *Editor) Cursor() int { return e.pos }

// SetPrompt changes the prompt and redraws.
func (e *Editor) SetPrompt(p string) {
	e.prompt = p
	if e.drawn {
		e.render()
		e.flush()
	}
}

// SetStatus shows s on its own line above the prompt ("" removes it).
func (e *Editor) SetStatus(s string) {
	if s == e.status {
		return
	}
	e.status = s
	if e.drawn {
		e.render()
		e.flush()
	}
}

// Start draws the prompt for the first time.
func (e *Editor) Start() {
	e.render()
	e.flush()
}

// Print writes text (one or more lines, may contain colours) above the
// input area and redraws the area below it.
func (e *Editor) Print(text string) {
	e.clear()
	for _, line := range splitLines(text) {
		e.w.WriteString(line)
		e.w.WriteString("\r\n")
	}
	e.render()
	e.flush()
}

// Clear removes the input area from the screen, for example before exiting.
func (e *Editor) Clear() {
	e.clear()
	e.flush()
}

// Redraw clears the whole screen and draws the input area at the top
// (Ctrl+L).
func (e *Editor) Redraw() {
	e.w.WriteString("\x1b[H\x1b[2J")
	e.drawn = false
	e.render()
	e.flush()
}

// Feed processes bytes read from the terminal and returns what the user
// submitted. The screen is updated once per call.
func (e *Editor) Feed(data []byte) []Event {
	var events []Event
	appendOnly := e.drawn && e.pos == len(e.buf)
	start := len(e.buf)
	for _, b := range data {
		ev, ok := e.feedByte(b, &appendOnly)
		if !ok {
			continue
		}
		events = append(events, ev)
		if ev.Kind == Interrupt {
			break
		}
		appendOnly = false // Enter resets the line
	}
	if appendOnly && len(e.buf) > start && e.drawnCols == e.cols() {
		// Typing at the end of the line: write just the new characters
		// and let the terminal wrap; then record where the cursor is.
		e.w.WriteString(string(e.buf[start:]))
		e.place(e.cols(), false)
	} else if !appendOnly || len(e.buf) != start {
		e.render()
	}
	e.flush()
	return events
}

func (e *Editor) feedByte(b byte, appendOnly *bool) (Event, bool) {
	switch {
	case len(e.esc) == 1:
		switch b {
		case '[', 'O': // CSI or SS3 sequence
			e.esc = append(e.esc, b)
			return Event{}, false
		case 'b', 'f', 0x7f, 8: // Alt+B, Alt+F, Alt+Backspace
			e.esc = nil
			*appendOnly = false
			e.escape([]byte{0x1b, b})
			return Event{}, false
		case 0x1b:
			return Event{}, false
		}
		e.esc = nil // a lone ESC: ignore it and handle the key normally
	case len(e.esc) > 1:
		e.esc = append(e.esc, b)
		if e.escapeDone() {
			seq := e.esc
			e.esc = nil
			*appendOnly = false
			e.escape(seq)
		}
		return Event{}, false
	}
	if len(e.pend) > 0 && b < 0x80 {
		e.pend = nil // broken UTF-8 sequence: drop it
	}
	switch {
	case b == 0x1b:
		e.esc = []byte{b}
		return Event{}, false
	case b == '\r' || b == '\n':
		text := string(e.buf)
		e.addHistory(text)
		e.buf, e.pos = nil, 0
		return Event{Kind: Line, Text: text}, true
	case b == 3: // Ctrl+C
		return Event{Kind: Interrupt}, true
	case b < 0x20 || b == 0x7f:
		*appendOnly = false
		e.control(b)
		return Event{}, false
	case b < 0x80:
		e.insert(rune(b), appendOnly)
		return Event{}, false
	}
	e.pend = append(e.pend, b)
	for len(e.pend) > 0 && utf8.FullRune(e.pend) {
		r, size := utf8.DecodeRune(e.pend)
		e.pend = e.pend[size:]
		if r != utf8.RuneError {
			e.insert(r, appendOnly)
		}
	}
	if len(e.pend) >= utf8.UTFMax {
		e.pend = nil
	}
	return Event{}, false
}

// insert adds r at the cursor. Tabs and other spaces become a plain space;
// control characters, bidi controls and other invisible format characters
// are dropped, except the zero-width joiners that emoji sequences need.
func (e *Editor) insert(r rune, appendOnly *bool) {
	switch {
	case r == '\t' || unicode.Is(unicode.Zs, r):
		r = ' '
	case r == 0x200C || r == 0x200D:
	case !unicode.IsPrint(r):
		return
	}
	if e.pos != len(e.buf) {
		*appendOnly = false
	}
	e.buf = append(e.buf, 0)
	copy(e.buf[e.pos+1:], e.buf[e.pos:])
	e.buf[e.pos] = r
	e.pos++
}

func (e *Editor) control(b byte) {
	switch b {
	case 0x7f, 8: // Backspace
		if e.pos > 0 {
			e.buf = append(e.buf[:e.pos-1], e.buf[e.pos:]...)
			e.pos--
		}
	case 1: // Ctrl+A
		e.pos = 0
	case 5: // Ctrl+E
		e.pos = len(e.buf)
	case 2: // Ctrl+B
		e.left()
	case 6: // Ctrl+F
		e.right()
	case 4: // Ctrl+D: delete under the cursor
		e.deleteForward()
	case 11: // Ctrl+K: delete to the end
		e.buf = e.buf[:e.pos]
	case 21: // Ctrl+U: delete to the start
		e.buf = append([]rune{}, e.buf[e.pos:]...)
		e.pos = 0
	case 23: // Ctrl+W: delete the word before the cursor
		e.deleteWordBack()
	case 12: // Ctrl+L
		e.w.WriteString("\x1b[H\x1b[2J")
		e.drawn = false
	case 9: // Tab
		ao := false
		e.insert(' ', &ao)
	}
}

// escapeDone reports whether e.esc (ESC [ … or ESC O …) is complete.
// Overlong sequences are abandoned.
func (e *Editor) escapeDone() bool {
	if e.esc[1] == 'O' {
		return len(e.esc) >= 3
	}
	last := e.esc[len(e.esc)-1]
	return (len(e.esc) > 2 && last >= 0x40 && last <= 0x7e) || len(e.esc) > 16
}

func (e *Editor) escape(seq []byte) {
	switch seq[1] {
	case '[':
		final := seq[len(seq)-1]
		params := string(seq[2 : len(seq)-1])
		modified := bytes.ContainsRune(seq, ';') // e.g. ESC[1;5C (Ctrl/Alt+arrow)
		switch final {
		case 'A':
			e.historyPrev()
		case 'B':
			e.historyNext()
		case 'C':
			if modified {
				e.pos = e.wordRight()
			} else {
				e.right()
			}
		case 'D':
			if modified {
				e.pos = e.wordLeft()
			} else {
				e.left()
			}
		case 'H':
			e.pos = 0
		case 'F':
			e.pos = len(e.buf)
		case '~':
			switch params {
			case "1", "7":
				e.pos = 0
			case "4", "8":
				e.pos = len(e.buf)
			case "3":
				e.deleteForward()
			}
		}
	case 'O':
		switch seq[2] {
		case 'A':
			e.historyPrev()
		case 'B':
			e.historyNext()
		case 'C':
			e.right()
		case 'D':
			e.left()
		case 'H':
			e.pos = 0
		case 'F':
			e.pos = len(e.buf)
		}
	case 'b': // Alt+B
		e.pos = e.wordLeft()
	case 'f': // Alt+F
		e.pos = e.wordRight()
	case 0x7f, 8: // Alt+Backspace
		e.deleteWordBack()
	}
}

// left and right move by one character, skipping combining marks so the
// cursor never sits between a letter and its accent.
func (e *Editor) left() {
	for e.pos > 0 {
		e.pos--
		if RuneWidth(e.buf[e.pos]) > 0 {
			return
		}
	}
}

func (e *Editor) right() {
	if e.pos < len(e.buf) {
		e.pos++
	}
	for e.pos < len(e.buf) && RuneWidth(e.buf[e.pos]) == 0 {
		e.pos++
	}
}

func (e *Editor) deleteForward() {
	if e.pos < len(e.buf) {
		e.buf = append(e.buf[:e.pos], e.buf[e.pos+1:]...)
	}
}

func (e *Editor) wordLeft() int {
	i := e.pos
	for i > 0 && unicode.IsSpace(e.buf[i-1]) {
		i--
	}
	for i > 0 && !unicode.IsSpace(e.buf[i-1]) {
		i--
	}
	return i
}

func (e *Editor) wordRight() int {
	i := e.pos
	for i < len(e.buf) && unicode.IsSpace(e.buf[i]) {
		i++
	}
	for i < len(e.buf) && !unicode.IsSpace(e.buf[i]) {
		i++
	}
	return i
}

func (e *Editor) deleteWordBack() {
	i := e.wordLeft()
	e.buf = append(e.buf[:i], e.buf[e.pos:]...)
	e.pos = i
}

func (e *Editor) addHistory(text string) {
	if text != "" && (len(e.history) == 0 || e.history[len(e.history)-1] != text) {
		e.history = append(e.history, text)
		if len(e.history) > MaxHistory {
			e.history = e.history[len(e.history)-MaxHistory:]
		}
	}
	e.hidx = len(e.history)
	e.draft = nil
}

func (e *Editor) historyPrev() {
	if e.hidx == 0 {
		return
	}
	if e.hidx == len(e.history) {
		e.draft = append([]rune{}, e.buf...)
	}
	e.hidx--
	e.buf = []rune(e.history[e.hidx])
	e.pos = len(e.buf)
}

func (e *Editor) historyNext() {
	if e.hidx >= len(e.history) {
		return
	}
	e.hidx++
	if e.hidx == len(e.history) {
		e.buf = e.draft
		e.draft = nil
	} else {
		e.buf = []rune(e.history[e.hidx])
	}
	e.pos = len(e.buf)
}

// ── Drawing ─────────────────────────────────────────────────────────

func (e *Editor) cols() int {
	c := 80
	if e.width != nil {
		if w := e.width(); w > 0 {
			c = w
		}
	}
	return c
}

// visible returns the area's visible runes (status, newline, prompt and
// input) and the cursor's index into them.
func (e *Editor) visible() ([]rune, int) {
	var v []rune
	if e.status != "" {
		forEachVisible(e.status, func(r rune) {
			if r >= 0x20 {
				v = append(v, r)
			}
		})
		v = append(v, '\n')
	}
	forEachVisible(e.prompt, func(r rune) { v = append(v, r) })
	cur := len(v) + e.pos
	return append(v, e.buf...), cur
}

// cell is a screen position relative to the top of the area.
type cell struct{ row, col int }

// layout simulates writing text from column 0 on a terminal cols wide and
// returns where the cursor (before text[cur]) and the end of the text end
// up. pending reports that the text ends exactly at the last column, where
// terminals defer the wrap until the next character.
func layout(text []rune, cur, cols int) (cursor, end cell, pending bool) {
	row, col := 0, 0
	for i, r := range text {
		if r == '\n' {
			if i == cur {
				cursor = cell{row, col}
			}
			row, col = row+1, 0
			continue
		}
		w := RuneWidth(r)
		if w > 0 && col+w > cols && col > 0 {
			row, col = row+1, 0
		}
		if i == cur {
			cursor = cell{row, col}
		}
		col += w
	}
	end = cell{row, col}
	if col >= cols && len(text) > 0 && text[len(text)-1] != '\n' {
		pending = true
		end = cell{row + 1, 0}
	}
	if cur >= len(text) {
		cursor = end
	}
	return cursor, end, pending
}

// clear moves to the top of the area and erases it and everything below.
func (e *Editor) clear() {
	if !e.drawn {
		return
	}
	row := e.cursorRow
	if cols := e.cols(); cols != e.drawnCols {
		// The terminal was resized and has re-wrapped the area.
		c, _, _ := layout(e.drawnText, e.drawnCur, cols)
		row = c.row
	}
	if row > 0 {
		fmt.Fprintf(&e.w, "\x1b[%dA", row)
	}
	e.w.WriteString("\r\x1b[J")
	e.drawn = false
}

// render clears the area and draws it again.
func (e *Editor) render() {
	e.clear()
	if e.status != "" {
		e.w.WriteString(e.status)
		e.w.WriteString("\x1b[0m\r\n")
	}
	e.w.WriteString(e.prompt)
	e.w.WriteString(string(e.buf))
	e.place(e.cols(), true)
}

// place finishes a draw: it resolves a deferred wrap at the end, moves the
// cursor from the end of the text to its position and records the state.
func (e *Editor) place(cols int, move bool) {
	text, cur := e.visible()
	cursor, end, pending := layout(text, cur, cols)
	if pending {
		e.w.WriteString("\r\n")
	}
	if move {
		if up := end.row - cursor.row; up > 0 {
			fmt.Fprintf(&e.w, "\x1b[%dA", up)
		}
		if end.col != cursor.col || end.row != cursor.row {
			e.w.WriteString("\r")
			if cursor.col > 0 {
				fmt.Fprintf(&e.w, "\x1b[%dC", cursor.col)
			}
		}
	}
	e.drawn = true
	e.cursorRow = cursor.row
	e.drawnCols = cols
	e.drawnText = text
	e.drawnCur = cur
}

func (e *Editor) flush() {
	if e.w.Len() > 0 {
		e.out.Write(e.w.Bytes())
		e.w.Reset()
	}
}

func splitLines(text string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			lines = append(lines, trimCR(text[start:i]))
			start = i + 1
		}
	}
	if start < len(text) {
		lines = append(lines, trimCR(text[start:]))
	}
	return lines
}

func trimCR(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\r' {
		return s[:len(s)-1]
	}
	return s
}
