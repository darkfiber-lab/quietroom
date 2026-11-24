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

// Package vt is a small terminal emulator for tests. It implements the part
// of xterm behaviour the CLI relies on, so tests can check what a person
// would actually see: autowrap with the deferred wrap at the last column,
// wide characters, scrolling, and the escape sequences for cursor movement,
// erasing and colours.
package vt

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/darkfiber-lab/quietroom/lineedit"
)

// wideTail marks the second cell of a wide character.
const wideTail = -1

// Screen is an emulated terminal. Write terminal output to it.
type Screen struct {
	Cols, Rows int
	// Scrollback holds the lines that scrolled off the top, oldest first.
	Scrollback []string

	cells    [][]rune
	wrapped  []bool // row continues on the next row (autowrap)
	sbRaw    []string
	sbWrap   []bool
	row, col int
	pending  bool // deferred wrap: the last column was just written

	partial []byte // incomplete UTF-8 or escape sequence
}

// New returns an empty screen.
func New(cols, rows int) *Screen {
	s := &Screen{Cols: cols, Rows: rows}
	for i := 0; i < rows; i++ {
		s.cells = append(s.cells, s.blank())
	}
	s.wrapped = make([]bool, rows)
	return s
}

func (s *Screen) blank() []rune {
	r := make([]rune, s.Cols)
	for i := range r {
		r[i] = ' '
	}
	return r
}

// Cursor returns the cursor position (row and column, from 0).
func (s *Screen) Cursor() (row, col int) { return s.row, s.col }

// Line returns row i of the visible screen without trailing spaces.
func (s *Screen) Line(i int) string {
	var b strings.Builder
	for _, r := range s.cells[i] {
		if r != wideTail {
			b.WriteRune(r)
		}
	}
	return strings.TrimRight(b.String(), " ")
}

// Lines returns the visible screen, without trailing empty rows.
func (s *Screen) Lines() []string {
	var out []string
	for i := range s.cells {
		out = append(out, s.Line(i))
	}
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return out
}

// Transcript returns everything that scrolled off followed by the visible
// screen, without trailing empty rows.
func (s *Screen) Transcript() []string {
	all := append(append([]string{}, s.Scrollback...), s.Lines()...)
	for len(all) > 0 && all[len(all)-1] == "" {
		all = all[:len(all)-1]
	}
	return all
}

func (s *Screen) rawLine(i int) string {
	var b strings.Builder
	for _, r := range s.cells[i] {
		if r != wideTail {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// LogicalLines returns the transcript with rows that the terminal wrapped
// joined again, as copying text from a terminal does.
func (s *Screen) LogicalLines() []string {
	raw := append([]string{}, s.sbRaw...)
	wrap := append([]bool{}, s.sbWrap...)
	for i := range s.cells {
		raw = append(raw, s.rawLine(i))
		wrap = append(wrap, s.wrapped[i])
	}
	var out []string
	var cur strings.Builder
	for i, r := range raw {
		if wrap[i] {
			cur.WriteString(r)
			continue
		}
		cur.WriteString(strings.TrimRight(r, " "))
		out = append(out, cur.String())
		cur.Reset()
	}
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return out
}

// Write interprets terminal output.
func (s *Screen) Write(p []byte) (int, error) {
	data := append(s.partial, p...)
	s.partial = nil
	for i := 0; i < len(data); {
		b := data[i]
		switch {
		case b == 0x1b:
			n := s.escape(data[i:])
			if n == 0 { // incomplete
				s.partial = append([]byte{}, data[i:]...)
				return len(p), nil
			}
			i += n
		case b == '\r':
			s.col, s.pending = 0, false
			i++
		case b == '\n':
			s.lineFeed()
			i++
		case b == '\b':
			s.fixCol()
			if s.col > 0 {
				s.col--
			}
			i++
		case b < 0x20 || b == 0x7f:
			i++ // bell and other controls: no effect on the screen
		default:
			if !utf8.FullRune(data[i:]) {
				s.partial = append([]byte{}, data[i:]...)
				return len(p), nil
			}
			r, size := utf8.DecodeRune(data[i:])
			s.put(r)
			i += size
		}
	}
	return len(p), nil
}

// fixCol leaves the deferred-wrap state: the cursor is really on the last
// column.
func (s *Screen) fixCol() {
	if s.pending {
		s.col, s.pending = s.Cols-1, false
	}
}

func (s *Screen) lineFeed() {
	s.fixCol()
	if s.row == s.Rows-1 {
		s.Scrollback = append(s.Scrollback, s.Line(0))
		s.sbRaw = append(s.sbRaw, s.rawLine(0))
		s.sbWrap = append(s.sbWrap, s.wrapped[0])
		s.cells = append(s.cells[1:], s.blank())
		s.wrapped = append(s.wrapped[1:], false)
	} else {
		s.row++
	}
}

// autoWrap moves to the next row because the text continues there.
func (s *Screen) autoWrap() {
	s.wrapped[s.row] = true
	s.col, s.pending = 0, false
	s.lineFeed()
	s.wrapped[s.row] = false
}

func (s *Screen) put(r rune) {
	w := lineedit.RuneWidth(r)
	if w == 0 {
		return // combining marks attach to the previous cell; ignore them
	}
	if s.pending {
		s.autoWrap()
	}
	if w == 2 && s.col == s.Cols-1 {
		s.cells[s.row][s.col] = ' '
		s.autoWrap()
	}
	s.clearWide(s.row, s.col)
	s.cells[s.row][s.col] = r
	if w == 2 && s.col+1 < s.Cols {
		s.clearWide(s.row, s.col+1)
		s.cells[s.row][s.col+1] = wideTail
	}
	s.col += w
	if s.col >= s.Cols {
		s.col, s.pending = s.Cols-1, true
	}
}

// clearWide blanks the other half of a wide character being overwritten.
func (s *Screen) clearWide(row, col int) {
	line := s.cells[row]
	if line[col] == wideTail && col > 0 {
		line[col-1] = ' '
	}
	if col+1 < len(line) && line[col+1] == wideTail {
		line[col+1] = ' '
	}
}

// escape handles an escape sequence at the start of data and returns its
// length, or 0 if it is incomplete.
func (s *Screen) escape(data []byte) int {
	if len(data) < 2 {
		return 0
	}
	if data[1] != '[' {
		return 2 // other escapes: ignored
	}
	end := 2
	for end < len(data) && (data[end] < 0x40 || data[end] > 0x7e) {
		end++
	}
	if end == len(data) {
		return 0
	}
	params := strings.Split(string(data[2:end]), ";")
	n := func(i, def int) int {
		if i < len(params) {
			if v, err := strconv.Atoi(params[i]); err == nil && v > 0 {
				return v
			}
		}
		return def
	}
	switch data[end] {
	case 'A':
		s.fixCol()
		s.row = max(0, s.row-n(0, 1))
	case 'B':
		s.fixCol()
		s.row = min(s.Rows-1, s.row+n(0, 1))
	case 'C':
		s.fixCol()
		s.col = min(s.Cols-1, s.col+n(0, 1))
	case 'D':
		s.fixCol()
		s.col = max(0, s.col-n(0, 1))
	case 'H':
		s.row, s.col, s.pending = min(s.Rows-1, n(0, 1)-1), min(s.Cols-1, n(1, 1)-1), false
	case 'K':
		s.fixCol()
		line := s.cells[s.row]
		from, to := s.col, s.Cols // 0: to the end
		switch n(0, 0) {
		case 1:
			from, to = 0, s.col+1
		case 2:
			from = 0
		}
		for i := from; i < to; i++ {
			line[i] = ' '
		}
	case 'J':
		s.fixCol()
		switch n(0, 0) {
		case 2, 3:
			for i := range s.cells {
				s.cells[i] = s.blank()
				s.wrapped[i] = false
			}
		default: // 0: from the cursor to the end of the screen
			for i := s.col; i < s.Cols; i++ {
				s.cells[s.row][i] = ' '
			}
			s.wrapped[s.row] = false
			for i := s.row + 1; i < s.Rows; i++ {
				s.cells[i] = s.blank()
				s.wrapped[i] = false
			}
		}
	}
	// 'm' (colours) and anything else: no effect on the text.
	return end + 1
}
