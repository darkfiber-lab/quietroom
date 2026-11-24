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

package lineedit_test

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/darkfiber-lab/quietroom/lineedit"
	"github.com/darkfiber-lab/quietroom/lineedit/vt"
)

const (
	left      = "\x1b[D"
	right     = "\x1b[C"
	up        = "\x1b[A"
	down      = "\x1b[B"
	home      = "\x1b[H"
	end       = "\x1b[F"
	del       = "\x1b[3~"
	backspace = "\x7f"
)

type term struct {
	t      *testing.T
	scr    *vt.Screen
	ed     *lineedit.Editor
	cols   int
	lines  []string // submitted lines
	printd []string // lines printed above the input, in order
	prompt string
	status string
}

func newTerm(t *testing.T, cols, rows int) *term {
	tm := &term{t: t, scr: vt.New(cols, rows), cols: cols, prompt: "> "}
	tm.ed = lineedit.New(tm.scr, func() int { return tm.cols })
	tm.ed.SetPrompt("\x1b[96m> \x1b[0m") // coloured, as in the CLI
	tm.ed.Start()
	return tm
}

func (tm *term) keys(s string) {
	for _, ev := range tm.ed.Feed([]byte(s)) {
		if ev.Kind == lineedit.Line {
			tm.lines = append(tm.lines, ev.Text)
		}
	}
}

func (tm *term) print(text string) {
	tm.ed.Print(text)
	tm.printd = append(tm.printd, strings.Split(text, "\n")...)
}

// wrap splits a string into screen rows the way a terminal wraps it.
func wrap(s string, cols int) []string {
	var rows []string
	var cur strings.Builder
	col := 0
	for _, r := range s {
		w := lineedit.RuneWidth(r)
		if w == 0 {
			continue
		}
		if col+w > cols {
			rows = append(rows, strings.TrimRight(cur.String(), " "))
			cur.Reset()
			col = 0
		}
		cur.WriteRune(r)
		col += w
	}
	return append(rows, strings.TrimRight(cur.String(), " "))
}

func visible(s string) string {
	var b strings.Builder
	for _, r := range s {
		if lineedit.RuneWidth(r) > 0 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// check verifies that the transcript is exactly: everything printed, then
// the status line, then the prompt and input, each wrapped, with no
// leftovers, and that the cursor is where the editor says it is.
func (tm *term) check() {
	tm.t.Helper()
	var want []string
	for _, p := range tm.printd {
		want = append(want, wrap(p, tm.cols)...)
	}
	if tm.status != "" {
		want = append(want, wrap(tm.status, tm.cols)...)
	}
	inputTop := len(want) // rows above the prompt
	want = append(want, wrap(tm.prompt+visible(tm.ed.Text()), tm.cols)...)
	for len(want) > 0 && want[len(want)-1] == "" {
		want = want[:len(want)-1]
	}
	got := tm.scr.Transcript()
	if !reflect.DeepEqual(got, want) {
		tm.t.Fatalf("screen mismatch\n got: %q\nwant: %q", got, want)
	}

	// Cursor: the cell where the character at the cursor index is drawn
	// (or the cell after the text).
	wantRow, wantCol := 0, 0
	for _, r := range tm.prompt + visible(string([]rune(tm.ed.Text())[:tm.ed.Cursor()])) {
		w := lineedit.RuneWidth(r)
		if w > 0 && wantCol+w > tm.cols {
			wantRow, wantCol = wantRow+1, 0
		}
		wantCol += w
	}
	if wantCol >= tm.cols {
		wantRow, wantCol = wantRow+1, 0
	} else if rest := []rune(tm.ed.Text())[tm.ed.Cursor():]; len(rest) > 0 && lineedit.RuneWidth(rest[0]) == 2 && wantCol == tm.cols-1 {
		wantRow, wantCol = wantRow+1, 0 // a wide character wraps as a whole
	}
	row, col := tm.scr.Cursor()
	gotRow := row + len(tm.scr.Scrollback) - inputTop
	if gotRow != wantRow || col != wantCol {
		tm.t.Fatalf("cursor at row %d col %d of the input, want row %d col %d (input %q, cursor %d)",
			gotRow, col, wantRow, wantCol, tm.ed.Text(), tm.ed.Cursor())
	}
}

// The reported bug: backspace in a wrapped line duplicated the message.
func TestBackspaceInWrappedLine(t *testing.T) {
	tm := newTerm(t, 20, 10)
	tm.keys("this message is long enough to wrap twice on a narrow screen")
	tm.check()
	for i := 0; i < 5; i++ {
		tm.keys(backspace)
		tm.check()
	}
	if got := tm.ed.Text(); got != "this message is long enough to wrap twice on a narrow s" {
		t.Fatalf("text = %q", got)
	}
	tm.keys(strings.Repeat(backspace, 40))
	tm.check()
	tm.keys("\r")
	tm.check()
	if tm.lines[0] != "this message is" {
		t.Fatalf("submitted %q", tm.lines[0])
	}
}

func TestMessagesArriveWhileTypingWrappedLine(t *testing.T) {
	tm := newTerm(t, 20, 8)
	tm.keys("a line that wraps over three rows of input")
	for i := 0; i < 12; i++ { // more than the screen: scrolling
		tm.print(fmt.Sprintf("[12:00:%02d] alice: message number %d", i, i))
		tm.check()
	}
	tm.keys(backspace + backspace + "!!")
	tm.check()
}

func TestExactWidthBoundary(t *testing.T) {
	tm := newTerm(t, 20, 6)
	tm.keys(strings.Repeat("x", 18)) // prompt (2) + 18 = exactly one row
	tm.check()
	tm.keys("y")
	tm.check()
	tm.keys(backspace)
	tm.check()
	tm.keys(backspace)
	tm.check()
	tm.keys(strings.Repeat("z", 20)) // exactly two rows
	tm.check()
	tm.print("hello")
	tm.check()
}

func TestWideCharacters(t *testing.T) {
	tm := newTerm(t, 20, 6)
	tm.keys(strings.Repeat("a", 17) + "日本語のテキスト") // a wide character at the last column wraps
	tm.check()
	tm.keys(left + left + left + "中")
	tm.check()
	tm.keys(backspace + backspace)
	tm.check()
	tm.keys("😀👨‍👩‍👧 ok")
	tm.check()
}

func TestCursorMovementAndEditing(t *testing.T) {
	tm := newTerm(t, 20, 8)
	tm.keys("hello world, wrapping line")
	tm.keys(home + right + right + "X")
	tm.check()
	if got := tm.ed.Text(); got != "heXllo world, wrapping line" {
		t.Fatalf("text = %q", got)
	}
	tm.keys(end + left + left + del)
	tm.check()
	if got := tm.ed.Text(); got != "heXllo world, wrapping lie" {
		t.Fatalf("after delete: %q", got)
	}
	tm.keys("\x17") // Ctrl+W: delete the word before the cursor
	tm.check()
	if got := tm.ed.Text(); got != "heXllo world, wrapping e" {
		t.Fatalf("after Ctrl+W: %q", got)
	}
	tm.keys("\x01\x0b") // Ctrl+A, Ctrl+K
	tm.check()
	if tm.ed.Text() != "" {
		t.Fatalf("after Ctrl+K: %q", tm.ed.Text())
	}
	tm.keys("one two three\x1b[1;5D\x1b[1;5D") // Ctrl+Left twice
	if tm.ed.Cursor() != 4 {
		t.Fatalf("word left: cursor %d", tm.ed.Cursor())
	}
	tm.keys("\x1bf") // Alt+F
	if tm.ed.Cursor() != 7 {
		t.Fatalf("word right: cursor %d", tm.ed.Cursor())
	}
	tm.check()
}

// Arrow keys used to insert "[A", "[D" and so on.
func TestEscapeSequencesInsertNothing(t *testing.T) {
	tm := newTerm(t, 30, 6)
	tm.keys("abc" + up + down + left + right + "\x1bOA" + "\x1b[5~" + "\x1b[1;2P" + "\x1b[200~" + "d")
	if got := tm.ed.Text(); got != "abcd" {
		t.Fatalf("text = %q", got)
	}
	// A lone Esc does not swallow the next key, even Enter.
	tm.keys("\x1b" + "e" + "\x1b" + "\r")
	if len(tm.lines) != 1 || tm.lines[0] != "abcde" {
		t.Fatalf("lines = %q", tm.lines)
	}
	tm.check()
}

func TestEscapeSequenceSplitAcrossReads(t *testing.T) {
	tm := newTerm(t, 30, 6)
	tm.keys("ab\x1b")
	tm.keys("[")
	tm.keys("D")
	tm.keys("X")
	if got := tm.ed.Text(); got != "aXb" {
		t.Fatalf("text = %q", got)
	}
	tm.keys("\xc3") // first byte of "é"
	tm.keys("\xa9")
	if got := tm.ed.Text(); got != "aXéb" {
		t.Fatalf("utf-8 split: %q", got)
	}
	tm.check()
}

func TestHiddenAndControlCharactersNotInserted(t *testing.T) {
	tm := newTerm(t, 30, 6)
	tm.keys("a‮b​c\x00d\x07e\tf g")
	if got := tm.ed.Text(); got != "abcde f g" {
		t.Fatalf("text = %q", got)
	}
	tm.check()
}

func TestHistory(t *testing.T) {
	tm := newTerm(t, 30, 6)
	tm.keys("first\rsecond\rdraft")
	tm.keys(up)
	if tm.ed.Text() != "second" {
		t.Fatalf("up: %q", tm.ed.Text())
	}
	tm.keys(up + up)
	if tm.ed.Text() != "first" {
		t.Fatalf("up up: %q", tm.ed.Text())
	}
	tm.keys(down + down)
	if tm.ed.Text() != "draft" {
		t.Fatalf("back to draft: %q", tm.ed.Text())
	}
	tm.check()
}

func TestStatusLine(t *testing.T) {
	tm := newTerm(t, 20, 8)
	tm.keys("typing a wrapped line here")
	tm.status = "Receiving big.bin: 42.0% (1 MB of 2 MB)"
	tm.ed.SetStatus(tm.status)
	tm.check()
	tm.print("alice: hi")
	tm.check()
	tm.keys(backspace)
	tm.check()
	tm.status = ""
	tm.ed.SetStatus("")
	tm.check()
}

func TestPasteManyLines(t *testing.T) {
	tm := newTerm(t, 20, 6)
	tm.keys("one\r\ntwo\rthree")
	if !reflect.DeepEqual(tm.lines, []string{"one", "", "two"}) || tm.ed.Text() != "three" {
		t.Fatalf("lines %q, text %q", tm.lines, tm.ed.Text())
	}
	tm.check()
}

func TestInterrupt(t *testing.T) {
	tm := newTerm(t, 20, 6)
	evs := tm.ed.Feed([]byte("abc\x03def"))
	if len(evs) != 1 || evs[0].Kind != lineedit.Interrupt {
		t.Fatalf("events %+v", evs)
	}
}

// TestRandomEditing types, edits and prints at random on terminals of
// several widths and checks the whole screen after every step.
func TestRandomEditing(t *testing.T) {
	alphabet := []string{"a", "b", " ", "x", "é", "日", "😀", "é", backspace, backspace, left, right, home, end, del, "\x17", "\x15", "\x0b"}
	for _, cols := range []int{8, 13, 20, 41, 80} {
		t.Run(fmt.Sprint(cols), func(t *testing.T) {
			rng := rand.New(rand.NewSource(int64(cols)))
			tm := newTerm(t, cols, 12)
			for step := 0; step < 2000; step++ {
				switch n := rng.Intn(100); {
				case n < 3:
					tm.print(fmt.Sprintf("message %d %s", step, strings.Repeat("~", rng.Intn(cols*2))))
				case n < 5:
					tm.status = fmt.Sprintf("progress %d%%", rng.Intn(100))
					if rng.Intn(3) == 0 {
						tm.status = ""
					}
					tm.ed.SetStatus(tm.status)
				case n < 6:
					tm.keys("\r")
				default:
					tm.keys(alphabet[rng.Intn(len(alphabet))])
				}
				tm.check()
			}
		})
	}
}

func TestWidthTableSorted(t *testing.T) {
	for _, c := range []struct {
		r rune
		w int
	}{{'a', 1}, {'é', 1}, {'́', 0}, {'日', 2}, {'한', 2}, {'😀', 2}, {'‍', 0}, {'Ａ', 2}, {'→', 1}} {
		if got := lineedit.RuneWidth(c.r); got != c.w {
			t.Errorf("RuneWidth(%q) = %d, want %d", c.r, got, c.w)
		}
	}
	if lineedit.StringWidth("\x1b[96m> \x1b[0m日") != 4 {
		t.Error("StringWidth must skip colour sequences")
	}
}
