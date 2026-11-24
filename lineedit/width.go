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

package lineedit

import "unicode"

// RuneWidth returns how many terminal columns r occupies: 0 for combining
// marks and other zero-width characters, 2 for East Asian wide and
// fullwidth characters and most emoji, 1 otherwise. It follows what common
// terminals (xterm, VTE, iTerm2, Terminal.app, Windows Terminal) do; a few
// ambiguous characters may differ between terminals.
func RuneWidth(r rune) int {
	switch {
	case r == 0:
		return 0
	case r < 32 || (r >= 0x7f && r < 0xa0):
		return 0 // control characters are never inserted; be safe
	case r < 0x300:
		return 1
	case unicode.In(r, unicode.Mn, unicode.Me, unicode.Cf):
		return 0
	case r >= 0x1160 && r <= 0x11FF: // Hangul jamo medial vowels and final consonants
		return 0
	case r == 0x200B:
		return 0
	case isWide(r):
		return 2
	}
	return 1
}

// wide lists East Asian Wide (W) and Fullwidth (F) ranges and the emoji
// blocks that terminals draw two columns wide.
var wide = [][2]rune{
	{0x1100, 0x115F},   // Hangul jamo initial consonants
	{0x231A, 0x231B},   // watch, hourglass
	{0x2329, 0x232A},   // angle brackets
	{0x23E9, 0x23EC},   // media controls
	{0x23F0, 0x23F0},   // alarm clock
	{0x23F3, 0x23F3},   // hourglass
	{0x25FD, 0x25FE},   // small squares
	{0x2614, 0x2615},   // umbrella, hot beverage
	{0x2648, 0x2653},   // zodiac
	{0x267F, 0x267F},   // wheelchair
	{0x2693, 0x2693},   // anchor
	{0x26A1, 0x26A1},   // high voltage
	{0x26AA, 0x26AB},   // circles
	{0x26BD, 0x26BE},   // soccer, baseball
	{0x26C4, 0x26C5},   // snowman, sun behind cloud
	{0x26CE, 0x26CE},   // ophiuchus
	{0x26D4, 0x26D4},   // no entry
	{0x26EA, 0x26EA},   // church
	{0x26F2, 0x26F3},   // fountain, golf
	{0x26F5, 0x26F5},   // sailboat
	{0x26FA, 0x26FA},   // tent
	{0x26FD, 0x26FD},   // fuel pump
	{0x2705, 0x2705},   // check mark button
	{0x270A, 0x270B},   // fists
	{0x2728, 0x2728},   // sparkles
	{0x274C, 0x274C},   // cross mark
	{0x274E, 0x274E},   // cross mark button
	{0x2753, 0x2755},   // question marks
	{0x2757, 0x2757},   // exclamation mark
	{0x2795, 0x2797},   // plus, minus, divide
	{0x27B0, 0x27B0},   // curly loop
	{0x27BF, 0x27BF},   // double curly loop
	{0x2B1B, 0x2B1C},   // large squares
	{0x2B50, 0x2B50},   // star
	{0x2B55, 0x2B55},   // circle
	{0x2E80, 0x303E},   // CJK radicals, punctuation
	{0x3041, 0x33FF},   // Hiragana, Katakana, CJK compatibility
	{0x3400, 0x4DBF},   // CJK extension A
	{0x4E00, 0x9FFF},   // CJK unified ideographs
	{0xA000, 0xA4CF},   // Yi
	{0xA960, 0xA97F},   // Hangul jamo extended A
	{0xAC00, 0xD7A3},   // Hangul syllables
	{0xF900, 0xFAFF},   // CJK compatibility ideographs
	{0xFE10, 0xFE19},   // vertical forms
	{0xFE30, 0xFE6F},   // CJK compatibility forms, small forms
	{0xFF00, 0xFF60},   // fullwidth forms
	{0xFFE0, 0xFFE6},   // fullwidth signs
	{0x16FE0, 0x16FE4}, // ideographic symbols
	{0x17000, 0x18CFF}, // Tangut
	{0x1AFF0, 0x1B2FF}, // Kana extensions, Nushu
	{0x1F004, 0x1F004}, // mahjong
	{0x1F0CF, 0x1F0CF}, // joker
	{0x1F18E, 0x1F18E}, // AB button
	{0x1F191, 0x1F19A}, // squared words
	{0x1F200, 0x1F2FF}, // enclosed ideographic supplement
	{0x1F300, 0x1F64F}, // pictographs, emoticons
	{0x1F680, 0x1F6FF}, // transport and map
	{0x1F7E0, 0x1F7EB}, // coloured circles and squares
	{0x1F90C, 0x1F9FF}, // supplemental symbols and pictographs
	{0x1FA70, 0x1FAFF}, // symbols and pictographs extended A
	{0x20000, 0x2FFFD}, // CJK extension B and beyond
	{0x30000, 0x3FFFD}, // CJK extension G and beyond
}

func isWide(r rune) bool {
	lo, hi := 0, len(wide)
	for lo < hi {
		m := (lo + hi) / 2
		switch {
		case r < wide[m][0]:
			hi = m
		case r > wide[m][1]:
			lo = m + 1
		default:
			return true
		}
	}
	return false
}

// StringWidth returns the number of columns s occupies, ignoring ANSI
// escape sequences (such as colours).
func StringWidth(s string) int {
	w := 0
	forEachVisible(s, func(r rune) { w += RuneWidth(r) })
	return w
}

// forEachVisible calls f for every rune of s outside ANSI escape sequences.
func forEachVisible(s string, f func(rune)) {
	esc := 0 // 0 normal, 1 after ESC, 2 inside CSI
	for _, r := range s {
		switch esc {
		case 1:
			if r == '[' {
				esc = 2
			} else {
				esc = 0
			}
			continue
		case 2:
			if r >= 0x40 && r <= 0x7e {
				esc = 0
			}
			continue
		}
		if r == 0x1b {
			esc = 1
			continue
		}
		f(r)
	}
}
