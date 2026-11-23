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

package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func TestRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 100, 247, 248, 249, 1000, 4096, DataChunk + IDLen, MaxPayload} {
		payload := bytes.Repeat([]byte{0xab}, n)
		enc, err := Encode(FrameControl, payload)
		if err != nil {
			t.Fatalf("encode %d: %v", n, err)
		}
		if len(enc) > MaxFrame || len(enc) < minFrame {
			t.Fatalf("encode %d: wire size %d outside [%d, %d]", n, len(enc), minFrame, MaxFrame)
		}
		if len(enc)&(len(enc)-1) != 0 {
			t.Fatalf("encode %d: wire size %d is not a bucket", n, len(enc))
		}
		f, err := Read(bytes.NewReader(enc))
		if err != nil {
			t.Fatalf("read %d: %v", n, err)
		}
		if f.Type != FrameControl || !bytes.Equal(f.Payload, payload) {
			t.Fatalf("round trip %d: mismatch", n)
		}
	}
	if _, err := Encode(FrameControl, make([]byte, MaxPayload+1)); err == nil {
		t.Fatal("oversized payload accepted")
	}
}

func TestFullDataFrameHasNoPadding(t *testing.T) {
	enc, err := EncodeData([IDLen]byte{1}, make([]byte, DataChunk))
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != 32*1024 {
		t.Fatalf("full data frame is %d bytes, want 32768", len(enc))
	}
	if pad := binary.BigEndian.Uint16(enc[6:8]); pad != 0 {
		t.Fatalf("full data frame has %d padding bytes", pad)
	}
}

// Frames survive any split of the byte stream (the failure mode of the old
// protocol, which depended on TLS record boundaries).
func TestStreamSplitting(t *testing.T) {
	var stream bytes.Buffer
	var want [][]byte
	for i := 0; i < 50; i++ {
		p := bytes.Repeat([]byte{byte(i)}, i*97)
		enc, _ := Encode(FrameControl, p)
		stream.Write(enc)
		want = append(want, p)
		dec, _ := EncodeSize(FrameDecoy, nil, 300+i)
		stream.Write(dec)
	}
	for name, r := range map[string]io.Reader{
		"one byte": iotest.OneByteReader(bytes.NewReader(stream.Bytes())),
		"half":     iotest.HalfReader(bytes.NewReader(stream.Bytes())),
	} {
		var got [][]byte
		for {
			f, err := Read(r)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if f.Type == FrameControl {
				got = append(got, f.Payload)
			}
		}
		if len(got) != len(want) {
			t.Fatalf("%s: got %d frames, want %d", name, len(got), len(want))
		}
		for i := range want {
			if !bytes.Equal(got[i], want[i]) {
				t.Fatalf("%s: frame %d differs", name, i)
			}
		}
	}
}

func TestMalformedFrames(t *testing.T) {
	frame := func(length uint32, typ, flags byte, pad uint16, body int) []byte {
		b := make([]byte, 8+body)
		binary.BigEndian.PutUint32(b, length)
		b[4], b[5] = typ, flags
		binary.BigEndian.PutUint16(b[6:], pad)
		return b
	}
	cases := map[string][]byte{
		"length below header": frame(3, FrameControl, 0, 0, 0),
		"length 4 GB":         frame(0xFFFFFFFF, FrameControl, 0, 0, 0),
		"length over max":     frame(MaxFrame-3, FrameControl, 0, 0, 0),
		"padding over frame":  frame(10, FrameControl, 0, 7, 6),
		"unknown type":        frame(4, 0x7f, 0, 0, 0),
		"flags set":           frame(4, FrameControl, 1, 0, 0),
	}
	for name, b := range cases {
		_, err := Read(bytes.NewReader(b))
		if !errors.Is(err, ErrFrame) {
			t.Errorf("%s: err = %v, want ErrFrame", name, err)
		}
	}
	// Truncated input is an I/O error, not a hang.
	enc, _ := Encode(FrameControl, []byte("hello"))
	if _, err := Read(bytes.NewReader(enc[:len(enc)-1])); err != io.ErrUnexpectedEOF {
		t.Errorf("truncated: err = %v", err)
	}
}

func TestDecodeMsg(t *testing.T) {
	for _, bad := range []string{``, `{}`, `{"t":""}`, `[1]`, `{"t":"chat","size":"x"}`, "\xff\xfe"} {
		if _, err := DecodeMsg([]byte(bad)); err == nil {
			t.Errorf("DecodeMsg(%q) accepted", bad)
		}
	}
	m, err := DecodeMsg([]byte(`{"t":"chat","text":"hi","room":"#a","unknown":1}`))
	if err != nil || m.T != TChat || m.Text != "hi" || m.Room != "#a" {
		t.Fatalf("DecodeMsg = %+v, %v", m, err)
	}
}

func TestValidation(t *testing.T) {
	for _, ok := range []string{"alice", "Bob Smith", "a.b-c_d", "x"} {
		if !ValidUsername(ok) {
			t.Errorf("ValidUsername(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", " a", "a ", "<b>", "ä", "a\nb", "\x1b[31m", string(make([]byte, 33))} {
		if ValidUsername(bad) {
			t.Errorf("ValidUsername(%q) = true", bad)
		}
	}
	for _, ok := range []string{"#a", "#general", "#a.b-c_d"} {
		if !ValidRoomName(ok) {
			t.Errorf("ValidRoomName(%q) = false", ok)
		}
	}
	for _, bad := range []string{"#", "a", "##", "#a b", "#<x>", "#ä"} {
		if ValidRoomName(bad) {
			t.Errorf("ValidRoomName(%q) = true", bad)
		}
	}
	cases := map[string]string{
		"report.pdf":          "report.pdf",
		"../../etc/passwd":    "passwd",
		`C:\Users\x\evil.exe`: "evil.exe",
		"..":                  "",
		"a\x00b\nc":           "abc",
		"  ":                  "",
	}
	for in, want := range cases {
		if got := CleanFileName(in); got != want {
			t.Errorf("CleanFileName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseCommand(t *testing.T) {
	c, err := ParseCommand("/msg bob  hello   there ")
	if err != nil || c.Name != "msg" || c.Args[0] != "bob" || c.Rest != "hello   there" {
		t.Fatalf("msg: %+v %v", c, err)
	}
	c, err = ParseCommand(`/file bob "/tmp/my file.txt"`)
	if err != nil || c.Rest != "/tmp/my file.txt" {
		t.Fatalf("file: %+v %v", c, err)
	}
	c, err = ParseCommand("/JOIN #vault correct horse")
	if err != nil || c.Name != "join" || c.Args[0] != "#vault" || c.Rest != "correct horse" {
		t.Fatalf("join: %+v %v", c, err)
	}
	for _, bad := range []string{"/msg bob", "/join", "/nope", "/file bob"} {
		if _, err := ParseCommand(bad); err == nil {
			t.Errorf("ParseCommand(%q) accepted", bad)
		}
	}
}

func FuzzRead(f *testing.F) {
	ok, _ := Encode(FrameControl, []byte(`{"t":"chat","text":"hi"}`))
	data, _ := EncodeData([IDLen]byte{9}, []byte("chunk"))
	f.Add(ok)
	f.Add(data)
	f.Add([]byte{0, 0, 0, 4, 1, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		r := bytes.NewReader(b)
		for {
			fr, err := Read(r)
			if err != nil {
				return
			}
			if len(fr.Payload) > MaxPayload {
				t.Fatalf("payload of %d bytes", len(fr.Payload))
			}
			switch fr.Type {
			case FrameControl:
				DecodeMsg(fr.Payload)
			case FrameData:
				SplitData(fr.Payload)
			}
		}
	})
}

func FuzzDecodeMsg(f *testing.F) {
	f.Add([]byte(`{"t":"file_offer","to":"bob","name":"a.txt","size":5,"sha256":"00"}`))
	f.Add([]byte(`{"t":"join","room":"#a","password":"x"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := DecodeMsg(b)
		if err != nil {
			return
		}
		// Whatever decodes must re-encode within limits or fail cleanly.
		if enc, err := EncodeMsg(m); err == nil && len(enc) > MaxFrame {
			t.Fatalf("encoded message of %d bytes", len(enc))
		}
		ValidUsername(m.User)
		ValidRoomName(m.Room)
		CleanFileName(m.Name)
		ParseID(m.ID)
	})
}

func FuzzParseCommand(f *testing.F) {
	f.Add("/msg bob hi")
	f.Add(`/file bob "x y"`)
	f.Add("/join #a pw")
	f.Fuzz(func(t *testing.T, s string) {
		ParseCommand(s)
	})
}
