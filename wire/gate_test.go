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
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

func TestGateToken(t *testing.T) {
	key := GateKey([]byte("access key"))
	other := GateKey([]byte("another access key"))
	now := time.Unix(1_800_000_000, 0)

	tok := GateToken(key, now)
	if len(tok) != GateTokenLen || len(tok) > 63 || strings.ToLower(tok) != tok {
		t.Fatalf("token %q is not a single lowercase DNS label of %d chars", tok, GateTokenLen)
	}
	if tok == GateToken(key, now) {
		t.Fatal("two tokens are equal: the nonce is not random")
	}
	nonce, ok := CheckGate(key, tok, now)
	if !ok || len(nonce) != gateNonceLen {
		t.Fatal("valid token refused")
	}
	if _, ok := CheckGate(key, strings.ToUpper(tok), now); !ok {
		t.Fatal("upper-case token refused (DNS names are case-insensitive)")
	}
	for _, d := range []time.Duration{-GateSkew * time.Minute, GateSkew * time.Minute, -90 * time.Second, 4 * time.Minute} {
		if _, ok := CheckGate(key, GateToken(key, now.Add(d)), now); !ok {
			t.Errorf("token from %s away refused", d)
		}
	}
	for _, d := range []time.Duration{-(GateSkew + 1) * time.Minute, (GateSkew + 1) * time.Minute, -time.Hour, 24 * time.Hour} {
		if _, ok := CheckGate(key, GateToken(key, now.Add(d)), now); ok {
			t.Errorf("token from %s away accepted", d)
		}
	}
	if _, ok := CheckGate(other, tok, now); ok {
		t.Error("token accepted under another key")
	}
	flipped := []byte(tok)
	flipped[len(flipped)-1] ^= 1
	for _, bad := range []string{"", "localhost", "130.61.45.243", tok[:len(tok)-2], tok + "00", string(flipped), strings.Repeat("z", GateTokenLen)} {
		if _, ok := CheckGate(key, bad, now); ok {
			t.Errorf("CheckGate(%q) accepted", bad)
		}
	}
}

// captureHello returns the first record a real Go TLS client sends.
func captureHello(t testing.TB, serverName string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go tls.Client(c1, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}).Handshake()
	rec, name, err := ReadClientHello(c2)
	if err != nil {
		t.Fatal(err)
	}
	if name != serverName {
		t.Fatalf("server name = %q, want %q", name, serverName)
	}
	return rec
}

func TestReadClientHello(t *testing.T) {
	tok := GateToken(GateKey([]byte("k")), time.Now())
	rec := captureHello(t, tok)
	// The record is returned unchanged, followed by nothing else.
	got, name, err := ReadClientHello(bytes.NewReader(append(rec, "rest"...)))
	if err != nil || name != tok || !bytes.Equal(got, rec) {
		t.Fatalf("re-read: %q %v", name, err)
	}
	captureHello(t, "") // no SNI at all

	for name, in := range map[string][]byte{
		"empty":           nil,
		"http":            []byte("GET / HTTP/1.1\r\n\r\n"),
		"not handshake":   append([]byte{23}, rec[1:]...),
		"oversize record": {22, 3, 1, 0x40, 0x01},
		"truncated":       rec[:len(rec)-1],
		"hello too long":  func() []byte { b := bytes.Clone(rec); b[7]++; return b }(),
	} {
		if _, _, err := ReadClientHello(bytes.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func FuzzReadClientHello(f *testing.F) {
	f.Add(captureHello(f, GateToken(GateKey([]byte("k")), time.Now())))
	f.Add(captureHello(f, ""))
	f.Add([]byte{22, 3, 1, 0, 4, 1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		rec, _, err := ReadClientHello(bytes.NewReader(data))
		if err == nil && !bytes.Equal(rec, data[:len(rec)]) {
			t.Fatal("record differs from the input")
		}
	})
}
