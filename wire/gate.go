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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"time"
)

// The gate keeps the server silent towards anyone without the access file.
//
// In TLS 1.3 the server sends its certificate before the client proves
// anything, so a plain TLS server shows its certificate to every scanner.
// To avoid that, the client puts a gate token in the server name (SNI) of
// its ClientHello. The server reads the ClientHello before starting TLS and
// closes the connection without sending a single byte unless the token is
// valid.
//
// A token is a random nonce plus an HMAC over the current minute and the
// nonce, keyed with a key derived from the access private key. The server
// accepts tokens from the last and next GateSkew minutes (clock skew) and
// remembers nonces, so a token seen on the wire cannot be replayed.

const (
	gateNonceLen = 12
	gateMACLen   = 16
	// GateTokenLen is the length of a token in characters (one DNS label).
	GateTokenLen = 2 * (gateNonceLen + gateMACLen)
	// GateSkew is how many minutes a client clock may be ahead or behind.
	GateSkew = 5
	// GateLifetime is how long a token stays valid; nonces must be
	// remembered at least this long.
	GateLifetime = (2*GateSkew + 2) * time.Minute
)

// GateKey derives the gate key from the DER bytes of the access private key
// (the PRIVATE KEY block of the access file).
func GateKey(accessKeyDER []byte) []byte {
	m := hmac.New(sha256.New, accessKeyDER)
	m.Write([]byte("quietroom gate v1"))
	return m.Sum(nil)
}

func gateMAC(key []byte, minute int64, nonce []byte) []byte {
	m := hmac.New(sha256.New, key)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(minute))
	m.Write(b[:])
	m.Write(nonce)
	return m.Sum(nil)[:gateMACLen]
}

func minuteOf(t time.Time) int64 { return t.Unix() / 60 }

// GateToken returns a fresh token for a connection made at now.
func GateToken(key []byte, now time.Time) string {
	nonce := make([]byte, gateNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return hex.EncodeToString(append(nonce, gateMAC(key, minuteOf(now), nonce)...))
}

// CheckGate reports whether name is a valid token at now, and returns its
// nonce for replay tracking.
func CheckGate(key []byte, name string, now time.Time) (nonce string, ok bool) {
	if len(name) != GateTokenLen {
		return "", false
	}
	b, err := hex.DecodeString(name)
	if err != nil {
		return "", false
	}
	n, mac := b[:gateNonceLen], b[gateNonceLen:]
	m := minuteOf(now)
	for d := int64(-GateSkew); d <= GateSkew; d++ {
		if hmac.Equal(mac, gateMAC(key, m+d, n)) {
			return string(n), true
		}
	}
	return "", false
}

// ErrNotClientHello is returned when the first bytes are not a well-formed
// TLS ClientHello contained in a single record.
var ErrNotClientHello = errors.New("not a TLS ClientHello")

const maxTLSRecord = 1 << 14

// ReadClientHello reads the first TLS record from r, which must hold a
// complete ClientHello, and returns the raw record (to be replayed to the
// TLS stack) and the host name from its SNI extension ("" if absent).
func ReadClientHello(r io.Reader) (record []byte, serverName string, err error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, "", err
	}
	n := int(binary.BigEndian.Uint16(hdr[3:]))
	if hdr[0] != 22 || hdr[1] != 3 || n < 4 || n > maxTLSRecord {
		return nil, "", ErrNotClientHello
	}
	record = make([]byte, 5+n)
	copy(record, hdr[:])
	if _, err := io.ReadFull(r, record[5:]); err != nil {
		return nil, "", err
	}
	name, err := clientHelloSNI(record[5:])
	if err != nil {
		return nil, "", err
	}
	return record, name, nil
}

// reader is a bounds-checked cursor over a byte slice.
type reader struct {
	b  []byte
	ok bool
}

func (r *reader) bytes(n int) []byte {
	if !r.ok || n < 0 || n > len(r.b) {
		r.ok = false
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) uint(n int) int {
	v := 0
	for _, c := range r.bytes(n) {
		v = v<<8 | int(c)
	}
	return v
}

// vec reads a vector with an n-byte length prefix.
func (r *reader) vec(n int) *reader { return &reader{b: r.bytes(r.uint(n)), ok: r.ok} }

func clientHelloSNI(body []byte) (string, error) {
	r := &reader{b: body, ok: true}
	if r.uint(1) != 1 { // handshake type: client_hello
		return "", ErrNotClientHello
	}
	hello := r.vec(3)
	hello.bytes(2 + 32) // legacy_version, random
	hello.vec(1)        // legacy_session_id
	hello.vec(2)        // cipher_suites
	hello.vec(1)        // legacy_compression_methods
	if !hello.ok {
		return "", ErrNotClientHello
	}
	if len(hello.b) == 0 {
		return "", nil // no extensions
	}
	exts := hello.vec(2)
	name := ""
	for exts.ok && len(exts.b) > 0 {
		typ := exts.uint(2)
		data := exts.vec(2)
		if !exts.ok {
			break
		}
		if typ != 0 { // server_name
			continue
		}
		list := data.vec(2)
		for list.ok && len(list.b) > 0 {
			kind := list.uint(1)
			host := list.vec(2)
			if list.ok && kind == 0 && name == "" {
				name = string(host.b)
			}
		}
		if !list.ok || !data.ok {
			return "", ErrNotClientHello
		}
	}
	if !exts.ok || !hello.ok || !r.ok {
		return "", ErrNotClientHello
	}
	return name, nil
}
