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

package e2e

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Pair is the encrypted channel between this connection and one other
// member. It carries direct messages, file offers and room keys. Each
// direction has its own KDF chain; the wire message type is authenticated,
// so the server cannot pass one kind of message off as another.
type Pair struct {
	mu   sync.Mutex
	self PublicKeys
	peer PublicKeys
	send chain
	recv recvChain
}

// NewPair sets up the channel with a member's session keys. Both sides
// derive the same two chains from X25519 between their session keys.
func (id *Identity) NewPair(peer PublicKeys) (*Pair, error) {
	if bytes.Equal(peer.KX, id.pub.KX) {
		return nil, errors.New("cannot open a channel to ourselves")
	}
	pk, err := ecdhPublic(peer.KX)
	if err != nil {
		return nil, err
	}
	shared, err := id.kx.ECDH(pk)
	if err != nil {
		return nil, ErrKey // low-order point
	}
	// Order the two key sets so both sides build the same info string.
	lo, hi := id.pub, peer
	selfFirst := true
	if bytes.Compare(lo.KX, hi.KX) > 0 {
		lo, hi = hi, lo
		selfFirst = false
	}
	info := pack([]byte(labelPair), lo.KX, lo.SK, hi.KX, hi.SK)
	okm, err := hkdf.Key(sha256.New, shared, nil, string(info), 2*KeyLen)
	if err != nil {
		return nil, err
	}
	p := &Pair{self: id.pub, peer: peer}
	loToHi, hiToLo := okm[:KeyLen], okm[KeyLen:]
	if selfFirst {
		copy(p.send.ck[:], loToHi)
		copy(p.recv.ck[:], hiToLo)
	} else {
		copy(p.send.ck[:], hiToLo)
		copy(p.recv.ck[:], loToHi)
	}
	return p, nil
}

// Peer returns the keys the channel was opened with.
func (p *Pair) Peer() PublicKeys { return p.peer }

func pairAAD(kind string, from, to PublicKeys, n uint32) []byte {
	return pack([]byte(labelPairAAD), []byte(kind), from.KX, to.KX, u32(n))
}

// Seal encrypts one message of the given wire type (dm, rkey, file_offer).
func (p *Pair) Seal(kind string, plain []byte) (n uint32, ct []byte, err error) {
	padded, err := pad(plain)
	if err != nil {
		return 0, nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	mk, n, err := p.send.next()
	if err != nil {
		return 0, nil, err
	}
	return n, sealOnce(mk, padded, pairAAD(kind, p.self, p.peer, n)), nil
}

// Open decrypts message n of the given wire type. A message that does not
// authenticate leaves the channel unchanged.
func (p *Pair) Open(kind string, n uint32, ct []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	mk, commit, err := p.recv.key(n)
	if err != nil {
		return nil, err
	}
	padded, err := openOnce(mk, ct, pairAAD(kind, p.peer, p.self, n))
	if err != nil {
		return nil, err
	}
	plain, err := unpad(padded)
	if err != nil {
		return nil, err
	}
	commit()
	return plain, nil
}

// ── Safety numbers ─────────────────────────────────────────────────

// fingerprint is a member's 30-digit number for one session, computed like
// Signal's: 5200 iterations of SHA-512 over the keys and name.
func fingerprint(user string, pub PublicKeys) string {
	keys := append(append([]byte{}, pub.KX...), pub.SK...)
	h := sha512.Sum512(pack([]byte(labelSafety), []byte(strings.ToLower(user)), keys))
	for i := 0; i < 5200; i++ {
		h = sha512.Sum512(append(h[:], keys...))
	}
	var b strings.Builder
	for i := 0; i < 6; i++ {
		c := h[i*5 : i*5+5]
		v := uint64(c[0])<<32 | uint64(c[1])<<24 | uint64(c[2])<<16 | uint64(c[3])<<8 | uint64(c[4])
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%05d", v%100000)
	}
	return b.String()
}

// SafetyNumber returns the number identifying a member's session keys.
// Two members compare both of their numbers over another channel: if they
// match, nobody (the server included) is between them. Numbers change with
// every connection.
func SafetyNumber(user string, pub PublicKeys) string { return fingerprint(user, pub) }
