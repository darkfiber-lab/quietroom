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

// Package e2e implements QuietRoom's end-to-end encryption (protocol 4):
// direct messages, file transfers and password rooms are encrypted between
// clients, so the server relays data it cannot read. See docs/E2E_DESIGN.md.
//
// Every key is created per connection and kept in memory only. The package
// uses standard primitives only: X25519, Ed25519, HKDF-SHA256, HMAC-SHA256,
// SHA-512, ChaCha20-Poly1305 and Argon2id.
package e2e

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// KeyLen is the length of every public key and symmetric key.
const KeyLen = 32

// Domain-separation labels. Changing any of them changes the protocol.
const (
	labelPair     = "QuietRoom v4 pair"
	labelPairAAD  = "QuietRoom v4 pair message"
	labelRoomSalt = "QuietRoom v4 room salt"
	labelRoomVf   = "QuietRoom v4 room verifier"
	labelRoomAuth = "QuietRoom v4 room auth"
	labelProof    = "QuietRoom v4 room member"
	labelRoomAAD  = "QuietRoom v4 room message"
	labelRoomSig  = "QuietRoom v4 room signature"
	labelFile     = "QuietRoom v4 file"
	labelSafety   = "QuietRoom v4 safety number"
)

var (
	// ErrDecrypt reports a message that does not authenticate: wrong key,
	// tampered, replayed or not meant for us.
	ErrDecrypt = errors.New("message could not be decrypted")
	// ErrKey reports an unusable public key.
	ErrKey = errors.New("invalid public key")
)

// b64 is the encoding of keys and ciphertexts in control messages.
var b64 = base64.StdEncoding

// Encode encodes bytes for a control message.
func Encode(b []byte) string { return b64.EncodeToString(b) }

// Decode decodes a control-message field, refusing more than max bytes.
func Decode(s string, max int) ([]byte, error) {
	if b64.DecodedLen(len(s)) > max+2 {
		return nil, fmt.Errorf("field too long")
	}
	b, err := b64.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) > max {
		return nil, fmt.Errorf("field too long")
	}
	return b, nil
}

// pack joins fields unambiguously: each is prefixed with its length as a
// 4-byte big-endian integer. Used for every HKDF info, AAD, MAC and
// signature input.
func pack(fields ...[]byte) []byte {
	n := 0
	for _, f := range fields {
		n += 4 + len(f)
	}
	out := make([]byte, 0, n)
	for _, f := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out
}

func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func hmacSHA256(key []byte, data ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, d := range data {
		m.Write(d)
	}
	return m.Sum(nil)
}

// ── Session identity ───────────────────────────────────────────────

// PublicKeys are a member's session public keys as relayed by the server.
type PublicKeys struct {
	KX []byte // X25519, for key agreement
	SK []byte // Ed25519, for signing room messages
}

// Encode returns the keys as control-message fields.
func (p PublicKeys) Encode() (kx, sk string) { return Encode(p.KX), Encode(p.SK) }

// Equal reports whether two key sets are the same.
func (p PublicKeys) Equal(o PublicKeys) bool {
	return hmac.Equal(p.KX, o.KX) && hmac.Equal(p.SK, o.SK)
}

// ParsePublicKeys decodes and checks keys from control-message fields.
func ParsePublicKeys(kx, sk string) (PublicKeys, error) {
	k, err1 := Decode(kx, KeyLen)
	s, err2 := Decode(sk, KeyLen)
	if err1 != nil || err2 != nil || len(k) != KeyLen || len(s) != ed25519.PublicKeySize {
		return PublicKeys{}, ErrKey
	}
	if _, err := ecdh.X25519().NewPublicKey(k); err != nil {
		return PublicKeys{}, ErrKey
	}
	return PublicKeys{KX: k, SK: s}, nil
}

// Identity is this connection's key pair. It lives for one connection.
type Identity struct {
	kx  *ecdh.PrivateKey
	sk  ed25519.PrivateKey
	pub PublicKeys
}

// NewIdentity creates fresh session keys.
func NewIdentity() (*Identity, error) {
	kx, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	spub, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{kx: kx, sk: sk, pub: PublicKeys{KX: kx.PublicKey().Bytes(), SK: spub}}, nil
}

// Public returns the session public keys.
func (id *Identity) Public() PublicKeys { return id.pub }

// ── Padding ────────────────────────────────────────────────────────

const (
	minPadded = 64
	// MaxPadded bounds a padded plaintext (and so every ciphertext).
	MaxPadded = 32 * 1024
)

// pad appends 0x80 and zero bytes up to the next power of two (at least
// 64), so ciphertext lengths reveal only a size class.
func pad(b []byte) ([]byte, error) {
	size := minPadded
	for size < len(b)+1 {
		size *= 2
	}
	if size > MaxPadded {
		return nil, fmt.Errorf("message too large to encrypt")
	}
	out := make([]byte, size)
	copy(out, b)
	out[len(b)] = 0x80
	return out, nil
}

func unpad(b []byte) ([]byte, error) {
	i := len(b) - 1
	for i >= 0 && b[i] == 0 {
		i--
	}
	if i < 0 || b[i] != 0x80 {
		return nil, ErrDecrypt
	}
	return b[:i], nil
}

func ecdhPublic(kx []byte) (*ecdh.PublicKey, error) {
	pk, err := ecdh.X25519().NewPublicKey(kx)
	if err != nil {
		return nil, ErrKey
	}
	return pk, nil
}

// sealOnce encrypts with a key used for exactly one message, so a zero
// nonce is safe.
func sealOnce(key, plain, aad []byte) []byte {
	aead, _ := chacha20poly1305.New(key)
	return aead.Seal(nil, make([]byte, chacha20poly1305.NonceSize), plain, aad)
}

func openOnce(key, ct, aad []byte) ([]byte, error) {
	aead, _ := chacha20poly1305.New(key)
	out, err := aead.Open(nil, make([]byte, chacha20poly1305.NonceSize), ct, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}

// ── Symmetric ratchet ──────────────────────────────────────────────

// chain is a KDF chain: each step yields a one-time message key and replaces
// the chain key, so earlier message keys cannot be recomputed from a later
// state (forward secrecy within the connection).
type chain struct {
	ck [KeyLen]byte
	n  uint32 // number of the next message key
}

func step(ck []byte) (mk, next []byte) {
	return hmacSHA256(ck, []byte{1}), hmacSHA256(ck, []byte{2})
}

func (c *chain) next() (mk []byte, n uint32, err error) {
	if c.n == ^uint32(0) {
		return nil, 0, errors.New("key chain exhausted")
	}
	mk, nck := step(c.ck[:])
	n = c.n
	copy(c.ck[:], nck)
	c.n++
	return mk, n, nil
}

// MaxSkip is how far ahead of the expected message a received counter may
// be; keys for the messages skipped are kept (up to maxStored) so they can
// still arrive late.
const (
	MaxSkip   = 1024
	maxStored = 256
)

// recvChain is the receiving side of a chain, tolerating dropped and
// reordered messages.
type recvChain struct {
	chain
	skipped map[uint32][]byte
	order   []uint32
}

// key returns the message key for counter n without changing state; commit
// applies the change once the message authenticated.
func (r *recvChain) key(n uint32) (mk []byte, commit func(), err error) {
	if n < r.n {
		mk, ok := r.skipped[n]
		if !ok {
			return nil, nil, ErrDecrypt // replay, or too old
		}
		return mk, func() { delete(r.skipped, n) }, nil
	}
	if n-r.n > MaxSkip {
		return nil, nil, ErrDecrypt
	}
	ck := r.ck[:]
	var keys [][]byte
	for i := r.n; i < n; i++ {
		var mki []byte
		mki, ck = step(ck)
		keys = append(keys, mki)
	}
	mk, nck := step(ck)
	return mk, func() {
		if r.skipped == nil {
			r.skipped = make(map[uint32][]byte)
		}
		for i, k := range keys {
			idx := r.n + uint32(i)
			r.skipped[idx] = k
			r.order = append(r.order, idx)
		}
		for len(r.skipped) > maxStored && len(r.order) > 0 {
			delete(r.skipped, r.order[0])
			r.order = r.order[1:]
		}
		if len(r.order) > 4*maxStored {
			kept := r.order[:0]
			for _, i := range r.order {
				if _, ok := r.skipped[i]; ok {
					kept = append(kept, i)
				}
			}
			r.order = kept
		}
		copy(r.ck[:], nck)
		r.n = n + 1
	}, nil
}
