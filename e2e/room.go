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
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters for room passwords (RFC 9106, second recommended
// option). A malicious server sees material it could test password guesses
// against, so each guess is made expensive.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
)

// RoomSecret is what a room password yields. The password itself never
// leaves the client.
type RoomSecret struct {
	// Verifier is sent to the server, which admits members presenting the
	// same verifier. It reveals nothing about Auth.
	Verifier []byte
	auth     []byte // proves knowledge of the password to other members
	room     string
}

// DeriveRoom stretches a room password with Argon2id (about 64 MiB and a
// fraction of a second) and derives the verifier and the member key. The
// salt is fixed per room name, so nothing has to be stored anywhere.
func DeriveRoom(room, password string) RoomSecret {
	salt := sha256.Sum256(pack([]byte(labelRoomSalt), []byte(room)))
	secret := argon2.IDKey([]byte(password), salt[:], argonTime, argonMemory, argonThreads, KeyLen)
	vf, _ := hkdf.Key(sha256.New, secret, nil, labelRoomVf, KeyLen)
	auth, _ := hkdf.Key(sha256.New, secret, nil, labelRoomAuth, KeyLen)
	return RoomSecret{Verifier: vf, auth: auth, room: room}
}

// Proof shows other members that the holder of these session keys knows the
// room password. It binds the room, the member's name and both session keys.
func (r RoomSecret) Proof(user string, pub PublicKeys) []byte {
	return hmacSHA256(r.auth, pack([]byte(labelProof), []byte(r.room), []byte(strings.ToLower(user)), pub.KX, pub.SK))
}

// CheckProof verifies another member's proof.
func (r RoomSecret) CheckProof(user string, pub PublicKeys, proof []byte) bool {
	return hmac.Equal(r.Proof(user, pub), proof)
}

// SenderKey is the state of one member's sending chain in a room, as handed
// to other members: from it they can derive this and later message keys,
// never earlier ones.
type SenderKey struct {
	KID uint32 // identifies this key; a new one is made after a member leaves
	CK  []byte
	N   uint32 // counter of the next message
}

// Sender is our own sending chain in one room.
type Sender struct {
	room string
	kid  uint32
	c    chain
}

// NewSender creates a fresh sending chain with a random key ID.
func NewSender(room string) (*Sender, error) {
	s := &Sender{room: room}
	var b [4 + KeyLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	s.kid = binary.BigEndian.Uint32(b[:4])
	copy(s.c.ck[:], b[4:])
	return s, nil
}

// Key returns the current chain state, to share with a member.
func (s *Sender) Key() SenderKey {
	return SenderKey{KID: s.kid, CK: append([]byte{}, s.c.ck[:]...), N: s.c.n}
}

func roomAAD(room string, from PublicKeys, kid, n uint32) []byte {
	return pack([]byte(labelRoomAAD), []byte(room), from.KX, u32(kid), u32(n))
}

func roomSigInput(room string, kid, n uint32, ct []byte) []byte {
	return pack([]byte(labelRoomSig), []byte(room), u32(kid), u32(n), ct)
}

// Seal encrypts a room message and signs it with our session key, so other
// members, who all hold our chain key, still cannot forge messages from us.
func (s *Sender) Seal(id *Identity, plain []byte) (kid, n uint32, ct, sig []byte, err error) {
	padded, err := pad(plain)
	if err != nil {
		return 0, 0, nil, nil, err
	}
	mk, n, err := s.c.next()
	if err != nil {
		return 0, 0, nil, nil, err
	}
	ct = sealOnce(mk, padded, roomAAD(s.room, id.pub, s.kid, n))
	sig = ed25519.Sign(id.sk, roomSigInput(s.room, s.kid, n, ct))
	return s.kid, n, ct, sig, nil
}

// Receiver holds another member's sending chain in one room.
type Receiver struct {
	room string
	from PublicKeys
	kid  uint32
	r    recvChain
}

// NewReceiver accepts a member's sender key.
func NewReceiver(room string, from PublicKeys, k SenderKey) (*Receiver, error) {
	if len(k.CK) != KeyLen {
		return nil, errors.New("invalid sender key")
	}
	rc := &Receiver{room: room, from: from, kid: k.KID}
	copy(rc.r.ck[:], k.CK)
	rc.r.n = k.N
	return rc, nil
}

// KID returns the key ID this receiver decrypts.
func (rc *Receiver) KID() uint32 { return rc.kid }

// Open checks the signature and decrypts a room message.
func (rc *Receiver) Open(kid, n uint32, ct, sig []byte) ([]byte, error) {
	if kid != rc.kid {
		return nil, ErrDecrypt
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(rc.from.SK, roomSigInput(rc.room, kid, n, ct), sig) {
		return nil, ErrDecrypt
	}
	mk, commit, err := rc.r.key(n)
	if err != nil {
		return nil, err
	}
	padded, err := openOnce(mk, ct, roomAAD(rc.room, rc.from, kid, n))
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
