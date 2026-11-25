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

import "testing"

// Hostile input reaches these functions straight from the network: they must
// never panic, and never accept anything a genuine sender did not produce.

func FuzzPairOpen(f *testing.F) {
	a, _ := NewIdentity()
	b, _ := NewIdentity()
	ab, _ := a.NewPair(b.Public())
	n, ct, _ := ab.Seal("dm", []byte("seed"))
	f.Add(n, ct, "dm")
	f.Add(uint32(5000), []byte{}, "rkey")
	f.Fuzz(func(t *testing.T, n uint32, ct []byte, kind string) {
		ba, _ := b.NewPair(a.Public())
		if plain, err := ba.Open(kind, n, ct); err == nil && string(plain) != "seed" {
			t.Fatalf("forged message accepted: %q", plain)
		}
	})
}

func FuzzRoomOpen(f *testing.F) {
	id, _ := NewIdentity()
	s, _ := NewSender("#r")
	kid, n, ct, sig, _ := s.Seal(id, []byte("seed"))
	f.Add(kid, n, ct, sig)
	f.Fuzz(func(t *testing.T, kid, n uint32, ct, sig []byte) {
		r, _ := NewReceiver("#r", id.Public(), SenderKey{KID: s.kid, CK: make([]byte, KeyLen)})
		r.Open(kid, n, ct, sig) // must not panic
		r2, _ := NewReceiver("#r", id.Public(), SenderKey{KID: kid, CK: make([]byte, KeyLen), N: n})
		r2.Open(kid, n, ct, sig)
	})
}

func FuzzParsePublicKeys(f *testing.F) {
	id, _ := NewIdentity()
	kx, sk := id.Public().Encode()
	f.Add(kx, sk)
	f.Fuzz(func(t *testing.T, kx, sk string) {
		if p, err := ParsePublicKeys(kx, sk); err == nil {
			id.NewPair(p) // must not panic
		}
	})
}

func FuzzFileOpen(f *testing.F) {
	f.Add(make([]byte, CipherChunk), true)
	f.Fuzz(func(t *testing.T, ct []byte, last bool) {
		o, _ := NewFileOpener(make([]byte, KeyLen))
		if _, err := o.Open(ct, last); err == nil {
			// Only a genuine chunk under this key may open.
			s, _ := NewFileSealer(make([]byte, KeyLen))
			if _, err := s.Seal(nil, last); err != nil {
				t.Fatal(err)
			}
		}
	})
}
