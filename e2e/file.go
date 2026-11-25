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
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// File encryption: the sender picks a random key per file and sends it
// inside the encrypted offer. The file travels in chunks that each fill one
// data frame exactly; the last chunk is padded with zeros, so the server
// learns the size only to the nearest chunk.
const (
	// CipherChunk is one encrypted chunk: it equals wire.DataChunk.
	CipherChunk = 32*1024 - 8 - 16
	// PlainChunk is the file bytes carried per chunk.
	PlainChunk = CipherChunk - chacha20poly1305.Overhead
)

// CipherSize is the number of bytes sent on the wire for a file of size
// bytes.
func CipherSize(size int64) int64 {
	chunks := (size + PlainChunk - 1) / PlainChunk
	return chunks * CipherChunk
}

// NewFileKey returns a random file key.
func NewFileKey() ([]byte, error) {
	k := make([]byte, KeyLen)
	_, err := rand.Read(k)
	return k, err
}

// fileNonce is the chunk index, with the last byte marking the final chunk
// (as in the STREAM construction), so chunks cannot be reordered, dropped
// or the file cut short without detection.
func fileNonce(i uint64, last bool) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(n, i)
	if last {
		n[len(n)-1] = 1
	}
	return n
}

// FileSealer encrypts a file chunk by chunk.
type FileSealer struct {
	aead cipher.AEAD
	i    uint64
	done bool
}

// NewFileSealer starts encrypting with a file key.
func NewFileSealer(key []byte) (*FileSealer, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &FileSealer{aead: aead}, nil
}

// Seal encrypts up to PlainChunk bytes; last marks the final chunk. The
// result is always CipherChunk bytes.
func (f *FileSealer) Seal(plain []byte, last bool) ([]byte, error) {
	if f.done || len(plain) > PlainChunk {
		return nil, errors.New("invalid file chunk")
	}
	buf := make([]byte, PlainChunk)
	copy(buf, plain)
	ct := f.aead.Seal(nil, fileNonce(f.i, last), buf, []byte(labelFile))
	f.i++
	f.done = last
	return ct, nil
}

// FileOpener decrypts a file chunk by chunk.
type FileOpener struct {
	aead cipher.AEAD
	i    uint64
	done bool
}

// NewFileOpener starts decrypting with a file key.
func NewFileOpener(key []byte) (*FileOpener, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &FileOpener{aead: aead}, nil
}

// Open decrypts the next chunk; the caller says whether it expects it to be
// the last one (it knows the file size from the offer).
func (f *FileOpener) Open(ct []byte, last bool) ([]byte, error) {
	if f.done || len(ct) != CipherChunk {
		return nil, ErrDecrypt
	}
	plain, err := f.aead.Open(nil, fileNonce(f.i, last), ct, []byte(labelFile))
	if err != nil {
		return nil, ErrDecrypt
	}
	f.i++
	f.done = last
	return plain, nil
}

// Done reports whether the final chunk was decrypted.
func (f *FileOpener) Done() bool { return f.done }
