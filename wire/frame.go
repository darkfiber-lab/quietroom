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

// Package wire implements the QuietRoom protocol, version 4, spoken inside a
// mutually authenticated TLS 1.3 connection.
//
// Every frame is self-delimiting:
//
//	| length (4) | type (1) | flags (1) | padding length (2) | payload | padding |
//
// length counts every byte after the length field. The receiver reads exactly
// that many bytes, so frame boundaries never depend on timing or on how TLS
// splits records. Frames are padded to size buckets to hide message lengths
// from network observers; the padding length is only visible inside TLS.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Version is the protocol version announced in the hello message.
const Version = 4

// Frame types.
const (
	FrameControl byte = 0x01 // JSON-encoded Msg
	FrameDecoy   byte = 0x02 // random cover traffic, discarded by the receiver
	FrameData    byte = 0x03 // file data: 16-byte transfer ID followed by file bytes
)

const (
	lengthLen = 4
	headerLen = 4 // type, flags, padding length (after the length field)

	// MaxFrame is the largest frame on the wire, length field included.
	MaxFrame = 64 * 1024

	// minFrame is the smallest bucket a frame is padded to.
	minFrame = 256

	// IDLen is the length of a binary transfer ID.
	IDLen = 16

	// DataChunk is the number of file bytes per data frame, chosen so a full
	// data frame fills a 32 KiB bucket exactly (no padding overhead).
	DataChunk = 32*1024 - lengthLen - headerLen - IDLen

	// MaxPayload is the largest payload a frame can carry.
	MaxPayload = MaxFrame - lengthLen - headerLen
)

// ErrFrame reports a malformed frame. The connection cannot be resynchronised
// after it and must be closed.
var ErrFrame = errors.New("malformed frame")

// Frame is one decoded frame.
type Frame struct {
	Type    byte
	Payload []byte
}

// bucket returns the padded wire size for a frame of n bytes (length field
// included): the next power of two, at least minFrame, at most MaxFrame.
func bucket(n int) int {
	size := minFrame
	for size < n {
		size *= 2
	}
	if size > MaxFrame {
		size = MaxFrame
	}
	return size
}

// Encode builds a padded frame. Padding bytes are zero: they are encrypted by
// TLS, so their content is irrelevant.
func Encode(typ byte, payload []byte) ([]byte, error) {
	return EncodeSize(typ, payload, 0)
}

// EncodeSize builds a frame padded to at least minSize bytes on the wire
// (used for decoys of a chosen size). The result never exceeds MaxFrame.
func EncodeSize(typ byte, payload []byte, minSize int) ([]byte, error) {
	if len(payload) > MaxPayload {
		return nil, fmt.Errorf("payload too large: %d bytes (max %d)", len(payload), MaxPayload)
	}
	n := lengthLen + headerLen + len(payload)
	if minSize > n {
		n = minSize
	}
	size := bucket(n)
	pad := size - (lengthLen + headerLen + len(payload))
	buf := make([]byte, size)
	binary.BigEndian.PutUint32(buf[0:4], uint32(size-lengthLen))
	buf[4] = typ
	buf[5] = 0 // flags: reserved
	binary.BigEndian.PutUint16(buf[6:8], uint16(pad))
	copy(buf[lengthLen+headerLen:], payload)
	return buf, nil
}

// Read reads exactly one frame. Any inconsistency returns an error wrapping
// ErrFrame; the caller must then close the connection.
func Read(r io.Reader) (Frame, error) {
	var lb [lengthLen]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return Frame{}, err
	}
	length := binary.BigEndian.Uint32(lb[:])
	if length < headerLen || length > MaxFrame-lengthLen {
		return Frame{}, fmt.Errorf("%w: length %d", ErrFrame, length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return Frame{}, err
	}
	typ, flags := body[0], body[1]
	pad := int(binary.BigEndian.Uint16(body[2:4]))
	if flags != 0 {
		return Frame{}, fmt.Errorf("%w: unknown flags 0x%02x", ErrFrame, flags)
	}
	if pad > int(length)-headerLen {
		return Frame{}, fmt.Errorf("%w: padding %d exceeds frame", ErrFrame, pad)
	}
	switch typ {
	case FrameControl, FrameDecoy, FrameData:
	default:
		return Frame{}, fmt.Errorf("%w: unknown type 0x%02x", ErrFrame, typ)
	}
	return Frame{Type: typ, Payload: body[headerLen : int(length)-pad]}, nil
}

// EncodeData builds a data frame for the given transfer.
func EncodeData(id [IDLen]byte, data []byte) ([]byte, error) {
	if len(data) > DataChunk {
		return nil, fmt.Errorf("data chunk too large: %d bytes (max %d)", len(data), DataChunk)
	}
	payload := make([]byte, IDLen+len(data))
	copy(payload, id[:])
	copy(payload[IDLen:], data)
	return Encode(FrameData, payload)
}

// SplitData splits a data frame payload into transfer ID and file bytes.
func SplitData(payload []byte) (id [IDLen]byte, data []byte, err error) {
	if len(payload) < IDLen || len(payload) > IDLen+DataChunk {
		return id, nil, fmt.Errorf("%w: data payload of %d bytes", ErrFrame, len(payload))
	}
	copy(id[:], payload[:IDLen])
	return id, payload[IDLen:], nil
}
