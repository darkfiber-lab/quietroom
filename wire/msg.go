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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Message types (Msg.T).
//
// Client to server:
//
//	hello{v,user}          first message; answered by welcome or error
//	chat{room,text}        room "" = lobby
//	dm{to,text}
//	join{room,password} leave{room}
//	rooms users members{room} help   (room "lobby" for lobby members)
//	file_offer{ref,to,name,size,sha256}
//	file_accept{id,bytes}  bytes = initial flow-control window
//	file_credit{id,bytes}  grant more window
//	file_decline{id} file_cancel{id} file_end{id}
//	quit
//
// Server to client:
//
//	welcome{user,v}
//	chat{from,room,text,time} dm{from,to,text,time}
//	joined{user,room,created} left{user,room}   room "" = the chat itself
//	info{text} error{code,text}
//	file_offer{id,from,name,size,sha256}        to the recipient
//	file_offered{ref,id,to,name}                to the sender
//	file_accept{id,bytes} file_credit{id,bytes} to the sender
//	file_decline{id,user} file_cancel{id,text}
//	file_end{id}                                 to the recipient
//	file_done{id}                                to the sender
const (
	THello       = "hello"
	TWelcome     = "welcome"
	TChat        = "chat"
	TDM          = "dm"
	TJoin        = "join"
	TJoined      = "joined"
	TLeave       = "leave"
	TLeft        = "left"
	TRooms       = "rooms"
	TUsers       = "users"
	TMembers     = "members"
	THelp        = "help"
	TInfo        = "info"
	TError       = "error"
	TQuit        = "quit"
	TFileOffer   = "file_offer"
	TFileOffered = "file_offered"
	TFileAccept  = "file_accept"
	TFileCredit  = "file_credit"
	TFileDecline = "file_decline"
	TFileCancel  = "file_cancel"
	TFileEnd     = "file_end"
	TFileDone    = "file_done"
)

// Error codes (Msg.Code) the client may act on.
const (
	CodeUsernameTaken   = "username_taken"
	CodeInvalidUsername = "invalid_username"
	CodeVersion         = "version"
	CodeProtocol        = "protocol"
	CodeRateLimited     = "rate_limited"
)

// Limits shared by server and clients.
const (
	MaxTextBytes     = 8 * 1024 // chat and DM text
	MaxUsernameLen   = 32
	MaxRoomNameLen   = 32
	MaxFileNameBytes = 255
	MaxPasswordBytes = 256
)

// Flow control for file transfers. The recipient grants credit in bytes; the
// sender never has more than the granted amount in flight.
const (
	InitialWindow = 1 << 20 // granted on accept
	CreditStep    = 256 << 10
	MaxWindow     = 4 << 20 // outstanding credit the server allows per transfer
)

// Msg is a control message. One flat struct keeps the encoding simple for
// every client (Go and Python); unused fields are omitted.
type Msg struct {
	T        string `json:"t"`
	V        int    `json:"v,omitempty"`
	User     string `json:"user,omitempty"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Room     string `json:"room,omitempty"`
	Text     string `json:"text,omitempty"`
	Password string `json:"password,omitempty"`
	Time     string `json:"time,omitempty"`
	Code     string `json:"code,omitempty"`
	Created  bool   `json:"created,omitempty"`
	Ref      string `json:"ref,omitempty"`
	ID       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	Size     int64  `json:"size,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Bytes    int64  `json:"bytes,omitempty"`
}

// EncodeMsg builds a control frame.
func EncodeMsg(m Msg) ([]byte, error) {
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return Encode(FrameControl, payload)
}

// DecodeMsg parses a control frame payload.
func DecodeMsg(payload []byte) (Msg, error) {
	var m Msg
	if !utf8.Valid(payload) {
		return m, fmt.Errorf("%w: control message is not UTF-8", ErrFrame)
	}
	if err := json.Unmarshal(payload, &m); err != nil {
		return m, fmt.Errorf("%w: %v", ErrFrame, err)
	}
	if m.T == "" {
		return m, fmt.Errorf("%w: message without type", ErrFrame)
	}
	return m, nil
}

// NewID returns a random transfer ID.
func NewID() ([IDLen]byte, error) {
	var id [IDLen]byte
	_, err := rand.Read(id[:])
	return id, err
}

// IDString encodes a transfer ID for control messages.
func IDString(id [IDLen]byte) string { return hex.EncodeToString(id[:]) }

// ParseID decodes a transfer ID from a control message.
func ParseID(s string) ([IDLen]byte, bool) {
	var id [IDLen]byte
	if len(s) != 2*IDLen {
		return id, false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return id, false
	}
	copy(id[:], b)
	return id, true
}

// ValidUsername: 1-32 ASCII letters, digits, space, '_', '-', '.', not only
// spaces, no leading or trailing space.
func ValidUsername(name string) bool {
	if name == "" || len(name) > MaxUsernameLen || strings.TrimSpace(name) != name {
		return false
	}
	for _, ch := range name {
		ok := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == ' ' || ch == '_' || ch == '-' || ch == '.'
		if !ok {
			return false
		}
	}
	return true
}

// ValidRoomName: "#" followed by 1-32 ASCII letters, digits, '_', '-', '.'.
func ValidRoomName(name string) bool {
	if !strings.HasPrefix(name, "#") {
		return false
	}
	rest := name[1:]
	if rest == "" || len(rest) > MaxRoomNameLen {
		return false
	}
	for _, ch := range rest {
		ok := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.'
		if !ok {
			return false
		}
	}
	return true
}

// ValidSHA256 checks for 64 lowercase or uppercase hex characters.
func ValidSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// CleanFileName reduces a file name to a safe base name for display and
// saving: no directories, no control characters, at most 255 bytes. It
// returns "" if nothing usable remains.
func CleanFileName(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 || r == utf8.RuneError {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	for len(name) > MaxFileNameBytes {
		_, size := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-size]
	}
	if name == "" || name == "." || name == ".." {
		return ""
	}
	return name
}
