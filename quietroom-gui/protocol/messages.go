package protocol

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Compiled patterns for server message parsing
var (
	reLobbyMsg	  = regexp.MustCompile(`^\[(\d{2}:\d{2}:\d{2})\] (?:\[(#\S+)\] )?(.+?): (.+)$`)
	reDMFrom      = regexp.MustCompile(`^\[DM from (.+?)\]: (.+)$`)
	reDMTo        = regexp.MustCompile(`^\[DM to (.+?)\]: (.+)$`)
	reUserJoined  = regexp.MustCompile(`^\*\*\* (.+) joined the chat \*\*\*$`)
	reUserLeft    = regexp.MustCompile(`^\*\*\* (.+) left the chat \*\*\*$`)
	reRoomJoined  = regexp.MustCompile(`^\*\*\* (.+) joined (#\S+) \*\*\*$`)
	reRoomLeft    = regexp.MustCompile(`^\*\*\* (.+) left (#\S+) \*\*\*$`)
	reFileRequest = regexp.MustCompile(`(?s)^\*\*\* FILE TRANSFER REQUEST \*\*\*\nSender: (.+)\nFile: (.+)\nSHA-256: (.+)\nTransfer ID: (.+)\n`)
	reBeginSend   = regexp.MustCompile(`^BEGIN_SEND\|(.+)\|(.+)$`)
)

// ChatMessage is a parsed, display-ready message
type ChatMessage struct {
	Timestamp string
	Username  string
	Text      string
	Room      string // empty for lobby
	IsDM      bool
	IsSystem  bool
	IsOwn     bool
}

// dispatchMessageEvent parses a raw decrypted server message and fires the
// appropriate Event on the handler
func (c *Client) dispatchMessageEvent(text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}

	now := time.Now().Format("15:04:05")

	// File transfer: BEGIN_SEND instructs us to start sending a file
	if m := reBeginSend.FindStringSubmatch(text); m != nil {
		c.handler(Event{
			Type: EvtFileBeginSend,
			Payload: map[string]string{
				"filename":     m[1],
				"expectedHash": m[2],
			},
		})
		return
	}

	// Incoming file transfer request
	if m := reFileRequest.FindStringSubmatch(text); m != nil {
		c.handler(Event{
			Type: EvtFileRequest,
			Payload: FileRequestPayload{
				SenderName:   m[1],
				Filename:     m[2],
				ExpectedHash: m[3],
				TransferID:   m[4],
			},
		})
		return
	}

	// DM received
	if m := reDMFrom.FindStringSubmatch(text); m != nil {
		c.handler(Event{
			Type:   EvtPrivateMessage,
			Sender: m[1],
			Text:   m[2],
			Payload: ChatMessage{
				Timestamp: now,
				Username:  m[1],
				Text:      m[2],
				IsDM:      true,
			},
		})
		return
	}

	// DM sent echo (our own DM confirmation)
	if m := reDMTo.FindStringSubmatch(text); m != nil {
		c.handler(Event{
			Type:   EvtPrivateMessage,
			Sender: fmt.Sprintf("__self__%s", m[1]),
			Text:   m[2],
			Payload: ChatMessage{
				Timestamp: now,
				Username:  "You",
				Text:      m[2],
				IsDM:      true,
				IsOwn:     true,
			},
		})
		return
	}

	// User joined lobby
	if m := reUserJoined.FindStringSubmatch(text); m != nil {
		c.handler(Event{
			Type:   EvtUserJoined,
			Sender: m[1],
			Text:   text,
		})
		return
	}

	// User left lobby
	if m := reUserLeft.FindStringSubmatch(text); m != nil {
		c.handler(Event{
			Type:   EvtUserLeft,
			Sender: m[1],
			Text:   text,
		})
		return
	}

	// User joined a room
	if m := reRoomJoined.FindStringSubmatch(text); m != nil {
		c.handler(Event{
			Type:   EvtRoomJoined,
			Sender: m[1],
			Room:   m[2],
			Text:   text,
		})
		return
	}

	// User left a room
	if m := reRoomLeft.FindStringSubmatch(text); m != nil {
		c.handler(Event{
			Type:   EvtRoomLeft,
			Sender: m[1],
			Room:   m[2],
			Text:   text,
		})
		return
	}

	// Timestamped chat message (lobby or room)
	if m := reLobbyMsg.FindStringSubmatch(text); m != nil {
		c.handler(Event{
			Type:   EvtMessage,
			Sender: m[3],
			Text:   m[4],
			Room:   m[2],
			Payload: ChatMessage{
				Timestamp: m[1],
				Username:  m[3],
				Text:      m[4],
				Room:      m[2],
			},
		})
		return
	}

	// Everything else: system message (help text, room lists, errors, etc.)
	c.handler(Event{
		Type: EvtSystemMessage,
		Text: text,
		Payload: ChatMessage{
			Timestamp: now,
			Text:      text,
			IsSystem:  true,
		},
	})
}

// dispatchFileEvent handles incoming file transfer data packets (type 0x03)
func (c *Client) dispatchFileEvent(data []byte) {
	text := strings.TrimSpace(string(data))

	if strings.HasPrefix(text, "FILE_START|") {
		parts := strings.SplitN(text, "|", 4)
		if len(parts) >= 3 {
			payload := FileStartPayload{
				Filename: parts[1],
			}
			fmt.Sscanf(parts[2], "%d", &payload.Filesize)
			if len(parts) == 4 {
				payload.ExpectedHash = parts[3]
			}
			c.handler(Event{
				Type:    EvtFileStart,
				Payload: payload,
			})
		}
		return
	}

	if text == "FILE_END" {
		c.handler(Event{Type: EvtFileEnd})
		return
	}

	// Raw file chunk
	c.handler(Event{
		Type:    EvtFileChunk,
		Payload: data,
	})
}
