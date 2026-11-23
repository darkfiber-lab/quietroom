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
	"fmt"
	"strings"
)

// Command is a parsed slash command typed by a user.
type Command struct {
	Name string   // without the slash, lower case
	Args []string // positional arguments
	Rest string   // for /msg: the message; for /file: the path; for /join: the password
}

// ParseCommand parses "/name args...". Usage errors are returned as errors
// whose text can be shown to the user.
func ParseCommand(line string) (Command, error) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "/") {
		return Command{}, fmt.Errorf("not a command")
	}
	fields := strings.Fields(line)
	name := strings.ToLower(strings.TrimPrefix(fields[0], "/"))
	args := fields[1:]
	cmd := Command{Name: name}

	rest := func(n int) string {
		// Text after the first n arguments, with original spacing.
		s := strings.TrimSpace(line[len(fields[0]):])
		for i := 0; i < n; i++ {
			s = strings.TrimSpace(strings.TrimPrefix(s, fields[1+i]))
		}
		return s
	}

	switch name {
	case "help", "rooms", "users", "quit":
	case "msg":
		if len(args) < 2 {
			return cmd, fmt.Errorf("Usage: /msg <username> <message>")
		}
		cmd.Args = args[:1]
		cmd.Rest = rest(1)
	case "join":
		if len(args) < 1 {
			return cmd, fmt.Errorf("Usage: /join <#room> [password]")
		}
		cmd.Args = args[:1]
		cmd.Rest = rest(1)
	case "leave":
		if len(args) < 1 {
			return cmd, fmt.Errorf("Usage: /leave <#room>")
		}
		cmd.Args = args[:1]
	case "members":
		if len(args) < 1 {
			return cmd, fmt.Errorf("Usage: /members <#room|lobby>")
		}
		cmd.Args = args[:1]
	case "file":
		if len(args) < 2 {
			return cmd, fmt.Errorf("Usage: /file <username> <path>  (quote paths with spaces)")
		}
		cmd.Args = args[:1]
		p := rest(1)
		if len(p) >= 2 && (p[0] == '"' && p[len(p)-1] == '"' || p[0] == '\'' && p[len(p)-1] == '\'') {
			p = p[1 : len(p)-1]
		}
		cmd.Rest = p
	case "accept", "decline", "cancel":
		if len(args) < 1 {
			return cmd, fmt.Errorf("Usage: /%s <transfer id>", name)
		}
		cmd.Args = args[:1]
	default:
		return cmd, fmt.Errorf("Unknown command: /%s. Type /help for available commands.", name)
	}
	return cmd, nil
}

// HelpText is shown for /help (by the server, so all clients agree).
const HelpText = `Available Commands:
  /help                      - Show this help message
  /msg <user> <message>      - Send a private message
  /join <#room> [password]   - Join or create a room (optionally password-protected)
  /leave <#room>             - Leave a room
  /rooms                     - List active rooms
  /users                     - List online users
  /members <#room|lobby>     - List members of a room or the lobby
  /file <user> <path>        - Offer a file to a user
  /accept <id>               - Accept a file transfer
  /decline <id>              - Decline a file transfer
  /cancel <id>               - Cancel a file transfer in progress
  /quit                      - Disconnect`
