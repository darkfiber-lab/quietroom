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

package client

// End-to-end encryption state: the session keys of other members, the
// pairwise channels (direct messages, file offers, room keys) and the
// password rooms we are in. See docs/E2E_DESIGN.md.

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/darkfiber-lab/quietroom/e2e"
	"github.com/darkfiber-lab/quietroom/wire"
)

// Inner (encrypted) payloads.
type textBody struct {
	Text string `json:"text"`
}

type fileBody struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Key    string `json:"key"`
}

type roomKeyBody struct {
	Room  string `json:"room"`
	Proof string `json:"proof"`
	KID   uint32 `json:"kid"`
	CK    string `json:"ck"`
	N     uint32 `json:"n"`
}

const (
	maxPendingPerSender = 64   // room messages waiting for the sender's key
	maxSentRemembered   = 1024 // our own messages waiting for the server's echo
)

// peer is another member's session.
type peer struct {
	name string
	pub  e2e.PublicKeys
	pair *e2e.Pair
}

// member is another member of a password room who proved the password.
type member struct {
	recv    *e2e.Receiver // their sending chain; nil until their key arrives
	sentKID uint32        // our key ID they last received
	sent    bool
}

// secureRoom is a password room we are in.
type secureRoom struct {
	name    string
	secret  e2e.RoomSecret
	sender  *e2e.Sender
	members map[string]*member    // by username key
	pending map[string][]wire.Msg // undecryptable messages, by sender key
	refused map[string]bool       // members whose proof failed (warned once)
}

type sentKey struct {
	scope string // username key (DMs) or room name
	kid   uint32
	n     uint32
}

// secureState is guarded by Client.smu.
type secureState struct {
	id      *e2e.Identity
	peers   map[string]*peer       // by username key
	rooms   map[string]*secureRoom // by room name
	joining map[string]e2e.RoomSecret
	sent    map[sentKey]string // our encrypted messages, until echoed
	order   []sentKey
	newPeer chan struct{} // closed and replaced whenever a peer is added
}

func newSecureState(id *e2e.Identity) *secureState {
	return &secureState{
		id:      id,
		peers:   make(map[string]*peer),
		rooms:   make(map[string]*secureRoom),
		joining: make(map[string]e2e.RoomSecret),
		sent:    make(map[sentKey]string),
		newPeer: make(chan struct{}),
	}
}

// peerWait is how long a message to a member waits for their keys: they
// arrive with the member's join notice, which can trail their first
// appearance by a moment.
const peerWait = 3 * time.Second

func (st *secureState) remember(k sentKey, text string) {
	st.sent[k] = text
	st.order = append(st.order, k)
	for len(st.order) > maxSentRemembered {
		delete(st.sent, st.order[0])
		st.order = st.order[1:]
	}
}

func (st *secureState) recall(k sentKey) (string, bool) {
	t, ok := st.sent[k]
	delete(st.sent, k)
	return t, ok
}

func marshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// cleanIncoming applies the same rules the server applies to plain text.
func cleanIncoming(t string) (string, bool) {
	t = strings.TrimSpace(wire.CleanText(t))
	return t, t != "" && len(t) <= wire.MaxTextBytes
}

// ── Peers ───────────────────────────────────────────────────────────

func (c *Client) addPeer(name, kx, sk string) {
	if !wire.ValidUsername(name) || strings.EqualFold(name, c.user) {
		return
	}
	pub, err := e2e.ParsePublicKeys(kx, sk)
	if err != nil {
		return
	}
	pair, err := c.sec.id.NewPair(pub)
	if err != nil {
		return
	}
	c.smu.Lock()
	c.sec.peers[wire.UsernameKey(name)] = &peer{name: name, pub: pub, pair: pair}
	close(c.sec.newPeer)
	c.sec.newPeer = make(chan struct{})
	c.smu.Unlock()
}

// waitPeer returns with smu held and the member's session, or nil if they
// are not online (their keys did not arrive within peerWait).
func (c *Client) waitPeer(name string) *peer {
	deadline := time.After(peerWait)
	for {
		c.smu.Lock()
		if p := c.peerFor(name); p != nil {
			return p
		}
		ch := c.sec.newPeer
		c.smu.Unlock()
		select {
		case <-ch:
		case <-deadline:
			c.smu.Lock()
			return nil
		case <-c.done:
			c.smu.Lock()
			return nil
		}
	}
}

func (c *Client) removePeer(name string) {
	c.smu.Lock()
	delete(c.sec.peers, wire.UsernameKey(name))
	c.smu.Unlock()
}

// PublicKeys returns our session public keys.
func (c *Client) PublicKeys() e2e.PublicKeys { return c.sec.id.Public() }

// peerFor returns a member's session. Caller holds smu.
func (c *Client) peerFor(name string) *peer { return c.sec.peers[wire.UsernameKey(name)] }

// SafetyNumbers returns our and another member's safety numbers for this
// session. If both members see the same two numbers, nobody (the server
// included) has substituted keys between them.
func (c *Client) SafetyNumbers(user string) (mine, theirs string, err error) {
	_, mine, theirs, err = c.safetyNumbers(user)
	return mine, theirs, err
}

func (c *Client) safetyNumbers(user string) (name, mine, theirs string, err error) {
	c.smu.Lock()
	p := c.peerFor(user)
	c.smu.Unlock()
	if p == nil {
		return "", "", "", fmt.Errorf("user '%s' is not online", user)
	}
	return p.name, e2e.SafetyNumber(c.user, c.sec.id.Public()), e2e.SafetyNumber(p.name, p.pub), nil
}

// VerifyText is the /verify output.
func (c *Client) VerifyText(user string) (string, error) {
	name, mine, theirs, err := c.safetyNumbers(user)
	if err != nil {
		return "", err
	}
	w := len(c.user)
	if len(name) > w {
		w = len(name)
	}
	return fmt.Sprintf("Safety numbers for your conversation with %s (valid for this session only):\n"+
		"  %-*s  %s\n  %-*s  %s\n"+
		"Compare both numbers with %s over another channel (in person, by phone). If they match,\n"+
		"nobody, not even the server, can read your direct messages and files.",
		name, w, c.user, mine, w, name, theirs, name), nil
}

// ── Direct messages ─────────────────────────────────────────────────

func (c *Client) sendDM(to, text string) error {
	if strings.EqualFold(to, c.user) {
		c.emit(Event{Kind: EvDM, From: c.user, To: c.user, Text: text, Time: nowClock(), Self: true})
		return nil
	}
	p := c.waitPeer(to)
	defer c.smu.Unlock()
	if p == nil {
		c.emitAsync(Event{Kind: EvError, Text: fmt.Sprintf("User '%s' is not online.", to)})
		return nil
	}
	n, ct, err := p.pair.Seal(wire.TDM, marshal(textBody{Text: text}))
	if err != nil {
		return err
	}
	c.sec.remember(sentKey{scope: wire.UsernameKey(p.name), n: n}, text)
	return c.send(wire.Msg{T: wire.TDM, To: p.name, N: n, CT: e2e.Encode(ct)})
}

func (c *Client) handleDM(m wire.Msg) {
	if m.From == c.user {
		// Delivery notice for one of ours.
		c.smu.Lock()
		text, ok := c.sec.recall(sentKey{scope: wire.UsernameKey(m.To), n: m.N})
		c.smu.Unlock()
		if ok {
			c.emit(Event{Kind: EvDM, From: m.From, To: m.To, Text: text, Time: m.Time, Self: true})
		}
		return
	}
	plain, err := c.openPair(m.From, wire.TDM, m.N, m.CT)
	if err != nil {
		c.emit(Event{Kind: EvError, Text: fmt.Sprintf("A direct message from %s could not be decrypted and was dropped.", m.From)})
		return
	}
	var body textBody
	if json.Unmarshal(plain, &body) != nil {
		return
	}
	text, ok := cleanIncoming(body.Text)
	if !ok {
		return
	}
	c.emit(Event{Kind: EvDM, From: m.From, To: m.To, Text: text, Time: m.Time})
}

// openPair decrypts a pairwise message from a member.
func (c *Client) openPair(from, kind string, n uint32, ct string) ([]byte, error) {
	raw, err := e2e.Decode(ct, wire.MaxCipherText)
	if err != nil {
		return nil, err
	}
	c.smu.Lock()
	p := c.peerFor(from)
	c.smu.Unlock()
	if p == nil {
		return nil, e2e.ErrDecrypt
	}
	return p.pair.Open(kind, n, raw)
}

// ── Password rooms ──────────────────────────────────────────────────

// prepareJoin derives the room keys from a password (Argon2id: this takes
// a moment) and returns the verifier for the server.
func (c *Client) prepareJoin(room, password string) string {
	rs := e2e.DeriveRoom(room, password)
	c.smu.Lock()
	c.sec.joining[room] = rs
	c.smu.Unlock()
	return e2e.Encode(rs.Verifier)
}

// IsSecureRoom reports whether we are in room as an end-to-end encrypted
// (password) room.
func (c *Client) IsSecureRoom(room string) bool {
	c.smu.Lock()
	defer c.smu.Unlock()
	return c.sec.rooms[room] != nil
}

// sendRoomKey gives a verified member our current sending key. Caller holds
// smu.
func (c *Client) sendRoomKey(r *secureRoom, name string, mb *member) {
	p := c.peerFor(name)
	if p == nil {
		return
	}
	k := r.sender.Key()
	body := roomKeyBody{
		Room: r.name, Proof: e2e.Encode(r.secret.Proof(c.user, c.sec.id.Public())),
		KID: k.KID, CK: e2e.Encode(k.CK), N: k.N,
	}
	n, ct, err := p.pair.Seal(wire.TRoomKey, marshal(body))
	if err != nil {
		return
	}
	if c.send(wire.Msg{T: wire.TRoomKey, To: p.name, N: n, CT: e2e.Encode(ct)}) == nil {
		mb.sentKID, mb.sent = k.KID, true
	}
}

// joinedSecure sets up a password room we just joined and announces our
// proof of the password. It reports whether the room is end-to-end
// encrypted, and whether we must leave it again: a room joined with a
// password that turns out to be open (it exists without one, or a server
// pretends so) is never used, so nothing meant to be private goes out in
// the clear.
func (c *Client) joinedSecure(room string, locked bool) (secure, leave bool, note string) {
	c.smu.Lock()
	defer c.smu.Unlock()
	rs, ok := c.sec.joining[room]
	delete(c.sec.joining, room)
	if !locked {
		if ok {
			return false, true, fmt.Sprintf("⚠ %s already exists as an open room, without a password: its messages would not be end-to-end encrypted. You left it again; choose another name for a private room.", room)
		}
		return false, false, ""
	}
	if !ok {
		return false, true, fmt.Sprintf("⚠ Joined %s without its password, so its keys are missing. You left it again; join with the password.", room)
	}
	sender, err := e2e.NewSender(room)
	if err != nil {
		return false, true, "Cannot create room keys: " + err.Error()
	}
	r := &secureRoom{name: room, secret: rs, sender: sender,
		members: make(map[string]*member), pending: make(map[string][]wire.Msg), refused: make(map[string]bool)}
	c.sec.rooms[room] = r
	c.send(wire.Msg{T: wire.TRoomHello, Room: room, Proof: e2e.Encode(rs.Proof(c.user, c.sec.id.Public()))})
	return true, false, ""
}

// memberLeft forgets a member and, if they held our key, replaces it so
// they cannot read what we send next.
func (c *Client) memberLeft(room, name string) {
	c.smu.Lock()
	defer c.smu.Unlock()
	r := c.sec.rooms[room]
	if r == nil {
		return
	}
	key := wire.UsernameKey(name)
	mb := r.members[key]
	delete(r.members, key)
	delete(r.pending, key)
	delete(r.refused, key)
	if mb == nil || !mb.sent {
		return
	}
	sender, err := e2e.NewSender(room)
	if err != nil {
		return
	}
	r.sender = sender
	for k, other := range r.members {
		if p := c.sec.peers[k]; p != nil {
			c.sendRoomKey(r, p.name, other)
		}
	}
}

func (c *Client) leftSecure(room string) {
	c.smu.Lock()
	delete(c.sec.rooms, room)
	c.smu.Unlock()
}

// handleRoomHello answers a member's proof of the password with our key.
func (c *Client) handleRoomHello(m wire.Msg) {
	var warn string
	c.smu.Lock()
	r := c.sec.rooms[m.Room]
	p := c.peerFor(m.From)
	if r != nil && p != nil {
		proof, _ := e2e.Decode(m.Proof, e2e.KeyLen)
		key := wire.UsernameKey(p.name)
		if r.secret.CheckProof(p.name, p.pub, proof) {
			mb := r.members[key]
			if mb == nil {
				mb = &member{}
				r.members[key] = mb
			}
			// Repeated hellos get no new copies of an unchanged key.
			if !mb.sent || mb.sentKID != r.sender.Key().KID {
				c.sendRoomKey(r, p.name, mb)
			}
		} else if !r.refused[key] {
			r.refused[key] = true
			warn = fmt.Sprintf("⚠ %s is in %s but could not prove the room password: they get no keys and cannot read the room.", p.name, m.Room)
		}
	}
	c.smu.Unlock()
	if warn != "" {
		c.emit(Event{Kind: EvError, Text: warn})
	}
}

// handleRoomKey stores a member's sending key and gives them ours.
func (c *Client) handleRoomKey(m wire.Msg) {
	plain, err := c.openPair(m.From, wire.TRoomKey, m.N, m.CT)
	if err != nil {
		return
	}
	var body roomKeyBody
	if json.Unmarshal(plain, &body) != nil {
		return
	}
	ck, err1 := e2e.Decode(body.CK, e2e.KeyLen)
	proof, err2 := e2e.Decode(body.Proof, e2e.KeyLen)
	if err1 != nil || err2 != nil {
		return
	}
	var retry []wire.Msg
	c.smu.Lock()
	r := c.sec.rooms[body.Room]
	p := c.peerFor(m.From)
	if r == nil || p == nil || !r.secret.CheckProof(p.name, p.pub, proof) {
		c.smu.Unlock()
		return
	}
	key := wire.UsernameKey(p.name)
	recv, err := e2e.NewReceiver(r.name, p.pub, e2e.SenderKey{KID: body.KID, CK: ck, N: body.N})
	if err != nil {
		c.smu.Unlock()
		return
	}
	mb := r.members[key]
	if mb == nil {
		mb = &member{}
		r.members[key] = mb
	}
	mb.recv = recv
	if !mb.sent || mb.sentKID != r.sender.Key().KID {
		c.sendRoomKey(r, p.name, mb)
	}
	retry = r.pending[key]
	delete(r.pending, key)
	c.smu.Unlock()
	for _, pm := range retry {
		c.handleSecureChat(pm)
	}
}

// sendSecureChat encrypts a message to a password room. Caller holds smu.
func (c *Client) sendSecureChat(r *secureRoom, text string) error {
	kid, n, ct, sig, err := r.sender.Seal(c.sec.id, marshal(textBody{Text: text}))
	if err != nil {
		return err
	}
	c.sec.remember(sentKey{scope: r.name, kid: kid, n: n}, text)
	return c.send(wire.Msg{T: wire.TChat, Room: r.name, KID: kid, N: n, CT: e2e.Encode(ct), Sig: e2e.Encode(sig)})
}

// handleSecureChat decrypts a password-room message, or keeps it until the
// sender's key arrives.
func (c *Client) handleSecureChat(m wire.Msg) {
	if m.From == c.user {
		c.smu.Lock()
		text, ok := c.sec.recall(sentKey{scope: m.Room, kid: m.KID, n: m.N})
		c.smu.Unlock()
		if ok {
			c.emit(Event{Kind: EvChat, From: m.From, Room: m.Room, Text: text, Time: m.Time, Self: true})
		}
		return
	}
	ct, err1 := e2e.Decode(m.CT, wire.MaxCipherText)
	sig, err2 := e2e.Decode(m.Sig, 64)
	if err1 != nil || err2 != nil {
		return
	}
	c.smu.Lock()
	r := c.sec.rooms[m.Room]
	if r == nil {
		c.smu.Unlock()
		return
	}
	key := wire.UsernameKey(m.From)
	mb := r.members[key]
	if mb == nil || mb.recv == nil || mb.recv.KID() != m.KID {
		// Their key has not arrived yet (it is on its way when they just
		// joined or rekeyed).
		if len(r.pending[key]) < maxPendingPerSender {
			r.pending[key] = append(r.pending[key], m)
		}
		c.smu.Unlock()
		return
	}
	plain, err := mb.recv.Open(m.KID, m.N, ct, sig)
	c.smu.Unlock()
	if err != nil {
		c.emit(Event{Kind: EvError, Text: fmt.Sprintf("A message from %s in %s could not be verified and was dropped.", m.From, m.Room)})
		return
	}
	var body textBody
	if json.Unmarshal(plain, &body) != nil {
		return
	}
	if text, ok := cleanIncoming(body.Text); ok {
		c.emit(Event{Kind: EvChat, From: m.From, Room: m.Room, Text: text, Time: m.Time})
	}
}

// emitAsync delivers an event without blocking the caller, which may hold
// locks the event handler needs.
func (c *Client) emitAsync(e Event) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.emit(e)
	}()
}
