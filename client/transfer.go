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

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/darkfiber-lab/quietroom/e2e"
	"github.com/darkfiber-lab/quietroom/wire"
)

const progressEvery = 250 * time.Millisecond

// maxIncoming bounds the offers and transfers to us we keep track of.
const maxIncoming = 64

// outgoing is a file we offered. Sizes and flow control on the wire count
// encrypted bytes (csize, credit, csent); size and sent are the file's.
type outgoing struct {
	ref   string
	id    string
	idb   [wire.IDLen]byte
	to    string
	path  string
	name  string
	size  int64
	csize int64
	sha   string
	key   []byte

	mu      sync.Mutex
	credit  int64
	sent    int64
	csent   int64
	started bool
	wake    chan struct{} // credit arrived
	stop    chan struct{} // cancelled
	once    sync.Once
}

func (o *outgoing) snapshot() *Transfer {
	o.mu.Lock()
	defer o.mu.Unlock()
	return &Transfer{ID: o.id, Outgoing: true, Peer: o.to, Name: o.name, Size: o.size, SHA256: o.sha, Done: o.sent, Path: o.path}
}

func (o *outgoing) halt() { o.once.Do(func() { close(o.stop) }) }

// incoming is a file offered to us. recv counts file bytes; crecv and
// granted count encrypted bytes on the wire.
type incoming struct {
	id    string
	idb   [wire.IDLen]byte
	from  string
	name  string
	size  int64
	csize int64
	sha   string
	key   []byte

	accepted bool
	f        *os.File
	part     string // temporary path while receiving
	dir      string
	h        hash.Hash
	open     *e2e.FileOpener
	recv     int64
	crecv    int64
	granted  int64
	lastProg time.Time
}

func (in *incoming) snapshot() *Transfer {
	return &Transfer{ID: in.id, Peer: in.from, Name: in.name, Size: in.size, SHA256: in.sha, Done: in.recv}
}

// HashFile computes the SHA-256 of a file.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// OfferFile hashes a file and offers it to a member, end-to-end encrypted:
// the name, size, hash and file key travel inside the encrypted offer. It
// returns once the offer is sent; EvFileOffered follows when the server has
// registered it.
func (c *Client) OfferFile(to, path string) (*Transfer, error) {
	path = filepath.Clean(path)
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot access file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() == 0 {
		return nil, fmt.Errorf("cannot send an empty file")
	}
	name := wire.CleanFileName(filepath.Base(path))
	if name == "" {
		return nil, fmt.Errorf("unusable file name")
	}
	sum, err := HashFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot hash file: %w", err)
	}
	key, err := e2e.NewFileKey()
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.refSeq++
	o := &outgoing{
		ref: strconv.Itoa(c.refSeq), to: to, path: path, name: name, size: info.Size(),
		csize: e2e.CipherSize(info.Size()), sha: sum, key: key,
		wake: make(chan struct{}, 1), stop: make(chan struct{}),
	}
	c.offers[o.ref] = o
	c.mu.Unlock()

	if strings.EqualFold(to, c.user) {
		snap := o.snapshot()
		c.failOffer(o.ref, "You cannot send files to yourself.")
		return snap, nil
	}
	p := c.waitPeer(to)
	if p == nil {
		c.smu.Unlock()
		snap := o.snapshot()
		c.failOffer(o.ref, fmt.Sprintf("User '%s' is not online.", to))
		return snap, nil
	}
	n, ct, err := p.pair.Seal(wire.TFileOffer, marshal(fileBody{Name: name, Size: o.size, SHA256: sum, Key: e2e.Encode(key)}))
	if err == nil {
		err = c.send(wire.Msg{T: wire.TFileOffer, Ref: o.ref, To: p.name, Size: o.csize, N: n, CT: e2e.Encode(ct)})
	}
	c.smu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.offers, o.ref)
		c.mu.Unlock()
		return nil, err
	}
	return o.snapshot(), nil
}

func (c *Client) failOffer(ref, reason string) bool {
	c.mu.Lock()
	o, ok := c.offers[ref]
	delete(c.offers, ref)
	c.mu.Unlock()
	if !ok {
		return false
	}
	c.emit(Event{Kind: EvFileFailed, Transfer: o.snapshot(), Text: reason})
	return true
}

func (c *Client) handleOffered(m wire.Msg) {
	idb, ok := wire.ParseID(m.ID)
	if !ok {
		return
	}
	c.mu.Lock()
	o, found := c.offers[m.Ref]
	if found {
		delete(c.offers, m.Ref)
		o.mu.Lock()
		o.id, o.idb = m.ID, idb
		if wire.ValidUsername(m.To) {
			o.to = m.To // the recipient's own spelling of the name
		}
		o.mu.Unlock()
		c.out[m.ID] = o
	}
	c.mu.Unlock()
	if found {
		c.emit(Event{Kind: EvFileOffered, Transfer: o.snapshot()})
	}
}

// handleCredit processes file_accept (first credit) and file_credit.
func (c *Client) handleCredit(m wire.Msg) {
	c.mu.Lock()
	o := c.out[m.ID]
	c.mu.Unlock()
	if o == nil || m.Bytes <= 0 {
		return
	}
	o.mu.Lock()
	o.credit += m.Bytes
	start := !o.started
	o.started = true
	o.mu.Unlock()
	select {
	case o.wake <- struct{}{}:
	default:
	}
	if start {
		c.emit(Event{Kind: EvFileStarted, Transfer: o.snapshot()})
		c.wg.Add(1)
		go c.stream(o)
	}
}

// stream sends the file within the granted credit.
func (c *Client) stream(o *outgoing) {
	defer c.wg.Done()
	fail := func(reason string) {
		c.send(wire.Msg{T: wire.TFileCancel, ID: o.id})
		c.finishOut(o.id, false, reason)
	}
	f, err := os.Open(o.path)
	if err != nil {
		fail("cannot open file: " + err.Error())
		return
	}
	defer f.Close()
	sealer, err := e2e.NewFileSealer(o.key)
	if err != nil {
		fail(err.Error())
		return
	}

	buf := make([]byte, e2e.PlainChunk)
	last := time.Now()
	for {
		// Whole encrypted chunks only: wait until the credit covers one.
		o.mu.Lock()
		remaining := o.size - o.sent
		ready := o.credit >= e2e.CipherChunk
		o.mu.Unlock()
		if remaining == 0 {
			break
		}
		if !ready {
			select {
			case <-o.wake:
				continue
			case <-o.stop:
				return
			case <-c.done:
				return
			}
		}
		n := int64(len(buf))
		if remaining < n {
			n = remaining
		}
		if _, err := io.ReadFull(f, buf[:n]); err != nil {
			fail("file changed while sending")
			return
		}
		chunk, err := sealer.Seal(buf[:n], n == remaining)
		if err != nil {
			fail(err.Error())
			return
		}
		frame, err := wire.EncodeData(o.idb, chunk)
		if err != nil {
			fail(err.Error())
			return
		}
		select {
		case c.bulk <- frame:
		case <-o.stop:
			return
		case <-c.done:
			return
		}
		o.mu.Lock()
		o.credit -= e2e.CipherChunk
		o.csent += e2e.CipherChunk
		o.sent += n
		o.mu.Unlock()
		if time.Since(last) >= progressEvery {
			last = time.Now()
			c.emit(Event{Kind: EvFileProgress, Transfer: o.snapshot()})
		}
	}
	c.emit(Event{Kind: EvFileProgress, Transfer: o.snapshot()})
	// file_end travels in the bulk queue, so it is written after all data.
	endFrame, _ := wire.EncodeMsg(wire.Msg{T: wire.TFileEnd, ID: o.id})
	select {
	case c.bulk <- endFrame:
	case <-o.stop:
	case <-c.done:
	}
}

// finishOut ends one of our transfers: ok means the recipient has it.
func (c *Client) finishOut(id string, ok bool, reason string) {
	c.mu.Lock()
	o := c.out[id]
	delete(c.out, id)
	c.mu.Unlock()
	if o == nil {
		return
	}
	o.halt()
	if ok {
		t := o.snapshot()
		t.OK = true
		c.emit(Event{Kind: EvFileComplete, Transfer: t})
	} else {
		c.emit(Event{Kind: EvFileFailed, Transfer: o.snapshot(), Text: reason})
	}
}

func (c *Client) handleOffer(m wire.Msg) {
	idb, ok := wire.ParseID(m.ID)
	if !ok {
		return
	}
	plain, err := c.openPair(m.From, wire.TFileOffer, m.N, m.CT)
	if err != nil {
		c.send(wire.Msg{T: wire.TFileDecline, ID: m.ID})
		c.emit(Event{Kind: EvError, Text: fmt.Sprintf("A file offer from %s could not be decrypted and was declined.", m.From)})
		return
	}
	var body fileBody
	if json.Unmarshal(plain, &body) != nil {
		return
	}
	name := wire.CleanFileName(body.Name)
	key, kerr := e2e.Decode(body.Key, e2e.KeyLen)
	if name == "" || body.Size <= 0 || !wire.ValidSHA256(body.SHA256) || kerr != nil || len(key) != e2e.KeyLen ||
		e2e.CipherSize(body.Size) != m.Size {
		c.send(wire.Msg{T: wire.TFileDecline, ID: m.ID})
		return
	}
	in := &incoming{id: m.ID, idb: idb, from: m.From, name: name, size: body.Size, csize: m.Size,
		sha: strings.ToLower(body.SHA256), key: key}
	c.mu.Lock()
	if _, dup := c.in[m.ID]; dup || len(c.in) >= maxIncoming {
		c.mu.Unlock()
		return
	}
	c.in[m.ID] = in
	c.mu.Unlock()
	c.emit(Event{Kind: EvFileOffer, Transfer: in.snapshot()})
}

// AcceptFile accepts an offered file; it is saved in Config.DownloadDir.
func (c *Client) AcceptFile(id string) error {
	c.mu.Lock()
	in := c.in[id]
	var accepted bool
	var size int64
	var name string
	if in != nil {
		accepted, size, name = in.accepted, in.size, in.name
	}
	c.mu.Unlock()
	if in == nil {
		return fmt.Errorf("no pending file transfer with ID %s", id)
	}
	if accepted {
		return fmt.Errorf("transfer %s is already accepted", id)
	}
	if size > c.cfg.MaxReceive {
		c.DeclineFile(id)
		return fmt.Errorf("file is too large (%d bytes, limit %d) — declined", size, c.cfg.MaxReceive)
	}
	if err := os.MkdirAll(c.cfg.DownloadDir, 0700); err != nil {
		return fmt.Errorf("cannot create download directory: %w", err)
	}
	opener, err := e2e.NewFileOpener(in.key)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(c.cfg.DownloadDir, "."+name+".*.part")
	if err != nil {
		return fmt.Errorf("cannot create file: %w", err)
	}
	c.mu.Lock()
	if c.in[id] != in || in.accepted { // cancelled or accepted meanwhile
		c.mu.Unlock()
		f.Close()
		os.Remove(f.Name())
		return fmt.Errorf("transfer %s is no longer pending", id)
	}
	in.accepted = true
	in.f = f
	in.part = f.Name()
	in.dir = c.cfg.DownloadDir
	in.h = sha256.New()
	in.open = opener
	in.granted = wire.InitialWindow
	in.lastProg = time.Now()
	snap := in.snapshot()
	c.mu.Unlock()
	if err := c.send(wire.Msg{T: wire.TFileAccept, ID: id, Bytes: wire.InitialWindow}); err != nil {
		c.finishIn(id, "connection lost")
		return err
	}
	c.emit(Event{Kind: EvFileStarted, Transfer: snap})
	return nil
}

// DeclineFile declines an offered file.
func (c *Client) DeclineFile(id string) error {
	c.mu.Lock()
	in := c.in[id]
	accepted := in != nil && in.accepted
	if in != nil && !accepted {
		delete(c.in, id)
	}
	c.mu.Unlock()
	if in == nil {
		return fmt.Errorf("no pending file transfer with ID %s", id)
	}
	if accepted {
		return fmt.Errorf("transfer %s is already running — use cancel", id)
	}
	return c.send(wire.Msg{T: wire.TFileDecline, ID: id})
}

// CancelFile stops a transfer in either direction.
func (c *Client) CancelFile(id string) error {
	c.mu.Lock()
	_, isOut := c.out[id]
	_, isIn := c.in[id]
	c.mu.Unlock()
	if !isOut && !isIn {
		return fmt.Errorf("no file transfer with ID %s", id)
	}
	err := c.send(wire.Msg{T: wire.TFileCancel, ID: id})
	c.finishOut(id, false, "cancelled")
	c.finishIn(id, "cancelled")
	return err
}

func (c *Client) handleData(payload []byte) {
	idb, data, err := wire.SplitData(payload)
	if err != nil {
		return
	}
	id := wire.IDString(idb)

	var credit int64
	var progress *Transfer
	var failure string
	c.mu.Lock()
	in := c.in[id]
	switch {
	case in == nil || !in.accepted || in.f == nil:
		c.mu.Unlock()
		return
	case in.crecv+int64(len(data)) > in.csize:
		failure = "sender sent more data than announced"
	default:
		in.crecv += int64(len(data))
		plain, err := in.open.Open(data, in.crecv == in.csize)
		if err != nil {
			failure = "file data failed authentication (corrupted or tampered with)"
			break
		}
		if rest := in.size - in.recv; int64(len(plain)) > rest {
			plain = plain[:rest] // padding of the last chunk
		}
		if _, err := in.f.Write(plain); err != nil {
			failure = "cannot write file: " + err.Error()
			break
		}
		in.h.Write(plain)
		in.recv += int64(len(plain))
		// Keep about InitialWindow bytes of credit outstanding.
		if in.granted-in.crecv <= wire.InitialWindow-wire.CreditStep && in.granted < in.csize {
			in.granted += wire.CreditStep
			credit = wire.CreditStep
		}
		if time.Since(in.lastProg) >= progressEvery {
			in.lastProg = time.Now()
			progress = in.snapshot()
		}
	}
	c.mu.Unlock()

	if failure != "" {
		c.send(wire.Msg{T: wire.TFileCancel, ID: id})
		c.finishIn(id, failure)
		return
	}
	if credit > 0 {
		c.send(wire.Msg{T: wire.TFileCredit, ID: id, Bytes: credit})
	}
	if progress != nil {
		c.emit(Event{Kind: EvFileProgress, Transfer: progress})
	}
}

// completeIn verifies and saves a received file.
func (c *Client) completeIn(id string) {
	c.mu.Lock()
	in := c.in[id]
	if in == nil || !in.accepted || in.f == nil {
		c.mu.Unlock()
		return
	}
	delete(c.in, id)
	t := in.snapshot()
	recv, size, part, dir, name, want := in.recv, in.size, in.part, in.dir, in.name, in.sha
	if !in.open.Done() {
		recv = -1 // the final chunk never arrived
	}
	sum := hex.EncodeToString(in.h.Sum(nil))
	closeErr := in.f.Close()
	c.mu.Unlock()

	if recv != size {
		os.Remove(part)
		c.emit(Event{Kind: EvFileFailed, Transfer: t, Text: fmt.Sprintf("incomplete file (%d of %d bytes)", max(recv, 0), size)})
		return
	}
	if sum != want {
		// The content differs from what the sender announced (changed while
		// sending, or deliberately): never put it in the download folder.
		os.Remove(part)
		t.ActualSHA256 = sum
		c.emit(Event{Kind: EvFileFailed, Transfer: t, Text: fmt.Sprintf("SHA-256 mismatch, file discarded (expected %s, got %s)", want, sum)})
		return
	}
	final, err := uniquePath(dir, name)
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(part, final)
	}
	if err != nil {
		os.Remove(part)
		c.emit(Event{Kind: EvFileFailed, Transfer: t, Text: "cannot save file: " + err.Error()})
		return
	}
	t.Path = final
	t.ActualSHA256 = sum
	t.OK = true
	c.emit(Event{Kind: EvFileComplete, Transfer: t})
}

// finishIn abandons an incoming transfer and removes the partial file.
func (c *Client) finishIn(id, reason string) {
	c.mu.Lock()
	in := c.in[id]
	delete(c.in, id)
	var t *Transfer
	if in != nil {
		t = in.snapshot()
		if in.f != nil {
			in.f.Close()
			os.Remove(in.part)
		}
	}
	c.mu.Unlock()
	if in != nil {
		c.emit(Event{Kind: EvFileFailed, Transfer: t, Text: reason})
	}
}

func (c *Client) failAll(reason string) {
	c.mu.Lock()
	var outIDs, inIDs, refs []string
	for id := range c.out {
		outIDs = append(outIDs, id)
	}
	for id := range c.in {
		inIDs = append(inIDs, id)
	}
	for ref := range c.offers {
		refs = append(refs, ref)
	}
	c.mu.Unlock()
	for _, id := range outIDs {
		c.finishOut(id, false, reason)
	}
	for _, id := range inIDs {
		c.finishIn(id, reason)
	}
	for _, ref := range refs {
		c.failOffer(ref, reason)
	}
}

// uniquePath returns dir/name, or dir/name_1.ext, ... if it exists.
func uniquePath(dir, name string) (string, error) {
	p := filepath.Join(dir, name)
	if _, err := os.Lstat(p); os.IsNotExist(err) {
		return p, nil
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for i := 1; i < 10000; i++ {
		p = filepath.Join(dir, fmt.Sprintf("%s_%d%s", base, i, ext))
		if _, err := os.Lstat(p); os.IsNotExist(err) {
			return p, nil
		}
	}
	return "", fmt.Errorf("too many files named %s", name)
}
