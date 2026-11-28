# End-to-end encryption (protocol 4)

QuietRoom 4 encrypts **direct messages, file transfers and password rooms**
between clients. The server relays ciphertext it cannot read. The lobby and
rooms without a password stay readable by the server: they are public to
everyone holding the access file, and a server could join them like any
member anyway.

The design keeps QuietRoom's model: no accounts, no long-term keys, nothing
stored. Every key below is created per connection, kept in memory only and
discarded when the connection ends.

Implementations: Go package [`e2e`](../e2e) (server, CLI, GUI) and the
Python connector ([`connector/quietroom_connector.py`](../connector/quietroom_connector.py)).
The integration tests run both against each other.

## Goals and limits

The server, or anyone who controls it, must not be able to:

- read direct messages, file names, file contents or password-room messages;
- forge or alter them without detection;
- join a password room as a member without knowing the password;
- read earlier messages with keys stolen later (forward secrecy).

Out of scope, by design or by nature:

- **Metadata.** The server still sees who is online, who sends a DM or file
  to whom and when, room names and members, and message sizes rounded up to a
  size class. Hiding that needs a mix network, not a better server.
- **Active key substitution in DMs** is detected, not prevented: a server can
  hand out its own keys and sit in the middle unless the two members compare
  safety numbers (see below). Password rooms do not have this weakness.
- **Availability.** A server can drop, delay or refuse to relay messages.
- **Weak room passwords.** A malicious server sees material it can test
  password guesses against offline; Argon2id makes each guess expensive, but
  only a strong password makes guessing hopeless.
- **Compromised devices.** A member's computer that is compromised exposes
  what that member can read.

## Primitives

| Purpose | Primitive |
|---|---|
| Key agreement | X25519 |
| Signatures (room messages) | Ed25519 |
| Key derivation | HKDF-SHA256, HMAC-SHA256 |
| Encryption | ChaCha20-Poly1305 |
| Room passwords | Argon2id (t=3, m=64 MiB, p=4; RFC 9106) |
| Safety numbers | SHA-512, 5200 iterations (as in Signal) |

Every input to HKDF, an AAD, a MAC or a signature is built with `pack`: each
field prefixed with its length as a 4-byte big-endian integer, so fields can
never run into each other. Labels (`"QuietRoom v4 ..."`) separate every use.

Plaintexts are padded before encryption: `0x80` and zero bytes up to the next
power of two (at least 64 bytes, at most 32 KiB).

## Session keys

On connecting, a client creates an X25519 key pair (`kx`) and an Ed25519 key
pair (`sk`) and sends the public halves in `hello`. The server checks their
format and relays them: to the newcomer, a `peer` message for everyone already
online; to everyone, the newcomer's keys in its `joined` notice.

## Direct messages, file offers and room keys: pairwise channels

Two members derive a shared channel from their session keys:

```
shared = X25519(my kx, their kx)
lo, hi = the two key sets, ordered by kx bytes
okm    = HKDF(shared, info = pack("QuietRoom v4 pair", lo.kx, lo.sk, hi.kx, hi.sk), 64 bytes)
chain lo→hi = okm[0:32], chain hi→lo = okm[32:64]
```

Each direction is a KDF chain (as in Signal's symmetric ratchet): message key
`mk = HMAC(ck, 0x01)`, next chain key `ck = HMAC(ck, 0x02)`. Message `n` is
encrypted with its own `mk` (so a zero nonce is safe):

```
ct  = ChaCha20-Poly1305(mk, nonce 0, pad(payload),
                        aad = pack("QuietRoom v4 pair message", wire type, sender kx, recipient kx, n))
```

The wire type (`dm`, `file_offer`, `rkey`) is authenticated, so the server
cannot pass one kind of message off as another. Old chain keys are discarded,
so a key stolen later cannot decrypt earlier messages. Receivers accept
messages up to 1024 ahead and keep up to 256 skipped keys for late arrivals; a
counter seen before is refused (no replays). A message that fails to decrypt
leaves the channel unchanged.

Session keys change with every connection, which also limits what a stolen
key could ever read to one session. There is no DH ratchet within a session
(no post-compromise security until the next connection).

Payloads are JSON: `{"text": ...}` for a DM; for a file offer
`{"name", "size", "sha256", "key"}`; for a room key see below.

### Safety numbers

Each member's session has a 30-digit number:

```
h = SHA-512(pack("QuietRoom v4 safety number", lower(name), kx‖sk))
repeat 5200 times: h = SHA-512(h ‖ kx‖sk)
number = six groups of five digits from h[0:30] (each 5 bytes mod 100000)
```

`/verify <user>` (CLI) and the 🔒 Verify button of a DM (GUI) show both numbers. If both members see the same two numbers
(compared in person, by phone, ...), the server did not substitute keys. The
numbers are per member rather than one combined number, so a server cannot
use a birthday attack to make substituted keys collide; it would need a
second preimage for one specific number. The numbers change with every
connection.

## File transfers

The sender picks a random 32-byte key per file and sends it, with the name,
real size and SHA-256, inside the encrypted offer. The file travels in chunks
that each fill one data frame exactly (32 744 bytes encrypted, 32 728 bytes of
file); the last chunk is padded with zeros. The server sees only the
encrypted size, which reveals the file size to the nearest chunk.

```
chunk i = ChaCha20-Poly1305(file key, nonce = i (8 bytes, big-endian) ‖ 0 0 0 ‖ last, chunk, aad = "QuietRoom v4 file")
```

`last` is 1 only for the final chunk (as in the STREAM construction), so
chunks cannot be reordered, dropped or the file cut short. The recipient also
checks the SHA-256 from the offer before keeping the file. Flow control counts
encrypted bytes; senders only send whole chunks.

## Password rooms

### Password to keys

```
salt     = SHA-256(pack("QuietRoom v4 room salt", room name))
secret   = Argon2id(password, salt, t=3, m=64 MiB, p=4, 32 bytes)
verifier = HKDF(secret, info = "QuietRoom v4 room verifier")
auth     = HKDF(secret, info = "QuietRoom v4 room auth")
```

The salt comes from the room name, so nothing needs to be stored. The password
never leaves the client.

### Joining

1. The client sends `join{room, vf: verifier}`. The server keeps SHA-256 of the
   first verifier (which makes the room end-to-end encrypted) and admits later
   joiners presenting the same verifier. This only stops people without the
   password from wasting room resources; it is not what protects the content.
2. The new member broadcasts `rhello{room, proof}` with
   `proof = HMAC(auth, pack("QuietRoom v4 room member", room, lower(name), kx, sk))`.
3. Every member who verifies the proof answers with an `rkey` on the pairwise
   channel: its own proof and the current state of its sending chain
   (`kid`, chain key, counter). The newcomer verifies the proof and answers
   with its own `rkey`, giving its chain from its first message (see below).

A member who cannot produce a valid proof (for example someone a malicious
server let in, or who obtained the verifier) gets no keys from anyone, and
members are warned. Because the proof needs `auth`, which needs the password,
**the server cannot join a password room as a reader**, and no safety-number
check is needed in password rooms.

### Messages

Each member has its own sending chain (sender keys, as in Signal groups),
identified by a random 32-bit `kid`:

```
ct  = ChaCha20-Poly1305(mk, nonce 0, pad({"text": ...}),
                        aad = pack("QuietRoom v4 room message", room, sender kx, kid, n))
sig = Ed25519(sender sk, pack("QuietRoom v4 room signature", room, kid, n, ct))
```

Every member holds every other member's chain key, so the signature is what
stops one member from forging messages as another. A newcomer receives the
chain at its current position and cannot derive earlier message keys: **no
history for newcomers**. When a member leaves, every remaining member who had
given them its key switches to a new chain (new `kid`) and sends it to the
others, so **a member who left cannot read what follows**.

Messages that arrive before the sender's key (for example right after a join)
are kept briefly (up to 64 per sender) and decrypted when the key arrives.

A newcomer may write before the keys are swapped (the exchange takes
milliseconds). Its chain has moved on by then, so the members it answers in
step 3, who were in the room first and received those messages, get its chain
**from its first message** rather than its current position; otherwise they
could not read them. This start is only offered while the chain is young (its
first 64 messages and 10 seconds), then wiped. Members who join later always
get the current position. The bound matters in one case: someone who knows
the password and, with the server's help, poses as an earlier member could
read what a newcomer wrote in its first seconds; never anything older.

## Protocol messages

See the message list in [`wire/msg.go`](../wire/msg.go). New or changed in
protocol 4:

| Message | Fields | Notes |
|---|---|---|
| `hello` | `kx`, `sk` | session keys; required |
| `peer` | `user`, `kx`, `sk` | server → client, members already online |
| `joined` | `kx`, `sk`, `locked` | keys on joining the chat; `locked` on joining a password room |
| `dm` | `to`, `n`, `ct` | no plain-text DMs; the sender gets a delivery notice without `ct` |
| `chat` | `kid`, `n`, `ct`, `sig` | password rooms only; plain `text` elsewhere |
| `join` | `vf` | replaces `password` |
| `rhello` | `room`, `proof` | |
| `rkey` | `to`, `n`, `ct` | pairwise-encrypted room key |
| `file_offer` | `size`, `n`, `ct` | `size` = encrypted bytes; name and hash are inside `ct` |

Protocol 3 clients and servers cannot talk to protocol 4 ones: the server
refuses other versions in `hello`.
