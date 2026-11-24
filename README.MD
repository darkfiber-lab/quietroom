# QuietRoom

A privacy-focused, self-hosted encrypted chat system: TLS 1.3 with forward secrecy, a shared access key that keeps outsiders out, padded traffic and decoys against traffic analysis.

## Rationale and Design Principles

In 1979, the United States Supreme Court decided Smith v. Maryland, a case that would quietly redefine the boundaries of privacy in modern communications. The Court held that law enforcement's use of a pen register—obtaining records of dialed telephone numbers directly from a telephone company without a warrant—did not constitute a "search" under the Fourth Amendment. The justification was explicit: because the caller had voluntarily conveyed those numbers to a third party (the telephone company) for the purpose of completing the call, there was no reasonable expectation of privacy in that information.

This decision formalized what later became known as the third-party doctrine: once information is shared with a service provider, constitutional privacy protections no longer apply. While Smith v. Maryland concerned telephone metadata rather than content, its implications were far broader. It established the principle that merely using a communications service could be interpreted as consent to surveillance of its transactional data, without judicial oversight.

Although this was a U.S. case rooted in domestic constitutional law, its influence extended well beyond American borders. As the internet emerged and centralized platforms came to dominate global communication, the same logic was repeatedly reused—often implicitly—by regulators, legislators, and corporations worldwide. The result has been a default legal and cultural mindset in which online communication is treated as inherently unprivate, with privacy framed as an exception rather than a baseline right. Metadata collection, retention, and analysis have been normalized, frequently without warrants, meaningful consent, or realistic opt-out options.

In theory, users are said to "choose" these services. In practice, market concentration has eliminated most alternatives. Participation in modern social, professional, and familial life increasingly requires the use of platforms owned by a small number of large entities whose business models depend on data extraction. The only truly indispensable service is internet connectivity itself; everything layered on top of it is optional in name only.

This project exists as a deliberate response to that reality.

The encrypted chat server and client described here are designed to allow individuals to operate their own private communication infrastructure. By self-hosting, users remove third-party intermediaries entirely. There is no central service provider, no data broker, and no institutional actor positioned to collect, aggregate, monetize, or disclose communication metadata or content. Private conversations remain private by architecture, not by policy or promises.

The system is intentionally not designed for mass adoption or internet-scale deployment. Its architecture relies on a physically distributed key file that must be exchanged manually among trusted participants. This imposes a clear scalability limitation, but that limitation is a conscious design choice. It functions as a security property, reinforcing a model analogous to a private room rather than a public square. Access requires trust, intent, and proximity, not frictionless growth.

At a conceptual level, the system is meant to preserve fundamental rights that predate the digital era: the presumption of innocence, the right to remain silent, and the ability to communicate privately with family members or closely trusted groups without being observed, profiled, or recorded. No external party should have the power to strip individuals of these rights simply because communication has moved online.

The software is provided free of charge. Responsibility for its deployment and use rests entirely with the individual operating it. It is not intended to facilitate illegal activity, nor does it claim immunity from applicable law. Instead, it restores agency: those who choose to run it do so knowingly, accepting both the freedom and the responsibility that come with controlling their own communication infrastructure.

This project does not seek to compete with large-scale platforms. It offers something fundamentally different: a small, deliberately constrained, user-controlled space where privacy is not an afterthought, but the default.

## Features

- 🔐 **TLS 1.3 with forward secrecy** - All traffic encrypted; the server certificate is pinned by every client
- 🔑 **Access key** - Only holders of the current `quietroom_access.pem` can connect; a server restart issues a new key
- 🕵️ **Traffic padding** - Messages are padded to fixed size classes, so their length is hidden
- 🎭 **Decoy Traffic** - Random cover messages at random intervals hide activity patterns
- 💬 **Private Messaging** - Direct messages between users
- 🚪 **Chat Rooms** - Create password-protected rooms for group conversations
- 📁 **File Transfers** - Any size, with flow control, several at once, SHA-256 verification; chat stays responsive during transfers
- 📝 **Security Logging** - Security events without participant metadata (unless explicitly enabled)

## Quick Start

### Server Setup

1. Build and run the server:
   ```bash
   go build -o quietroom_server quietroom_server.go
   ./quietroom_server
   ```

2. Securely distribute `quietroom_access.pem` to your clients (physical media). The file is **secret**: it contains the access key, and anyone holding it can join. Every server restart creates a new access file and invalidates the previous one.

### Client Setup

1. Obtain `quietroom_access.pem` from your server administrator

2. Build and run the client:
   ```bash
   go build -o quietroom_client quietroom_client.go
   ./quietroom_client
   ```

3. Connect and start chatting!

## Documentation

For detailed setup instructions, configuration options, and troubleshooting:

- **[Server Documentation](SERVER_README.MD)** - Complete server setup, configuration, and administration guide
- **[Client Documentation](CLIENT_README.MD)** - Client installation, configuration, and usage instructions

## Security Overview

### Encryption Layers

1. **TLS 1.3** - Encrypts all traffic between client and server with ephemeral keys (forward secrecy)
2. **Certificate Pinning** - Clients accept only the exact server certificate from `quietroom_access.pem`, which prevents man-in-the-middle attacks
3. **Access Key (mutual TLS)** - Clients must present the master access key from `quietroom_access.pem`; connections without it are refused during the TLS handshake, before any QuietRoom code runs
4. **Silent to strangers** - Without a valid gate token (derived from the access key) in the first TLS message, the server closes the connection without sending anything: scanners never see its certificate
5. **Fresh keys per run** - The server generates new keys on every start and keeps its private key in memory only; a restart revokes every access file

The server decrypts and relays messages: the operator's server is trusted by design. Messages are never stored.

### Traffic Protection

- **Padding**: Every frame is padded to a size class (256 B, 512 B, 1 KB, ...), hiding message lengths
- **Decoy Traffic**: Random cover frames at random intervals (both directions) mask activity patterns
- **Limits**: Connection limits before TLS, message rate limits, room limits and flow-controlled file transfers keep one member from overwhelming the server

### Privacy Features

- **Forward Secrecy**: TLS 1.3 session keys are ephemeral; recorded traffic stays secure even if a key file is later compromised
- **No Message Persistence**: Messages are not stored on the server
- **No User Tracking**: No logs of message content; participant metadata (who connected, DMs, file transfers, member IPs) is not logged unless the operator explicitly enables `log_metadata`
- **Self-Hosted**: Complete control over your infrastructure

## System Requirements

- **Go**: Version 1.26 or higher (only needed to build from source)
- **Operating Systems**: Linux, macOS, Windows
- **Network**: TCP connectivity between server and clients
- **Disk Space**: Minimal (< 50MB for binaries and logs)
- **Memory**: ~10-20MB for server + ~2MB per connected client

## Architecture

```
┌──────────────┐                                  ┌──────────────┐
│    Client    │◄──────────── TLS 1.3 ───────────►│    Server    │
│              │  1. Handshake: server cert       │              │
│ access file: │     pinned, client presents      │ keys made at │
│ • server cert│     the access key               │ every start  │
│ • access key │  2. hello / welcome              │              │
│              │  3. Framed messages (JSON) and   │ relays chat, │
│              │     file data, padded; decoys    │ DMs, files   │
└──────────────┘                                  └──────────────┘
```

The protocol (version 3) is specified in the [`wire`](wire/) package. CLI and
GUI share one client implementation in [`client`](client/).

## Verifying Downloads

Every release includes a `SHA256SUMS.txt` file and a signed build provenance attestation.

**Check a file against the published checksums** (run in the folder with the downloaded files):

```bash
# Linux
sha256sum -c SHA256SUMS.txt --ignore-missing
# macOS
shasum -a 256 -c SHA256SUMS.txt --ignore-missing
# Windows (PowerShell): compare with the matching line in SHA256SUMS.txt
Get-FileHash .\quietroom_client_gui-windows-amd64-vX.Y.Z.exe -Algorithm SHA256
```

For the strongest check, get the expected checksum from your server administrator out of band (for example together with `quietroom_access.pem`) instead of from the same download page.

**Verify that a file was built by this repository's release workflow** (requires the GitHub CLI):

```bash
gh attestation verify quietroom-cli-linux-arm64-vX.Y.Z.zip -R darkfiber-lab/quietroom
```

## Building from Source

```bash
# Clone the repository
git clone <repository-url>
cd quietroom

# Build server
go build -o quietroom_server quietroom_server.go

# Build client
go build -o quietroom_client quietroom_client.go

# Tests (QUIETROOM_RACE=1 builds the server with the race detector)
go test ./wire/                                     # protocol unit tests
QUIETROOM_RACE=1 go test -race ./tests/integration/ # real server + clients
QUIETROOM_RACE=1 go test -race ./tests/attack/      # hostile clients
(cd quietroom-gui && go test -race ./...)           # GUI backend
```

- **Integration tests** run real servers with the client library, the CLI
  (in a pseudo-terminal) and the Python connector: chat, rooms, DMs, and
  large, concurrent and interrupted file transfers.
- **Attack tests** try to get in or break the server: missing, forged and
  stale access keys, malformed frames, spoofed fields, hostile names,
  flow-control abuse, floods, reconnect races, slow readers, and metadata
  in logs.
- The frame reader and message decoder are **fuzzed**
  (`go test ./wire/ -fuzz=FuzzRead`).

All of these run in CI on every change.

## Contributing

Contributions are welcome! Please ensure:
- Code follows Go best practices
- Security features are not weakened
- Changes are well-documented
- Tests pass (see Building from Source)

## Security Disclosure

If you discover a security vulnerability, please report it privately via the repository's **Security** tab → **Report a vulnerability**. Do not open a public issue. See [SECURITY.md](SECURITY.md) for details.

## License

This project is licensed under the GNU Affero General Public License v3 (AGPL-3.0).

If you modify this software or run it as a network service, you are required
to make the complete corresponding source code available under the same license.

Commercial use as part of a proprietary product or service requires a separate
commercial license. Contact the author for details.

## Acknowledgments

Built with:
- Go standard library (crypto/tls, TLS 1.3)
- golang.org/x/crypto (bcrypt for room passwords)
