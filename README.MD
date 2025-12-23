# QuietRoom

A privacy-focused encrypted chat system with end-to-end encryption, perfect forward secrecy, and traffic obfuscation features.

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

- 🔐 **RSA-4096 Authentication** - Verify server identity and prevent impersonation
- 🔑 **Diffie-Hellman Key Exchange** - Perfect forward secrecy with ephemeral session keys
- 🛡️ **AES-256-GCM Encryption** - Strong encryption for all messages
- 🕵️ **Traffic Obfuscation** - TLS-like packet structure to blend with normal HTTPS traffic
- 🎭 **Decoy Traffic** - Optional feature to hide communication patterns
- 💬 **Private Messaging** - Direct messages between users
- 🚪 **Chat Rooms** - Create password-protected rooms for group conversations
- 📁 **File Transfers** - Secure file sharing with integrity verification
- 📝 **Security Logging** - Track authentication attempts and security events

## Quick Start

### Server Setup

1. Build and run the server:
   ```bash
   go build -o quietroom_server quietroom_server.go
   ./quietroom_server
   ```

2. Securely distribute `chat_public.pem` to your clients

### Client Setup

1. Obtain `chat_public.pem` from your server administrator

2. Build and run the client:
   ```bash
   go build -o  quietroom_client  quietroom_client.go
   ./ quietroom_client
   ```

3. Connect and start chatting!

## Documentation

For detailed setup instructions, configuration options, and troubleshooting:

- **[Server Documentation](SERVER_README.md)** - Complete server setup, configuration, and administration guide
- **[Client Documentation](CLIENT_README.md)** - Client installation, configuration, and usage instructions

## Security Overview

### Encryption Layers

1. **TLS 1.3 Transport Layer** - Encrypts all network traffic between client and server
2. **RSA-4096 Authentication** - Server proves its identity to prevent man-in-the-middle attacks
3. **Diffie-Hellman Key Exchange** - Generates unique session keys for perfect forward secrecy
4. **AES-256-GCM Session Encryption** - Encrypts all messages with authenticated encryption

### Traffic Protection

- **Obfuscation**: Packets use TLS-like structure with random padding
- **Decoy Traffic**: Optional random data transmission to mask activity patterns
- **Certificate Pinning**: Clients verify exact server certificate to prevent substitution attacks

### Privacy Features

- **Perfect Forward Secrecy**: Past sessions remain secure even if long-term keys are compromised
- **No Message Persistence**: Messages are not stored on the server
- **No User Tracking**: No logs of message content or metadata
- **Self-Hosted**: Complete control over your infrastructure

## System Requirements

- **Go**: Version 1.16 or higher
- **Operating Systems**: Linux, macOS, Windows
- **Network**: TCP connectivity between server and clients
- **Disk Space**: Minimal (< 50MB for binaries and logs)
- **Memory**: ~10-20MB for server + ~2MB per connected client

## Architecture

```
┌──────────┐                           ┌──────────┐
│  Client  │◄────── TLS 1.3 ──────────►│  Server  │
│          │                           │          │
│ • RSA    │   1. TLS Handshake        │ • RSA    │
│ • DH     │   2. Certificate Pin      │ • DH     │
│ • AES    │   3. DH Key Exchange      │ • AES    │
│          │   4. Encrypted Session    │          │
└──────────┘                           └──────────┘
     │                                      │
     │         ┌────────────────┐          │
     └────────►│  AES-256-GCM   │◄─────────┘
               │  Encrypted     │
               │  Messages      │
               └────────────────┘
```

## Building from Source

```bash
# Clone the repository
git clone <repository-url>
cd quietroom

# Build server
go build -o quietroom_server quietroom_server.go

# Build client
go build -o  quietroom_client quietroom_client.go

# Run tests (if available)
go test ./...
```

## Contributing

Contributions are welcome! Please ensure:
- Code follows Go best practices
- Security features are not weakened
- Changes are well-documented
- Tests pass (when available)

## Security Disclosure

If you discover a security vulnerability, please email the maintainers directly rather than opening a public issue. We take security seriously and will respond promptly.

## License

This project is licensed under the GNU Affero General Public License v3 (AGPL-3.0).

If you modify this software or run it as a network service, you are required
to make the complete corresponding source code available under the same license.

Commercial use as part of a proprietary product or service requires a separate
commercial license. Contact the author for details.

## Acknowledgments

Built with:
- Go standard library crypto packages
- RFC 3526 (DH parameters)
- NIST recommendations for key sizes

## Version

Current Version: 1.0.0