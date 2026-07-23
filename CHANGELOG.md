# Changelog

All notable changes to `openiwan` will be documented in this file.

The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- English-first community and technical documentation
- Simplified Chinese README translation
- Contribution guidelines, code of conduct, and architecture guide
- Configuration-driven `managed fetch`, `list`, `connect`, and `all` commands
- PKCE OIDC login with state, nonce, discovery, JWKS, and ID-token validation
- Signed controller configuration fetch and authenticated AES-GCM line-password
  decryption
- CIDR, IP, and one-time domain route targets on Linux and macOS
- Explicit managed-provider compatibility for endpoints that omit AUTH_VERIFY
  from OPENACK, while still rejecting mismatched echoes

## [0.1.0] - 2026-07-23

### Added

- Traditional iWAN packet, TLV, authentication, heartbeat, and CLOSE handling
- Compact 8-byte heartbeat responses used by compatible USTC servers
- Configurable 8/16-byte XOR key cycling, with USTC using the 8-byte form
- Plaintext, repeating XOR, and legacy AES-128-ECB data modes
- IPv4, IPv6, IPFRAG, and IPFRAG6 receive paths
- Bounded fragment reassembly and reconnect policies
- Linux TUN and macOS utun support
- `ping`, `auth`, `connect`, and `decode` CLI commands
- Static-analysis evidence and wire-protocol reference for client version 2.3.0
- Unit tests and a synthetic local UDP authentication endpoint
