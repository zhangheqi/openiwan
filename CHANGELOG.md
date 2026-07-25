# Changelog

All notable changes to OpeniWAN will be documented in this file.

The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-07-25

### Added

- Windows 10/11 x86_64 and ARM64 TUN support with native IPv4/IPv6 route
  management and rollback
- Embedded, signed Wintun 0.14.1 binaries with verified, atomic first-use
  extraction for `cargo install`
- Cross-platform hidden password prompts and Windows managed-state directories

### Changed

- Replaced the hand-written Linux/macOS TUN implementation with `tun` 0.8.14
- Raised the minimum supported Rust version from 1.85 to 1.88
- Made `--tun` platform-aware: `openiwan0` on Linux/Windows and automatic
  `utunN` allocation on macOS
- Changed `TunDevice::open` and `RouteGuard::configure` to accept authenticated
  session/device state directly

## [0.1.0] - 2026-07-25

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
- English-first community and technical documentation
- Simplified Chinese README translation
- Contribution guidelines, code of conduct, and architecture guide
- Configuration-driven `managed fetch`, `list`, `connect`, and `all` commands
- PKCE OIDC login with state, nonce, discovery, JWKS, and ID-token validation
- Signed controller configuration fetch and authenticated AES-GCM line-password
  decryption
- CIDR, IP, and one-time domain route targets on Linux and macOS
- Route-free `serve` and `managed serve` HTTP/1.1 reverse proxy commands using
  an in-process TCP/IP stack with HTTP and verified HTTPS upstream support
- Fixed `--upstream-ip` connection targets that bypass VPN Fake-IP DNS while
  retaining the configured HTTP Host and HTTPS identity
- Automatic organization DNS through the iWAN userspace stack with provider
  and OPENACK resolvers, CNAME support, bounded TTL caching, response
  validation, multi-server retry, and DNS-over-TCP fallback
- Explicit managed-provider compatibility for endpoints that omit AUTH_VERIFY
  from OPENACK, while still rejecting mismatched echoes

### Changed

- Isolated deployment-specific configuration and guidance from generic code,
  examples, and documentation
- Require AUTH_VERIFY policy, XOR key width, and managed-provider DNS settings
  explicitly in the current configuration schema
- Replace the pre-release fixed-width cipher constructors with fallible APIs
  that require an explicit 8- or 16-byte XOR key width

[Unreleased]: https://github.com/zhangheqi/openiwan/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/zhangheqi/openiwan/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/zhangheqi/openiwan/tree/v0.1.0
