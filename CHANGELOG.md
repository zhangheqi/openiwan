# Changelog

All notable changes to `openiwan` will be documented in this file.

The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- English-first community and technical documentation
- Simplified Chinese README translation
- Contribution guidelines, code of conduct, and architecture guide

## [0.1.0] - 2026-07-23

### Added

- Traditional iWAN packet, TLV, authentication, heartbeat, and CLOSE handling
- Plaintext, repeating XOR, and legacy AES-128-ECB data modes
- IPv4, IPv6, IPFRAG, and IPFRAG6 receive paths
- Bounded fragment reassembly and reconnect policies
- Linux TUN and macOS utun support
- `ping`, `auth`, `connect`, and `decode` CLI commands
- Static-analysis evidence and wire-protocol reference for client version 2.3.0
- Unit tests and a synthetic local UDP authentication endpoint
