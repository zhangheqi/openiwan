# Changelog

All notable changes to OpeniWAN are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and
the project follows [Semantic Versioning](https://semver.org/). Before `1.0`,
minor releases may contain explicitly documented breaking changes.
Released sections retain their published contents; current work belongs only
under `Unreleased`.

## [Unreleased]

This section is verified between the latest published tag and `HEAD`. The next
release is a breaking update to the CLI, configuration schema, Cargo features,
and public managed APIs.

### Added

- Complete Segment Routing transport, including directional path headers,
  inner and outer encryption, two-fragment planning and reassembly, returned
  path validation, monitoring, counters, and peer-down handling.
- Customer-domain discovery with primary and fallback services, canonical
  domain handling, signed requests, retries, and a seven-day local cache.
- Controller-managed credential and OIDC authentication, generated
  per-ingress credential decryption, posture and device-binding gates,
  traditional/SR line probing, and persistent connection preparation.
- Versioned non-secret CLI profiles with atomic locked updates, a generated
  installation Device ID, default-profile selection, stable line preferences,
  and JSON output for profiles and line probes.
- Saved password and OIDC refresh-token authentication through macOS Keychain,
  Windows Credential Manager, and the Unix Secret Service, including refresh
  rotation, `--save`, `--reauth`, `--non-interactive`, explicit logout, and
  chunked Windows storage.
- A shared DNS subsystem with typed policy layers, split-DNS rules,
  encrypted-DNS handling, packet-level enforcement, a protected physical
  resolver relay, reconnect-aware generations, and platform DNS leases.
- Controller-driven `all`, `ipfilter`, and `custom` TUN routing with
  transport-loop exclusions and rollback.
- Route-free forwarding for raw TCP and fixed-origin HTTP(S), available for
  both direct and managed authentication.
- Typed managed keepalive request, response, and metric models with canonical
  HMAC signing and retry behavior.
- Protocol references and byte-vector coverage for traditional and Segment
  Routing packets, OPEN, ping, close, XOR, AES, fragments, monitor packets,
  generated credentials, and keepalive signing.

### Changed

- Updated the dependency graph to the latest stable releases and raised the
  minimum supported Rust version to 1.91.
- Rebuilt managed operation around customer-domain discovery and live
  controller policy instead of provider files and serialized controller
  responses.
- Reworked the CLI into `ping`, `auth`, `connect`, `forward`, `decode`,
  `managed`, and `profile` command groups. Endpoint probing now takes a
  positional server, duration values require `ms`, `s`, or `m`, and current
  option names follow the built-in help without compatibility aliases.
- Renamed the default route-free Cargo feature to `forward` and extended its
  fixed target from HTTP(S) origins to `tcp://`, `http://`, and `https://`
  URIs.
- Simplified `ClientConfig` to data-plane settings. Authentication and
  heartbeat timings, AUTH_VERIFY behavior, and XOR key width now follow the
  protocol profile; Segment Routing configuration is a first-class field.
- Replaced the public provider-oriented managed API with domain lookup,
  controller models, prepared connections, stable line preferences, posture,
  and keepalive APIs.
- Added the public `openiwan::dns` policy/runtime API and session lifecycle
  hooks on `PacketDevice`; direct and managed TUN connections now share DNS
  enforcement.
- Aligned the wire profile with the analyzed 2.3.0 client behavior: Java
  US-ASCII credentials, canonical OPEN TLV order, optional-but-validated
  AUTH_VERIFY, eight-byte XOR repetition, 20-byte little-endian heartbeat,
  fixed stateless ping values, traditional data-class selection, and distinct
  traditional/SR fragmentation rules.
- OIDC now uses controller-provided authorization and token endpoints
  directly, preserves controller scopes, validates callback state, redirect
  URI, PKCE, and nonce, and does not require discovery or JWKS verification.
- Split DNS moved from platform resolver-domain routes into the TUN packet
  path. Controller, profile, command-line, and OPEN_ACK inputs now resolve
  through one deterministic policy.
- Reorganized project documentation around current protocol, architecture,
  CLI, configuration, security, support, and interoperability evidence rather
  than deployment-specific instructions.

### Removed

- Provider TOML configuration, bundled deployment profiles, serialized
  managed controller state, and the provider-based `managed fetch`, `list`,
  `all`, and `serve` workflows.
- The `serve` command, `http-proxy` Cargo feature, `--upstream-ip` override,
  and HTTP-origin-only forwarding interface.
- Configurable authentication/heartbeat timing, `require_auth_verify_echo`,
  and `xor_key_bytes` fields from `ClientConfig`.
- Deployment-specific provider documentation and reverse-engineering notes
  from the published documentation set.

### Fixed

- Read the discovered service type from `data.type` while retaining
  `serviceType: "fgb"` in the signed lookup request.
- Ignore an unusable `0.0.0.0` OPEN_ACK DNS address and use managed controller
  fallback resolvers when no usable configured server exists.
- Store credentials larger than the Windows Credential Manager per-entry
  limit as validated, versioned chunks and remove obsolete generations.
- Align human-readable managed line columns for mixed-width Unicode names and
  multi-digit values.

## [0.2.0] - 2026-07-25

### Added

- Windows 10/11 x86_64 and ARM64 TUN support with native IPv4/IPv6 route
  management and rollback.
- Embedded, signed Wintun 0.14.1 binaries with verified, atomic first-use
  extraction for `cargo install`.
- Cross-platform hidden password prompts and Windows managed-state
  directories.

### Changed

- Replaced the hand-written Linux/macOS TUN implementation with `tun` 0.8.14.
- Raised the minimum supported Rust version from 1.85 to 1.88.
- Made `--tun` platform-aware: `openiwan0` on Linux/Windows and automatic
  `utunN` allocation on macOS.
- Changed `TunDevice::open` and `RouteGuard::configure` to accept authenticated
  session/device state directly.

## [0.1.0] - 2026-07-25

### Added

- Traditional iWAN packet, TLV, authentication, heartbeat, and CLOSE handling.
- Compact 8-byte heartbeat responses used by compatible USTC servers.
- Configurable 8/16-byte XOR key cycling, with USTC using the 8-byte form.
- Plaintext, repeating XOR, and legacy AES-128-ECB data modes.
- IPv4, IPv6, IPFRAG, and IPFRAG6 receive paths.
- Bounded fragment reassembly and reconnect policies.
- Linux TUN and macOS utun support.
- `ping`, `auth`, `connect`, and `decode` CLI commands.
- Static-analysis evidence and wire-protocol reference for client version 2.3.0.
- Unit tests and a synthetic local UDP authentication endpoint.
- English-first community and technical documentation.
- Simplified Chinese README translation.
- Contribution guidelines, code of conduct, and architecture guide.
- Configuration-driven `managed fetch`, `list`, `connect`, and `all` commands.
- PKCE OIDC login with state, nonce, discovery, JWKS, and ID-token
  validation.
- Signed controller configuration fetch and authenticated AES-GCM
  line-password decryption.
- CIDR, IP, and one-time domain route targets on Linux and macOS.
- Route-free `serve` and `managed serve` HTTP/1.1 reverse proxy commands using
  an in-process TCP/IP stack with HTTP and verified HTTPS upstream support.
- Fixed `--upstream-ip` connection targets that bypass VPN Fake-IP DNS while
  retaining the configured HTTP Host and HTTPS identity.
- Automatic organization DNS through the iWAN userspace stack with provider
  and OPENACK resolvers, CNAME support, bounded TTL caching, response
  validation, multi-server retry, and DNS-over-TCP fallback.
- Explicit managed-provider compatibility for endpoints that omit AUTH_VERIFY
  from OPENACK, while still rejecting mismatched echoes.

### Changed

- Isolated deployment-specific configuration and guidance from generic code,
  examples, and documentation.
- Require AUTH_VERIFY policy, XOR key width, and managed-provider DNS settings
  explicitly in the current configuration schema.
- Replace the pre-release fixed-width cipher constructors with fallible APIs
  that require an explicit 8- or 16-byte XOR key width.

[Unreleased]: https://github.com/zhangheqi/openiwan/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/zhangheqi/openiwan/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/zhangheqi/openiwan/tree/v0.1.0
