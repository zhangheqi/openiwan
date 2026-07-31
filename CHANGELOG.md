# Changelog

Notable changes to OpeniWAN are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/), and the
project follows [Semantic Versioning](https://semver.org/). Released sections
retain their published contents; current work belongs under `Unreleased`.

## [Unreleased]

## [0.3.0] - 2026-07-31

This release contains breaking changes to the CLI, configuration schema,
Cargo features, and public managed APIs.

### Added

- Segment Routing transport with directional path validation, inner and outer
  encryption, fragmentation and reassembly, monitoring, counters, and
  peer-down handling.
- Customer-domain discovery through signed primary and fallback lookup
  services, canonical-domain handling, retries, and a seven-day local cache.
- Domain-managed connection preparation with credential or OIDC
  authentication, generated per-ingress credentials, posture and
  device-binding gates, and traditional/SR line probing.
- Non-secret CLI profiles with atomic locked updates, installation Device IDs,
  default-profile selection, stable line preferences, and JSON output.
- Saved passwords and OIDC refresh tokens through macOS Keychain, Windows
  Credential Manager, and the Unix Secret Service, including refresh rotation
  and chunked Windows storage.
- A public DNS policy and runtime API shared by direct and managed TUN
  connections, including split DNS, encrypted-DNS controls, a protected
  physical resolver relay, and platform DNS leases.
- Controller and user routing modes, transport-loop exclusions, transactional
  rollback, persistent custom routes, and connection-scoped IPv6 leak
  protection.
- Raw TCP as a route-free forwarding target for direct and managed
  connections.
- Typed managed keepalive requests, responses, metrics, signing, and retry
  behavior.

### Changed

- Updated dependencies and raised the minimum supported Rust version to 1.91.
- Rebuilt managed operation around customer-domain discovery and live
  controller policy instead of provider files and saved controller responses.
- Reorganized the CLI into `ping`, `auth`, `connect`, `forward`, `decode`,
  `managed`, and `profile` command groups. Ping uses a positional endpoint and
  durations use explicit `ms`, `s`, or `m` units.
- Replaced index/name-based managed line selection with profile-backed stable
  `iwan:ID` and `sr:ID` preferences plus one-shot overrides.
- Renamed the default route-free Cargo feature to `forward` and changed the
  forwarding interface to fixed `tcp://`, `http://`, and `https://` target
  URIs.
- Simplified `ClientConfig` to data-plane settings and made Segment Routing a
  first-class configuration field. Authentication, heartbeat, AUTH_VERIFY,
  XOR, and fragmentation now follow the implemented protocol profile.
- Replaced the provider-oriented public managed API with domain lookup,
  controller models, prepared connections, line preferences, posture, and
  keepalive APIs.
- Moved TUN and forwarding DNS behavior into one layered policy with
  controller, profile, command-line, and OPEN_ACK inputs.
- Updated the traditional wire profile for Java US-ASCII credentials,
  canonical OPEN TLV order, optional-but-validated AUTH_VERIFY, eight-byte XOR
  repetition, 20-byte little-endian heartbeat, stateless ping values, and
  protocol-specific fragmentation.
- Updated OIDC integration to trust controller-provided authorization and
  token endpoints, preserve controller scopes, and validate callback state,
  redirect URI, PKCE, and nonce.

### Removed

- Provider TOML configuration, bundled deployment profiles, serialized
  managed controller state, the `--state-dir` option, and the provider-based
  `managed fetch`, `list`, `all`, and `serve` workflows.
- The `serve` command, `http-proxy` Cargo feature, `--upstream` and
  `--upstream-ip` options, and the HTTP-origin-only forwarding interface.
- Managed `--line-index` and `--line-name` selection.
- Configurable authentication and heartbeat timing,
  `require_auth_verify_echo`, and `xor_key_bytes` fields from `ClientConfig`.
- Deployment-specific provider guides and reverse-engineering notes from the
  published documentation set.

### Fixed

- Route Windows TUN prefixes through the authenticated session gateway so
  Windows does not synthesize unusable local routes for remote prefixes.
- Ignore an unusable `0.0.0.0` OPEN_ACK DNS address and use managed fallback
  resolvers when no configured server is usable.
- Restore pre-existing Linux routes that were replaced during tunnel setup.

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
- Static-analysis evidence and wire-protocol reference for Panabit iWAN client
  version 2.3.0.
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

[Unreleased]: https://github.com/zhangheqi/openiwan/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/zhangheqi/openiwan/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/zhangheqi/openiwan/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/zhangheqi/openiwan/tree/v0.1.0
