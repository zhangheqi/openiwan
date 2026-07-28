# Changelog

All notable changes to OpeniWAN are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- A unified public DNS subsystem with typed server, split, encrypted-DNS, and
  domain-rule policies; packet-level DNS routing and enforcement; bounded
  physical resolver relay; reconnect-aware runtime state; and link-scoped
  Linux, macOS, and Windows DNS leases.
- One-shot and profile DNS overrides with deterministic
  CLI > profile > controller > OPEN_ACK precedence.

- Full Segment Routing transport with directional headers, inner and outer
  encryption, exact two-fragment planning, offset-aware reassembly, monitor
  handshakes, counters, and peer-down timing.
- Byte-vector coverage for OPEN, ping, signed close, XOR, AES, SR headers,
  fragment words, SR outer AES, and keepalive HMAC.
- Customer-domain lookup with primary/fallback endpoints, retries,
  canonical-domain handling, a seven-day cache, and platform
  `X-Auth-*` authentication.
- Controller authentication with signed requests, credential/OIDC selection,
  Authorization Code + PKCE, posture evaluation, device-binding gates,
  best-ingress probing, and separate temporary and persistent UDP sessions.
- Controller-generated credential decryption using AES-256-GCM, SHA-256 key
  derivation, and authenticated domain/user context.
- Typed traditional server lists, per-server credentials, SR groups, DNS,
  routing, IP-filter, and domain-filter configuration.
- Managed TUN policy for `all`, `ipfilter`, and `custom` modes, including CIDR
  exclusions, ingress-loop prevention, DNS routing, and platform DNS rollback.
- HTTP keepalive request/response metric models, Java-compatible URL
  canonicalization, HMAC headers, timeouts, and retry behavior.
- Standalone `SREntry` serialization model.
- Versioned CLI profiles for domain, device ID, username, and stable
  line preferences, with locked atomic writes and strict Unix permissions.
- Managed line listing with bounded parallel probes, stable human/JSON output,
  one-shot selection, persisted selection, and automatic stale-line recovery.
- Saved password and OIDC authentication in the operating-system credential
  store, refresh-token rotation, explicit logout and reauthentication,
  non-interactive service startup, and chunked storage for credentials larger
  than Windows Credential Manager's per-entry limit.
- Managed route-free TCP and HTTP(S) forwarding using controller discovery,
  authentication, line selection, and DNS policy.
- Automatic installation-wide Device ID generation and persistence, with
  optional CLI overrides for existing enrollments.

### Changed

- Simplified CLI help and option names for saved authentication, line
  selection, forwarding, profile edits, and timeouts. Duration arguments now
  require an explicit `ms`, `s`, or `m` unit.
- Replaced `DnsGuard`, controller `DnsConfiguration`/raw routing DNS fields,
  and forward-only `DnsMode`/`DnsConfig` with the breaking public
  `openiwan::dns` API. Forward flags are now `--resolve`, `--dns-server`, and
  `--dns-timeout`.
- Split DNS is enforced in the TUN packet path instead of platform
  route-only resolver domains. Encrypted-DNS compatibility now drops visible
  TCP/UDP 853 and denies configured DoH hostnames without TLS interception.

- Set the next package version to 0.3.0. Public APIs may change until the
  release is published.
- Made the documented iWAN wire profile the protocol contract.
- Use the runtime client platform for controller `/config.type`.
- Preserve controller-provided OIDC scopes, including `offline_access`, and
  apply the protocol username-claim precedence.
- Treat a missing or zero posture version as an empty/disabled configuration.
- Use `0xffff` and `0xffffffff` for stateless ping session values.
- Repeat only the first eight session-key bytes in XOR mode.
- Use a 20-byte little-endian traditional heartbeat with the defined timing
  and miss limits.
- Apply Java US-ASCII replacement, canonical OPEN TLV ordering, optional
  AUTH_VERIFY handling, defined OPEN_ACK integer widths, and structured
  OPEN_REJECT mapping.
- Use the traditional DATA/DATA_ENCRYPTED choice for both IPv4 and IPv6.
- Keep traditional and SR fragmentation as separate algorithms with their
  respective byte order and reassembly rules.
- Rename `LegacyFragmentReassembler` to
  `TraditionalFragmentReassembler`.
- Managed deployments now start from customer-domain discovery.
- Present OpeniWAN as a standalone open-source client, use protocol-oriented
  documentation names, and provide shell-neutral command examples with
  explicit PowerShell variants where syntax differs.

### Fixed

- Parse the lookup response service type from `data.type` while sending
  `serviceType: "fgb"` in the signed request body.
- Ignore an unspecified `0.0.0.0` OPEN_ACK DNS address and use the
  official-client fallback resolvers for managed controller connections.
- Use canonical `Duration` units so the Rust 1.97 Clippy quality gate passes
  with warnings denied.

## [0.2.0] - 2026-07-25

See the repository tag for the historical release.

## [0.1.0] - 2026-07-25

See the repository tag for the historical release.

[Unreleased]: https://github.com/zhangheqi/openiwan/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/zhangheqi/openiwan/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/zhangheqi/openiwan/tree/v0.1.0
