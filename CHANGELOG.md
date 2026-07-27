# Changelog

All notable changes to OpeniWAN are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- Parse the recovered lookup response service type from `data.type` while
  retaining `serviceType: "fgb"` only in the signed request body.

## [0.3.0] - 2026-07-27

### Added

- Full Segment Routing transport: directional headers, inner and outer
  encryption, exact two-fragment planning, offset-aware reassembly, monitor
  handshake, counters, and peer-down timing
- Android 2.3.0 byte-vector tests for OPEN, ping, signed close, XOR, AES, SR
  headers, fragment words, SR outer AES, and keepalive HMAC
- Confirmed `/config` request and dynamic response API
- Recovered `/config` mobile-API HMAC authentication in addition to its OIDC
  Bearer token
- Customer-domain lookup with the recovered primary/fallback endpoints,
  consent gate, retries, canonical-domain handling, seven-day cache, and
  platform `X-Auth-*` HMAC authentication
- Exact lookup-provided controller-auth endpoint, controller-app-ID secret
  derivation, credential/OIDC selection, controller-supplied OIDC
  Authorization Code + PKCE, posture evaluation, best-ingress probing, and
  separate login-probe and persistent OPEN handshakes
- Exact controller-generated credential decryption using the recovered
  AES-256-GCM payload, SHA-256 key derivation, and authenticated domain/user
  context
- Typed traditional server lists, per-server credentials, SR groups, DNS,
  routing, IP-filter, and domain-filter configuration
- Managed TUN policy for recovered `all`, `ipfilter`, and `custom` modes,
  including CIDR exclusions, ingress-loop prevention, DNS routing and
  platform DNS rollback
- Complete recovered HTTP keepalive request/response metric graph,
  Java-compatible URL canonicalization, HMAC headers, five-second timeouts, and
  one retry after a failed attempt except HTTP 401
- Exact standalone Android `SREntry` serializer model

### Changed

- Made the Android 2.3.0 reverse-engineering result the protocol contract
- Corrected controller `/config.type` from the lookup service type to the
  runtime client platform, preserved controller-provided OIDC scopes including
  `offline_access`, and matched the recovered username claim set
- Matched the controller posture resolver's missing/zero-version
  empty-or-disabled sentinel instead of attempting `/posture/evaluate`
- Corrected stateless ping sentinels to `0xffff` and `0xffffffff`
- Corrected XOR to repeat only the first eight session-key bytes
- Corrected heartbeat to a 20-byte little-endian monotonic body, two-second
  period, ten-miss limit, and 20-second response timeout
- Corrected Java US-ASCII credential replacement, OPEN TLV order, optional
  AUTH_VERIFY echo handling, OPEN_ACK integer widths, and OPEN_REJECT suffix
  parsing/error mapping
- Corrected traditional IPv6 transmission to use the same `DATA` or
  `DATA_ENCRYPTED` choice as IPv4
- Split legacy and SR fragment behavior, including their different ID
  endianness and reassembly rules
- Bumped the crate version directly to 0.3.0; compatibility with speculative
  0.1/0.2 APIs is intentionally not retained
- Removed the speculative hand-written managed-provider configuration and its
  example; managed deployments now start from the recovered customer-domain
  lookup flow

## [0.2.0] - 2026-07-25

See the repository tag for the historical release.

## [0.1.0] - 2026-07-25

See the repository tag for the historical release.

[Unreleased]: https://github.com/zhangheqi/openiwan/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/zhangheqi/openiwan/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/zhangheqi/openiwan/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/zhangheqi/openiwan/tree/v0.1.0
