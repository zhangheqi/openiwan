# Changelog

All notable changes to OpeniWAN are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-07-26

### Added

- Full Segment Routing transport: directional headers, inner and outer
  encryption, exact two-fragment planning, offset-aware reassembly, monitor
  handshake, counters, and peer-down timing
- Android 2.3.0 byte-vector tests for OPEN, ping, signed close, XOR, AES, SR
  headers, fragment words, SR outer AES, and keepalive HMAC
- Confirmed `/config` request and dynamic response API
- Complete recovered HTTP keepalive request/response metric graph,
  Java-compatible URL canonicalization, HMAC headers, five-second timeouts, and
  one retry after a failed attempt except HTTP 401
- Exact standalone Android `SREntry` serializer model

### Changed

- Made the Android 2.3.0 reverse-engineering result the protocol contract
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

## [0.2.0] - 2026-07-25

See the repository tag for the historical release.

## [0.1.0] - 2026-07-25

See the repository tag for the historical release.

[Unreleased]: https://github.com/zhangheqi/openiwan/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/zhangheqi/openiwan/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/zhangheqi/openiwan/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/zhangheqi/openiwan/tree/v0.1.0
