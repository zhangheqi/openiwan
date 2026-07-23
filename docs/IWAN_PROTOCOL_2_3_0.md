# iWAN 2.3.0 Client Wire Protocol

This document describes the traditional single-path UDP protocol implemented by
`com.panabit.iwan.macosclient.PacketTunnel` version `2.3.0 (230)`.

It is an interoperability reference derived from static analysis. It is not an
official specification. See
[Reverse-Engineering Evidence and Limitations](REVERSE_ENGINEERING.md) for the
source and confidence level of each conclusion.

Unless stated otherwise, all multibyte integers use network byte order
(big-endian). The second 32-bit word in an IPFRAG header is the only known
exception; it is a little-endian C bitfield.

## Transport and Session Model

- The transport is UDP.
- The client starts a session with OPEN.
- The server answers with OPENACK or OPENREJECT.
- After OPENACK, every stateful packet carries the assigned `session_id` and
  `token`.
- One UDP datagram contains one complete iWAN packet. There is no stream
  framing across datagrams.

## Common Header

Every packet begins with an 8-byte header:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | Packet type |
| 1 | 1 | Encryption method |
| 2 | 2 | Session ID, big-endian |
| 4 | 4 | Token, big-endian |

Control packets append a 16-byte signature immediately after the header:

```text
MD5(header[0..8] || ASCII("mw"))
```

The signature does not cover the control-packet body. A decoder should verify
the signature before parsing that body.

Data packets do not contain this signature. Their body starts immediately
after the common header.

## Packet Types

| Value | Name | Class | Body |
|---:|---|---|---|
| `0x11` | OPENREJECT | Control | TLVs or error code/message |
| `0x12` | OPENACK | Control | TLVs |
| `0x13` | OPEN | Control | TLVs |
| `0x14` | DATA | Data | IPv4 packet |
| `0x15` | echoRequest | Control | 8-byte timestamp |
| `0x16` | echoResponse | Control | Timestamp and three delay values |
| `0x17` | CLOSE | Control | Empty |
| `0x18` | DATAENC | Data | Encrypted IP packet |
| `0x19` | DATADUP | Data | Duplicated plaintext IP packet |
| `0x20` | DATAENCDUP | Data | Duplicated encrypted IP packet |
| `0x22` | IPFRAG | Data | Fragmented IPv4 envelope |
| `0x23` | DATA6 | Data | IPv6 packet |
| `0x24` | IPFRAG6 | Data | Fragmented IPv6 envelope |
| `0x28` | SEGRT | Data | SR/multipath envelope |
| `0x29` | pingRequest | Control | Empty |
| `0x2a` | pingResponse | Control | Empty |

`0x15` and `0x16` are stateful session heartbeats. `0x29` and `0x2a` are
stateless endpoint probes. They are distinct exchanges.

## TLV Encoding

Attributes use a one-byte type and a one-byte total length. The total length
includes the type and length bytes:

```text
+---------+--------------+------------------+
| type:u8 | total_len:u8 | value[len - 2]   |
+---------+--------------+------------------+
```

The total length must be at least 2 and must not exceed the remaining packet
body.

| Value | Name | Value encoding |
|---:|---|---|
| `0x01` | USERNAME | UTF-8 bytes |
| `0x02` | PASSWORD | 16-byte encrypted password block |
| `0x03` | MTU | `u16` |
| `0x04` | IP | 4-byte IPv4 address |
| `0x05` | DNS | One or more IPv4 addresses |
| `0x06` | GATEWAY | 4-byte IPv4 address |
| `0x07` | NETMASK | 4-byte IPv4 netmask |
| `0x08` | ENCRYPT | `u8` |
| `0x09` | DUPPKT | `u8` boolean |
| `0x0a` | LINK | `u32` first-hop link |
| `0x0b` | IP6 | 16-byte IPv6 address |
| `0x0c` | DNS6 | One or more IPv6 addresses |
| `0x0d` | GATEWAY6 | 16-byte IPv6 address |
| `0x0e` | SERVER_CONFIG | Opaque variable-length data |
| `0x0f` | AUTH_VERIFY | `u32` |
| `0x10` | REJECT_REASON | `u8` error code |

## Authentication

An OPEN packet uses:

```text
type=0x13, encryption=requested, session_id=0, token=0
```

The observed TLV order is:

1. MTU
2. USERNAME
3. PASSWORD
4. ENCRYPT
5. LINK, when an SR first hop is present
6. AUTH_VERIFY, containing a random `u32`

The PASSWORD value is produced as follows:

```text
password_key = MD5("mw" || username_utf8)
plain_block  = first_16_bytes(password_utf8) || zero_padding
PASSWORD     = AES-128-ECB-Encrypt(password_key, plain_block)
```

OPENACK returns a nonzero session ID, a token, address configuration, and the
same AUTH_VERIFY value. A client should reject an absent or mismatched
AUTH_VERIFY value so that a stale OPENACK cannot be associated with the current
request.

The traditional data-plane session key is:

```text
session_key = MD5(username_utf8 || password_utf8)
```

## Data Encryption

The ENCRYPT values are:

| Value | Algorithm |
|---:|---|
| 0 | None |
| 1 | Repeating XOR |
| 2 | AES |

Repeating XOR applies:

```text
cipher[i] = plain[i] XOR session_key[i mod 16]
```

The AES mode is AES-128-ECB without PKCS#7. The sender appends zero bytes until
the body length is a multiple of 16; it does not append an extra block when the
input is already aligned. The receiver removes the zero padding by reading the
IPv4 total length or IPv6 payload length from the decrypted packet.

None of these legacy modes provides reliable packet integrity.

## Heartbeat

An echoRequest body contains:

```text
timestamp_micros: u64
```

An echoResponse body contains:

```text
timestamp_micros:     u64
current_delay_micros: u32
minimum_delay_micros: u32
maximum_delay_micros: u32
```

All fields are big-endian. The response echoes the request timestamp.

## IPFRAG and IPFRAG6

The fragment body starts with an 8-byte prefix:

```text
fragment_id: u32 big-endian
packed:      u32 little-endian
```

The `packed` bitfield is:

- bit 0: EOP, marking the final fragment
- bit 1: reserved
- bits 2 through 14: 13-bit byte offset
- bits 15 through 25: 11-bit fragment payload length
- bits 26 through 31: reserved

A receiver should group fragments by ID and IP family, reject zero-length,
overlapping, out-of-range, or inconsistent fragments, and enforce limits on
group count, packet size, and lifetime. An inner IP packet is complete only
when fragments cover every byte from offset zero through the EOP fragment.

## SEGRT

The 2.3.0 binary contains `SegrtHeader`, `SegrtSession`, path monitoring,
AES-128/AES-256 outer encryption, and reassembly code. That path depends on SR
group and site configuration delivered by a controller; it is not part of the
traditional single-endpoint handshake documented above.

`openiwan` recognizes packet type `0x28` and discards its body instead of
passing unknown data to the TUN interface. SEGRT must not be described as
production-compatible until an implementation has been validated with an
authorized SR configuration, bidirectional captures, and the corresponding
server state machine.

## Security Considerations

- The control signature authenticates neither the body nor a peer identity.
- MD5, repeating XOR, and AES-ECB are legacy compatibility mechanisms.
- Traditional data packets have no authenticated integrity protection.
- The protocol should be used only on authorized networks and, where
  appropriate, inside an additional trusted security layer.

See the project [Security Policy](../SECURITY.md) for reporting guidance.
