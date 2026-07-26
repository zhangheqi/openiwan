# iWAN Android 2.3.0 Protocol Reference

The normative engineering reference for OpeniWAN 0.3 is
`reverse/IWAN_PROTOCOL_SPEC.md` in the source workspace. That document was
reconstructed from the Android 2.3.0 APK and contains the complete byte
layouts, recovered state machines, test vectors, evidence map, and known
ambiguities.

This file is a packaged quick reference. It deliberately does not extend the
recovered contract.

## Standard datagram

The standard header is eight bytes:

```text
type:u8 | encrypt:u8 | session_id:u16 BE | token:u32 BE
```

Signed controls append:

```text
MD5(exact_header || ASCII("mw"))
```

The 16-byte signature covers only the header. It does not cover the body.

Confirmed packet types are:

| Value | Type |
|---:|---|
| `0x11` | `OPEN_REJECT` |
| `0x12` | `OPEN_ACK` |
| `0x13` | `OPEN` |
| `0x14` | `DATA` |
| `0x15` | `ECHO_REQUEST` |
| `0x16` | `ECHO_RESPONSE` |
| `0x17` | `CLOSE` |
| `0x18` | `DATA_ENCRYPTED` |
| `0x19` | `DATA_DUP` |
| `0x20` | `DATA_ENC_DUP` |
| `0x22` | `IP_FRAGMENT` |
| `0x23` | `DATA_IPV6` |
| `0x24` | `IP_FRAGMENT_IPV6` |
| `0x28` | `SEGMENT_ROUTING` |
| `0x29` | `PING_REQUEST` |
| `0x2a` | `PING_RESPONSE` |

Encryption values are `NONE=0`, `XOR=1`, and `AES=2`.

## Authentication TLVs

Each TLV is `type:u8 | total_length:u8 | value`. Confirmed types are:

```text
01 USERNAME   02 PASSWORD    03 MTU       04 IP
05 DNS        06 GATEWAY     07 NETMASK   08 ENCRYPT
09 DUP_PKT    0a LINK        0f AUTH_VERIFY
10 ERR_MSG
```

`NETMASK` and `DUP_PKT` exist in the registry but are not applied by the
recovered `OPEN_ACK` consumer. The generic parser ignores a final one- or
two-byte suffix; conforming senders must not emit one.

An `OPEN` body is ordered as MTU, USERNAME, PASSWORD, ENCRYPT, optional LINK,
and optional nonzero AUTH_VERIFY.

Credentials use Java US-ASCII replacement behavior. Password wrapping is:

```text
key   = MD5("mw" || ASCII(username))
block = first 16 ASCII(password) bytes, then zeroes to 16 bytes
wire  = AES-128-ECB(key, block)
```

The post-authentication session key is:

```text
MD5(ASCII(username || full_password))
```

AUTH_VERIFY is checked when returned and may be omitted by a response.

## Session payloads

- `NONE` is identity.
- `XOR` repeats only the first eight bytes of the 16-byte session key.
- `AES` is AES-128-ECB with zero padding and no authenticated integrity.
- the traditional transmit path chooses `DATA` or `DATA_ENCRYPTED` without
  inspecting the IP version;
- `DATA_DUP` is plain and `DATA_ENC_DUP` is encrypted;
- only encrypted data classes are session-decrypted.

Traditional fragments use a big-endian ID and a little-endian packed word.
The legacy receiver combines exactly two fragments by EOP order, ignores
offsets, retains at most 256 pending entries, and expires entries after 100 ms.

## Heartbeat, ping, and close

The traditional heartbeat body is 20 bytes, all little-endian:

```text
tick_us:u64 | current_us:u32 | minimum_us:u32 | maximum_us:u32
```

Requests are sent every two seconds. Ten misses or more than 20 seconds without
a valid response ends the session.

Ping is exactly 24 bytes with `session_id=0xffff`, `token=0xffffffff`, and no
body. A new client sends a 24-byte signed close; receivers accept both that
form and the recovered eight-byte probe close.

## Segment Routing

An SR datagram is:

```text
sr_header || inner_standard_header || inner_payload
```

The SR header is:

```text
28 | next_id | link_count | (pad_len << 3 | algorithm) | links:u32 BE[]
```

Link count is `1..6`, link IDs are `1..0x00ffffff`, and algorithms are
none/AES-128/AES-256. Outbound paths reverse the controller order and start at
`next_id = link_count - 1`; returned paths use controller order and require
`next_id=0`.

Outer AES encrypts only bytes after the inner eight-byte header, uses a raw
UTF-8 key prefix, AES-ECB-NoPadding, and zero padding recorded in the SR header.
IPv6 disables inner session encryption. Fragmentation is allowed only when
both encryption layers are off and emits exactly two fragments. SR fragment
IDs are little-endian and the SR reassembler honors offsets, gaps, duplicates,
overlaps, a 2-second lifetime, 16 groups, and 262144 buffered bytes.

SR monitor packets use an unencrypted SR envelope, an unsigned inner echo
header, and a 40-byte body containing the traditional delay fields, `"SRID"`,
a big-endian SR ID, marker bytes, flags, and counters. The period is one second
and peer-down threshold is five seconds.

## Managed HTTP

The confirmed `/config` request is:

```json
{
  "domain": "domain",
  "type": "service-type",
  "oem_name": "panabit",
  "app_version": "2.3.0",
  "device_id": "device-id",
  "userName": "optional",
  "posture_version": "optional"
}
```

It uses `Content-Type: application/json`, `X-Mobile-Api-Version: 4`, and an
optional OIDC bearer token. Its aggregate response schema is unresolved and
must remain dynamic.

Keepalive uses API version 3, a bearer token, five-second connect/read
timeouts, and one retry after a failed attempt except HTTP 401. Every attempt
uses a fresh timestamp, nonce, and signature over the same serialized body.
Its HMAC canonical string is six lines:

```text
POST
decoded path
decoded/sorted query
lowercase SHA-256 body hex
Unix timestamp
lowercase 16-byte nonce hex
```

The four `X-Auth-*` headers use HMAC-SHA256 with the UTF-8 app secret. See the
source reference for the complete metrics graph and normative HMAC vector.

## Known ambiguities

The recovered artifacts do not establish:

- authoritative `DUP_PKT` server policy;
- other-platform use of `NETMASK`;
- the production-preferred `OPEN_REJECT` construction;
- vendor names for SR monitor bits or marker `0x79`;
- relay-side SR path mutation;
- complete `/lookup`, `/auth`, or aggregate `/config` schemas;
- whether production servers require signed `CLOSE`;
- server-side duplicate suppression.

These points must not be filled in from intuition or another implementation.
