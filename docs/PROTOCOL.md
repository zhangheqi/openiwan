# iWAN Wire Protocol Profile

This document defines the interoperable wire profile implemented on
OpeniWAN's `main` branch. It describes observed compatible behavior, not a
vendor specification. Use the matching Git tag for a released implementation.

Protocol provenance, evidence standards, and unresolved details are documented
separately in [Protocol Provenance](PROTOCOL_PROVENANCE.md). Numeric fields are
unsigned unless stated otherwise. Byte order is named explicitly; bytes shown
as text use ASCII.

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

Defined packet types are:

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

Each TLV is `type:u8 | total_length:u8 | value`. Defined types are:

```text
01 USERNAME   02 PASSWORD    03 MTU       04 IP
05 DNS        06 GATEWAY     07 NETMASK   08 ENCRYPT
09 DUP_PKT    0a LINK        0f AUTH_VERIFY
10 ERR_MSG
```

`NETMASK` and `DUP_PKT` exist in the registry but are not applied to the active
session. The generic parser ignores a final one- or two-byte suffix;
conforming senders must not emit one.

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
The traditional receiver combines exactly two fragments by EOP order, ignores
offsets, retains at most 256 pending entries, and expires entries after 100 ms.

## Heartbeat, ping, and close

The traditional heartbeat body is 20 bytes, all little-endian:

```text
tick_us:u64 | current_us:u32 | minimum_us:u32 | maximum_us:u32
```

Requests are sent every two seconds. Ten misses or more than 20 seconds without
a valid response ends the session.

Ping is exactly 24 bytes with `session_id=0xffff`, `token=0xffffffff`, and no
body. A persistent session sends a 24-byte signed close; receivers accept both
that form and the eight-byte close used by temporary authentication probes.

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

The `/config` request is:

```json
{
  "domain": "domain",
  "type": "client-platform",
  "oem_name": "panabit",
  "app_version": "2.3.0",
  "device_id": "device-id",
  "userName": "optional",
  "posture_version": 7
}
```

The `type` member is the runtime platform (`android`, `ios`, `macos`, or
`windows`), not the lookup result's `controller` service type.

It uses `Content-Type: application/json`, `X-Mobile-Api-Version: 4`, the four
mobile-API `X-Auth-*` headers over the final URL and exact body, and an
optional OIDC bearer token. Deployment-specific response members remain
dynamic below the typed outer fields.

Managed discovery begins with `POST /lookup` against `lookup.gsase.com`, then
`lookupbak.hypersase.com`, with two attempts per server and a seven-day cache
fallback. The request sends
`serviceType: "fgb"` while the successful response carries the resolved
service type in `data.type`. It accepts only `serverlist`, `saas`, and
`controller`. Controller domains POST to the exact auth URL returned by
lookup; the domain is in the body and is not appended to the URL.
`credential` selects password login and `oidc` selects Authorization Code +
PKCE S256. The auth request is signed with the controller `app_id` and its
defined secret-selection rule.
Both lookup and auth use the same mobile-API HMAC header construction as
`/config`, with the actual HTTP method and exact body in the canonical request.

Password login probes ingress latency, selects the best responder, performs a
one-shot OPEN, saves the selected server and credentials, and closes the UDP
socket. Controller credential mode downloads its controller-provided
serverlist endpoint; OIDC login obtains `/config`, uses `server_credentials`
by `server_id`, and evaluates posture and device-binding gates when configured.
The persistent VPN connection always performs another OPEN before creating
TUN.

Controller iWAN lines are nested under `serverlist.serverlist`; SR groups use
the mutually exclusive top-level `sites` member. Each controller line can
carry `userName` and `passWord`; OpeniWAN associates these credentials with
the line's server ID.

Controller `passWord` is standard Base64 containing
`nonce[12] || ciphertext || tag[16]`. The AES-256-GCM key is
`SHA256(secret || "|" || active_domain || "|" || userName)`, where `secret`
uses the controller `app_id` selector above. Associated data is
`active_domain || "|" || userName`. SR ingress credentials use the same
construction with the ingress username.

For posture responses, integer and decimal-string versions are normalized. A
missing version or version `0` represents an empty or disabled configuration
and does not trigger `/posture/evaluate`.

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

The four `X-Auth-*` headers use HMAC-SHA256 with the UTF-8 app secret. The
crate exposes the complete metrics graph and tests the canonical HMAC vector.

## Protocol boundaries

The implemented profile does not define:

- authoritative `DUP_PKT` server policy;
- other-platform use of `NETMASK`;
- the production-preferred `OPEN_REJECT` construction;
- vendor names for SR monitor bits or marker `0x79`;
- relay-side SR path mutation;
- deployment-specific nested `/config` policy schemas;
- whether production servers require signed `CLOSE`;
- server-side duplicate suppression.

Extensions in these areas require interoperable evidence and an explicit
protocol-reference update.
