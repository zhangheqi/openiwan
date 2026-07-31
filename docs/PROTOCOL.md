# iWAN protocol profile

This reference describes the interoperable wire behavior implemented by
OpeniWAN. It is based on independent analysis and authorized testing, not a
vendor specification. See [Protocol Provenance](PROTOCOL_PROVENANCE.md) for
evidence requirements and unresolved areas.

Numeric fields are unsigned unless stated otherwise. Byte order is named
explicitly; text bytes use ASCII.

## Standard datagrams

The standard header is eight bytes:

```text
type:u8 | encrypt:u8 | session_id:u16 BE | token:u32 BE
```

Signed controls append:

```text
MD5(exact_header || ASCII("mw"))
```

The 16-byte signature covers only the header.

| Value | Packet type |
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

## Authentication

Each TLV is `type:u8 | total_length:u8 | value`:

```text
01 USERNAME   02 PASSWORD    03 MTU       04 IP
05 DNS        06 GATEWAY     07 NETMASK   08 ENCRYPT
09 DUP_PKT    0a LINK        0f AUTH_VERIFY
10 ERR_MSG
```

The generic parser tolerates a final one- or two-byte suffix, although
conforming senders should not emit one. `NETMASK` and `DUP_PKT` are parsed but
do not change the active session.

An `OPEN` body is ordered as MTU, USERNAME, PASSWORD, ENCRYPT, optional LINK,
and optional nonzero AUTH_VERIFY. Credentials use Java US-ASCII replacement
behavior. Password wrapping is:

```text
key   = MD5("mw" || ASCII(username))
block = first 16 ASCII(password) bytes, then zeroes to 16 bytes
wire  = AES-128-ECB(key, block)
```

The session key after authentication is:

```text
MD5(ASCII(username || full_password))
```

AUTH_VERIFY may be omitted by the response; when present, it must match.

## Session data

- `NONE` is identity.
- `XOR` repeats the first eight bytes of the 16-byte session key.
- `AES` is AES-128-ECB with zero padding and no authenticated integrity.
- The traditional transmit path selects `DATA` or `DATA_ENCRYPTED` without
  inspecting the IP version.
- `DATA_DUP` is plain and `DATA_ENC_DUP` is encrypted.
- Only encrypted data classes are session-decrypted.

Traditional fragments use a big-endian ID and a little-endian packed word.
The receiver combines exactly two fragments by EOP order, ignores offsets,
retains at most 256 pending groups, and expires them after 100 ms.

## Heartbeat, ping, and close

The traditional heartbeat body is 20 bytes, all little-endian:

```text
tick_us:u64 | current_us:u32 | minimum_us:u32 | maximum_us:u32
```

Requests are sent every two seconds. Ten misses or more than 20 seconds
without a valid response ends the session.

Ping is exactly 24 bytes with `session_id=0xffff`, `token=0xffffffff`, and no
body. A persistent session sends a 24-byte signed close. Receivers also accept
the eight-byte close used by temporary authentication probes.

## Segment Routing

An SR datagram is:

```text
sr_header || inner_standard_header || inner_payload
```

The SR header is:

```text
28 | next_id | link_count | (pad_len << 3 | algorithm) | links:u32 BE[]
```

Link count is `1..6`, link IDs are `1..0x00ffffff`, and outer algorithms are
none, AES-128, and AES-256. Outbound paths reverse controller order and begin
at `next_id = link_count - 1`; returned paths use controller order and require
`next_id=0`.

Outer AES encrypts only bytes after the inner eight-byte header. It uses a raw
UTF-8 key prefix, AES-ECB-NoPadding, and zero padding recorded in the SR
header. IPv6 disables inner session encryption.

Fragmentation is available only when both encryption layers are off and
produces exactly two fragments. SR fragment IDs are little-endian. The SR
reassembler waits for gaps, ignores duplicate offsets, and rejects overlaps;
it retains at most 16 groups and 262144 bytes for two seconds.

Monitor packets use an unencrypted SR envelope, an unsigned inner echo header,
and a 40-byte body containing the traditional delay fields, `"SRID"`, a
big-endian SR ID, marker bytes, flags, and counters. The period is one second
and the peer-down threshold is five seconds.

## Managed HTTP

Managed discovery starts with `POST /lookup` against the primary lookup
service, then its fallback. Each service receives two attempts before a
seven-day cache is considered. The request uses `serviceType: "fgb"`; the
resolved service type is read from `data.type` and must be `serverlist`,
`saas`, or `controller`.

Controller domains post to the exact authentication URL returned by lookup.
The domain remains in the JSON body. `credential` selects password login and
`oidc` selects OAuth Authorization Code with PKCE S256.

Lookup, controller authentication, `/config`, and keepalive share a canonical
HMAC request with the actual method, decoded path, decoded and sorted query,
lowercase SHA-256 body digest, Unix timestamp, and lowercase 16-byte nonce.
Every retry receives a fresh timestamp, nonce, and signature.

Configuration requests use mobile API version 4 and this body shape:

```json
{
  "domain": "active-domain",
  "type": "client-platform",
  "oem_name": "panabit",
  "app_version": "compatibility-identifier",
  "device_id": "device-id",
  "userName": "optional",
  "posture_version": 7
}
```

The wire compatibility identifier currently sent in `app_version` is
`2.3.0`; it is independent of the OpeniWAN package version. Android, iOS,
macOS, and Windows use their corresponding controller platform value. Linux
and other desktop Unix targets use `android` because the controller schema
has no Linux value.

Traditional controller lines are nested under `serverlist.serverlist`; SR
groups use the mutually exclusive top-level `sites` member. Each traditional
line may carry credentials associated with its server ID. SR credentials
belong to the selected entry's ingress.

Controller `passWord` is standard Base64 containing:

```text
nonce[12] || ciphertext || tag[16]
```

The AES-256-GCM key and associated data are:

```text
key = SHA256(secret || "|" || active_domain || "|" || userName)
aad = active_domain || "|" || userName
```

The controller `app_id` selects the signing/decryption secret. The decoder
requires the exact nonce and tag sizes and authenticates the associated data.

Credential login probes ingresses, authenticates the selected line with a
temporary OPEN, and closes it. OIDC login obtains configuration and chooses
credentials by the selected server or SR ingress. Every persistent connection
then performs a fresh OPEN before creating TUN.

A posture object with a nonzero version triggers `/posture/evaluate`. Versions
encoded as integers or decimal strings are normalized. Access requires a true
local gate and an acknowledgement other than `DENY`.

Keepalive uses mobile API version 3, bearer authentication, five-second
connect/read timeouts, and one retry except after HTTP 401. Each attempt is
signed independently over the same serialized body.

## Known boundaries

The profile does not define:

- authoritative `DUP_PKT` scheduling;
- other-platform use of `NETMASK`;
- the preferred server construction of `OPEN_REJECT`;
- vendor names for SR monitor bits or marker `0x79`;
- relay-side SR path mutation;
- deployment-specific nested `/config` policy schemas;
- whether production servers require signed `CLOSE`;
- server-side duplicate suppression.

Changes in these areas require reproducible interoperability evidence and an
update to this reference.
