# Architecture

OpeniWAN separates wire-protocol behavior from host integration.

```text
ClientConfig
    -> OPEN authentication
    -> ConnectedSession
       -> PacketDevice::activate_session
       -> traditional DATA/heartbeat
       -> or SR envelope/data/monitor
    -> PacketDevice
       -> DnsPacketDevice -> native TUN
       -> or userspace forwarding stack
```

## Protocol modules

- `protocol.rs` owns the standard packet registry, eight-byte header, control
  signature, TLVs, OPEN construction, heartbeat, ping, and close.
- `crypto.rs` owns Java US-ASCII conversion, MD5 key derivation, password
  wrapping, 8-byte repeating XOR, and AES-128-ECB.
- `fragment.rs` keeps the intentionally different traditional and SR fragment
  ID endianness and reassembly algorithms separate.
- `sr.rs` owns directional SR headers, outer AES, normal/fragment planning,
  returned-path validation, inner decoding, and the monitor state machine.
- `client.rs` owns UDP authentication, tuple validation, session workers,
  reconnect policy, TUN packet delivery, and shutdown.

Protocol timing such as the 3-second authentication attempt, 13-second overall
window, 2-second traditional heartbeat, and 1-second SR monitor is kept as
protocol behavior rather than deployment configuration.

## Traditional session

Authentication sends one byte-identical OPEN repeatedly within the protocol
retry window. A present AUTH_VERIFY must match; omission is accepted. OPEN_ACK
selects the tuple, encryption, MTU, IPv4 address, DNS, and gateway.

The connected session runs:

1. a packet sender that validates IP lengths and encapsulates one packet;
2. a receiver that validates the UDP peer through the connected socket,
   session tuple, packet class, encryption, fragments, and inner IP length;
3. a 20-byte little-endian heartbeat worker.

The traditional outbound path does not generate fragments. It reports an
oversized TUN packet instead.

## Segment Routing session

SR configuration adds a logical forward path, SR ID, optional monitor, and
outer-algorithm/key pair. OPEN carries the first logical link. `SREntry.ip`
remains serializer metadata and is not used as the ingress endpoint.

Outbound SR serialization reverses the logical path. Returned datagrams must
use the logical order, `next_id=0`, the active tuple, and the configured outer
algorithm. IPv6 uses `DATA_IPV6` without inner session encryption.

The planner enforces protocol constraints: encrypted packets must fit one
payload MTU; inner AES cannot expand; fragments require both encryption layers
off and consist of exactly two datagrams.

## Managed boundary

The `managed` feature contains:

- primary/fallback lookup, exact domain validation, retries,
  canonical-domain handling, the seven-day lookup cache, and platform HMAC
  authentication;
- the exact lookup-provided controller auth endpoint, controller-app-ID
  signing, credential/OIDC selection, and exact generated-credential
  decryption;
- controller-configured OIDC Authorization Code + PKCE;
- the `/config` request and typed outer server, credential, DNS,
  posture, device-binding, routing, IP/domain-filter, and SR-group members;
- best-ingress UDP probing, the temporary credential-login OPEN, and creation
  of a client that performs the persistent second OPEN;
- stable traditional-server and SR-group line preferences plus bounded
  concurrent reachability probing;
- the complete HTTP keepalive model and shared mobile-API signer.

Managed connection turns the `all`, `ipfilter`, or `custom` setting
into a platform route transaction. CIDR subtraction preserves exclusive
networks and every known ingress outside the TUN, preventing the persistent
UDP socket from routing into itself.

## DNS subsystem

`dns::policy` parses controller, profile, CLI, and OPEN_ACK inputs into one
immutable `EffectiveDnsPolicy`. Controller wire strings do not cross this
boundary. `DnsPacketDevice` decorates the native TUN and is activated for the
initial session and each reconnect:

```text
controller/App defaults <- profile <- one-shot CLI
                  + OPEN_ACK DNS
                         |
                EffectiveDnsPolicy
          +--------------+---------------+
          |              |               |
 platform DNS lease  packet engine  userspace resolver
                         |
                 protected physical relay
```

The engine handles unfragmented IPv4. UDP/53 queries are either passed to the
tunnel, answered synthetically, or relayed over a physical-interface-bound
socket. It returns empty NOERROR for AAAA, NXDOMAIN for blocked DoH hostnames,
and drops visible TCP/UDP 853 when blocking is enabled. The relay bounds
concurrency, rewrites transaction IDs, validates replies, retries servers,
and falls back from truncated UDP to TCP. Session changes reset its generation
so obsolete replies cannot be injected.

Platform DNS uses a link-scoped RAII lease: systemd-resolved with a
`resolvconf` fallback on Linux, a scoped SystemConfiguration entry on macOS,
and IP Helper DNS APIs on Windows. Physical resolvers are captured before the
lease is installed. Session teardown stops the packet engine and relay workers
before restoring DNS and routes.

Unknown nested policy fields remain `serde_json::Value`. Traditional
top-level `serverlist` and SR `sites` are mutually exclusive.

The CLI state boundary is separate from controller configuration. It persists
an automatically generated installation Device ID, non-secret profile
metadata, and a stable line preference. Controller payloads can contain
generated passwords and SR keys, so they are intentionally kept in memory and
never serialized into the profile store. State updates use an inter-process
lock and atomic replacement.

Saved authentication is a separate boundary implemented by
`src/bin/openiwan/credentials.rs`. Passwords and OIDC refresh tokens are
versioned, redacted, zeroized after use, and stored through the operating
system credential service. OIDC access tokens are freshly obtained with a
refresh-token grant and remain in memory. Profile changes that alter the
domain, device ID, or username invalidate the associated saved
authentication.

## Packet devices

`PacketDevice` is the data-plane boundary. Its session lifecycle callbacks
allow decorators to refresh state on reconnect. `TunDevice` implements it
with the `tun` crate and host route management. `DnsPacketDevice` provides the
TUN DNS behavior without coupling it to native interface creation. The optional `forward` feature
implements it with bounded in-memory channels and a userspace TCP/IP stack.
Both direct and managed authentication feed the same forward data plane.

Because NETMASK is not applied to the active session, host integration uses
host prefixes (`/32` for IPv4 and `/128` for IPv6).

## Resource and trust boundaries

- standard and SR packet lengths are checked before field access;
- packet type, encryption, tuple, SR path, algorithm, and SR ID are validated;
- traditional fragment state is bounded to 256 groups and 100 ms;
- SR state is bounded to 16 groups, 262144 bytes, and two seconds;
- credentials and cryptographic key owners zeroize secrets on drop;
- debug output redacts credentials, app secrets, authorization headers, and SR
  keys.

These checks protect the implementation. They do not add integrity,
confidentiality, or replay protection absent from the wire protocol.
