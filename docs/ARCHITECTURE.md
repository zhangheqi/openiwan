# Architecture

This document describes the component boundaries and runtime invariants of
the current `main` branch. It is intended for contributors and library
integrators; wire details belong in [Protocol Reference](PROTOCOL.md).

## Design goals

OpeniWAN is organized around five goals:

1. keep wire-protocol code independent of the CLI and native TUN;
2. validate untrusted bytes before allocation or state changes;
3. keep deployment policy outside the stable protocol core;
4. make route, DNS, interface, and worker cleanup transactional;
5. keep credentials and controller-provided secrets out of persistent profile
   state.

Non-goals include server implementation, vendor certification, TLS
interception, and adding cryptographic guarantees absent from iWAN.

## System map

```text
CLI or library caller
        |
        +--> direct ClientConfig -------------------+
        |                                           |
        +--> managed DomainClient                    |
               |                                    |
               +-- lookup/auth/config/posture       |
               +-- line selection and credentials   |
               +-- PreparedConnection --------------+
                                                    |
                                              Client::authenticate
                                                    |
                                             ConnectedSession
                                                    |
                              +---------------------+--------------------+
                              |                                          |
                        native TUN                                 forward stack
                              |                                          |
                       DnsPacketDevice                            channel PacketDevice
                              |                                          |
                     routes + DNS lease                         userspace TCP/IP
```

The CLI in `src/bin/openiwan.rs` composes these layers. Library users can stop
at any lower boundary.

## Module boundaries

| Module | Responsibility |
|---|---|
| `protocol` | Standard packet registry, eight-byte header, control signatures, TLVs, OPEN, heartbeat, ping, and close |
| `crypto` | Java US-ASCII conversion, password wrapping, session keys, XOR, and AES-128-ECB |
| `fragment` | Separate traditional and Segment Routing fragment parsing and bounded reassembly |
| `sr` | Directional SR headers, outer AES, data planning, decoding, and monitor state |
| `client` | UDP authentication, tuple validation, session workers, reconnect, and shutdown |
| `managed` | Domain lookup, authentication, controller policy, posture, lines, credentials, and keepalive |
| `dns` | Typed policy resolution, packet enforcement, physical relay, and platform DNS leases |
| `tun` | Native packet device and transactional route integration |
| `src/bin/openiwan/forward.rs` | Userspace TCP/IP and raw TCP forwarding |
| `src/bin/openiwan/http_forward.rs` | Fixed-origin HTTP/1.1 proxy and upstream TLS |
| `src/bin/openiwan/state.rs` | Versioned non-secret profile state |
| `src/bin/openiwan/credentials.rs` | Operating-system credential storage |

Wire modules do not depend on the CLI. Managed controller payloads are
normalized before entering the direct client runtime.

## Direct session lifecycle

`ClientConfig` contains data-plane settings. Credentials are passed separately
to `Client::new` and are zeroized with their owner.

Authentication:

1. resolve and connect one UDP socket to the configured peer;
2. construct one OPEN packet with a random nonzero nonce;
3. resend the byte-identical packet within the protocol retry window;
4. validate OPEN_ACK or OPEN_REJECT framing, tuple, TLVs, and nonce;
5. derive the session cipher and return `ConnectedSession`.

The connected UDP socket enforces the peer address. Session processing also
validates packet type, encryption marker, session ID, token, inner IP length,
and Segment Routing path where applicable.

`ConnectedSession::run` calls `PacketDevice::activate_session`, starts the
workers, runs the receiver, joins workers, and calls
`PacketDevice::deactivate_session`. Device lifecycle hooks allow DNS and other
decorators to update policy on every reconnect without coupling them to the
client.

## Traditional data plane

The traditional session uses:

1. a sender that validates complete IPv4 or IPv6 packets and encapsulates one
   datagram;
2. a receiver that validates standard data, fragments, heartbeat, and close;
3. a 20-byte little-endian heartbeat worker.

Authentication attempts use a three-second attempt timeout and 13-second
overall window. Heartbeats run every two seconds; ten misses or more than 20
seconds without a valid response ends the session. These values are protocol
behavior, not deployment settings.

The traditional transmit path does not generate fragments. Packets larger than
the negotiated MTU fail encapsulation instead of relying on unspecified
fragment behavior.

## Segment Routing data plane

`SegmentRoutingConfig` adds a logical forward path, selected SR ID, optional
monitor, and outer-algorithm/key pair. OPEN carries the first logical link.

Outbound serialization reverses the logical path. Returned datagrams must use
logical order, `next_id=0`, the active session tuple, and the configured outer
algorithm. `SREntry.ip` is controller metadata and is not used as the ingress
endpoint.

The planner enforces:

- one to six nonzero 24-bit links;
- IPv6 without inner session encryption;
- no inner AES expansion;
- encrypted payloads fitting one MTU;
- fragmentation only when inner and outer encryption are both off;
- exactly two fragments with the SR-specific offset-aware reassembler.

The optional monitor runs every second and marks the peer down after five
seconds. Monitor request and response state is separate from traditional
heartbeat tracking.

## Managed connection boundary

The `managed` feature performs:

1. primary/fallback domain lookup with exact validation and a seven-day cache;
2. signed controller authentication and credential/OIDC selection;
3. controller configuration, posture, and device-binding evaluation;
4. traditional server or SR-group normalization;
5. bounded ingress probing and stable line selection;
6. one temporary authentication OPEN;
7. construction of a fresh direct `Client` for the persistent OPEN.

The temporary OPEN proves the selected credentials and ends with a
header-only close. The persistent tunnel always uses a second OPEN on a new
client.

Controller responses remain untrusted. Stable outer fields are typed; unknown
deployment-specific nested policy remains available as JSON. Traditional
`serverlist` and SR `sites` payloads are mutually exclusive.

See [Managed Connections](MANAGED_CONNECTIONS.md) for request and policy
contracts.

## Routing and TUN

`TunDevice` implements `PacketDevice` through the `tun` crate. `RouteGuard`
applies canonical route changes and owns enough prior state to restore them in
reverse order.

Managed `all`, `ipfilter`, and `custom` policy becomes a list of CIDR
differences. The active peer, known ingresses, loopback, multicast, and
link-local addresses stay outside TUN, preventing the transport socket from
routing into itself.

Because the NETMASK TLV is not applied to the active session, host integration
uses host prefixes (`/32` for IPv4 and `/128` for IPv6).

## DNS subsystem

`dns::policy` converts controller, profile, CLI, and OPEN_ACK inputs into one
immutable `EffectiveDnsPolicy`:

```text
controller and service defaults <- profile <- one-shot CLI
                     + OPEN_ACK DNS
                            |
                   EffectiveDnsPolicy
             +--------------+---------------+
             |              |               |
      platform DNS lease  packet engine  userspace resolver
                            |
                    physical DNS relay
```

`DnsPacketDevice` decorates another packet device. Activation recomputes the
effective policy from the new session; deactivation stops the engine and
restores the platform lease.

The packet engine handles visible unfragmented IPv4 DNS traffic. Queries pass
to the tunnel, receive a synthetic response, or relay through sockets bound
outside TUN. The relay bounds concurrency, rewrites transaction IDs, validates
responses, retries servers, and retries truncated UDP over TCP. A session
generation invalidates obsolete replies.

Platform leases use systemd-resolved with a `resolvconf` fallback on Linux, a
scoped SystemConfiguration entry on macOS, and IP Helper APIs on Windows.
Physical resolvers are captured before changing link DNS.

## Route-free forwarding

The optional `forward` feature implements `PacketDevice` with bounded
in-memory channels connected to a userspace TCP/IP stack.

Raw TCP copies bytes between a loopback socket and one fixed userspace TCP
target. HTTP(S) uses the same connector beneath an HTTP/1.1 fixed-origin proxy.
Target parsing, DNS policy, connection capacity, timeouts, HTTP header
rewriting, and upstream TLS remain outside the core session runtime.

Direct and managed authentication therefore share one forwarding data plane.
No platform route or DNS lease is installed.

## Persistent state boundaries

Profile state and controller state are deliberately separate.

`profiles.toml` contains the installation Device ID, profile metadata, stable
line preference, DNS overrides, and opaque credential references. It uses an
inter-process lock and atomic replacement. It never stores controller payloads,
generated ingress passwords, access/refresh tokens, or SR keys.

Saved passwords and refresh tokens live in the operating-system credential
service. Profile changes to domain, Device ID, or username invalidate the
associated credential reference.

Lookup cache entries contain discovery metadata only and expire after seven
days. Controller configurations and decrypted runtime credentials remain in
memory.

## Concurrency and cleanup

Session workers communicate failures through bounded ownership and a channel;
an atomic flag coordinates shutdown. Every spawned worker is joined before
the session returns.

Line probing has a fixed worker bound. DNS relay concurrency, fragment groups,
fragment bytes, CNAME depth, forwarding connections, retries, and timeouts are
all bounded.

Host state is acquired in an order that permits reverse cleanup:

```text
TUN -> routes -> DNS runtime/lease -> session workers
```

Setup failure drops already-acquired guards. Normal shutdown stops workers and
packet processing before restoring DNS and routes.

## Trust boundaries

- Network datagrams, controller JSON, OIDC callbacks, DNS replies, config
  files, profile files, and password files are untrusted input.
- Packet lengths are checked before field access.
- Cryptographic algorithm, tuple, path, and ID selections are checked against
  active state.
- Traditional fragments retain at most 256 groups for 100 ms.
- SR fragments retain at most 16 groups and 262144 bytes for two seconds.
- Debug output redacts credential and key owners.
- Platform commands receive separate arguments rather than interpolated shell
  strings.

These invariants limit implementation risk. They do not add confidentiality,
integrity, replay protection, or identity guarantees missing from the
underlying protocol. See [Security Policy](../SECURITY.md).
