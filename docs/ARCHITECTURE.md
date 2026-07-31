# Architecture

This document explains OpeniWAN's component boundaries, data flow, and runtime
invariants. It is intended for contributors and library integrators.

Wire formats belong in the [Protocol Reference](PROTOCOL.md), operator policy
in [Configuration](CONFIGURATION.md), managed HTTP behavior in
[Managed Connections](MANAGED_CONNECTIONS.md), and the attacker model in the
[Security Policy](../SECURITY.md).

## Design principles

- Keep packet encoding independent of the CLI and platform networking.
- Validate external input before allocating resources or changing state.
- Normalize deployment policy before it enters the session runtime.
- Represent routes, DNS settings, interfaces, and workers with scoped owners.
- Keep credentials and controller-provided secrets out of profile state.

## Runtime overview

```text
direct ClientConfig + credentials ----+
                                      +--> Client::authenticate
managed DomainClient                  |            |
    -> lookup and authentication      |      ConnectedSession
    -> policy and line selection      |            |
    -> PreparedConnection ------------+      PacketDevice
                                                   |
                               +-------------------+------------------+
                               |                                      |
                         DnsPacketDevice                        channel device
                               |                                      |
                            native TUN                       userspace TCP/IP
                               |                                      |
                         routes and DNS                     fixed-target forward
```

The CLI composes the complete graph. A library can provide its own
`PacketDevice`, use `Client` without platform integration, or stop at a
managed `PreparedConnection`.

## Component ownership

| Component | Owns |
|---|---|
| `protocol` | Standard headers, packet classes, control signatures, TLVs, OPEN, heartbeat, ping, and close encoding |
| `crypto` | iWAN-compatible text conversion, password wrapping, session ciphers, and key material |
| `fragment` | Bounded traditional and Segment Routing reassembly |
| `sr` | SR envelopes, outer encryption, packet planning, decoding, and monitor state |
| `client` | UDP authentication, session tuple checks, workers, reconnect, and shutdown |
| `managed` | Domain lookup, controller authentication and policy, posture, line selection, and prepared credentials |
| `dns` | Effective DNS policy, packet handling, physical relay, and platform DNS leases |
| `tun` | Native packet I/O and transactional route changes |
| `src/bin/openiwan/forward.rs` | Route-free userspace TCP/IP forwarding |
| `src/bin/openiwan/http_forward.rs` | Fixed-origin HTTP proxying and upstream TLS |
| `src/bin/openiwan/state.rs` | Versioned, non-secret profile state |
| `src/bin/openiwan/credentials.rs` | Operating-system credential storage |

The wire modules have no CLI dependency. The `client` layer depends on the
wire modules and the `PacketDevice` trait, while managed controller data is
validated and normalized before a direct `Client` is constructed. Platform
commands and persistent state remain at the outer layers.

## Direct session lifecycle

`ClientConfig` holds data-plane settings. `Client` owns credentials separately
and zeroizes them when dropped.

Authentication proceeds as follows:

1. Validate the configuration, resolve one peer, and connect a UDP socket.
2. Build one OPEN with a random nonzero nonce and resend the same bytes within
   the authentication budget.
3. Accept a response only after validating framing, control signature, packet
   class, TLVs, and the returned nonce when present.
4. Adopt the returned session ID and token as the active tuple, derive the
   session cipher, and return a `ConnectedSession` that owns that state.

Authentication uses a three-second attempt window, a 13-second overall
budget, and one-second retry spacing. A traditional session sends heartbeat
requests every two seconds and ends after ten misses or 20 seconds without a
valid response. When enabled, SR monitoring runs once per second and marks the
peer down after five seconds. These fixed timers are owned by the protocol
runtime.

`ConnectedSession::run` activates its `PacketDevice`, starts the sender and
protocol workers, runs receive processing, joins every worker, and deactivates
the device. Reconnection creates a new authenticated session and repeats the
activation hooks, allowing DNS and other decorators to refresh per-session
state.

## Data-plane invariants

### Traditional sessions

The sender validates inner IPv4 or IPv6 packets against the negotiated MTU.
Malformed or oversized inputs are logged and dropped; valid input is emitted
as one traditional datagram. The receiver validates data, fragments,
heartbeat, and close packets against the active tuple before dispatch.

Traditional reassembly is deliberately small and short-lived: at most 256
groups are retained for 100 milliseconds. Exact packet forms and reassembly
semantics are specified in the [Protocol Reference](PROTOCOL.md).

### Segment Routing sessions

`SegmentRoutingConfig` adds the logical forward path, selected SR identifier,
optional monitor, and outer cipher. The selected ingress remains the UDP peer;
an entry's `ip` field is retained as controller metadata.

The SR planner enforces valid nonzero link identifiers, the configured path
direction, MTU accounting, and the supported combinations of inner and outer
encryption. Its fragmentation path emits the defined two-fragment form and
uses an offset-aware reassembler bounded to 16 groups and 262144 bytes for two
seconds. Monitor traffic has independent state from traditional heartbeat
tracking.

## Managed boundary

The managed layer turns a customer domain and authentication result into a
`PreparedConnection`. It owns lookup, controller requests, posture and device
gates, ingress probing, controller credential decoding, and SR normalization.
The result contains one selected ingress plus the normalized policy needed by
the CLI and library caller.

Each call to `PreparedConnection::client()` rechecks the device-binding gate
and creates a fresh direct client. Credential login uses a temporary OPEN to
verify the selected credentials, closes that probe, and leaves the persistent
OPEN to the fresh client. OIDC login prepares credentials from controller
configuration; its fresh client performs the connection's OPEN.

See [Managed Connections](MANAGED_CONNECTIONS.md) for the state machine and
integration contract.

## Packet devices and host networking

`PacketDevice` separates session processing from packet transport. Its
`activate_session` and `deactivate_session` hooks bracket every authenticated
session; `read_packet` and `write_packet` exchange complete IP packets.

`TunDevice` implements the trait with the `tun` crate. `RouteGuard` applies a
canonical route plan and records enough prior state to reverse its own work.
Full-tunnel plans subtract the active peer, known managed ingresses, loopback,
multicast, and link-local destinations so the UDP transport stays outside the
TUN. Platform-specific route behavior is documented in
[Configuration](CONFIGURATION.md#routing).

`DnsPacketDevice` decorates another device. Activation combines controller,
profile, command-line, and OPEN_ACK inputs into an immutable
`EffectiveDnsPolicy`; deactivation stops packet processing and restores the
platform DNS lease.

```text
policy sources + OPEN_ACK -> EffectiveDnsPolicy
                              +-> platform lease
                              +-> packet engine -> physical DNS relay
```

The packet engine and relay validate requests and replies, bound concurrency,
and tag work with a session generation so replies from an old session cannot
enter a new one. Detailed selection and split-DNS rules live in
[Configuration](CONFIGURATION.md#dns-policy).

## Route-free forwarding

With the `forward` feature, bounded channels implement `PacketDevice` for a
userspace TCP/IP stack. Raw TCP and HTTP(S) forwarding share that stack and
connect to one fixed target. This path reuses direct or managed authentication
without acquiring a TUN, routes, or a platform DNS lease.

## State and secret ownership

| Storage | Contents |
|---|---|
| `profiles.toml` | Device ID, profile metadata, stable line preference, local policy overrides, and opaque credential references |
| OS credential service | Saved passwords and OIDC refresh tokens |
| lookup cache | Time-bounded lookup responses used after a live lookup failure |
| process memory | Access tokens, controller configuration, generated ingress credentials, and SR keys |

Profile updates use an inter-process lock and atomic replacement. Changes to
the domain, Device ID, or username invalidate the associated credential
reference. Permissions and platform storage locations are specified in
[Configuration](CONFIGURATION.md#profiles-and-local-state).

## Concurrency and cleanup

Session workers report failure through a channel and share an atomic shutdown
flag. Every spawned worker is joined before the session returns. Line probes,
DNS relay work, fragment state, forwarding connections, retries, and queues
all have explicit bounds.

Host resources are acquired through guards in the order TUN, routes, DNS
runtime and lease, then session workers. A setup failure drops resources
already acquired. Normal shutdown first stops session and packet workers,
then restores DNS and routes. Process termination and operating-system
failures remain recovery cases covered by the
[Security Policy](../SECURITY.md#host-networking).

## Trust boundaries

Network datagrams, controller JSON, OIDC callbacks, DNS replies, configuration
files, profile files, and cached lookup responses are treated as untrusted.
Lengths and types are checked before field access; algorithms, tuples, paths,
and identifiers are checked against active state before dispatch or mutation.

Resource limits constrain fragments, workers, relay requests, DNS traversal,
and forwarding connections. Secret-owning types redact debug output, and
platform commands receive separate arguments. These controls protect the
implementation while the protocol's cryptographic guarantees remain those
described in the [Security Policy](../SECURITY.md#security-model).
