# Architecture

`openiwan` separates wire compatibility, session state, and host networking so
that protocol code can be tested without privileged access to a TUN device.

## Scope

The data-plane compatibility target is the traditional single-path UDP protocol
observed in macOS iWAN client `2.3.0 (230)`. The optional managed layer supports
configuration-driven OIDC providers and the compatible Panabit mobile
controller flow. It does not claim compatibility with controllers that use a
different signing, response, or password-wrapping scheme. DNS relay, operating
system policy management, and SEGRT/SR multipath remain outside the boundary.

## Crate Layout

| Module | Responsibility |
|---|---|
| `protocol` | Packet headers, packet types, TLVs, signatures, and control-packet builders |
| `crypto` | Legacy password wrapping and data-plane compatibility ciphers |
| `client` | Authentication, session validation, heartbeat, packet exchange, and reconnection |
| `fragment` | Strict fragment parsing, bounded reassembly, and inner IP validation |
| `config` | Serializable client and reconnect configuration |
| `managed` | Provider validation, OIDC/JWKS, controller signing, encrypted line state |
| `tun` | Linux TUN, macOS utun, interface configuration, routes, and cleanup |
| `error` | Public error model |
| `bin/openiwan` | CLI, secret input, signals, logging, and command dispatch |

The `PacketDevice` trait is the boundary between protocol/session logic and a
TUN interface or userspace IP stack.

## Managed Provider Lifecycle

The default-enabled `managed` feature keeps organization parameters outside the
binary in a protected provider TOML file. A managed fetch:

1. loads and validates the provider and its file permissions
2. performs OIDC discovery and creates a PKCE S256 request with state and nonce
3. validates the callback, exchanges the code, and verifies the ID token through
   the advertised JWKS
4. signs the exact controller request bytes and calls auth, keepalive, and config
5. atomically stores only the encrypted line records

At connect time, only the selected line password is authenticated and decrypted.
It is passed directly into the normal `Client` lifecycle and zeroized on drop.
OAuth tokens and plaintext line passwords are never persisted.

## Session Lifecycle

```mermaid
sequenceDiagram
    participant CLI as Caller
    participant Client
    participant Server as iWAN endpoint
    participant Device as PacketDevice

    CLI->>Client: authenticate()
    Client->>Server: OPEN + TLVs + AUTH_VERIFY
    Server-->>Client: OPENACK or OPENREJECT
    Client->>Client: verify signature, nonce, session, and configuration
    Client-->>CLI: ConnectedSession + SessionInfo
    CLI->>Device: configure address, MTU, and explicit routes
    CLI->>Client: run_reconnecting_from(session, device)
    loop Connected session
        Device-->>Client: outbound IP packet
        Client->>Server: DATA or DATAENC
        Server-->>Client: DATA, DATAENC, or fragments
        Client->>Device: validated inner IP packet
        Client->>Server: echoRequest
        Server-->>Client: echoResponse
    end
    Client->>Server: CLOSE
    CLI->>Device: remove routes and close interface
```

## Authentication

`Client::authenticate` resolves one UDP endpoint, creates a connected UDP
socket, builds OPEN, and retries within the configured authentication budget.
Every response passes through the strict control-packet decoder before the
client accepts OPENACK.

OPENACK validation includes:

- a valid control signature
- a nonzero session ID
- a matching AUTH_VERIFY nonce when present, with provider-controlled handling
  for deployments known to omit the echo
- consistency between requested, header, and advertised encryption
- bounded MTU and correctly sized address attributes

Credentials are owned by `Client`, redacted from `Debug`, and zeroized on drop.
Session cipher keys are also zeroized on drop.

## Data Plane

The session uses:

- one receive loop for UDP datagrams
- one worker for packets read from `PacketDevice`
- one heartbeat worker

The UDP socket is connected to the selected endpoint. Stateful packets must
match the active session ID and token. Malformed or unrelated datagrams are
dropped; device and socket failures terminate the session.

IPv4 and IPv6 fragments use separate bounded reassembly queues. Reassembled or
decrypted packets are checked against their inner IP length before delivery.

## Reconnection

Transient transport and heartbeat failures use bounded exponential backoff.
The native TUN path compares the address, gateway, netmask, and MTU from every
new OPENACK with the original assignment. It stops if the assignment changes,
rather than continuing with stale host configuration.

A session that remains healthy for at least one heartbeat timeout resets the
consecutive-failure budget.

## Host Networking

`TunDevice` implements native Linux and macOS packet framing. `RouteGuard`
configures the interface and explicit routes, then removes them on drop,
including rollback after partial configuration.

CIDR, IP, and one-time domain targets share one resolver. It rejects invalid
targets, default routes, duplicates, and routes that would contain the active
iWAN endpoint before changing the host network.

Default routes are intentionally rejected. A future full-tunnel implementation
must first pin the control endpoint to the physical uplink and provide
platform-specific route restoration.

## Trust Boundaries

The project assumes that:

- callers provide authorized endpoint and credential data
- `PacketDevice` implementations use nonblocking reads
- system networking tools are trusted platform components

The project does not assume that UDP bodies are well formed. All lengths,
types, session fields, fragments, and inner IP packets are validated before
use.

Legacy iWAN cryptography does not authenticate data packets. Defensive parsing
limits implementation risk but cannot add security properties absent from the
wire protocol.

## Extending the Protocol

Protocol changes should begin with a synthetic test and documented evidence.
Keep unverified behavior behind an explicit compatibility boundary. SEGRT
support, in particular, requires authorized bidirectional interoperability data
and must not be inferred solely from type names or isolated constants.
