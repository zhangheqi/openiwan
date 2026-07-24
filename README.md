# openiwan

An independent, open-source Rust implementation of the iWAN client protocol.

[English](README.md) | [简体中文](README.zh-CN.md)

`openiwan` provides a protocol library and command-line client for the
traditional single-path UDP data plane observed in the macOS iWAN client
`2.3.0 (230)`.

> [!IMPORTANT]
> This project is not affiliated with or endorsed by Panabit or the University
> of Science and Technology of China. It is an interoperability project, not an
> official specification or vendor-certified client.

## Features

- OPEN, OPENACK, and OPENREJECT authentication with AUTH_VERIFY correlation
- Plaintext, repeating XOR, and legacy AES-128-ECB data modes
- IPv4, IPv6, heartbeat, CLOSE, bounded reconnection, and fragment reassembly
- Native Linux `/dev/net/tun` and macOS `utun` support
- A route-free local HTTP to internal HTTPS reverse proxy with no TUN device
- Strict packet validation, bounded fragment queues, route cleanup, and
  credential zeroization
- Config-driven OIDC/JWKS login and controller-managed line discovery
- A reusable Rust library plus `ping`, `auth`, `connect`, `decode`, and
  `managed` commands

## Status

| Capability | Status |
|---|---|
| Traditional single-path authentication and UDP tunnel | Implemented |
| Plaintext and XOR data plane | Implemented |
| Legacy AES-128 data plane | Implemented; real-server validation required |
| IPv4 and IPv6 | Implemented |
| IPFRAG and IPFRAG6 receive-side reassembly | Implemented |
| Heartbeat, CLOSE, failure detection, and reconnection | Implemented |
| Route-free local HTTP to HTTPS reverse proxy | Implemented; fixed HTTP/1.1 upstream |
| Config-driven OIDC and compatible Panabit controller flows | Implemented |
| USTC managed login profile | Example included; authorized live validation required |
| SEGRT/SR multipath | Recognized and safely discarded; not implemented |
| `serve` userspace DNS (UDP, TCP fallback, TTL cache) | Implemented |

Production-oriented here means that the implementation has defensive parsing,
resource limits, explicit error handling, credential hygiene, cleanup logic,
tests, and CI. It does not mean that the project has passed vendor
certification. Validate every deployment against an authorized test endpoint.

## Build

The minimum supported Rust version is 1.85.

```bash
cargo build --release
```

Run the project checks with:

```bash
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

Creating and configuring a TUN interface normally requires root or equivalent
network privileges. The userspace `serve` path creates no network interface and
does not require elevated privileges.

## Usage

Probe an iWAN UDP endpoint:

```bash
openiwan ping --server 192.0.2.10:6001
```

Authenticate without changing the host network:

```bash
openiwan auth \
  --server 192.0.2.10:6001 \
  --username alice \
  --encryption xor
```

If `OPENIWAN_PASSWORD` is unset, the client reads the password from `/dev/tty`
without echoing it. Do not pass passwords directly on the command line.

Create a tunnel for explicit destination prefixes:

```bash
sudo openiwan connect \
  --server 192.0.2.10:6001 \
  --username alice \
  --encryption xor \
  --route 10.0.0.0/8 \
  --route 2001:db8::/32
```

`--route` accepts CIDRs, `--route-ip` creates host routes, and `--route-domain`
resolves a domain once before connecting. Values are passed to platform tools
as separate arguments, never through a shell. The client rejects default
routes and any route containing the active iWAN endpoint.

### Access an HTTPS API without changing host routes

Expose one fixed organization HTTPS origin on a loopback-only HTTP listener:

```bash
openiwan serve \
  --server 192.0.2.10:6001 \
  --username alice \
  --encryption xor \
  --upstream https://api.example.edu \
  --listen 127.0.0.1:8080
```

A local request for `http://127.0.0.1:8080/v1/profile?full=true` is sent through
the iWAN userspace TCP/IP stack to
`https://api.example.edu/v1/profile?full=true`. Methods, queries, streaming
bodies, and end-to-end headers such as `Authorization` are preserved. HTTPS
Host, SNI, and certificate verification continue to use the original upstream
name.

`serve` opens no TUN device, invokes no platform route command, and has no route
options. The listener must be a loopback address, and the upstream must be an
HTTPS origin without a path, query, or user information. System roots are used
by default; repeat `--ca-cert organization-ca.pem` to add private roots.

The default `--dns-mode auto` first queries organization resolvers advertised
by OPENACK or configured by the managed provider through the iWAN userspace
stack. It validates transactions and responses, follows CNAMEs, caches by TTL,
and retries truncated UDP responses over DNS-over-TCP. Shadowrocket cannot see
that inner DNS query or replace the answer with a Fake-IP. The USTC provider
includes its campus resolver; reinstall an older local copy or add this
top-level setting:

```toml
dns_servers = ["202.38.64.1"]
```

Manual mode and temporary overrides can pass `--dns-server 202.38.64.1`.
`--dns-mode iwan` requires an iWAN resolver. `auto` uses host DNS only when no
iWAN resolver is available; failure of a configured organization resolver is
fail-closed and does not leak the hostname to the host resolver. Host answers
in `198.18.0.0/15` are rejected instead of causing a useless TCP timeout.
`--upstream-ip` remains available as an emergency operator override, but normal
production use does not require pre-resolving API addresses.

### Managed login and connection

Managed providers are external TOML files so the authentication and controller
parameters can be updated without recompiling. Install the included USTC
example as a protected file:

```bash
install -d -m 700 "$HOME/.config/openiwan/providers"
install -m 600 examples/providers/ustc.toml \
  "$HOME/.config/openiwan/providers/ustc.toml"
```

Fetch and list encrypted line configuration without elevated privileges:

```bash
openiwan managed \
  --provider "$HOME/.config/openiwan/providers/ustc.toml" fetch
openiwan managed \
  --provider "$HOME/.config/openiwan/providers/ustc.toml" list
```

Select a line and connect:

```bash
sudo openiwan managed \
  --provider "$HOME/.config/openiwan/providers/ustc.toml" \
  connect --route-domain example.edu --route 10.0.0.0/8
```

Use `all` in place of `fetch` or `connect` to perform the complete flow. The
access token and decrypted line password are never written to disk. See
[Managed Providers](docs/MANAGED_PROVIDERS.md) for the provider schema, state
layout, and security model.

An existing managed line can run the route-free proxy as well:

```bash
openiwan managed \
  --provider "$HOME/.config/openiwan/providers/ustc.toml" \
  serve --line-index 1 --upstream https://api.example.edu
```

Configuration can also be loaded from TOML:

```toml
server = "192.0.2.10:6001"
mtu = 1400
encryption = "xor"
auth_timeout_ms = 3000
auth_attempts = 3
require_auth_verify_echo = true
xor_key_bytes = 16
heartbeat_interval_ms = 5000
heartbeat_timeout_ms = 30000
receive_poll_ms = 250

[reconnect]
attempts = 10
initial_delay_ms = 1000
max_delay_ms = 30000
```

```bash
openiwan auth --config openiwan.toml --username alice
```

Use `openiwan --help` or `openiwan <command> --help` for the complete CLI
reference.

## Library

Packet and TLV codecs live in `openiwan::protocol`; compatibility cryptography
lives in `openiwan::crypto`. Applications that already own a TUN device,
virtual interface, or userspace IP stack can implement `PacketDevice` and use
`Client::authenticate`, `ConnectedSession::run`, or the bounded reconnect
helpers. The default `managed` Cargo feature exposes typed provider, OIDC,
controller, and encrypted-state APIs; disable default features for a
protocol-only dependency.

The public API documentation can be built locally with `cargo doc --open`.

## Documentation

- [Documentation index](docs/README.md)
- [Wire protocol reference](docs/IWAN_PROTOCOL_2_3_0.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Managed providers](docs/MANAGED_PROVIDERS.md)
- [Reverse-engineering evidence and limitations](docs/REVERSE_ENGINEERING.md)
- [Security policy](SECURITY.md)

All technical and community documentation is maintained in English. Translated
README files are welcome when they remain faithful to this canonical README.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.
By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

Security issues should be reported according to [SECURITY.md](SECURITY.md), not
through a public issue.

## Security

The traditional iWAN data plane uses MD5, repeating XOR, or AES-ECB. Its control
signature is not a modern message authentication code. These mechanisms exist
for compatibility and do not provide the confidentiality, integrity, forward
secrecy, or peer authentication expected from a modern VPN protocol.

Use `openiwan` only on authorized networks, preferably inside an additional
trusted security layer, and choose a stronger protocol when the endpoint
supports one.

## License

`openiwan` is available under the [MIT License](LICENSE).
