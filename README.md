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
- Strict packet validation, bounded fragment queues, route cleanup, and
  credential zeroization
- A reusable Rust library plus `ping`, `auth`, `connect`, and `decode` commands

## Status

| Capability | Status |
|---|---|
| Traditional single-path authentication and UDP tunnel | Implemented |
| Plaintext and XOR data plane | Implemented |
| Legacy AES-128 data plane | Implemented; real-server validation required |
| IPv4 and IPv6 | Implemented |
| IPFRAG and IPFRAG6 receive-side reassembly | Implemented |
| Heartbeat, CLOSE, failure detection, and reconnection | Implemented |
| Controller and organization-specific OIDC flows | Out of scope |
| SEGRT/SR multipath | Recognized and safely discarded; not implemented |
| DNS relay and operating-system policy management | Out of scope |

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
network privileges.

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

`--route` accepts CIDR values and passes them to platform tools as separate
arguments, never through a shell. The client rejects `0.0.0.0/0` and `::/0`
because a full-tunnel setup must first pin the iWAN control endpoint to the
physical uplink.

Configuration can also be loaded from TOML:

```toml
server = "192.0.2.10:6001"
mtu = 1400
encryption = "xor"
auth_timeout_ms = 3000
auth_attempts = 3
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
helpers.

The public API documentation can be built locally with `cargo doc --open`.

## Documentation

- [Documentation index](docs/README.md)
- [Wire protocol reference](docs/IWAN_PROTOCOL_2_3_0.md)
- [Architecture](docs/ARCHITECTURE.md)
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
