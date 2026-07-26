# OpeniWAN

[![Crates.io](https://img.shields.io/crates/v/openiwan.svg)](https://crates.io/crates/openiwan)
[![docs.rs](https://img.shields.io/docsrs/openiwan.svg)](https://docs.rs/openiwan)
[![CI](https://img.shields.io/github/actions/workflow/status/zhangheqi/openiwan/ci.yml?branch=main&label=CI)](https://github.com/zhangheqi/openiwan/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/crates/msrv/openiwan.svg)](https://crates.io/crates/openiwan)
[![License](https://img.shields.io/crates/l/openiwan.svg)](LICENSE)

An independent, open-source Rust implementation of the iWAN client protocol.

[English](README.md) | [简体中文](README.zh-CN.md)

OpeniWAN provides a protocol library and command-line client for the
traditional single-path UDP data plane observed in the macOS iWAN client
`2.3.0 (230)`.

> [!IMPORTANT]
> This project is not affiliated with or endorsed by Panabit or any deployment
> operator. It is an interoperability project, not an official specification or
> vendor-certified client.

## Features

- OPEN, OPENACK, and OPENREJECT authentication with AUTH_VERIFY correlation
- Plaintext, repeating XOR, and legacy AES-128-ECB data modes
- IPv4, IPv6, heartbeat, CLOSE, bounded reconnection, and fragment reassembly
- Native Linux, macOS, and Windows TUN support through the `tun` crate
- Route-free raw TCP forwarding and HTTP/HTTPS reverse proxying from a
  loopback listener, with no TUN device
- Strict packet validation, bounded fragment queues, route cleanup, and
  credential zeroization
- Config-driven OIDC/JWKS login and controller-managed line discovery
- A reusable Rust library plus `ping`, `auth`, `connect`, `decode`, `forward`,
  and `managed` commands

## Status

### Available

- Traditional single-path authentication and UDP tunneling
- Plaintext and repeating XOR data modes
- IPv4, IPv6, IPFRAG, and IPFRAG6 receive paths
- Heartbeat, CLOSE, failure detection, and bounded reconnection
- URI-selected raw TCP forwarding and HTTP/HTTPS reverse proxying
- Config-driven OIDC and compatible Panabit controller flows
- `forward` userspace DNS with UDP, TCP fallback, and TTL caching

### Requires deployment validation

- Legacy AES-128 data mode is implemented but still requires validation against
  an authorized real endpoint.

### Not implemented

- SEGRT/SR multipath packets are recognized and safely discarded.

Production-oriented here means that the implementation has defensive parsing,
resource limits, explicit error handling, credential hygiene, cleanup logic,
tests, and CI. It does not mean that the project has passed vendor
certification. Validate every deployment against an authorized test endpoint.

## Installation

OpeniWAN requires Rust 1.88 or newer. Install the CLI from crates.io:

```bash
cargo install openiwan --locked
```

By default, Cargo installs the executable to `$HOME/.cargo/bin` on Linux and
macOS or `%USERPROFILE%\.cargo\bin` on Windows. Ensure that directory is on
`PATH`, then verify the installation:

```bash
openiwan --version
```

## Build from source

From a repository checkout, build the optimized executable with:

```bash
cargo build --release --locked
```

The executable is written to `target/release/openiwan` (`openiwan.exe` on
Windows). To install the current checkout into Cargo's binary directory instead:

```bash
cargo install --path . --locked
```

Contributor checks and development requirements are documented in
[CONTRIBUTING.md](CONTRIBUTING.md).

## Platform notes

Installation does not require elevated privileges. Creating a TUN interface or
changing routes does: run `connect`, `managed connect`, and `managed all` as
root on Linux/macOS or from an elevated terminal on Windows. `ping`, `auth`,
`decode`, `forward`, managed login, and managed listing do not require
elevation.

### Windows

Windows 10/11 on x86_64 and ARM64 is supported.

The official signed Wintun 0.14.1 library is embedded in the executable. On the
first TUN connection, OpeniWAN verifies its SHA-256 digest, atomically extracts
it below `%LOCALAPPDATA%\openiwan\wintun\0.14.1`, verifies its Authenticode
signature while loading it, and reuses the validated file thereafter. No
separate Wintun setup or DLL copy is required.

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

If `OPENIWAN_PASSWORD` is unset, the client securely prompts for the password
without echoing it on Linux, macOS, and Windows. Do not pass passwords directly
on the command line.

Create a tunnel for explicit destination prefixes:

```bash
sudo openiwan connect \
  --server 192.0.2.10:6001 \
  --username alice \
  --encryption xor \
  --route 10.0.0.0/8 \
  --route 2001:db8::/32
```

On Windows, run the equivalent command in an elevated terminal without
`sudo`. The default interface is `openiwan0` on Linux and Windows; macOS
automatically allocates an available `utunN`. Use `--tun` to override the name
(`utunN` is required for an explicit macOS name).

`--route` accepts CIDRs, `--route-ip` creates host routes, and `--route-domain`
resolves a domain once before connecting. Unix values are passed to platform
tools as separate arguments, never through a shell; Windows uses the native IP
Helper API. The client rejects default routes and any route containing the
active iWAN endpoint.

### Forward TCP or HTTP(S) without changing host routes

`--target` is a URI whose scheme selects the forwarding mode. For a raw TCP
service, include an explicit nonzero port:

```bash
openiwan forward \
  --server 192.0.2.10:6001 \
  --username alice \
  --encryption xor \
  --listen 127.0.0.1:3307 \
  --target tcp://db.internal.example:3306
```

A connection to `127.0.0.1:3307` is carried through the iWAN userspace TCP/IP
stack to `db.internal.example:3306`. Bytes flow unchanged in both directions;
OpeniWAN does not parse the application protocol or terminate TLS. If the
application needs confidentiality or server authentication, configure TLS in
the local client and target service.

For an HTTP or HTTPS origin, the local listener is always plaintext HTTP/1.1:

```bash
openiwan forward \
  --server 192.0.2.10:6001 \
  --username alice \
  --encryption xor \
  --listen 127.0.0.1:8080 \
  --target https://api.example.edu \
  --ca-cert organization-ca.pem
```

A local request for `http://127.0.0.1:8080/v1/profile?full=true` is proxied to
`https://api.example.edu/v1/profile?full=true`. Methods, paths, queries,
streaming bodies and responses, and end-to-end headers such as `Authorization`
are preserved. OpeniWAN rewrites `Host` to the target authority, removes
hop-by-hop headers, and rewrites same-origin absolute `Location` values to
relative references. HTTPS targets use the target hostname for TLS SNI and
certificate verification when it is a domain; an IP literal is verified as an
IP certificate identity. System roots are loaded by default; repeat `--ca-cert`
to add private CA files. `--ca-cert` is accepted only for an `https://` target.
An `http://` target uses plain TCP inside iWAN and provides no upstream TLS
protection.

`forward` opens no TUN device, invokes no platform route command, and has no
route options. The listener must be a loopback address and defaults to
`127.0.0.1:8080`. Bare `HOST:PORT` targets are rejected:

- `tcp://HOST:PORT` selects raw TCP and always requires the port.
- `http://HOST[:PORT]` selects HTTP reverse proxying and defaults to port 80.
- `https://HOST[:PORT]` selects verified HTTPS upstreams and defaults to port
  443.

For example, `http://example.com` and `https://example.com` use the defaults,
while `http://example.com:12345` and `https://example.com:12345` select a
custom port.

HTTP(S) targets must be origins without user information, a non-root path,
query, or fragment. Bracket IPv6 literals, for example
`tcp://[2001:db8::10]:3306` or `https://[2001:db8::10]`. Incoming `CONNECT`,
WebSocket and other HTTP Upgrade requests, and HTTP/2 are not supported.
`--connect-timeout-ms` bounds the complete DNS, TCP, and, when applicable, TLS
setup for each accepted connection. The forwarder permits at most 256
concurrent connections and closes new connections while at capacity.

The default `--dns-mode auto` first queries organization resolvers advertised
by OPENACK or configured by the managed provider through the iWAN userspace
stack. It validates transactions and responses, follows CNAMEs, caches by TTL,
and retries truncated UDP responses over DNS-over-TCP. Because these queries
stay inside iWAN, host-side VPNs and proxies cannot observe them or substitute
Fake-IP answers. Every managed provider must explicitly declare its
organization resolvers; use an empty list when the deployment relies only on
OPENACK DNS attributes:

```toml
dns_servers = []
```

Manual mode and temporary overrides can pass `--dns-server 192.0.2.53`;
`--dns-timeout-ms` bounds each resolver attempt. `--dns-mode iwan` requires an
iWAN resolver. `auto` uses host DNS only when no iWAN resolver is available;
failure of a configured organization resolver is fail-closed and does not leak
the hostname to the host resolver. Host answers in `198.18.0.0/15` are rejected
instead of causing a useless TCP timeout. To bypass DNS, put a literal IPv4 or
bracketed IPv6 address directly in the target URI, for example
`tcp://192.0.2.25:22` or `https://[2001:db8::25]`. There is no separate
`--target-ip` override.

### Managed login and connection

Managed providers are external TOML files so the authentication and controller
parameters can be updated without recompiling. The schema-complete
`examples/providers/example.toml` is a non-operational template; replace every
placeholder or use a bundled profile before installing the provider as a
protected file:

```bash
install -d -m 700 "$HOME/.config/openiwan/providers"
install -m 600 /path/to/provider.toml \
  "$HOME/.config/openiwan/providers/provider.toml"
```

Fetch and list encrypted line configuration without elevated privileges:

```bash
openiwan managed \
  --provider "$HOME/.config/openiwan/providers/provider.toml" fetch
openiwan managed \
  --provider "$HOME/.config/openiwan/providers/provider.toml" list
```

Select a line and connect:

```bash
sudo openiwan managed \
  --provider "$HOME/.config/openiwan/providers/provider.toml" \
  connect --route-domain example.edu --route 10.0.0.0/8
```

Use `all` in place of `fetch` or `connect` to perform the complete flow. The
access token and decrypted line password are never written to disk. See
[Managed Providers](docs/MANAGED_PROVIDERS.md) for the provider schema, state
layout, and security model. Bundled configurations and deployment-specific
instructions are listed under [Provider Profiles](docs/providers/README.md).
The default managed state directory is `~/.config/openiwan/managed` on Unix and
`%APPDATA%\openiwan\managed` on Windows.

`connect`, `all`, and `forward` print the line list before prompting when no
selector is provided. Passing `--line-index` or `--line-name` selects the line
directly without printing the complete list.

An existing managed line can run the same route-free forwarder:

```bash
openiwan managed \
  --provider "$HOME/.config/openiwan/providers/provider.toml" \
  forward --line-index 1 \
  --listen 127.0.0.1:3307 \
  --target tcp://db.internal.example:3306
```

Configuration can also be loaded from TOML. `require_auth_verify_echo` and
`xor_key_bytes` are required because their values depend on the deployment:

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

Add OpeniWAN to a Rust project with `cargo add openiwan`. For a protocol-only
dependency without the default `managed` and `forward` features, use
`cargo add openiwan --no-default-features`.

Packet and TLV codecs live in `openiwan::protocol`; compatibility cryptography
lives in `openiwan::crypto`. Applications that already own a TUN device,
virtual interface, or userspace IP stack can implement `PacketDevice` and use
`Client::authenticate`, `ConnectedSession::run`, or the bounded reconnect
helpers. The default `managed` Cargo feature exposes typed provider, OIDC,
controller, and encrypted-state APIs; disable default features for a
protocol-only dependency.

Programmatic client and cipher construction requires an explicit
`require_auth_verify_echo` policy and XOR key width. Cipher constructors return
an error unless the width is `8` or `16`.

The public API documentation can be built locally with `cargo doc --open`.

## Documentation

- [Documentation index](docs/README.md)
- [Wire protocol reference](docs/IWAN_PROTOCOL_2_3_0.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Managed providers](docs/MANAGED_PROVIDERS.md)
- [Provider profiles](docs/providers/README.md)
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

Use OpeniWAN only on authorized networks, preferably inside an additional
trusted security layer, and choose a stronger protocol when the endpoint
supports one.

## License

OpeniWAN is available under the [MIT License](LICENSE).
