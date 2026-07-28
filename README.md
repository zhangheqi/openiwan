# OpeniWAN

[![Crates.io](https://img.shields.io/crates/v/openiwan.svg)](https://crates.io/crates/openiwan)
[![docs.rs](https://img.shields.io/docsrs/openiwan.svg)](https://docs.rs/openiwan)
[![CI](https://img.shields.io/github/actions/workflow/status/zhangheqi/openiwan/ci.yml?branch=main&label=CI)](https://github.com/zhangheqi/openiwan/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/crates/msrv/openiwan.svg)](https://crates.io/crates/openiwan)
[![License](https://img.shields.io/crates/l/openiwan.svg)](LICENSE)

An open-source iWAN client and Rust protocol library.

[English](README.md) | [简体中文](README.zh-CN.md)

OpeniWAN can authenticate directly to an iWAN UDP endpoint, establish a
native TUN tunnel, forward one TCP or HTTP(S) target without changing host
routes, or discover and connect through a controller-managed customer domain.
The library exposes the traditional and Segment Routing wire formats, client
session runtime, DNS policy engine, and managed-controller models.

> [!IMPORTANT]
> OpeniWAN is an independent interoperability project. It is not affiliated
> with or endorsed by Panabit or any network operator. Use it only with
> systems and networks you are authorized to access.

## Project status

The `main` branch targets the unreleased `0.3.0` series and contains breaking
changes from `0.2.0`. The documentation in this branch describes that
unreleased interface; use the matching Git tag when working with a published
version.

| Area | Status |
|---|---|
| Traditional iWAN authentication and tunneling | Implemented |
| Segment Routing transport and monitoring | Implemented |
| Controller-managed credential and OIDC login | Implemented |
| Linux, macOS, and Windows TUN integration | Implemented |
| Route-free TCP and HTTP(S) forwarding | Implemented |
| Vendor certification | Not provided |

OpeniWAN has defensive parsing, bounded resource use, cleanup transactions,
tests, and cross-platform CI. It does not add cryptographic properties absent
from the iWAN protocol, and interoperability can vary by deployment. Review
the [security model](SECURITY.md) and validate against an authorized endpoint
before production use.

## Installation

OpeniWAN requires Rust 1.88 or newer.

Install the latest published release:

```console
cargo install openiwan --locked
```

Build the unreleased interface documented on `main`:

```console
git clone https://github.com/zhangheqi/openiwan.git
cd openiwan
cargo build --release --locked
```

The executable is written to `target/release/openiwan` (`openiwan.exe` on
Windows). To install that checkout into Cargo's binary directory:

```console
cargo install --path . --locked
```

## Quick start

Probe an endpoint:

```console
openiwan ping 192.0.2.10:6001
```

Authenticate without changing host networking:

```console
openiwan auth --server 192.0.2.10:6001 --username alice --encryption xor
```

Open a tunnel for one route:

```console
sudo openiwan connect --server 192.0.2.10:6001 --username alice --encryption xor --route 10.0.0.0/8
```

Windows users run tunnel commands from an elevated terminal without `sudo`.
If `OPENIWAN_PASSWORD` is unset, the CLI prompts without echoing the password.
A protected `--password-file` is also supported; passwords are never accepted
as command-line values.

### Managed connection

Create a reusable, non-secret profile:

```console
openiwan profile set work --domain iwan.example --username alice
```

Inspect discovery, save verified authentication to the operating-system
credential store, and connect:

```console
openiwan managed discover
openiwan managed login --save
sudo openiwan managed connect
```

The first profile becomes the default. OIDC domains print an authorization
URL and ask for the complete callback URL; credential domains read the
password from the configured protected source.

### Route-free forwarding

Expose one fixed target on a loopback listener without creating TUN or
modifying host routes:

```console
openiwan forward --server 192.0.2.10:6001 --username alice --target tcp://db.internal.example:3306 --listen 127.0.0.1:3307
```

Targets may use `tcp://`, `http://`, or `https://`. HTTPS verifies the
upstream certificate and can use repeatable `--ca-cert` files for additional
trust anchors.

See the [CLI guide](docs/CLI.md) for the complete command hierarchy,
privilege requirements, profile lifecycle, automation output, duration
syntax, and environment variables.

## Library

Add the crate with its default managed and forwarding features:

```console
cargo add openiwan
```

For the protocol and direct client without optional managed or forwarding
dependencies:

```console
cargo add openiwan --no-default-features
```

Credentials are supplied separately from serializable configuration:

```rust
use openiwan::{Client, ClientConfig, EncryptionMethod, Result};

fn client(password: String) -> Result<Client> {
    let mut config = ClientConfig::new("192.0.2.10:6001");
    config.encryption = EncryptionMethod::Xor;
    Client::new(config, "alice", password)
}
```

Applications can provide their own `PacketDevice`, use a native `TunDevice`,
or integrate the DNS and protocol modules independently. Public API
documentation is published on [docs.rs](https://docs.rs/openiwan).

### Cargo features

| Feature | Default | Provides |
|---|:---:|---|
| `managed` | Yes | Domain discovery, credential/OIDC authentication, controller policy, profiles, and keepalive models |
| `forward` | Yes | Route-free TCP and HTTP(S) forwarding through a userspace IP stack |

Core packet, crypto, Segment Routing, DNS policy, client, and TUN APIs are
available without optional features.

## Platform support

| Platform | TUN and routes | Notes |
|---|:---:|---|
| Linux | Yes | Normally requires root or equivalent network capabilities |
| macOS | Yes | Uses an automatically allocated `utunN` by default |
| Windows 10/11 x86_64 | Yes | Requires an elevated terminal |
| Windows 10/11 ARM64 | Yes | Requires an elevated terminal |

The signed Wintun 0.14.1 binaries for Windows x86_64 and ARM64 are embedded in
the executable. OpeniWAN validates the extracted library before loading it.

## Documentation

| Document | Purpose |
|---|---|
| [CLI guide](docs/CLI.md) | Commands, credentials, profiles, forwarding, privileges, and automation |
| [Configuration guide](docs/CONFIGURATION.md) | TOML, routes, DNS policy, state, and precedence |
| [Managed connections](docs/MANAGED_CONNECTIONS.md) | Domain lookup, authentication, controller policy, posture, and keepalive |
| [Architecture](docs/ARCHITECTURE.md) | Components, lifecycle, trust boundaries, and cleanup |
| [Protocol reference](docs/PROTOCOL.md) | Traditional, Segment Routing, and managed HTTP wire contracts |
| [Protocol provenance](docs/PROTOCOL_PROVENANCE.md) | Evidence requirements and unresolved protocol areas |
| [Security policy](SECURITY.md) | Vulnerability reporting and operational security boundaries |
| [Changelog](CHANGELOG.md) | User-visible changes by release |

The [documentation index](docs/README.md) identifies the intended audience and
authority of every guide.

## Contributing and support

Bug reports, feature proposals, documentation fixes, and reproducible
interoperability evidence are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md)
before making a substantial change. Use [SUPPORT.md](SUPPORT.md) to choose the
right support channel, and report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

All contributors must follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

OpeniWAN is available under the [MIT License](LICENSE).
