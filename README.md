# OpeniWAN

[![Crates.io](https://img.shields.io/crates/v/openiwan.svg)](https://crates.io/crates/openiwan)
[![docs.rs](https://img.shields.io/docsrs/openiwan.svg)](https://docs.rs/openiwan)
[![CI](https://img.shields.io/github/actions/workflow/status/zhangheqi/openiwan/ci.yml?branch=main&label=CI)](https://github.com/zhangheqi/openiwan/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/crates/msrv/openiwan.svg)](https://crates.io/crates/openiwan)
[![License](https://img.shields.io/crates/l/openiwan.svg)](LICENSE)

Open-source iWAN client and Rust protocol library.

[English](README.md) | [简体中文](README.zh-CN.md)

OpeniWAN supports direct iWAN authentication, native TUN tunnels,
route-free TCP and HTTP(S) forwarding, and controller-managed connections.
The crate also exposes the traditional and Segment Routing wire formats,
session runtime, DNS policy engine, and managed-controller models.

> [!IMPORTANT]
> OpeniWAN is an independent interoperability project. It is not affiliated
> with or endorsed by Panabit or any network operator. Use it only with
> systems and networks you are authorized to access.

## Features

- Traditional iWAN and Segment Routing transports
- Direct and controller-managed authentication
- Native TUN and route management on Linux, macOS, and Windows
- Split-DNS policy and encrypted-DNS controls
- Route-free forwarding to a fixed TCP or HTTP(S) target
- Rust APIs for protocol, client, managed, DNS, and TUN integration

The iWAN protocol has security limitations that an implementation cannot
remove. Review the [security model](SECURITY.md) before using OpeniWAN in a
production network.

## Install

Install the latest published release from crates.io:

```console
cargo install openiwan --locked
```

To build from source:

```console
git clone https://github.com/zhangheqi/openiwan.git
cd openiwan
cargo build --release --locked
```

The required Rust version is declared in [Cargo.toml](Cargo.toml). The binary
is written to `target/release/openiwan` (`openiwan.exe` on Windows).

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

Windows users should run tunnel commands from an elevated terminal and omit
`sudo`. If `OPENIWAN_PASSWORD` is unset, the CLI prompts without echoing the
password. A protected `--password-file` is also supported.

### Managed connections

Managed connections use a customer domain and can save authentication in the
operating-system credential store. On Unix, create the profile, authenticate,
and connect as the same elevated account:

```console
sudo -H -s
openiwan profile set work --domain iwan.example --username alice
openiwan managed login --profile work
openiwan managed connect --profile work
exit
```

See the [CLI guide](docs/CLI.md) for profile selection, OIDC login, routing,
DNS, and non-interactive operation.

### Route-free forwarding

Forward a fixed target through iWAN without creating a TUN interface or
changing host routes:

```console
openiwan forward --server 192.0.2.10:6001 --username alice --target tcp://db.internal.example:3306 --listen 127.0.0.1:3307
```

Targets may use `tcp://`, `http://`, or `https://`. HTTPS verifies the
upstream certificate; repeat `--ca-cert FILE` to add private trust anchors.

## Use as a library

Add the crate with its default managed and forwarding features:

```console
cargo add openiwan
```

Disable the optional managed and forwarding features:

```console
cargo add openiwan --no-default-features
```

```rust
use openiwan::{Client, ClientConfig, EncryptionMethod, Result};

fn client(password: String) -> Result<Client> {
    let mut config = ClientConfig::new("192.0.2.10:6001");
    config.encryption = EncryptionMethod::Xor;
    Client::new(config, "alice", password)
}
```

API documentation is available on [docs.rs](https://docs.rs/openiwan).

| Feature | Default | Provides |
|---|:---:|---|
| `managed` | Yes | Domain discovery, controller authentication and policy, profiles, and keepalive models |
| `forward` | Yes | Route-free TCP and HTTP(S) forwarding through a userspace network stack |

## Platform support

| Platform | TUN and routes | Notes |
|---|:---:|---|
| Linux | Yes | Requires root or equivalent network capabilities |
| macOS | Yes | Uses an automatically allocated `utun` interface by default |
| Windows x86_64 | Yes | Requires an elevated terminal |
| Windows ARM64 | Yes | Requires an elevated terminal |

Signed Wintun binaries for the supported Windows architectures are included
in the crate and verified before loading.

## Documentation

- [Command-line guide](docs/CLI.md)
- [Configuration](docs/CONFIGURATION.md)
- [Managed connections](docs/MANAGED_CONNECTIONS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Protocol reference](docs/PROTOCOL.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

Documentation on the default branch may describe changes that have not been
published yet. For a released build, use its built-in help, docs.rs page, and
matching Git tag.

## Community

Use [SUPPORT.md](SUPPORT.md) to report bugs or request help. Security issues
must be reported privately as described in [SECURITY.md](SECURITY.md). All
participants must follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

OpeniWAN is available under the [MIT License](LICENSE).
