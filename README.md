# OpeniWAN

[![Crates.io](https://img.shields.io/crates/v/openiwan.svg)](https://crates.io/crates/openiwan)
[![docs.rs](https://img.shields.io/docsrs/openiwan.svg)](https://docs.rs/openiwan)
[![CI](https://img.shields.io/github/actions/workflow/status/zhangheqi/openiwan/ci.yml?branch=main&label=CI)](https://github.com/zhangheqi/openiwan/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/openiwan.svg)](LICENSE)

A Rust client and protocol library for iWAN-compatible networks.

[English](README.md) | [简体中文](README.zh-CN.md)

> [!IMPORTANT]
> OpeniWAN is an independent project. It is not affiliated with or endorsed by
> Panabit or any network operator. Use it only with systems and networks you
> are authorized to access.

## Features

- complete standard packet and TLV registries;
- signed `OPEN`, `OPEN_ACK`, `OPEN_REJECT`, heartbeat, ping, and `CLOSE`;
- Java US-ASCII credential conversion, password wrapping, and session keys;
- plaintext, 8-byte repeating XOR, and AES-128-ECB session payloads;
- traditional IPv4/IPv6 data classes and bounded two-fragment reassembly;
- Segment Routing headers, directional paths, inner and outer encryption,
  fragmentation, reassembly, and monitoring;
- customer-domain discovery with primary/fallback lookup, retries,
  canonical-domain handling, and a seven-day optional cache;
- credential and OIDC Authorization Code + PKCE S256 authentication;
- controller configuration, generated per-server credentials, posture and
  device-binding gates, ingress probing, and traditional/SR selection;
- versioned non-secret CLI profiles, persistent line preferences, bounded
  parallel line probing, and stable JSON output for automation;
- native TUN integration and route/DNS transactions on Linux, macOS, and
  Windows;
- route-free TCP and HTTP(S) forwarding through a userspace IP stack;
- authenticated controller keepalive requests and metric models.

Deployment-specific nested policy blocks remain available as dynamic JSON.
Stable outer fields and server/SR models use typed APIs. See the
[protocol reference](docs/PROTOCOL.md) for wire-level details.

## Installation

OpeniWAN requires Rust 1.88 or newer.

```console
cargo install openiwan --locked
```

Build a checkout:

```console
cargo build --release --locked
```

Library users that need only the UDP protocol can disable the default
`managed` and `forward` features:

```console
cargo add openiwan --no-default-features
```

## Command-line usage

The commands below are intentionally single-line and work in POSIX shells and
PowerShell. On Unix, commands that create a TUN interface normally need
`sudo`. On Windows, run the same command in an elevated PowerShell session
without `sudo`.

Probe an endpoint:

```console
openiwan ping --server 192.0.2.10:6001
```

Authenticate without creating an interface:

```console
openiwan auth --server 192.0.2.10:6001 --username alice --encryption xor
```

If `OPENIWAN_PASSWORD` is unset, OpeniWAN prompts without echoing the password.
A protected `--password-file` can be used instead. Passwords are not accepted
as command-line values.

Create a TUN interface and add an explicit route:

```console
sudo openiwan connect --server 192.0.2.10:6001 --username alice --encryption xor --route 10.0.0.0/8
```

In elevated PowerShell:

```powershell
openiwan connect --server 192.0.2.10:6001 --username alice --encryption xor --route 10.0.0.0/8
```

Linux and Windows default to `openiwan0`; macOS requests an available `utunN`.
Default routes and routes containing the active UDP endpoint are rejected.

Decode a traditional or SR datagram:

```console
openiwan decode 2900ffffffffffff815db7391fcafc3df035553a42cc5db6
```

## Configuration

Traditional connection:

```toml
server = "192.0.2.10:6001"
mtu = 1400
encryption = "xor"
receive_poll_ms = 250

[reconnect]
attempts = 10
initial_delay_ms = 1000
max_delay_ms = 30000
```

Authentication and heartbeat timing are protocol constants rather than
deployment settings.

For an SR path, add:

```toml
[segment_routing]
id = 1
keepalive = true
encrypt_algo = "aes128"
encrypt_key = "0123456789abcdef"
links = [1, 258, 11259375]
```

`links` is the logical client-to-network order. OpeniWAN reverses it only for
outbound SR serialization. `encrypt_key` is raw UTF-8 key material; AES-128
uses its first 16 bytes and AES-256 its first 32.

Use the file:

```console
openiwan auth --config openiwan.toml --username alice
```

## Route-free forwarding

The optional `forward` feature runs a userspace IP stack and does not create a
TUN interface or modify host routes:

```console
openiwan forward --server 192.0.2.10:6001 --username alice --target tcp://db.internal.example:3306 --listen 127.0.0.1:3307
```

`tcp://` forwards bytes unchanged. `http://` and `https://` select an HTTP/1.1
reverse proxy to one fixed origin. HTTPS validates the upstream certificate
and supports repeatable `--ca-cert` roots. The listener must be loopback.

## Managed connection

Managed connections start with a customer domain and device identifier.

Discover the service and authentication method:

```console
openiwan managed --domain iwan.example --device-id device-identifier discover
```

Complete authentication and ingress selection without creating a TUN:

```console
openiwan managed --domain iwan.example --device-id device-identifier login --username alice
```

For an OIDC domain, `--username` is ignored and the CLI prints the PKCE
authorization URL. Paste the complete callback URL when prompted. A credential
domain probes available ingress servers and validates the credentials with a
temporary UDP session.

Establish the persistent tunnel on Unix:

```console
sudo openiwan managed --domain iwan.example --device-id device-identifier connect --username alice
```

In elevated PowerShell:

```powershell
openiwan managed --domain iwan.example --device-id device-identifier connect --username alice
```

For repeated use, create a non-secret profile and make it the default:

```console
openiwan profile set work --domain iwan.example --device-id device-identifier --username alice
```

The first profile becomes the default automatically. Use
`openiwan profile use NAME` when more than one profile exists. Then inspect or
connect without repeating the domain, device ID, or username:

```console
openiwan profile list
openiwan managed discover
sudo openiwan managed connect
```

Passwords and OIDC tokens are never written to the profile store. Passwords
continue to come from the environment, a protected file, or the no-echo
prompt. Each new `managed login`, `managed lines`, or `managed connect`
process authenticates again. A running `managed connect` keeps credentials
only in memory, so automatic tunnel reconnections do not prompt again.

List and re-test all selectable lines:

```console
openiwan managed lines
openiwan managed lines --json
```

Traditional lines have stable IDs such as `iwan:7`; SR lines use a stable group
ID such as `sr:3`. Save a preference after validating it against the current
controller configuration:

```console
openiwan managed lines --save iwan:7
```

`auto` chooses the reachable line with the lowest measured latency. A saved SR
group retains the controller's primary/failover ordering within that group. A
one-shot `--line iwan:7` or `--line sr:3` on `login`, `connect`, or `lines`
overrides the saved preference without modifying it.

Profiles are stored as a versioned TOML document with an inter-process lock and
atomic replacement. Unix directories use mode `0700` and files use `0600`.
The default locations are `%LOCALAPPDATA%\OpeniWAN` on Windows,
`~/Library/Application Support/openiwan` on macOS, and
`$XDG_STATE_HOME/openiwan` (or `~/.local/state/openiwan`) on other Unix
systems. `--state-dir` and `OPENIWAN_STATE_DIR` override the location.

If `sudo` changes `HOME`, pass the unprivileged user's state directory
explicitly, for example `sudo openiwan --state-dir "$HOME/.local/state/openiwan"
managed connect` on a default Linux setup. Do not create a second root-owned
profile store.

Local posture results can be supplied as a JSON array with
`--posture-results`. Managed connect applies controller routing, IP-filter,
DNS, split-DNS, and MTU policy. See
[Managed Client Flow](docs/MANAGED_CLIENT_FLOW.md).

## Library layout

- `protocol`: standard headers, TLVs, control signatures, ping, and heartbeat;
- `crypto`: password wrapping and session ciphers;
- `fragment`: traditional and SR fragment codecs and reassembly;
- `sr`: Segment Routing framing, encryption, data planning, and monitoring;
- `client`: authentication and connected-session workers;
- `managed`: lookup, authentication, OIDC, controller configuration, posture,
  ingress selection, SR models, and HTTP keepalive;
- `tun`: native interface, routing, and DNS integration.

`Client`, `ConnectedSession`, and `PacketDevice` allow applications to supply
their own packet device or userspace stack.

## Development

Run the repository checks:

```console
cargo test --all-targets --all-features --locked
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
```

Generate API documentation in a POSIX shell:

```console
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked
```

Generate it in PowerShell:

```powershell
$env:RUSTDOCFLAGS = "-D warnings"; cargo doc --no-deps --all-features --locked; Remove-Item Env:RUSTDOCFLAGS
```

Passing protocol vectors is not vendor certification. Validate deployments
against an authorized endpoint.

## Security

The control signature is `MD5(header || "mw")` and does not cover the body.
XOR and AES-ECB data modes have no integrity or replay protection; SR outer
AES is also ECB without authentication. These are interoperability mechanisms,
not modern VPN security.

See [SECURITY.md](SECURITY.md) for reporting and operational guidance.

## License

OpeniWAN is available under the [MIT License](LICENSE).
