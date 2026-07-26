# OpeniWAN

[![Crates.io](https://img.shields.io/crates/v/openiwan.svg)](https://crates.io/crates/openiwan)
[![docs.rs](https://img.shields.io/docsrs/openiwan.svg)](https://docs.rs/openiwan)
[![CI](https://img.shields.io/github/actions/workflow/status/zhangheqi/openiwan/ci.yml?branch=main&label=CI)](https://github.com/zhangheqi/openiwan/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/openiwan.svg)](LICENSE)

An independent Rust implementation of the protocol recovered from the Android
iWAN client 2.3.0.

[English](README.md) | [简体中文](README.zh-CN.md)

> [!IMPORTANT]
> OpeniWAN is not affiliated with or endorsed by Panabit or any network
> operator. Use it only with systems and networks you are authorized to access.

## Compatibility target

Version 0.3.0 follows the Android 2.3.0 reverse-engineering result as its
protocol contract. It implements:

- the complete standard packet and TLV registries;
- signed `OPEN`, `OPEN_ACK`, `OPEN_REJECT`, heartbeat, ping, and `CLOSE`;
- Java US-ASCII credential conversion and the recovered password/session keys;
- plaintext, 8-byte repeating XOR, and AES-128-ECB session payloads;
- traditional IPv4/IPv6 data classes and the two-fragment legacy receiver;
- Segment Routing headers, directional paths, inner/outer encryption,
  two-fragment transmission, offset-aware reassembly, and SR monitoring;
- OIDC Authorization Code with PKCE S256;
- the confirmed `/config` request, returned as dynamic JSON;
- the authenticated HTTP keepalive request, metric graph, response, retry, and
  HMAC canonicalization.

The aggregate `/config`, `/lookup`, and `/auth` schemas are not recoverable
without guessing, so they remain outside the typed API. Known ambiguities are
documented in
[the protocol reference](docs/IWAN_PROTOCOL_2_3_0.md).

## Installation

OpeniWAN requires Rust 1.88 or newer:

```bash
cargo install openiwan --locked
```

Build a checkout with:

```bash
cargo build --release --locked
```

The default features are `managed` and `forward`. Library users that need only
the UDP protocol can disable them:

```bash
cargo add openiwan --no-default-features
```

## Command-line usage

Probe an endpoint:

```bash
openiwan ping --server 192.0.2.10:6001
```

Authenticate without creating an interface:

```bash
openiwan auth \
  --server 192.0.2.10:6001 \
  --username alice \
  --encryption xor
```

If `OPENIWAN_PASSWORD` is unset, OpeniWAN prompts without echoing the password.
A protected `--password-file` can be used instead. Passwords are not accepted
as command-line values.

Create a TUN interface and add explicit routes:

```bash
sudo openiwan connect \
  --server 192.0.2.10:6001 \
  --username alice \
  --encryption xor \
  --route 10.0.0.0/8
```

Linux and Windows default to `openiwan0`; macOS requests an available `utunN`.
TUN creation and route changes require the corresponding platform privileges.
Default routes and routes containing the active UDP endpoint are rejected.

Decode a traditional or SR datagram:

```bash
openiwan decode 2900ffffffffffff815db7391fcafc3df035553a42cc5db6
```

## Configuration

Traditional configuration:

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

Authentication timing and heartbeat timing are fixed Android 2.3.0 behavior,
not deployment compatibility switches.

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

Use the file with:

```bash
openiwan auth --config openiwan.toml --username alice
```

## Route-free forwarding

The optional `forward` feature runs a userspace IP stack and does not create a
TUN interface or modify host routes:

```bash
openiwan forward \
  --server 192.0.2.10:6001 \
  --username alice \
  --target tcp://db.internal.example:3306 \
  --listen 127.0.0.1:3307
```

`tcp://` forwards bytes unchanged. `http://` and `https://` select an HTTP/1.1
reverse proxy to one fixed origin; HTTPS validates the upstream certificate
and supports repeatable `--ca-cert` roots. The listener must be loopback.

## Managed configuration

A provider file contains only the fields used by the confirmed OIDC,
`/config`, and keepalive contracts. See
[Managed Providers](docs/MANAGED_PROVIDERS.md) and
[the non-operational template](examples/providers/example.toml).

Fetch and print the dynamic `/config` response:

```bash
openiwan managed \
  --provider provider.toml \
  --device-id device-identifier \
  config
```

The CLI intentionally does not save or automatically interpret that aggregate
response. Applications can inspect `ControllerConfiguration::raw`, deserialize
a confirmed `SrEntry` at the deployment-specific location, and explicitly
construct `ClientConfig`.

## Library layout

- `protocol`: standard headers, TLVs, control signatures, ping, and heartbeat;
- `crypto`: password wrapping and session ciphers;
- `fragment`: traditional and SR fragment codecs/reassembly;
- `sr`: Segment Routing framing, encryption, data planning, and monitoring;
- `client`: authentication and connected-session workers;
- `managed`: OIDC, `/config`, SR serializer models, and HTTP keepalive;
- `tun`: native interface and route integration.

`Client`, `ConnectedSession`, and `PacketDevice` allow applications to supply
their own packet device or userspace stack.

## Verification

The repository includes byte-exact tests for the recovered OPEN, ping, signed
close, XOR, AES, SR header, SR outer AES, fragment words, monitor body, and HTTP
keepalive HMAC vectors.

```bash
cargo test --all-targets --all-features
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

Passing synthetic vectors is not vendor certification. Validate real
deployments against an authorized endpoint.

## Security

The recovered control signature is `MD5(header || "mw")` and does not cover the
body. XOR and AES-ECB data modes have no integrity or replay protection; SR
outer AES is also ECB without authentication. These are compatibility
mechanisms, not modern VPN security.

See [SECURITY.md](SECURITY.md) for reporting and operational guidance.

## License

OpeniWAN is available under the [MIT License](LICENSE).
