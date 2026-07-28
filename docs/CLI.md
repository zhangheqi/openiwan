# Command-Line Guide

This guide describes the unreleased `0.3.0` command-line interface on
`main`. The built-in help is the final authority for the installed binary:

```console
openiwan --help
openiwan <command> --help
```

## Conventions

- `HOST:PORT` is an iWAN UDP endpoint.
- `DURATION` requires an integer and an `ms`, `s`, or `m` suffix, such as
  `500ms`, `3s`, or `1m`.
- Options described as repeatable may be passed more than once. Route options
  also accept comma-separated values.
- `-v` enables debug logs and `-vv` enables trace logs. `RUST_LOG` overrides
  this default filter.
- Examples use documentation-only addresses and domains.

## Command overview

| Command | Purpose | Elevated privileges |
|---|---|:---:|
| `ping` | Probe an iWAN UDP endpoint | No |
| `auth` | Perform authentication without opening TUN | No |
| `connect` | Authenticate and open a native TUN tunnel | Yes |
| `forward` | Forward one TCP or HTTP(S) target without TUN | No |
| `decode` | Decode a hexadecimal iWAN datagram offline | No |
| `managed discover` | Inspect domain discovery and authentication type | No |
| `managed login` | Authenticate, evaluate gates, and test a line | No |
| `managed connect` | Open a controller-managed TUN tunnel | Yes |
| `managed forward` | Forward one target through a managed connection | No |
| `managed lines` | Probe and list controller lines | No |
| `profile` | Manage non-secret connection profiles | No |

On Linux and macOS, TUN and route changes normally require `sudo` or
equivalent network capabilities. On Windows, run tunnel commands from an
elevated terminal. Installation, authentication, discovery, profile changes,
packet decoding, and route-free forwarding do not require elevation.

## Credentials

Direct and managed credential login resolve passwords in this order:

1. the first line of `--password-file FILE`;
2. the environment variable named by `--password-env` (default:
   `OPENIWAN_PASSWORD`);
3. a no-echo interactive prompt.

Password files must not be group- or world-accessible on Unix. Passwords are
not accepted as argument values because process listings and shell history
are not secret stores.

Managed commands can use saved authentication:

- `--save` stores a verified password or OIDC refresh token in the operating
  system credential store; it requires an explicit or default profile.
- `--reauth` ignores saved authentication and performs a fresh login.
- `--non-interactive` fails instead of prompting or starting an interactive
  OIDC flow.
- `profile logout [NAME]` deletes saved authentication without removing the
  profile.

The profile and saved authentication must be accessed by the same operating
system account. Passing `--state-dir` through `sudo` can preserve the profile
path, but it cannot cross the system credential-store account boundary.

## Direct endpoint commands

Probe an endpoint:

```console
openiwan ping 192.0.2.10:6001 --timeout 3s
```

Authenticate and immediately close the session:

```console
openiwan auth --server 192.0.2.10:6001 --username alice --encryption xor
```

Open a tunnel with explicit routes:

```console
sudo openiwan connect --server 192.0.2.10:6001 --username alice --encryption xor --route 10.0.0.0/8 --route 2001:db8::/32
```

`--server` may be replaced by `--config FILE`. Command-line connection
options override values loaded from TOML where both are supported.

The route options are:

| Option | Behavior |
|---|---|
| `--route CIDR` | Add a network prefix |
| `--route-ip IP` | Add a host route |
| `--route-domain DOMAIN` | Resolve once, then add host routes for the result |

Default routes and routes containing the active iWAN endpoint are rejected.
See [Configuration](CONFIGURATION.md) for route and DNS policy details.

## Route-free forwarding

`forward` authenticates to iWAN and runs a userspace IP stack. It creates no
TUN interface and does not modify host routes:

```console
openiwan forward --server 192.0.2.10:6001 --username alice --target tcp://db.internal.example:5432 --listen 127.0.0.1:15432
```

Target schemes:

| Scheme | Behavior |
|---|---|
| `tcp://HOST:PORT` | Bidirectional byte forwarding |
| `http://HOST[:PORT]` | HTTP/1.1 reverse proxy to one fixed origin |
| `https://HOST[:PORT]` | HTTP/1.1 reverse proxy with upstream TLS verification |

The listener must be loopback. For HTTPS, system roots are always loaded;
repeat `--ca-cert FILE` to add private trust anchors. Certificate verification
cannot be disabled.

Target resolution uses `--resolve MODE`:

| Mode | Behavior |
|---|---|
| `auto` | Use tunnel DNS when configured, otherwise system DNS |
| `tunnel` | Require DNS through iWAN |
| `system` | Use the host resolver |

Repeat `--dns-server HOST[:PORT]` to provide resolvers reached through iWAN.
`--dns-timeout` bounds each resolver attempt and `--connect-timeout` bounds
DNS, TCP, and TLS setup.

## Managed lifecycle

Managed commands start with either `--domain DOMAIN` or a profile. When
neither is passed, the default profile is used.

Inspect discovery:

```console
openiwan managed --domain iwan.example discover
```

Authenticate and test the selected line without opening TUN:

```console
openiwan managed --domain iwan.example login --username alice
```

Open a managed tunnel:

```console
sudo openiwan managed --domain iwan.example connect --username alice
```

Forward one target through a managed connection:

```console
openiwan managed --domain iwan.example forward --username alice --target https://api.internal.example --listen 127.0.0.1:8080
```

The first use generates an installation-wide Device ID. `--device-id ID`
exists for deployments that must preserve an existing enrollment. The
seven-day domain lookup cache normally lives below the state directory;
`--cache-dir DIR` overrides it.

OIDC domains print the authorization URL and accept the complete callback URL
at the prompt. `--redirect-uri URI`, `--posture-results FILE`, and
`--posture-version VERSION` are advanced integration options described in
[Managed Connections](MANAGED_CONNECTIONS.md).

## Profiles

Profiles store non-secret connection preferences:

```console
openiwan profile set work --domain iwan.example --username alice
openiwan profile list
openiwan profile show work
openiwan profile use work
```

The first profile becomes the default. `profile use NAME` changes the default.
`profile remove NAME` deletes the profile and its saved authentication.
`profile logout [NAME]` deletes only saved authentication.

Profile updates are partial:

```console
openiwan profile set work --line sr:3
openiwan profile set work --unset-username
openiwan profile set work --reset-dns
```

Line preferences use stable controller identifiers:

- `auto`: choose the reachable line with the lowest measured latency;
- `iwan:ID`: choose one traditional server;
- `sr:ID`: choose one Segment Routing group.

List and probe all lines:

```console
openiwan managed lines
openiwan managed lines --json
openiwan managed lines --set iwan:7
```

`--set LINE` validates and saves the selected profile's preference. `--line
LINE` is a one-shot override for the current managed command.

## Automation

Stable JSON is available from:

```console
openiwan profile list --json
openiwan profile show work --json
openiwan managed lines --json
```

Human-readable output may evolve between releases. Scripts should use JSON
where available and must not parse log output.

Exit status is `0` on success. Runtime and configuration failures exit `1`;
command-line usage errors are emitted by `clap` and use its nonzero usage
status.

## Environment

| Variable | Purpose |
|---|---|
| `OPENIWAN_PASSWORD` | Default password source |
| `OPENIWAN_STATE_DIR` | Override profile and cache state location |
| `RUST_LOG` | Override the tracing filter |

The password variable name can be changed per command with `--password-env
ENV`. See [Configuration](CONFIGURATION.md) for platform state locations and
credential-storage boundaries.
