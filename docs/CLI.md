# Command-Line Guide

This guide describes the unreleased command-line interface on `main`. The
built-in help is the final authority for the installed binary:

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
| `managed login` | Authenticate, test a line, and save authentication | No |
| `managed connect` | Open a controller-managed TUN tunnel | Yes |
| `managed forward` | Forward one target through a managed connection | No |
| `managed lines` | Probe and list controller lines | No |
| `profile` | Manage non-secret connection profiles | No |

On Linux and macOS, TUN and route changes normally require `sudo` or
equivalent network capabilities. On Windows, run tunnel commands from an
elevated terminal. Installation, authentication, discovery, profile changes,
packet decoding, and route-free forwarding do not require elevation.

## Credentials

Direct credential commands resolve passwords in this order:

1. the first line of `--password-file FILE`;
2. the environment variable named by `--password-env` (default:
   `OPENIWAN_PASSWORD`);
3. a no-echo interactive prompt.

Password files must not be group- or world-accessible on Unix. Passwords are
not accepted as argument values because process listings and shell history
are not secret stores.

Managed credential commands use the first available source:

- the first line of `--password-file FILE`;
- `OPENIWAN_PASSWORD`;
- authentication saved for the selected profile;
- a no-echo interactive prompt.

`managed login` deliberately skips saved authentication, performs a fresh
login, and stores the verified password or OIDC refresh token for its profile.
Other managed commands never save an interactive fallback:

- `--non-interactive` fails instead of prompting or starting an interactive
  OIDC flow.
- `profile logout [NAME]` deletes saved authentication without removing the
  profile.

The profile and saved authentication must be accessed by the same operating
system account. Preserving `OPENIWAN_STATE_DIR` through `sudo` can preserve
the profile path, but it cannot cross the system credential-store account
boundary.

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

Open an all-IPv4 tunnel and block IPv6 bypass while it is active:

```console
sudo openiwan connect --server 192.0.2.10:6001 --username alice --routing-mode all --block-ipv6
```

`--server` may be replaced by `--config FILE`. Command-line connection
options override values loaded from TOML where both are supported.

The route options are:

| Option | Behavior |
|---|---|
| `--route CIDR` | Add a network prefix |
| `--route-ip IP` | Add a host route |
| `--route-domain DOMAIN` | Resolve once, then add host routes for the result |
| `--routing-mode all|custom` | Select all-IPv4 or custom routing |
| `--block-ipv6` | Capture and drop IPv6 for this connection |
| `--allow-ipv6` | Override a saved IPv6 block |

Connection routes are canonicalized and reduced by the required safety
exclusions. A same-family default route or a prefix containing the active iWAN
endpoint is therefore installed as safe CIDR differences; a route that becomes
empty contributes nothing. Profile storage remains stricter and rejects a
literal default route. See [Configuration](CONFIGURATION.md) for route and DNS
policy details.

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
| `auto` | Direct mode uses tunnel DNS when available; managed mode follows split-DNS policy for the target name |
| `tunnel` | Require DNS through iWAN |
| `system` | Use the host resolver |

In managed `auto` mode, a name excluded from the tunnel DNS policy uses the
host resolver even when tunnel resolvers are configured. Select `tunnel`
explicitly to override that choice.

Repeat `--dns-server IP[:PORT]` to provide numeric resolvers reached through iWAN.
`--dns-timeout` bounds each resolver attempt and `--connect-timeout` bounds
DNS, TCP, and TLS setup.

## Managed lifecycle

Managed selectors belong to each subcommand. Use `--profile NAME` or
`--domain DOMAIN`; they are mutually exclusive, and the default profile is
used when neither is passed. `--domain` is for one-shot operations and is not
accepted by `managed login`.

Inspect discovery:

```console
openiwan managed discover --domain iwan.example
```

Authenticate, test the profile's selected line, and save authentication:

```console
openiwan managed login --profile work --username alice
```

Open a managed tunnel:

```console
sudo openiwan managed connect --domain iwan.example --username alice
```

Forward one target through a managed connection:

```console
openiwan managed forward --domain iwan.example --username alice --target https://api.internal.example --listen 127.0.0.1:8080
```

The first use generates an installation-wide Device ID. One-shot domain
operations use that ID; a deployment that must preserve an existing
enrollment can set a profile's ID with `profile set --device-id ID`. The
seven-day domain lookup cache always lives in the state directory's `cache`
child.

OIDC domains print the authorization URL and accept the complete callback URL
at the prompt. The CLI uses its compatible redirect URI and reads the posture
version from the controller. `--posture-results FILE` supplies externally
evaluated local posture results as described in
[Managed Connections](MANAGED_CONNECTIONS.md).

Line probes use a fixed two-second timeout. `--line LINE` is a one-shot
override on `connect` and `forward`; `login` uses the profile preference and
`lines` always probes every current line.

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
openiwan profile set work --routing-mode custom --route 10.0.0.0/8 --block-ipv6
```

Profile `--route` values replace the saved CIDR list. Use
`--unset-routing-mode`, `--unset-routes`, or `--allow-ipv6` to clear the
corresponding saved behavior. A connect-time routing mode or IPv6 flag wins
over the profile; one-shot route targets remain additive.

Line preferences use stable controller identifiers:

- `auto`: choose the reachable line with the lowest measured latency;
- `iwan:ID`: choose one traditional server;
- `sr:ID`: choose one Segment Routing group.

List and probe all lines:

```console
openiwan managed lines
openiwan managed lines --json
openiwan profile set work --line iwan:7
```

Use the ID printed by `managed lines` with `profile set --line`. `--line LINE`
is a one-shot override for `managed connect` or `managed forward`.

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

Direct commands can change the password variable name with `--password-env
ENV`; managed commands always use `OPENIWAN_PASSWORD`. See
[Configuration](CONFIGURATION.md) for platform state locations and
credential-storage boundaries.
