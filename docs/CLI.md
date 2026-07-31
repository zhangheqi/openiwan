# Command-line guide

The built-in help is the authoritative command reference for the installed
binary:

```console
openiwan --help
openiwan <command> --help
```

Durations use an integer followed by `ms`, `s`, or `m`, such as `500ms`, `3s`,
or `1m`. Repeatable route options also accept comma-separated values. Use `-v`
for debug logs and `-vv` for trace logs; `RUST_LOG` overrides the default
filter.

## Commands

| Command | Purpose | Elevation |
|---|---|:---:|
| `ping` | Probe an iWAN UDP endpoint | No |
| `auth` | Authenticate and close the session | No |
| `connect` | Open a native TUN tunnel | Yes |
| `forward` | Forward one fixed target without TUN | No |
| `decode` | Decode a hexadecimal datagram | No |
| `managed discover` | Inspect domain discovery | No |
| `managed login` | Authenticate a profile and save credentials | No |
| `managed connect` | Open a controller-managed tunnel | Yes |
| `managed forward` | Forward through a managed connection | No |
| `managed lines` | Probe available controller lines | No |
| `profile` | Manage connection profiles | No |

On Linux and macOS, TUN and route changes require root or equivalent network
capabilities. On Windows, run tunnel commands from an elevated terminal.

Profiles and saved credentials belong to the operating-system account that
created them. For a managed TUN on Unix, the simplest reliable workflow is to
run profile setup, login, and connect in the same elevated shell.

## Credentials

Direct commands read a password from the first available source:

1. the first line of `--password-file FILE`;
2. the variable named by `--password-env` (default `OPENIWAN_PASSWORD`);
3. a no-echo interactive prompt.

Managed commands use `--password-file`, `OPENIWAN_PASSWORD`, authentication
saved for the selected profile, or an interactive flow. `managed login`
performs fresh authentication and saves the verified password or OIDC refresh
token. Use `--non-interactive` for services and scripts.

On Unix, password files must not be group- or world-readable. Avoid passing
secrets through process arguments, logs, or shell history.

## Direct connections

Probe an endpoint:

```console
openiwan ping 192.0.2.10:6001 --timeout 3s
```

Authenticate and close:

```console
openiwan auth --server 192.0.2.10:6001 --username alice --encryption xor
```

Open a tunnel with explicit routes:

```console
sudo openiwan connect --server 192.0.2.10:6001 --username alice --encryption xor --route 10.0.0.0/8 --route 2001:db8::/32
```

Open an all-IPv4 tunnel and block ordinary IPv6 bypass while it is active:

```console
sudo openiwan connect --server 192.0.2.10:6001 --username alice --routing-mode all --block-ipv6
```

Use `--config FILE` in place of `--server` to load direct-client TOML.
Command-line connection settings take precedence over the file.

Route options:

| Option | Effect |
|---|---|
| `--route CIDR` | Add a network prefix |
| `--route-ip IP` | Add a host route |
| `--route-domain DOMAIN` | Resolve once and add host routes |
| `--routing-mode all\|custom` | Select all-IPv4 or custom routing |
| `--block-ipv6` | Capture and drop IPv6 for this connection |

Routes are reduced by safety exclusions for the transport peer, loopback,
multicast, and link-local networks. See [Configuration](CONFIGURATION.md) for
routing precedence and DNS policy.

## Route-free forwarding

`forward` authenticates to iWAN and connects a loopback listener to one fixed
target through a userspace network stack:

```console
openiwan forward --server 192.0.2.10:6001 --username alice --target tcp://db.internal.example:5432 --listen 127.0.0.1:15432
```

| Target | Behavior |
|---|---|
| `tcp://HOST:PORT` | Bidirectional byte forwarding |
| `http://HOST[:PORT]` | HTTP/1.1 proxy to a fixed origin |
| `https://HOST[:PORT]` | HTTP/1.1 proxy with upstream TLS verification |

The listener must use loopback. HTTPS always loads system trust roots; repeat
`--ca-cert FILE` to add private roots.

Target lookup is selected with `--resolve auto|tunnel|system`. `auto` uses
tunnel DNS when appropriate for the active direct or managed DNS policy.
Repeat `--dns-server IP[:PORT]` to provide resolvers reachable through iWAN.
`--dns-timeout` bounds each resolver attempt, while `--connect-timeout` covers
DNS, TCP, and TLS setup.

## Managed connections

A managed command selects either a saved profile or a customer domain:

- `--profile NAME` uses a saved profile; omitting it uses the default profile.
- `--domain DOMAIN` performs a one-shot `discover`, `connect`, `forward`, or
  `lines` operation.
- `managed login` is profile-based so saved authentication has a stable owner.

Create a profile and authenticate it:

```console
openiwan profile set work --domain iwan.example --username alice
openiwan managed discover --profile work
openiwan managed login --profile work
```

OIDC login prints an authorization URL and prompts for the complete callback
URL. `--posture-results FILE` supplies an already evaluated JSON array when a
controller requires local posture checks.

Connect or forward:

```console
sudo openiwan managed connect --profile work
openiwan managed forward --profile work --target https://api.internal.example --listen 127.0.0.1:8080
```

For one-shot use:

```console
openiwan managed discover --domain iwan.example
sudo openiwan managed connect --domain iwan.example --username alice
```

The first use generates an installation Device ID. A profile can retain a
deployment's existing ID with `profile set --device-id ID`.

### Line selection

List and probe the available lines:

```console
openiwan managed lines --profile work
openiwan managed lines --profile work --json
```

Line preferences use stable controller identifiers:

- `auto` chooses the reachable line with the lowest measured latency;
- `iwan:ID` selects a traditional server;
- `sr:ID` selects a Segment Routing group.

Save a preference with `profile set --line`, or pass `--line` to
`managed connect` or `managed forward` for one operation.

## Profiles

Profiles contain non-secret managed-connection preferences:

```console
openiwan profile set work --domain iwan.example --username alice
openiwan profile list
openiwan profile show work
openiwan profile use work
```

The first profile becomes the default. Updates are partial, so a later
`profile set` changes only the supplied values:

```console
openiwan profile set work --line sr:3
openiwan profile set work --routing-mode custom --route 10.0.0.0/8 --block-ipv6
openiwan profile set work --reset-dns
```

Use `profile logout [NAME]` to delete saved authentication while keeping the
profile. `profile remove NAME` deletes both.

See [Configuration](CONFIGURATION.md) for state locations, permissions,
credential stores, and the full set of clear/reset operations.

## Automation

Stable JSON output is available from:

```console
openiwan profile list --json
openiwan profile show work --json
openiwan managed lines --json
```

Scripts should use JSON where available and should not parse log output. Exit
status is zero on success; runtime, configuration, and command-line errors use
a nonzero status.

| Environment variable | Purpose |
|---|---|
| `OPENIWAN_PASSWORD` | Default password source |
| `OPENIWAN_STATE_DIR` | Override profile and lookup-cache state location |
| `RUST_LOG` | Override the tracing filter |
