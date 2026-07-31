# Configuration

This guide describes direct-client TOML, route and DNS policy, managed
profiles, and local state on the current `main` branch. Use the matching Git
tag for a released interface.

## Direct client TOML

`auth`, `connect`, and `forward` accept `--config FILE`. A minimal file is:

```toml
server = "192.0.2.10:6001"
```

The full traditional configuration is:

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

| Field | Default | Meaning |
|---|---:|---|
| `server` | Required | iWAN UDP endpoint in `HOST:PORT` form |
| `mtu` | `1400` | Packet MTU; valid range `576..=9000` |
| `encryption` | `xor` | `none`, `xor`, or `aes` |
| `receive_poll_ms` | `250` | Session receive poll interval; must be greater than zero |
| `reconnect.attempts` | `10` | Maximum reconnection attempts |
| `reconnect.initial_delay_ms` | `1000` | Initial reconnect backoff; must not exceed the maximum |
| `reconnect.max_delay_ms` | `30000` | Maximum reconnect backoff; must be greater than zero |

Unknown fields are rejected. Authentication and heartbeat timing are protocol
constants and are not configuration knobs. Usernames and passwords are
supplied separately so secrets are never serialized as `ClientConfig`.

### Segment Routing

An application can construct a selected Segment Routing path with:

```toml
[segment_routing]
id = 7
keepalive = true
encrypt_algo = "aes128"
encrypt_key = "0123456789abcdef"
links = [1, 258, 11259375]
```

`links` uses logical client-to-network order and accepts one to six nonzero
24-bit IDs. `encrypt_algo` is `none`, `aes128`, or `aes256`. The raw UTF-8 key
must provide at least 16 or 32 bytes for the selected AES algorithm. Managed
connections obtain this section from controller policy; users normally do not
write it by hand.

## Routes

Direct `connect` defaults to `custom` with no data routes. Managed `connect`
defaults to the controller routing policy. `--routing-mode all|custom`
overrides that selection, and command-line routes add to the effective policy:

- `--route CIDR` adds a prefix;
- `--route-ip IP` adds a `/32` or `/128` host route;
- `--route-domain DOMAIN` resolves once and adds host routes.

Routes are canonicalized, deduplicated, and validated before TUN is opened.
The active UDP peer, loopback, multicast, link-local addresses, and all known
managed ingresses remain outside full-tunnel policy. Default routes are
represented as safe CIDR differences rather than installing an unsafe route
that could feed iWAN transport back into its own TUN.

Managed routing modes are:

| Mode | Effective policy |
|---|---|
| `all` | All IPv4 destinations minus required exclusions |
| `ipfilter` | Inclusive prefixes minus exclusive prefixes; all IPv4 when both lists are empty |
| `custom` | IP-filter base plus effective custom routes |

The user-visible modes are `all` and `custom`. Controller `ipfilter` remains
available only when inherited. A command-line mode wins over a profile, which
wins over the controller. When the user selects `custom`, controller IP-filter
rules remain the base but controller `custom_routes` are replaced by profile
and command-line routes.

`--block-ipv6` captures IPv6 through the active TUN and drops it instead of
sending it through iWAN. `--allow-ipv6` overrides a saved block for one
connection. This is connection-scoped protection for ordinary routing, not a
host firewall; it does not disable interface IPv6 or promise to override
privileged interface-bound sockets and pre-existing more-specific routes.
Physical IPv6 DNS resolvers are not used while blocking is active.

All route and interface changes use rollback guards. Dropping the session
restores replaced state in reverse order. Linux snapshots routes before
`ip route replace`, Windows retains replaced IP Helper rows, and macOS removes
only routes successfully added by the session.

## DNS policy

Direct and managed TUN connections use the same DNS policy engine. Effective
precedence is:

```text
one-shot CLI > profile > controller policy > OPEN_ACK and service defaults
```

### Server selection

`--dns-mode` accepts:

| Mode | Behavior |
|---|---|
| `inherit` | Use controller/default DNS for this command; remove the scalar in `profile set` |
| `server` | Use controller/server-list DNS, then OPEN_ACK DNS |
| `custom` | Require one or two repeatable `--dns-server IP` values |
| `disabled` | Install no VPN DNS |

Direct commands have no controller layer. Managed controller services with no
usable configured or OPEN_ACK server use the service fallback resolvers
documented in [Managed Connections](MANAGED_CONNECTIONS.md).

### Split DNS

`--split-dns-mode` accepts:

| Mode | Behavior |
|---|---|
| `inherit` | Use controller/default split DNS for this command; remove the scalar in `profile set` |
| `off` | Do not split by domain |
| `tunnel-all` | Send every DNS query through iWAN |
| `managed` | Use controller include/exclude rules |
| `custom` | Use repeatable `--split-dns-domain RULE` values |

Domain rules preserve the protocol's matching prefixes:

| Form | Match |
|---|---|
| `example.com` or `*example.com` | Raw suffix |
| `@example.com` | Domain and label-boundary subdomains |
| `^host.example.com` | Exact normalized name |

Controller exclusions always win. Custom managed policy combines local
inclusions with controller inclusions and retains controller exclusions.

### Encrypted DNS handling

`--encrypted-dns` accepts `inherit`, `block`, or `allow`. Blocking remains
active even when tunnel DNS or split DNS is disabled. In the visible
unfragmented IPv4 TUN packet path it:

- drops TCP and UDP port 853;
- returns NXDOMAIN for configured `--doh-host` names and
  `use-application-dns.net`;
- does not intercept TLS or inspect general DoH/QUIC traffic.

When packet DNS routing is active, other IPv4 UDP/53 AAAA queries receive an
empty NOERROR response. Split routing and synthetic DNS responses operate on
unfragmented IPv4 UDP/53; TCP/53 is not intercepted. Physical DNS relay sockets
are bound outside the tunnel, validate replies, retry truncated UDP over TCP,
and discard replies from obsolete session generations.

### Saving profile DNS

Profiles accept the same DNS flags:

```console
openiwan profile set work --dns-mode custom --dns-server 192.0.2.53
openiwan profile set work --split-dns-mode custom --split-dns-domain @corp.example
```

Use `inherit` to remove a saved scalar override. Use repeatable
`--unset-dns FIELD` for `servers`, `split-domains`, or `doh-hosts`.
`--reset-dns` removes the entire saved DNS layer. Options in the same
`profile set` command are then applied to the empty layer.

## Profiles and state

A profile contains:

- customer domain;
- effective Device ID;
- optional username;
- stable line preference;
- non-secret DNS overrides;
- optional routing mode, custom CIDRs, and an IPv6 block preference;
- an opaque credential-store identifier when authentication has been saved.

It never contains a password, access token, refresh token, controller
response, generated server credential, or Segment Routing key.

The versioned `profiles.toml` document is protected by an inter-process lock
and same-directory atomic replacement. On Unix, state directories use mode
`0700`, files use `0600`, and symlinked state paths are rejected.

Default state locations:

| Platform | Directory |
|---|---|
| Windows | `%LOCALAPPDATA%\OpeniWAN`, falling back to `%APPDATA%\OpeniWAN` |
| macOS | `~/Library/Application Support/openiwan` |
| Other Unix | `$XDG_STATE_HOME/openiwan` or `~/.local/state/openiwan` |

`OPENIWAN_STATE_DIR` overrides the location. Domain lookup cache data is
always stored in its `cache` child.

Changing a profile's domain, Device ID, or username invalidates its associated
saved authentication. Removing a profile deletes that authentication.

Profile routing can be updated with:

```console
openiwan profile set work --routing-mode custom --route 10.0.0.0/8 --block-ipv6
openiwan profile set work --unset-routing-mode --unset-routes --allow-ipv6
```

One or more `--route` values replace the saved CIDR list as a group.
`--unset-routing-mode` returns to controller inheritance and `--unset-routes`
clears the saved list. `--route-ip` and `--route-domain` remain one-shot
connection options.

## Credential storage

`managed login` writes verified authentication to:

| Platform | Store |
|---|---|
| macOS | Keychain |
| Windows | Credential Manager |
| Unix | Secret Service |

Passwords and OIDC refresh tokens are versioned, redacted from debug output,
and zeroized after use. Windows values larger than one Credential Manager
entry are stored as a versioned chunk set. OIDC access tokens remain in
memory; a rotated refresh token replaces the saved value immediately.

Credential stores are scoped to the operating system account. Services should
run as the account that saved authentication and use `--non-interactive` so a
missing, locked, revoked, or mismatched credential fails instead of waiting
for input.
