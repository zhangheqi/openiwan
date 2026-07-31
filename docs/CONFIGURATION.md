# Configuration

OpeniWAN has two configuration surfaces:

- direct commands can load connection settings from TOML;
- managed commands use non-secret CLI profiles layered over controller policy.

Credentials are supplied separately and are never written to either format.

## Direct-client TOML

`auth`, `connect`, and `forward` accept `--config FILE`. A minimal file is:

```toml
server = "192.0.2.10:6001"
```

All traditional connection fields:

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
| `mtu` | `1400` | Packet MTU in the range `576..=9000` |
| `encryption` | `xor` | `none`, `xor`, or `aes` |
| `receive_poll_ms` | `250` | Nonzero session receive-poll interval |
| `reconnect.attempts` | `10` | Maximum reconnect attempts |
| `reconnect.initial_delay_ms` | `1000` | Initial reconnect backoff |
| `reconnect.max_delay_ms` | `30000` | Maximum reconnect backoff |

The initial delay must not exceed the maximum. Unknown fields and invalid
values are rejected.

### Segment Routing

Library users can describe a selected Segment Routing path in the same
configuration type:

```toml
[segment_routing]
id = 7
keepalive = true
encrypt_algo = "aes128"
encrypt_key = "0123456789abcdef"
links = [1, 258, 11259375]
```

`links` contains one to six nonzero 24-bit IDs in logical client-to-network
order. `encrypt_algo` accepts `none`, `aes128`, or `aes256`; AES keys require at
least 16 or 32 raw UTF-8 bytes respectively. Managed connections obtain this
configuration from the controller.

## Routing

Direct connections default to custom routing with no data routes. Managed
connections begin with controller policy. The effective user override order
is:

```text
one-shot command > profile > controller
```

Command-line route inputs are additive:

- `--route CIDR` adds a network prefix;
- `--route-ip IP` adds a host route;
- `--route-domain DOMAIN` resolves once and adds host routes.

`--routing-mode all` covers IPv4 except required exclusions.
`--routing-mode custom` uses explicit routes; for managed connections it also
retains the controller IP-filter base. Controller `custom_routes` are replaced
when a profile or command selects custom mode.

Routes are canonicalized and deduplicated before the TUN interface is opened.
The active UDP peer, known managed ingresses, loopback, multicast, and
link-local addresses remain outside the tunnel. Broad routes are split around
these exclusions to avoid routing the iWAN transport into its own TUN.

`--block-ipv6` installs connection-scoped capture routes and drops IPv6 in the
packet path. `--allow-ipv6` overrides a saved block for one connection. This
reduces ordinary IPv6 bypass but is not a persistent host firewall.

Route and interface updates use rollback guards. Normal shutdown and setup
failures restore replaced state in reverse order.

## DNS policy

Direct and managed TUN connections share one DNS policy engine. Inputs are
resolved in this order:

```text
one-shot command > profile > controller > OPEN_ACK and service defaults
```

### Resolver selection

`--dns-mode` accepts:

| Mode | Behavior |
|---|---|
| `inherit` | Use the next lower policy layer |
| `server` | Follow server-list policy: custom server-list DNS when configured, otherwise OPEN_ACK DNS, then controller fallback |
| `custom` | Use one or two `--dns-server IP` values |
| `disabled` | Install no VPN DNS |

Direct commands have no controller layer. Physical resolvers are captured
before OpeniWAN changes platform DNS and are reached through sockets protected
from the tunnel route.

### Split DNS

`--split-dns-mode` accepts:

| Mode | Behavior |
|---|---|
| `inherit` | Use the next lower policy layer |
| `off` | Do not route by domain |
| `tunnel-all` | Send every DNS query through iWAN |
| `managed` | Apply controller include/exclude rules |
| `custom` | Apply repeatable `--split-dns-domain RULE` values |

Domain rule forms:

| Form | Match |
|---|---|
| `example.com` or `*example.com` | Raw suffix |
| `@example.com` | The domain and label-boundary subdomains |
| `^host.example.com` | Exact normalized name |

Controller exclusions take precedence over inclusions. In a managed custom
policy, local inclusions are combined with controller inclusions while
controller exclusions remain in force.

### Encrypted DNS

`--encrypted-dns` accepts `inherit`, `block`, or `allow`. In block mode the
visible unfragmented IPv4 packet path drops TCP/UDP port 853 and returns
NXDOMAIN for configured `--doh-host` names and `use-application-dns.net`.
When packet DNS routing is active, other AAAA queries receive an empty NOERROR
response.

These controls do not intercept TLS or identify arbitrary DoH, HTTP/3, QUIC,
or IP-based encrypted DNS. See [Security Policy](../SECURITY.md) for the full
boundary.

### Saving DNS settings

Profiles accept the same DNS flags:

```console
openiwan profile set work --dns-mode custom --dns-server 192.0.2.53
openiwan profile set work --split-dns-mode custom --split-dns-domain @corp.example
```

`inherit` clears a saved scalar override. Use `--unset-dns servers`,
`--unset-dns split-domains`, or `--unset-dns doh-hosts` to clear one saved
list. `--reset-dns` clears the complete profile DNS layer.

## Profiles and local state

A managed profile stores:

- customer domain and Device ID;
- optional username;
- stable line preference;
- routing and DNS overrides;
- an opaque reference to saved authentication.

Profile state uses an inter-process lock and same-directory atomic
replacement. On Unix, state directories use mode `0700`, files use `0600`,
and symlinked state paths are rejected.

| Platform | Default state directory |
|---|---|
| Windows | `%LOCALAPPDATA%\OpeniWAN`, then `%APPDATA%\OpeniWAN` |
| macOS | `~/Library/Application Support/openiwan` |
| Other Unix | `$XDG_STATE_HOME/openiwan` or `~/.local/state/openiwan` |

`OPENIWAN_STATE_DIR` overrides the directory. Domain lookup cache entries live
in its `cache` child and expire after seven days.

Profile updates are partial. Route values supplied by one `profile set`
replace the saved route list as a group:

```console
openiwan profile set work --routing-mode custom --route 10.0.0.0/8 --block-ipv6
openiwan profile set work --unset-routing-mode --unset-routes --allow-ipv6
```

Changing a profile's domain, Device ID, or username invalidates the associated
saved authentication. Removing a profile also deletes that authentication.

## Credential storage

`managed login` stores verified credentials in the platform service:

| Platform | Store |
|---|---|
| macOS | Keychain |
| Windows | Credential Manager |
| Unix | Secret Service |

Passwords and OIDC refresh tokens are redacted from debug output and zeroized
after use. Access tokens, controller responses, generated ingress credentials,
and Segment Routing keys remain in memory.

Credential stores are scoped to an operating-system account. Services should
run as the account that saved authentication and pass `--non-interactive` so a
missing or locked credential produces an error instead of waiting for input.
