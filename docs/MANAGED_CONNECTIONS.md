# Managed Connections

The `managed` feature turns a customer domain and user authentication into a
validated `PreparedConnection`. It covers domain lookup, controller
authentication and policy, posture and device gates, ingress selection, and
credential preparation.

This document is the integration contract. Exact HTTP and UDP wire forms are
defined in the [Protocol Reference](PROTOCOL.md); CLI workflows and persistent
state are covered by the [CLI guide](CLI.md) and
[Configuration](CONFIGURATION.md).

```text
customer domain
    -> lookup and canonical domain
    -> credential or OIDC authentication
    -> server-list or controller configuration
    -> posture and device-binding gates
    -> line normalization, probing, and selection
    -> PreparedConnection
    -> fresh Client and persistent OPEN
```

## Public boundary

| Type | Responsibility |
|---|---|
| `DomainClient` | Owns the HTTP transport, optional lookup cache, and managed operations |
| `DiscoveredDomain` | Holds the validated lookup result, active domain, and authentication choice |
| `PendingDomainAuthorization` | Owns one in-progress OIDC authorization, including state, nonce, and PKCE verifier |
| `OidcIdentity` | Owns access and refresh tokens plus the subject, username, and expiry |
| `ControllerConfiguration` | Exposes typed policy while retaining deployment-specific JSON through `raw()` |
| `PreparedConnection` | Holds the selected ingress, normalized configuration, and ephemeral connection credentials |

Applications normally keep one `DomainClient`, complete lookup and login, then
call `PreparedConnection::client()` for each direct connection attempt. The
prepared value is also the policy handoff point for routing and DNS setup.

## Domain lookup

Input domains are non-empty, contain at most 128 characters, and use letters,
digits, `.`, `-`, `@`, `#`, `$`, or `_`. The Device ID must be non-empty.

Lookup sends `POST /lookup` to the primary service and then the fallback
service, with two attempts per endpoint. Every attempt receives a new
timestamp, nonce, and HMAC signature. The request uses `serviceType: "fgb"`;
the response selects one of these service types:

- `serverlist`;
- `saas`;
- `controller`.

A fuzzy match may return `completeDomain`. That value becomes the active
domain; otherwise the domain supplied by the caller remains active. All later
controller requests and generated-credential decoding use the active domain.

When a cache directory is configured, a successful response is stored under
`lookup/<domain>.json`. After live lookup fails, an entry no older than seven
days may satisfy the request. Cache write failures do not change a successful
network result, and malformed or expired entries do not mask the live error.

The endpoint order, request members, and signing algorithm are specified in
[Managed HTTP](PROTOCOL.md#managed-http).

## Authentication choice

`serverlist` and `saas` select credential authentication. For `controller`,
`DomainClient::discover` posts to the exact HTTPS auth URL supplied by lookup;
the active domain is a request-body member rather than a path suffix.

The controller auth request has three total attempts. HTTP 4xx responses stop
retrying, while transport errors, HTTP 5xx responses, and invalid response
bodies may be retried. A valid response selects `credential` or `oidc`.
Unavailable or invalid controller auth selects credential mode; a valid OIDC
selection remains authoritative for the login.

An OIDC selection requires HTTPS authorization and token endpoints plus a
non-empty client ID.

## Credential login

Credential mode fetches the lookup-resolved server-list URL. For a controller
domain this is `controller_info.url.serverlist`; the controller configuration
endpoint belongs to the OIDC path. Lookup-backed array responses and nested
controller server lists are normalized to one internal representation.

Login then:

1. validates the server entries and probes eligible UDP ingresses;
2. selects the requested line or the automatic lowest-latency candidate;
3. constructs a direct client with the supplied username and password;
4. authenticates one temporary OPEN;
5. sends the eight-byte probe CLOSE and releases that socket.

This temporary session verifies the selected credentials. The returned
`PreparedConnection` retains enough information to construct a fresh client,
whose `authenticate()` performs the OPEN for the persistent tunnel.

## OIDC login

OIDC uses the HTTPS authorization and token endpoints returned by the
controller. Authorization Code with PKCE S256 binds the browser flow to the
client. The authorization request also carries random state and nonce values,
the controller's whitespace-separated scopes, and supported string parameters
such as `kc_idp_hint`. The default scope is `openid profile email`.

Completion requires the callback's scheme, authority, and path to match the
configured redirect URI. The returned state must match, the code is redeemed
with the PKCE verifier, and the ID-token nonce must match the pending login.
The accepted response supplies:

- an access token and optional refresh token;
- a non-empty subject and username;
- an expiry from the token response or token claims.

These values are held by redacting, zeroizing owners. The identity trust
boundary is the controller-provided HTTPS authorization and token service;
the [Security Policy](../SECURITY.md#managed-authentication) describes its
security properties.

Refresh uses the current controller-provided token endpoint and the saved
subject and username. A returned refresh token replaces the previous token;
otherwise the previous token remains active. Credential-store persistence is
owned by the CLI layer.

## Configuration acquisition

OIDC controller login posts to the exact HTTPS configuration URL supplied by
lookup. The request is signed with the controller `app_id`, then receives the
OIDC bearer token. Its body carries the active domain, compatibility platform,
OEM identifier, compatibility `app_version`, Device ID, optional username,
and optional posture version.

The [Protocol Reference](PROTOCOL.md#managed-http) is authoritative for the
exact request fields and compatibility literals. The platform field uses the
controller schema's Android, iOS, macOS, or Windows value; Linux and other
desktop Unix targets use the Android compatibility value.

The response has two supported line shapes:

| Shape | Location | Credential source |
|---|---|---|
| Traditional iWAN | `serverlist.serverlist` | `userName` and `passWord`, associated by server ID |
| Segment Routing | top-level `sites` groups | credentials inside each selected entry's `ingress` |

A response containing both shapes is rejected. Generated passwords are
decoded only with the controller app-ID and active-domain context captured by
the lookup flow. Traditional credentials are chosen after line selection by
`server_id`; SR credentials follow the selected ingress. The authenticated
decryption format is defined in the
[Protocol Reference](PROTOCOL.md#managed-http).

The typed configuration surface includes server and SR identity, routing and
IP-filter policy, DNS defaults, posture, keepalive, device binding, domain
filtering, and branding. Deployment-specific nested members remain available
through `ControllerConfiguration::raw()`.

## Segment Routing normalization

Controller SR groups are normalized before probing:

- at most five entries are retained per group;
- an out-of-range primary index selects the first retained entry;
- entries with invalid ingress, credentials, path length, link IDs, or
  metadata IP are removed;
- ingress MTU outside `576..=1500` becomes 1392;
- unsupported or under-keyed outer encryption becomes `none`;
- monitor keepalive is enabled only for a six-link path;
- duplicate or zero serialized entry IDs receive distinct runtime-only SR IDs.

The group remains the stable selection unit. Its normalized primary is swapped
into the first probe position; subsequent failovers follow that normalized
entry order.

## Posture and device gates

OIDC configuration may provide a posture policy. A positive integer or decimal
string selects the version to evaluate; a missing value or `0` selects the
empty-policy path. When the configuration response omits posture after a
cached positive version was sent, that cached version still drives evaluation.

The caller supplies the `check_results` array. Evaluation posts the user ID,
version, and those results to the posture endpoint derived from the
configuration URL. It has a 40-second request timeout. Access requires both
`local_gate: true` and a valid `posture_ack` decision other than `DENY`.
HTTP 409 reports a version mismatch and HTTP 503 reports unavailable posture
configuration.

Recognized device-binding states block preparation and are checked again by
`PreparedConnection::client()`:

| State | Code |
|---|---:|
| `pending` | `8000` |
| `rejected` | `8001` |
| `revoked` | `8002` |
| `limitExceeded` | `8003` |
| `checkFailed` | `-1` |

Unknown state values remain visible in `raw()` and carry no defined blocking
meaning.

## Line selection

Stable preferences use `auto`, `iwan:<server-id>`, or `sr:<group-id>`.
Traditional preferences identify one server. SR preferences identify a group
and preserve its primary/failover order even when runtime SR IDs change.

Each ingress measurement launches three independent protocol pings and keeps
the lowest successful round-trip time. Automatic selection compares every
reachable traditional server with the first reachable entry from each SR
group, then chooses the lowest latency. A specific preference fails when that
server or group is absent or unreachable.

`PreparedConnection::probe_lines()` returns results in controller order and
batches work at 16 workers.

## Policy handoff

The prepared configuration exposes typed routing, IP-filter, MTU, DNS, and
domain-filter inputs. The CLI combines them with profile and one-shot
overrides, excludes transport endpoints from TUN routes, and reapplies
session-derived DNS after reconnect. The precedence rules and platform effects
are defined in [Configuration](CONFIGURATION.md#routing) and
[DNS policy](CONFIGURATION.md#dns-policy).

Managed preparation itself changes no routes, interfaces, or platform DNS.
Those resources are acquired only when the caller runs a session with the TUN
packet device. Route-free forwarding consumes the same prepared connection
without host-network changes.

## Saved authentication

The CLI persists non-secret profile metadata and opaque credential references.
Verified passwords and OIDC refresh tokens are stored through the operating
system credential service; access tokens, controller responses, generated
credentials, and SR keys remain process state.

`managed login` authenticates before saving. A rotated refresh token replaces
its stored predecessor immediately, while domain, Device ID, or username
changes invalidate the reference. See
[Profiles and local state](CONFIGURATION.md#profiles-and-local-state) for
storage and permission details.

## Controller keepalive

Controller keepalive is an explicit `DomainClient::send_keepalive` operation,
separate from the UDP session heartbeat. The calling application owns its
telemetry loop and supplies the endpoint, credentials, and metrics graph.

Each request uses mobile API version 3, a five-second transport timeout, and
up to two attempts. HTTP 401 is terminal; a retry receives a fresh timestamp,
nonce, and signature over the same serialized body. The canonical request and
metrics schema are defined in the
[Protocol Reference](PROTOCOL.md#managed-http).

## Failure and trust boundaries

Controller URLs, JSON, token responses, callbacks, generated credentials, and
cache files are validated at their owning boundary. Stable outer fields are
typed before selection or policy handoff, while unknown deployment policy is
retained as JSON for explicit consumers. Secrets are redacted from debug
output and zeroized by their owners.

Lookup exhaustion may fall back only to a valid cache entry. Authentication,
posture, device binding, credential decoding, and ingress selection must each
succeed before a persistent client is constructed. Host-state rollback and
the underlying protocol's cryptographic limits are covered by
[Architecture](ARCHITECTURE.md#concurrency-and-cleanup) and the
[Security Policy](../SECURITY.md).
