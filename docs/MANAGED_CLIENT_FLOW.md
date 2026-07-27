# Managed Client Flow

The `managed` feature implements domain discovery, authentication, controller
policy, ingress selection, and persistent tunnel setup.

## Domain discovery

Domains:

- must not be empty;
- must contain at most 128 characters;
- may contain only `A-Z`, `a-z`, `0-9`, `.`, `-`, `@`, `#`, `$`, and `_`.

Lookup sends a JSON `POST /lookup` request to:

1. `https://lookup.gsase.com/lookup`;
2. `https://lookupbak.hypersase.com/lookup`.

Each endpoint is attempted twice. A successful fuzzy result may supply
`completeDomain`, which becomes the active domain. Failed live lookup falls
back to a local `lookup_cache_<domain>.json` entry for seven days. Cache
failures never turn a successful network lookup into an error.

Every attempt carries the platform `X-Auth-AppId`,
`X-Auth-Timestamp`, `X-Auth-Nonce`, and `X-Auth-Sign` headers. The signature is
HMAC-SHA256 over the HTTP method, decoded path, canonical query, exact body
hash, timestamp, and nonce. Timestamp, nonce, and signature are regenerated
for every retry.

The request body uses `serviceType: "fgb"`. A successful response wraps the
resolved service type in `data.type`; these names are intentionally different
and are both retained exactly.

The only accepted service types are:

- `serverlist`;
- `saas`;
- `controller`.

## Authentication selection

`serverlist` and `saas` select credential authentication. A controller result
uses the exact `controller_info.url.auth` endpoint returned by lookup. The
active domain is carried in the JSON body; the client does not append it to
the endpoint path:

```text
POST <controller_info.url.auth>
Content-Type: application/json
X-Mobile-Api-Version: 4
X-Auth-AppId: <controller_info.app_id>
X-Auth-Timestamp: <Unix seconds>
X-Auth-Nonce: <random 16-byte lowercase hex>
X-Auth-Sign: <HMAC-SHA256>
```

The signed request body is:

```json
{
  "domain": "active-domain",
  "type": "android|ios|macos|windows",
  "oem_name": "panabit",
  "device_id": "device-id"
}
```

Controller authentication uses the same six-line canonical request as lookup
and keepalive. Its HMAC secret is selected from the controller `app_id`: the
two defined SaaS IDs use the fallback entry, IDs containing `panabit` use the
Panabit entry, and all other IDs derive a 24-character secret from
HMAC-SHA256 of the `app_id` using the SaaS salt.

The request has one initial attempt and two retries. Only `credential` and
`oidc` are accepted. `oidc` requires a valid `oidc` object containing at
least:

- `authorization_endpoint`;
- `token_endpoint`;
- `client_id`.

The response keeps authentication beneath an `auth` object. `version` and the
optional `keepalive` configuration are siblings of that object.

An unavailable or invalid auth response falls back to credential mode. A valid
explicit OIDC response is never downgraded; trying the password path for it
returns an error.

## Credential login

The client downloads the server list, probes each UDP ingress, and selects the
lowest-latency responder. A controller domain in credential mode uses
`controller_info.url.serverlist`; `/config` is reserved for OIDC mode. It then
sends a one-shot OPEN using the global username and password. On OPEN_ACK, the
session sends an eight-byte header-only `CLOSE` and closes immediately. This
temporary authentication probe is not the VPN tunnel.

`PreparedConnection::client()` creates a fresh client. Its subsequent
`authenticate()` sends the second OPEN used by the persistent connection.

## OIDC login

Controller-supplied authorization and token endpoints are used with OAuth 2.0
Authorization Code and PKCE S256. The controller-supplied whitespace-separated
scope is preserved. A typical scope is:

```text
openid profile email offline_access
```

The authorization request includes a random verifier/challenge, nonce, state,
and controller `parameters` such as `kc_idp_hint`. The controller-supplied
authorization and token endpoints are used directly. The ID token payload is
parsed and its nonce is checked. The session contains:

- access token;
- optional refresh token;
- subject/user ID;
- username;
- expiry.

Secrets use zeroizing owners and are redacted from debug output.

## Controller configuration

OIDC mode fetches:

```text
POST /config
Content-Type: application/json
X-Mobile-Api-Version: 4
Authorization: Bearer <access-token>
X-Auth-AppId: <controller_info.app_id>
X-Auth-Timestamp: <Unix seconds>
X-Auth-Nonce: <random 16-byte lowercase hex>
X-Auth-Sign: <HMAC-SHA256>
```

The shared mobile-API signer covers the final URL and exact JSON body before
the OIDC Bearer token is added. Controller `app_id` secret selection is
identical to the auth request.

The request body contains:

```json
{
  "domain": "active-domain",
  "type": "macos",
  "oem_name": "panabit",
  "app_version": "2.3.0",
  "device_id": "device-id",
  "userName": "oidc-user",
  "posture_version": 7
}
```

`type` is the runtime platform (`android`, `ios`, `macos`, or `windows`), not
the lookup service type.

The controller wraps traditional entries as `serverlist.serverlist`;
lookup-backed lists are normalized to the same internal model. Each controller
entry can contain `userName` and `passWord`, keyed by the entry `id`. SR groups
come from `sites`. A payload containing both is rejected.

The generated `passWord` uses:

```text
secret = controller secret selected from controller_info.app_id
key = SHA256(UTF8(secret + "|" + active_domain + "|" + userName))
aad = UTF8(active_domain + "|" + userName)

payload = StandardBase64Decode(passWord)
nonce = payload[0..12]
ciphertext = payload[12..len-16]
tag = payload[len-16..]
password = AES-256-GCM-Decrypt(key, nonce, ciphertext, tag, aad)
```

The implementation accepts only standard Base64, requires the exact 12-byte
nonce and 16-byte tag, authenticates the AAD, and zeroizes intermediate secret
material.

Typed members include:

- traditional server identity, host, port, auto flag, and optional IP;
- `server_credentials` keyed by `server_id`;
- SR group `id`, names, `primary_index`, and `sr` entries;
- DNS mode and servers;
- posture, keepalive, device-binding, routing, IP-filter, domain-filter, and
  branding outer blocks.

Deployment-specific nested policy fields remain accessible through
`ControllerConfiguration::raw()`.

For a traditional OIDC connection, credentials are selected only after the
server is chosen, using that server's `server_id`. SR uses the credentials
inside the selected entry's `ingress`.

SR groups are sanitized before probing: at most five entries are retained, an
invalid primary falls back to index zero, malformed entries are dropped,
invalid ingress MTU falls back to 1392, unsupported or under-keyed outer
encryption falls back to none, and keepalive is disabled below six path hops.
Duplicate or zero serialized SR IDs receive a distinct runtime-only local
SRID.

The defined device-binding states `pending` (8000), `rejected` (8001),
`revoked` (8002), `limitExceeded` (8003), and `checkFailed` (-1) block both
login completion and construction of the persistent connection. Unknown
values remain available through `raw()` and do not block access.

## Routing, DNS, and MTU

Managed `connect` applies the controller routing settings:

- `all` sends all IPv4 traffic through the tunnel;
- `ipfilter` installs `inclusive` CIDRs and subtracts `exclusive` CIDRs,
  falling back to `all` when no rules are available;
- `custom` installs the IP-filter base when present, then the comma-separated
  `custom_routes`.

The active UDP peer, all resolved ingress addresses, loopback, IPv4 multicast,
and link-local IPv4 remain outside the tunnel. Full routing is represented as
a CIDR difference instead of an unsafe default route that could feed the UDP
transport back into its own TUN.

`dns_mode=server` uses controller and OPEN_ACK DNS, `custom` uses
`custom_dns1`/`custom_dns2`, and `disabled` installs no VPN DNS. An unspecified
OPEN_ACK address such as `0.0.0.0` is ignored; controller deployments with no
usable server then use the official-client fallback resolvers `1.1.1.1` and
`114.114.114.114`. DNS servers receive tunnel host routes in split modes.
Linux uses `resolvectl`, macOS uses a scoped SystemConfiguration DNS entry, and
Windows configures the Wintun adapter; guards restore platform state when the
connection ends.
`split_dns_enabled` and `split_dns_custom_domains` become route-only resolver
domains. A valid `mtu_mode=custom` value in `576..=9000` overrides the TUN MTU.

The IP-filter cache shape, 12-field routing settings model, and domain-filter
model are typed. Domain-filter enforcement and encrypted-DNS blocking remain
outside the current DNS engine; the configuration fields stay available to
library users.

## Posture gate

When `/config` contains a non-empty posture object, the client sends:

```text
POST /posture/evaluate
Content-Type: application/json
X-Mobile-Api-Version: 4
Authorization: Bearer <access-token>
```

with:

```json
{
  "user_id": "oidc-subject",
  "version": 1,
  "check_results": []
}
```

Access is allowed only when `local_gate` is true and `posture_ack` is a valid
string other than `DENY` (directly or through its `decision`/`status` field).
HTTP 409 maps to a posture-version mismatch; HTTP 503 means posture
configuration is unavailable. The gate timeout is 40 seconds. If
`/config` omits posture because a cached version was supplied, that version is
still used for evaluation; omission never bypasses the gate.

A missing posture version or version `0` denotes an empty/disabled posture
policy. Controller responses may encode the version as an integer or decimal
string; the client normalizes it to an integer. It clears any stale posture
cache and does not call `/posture/evaluate` in this case.

The CLI accepts already evaluated local results using
`--posture-results FILE`. The file must contain the exact JSON array sent as
`check_results`; collecting platform posture data remains the calling
application's responsibility.

## CLI

Inspect discovery:

```console
openiwan managed --domain iwan.example discover
```

Complete login without creating TUN:

```console
openiwan managed --domain iwan.example login --username alice
```

Establish the tunnel:

```console
sudo openiwan managed --domain iwan.example connect --username alice
```

Windows users run the same connect command without `sudo` in an elevated
PowerShell session. Extra `--route`, `--route-ip`, and `--route-domain` values
augment the managed routing policy.

Forward one fixed target through the managed connection without creating TUN
or modifying host routes:

```console
openiwan managed --domain iwan.example forward --username alice --target tcp://db.internal.example:3306 --listen 127.0.0.1:3307
```

On first use the CLI generates an installation-wide UUID and persists it as
the Device ID. All managed commands and newly created profiles reuse it
automatically. `--device-id` is an optional override for preserving an
existing controller enrollment; `managed discover` prints the effective ID.

Credential passwords are read from `OPENIWAN_PASSWORD`, a protected
`--password-file`, or a no-echo prompt. OIDC prints the authorization URL and
accepts the complete callback URL.

## CLI profiles and line selection

The CLI persists only non-secret managed-client preferences. State contains
the generated installation Device ID, and each profile contains the customer
domain, its effective Device ID, optional username, and line preference.
Passwords, access tokens, refresh tokens, controller configurations, generated
server credentials, and SR encryption keys are never written to the profile
store. `managed login --remember` writes only the verified password or OIDC
refresh token plus the minimum identity metadata to the operating-system
credential store. The implementation uses macOS Keychain, Windows Credential
Manager, or the Unix Secret Service. Access tokens, controller responses,
generated server credentials, and SR encryption keys remain in memory.

On a later process, password authentication reuses the saved password. OIDC
authentication sends the standard `grant_type=refresh_token` request to the
current controller-provided token endpoint. A rotated refresh token replaces
the previous value immediately. The refreshed access token is not persisted.
`--reauthenticate` skips saved authentication, while `--non-interactive`
converts every otherwise-interactive prompt into an error. `profile logout`
deletes saved authentication.

The state document has an explicit schema version. Updates hold an
inter-process lock, write and sync a same-directory temporary file, atomically
replace the destination, and sync the parent directory on Unix. Unix state
directories and files use modes `0700` and `0600`; symlinked state paths are
rejected. `--state-dir` or `OPENIWAN_STATE_DIR` can override the platform
location.

Privilege elevation must not silently select a second profile or credential
store. `--state-dir` can preserve the profile path when `sudo` changes `HOME`,
but an operating-system credential store remains scoped to the security
principal. Enrollment and the long-running service must therefore use the
same account. A service should pass `--non-interactive` so unavailable,
revoked, or mismatched authentication fails instead of waiting on stdin.

Create a profile:

```console
openiwan profile set work --domain iwan.example --username alice
```

`profile list`, `profile show`, `profile use`, `profile logout`, and `profile
remove` provide explicit lifecycle operations. The first profile becomes the
default automatically; later changes are explicit through `profile use`.
`profile list --json` and `profile show --json` produce stable
machine-readable output.

Managed line preferences use these canonical forms:

- `auto`: probe all lines and choose the lowest-latency reachable candidate;
- `iwan:<server-id>`: select one traditional server by controller ID;
- `sr:<group-id>`: select one SR group by controller ID.

An SR group is the stable selection unit. Its entries remain ordered
primary/failover paths; runtime-only SR IDs are deliberately not persisted.
`managed lines` authenticates using an automatic recovery selection, then
probes controller lines with at most 16 concurrent workers. This means a stale
saved preference cannot prevent the user from listing and replacing it.

```console
openiwan managed lines
openiwan managed lines --json
openiwan managed lines --save iwan:7
```

`--save` requires an explicit or default profile and validates that the line
exists in the current controller configuration. An unavailable but existing
line may still be saved, with a warning, because temporary reachability must
not silently rewrite user intent. `--line` is a one-shot override and never
changes persisted state.

## HTTP keepalive

The separate controller keepalive request uses API version 3, a bearer token,
one retry except HTTP 401, a fresh nonce/timestamp per attempt, and the defined
HMAC-SHA256 canonical request. `DomainClient::send_keepalive` exposes this
operation for applications that own the connection telemetry loop.
