# Managed Client Flow

The `managed` feature reproduces the client-side control flow recovered from
Android iWAN 2.3.0. It does not require a hand-written provider file.

## Domain discovery

Before network access, the caller must explicitly grant consent. Domains:

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

Every attempt carries the recovered platform `X-Auth-AppId`,
`X-Auth-Timestamp`, `X-Auth-Nonce`, and `X-Auth-Sign` headers. The signature is
HMAC-SHA256 over the HTTP method, decoded path, canonical query, exact body
hash, timestamp, and nonce. Timestamp, nonce, and signature are regenerated
for every retry.

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
two retained SaaS IDs use the fallback entry, IDs containing `panabit` use the
retained Panabit entry, and all other IDs derive a 24-character secret from
HMAC-SHA256 of the `app_id` using the retained SaaS salt.

The request has one initial attempt and two retries. Only `credential` and
`oidc` are accepted. `oidc` requires a valid `oidc` object containing at
least:

- `authorization_endpoint`;
- `token_endpoint`;
- `client_id`.

The response keeps authentication beneath an `auth` object. `version` and the
optional `keepalive` configuration are siblings of that object.

The recovered UI falls back to credential mode when the auth request fails or
cannot be decoded. A successfully decoded explicit OIDC response is never
downgraded; trying the password path for it returns an error.

## Credential login

The client downloads the server list, probes each UDP ingress, and selects the
lowest-latency responder. A controller domain in credential mode uses
`controller_info.url.serverlist`; `/config` is reserved for OIDC mode. It then
sends the recovered one-shot OPEN using the global username and password. On
OPEN_ACK, the session sends the recovered eight-byte header-only `CLOSE` and
closes immediately. This reproduces the login-screen authentication probe; it
is not the VPN tunnel.

`PreparedConnection::client()` creates a fresh client. Its subsequent
`authenticate()` sends the second OPEN used by the persistent connection.

## OIDC login

Controller-supplied authorization and token endpoints are used with OAuth 2.0
Authorization Code and PKCE S256. The controller-supplied whitespace-separated
scope is preserved. The observed 2.3.0 controller response uses:

```text
openid profile email offline_access
```

The authorization request includes a random verifier/challenge, nonce, state,
and the retained controller `parameters` such as `kc_idp_hint`. As in the
recovered AppAuth path, the controller-supplied authorization and token
endpoints are used directly; OpeniWAN does not add a mandatory discovery/JWKS
round trip that is absent from that path. The ID token payload is parsed and
its nonce is checked. The retained session contains:

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

The recovered AOT config function invokes the shared mobile-API signer over
the final URL and exact JSON body before adding the OIDC Bearer token.
Controller `app_id` secret selection is identical to the auth-config request.

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

`type` is the client platform (`android`, `ios`, `macos`, or `windows`), not
the lookup service type. The official macOS 2.3.0 log records `type: macos`,
and the recovered request model names the source value `deviceType`.

The controller wraps traditional entries as `serverlist.serverlist`;
lookup-backed lists are normalized to the same internal model. Each controller
entry can contain `userName` and `passWord`. Flutter extracts those fields into
the native backend's top-level `server_credentials` array, keyed by the entry
`id`. SR groups come from `sites`. A payload containing both is rejected.

The generated `passWord` is decrypted exactly as recovered:

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

The implementation accepts only the recovered standard-Base64 form, requires
the exact 12-byte nonce and 16-byte tag, authenticates the recovered AAD, and
zeroizes intermediate secret material.

Confirmed typed members include:

- traditional server identity, host, port, auto flag, and optional IP;
- `server_credentials` keyed by `server_id`;
- SR group `id`, names, `primary_index`, and `sr` entries;
- DNS mode and servers;
- posture, keepalive, device-binding, routing, IP-filter, domain-filter, and
  branding outer blocks.

Deployment-specific nested policy fields remain accessible through
`ControllerConfiguration::raw()` and are not guessed.

For a traditional OIDC connection, credentials are selected only after the
server is chosen, using that server's `server_id`. SR uses the credentials
inside the selected entry's `ingress`.

SR groups are sanitized before probing as in the Android backend: at most five
entries are retained, an invalid primary falls back to index zero, malformed
entries are dropped, invalid ingress MTU falls back to 1392, unsupported or
under-keyed outer encryption falls back to none, and keepalive is disabled
below six path hops. Duplicate or zero serialized SR IDs receive a distinct
runtime-only local SRID.

The confirmed device-binding states `pending` (8000), `rejected` (8001),
`revoked` (8002), `limitExceeded` (8003), and `checkFailed` (-1) block both
login completion and construction of the persistent connection. Unknown
values are retained in `raw()` without inventing a new policy.

## Routing, DNS, and MTU

Managed `connect` applies the recovered routing settings:

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
`custom_dns1`/`custom_dns2`, and `disabled` installs no VPN DNS. DNS servers
receive tunnel host routes in split modes. Linux uses `resolvectl`, macOS uses
a scoped SystemConfiguration DNS entry, and Windows configures the Wintun
adapter; guards restore platform state when the connection ends.
`split_dns_enabled` and `split_dns_custom_domains` become route-only resolver
domains. A valid `mtu_mode=custom` value in `576..=9000` overrides the TUN MTU.

The exact IP-filter cache shape, 12-field routing settings model, and
domain-filter model are typed. Domain-filter enforcement and encrypted-DNS
blocking remain DNS-engine behavior whose complete platform contract is not
present in the recovered aggregate `/config` schema; OpeniWAN exposes those
confirmed fields without inventing an enforcement rule.

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
configuration is unavailable. The recovered gate timeout is 40 seconds. If
`/config` omits posture because a cached version was supplied, that version is
still used for evaluation; omission never bypasses the gate.

A missing posture version or version `0` denotes an empty/disabled posture
policy. Controller responses may encode the version as an integer or decimal
string; the client normalizes it to an integer. It clears any stale posture
cache and does not call `/posture/evaluate` in this case.

The CLI accepts already evaluated local results using
`--posture-results FILE`. The file must contain the exact JSON array sent as
`check_results`; OpeniWAN does not invent operating-system check arguments
that are absent from the recovered schema.

## CLI

Inspect discovery:

```bash
openiwan managed \
  --domain iwan.example \
  --device-id device-identifier \
  --consent \
  discover
```

Complete login without creating TUN:

```bash
openiwan managed \
  --domain iwan.example \
  --device-id device-identifier \
  --consent \
  login --username alice
```

Establish the tunnel:

```bash
sudo openiwan managed \
  --domain iwan.example \
  --device-id device-identifier \
  --consent \
  connect --username alice
```

Extra `--route`, `--route-ip`, and `--route-domain` values augment the
recovered managed routing policy.

Credential passwords are read from `OPENIWAN_PASSWORD`, a protected
`--password-file`, or a no-echo prompt. OIDC prints the authorization URL and
accepts the complete callback URL.

## HTTP keepalive

The separate controller keepalive request uses API version 3, a bearer token,
one retry except HTTP 401, a fresh nonce/timestamp per attempt, and the
recovered HMAC-SHA256 canonical request. `DomainClient::send_keepalive`
exposes this operation for applications that own the connection telemetry
loop.
