# Managed Providers

The `managed` feature implements only controller behavior confirmed by the
Android 2.3.0 reverse-engineering result:

- OIDC Authorization Code with PKCE S256;
- `/config` request fields and headers;
- the standalone Android SR-entry serializer;
- authenticated HTTP keepalive.

The unresolved aggregate `/config` response and `/lookup` or `/auth` schemas
remain outside the typed API.

## Provider file

```toml
[oidc]
issuer = "https://auth.example.test"
client_id = "public-client-id"
redirect_uri = "com.example.app://oauth2redirect"
scopes = ["openid", "profile", "offline_access"]
username_claim = "sub"
organization = "example"
provider = "oidc"

[controller]
base_url = "https://controller.example.test"
domain = "example"
type = "device"
```

Issuer and controller URLs must use HTTPS. Keepalive application credentials
are supplied separately through `KeepaliveCredentials`; they are not part of
the `/config` provider file. Library callers using
`fetch_configuration_raw` without OIDC may omit the entire `[oidc]` section;
the CLI's interactive managed flow requires it.

`username_claim` is the deployment-selected ID-token claim used for the
optional `/config` `userName` member. OIDC discovery must advertise PKCE S256.
The ID token is validated against JWKS for signature, algorithm, issuer,
audience, expiry, and nonce. Token exchange uses the standard
`application/x-www-form-urlencoded` authorization-code request and requires
access, refresh, and ID tokens.

## `/config`

The request always sends:

```text
POST /config
Content-Type: application/json
X-Mobile-Api-Version: 4
```

OIDC mode also sends `Authorization: Bearer <access_token>`. The JSON contains
`domain`, `type`, fixed `oem_name="panabit"`, fixed
`app_version="2.3.0"`, and `device_id`. `userName` and `posture_version` are
omitted when absent.

The response remains dynamic:

```rust
let value = configuration.raw();
```

This is intentional. The recovered AOT code shows that deployments may return
server lists, SR entries, posture, keepalive, routing, DNS, filters, branding,
and device binding, but it does not preserve one authoritative aggregate
schema.

The CLI performs OIDC and prints the JSON:

```bash
openiwan managed \
  --provider provider.toml \
  --device-id device-identifier \
  config
```

Pass `--posture-version VALUE` for an incremental posture request; omit it for
a full posture refresh.

## Confirmed SR entry

`SrEntry`, `SrIngress`, and `SrPath` reproduce the Android serializer:

```json
{
  "id": 1,
  "name": "",
  "keepalive": null,
  "encrypt_algo": "",
  "encrypt_key": "",
  "status": "UNKNOWN",
  "ip": "192.0.2.10",
  "ingress": {
    "serverName": "192.0.2.20",
    "serverPort": 6001,
    "userName": "alice",
    "passWord": "password",
    "mtu": 0
  },
  "path": {"links": [1, 2, 3]}
}
```

Only `id`, `ip`, `ingress`, and `path` are required at the entry level. The
runtime-only `localSrId` is not serialized. OpeniWAN does not guess where this
entry appears inside aggregate `/config`, nor does it automatically normalize
or select entries.

## HTTP keepalive

Keepalive is a separate endpoint URL supplied by controller configuration. It
uses:

- `POST` JSON;
- `X-Mobile-Api-Version: 3`;
- OIDC bearer access token;
- five-second connect/read timeouts;
- one retry after a failed attempt except HTTP 401;
- lowercase 16-byte random nonce and Unix-second timestamp;
- SHA-256 of the exact serialized body;
- Java-compatible decoded/sorted URL-query canonicalization;
- HMAC-SHA256 with `app_secret`.

`KeepaliveRequest` and its nested public types reproduce both current-value and
timestamp-series path metrics. `PathMetricsTs.sample_ts_ms` is required.
`KeepaliveResponse` contains only the recovered optional `timestamp`,
`posture_ack`, `posture`, and `device_binding` members. HTTP 401 maps to
`ControllerUnauthorized` without retry; other non-200 statuses and malformed
responses are retried once. Each attempt regenerates its timestamp, nonce, and
signature while preserving the exact serialized body.

The signer is separately exposed as `canonical_request` and `sign_request` for
testing custom transports. The specification vector is covered by a unit test.

## Security boundary

Keepalive app secrets, access/refresh tokens, SR encryption keys, ingress
passwords, and request authorization headers are redacted from debug output
where they are owned by OpeniWAN types. Token and key holders use zeroizing
storage.

Applications that persist dynamic controller responses must define and audit
their own storage and protection policy.
