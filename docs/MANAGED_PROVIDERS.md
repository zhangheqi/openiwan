# Managed Providers

The `managed` feature connects an OIDC identity provider and a compatible
Panabit mobile controller to the normal `openiwan::Client` data plane. Customer
parameters live in an external TOML file; the executable contains no built-in
organization profile.

This feature is enabled by default. Library users that need only the wire
protocol can build with `--no-default-features`.

## Provider File

A provider contains only deployment-level parameters:

```toml
version = 1
id = "example"
display_name = "Example iWAN"
dns_servers = ["192.0.2.53"]
require_auth_verify_echo = false
xor_key_bytes = 16

[oidc]
issuer = "https://auth.example.edu"
client_id = "public-client-id"
redirect_uri = "com.example.mobile://oauth2redirect"
scopes = ["openid", "profile", "email"]
username_claims = ["name", "displayName", "preferred_username", "sub"]
token_request_format = "json" # "json" or "form"

[controller]
base_url = "https://controller.example.edu"
domain = "iwan.example"
app_id = "controller-example"
app_secret = "deployment-application-material"
auth_path = "/m/auth"
keepalive_path = "/m/keepalive"
config_path = "/m/config"
device_type = "android"
oem_name = "example-oem"
```

The repository also provides
[`examples/providers/example.toml`](../examples/providers/example.toml) as a
schema-complete template. Its values are documentation placeholders and will
not connect to a real deployment. Replace every placeholder before use.

The provider must use HTTPS and advertise PKCE S256 through OIDC Discovery.
ID tokens must use an approved asymmetric algorithm and pass signature, issuer,
audience, expiry, and nonce validation against the advertised JWKS.

Provider files contain controller application material. Copy them with mode
`0600`; files readable by a Unix group or other users are rejected.

`dns_servers` is a required list of recursive resolver IP addresses reachable
inside iWAN. Use `[]` when a deployment relies only on DNS attributes from
OPENACK. `managed forward` queries configured resolvers through the userspace
iWAN stack instead of the host resolver path. Resolver addresses must be
unicast; provider addresses use DNS port 53.

`require_auth_verify_echo` controls compatibility with data endpoints that omit
the AUTH_VERIFY TLV from OPENACK. The client always sends AUTH_VERIFY and always
rejects a present but mismatched echo. Set the option to `true` only when the
deployment is known to echo it.

`xor_key_bytes` selects how many bytes of the 16-byte derived session key are
repeated by the legacy XOR data cipher. The field is required and must be `8`
or `16`.

Deployment-ready configurations and their operational notes are kept separate
from this generic schema. See the [provider profile index](providers/README.md).

## State and Secrets

The default state path is:

```text
Unix:    ~/.config/openiwan/managed/<provider-id>.json
Windows: %APPDATA%\openiwan\managed\<provider-id>.json
```

When invoked through `sudo`, the client resolves `SUDO_USER` and continues to
use that user's state. `--state-dir` provides an explicit override.

State writes are atomic. Unix files use mode `0600` and files with broader
permissions are rejected. Windows stores state inside the current user's
Roaming AppData and relies on that profile's NTFS access controls. The file
contains a schema version, provider ID, customer domain, stable random device
ID, fetch time, line names and endpoints, usernames, and the encrypted
passwords returned by the controller. It never contains an OAuth token or
plaintext line password.

The selected password is decrypted with authenticated AES-GCM only when
connecting, moved into `Client`, and zeroized on drop. Authentication failures
do not overwrite a previously valid state file.

## Routes

Managed and manual connections share the same route options:

- `--route <CIDR>`
- `--route-ip <IPv4-or-IPv6>`
- `--route-domain <name>`

Options may be repeated or comma-separated. Domains are resolved once before
the interface is changed. Duplicate targets are removed. Default routes and
routes containing the active iWAN endpoint are rejected; full-tunnel routing is
not implemented.

## Route-free forwarding

The `forward` managed action selects and decrypts a saved line exactly like
`connect`, but it does not create a TUN interface or modify host routes:

```bash
openiwan managed \
  --provider "$HOME/.config/openiwan/providers/provider.toml" \
  forward --line-index 1 \
  --listen 127.0.0.1:8080 \
  --target https://api.example.edu \
  --ca-cert organization-ca.pem
```

It binds `127.0.0.1:8080` by default; `--listen` may select a different
loopback address. `--target` must be a URI: `tcp://HOST:PORT` selects a raw
bidirectional byte stream and requires the port, while `http://HOST[:PORT]` and
`https://HOST[:PORT]` select an HTTP/1.1 reverse proxy with default ports 80
and 443. Bare `HOST:PORT` values are not accepted. HTTP(S) targets must be
origins without user information, a non-root path, query, or fragment.

For HTTP(S), the local side remains plaintext HTTP/1.1. The proxy rewrites
`Host` to the target authority, preserves streaming messages and application
headers, and removes hop-by-hop headers. HTTPS uses the target hostname for SNI
and certificate verification when the target is a domain; IP literals use IP
certificate identities. System roots are loaded by default; repeat
`--ca-cert` to add private CA files. That option is invalid for TCP and HTTP
targets. CONNECT, WebSocket/Upgrade, and HTTP/2 are not supported.

Organization DNS comes from `dns_servers` or OPENACK and runs inside iWAN with
TTL caching and DNS-over-TCP fallback. `--dns-mode iwan` forbids host-DNS
fallback, `--dns-server` supplies an explicit resolver, and
`--dns-timeout-ms` bounds each resolver attempt. The target URI's host is the
name passed to the selected resolver and, for an HTTPS domain target, the TLS
SNI and certificate identity. A literal IPv4 or bracketed IPv6 target bypasses
resolution; for HTTPS, the literal IP remains the verified certificate
identity. `--connect-timeout-ms` bounds DNS, TCP, and, for HTTPS, TLS setup for
each local connection. The managed state must already exist; run `fetch` first
when it does not.

## Compatibility Boundary

External provider files can represent additional customer domains only when
they use the same controller request signing, endpoint sequence, response
schema, and AES-GCM password derivation. A deployment with different behavior
requires a separate adapter and authorized interoperability evidence.
