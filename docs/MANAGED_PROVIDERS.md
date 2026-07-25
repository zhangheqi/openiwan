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
OPENACK. `managed serve` queries configured resolvers through the userspace
iWAN stack, so another VPN cannot replace answers with Fake-IP records.
Resolver addresses must be unicast; provider addresses use DNS port 53.

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

## Route-free HTTP(S) API proxy

The `serve` managed action selects and decrypts a saved line exactly like
`connect`, but it does not create a TUN interface or modify host routes:

```bash
openiwan managed \
  --provider "$HOME/.config/openiwan/providers/provider.toml" \
  serve --line-index 1 --upstream https://api.example.edu
```

It binds `127.0.0.1:8080` by default and forwards local HTTP/1.1 requests to the
fixed HTTP or HTTPS origin through an in-process TCP/IP stack. Use `--listen`
for a different loopback address and repeat `--ca-cert` for private HTTPS CA
roots.
Organization DNS comes from `dns_servers` or OPENACK and runs inside iWAN with
TTL caching and DNS-over-TCP fallback. `--dns-mode iwan` forbids host-DNS
fallback. The managed state must already exist; run `fetch` first when it does
not.

## Compatibility Boundary

External provider files can represent additional customer domains only when
they use the same controller request signing, endpoint sequence, response
schema, and AES-GCM password derivation. A deployment with different behavior
requires a separate adapter and authorized interoperability evidence.
