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
oem_name = "panabit"
```

The provider must use HTTPS and advertise PKCE S256 through OIDC Discovery.
ID tokens must use an approved asymmetric algorithm and pass signature, issuer,
audience, expiry, and nonce validation against the advertised JWKS.

Provider files contain controller application material. Copy them with mode
`0600`; files readable by a Unix group or other users are rejected.

`require_auth_verify_echo` controls compatibility with data endpoints that omit
the AUTH_VERIFY TLV from OPENACK. The client always sends AUTH_VERIFY and always
rejects a present but mismatched echo. Set the option to `true` only when the
deployment is known to echo it; the USTC example uses `false` because its
current endpoints omit the echo.

`xor_key_bytes` selects how many bytes of the 16-byte derived session key are
repeated by the legacy XOR data cipher. Managed providers default to the
widely-deployed 8-byte compatibility form; set `16` for endpoints known to use
the full key. The USTC provider uses `8`.

## USTC

The repository includes the currently observed USTC profile as an example, not
as a vendor-supported built-in:

```bash
install -d -m 700 "$HOME/.config/openiwan/providers"
install -m 600 examples/providers/ustc.toml \
  "$HOME/.config/openiwan/providers/ustc.toml"
```

Fetch the available lines:

```bash
openiwan managed \
  --provider "$HOME/.config/openiwan/providers/ustc.toml" fetch
```

The command prints an authorization URL. Open it, complete authentication, and
paste the complete custom-scheme callback URL into the terminal. `openiwan`
checks the redirect URI and state before exchanging the authorization code.

List the saved lines without network access or password decryption:

```bash
openiwan managed \
  --provider "$HOME/.config/openiwan/providers/ustc.toml" list
```

Connect interactively, by one-based index, or by a unique exact name:

```bash
sudo openiwan managed \
  --provider "$HOME/.config/openiwan/providers/ustc.toml" \
  connect --line-index 1 --route 10.0.0.0/8
```

Use `all` to fetch, list, select, and connect in one process. Fetch and list do
not need elevated privileges; TUN creation normally does.

## State and Secrets

The default state path is:

```text
~/.config/openiwan/managed/<provider-id>.json
```

When invoked through `sudo`, the client resolves `SUDO_USER` and continues to
use that user's state. `--state-dir` provides an explicit override.

State writes are atomic and use mode `0600`; state files with broader Unix
permissions are rejected. The file contains a schema version, provider ID,
customer domain, stable random device ID, fetch time, line names and endpoints,
usernames, and the encrypted passwords returned by the controller. It never
contains an OAuth token or plaintext line password.

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

## Compatibility Boundary

External provider files can represent additional customer domains only when
they use the same controller request signing, endpoint sequence, response
schema, and AES-GCM password derivation. A deployment with different behavior
requires a separate adapter and authorized interoperability evidence.
