# USTC Provider Profile

The repository includes the currently observed USTC configuration as a
community-maintained interoperability profile. It is not built into the
`openiwan` executable, and neither USTC nor Panabit endorses or supports this
project. The profile may need updates when the deployment changes.

Use it only with an account and network access you are authorized to use.

## Compatibility Notes

The bundled profile records the behavior currently associated with this
deployment:

- OPENACK may omit the AUTH_VERIFY echo, so
  `require_auth_verify_echo = false`.
- The repeating XOR data cipher uses the first 8 bytes of the derived session
  key, so `xor_key_bytes = 8`.
- Compatible endpoints may use the compact 8-byte heartbeat response.
- `dns_servers` contains the deployment resolver used by the route-free proxy.

These are deployment mappings, not universal properties of the iWAN protocol.
The generic client keeps them explicit so other providers can select their own
compatibility settings.

## Install

Provider files contain controller application material and must be protected
from other local users:

```bash
install -d -m 700 "$HOME/.config/openiwan/providers"
install -m 600 examples/providers/ustc.toml \
  "$HOME/.config/openiwan/providers/ustc.toml"
```

Review [`examples/providers/ustc.toml`](../../examples/providers/ustc.toml)
before installation. On Unix, `openiwan` rejects a provider file that is
readable by its group or other users.

## Fetch and Inspect Lines

Fetch the available lines without elevated privileges:

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

## Connect

Connect interactively, by one-based index, or by a unique exact name:

```bash
sudo openiwan managed \
  --provider "$HOME/.config/openiwan/providers/ustc.toml" \
  connect --line-index 1 --route 10.0.0.0/8
```

Use `all` to fetch, select, and connect in one process. `connect`, `all`, and
`serve` list the available lines before prompting only when neither
`--line-index` nor `--line-name` is provided. Fetch and list do not need
elevated privileges; TUN creation normally does.

## Route-free HTTP(S) Proxy

An existing managed line can run the route-free proxy without creating a TUN
device or changing host routes:

```bash
openiwan managed \
  --provider "$HOME/.config/openiwan/providers/ustc.toml" \
  serve --line-index 1 --upstream https://api.example.edu
```

The managed state must already exist; run `fetch` first when it does not. See
[Managed Providers](../MANAGED_PROVIDERS.md) for state handling, DNS behavior,
route options, and the security model.
