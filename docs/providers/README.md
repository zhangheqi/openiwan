# Provider Profiles

This directory contains deployment-specific configuration and operational
guidance. Provider profiles remain external TOML files: OpeniWAN does not
compile organization parameters into the executable.

Profiles are community-maintained interoperability material, not an endorsement
or support commitment from Panabit, an identity provider, or a deployment
operator. Parameters may change independently of OpeniWAN; review a profile
before installing it and validate it only against endpoints you are authorized
to use.

## Available Profiles

- [USTC](USTC.md) — bundled configuration, managed login, connection, proxy,
  and observed compatibility notes

For the provider schema and security model, see
[Managed Providers](../MANAGED_PROVIDERS.md). To prepare a new profile, start
from [`examples/providers/example.toml`](../../examples/providers/example.toml)
and replace every placeholder.
