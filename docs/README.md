# Documentation

The technical documentation for `openiwan` is written and reviewed in English.
The root README may have translations, but English is the canonical language
for protocol claims, architecture decisions, security guidance, and
contribution policy.

## Guides

- [Architecture](ARCHITECTURE.md) — crate layout, session lifecycle, trust
  boundaries, and extension points
- [Managed Providers](MANAGED_PROVIDERS.md) — OIDC, controller profiles,
  encrypted state, and managed CLI usage
- [Provider Profiles](providers/README.md) — deployment-specific bundled
  configurations and operational notes
- [iWAN 2.3.0 Client Wire Protocol](IWAN_PROTOCOL_2_3_0.md) — packet, TLV,
  authentication, encryption, heartbeat, and fragmentation formats
- [Reverse-Engineering Evidence and Limitations](REVERSE_ENGINEERING.md) —
  analyzed artifacts, evidence levels, reproducibility, and unknowns
- [Security Policy](../SECURITY.md) — supported versions and private reporting
- [Contributing](../CONTRIBUTING.md) — development workflow and evidence
  requirements

## Documentation Principles

1. Separate observed facts from inference.
2. Name the client version and evidence level behind every protocol claim.
3. Use synthetic examples; never publish credentials or private captures.
4. State compatibility boundaries prominently.
5. Keep commands copyable and avoid environment-specific assumptions.
6. Update the English source before updating translated README files.
7. Isolate deployment-specific names and parameters in provider profiles,
   evidence records, and release history.

API documentation is generated from the Rust source:

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --open
```
