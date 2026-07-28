# Documentation

The technical documentation for OpeniWAN is written and reviewed in English.
The root README may have translations, but English is the canonical language
for protocol claims, architecture decisions, security guidance, and
contribution policy.

## Guides

- [Architecture](ARCHITECTURE.md) — crate layout, session lifecycle, trust
  boundaries, and extension points
- [Managed Connections](MANAGED_CONNECTIONS.md) — lookup, auth selection, OIDC,
  `/config`, posture, ingress selection, and keepalive contracts
- [Protocol Reference](PROTOCOL.md) — traditional, SR, controller, and
  keepalive wire contracts
- [Protocol Provenance](PROTOCOL_PROVENANCE.md) — interoperability evidence,
  reproducibility, and unresolved details
- [Security Policy](../SECURITY.md) — supported versions and private reporting
- [Contributing](../CONTRIBUTING.md) — development workflow and evidence
  requirements

## Documentation Principles

1. Describe the supported contract rather than implementation history.
2. Record protocol evidence in the provenance document.
3. Use synthetic examples; never publish credentials or private captures.
4. State protocol and security boundaries prominently.
5. Keep commands single-line or provide explicit POSIX and PowerShell forms.
6. Update the English source before updating translated README files.
7. Keep deployment-specific names and parameters out of the repository unless
   they are part of a reproducible evidence record.

API documentation is generated from the Rust source:

POSIX shell:

```console
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --open
```

PowerShell:

```powershell
$env:RUSTDOCFLAGS = "-D warnings"; cargo doc --no-deps --all-features --open; Remove-Item Env:RUSTDOCFLAGS
```
