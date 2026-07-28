# Contributing to OpeniWAN

Thank you for contributing to OpeniWAN. Bug fixes, portability improvements,
documentation, tests, and reproducible interoperability evidence are welcome.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

- Read [SUPPORT.md](SUPPORT.md) and use the matching issue template.
- Report vulnerabilities privately through [SECURITY.md](SECURITY.md).
- Search existing issues and pull requests.
- Use only systems and networks you are authorized to test.
- Keep credentials, tokens, private controller responses, proprietary iWAN
  binaries, and unredacted captures out of the repository.

Open an issue before implementing a substantial protocol, public API,
architecture, dependency, or cross-platform networking change. Small bug
fixes, tests, and documentation corrections can go directly to a focused pull
request.

## Project language and naming

English is canonical for source comments, Rust API documentation, technical
guides, community policy, issues, and pull requests. Translated root READMEs
are welcome.

Use **OpeniWAN** for the project name in prose and headings. Use `openiwan`
for the crate, executable, commands, paths, configuration keys, and URLs.

## Development setup

The minimum supported Rust version is 1.88. Stable Rust is recommended for
development.

Clone and run the primary checks:

```console
git clone https://github.com/zhangheqi/openiwan.git
cd openiwan
cargo test --all-targets --all-features --locked
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --doc --all-features --locked
```

Build documentation and the publishable package:

```console
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked
cargo package --locked
```

PowerShell:

```powershell
$env:RUSTDOCFLAGS = "-D warnings"; cargo doc --no-deps --all-features --locked; Remove-Item Env:RUSTDOCFLAGS
```

Do not update `Cargo.lock` unless the dependency graph or package version
intentionally changes.

## Test expectations

Every behavior change needs tests at the lowest useful layer:

- exact byte vectors for framing, crypto, signatures, and canonical requests;
- parser tests for valid, invalid, truncated, oversized, and unknown input;
- synthetic transports and endpoints for authentication and controller flows;
- lifecycle tests for reconnect, shutdown, rollback, and stale state;
- CLI parsing tests for command and option changes;
- platform tests for TUN, route, DNS, and credential-store behavior where
  practical.

Networking changes must consider Linux, macOS, Windows x86_64, and Windows
ARM64. CI tests Rust 1.88 and stable on Linux, macOS, and Windows, compiles
Windows ARM64, installs the Windows package, and runs formatting, Clippy,
rustdoc, and package checks.

Privileged smoke tests should verify prompt shutdown and restoration of every
route, DNS, and interface change. Do not run them against production networks
without explicit authorization.

## Protocol evidence

Wire-level changes require evidence, not a plausible field name or inferred
schema. Read [Protocol Provenance](docs/PROTOCOL_PROVENANCE.md) before changing
packet bytes, controller signing, cryptography, timing, or state transitions.

A protocol contribution should identify:

1. the exact protocol surface;
2. the evidence level;
3. the peer or client version when known;
4. the smallest reproducible input;
5. expected bytes or state transition;
6. remaining uncertainty and deployment assumptions.

Acceptable evidence includes independent protocol analysis, cross-checks
against multiple implementations, synthetic local endpoints, and authorized
real-endpoint observations. Redact real data and prefer synthetic vectors in
the repository.

## Code guidelines

- Keep parsing strict and resource use bounded.
- Use explicit types at protocol and trust boundaries.
- Preserve the distinction between traditional and Segment Routing framing.
- Never log credentials, tokens, session keys, controller secrets, or packet
  contents by default.
- Use zeroizing owners for secret material.
- Preserve route, DNS, interface, credential, and worker cleanup on every
  return path.
- Avoid shell interpolation for platform commands; pass arguments separately.
- Document the invariant of every `unsafe` block.
- Add `Errors`, `Panics`, and `Safety` sections to public API docs where
  applicable.
- Prefer a focused change over unrelated refactoring or formatting.

Public API compatibility matters even before `1.0`. If a break is necessary,
explain the user impact and record it in the changelog.

## Documentation

The [documentation index](docs/README.md) defines each document's purpose and
authority. User-visible behavior changes must update:

- built-in CLI help when commands or options change;
- the relevant user guide or reference;
- English README and translated README when project-level guidance changes;
- protocol reference and provenance for wire changes;
- security policy when assumptions or secret handling change;
- changelog when users need to act or can observe a difference.

Examples must use reserved IP ranges and placeholder domains. Keep commands
single-line when they are intended to work unchanged in POSIX shells and
PowerShell.

## Changelog policy

Changelog entries describe differences from the latest release tag, not the
work performed in an individual commit. Use the categories and verification
procedure in [Release Process](docs/RELEASES.md).

Do not add lint-only cleanup, formatting, test refactors, or intermediate work
that is absent from both release endpoints. Explicitly call out removed or
renamed CLI options, Cargo features, serialized fields, public APIs, and
security assumptions.

## Pull requests

A pull request should contain:

1. a concise problem statement and rationale;
2. the affected protocol surface and platforms;
3. tests for changed behavior;
4. documentation and changelog updates where required;
5. security, resource, and cleanup considerations;
6. commands used for validation.

Keep commits reviewable and avoid mixing unrelated changes. Maintainers may
request changes when evidence, tests, portability, or documentation are
insufficient.

## Deployment-specific material

General code, tests, examples, and documentation must remain independent of a
particular deployment. Use neutral identifiers, reserved example addresses,
and placeholder domains.

Organization domains, private resolver addresses, branded operating
instructions, and deployment-only mappings belong in external documentation
or a precise provenance record. Necessary iWAN protocol attribution is not
deployment-specific.

## License

By submitting a contribution, you agree that it may be distributed under the
project's [MIT License](LICENSE).
