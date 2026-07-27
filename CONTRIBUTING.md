# Contributing to OpeniWAN

Thank you for helping make OpeniWAN a reliable, internationally accessible
interoperability project.

## Project Name

Use **OpeniWAN** for the project name in prose and headings. Use `openiwan`
only for technical identifiers such as the crate, executable, commands, paths,
configuration names, and URLs.

## Before You Start

- Use the issue tracker for bugs, feature proposals, and interoperability
  reports.
- Use the private process in [SECURITY.md](SECURITY.md) for vulnerabilities.
- Keep discussions and technical documentation in English so contributors can
  review one canonical record.
- Only test against systems and networks you are authorized to access.

For a substantial protocol or architecture change, open an issue before
writing the implementation. This gives maintainers and other contributors a
chance to agree on evidence, scope, and interoperability expectations.

## Development Setup

The minimum supported Rust version is 1.88. Current stable Rust is recommended
for development.

The first four commands work in POSIX shells and PowerShell:

```console
cargo test --all-targets --all-features --locked
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo package --locked
```

Generate API documentation in a POSIX shell:

```console
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked
```

In PowerShell:

```powershell
$env:RUSTDOCFLAGS = "-D warnings"; cargo doc --no-deps --all-features --locked; Remove-Item Env:RUSTDOCFLAGS
```

Changes should pass these commands on Linux, macOS, and Windows when they
affect platform networking. Windows networking changes must also compile for
`aarch64-pc-windows-msvc`; privileged smoke tests should verify route cleanup
and prompt shutdown on both IPv4 and IPv6.

## Pull Requests

A focused pull request is easier to review and safer to merge. Please include:

1. the problem being solved
2. the protocol surface and affected platform
3. tests for the new or changed behavior
4. documentation for user-visible or wire-level changes
5. security and cleanup implications

Avoid unrelated formatting or refactoring in the same pull request.

## Protocol Evidence

Wire-level changes require more than a plausible implementation. Follow
[Protocol Provenance](docs/PROTOCOL_PROVENANCE.md) and provide the smallest
reproducible synthetic example.

Acceptable contributions may include:

- independently observed constants or control flow
- synthetic packets and local interoperability endpoints
- redacted traces from an endpoint the contributor is authorized to test
- interoperability results that include the exact client/server versions

Do not submit:

- credentials, tokens, private controller responses, or unredacted captures
- proprietary binaries, non-redistributable source or assets, or copyrighted
  documentation
- unsupported claims based only on symbol names or intuition

Describe uncertainty explicitly. A well-documented unknown is preferable to
an unverified implementation presented as complete.

## Documentation and Translations

English is canonical for source comments, API documentation, technical guides,
community policy, issues, and pull requests.

The root README may be translated using the `README.<locale>.md` naming
convention. A translation should:

- link back to `README.md`
- preserve security warnings and interoperability boundaries
- avoid adding claims absent from the English source
- be updated when the canonical README changes materially

## Deployment-specific Material

Keep general code, tests, examples, and documentation independent of a
particular deployment. Use neutral identifiers, reserved example addresses, and
placeholder domains in examples.

Organization domains, private service or resolver addresses, branded operating
instructions, and deployment-only mappings belong in external documentation or
an accurate provenance record, never in runtime defaults.

Deployment-specific details must remain configurable rather than becoming
runtime defaults. Necessary Panabit protocol attribution and iWAN terminology
are not deployment-specific.

## Code Style

- Prefer small, explicit protocol types over unstructured byte manipulation.
- Keep parsers strict and resource use bounded.
- Avoid logging credentials, session keys, tokens, or packet contents by
  default.
- Preserve route and interface cleanup on every error path.
- Document every `unsafe` block with the invariant that makes it sound.
- Keep public API changes backward-compatible when practical.

## License

By submitting a contribution, you agree that it may be distributed under the
project's [MIT License](LICENSE).
