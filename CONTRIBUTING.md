# Contributing to openiwan

Thank you for helping make `openiwan` a reliable, internationally accessible
interoperability project.

## Before You Start

- Use the issue tracker for bugs, feature proposals, and compatibility reports.
- Use the private process in [SECURITY.md](SECURITY.md) for vulnerabilities.
- Keep discussions and technical documentation in English so contributors can
  review one canonical record.
- Only test against systems and networks you are authorized to access.

For a substantial protocol or architecture change, open an issue before
writing the implementation. This gives maintainers and other contributors a
chance to agree on evidence, scope, and compatibility expectations.

## Development Setup

The minimum supported Rust version is 1.85. Current stable Rust is recommended
for development.

```bash
cargo test --all-targets --all-features
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo package
```

Changes should pass these commands on both Linux and macOS when they affect
platform networking.

## Pull Requests

A focused pull request is easier to review and safer to merge. Please include:

1. the problem being solved
2. the compatibility target and affected platform
3. tests for the new or changed behavior
4. documentation for user-visible or wire-level changes
5. security and cleanup implications

Avoid unrelated formatting or refactoring in the same pull request.

## Protocol Evidence

Wire-level changes require more than a plausible implementation. State the
evidence level described in
[docs/REVERSE_ENGINEERING.md](docs/REVERSE_ENGINEERING.md) and provide the
smallest reproducible synthetic example.

Acceptable contributions may include:

- independently observed constants or control flow
- synthetic packets and local compatibility endpoints
- redacted traces from an endpoint the contributor is authorized to test
- interoperability results that include the exact client/server versions

Do not submit:

- credentials, tokens, private controller responses, or unredacted captures
- proprietary binaries, decompiled source, vendor assets, or copyrighted
  documentation
- claims of compatibility based only on symbol names or speculation

Describe uncertainty explicitly. A well-documented unknown is preferable to
an unverified implementation presented as complete.

## Documentation and Translations

English is canonical for source comments, API documentation, technical guides,
community policy, issues, and pull requests.

The root README may be translated using the `README.<locale>.md` naming
convention. A translation should:

- link back to `README.md`
- preserve security warnings and compatibility boundaries
- avoid adding claims absent from the English source
- be updated when the canonical README changes materially

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
