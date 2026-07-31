# Contributing to OpeniWAN

Thank you for contributing. Bug fixes, portability improvements,
documentation, tests, and reproducible interoperability evidence are welcome.
By participating, you agree to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

- Search existing issues and pull requests.
- Use the appropriate channel in [SUPPORT.md](SUPPORT.md).
- Report vulnerabilities privately as described in
  [SECURITY.md](SECURITY.md).
- Test only systems and networks you are authorized to use.
- Keep credentials, tokens, private controller responses, proprietary iWAN
  binaries, and unredacted captures out of the repository.

Open an issue before starting a substantial protocol, public API,
architecture, dependency, or cross-platform networking change. Small,
well-scoped fixes can go directly to a pull request.

## Development setup

Install Rust with Cargo. The minimum supported Rust version is defined by
`package.rust-version` in [`Cargo.toml`](Cargo.toml); stable Rust is
recommended for development.

```console
git clone https://github.com/zhangheqi/openiwan.git
cd openiwan
cargo test --all-targets --all-features --locked
```

Do not update `Cargo.lock` unless the dependency graph or package version is
changing intentionally.

## Checks

Run the checks relevant to your change. Before submitting a pull request,
run the full local set when your platform supports it:

```console
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo test --doc --all-features --locked
cargo doc --all-features --no-deps --locked
cargo package --locked
```

CI runs the test suite with the declared minimum Rust version and stable Rust
on Linux, macOS, and Windows. It also checks the Windows ARM64 target,
documentation, formatting, Clippy, and the packaged crate.

## Tests

Add tests at the lowest useful layer and assert the supported contract. The
current suite covers:

- wire framing, cryptography, signatures, parsing bounds, and fragment
  reassembly with exact or synthetic vectors;
- managed lookup, authentication, controller configuration, posture, and
  keepalive state transitions with synthetic endpoints;
- CLI parsing, profiles, saved state, and credential handling;
- TUN, route, DNS, worker, and rollback behavior where platform APIs permit;
- TCP and HTTP forwarding, tunnel-side resolution, limits, and cleanup.

Behavior changes should cover success, rejection, boundary, and cleanup paths
where applicable. Networking changes must consider Linux, macOS, Windows
x86_64, and Windows ARM64. Privileged smoke tests must use authorized,
non-production systems and verify restoration of every route, DNS, and
interface change.

Wire-level changes require reproducible evidence. Follow
[Protocol Provenance](docs/PROTOCOL_PROVENANCE.md) and include the affected
surface, evidence level, smallest reproducible input, expected bytes or state
transition, and remaining uncertainty. Prefer synthetic fixtures and redact
all real deployment data.

## Implementation guidelines

- Keep parsers strict and resource use bounded.
- Use explicit types at protocol and trust boundaries.
- Preserve cleanup on every route, DNS, interface, credential, and worker
  return path.
- Never log credentials, tokens, session keys, controller secrets, or packet
  contents by default.
- Use zeroizing owners for secret material.
- Pass platform-command arguments directly instead of using shell
  interpolation.
- Document the invariant of every `unsafe` block.
- Keep changes focused and avoid unrelated refactoring.

Treat the public API as compatibility-sensitive. Explain necessary breaking
changes and their user impact.

## Documentation and changelog

Update user-facing documentation, CLI help, Rust API docs, protocol reference,
or security policy when the corresponding contract changes. English
documentation is canonical; translated root READMEs should follow
project-level changes.

Changelog entries must describe user-visible differences from the previous
release, not intermediate commits. Verify each entry against the previous
release tag and follow [Release Process](docs/RELEASES.md). Formatting,
test-only refactors, and changes absent from both release endpoints do not
need entries.

Use reserved IP ranges, placeholder domains, and neutral identifiers in
examples.

## Pull requests

A pull request should include:

1. the problem and rationale;
2. the affected protocol surface and platforms;
3. tests for changed behavior;
4. documentation and changelog updates when needed;
5. security, resource-limit, and cleanup considerations;
6. the commands used for validation.

Keep commits reviewable and avoid mixing unrelated changes. Maintainers may
ask for more evidence, tests, portability work, or documentation before
merging.

Use **OpeniWAN** for the project name in prose. Use `openiwan` for the crate,
executable, commands, paths, configuration keys, and URLs.

## License

By submitting a contribution, you agree that it may be distributed under the
project's [MIT License](LICENSE).
