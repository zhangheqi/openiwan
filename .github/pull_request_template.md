## Summary

Describe the problem and the change.

## Interoperability and evidence

- Panabit iWAN client, server, or controller version:
- Evidence level, if this changes the wire protocol:
- Platforms tested:

## Validation

- [ ] Tests cover the change.
- [ ] `cargo fmt --all -- --check` passes.
- [ ] `cargo clippy --all-targets --all-features --locked -- -D warnings` passes.
- [ ] `cargo test --doc --all-features --locked` passes.
- [ ] `cargo doc --all-features --no-deps --locked` passes.
- [ ] Documentation is updated in English.
- [ ] `CHANGELOG.md` describes only user-visible differences from the previous release, or no changelog entry is needed.
- [ ] No credentials, tokens, private captures, proprietary binaries, or
      non-redistributable source are included.
- [ ] Route, interface, credential, and error cleanup paths were considered.
