# Release Process

This is the maintainer checklist for OpeniWAN releases. It exists to keep the
published crate, Git tag, documentation, and changelog consistent.

## Version policy

OpeniWAN follows [Semantic Versioning](https://semver.org/). Before `1.0.0`,
minor releases may contain breaking public API or CLI changes. Those changes
must still be called out explicitly in the changelog.

Documentation on `main` may describe an unreleased version. Released
documentation is immutable under its Git tag.

## Verify the changelog

Start from the most recent release tag, never from the existing changelog
text:

```console
git describe --tags --abbrev=0
git log --oneline --no-merges PREVIOUS_TAG..HEAD
git diff --name-status PREVIOUS_TAG..HEAD
git diff --stat PREVIOUS_TAG..HEAD
```

For every proposed changelog entry:

1. identify the implementing commit and affected files;
2. verify that the behavior is present at `HEAD`;
3. verify that it was absent or different at `PREVIOUS_TAG`;
4. classify it as `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, or
   `Security`;
5. write the user-visible consequence, not the implementation activity.

Do not include formatting, lint-only cleanup, dependency churn without a user
effect, test refactors, or work that was added and removed entirely between
the two release endpoints.

Check removed and renamed CLI options, Cargo features, serialized
configuration, public Rust exports, platform support, and security assumptions
explicitly. These are easy to miss in commit-message summaries.

The changelog follows [Keep a Changelog](https://keepachangelog.com/) and keeps
an `Unreleased` section. A release moves those entries under a version and ISO
date, then updates comparison links at the bottom of the file.

## Pre-release checks

The release commit must have a clean worktree and green CI. Run:

```console
cargo test --all-targets --all-features --locked
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --doc --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked
cargo package --list
cargo package --locked
cargo publish --dry-run --locked
```

Also verify:

- the version in `Cargo.toml` and `Cargo.lock`;
- README examples against the release binary;
- local Markdown links and renamed files;
- the MSRV job and stable job on Linux, macOS, and Windows;
- Windows ARM64 compilation and Windows package installation;
- that the crate contains both Wintun architectures and their license;
- that no credentials, local state, captures, or build artifacts are packaged.

## Publish

After review:

1. merge or commit the release metadata;
2. publish the crate with `cargo publish --locked`;
3. create a signed or annotated `vX.Y.Z` tag at that exact commit;
4. push the tag;
5. create a GitHub release from the matching changelog section;
6. verify crates.io installation and docs.rs generation.

If publishing fails after metadata has been committed, do not move an existing
tag or rewrite a published version. Fix the issue and prepare a new version as
required by the registry.

## Post-release

Create a fresh empty `Unreleased` section and update the comparison link to
start at the new tag. Keep release notes and the changelog semantically
identical even if their formatting differs.
