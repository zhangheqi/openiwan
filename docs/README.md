# Documentation

The root README is the project landing page. Built-in CLI help and generated
Rust API documentation are the authoritative interface references.

Documentation on `main` describes unreleased code; use the corresponding Git
tag when working with a published release.

## Start here

| Document | For | Contents |
|---|---|---|
| [Project README](../README.md) | Everyone | Scope, status, installation, quick start, and support |
| [Command-Line Guide](CLI.md) | CLI users and operators | Commands, privileges, profiles, credentials, forwarding, and automation |
| [Configuration](CONFIGURATION.md) | Operators and integrators | TOML, routing, DNS policy, state, and credential storage |
| [Rust API on docs.rs](https://docs.rs/openiwan) | Library users | Public types, functions, and examples |

## Design and protocol

| Document | For | Contents |
|---|---|---|
| [Managed Connections](MANAGED_CONNECTIONS.md) | Integrators | Lookup, authentication, controller policy, posture, line selection, and keepalive |
| [Architecture](ARCHITECTURE.md) | Contributors | Components, session lifecycle, concurrency, cleanup, and trust boundaries |
| [Protocol Reference](PROTOCOL.md) | Protocol implementers | Traditional, Segment Routing, and managed HTTP wire contracts |
| [Protocol Provenance](PROTOCOL_PROVENANCE.md) | Interoperability contributors | Evidence levels, acceptance criteria, and unresolved areas |

## Project policies

| Document | Purpose |
|---|---|
| [Security Policy](../SECURITY.md) | Private reporting, supported releases, and security boundaries |
| [Contributing](../CONTRIBUTING.md) | Setup, checks, tests, and pull-request expectations |
| [Support](../SUPPORT.md) | Issue and security-reporting channels |
| [Code of Conduct](../CODE_OF_CONDUCT.md) | Community behavior and enforcement |
| [Release Process](RELEASES.md) | Changelog verification and maintainer release checklist |
| [Changelog](../CHANGELOG.md) | Verified user-visible changes between releases |

## Source of truth

- Use `openiwan --help` for the installed command-line interface.
- Use generated API documentation for the installed crate's public Rust API.
- Treat protocol and configuration references as the supported written
  contract.
- Treat tests as executable contract evidence.

If documentation, tests, and behavior disagree, open an issue rather than
preserving the discrepancy as an undocumented compatibility promise.

## Writing documentation

- Document current supported behavior, not implementation history.
- Keep tutorials, operational guidance, architecture, and wire reference
  separate.
- State privileges, secret handling, cleanup, and protocol limitations near
  the affected workflow.
- Use reserved addresses, placeholder domains, neutral identifiers, and
  synthetic data.
- Keep portable commands on one line; label shell-specific examples.
- Update canonical English documentation before translations.
- Verify every changelog entry against the previous release.
- Never publish credentials, tokens, private controller responses,
  proprietary iWAN binaries, or unredacted captures.
