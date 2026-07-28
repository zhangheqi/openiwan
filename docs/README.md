# Documentation

OpeniWAN documentation is organized by task and authority. The root README is
the project landing page; built-in CLI help and Rust API documentation are the
authoritative interface references.

Unless a document says otherwise, files on `main` describe the unreleased
interface. Use the matching Git tag for a published version.

## Start here

| Document | Audience | Contents |
|---|---|---|
| [Project README](../README.md) | Everyone | Scope, status, installation, quick start, and support |
| [Command-Line Guide](CLI.md) | CLI users and operators | Commands, credentials, privileges, profiles, forwarding, and automation |
| [Configuration](CONFIGURATION.md) | Operators and integrators | TOML, routing, DNS policy, state, and credential storage |
| [Rust API on docs.rs](https://docs.rs/openiwan) | Library users | Public types, functions, and examples |

## Concepts and internals

| Document | Audience | Contents |
|---|---|---|
| [Managed Connections](MANAGED_CONNECTIONS.md) | Integrators | Lookup, authentication, controller policy, posture, line selection, and keepalive |
| [Architecture](ARCHITECTURE.md) | Contributors | Components, session lifecycle, concurrency, cleanup, and trust boundaries |
| [Protocol Reference](PROTOCOL.md) | Protocol implementers | Traditional, Segment Routing, and managed HTTP wire contracts |
| [Protocol Provenance](PROTOCOL_PROVENANCE.md) | Interoperability contributors | Evidence levels, acceptance criteria, and unresolved areas |

## Project policies

| Document | Purpose |
|---|---|
| [Security Policy](../SECURITY.md) | Private reporting, supported versions, and security boundaries |
| [Contributing](../CONTRIBUTING.md) | Development setup, review requirements, tests, and documentation style |
| [Support](../SUPPORT.md) | Where to ask questions or report bugs, interoperability issues, and vulnerabilities |
| [Code of Conduct](../CODE_OF_CONDUCT.md) | Community behavior and enforcement |
| [Release Process](RELEASES.md) | Changelog verification and maintainer release checklist |
| [Changelog](../CHANGELOG.md) | Curated user-visible changes by version |

## Documentation authority

When sources disagree, use this order:

1. tests and implementation for actual behavior;
2. built-in `--help` for the installed CLI;
3. generated Rust API documentation for the installed crate version;
4. protocol and configuration references from the matching Git tag;
5. translated or overview material.

Open an issue when documentation and behavior disagree. Do not silently
preserve obsolete behavior as a compatibility claim.

## Writing principles

1. Document the supported contract, not implementation history.
2. Separate tutorials, operational guidance, architecture, and wire
   reference.
3. Use reserved example addresses and placeholder domains.
4. State privileges, secret handling, cleanup, and protocol limitations near
   the affected workflow.
5. Keep shell examples single-line when they must work unchanged in POSIX
   shells and PowerShell; label shell-specific examples.
6. Update English canonical documentation before translations.
7. Verify every changelog entry against the previous release tag.
8. Never publish credentials, tokens, private controller responses,
   proprietary iWAN binaries, or unredacted captures.
