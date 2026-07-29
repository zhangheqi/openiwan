# Security Policy

## Supported versions

| Version | Security support |
|---|---|
| Latest published release | Fixes are provided |
| `main` / unreleased | Issues are fixed before release |
| Older releases | No guaranteed backports |

Use `openiwan --version` and the matching Git tag when assessing an issue.

## Report a vulnerability

Do not open a public issue or discussion for a suspected vulnerability.

Use GitHub's
[private vulnerability reporting](https://github.com/zhangheqi/openiwan/security/advisories/new).
If that channel is unavailable, open a public issue asking maintainers to
establish private contact without including technical details.

Include:

- affected version, commit, platform, and architecture;
- impact and required attacker capabilities;
- the smallest synthetic reproduction;
- whether credentials, routes, DNS, interfaces, or packet contents are
  exposed;
- any known mitigation;
- your preferred disclosure timeline, if relevant.

Do not attach live credentials, tokens, callback URLs, private controller
responses, lookup caches, proprietary iWAN binaries, unredacted packet
captures, or identifying production logs.

Maintainers will validate the report privately, coordinate remediation and
release timing, and credit reporters who want attribution. Response and fix
times depend on severity, reproducibility, and maintainer availability; this
project does not promise a fixed service level.

## Scope

Useful reports include:

- parser, fragment-reassembly, or resource-exhaustion vulnerabilities;
- memory-safety or unsafe-code violations;
- credential, token, key, callback, or log disclosure;
- authentication, session-tuple, OIDC-state, PKCE, or nonce bypasses;
- controller-signature, generated-credential, posture, or device-gate bypasses;
- route, DNS, interface, worker, or credential cleanup failures;
- lookup-cache poisoning, permission, symlink, or canonical-domain issues;
- forwarding target escape, TLS validation bypass, or listener exposure;
- Windows Wintun extraction or loading vulnerabilities.

The following are not vulnerabilities by themselves:

- cryptographic limitations inherent to the documented iWAN wire protocol;
- a deployment rejecting an unsupported or undocumented protocol variant;
- use against systems without authorization;
- general weaknesses in a third-party identity provider, controller, DNS
  server, or operating-system credential service;
- disclosure of information the operator explicitly chose to log or publish.

An implementation bug that makes a documented protocol limitation worse is
still in scope.

## Security model

OpeniWAN validates framing, lengths, packet classes, session tuples, returned
Segment Routing paths, controller signatures, callback state, and configured
resource limits. It uses rollback guards for host networking and zeroizing
owners for secret material.

These controls protect the implementation; they do not turn iWAN into a modern
authenticated VPN.

### Protocol cryptography

- The control signature is `MD5(header || "mw")` and does not cover the body.
- Traditional XOR and AES-128-ECB data modes provide no authenticated
  integrity or replay protection.
- Segment Routing outer AES is ECB without authentication.
- Password wrapping and session keys follow the interoperability contract,
  not current password-authentication best practice.

An on-path attacker with the capabilities implied by those protocol
limitations may observe or modify traffic. Prefer a stronger protocol when the
endpoint supports one.

### Managed authentication

OIDC access and refresh tokens, controller app secrets, generated ingress
passwords, and Segment Routing keys are redacted from owning types' debug
output and use zeroizing holders where practical.

Controller-supplied authorization and token endpoints are used directly.
OpeniWAN checks callback origin/path, state, PKCE, and the ID-token nonce. It
does not perform mandatory OIDC discovery or JWKS signature verification; the
identity result therefore depends on the HTTPS controller configuration and
token endpoint. This is an explicit interoperability boundary, not a general
OIDC-client security claim.

Lookup, controller-auth, configuration, posture, and keepalive requests use
the documented HMAC headers. Platform and controller app secrets embedded for
protocol compatibility are distributed client constants, not confidential
per-user credentials. Servers must not treat their possession as proof of a
trusted device.

### Saved state and credentials

Profiles contain non-secret domain, Device ID, username, line, DNS, and opaque
credential-reference data. They never contain passwords, access tokens,
refresh tokens, controller responses, generated server credentials, or
Segment Routing keys.

Profile updates use an inter-process lock and atomic replacement. Unix
directories use mode `0700`, files use `0600`, and symlinked state paths are
rejected. The optional seven-day lookup cache contains controller addresses
and customer-domain metadata; keep its directory private.

`managed login` stores verified passwords or OIDC refresh tokens in macOS
Keychain, Windows Credential Manager, or the Unix Secret Service.
Operating-system credential stores are scoped to a security principal.
Preserving `OPENIWAN_STATE_DIR` through `sudo` does not make another account's
saved credential available.

Use `--non-interactive` for services so unavailable, locked, revoked, or
mismatched authentication fails instead of waiting on input.

## Host networking

Creating TUN or changing routes and DNS requires elevated privileges. OpeniWAN
uses scoped guards and restores replaced state when a session exits or setup
fails. A process kill, kernel failure, or operating-system API failure can
still prevent cleanup; operators should know how to inspect and restore host
networking.

Full-tunnel policy excludes the active iWAN peer and known managed ingresses
to avoid routing the UDP transport into its own TUN. Default routes supplied
directly by users are rejected.

Platform DNS is installed through a link-scoped lease. Physical resolvers are
captured before the lease and used through protected relay sockets. Split-DNS
and encrypted-DNS behavior applies only to traffic visible in the supported
packet path:

- visible TCP/UDP port 853 can be dropped;
- configured DoH hostnames can receive NXDOMAIN over UDP/53;
- TLS is not intercepted;
- general DoH, HTTP/3, QUIC, and IP-based blocking are not provided.

## Route-free forwarding

`forward` accepts one fixed `tcp://`, `http://`, or `https://` target and a
loopback listener. The destination cannot be selected by an incoming client.
The listener does not authenticate local processes; any process able to
connect can use the configured target.

Raw TCP carries bytes unchanged and does not inspect or authenticate the
application protocol. End-to-end TLS remains the responsibility of the local
client and target.

For HTTP(S):

- the local side is plaintext HTTP/1.1;
- `Host` is rewritten to the fixed target;
- hop-by-hop headers are removed;
- application headers such as `Authorization` are forwarded without logging;
- incoming `CONNECT`, WebSocket/Upgrade, and HTTP/2 are unsupported;
- HTTPS uses the target host for SNI and certificate verification;
- system roots are always loaded, and `--ca-cert` can add trust anchors;
- certificate verification cannot be disabled.

The listener is capped at 256 active connections. Bind only the required
loopback port and stop the forwarder when it is no longer needed.

Target resolution with `--resolve system` exposes the hostname to the host
resolver. `--resolve tunnel` keeps lookup in the iWAN userspace path and does
not fall back to the host. DNS replies are checked for transaction and
question consistency, CNAME depth is bounded, cache TTLs are bounded, and
truncated UDP replies retry over TCP.

## Windows TUN deployment

The upstream Wintun 0.14.1 x86_64 and ARM64 binaries and their license are
distributed with the crate. Only the active architecture is embedded in an
executable.

Before loading, OpeniWAN validates the versioned LocalAppData cache against
the embedded size and SHA-256, replaces it atomically, and opens the DLL by
absolute path. The `tun` crate's signature-verification feature checks its
Authenticode signature.

## Logging and diagnostics

Normal logs do not include passwords, tokens, controller app secrets, Segment
Routing keys, authorization headers, or packet contents. Higher verbosity can
still reveal endpoints, domains, line names, routes, timing, or other private
deployment metadata.

Review diagnostic output before sharing it. Prefer the smallest scoped
`RUST_LOG` filter and synthetic reproduction.

## Supply-chain notes

The repository commits `Cargo.lock`, tests the minimum Rust version and stable
Rust across supported desktop platforms, builds Windows ARM64, and validates
the publishable package in CI. Review dependency and embedded-binary changes
as security-sensitive changes.
