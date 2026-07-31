# Security Policy

## Supported releases

Security fixes are made for the latest published release and for unreleased
code. Backports to older releases are not guaranteed.

## Reporting a vulnerability

Do not open a public issue or discussion for a suspected vulnerability. Use
GitHub's
[private vulnerability reporting](https://github.com/zhangheqi/openiwan/security/advisories/new).
If that channel is unavailable, open a public issue asking the maintainers to
establish private contact, without including technical details.

Please include:

- the affected release or commit, platform, and architecture;
- the impact and required attacker capabilities;
- the smallest synthetic reproduction;
- the affected security boundary, such as credentials, routes, DNS,
  interfaces, or packet handling;
- any known mitigation.

Do not attach live credentials, tokens, callback URLs, private controller
responses, proprietary iWAN binaries, unredacted packet captures, or
identifying production logs.

Maintainers will validate the report privately and coordinate remediation,
release, and disclosure. Response times depend on severity, reproducibility,
and maintainer availability; the project does not provide a fixed service
level.

## Scope

Reports are commonly in scope when they concern:

- parser, fragment-reassembly, or resource-exhaustion vulnerabilities;
- memory-safety or unsafe-code violations;
- credential, token, key, callback, packet, or log disclosure;
- authentication, session, callback-state, PKCE, nonce, controller-signature,
  posture, or device-gate bypasses;
- route, DNS, interface, worker, or credential cleanup failures;
- state-file, lookup-cache, permission, symlink, or canonical-domain issues;
- forwarding target escape, TLS validation bypass, or listener exposure;
- Wintun extraction or loading vulnerabilities.

Protocol limitations that behave exactly as documented, unauthorized testing,
and general weaknesses in third-party identity providers, controllers, DNS
servers, or operating-system credential stores are not vulnerabilities in
OpeniWAN by themselves. An implementation bug that makes a documented
limitation worse remains in scope.

## Security model

OpeniWAN validates framing, lengths, packet classes, session tuples, returned
Segment Routing paths, controller signatures, callback state, and configured
resource limits. Scoped guards restore host-networking state, and secret
material uses redacting or zeroizing owners where practical.

These controls protect the implementation. The confidentiality and integrity
of a connection are still limited by the negotiated iWAN protocol.

### Protocol cryptography

- The control signature is `MD5(header || "mw")` and does not cover the body.
- Traditional XOR and AES-128-ECB data modes provide no authenticated
  integrity or replay protection.
- Segment Routing outer AES is ECB without authentication.
- Password wrapping and session keys follow the interoperability contract,
  rather than current password-authentication best practice.

An on-path attacker with the capabilities implied by these limitations may
observe or modify traffic. Prefer a stronger protocol when the endpoint
supports one.

### Managed authentication

The managed OIDC flow uses the controller response as the source of its
authorization and token endpoints. Those endpoints must use HTTPS, and the
identity result returned by the token endpoint is part of the controller's
trust boundary. OpeniWAN validates the callback origin and path, state, PKCE,
and ID-token nonce before accepting the flow. Operators must therefore trust
the controller configuration and the identity endpoints it selects.

Lookup, controller-auth, configuration, posture, and keepalive requests use
the protocol's HMAC headers. Platform and controller application secrets
embedded for protocol compatibility are distributed client constants. A
server must not treat possession of those constants as proof of a trusted
device.

OIDC access and refresh tokens, controller application secrets, generated
ingress passwords, and Segment Routing keys are redacted from owning types'
debug output and use zeroizing holders where practical.

### Saved state and credentials

Profiles store non-secret connection metadata and opaque credential
references. Passwords and tokens are stored through macOS Keychain, Windows
Credential Manager, or the Unix Secret Service. Controller responses,
generated server credentials, and Segment Routing keys are not written to
profiles.

Profile updates use an inter-process lock and atomic replacement. On Unix,
state directories use mode `0700`, files use `0600`, and symlinked state paths
are rejected. The optional lookup cache contains controller addresses and
customer-domain metadata, so its directory should remain private.

Operating-system credential stores are scoped to a security principal.
Preserving `OPENIWAN_STATE_DIR` through `sudo` does not grant another account
access to saved credentials. Services should use `--non-interactive` so a
locked, revoked, unavailable, or mismatched credential fails instead of
waiting for input.

## Host networking

Creating a TUN interface or changing routes and DNS requires elevated
privileges. OpeniWAN restores replaced state when setup fails or a session
exits normally. A process kill, kernel failure, or operating-system API
failure can still prevent cleanup; operators should know how to inspect and
restore host networking.

Full-tunnel policy protects the active iWAN peer and known managed ingresses
from being routed back into the TUN. Connection-time default routes and
prefixes containing the active peer are reduced to safe CIDR differences.
Profiles reject literal default routes.

DNS policy applies only to traffic visible in the supported userspace packet
path. Physical resolvers are captured before the link-scoped DNS lease and are
used through protected relay sockets. TLS traffic remains end-to-end
encrypted and is not intercepted.

## Route-free forwarding

`forward` binds a loopback listener to one fixed `tcp://`, `http://`, or
`https://` target. Incoming clients cannot choose the destination. The
listener does not authenticate local processes, so any process able to connect
to it can use the configured target.

Raw TCP carries bytes unchanged. For HTTP forwarding, the local side is
plaintext HTTP/1.1, `Host` is rewritten to the fixed target, hop-by-hop headers
are removed, and application headers such as `Authorization` are forwarded
without logging. HTTPS uses the target hostname for SNI and certificate
verification. System trust roots are always loaded; `--ca-cert` only adds
trust anchors.

Active connections and DNS cache behavior are bounded. With
`--resolve tunnel`, name resolution stays in the iWAN userspace path and does
not fall back to the host resolver. DNS replies are checked for transaction
and question consistency, CNAME depth and cache TTLs are bounded, and
truncated UDP replies retry over TCP.

Bind only the required loopback port and stop the forwarder when it is no
longer needed.

## Windows TUN deployment

Official Wintun binaries for the supported Windows architectures are embedded
in the executable. The exact upstream version, checksums, license, and update
procedure are maintained in
[`assets/wintun/README.md`](assets/wintun/README.md).

Before loading the DLL, OpeniWAN validates the versioned LocalAppData cache
against the embedded size and SHA-256, replaces invalid files atomically, and
opens the DLL by absolute path. The `tun` dependency also verifies its
Authenticode signature.

## Logging and diagnostics

Normal logs do not include passwords, tokens, controller application secrets,
Segment Routing keys, authorization headers, or packet contents. Higher
verbosity can still reveal endpoints, domains, line names, routes, timing, and
other private deployment metadata.

Review diagnostic output before sharing it. Prefer a narrowly scoped
`RUST_LOG` filter and a synthetic reproduction.

## Supply chain

The repository commits `Cargo.lock`. CI tests the declared minimum Rust
version and stable Rust on supported desktop platforms, checks Windows ARM64,
and validates the publishable package. Treat dependency and embedded-binary
changes as security-sensitive.
