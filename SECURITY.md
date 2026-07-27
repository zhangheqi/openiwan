# Security Policy

## Supported Versions

Security fixes are provided for the latest released version. Older releases may
receive a fix when the change can be backported safely, but this is not
guaranteed.

| Version | Supported |
|---|---|
| Latest release | Yes |
| Earlier releases | Best effort |
| Unreleased development code | Case by case |

## Reporting a Vulnerability

Do not open a public issue for a suspected vulnerability.

Use the repository host's private vulnerability-reporting feature when it is
available. Otherwise, contact the maintainers through a private channel
published by the repository. If no private channel is available, open a public
issue that asks for private contact without including technical details.

Please include:

- the affected version, commit, and platform
- the impact and required attacker capabilities
- a minimal synthetic datagram, test, or reproduction
- whether credentials, routes, or interface state are exposed
- any proposed mitigation

Do not attach live credentials, private controller responses, unredacted packet
captures, or proprietary binaries.

Maintainers should acknowledge a report promptly, establish a private
coordination channel, and provide status updates while validating and fixing
the issue. Disclosure timing should be agreed with the reporter when practical.

## Security Scope

Reports are especially useful for:

- parser or fragment-reassembly vulnerabilities
- memory-safety or unsafe-code issues
- credential, key, token, or log disclosure
- route or interface cleanup failures
- session validation bypasses
- command invocation or privilege-boundary problems
- OIDC callback, token, or controller-configuration validation failures
- lookup cache poisoning, permission, or canonical-domain validation failures

The use of MD5, repeating XOR, and AES-ECB is a known property of the iWAN
wire protocol. A report should demonstrate an implementation
issue beyond those documented protocol limitations.

## Protocol Limitations

Traditional iWAN cryptography is not modern authenticated encryption. The
control signature does not cover the packet body, and traditional data packets
do not have authenticated integrity. OpeniWAN must not be presented as adding
security properties that are absent from the wire protocol.

Use the project only on authorized networks and prefer a stronger protocol when
the endpoint supports one.

## Managed Credentials

OIDC access and refresh tokens, caller-supplied keepalive secrets, SR keys, and
ingress passwords stay in memory, are redacted from owning types' debug output,
and use zeroizing holders where applicable. OpeniWAN does not persist controller
responses or OIDC sessions. The optional seven-day lookup cache contains only
domain discovery data and is replaced atomically; choose a private cache
directory because controller addresses and customer-domain metadata may still
be sensitive. Do not attach callback URLs, tokens, credentials, caches, or
controller responses to public reports.

The protocol uses platform-wide lookup credentials and a controller-app-ID
secret-selection rule to sign lookup, controller-auth, and controller-config
requests. These are distributed client constants, not confidential per-user
credentials. Servers must not treat possession of them as proof of a trusted
device. OIDC `/config` uses both `X-Auth-*` headers and a Bearer token.

OpeniWAN uses controller-supplied authorization and token endpoints directly.
It checks callback state, redirect URI, PKCE, and ID-token nonce, but does not
perform a mandatory discovery or JWKS request. Authenticity therefore depends
on the HTTPS controller configuration and token endpoint.

## Windows TUN deployment

The upstream Wintun 0.14.1 x86_64 and ARM64 binaries and their prebuilt-binary
license are distributed with the crate. Only the active architecture is
embedded in an executable. Before each load, OpeniWAN validates the versioned
LocalAppData cache against the embedded size and SHA-256; replacement uses an
atomic Windows file operation. The `tun` signature-verification feature then
checks the Authenticode signature while loading the DLL by absolute path.

Creating a Wintun adapter or changing routes requires an elevated process.
Commands that do not create TUN state remain usable without elevation.

## Route-free forwarding

The `forward` command accepts one fixed URI target and a loopback listen
address. Bare `HOST:PORT` values are rejected: `tcp://HOST:PORT` selects raw
TCP, while `http://HOST[:PORT]` and `https://HOST[:PORT]` select an HTTP/1.1
reverse proxy with default ports 80 and 443. The destination cannot be selected
from an incoming connection. The target URI's host fixes the upstream name or
address and, for HTTPS, the TLS identity.

For a `tcp://` target, each accepted connection carries arbitrary bytes
unchanged in both directions through the iWAN userspace TCP/IP stack. OpeniWAN
does not inspect the application protocol, terminate TLS, or verify the
target's application-level identity.

For HTTP(S), the local side is always plaintext HTTP/1.1. The proxy rewrites
`Host` to the fixed target authority and removes hop-by-hop headers. Application
credentials such as `Authorization` are forwarded without being logged.
Incoming `CONNECT`, WebSocket and other HTTP Upgrade requests, and HTTP/2 are
not supported.

An `https://` domain target uses the target hostname for SNI and certificate
verification. An IP literal is verified as an IP certificate identity. System
roots are always loaded, and repeatable `--ca-cert` files can add private trust
anchors; adding one expands the set of trusted issuers. There is no option to
disable verification, and `--ca-cert` is rejected for `tcp://` and `http://`
targets. An `http://` target uses unencrypted TCP inside iWAN and provides no
TLS confidentiality or server authentication.

Organization DNS queries can run through the iWAN userspace stack. The client
checks transaction IDs, response metadata and questions, bounds CNAME depth,
caches positive results with bounded TTLs, and retries truncated UDP replies
over TCP. `auto` uses an iWAN resolver when one is configured and otherwise
uses the host resolver. `--dns-mode iwan` prohibits host-DNS fallback, while
`--dns-mode system` explicitly exposes the target hostname to the host
resolver. `--dns-timeout-ms` bounds each resolver attempt, while
`--connect-timeout-ms` bounds the complete DNS, TCP, and, for HTTPS, TLS setup.

A literal IPv4 or bracketed IPv6 address in the target URI bypasses DNS. With
HTTPS it remains the certificate identity and must be covered by the upstream
certificate; it does not disable or weaken verification.

The loopback listener is intended only for processes on the same host, but it
does not authenticate local clients. Any process that can connect to the
listener can exchange bytes with a TCP target or issue HTTP requests to the
configured origin. Bind only the required port and stop the forwarder when it
is no longer needed. Browser cookie/SSO and mTLS behavior are not security
claims of this mode. The forwarder caps active connections at 256 and closes
newly accepted sockets while at capacity.

For raw TCP, application-level confidentiality, integrity, and server
authentication remain the responsibility of the local client and target
service; end-to-end TLS passes through unchanged when those endpoints use it.
For an HTTPS target, the proxy's upstream TLS protects the HTTP payload. HTTP
and non-TLS TCP targets receive no such protection from the iWAN data
plane, which does not add modern authenticated encryption. Destination
metadata and traffic patterns remain visible to the iWAN transport. Only the
outer iWAN UDP socket necessarily uses the host's existing routes and may be
affected by another VPN.
