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
- OIDC callback, token, JWKS, or controller-signature validation failures
- managed provider or encrypted-state permission bypasses

The use of MD5, repeating XOR, and AES-ECB is a known property of the legacy
iWAN compatibility protocol. A report should demonstrate an implementation
issue beyond those documented protocol limitations.

## Protocol Limitations

Traditional iWAN cryptography is not modern authenticated encryption. The
control signature does not cover the packet body, and traditional data packets
do not have authenticated integrity. `openiwan` must not be presented as adding
security properties that are absent from the wire protocol.

Use the project only on authorized networks and prefer a stronger protocol when
the endpoint supports one.

## Managed Credentials

Managed provider files contain controller application material and must be
private to their owner. On Unix, `openiwan` rejects provider files accessible by
group or other users. Managed state is written atomically with mode `0600` and
contains only the encrypted line password returned by the controller.

OIDC access tokens and decrypted line passwords stay in memory, are redacted
from debug output, and are zeroized when their owners are dropped. Do not attach
provider files, managed state, callback URLs, tokens, or controller responses to
public reports.

## Windows TUN deployment

The official Wintun 0.14.1 x86_64 and ARM64 binaries and their prebuilt-binary
license are distributed with the crate. Only the active architecture is
embedded in an executable. Before each load, OpenIWAN validates the versioned
LocalAppData cache against the embedded size and SHA-256; replacement uses an
atomic Windows file operation. The `tun` signature-verification feature then
checks the Authenticode signature while loading the DLL by absolute path.

Creating a Wintun adapter or changing routes requires an elevated process.
Commands that do not create TUN state remain usable without elevation.

## Route-free HTTP proxy

The `serve` command accepts only a fixed HTTP or HTTPS origin and a loopback
listen address. For HTTPS, it validates the upstream certificate chain,
hostname, and SNI with system roots plus explicitly supplied CA files. There is
no option to disable HTTPS verification, and the connector cannot select a
destination from an incoming request. An HTTP upstream uses plain TCP and
provides no TLS confidentiality or server authentication.

Organization DNS queries can run through the iWAN userspace stack. The client
checks transaction IDs, response metadata and questions, bounds CNAME depth,
caches positive results with bounded TTLs, and retries truncated UDP replies
over TCP. `auto` rejects host-DNS answers in the common `198.18.0.0/15`
Fake-IP range. `--dns-mode iwan` prohibits host-DNS fallback.

`--upstream-ip` remains an emergency DNS bypass, but does not change the HTTP
Host or, for HTTPS, the SNI or certificate identity. Supplying an address
therefore does not disable or weaken HTTPS certificate verification.

Hop-by-hop headers are removed, while application credentials such as
`Authorization` are forwarded without being logged. The local side is plain
HTTP and is intended only for processes on the same host; browser cookie/SSO,
mTLS, WebSocket, and HTTP/2 behavior are not security claims of this mode.

When an HTTPS upstream is used, TLS protects application payloads even though
the underlying legacy iWAN data plane lacks authenticated encryption. An HTTP
upstream has no such protection. Destination metadata and
traffic patterns remain visible to the iWAN transport. Only the outer iWAN UDP
socket necessarily uses the host's existing routes and may be affected by
another VPN.
