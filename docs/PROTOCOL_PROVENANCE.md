# Protocol Provenance and Interoperability Evidence

OpeniWAN is an independent implementation of the iWAN protocol. Its wire
profile is based on independent protocol analysis, authorized interoperability
tests, and reproducible byte vectors. No proprietary iWAN source code, client
binaries, credentials, or private captures are distributed with the project.

The repository does include redistributable Wintun binaries and their license
for Windows TUN support; they are unrelated to iWAN protocol evidence.

The evidence set covers:

- packet and TLV registries;
- control framing and MD5 signatures;
- password wrapping and session ciphers;
- OPEN/ACK/REJECT handling;
- traditional and SR fragmentation;
- SR headers, encryption, reassembly, and monitoring;
- lookup and controller request authentication;
- OIDC and controller configuration flows;
- keepalive serializers and HMAC signing.

Repository tests exercise byte vectors for OPEN, ping, signed close, XOR,
traditional AES, SR headers, SR fragment words, SR outer AES, and keepalive
HMAC.

## Evidence levels

Issue templates and reviews use these labels:

| Label | Evidence | Typical artifact |
|---|---|---|
| `S` | Independent protocol analysis | Reproducible field or control-flow analysis |
| `C` | Independent cross-check | Agreement between implementations or observations |
| `L` | Synthetic local endpoint | Deterministic request/response test |
| `R` | Authorized real endpoint | Redacted observation with exact versions |

An evidence label records how a claim was established; it is not a quality
score. Claims with deployment-specific assumptions must say so regardless of
level.

## Acceptance criteria

A protocol behavior may enter the implementation when at least one of these
conditions is met:

1. a reproducible wire capture establishes the bytes and state transition;
2. multiple interoperable implementations agree on the behavior;
3. clean-room analysis establishes the behavior and a synthetic vector tests
   it;
4. an authorized server test confirms the behavior.

The evidence must identify its level, protocol surface, smallest reproducer,
expected bytes or state transition, peer version when known, and any
deployment-specific assumptions. Plausible field names, symbol names, or
schemas are not sufficient.

## Current protocol boundaries

The following server-side or deployment-specific details are not defined by
the OpeniWAN profile:

1. authoritative `DUP_PKT` scheduling;
2. use of `NETMASK` by other clients;
3. preferred server construction of `OPEN_REJECT`;
4. semantic names for SR monitor marker bits;
5. relay-side SR path mutation;
6. deployment-specific nested `/config` policy schemas;
7. server requirements for signed versus header-only `CLOSE`;
8. duplicate suppression policy.

Changes in these areas require new interoperability evidence and an update to
[PROTOCOL.md](PROTOCOL.md).

## Contribution requirements

Protocol reports should include:

- Panabit iWAN software or component and version, or `Unknown` when it cannot
  be determined;
- OpeniWAN version and platform when OpeniWAN was part of the observation or
  comparison;
- evidence level (`S`, `C`, `L`, or `R`);
- a minimal synthetic reproducer;
- redacted packet bytes or structured traces;
- expected and actual behavior.

Never commit credentials, tokens, callback URLs, private controller responses,
proprietary iWAN binaries, non-redistributable source, or unredacted captures.

When an observation changes the supported contract, update the implementation
tests, [Protocol Reference](PROTOCOL.md), relevant security boundary, and
changelog together.
