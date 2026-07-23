# Reverse-Engineering Evidence and Limitations

This document records how the protocol reference was produced, which claims
are directly supported, and which questions remain open.

## Scope and Ethics

Analysis was performed on July 23, 2026. It was limited to static inspection of
the locally installed application bundle. The application was not launched, no
account was used, no VPN session was established, and no user traffic was
captured.

The work is intended for lawful interoperability, research, and access to
networks for which the operator has authorization.

## Analyzed Binaries

| File | Identity | SHA-256 |
|---|---|---|
| `/Applications/iWAN.app/Contents/MacOS/iWAN` | `com.panabit.iwan.macosclient` 2.3.0 (230) | `ce0c589574ee85f587e92a052c985d9fc3391d4836aeb1ac6543636945d89600` |
| `MobileExtension.appex/Contents/MacOS/MobileExtension` | `com.panabit.iwan.macosclient.PacketTunnel` 2.3.0 (230) | `76e579315cd8263bcaafd90e4b0667514a80c208f6085fb24495033db5906438` |

Both binaries are universal Mach-O files. The Packet Tunnel extension contains
the `MobileCore` implementation.

## Static Evidence

The extension retains Swift symbols and reflection metadata for relevant
types, including:

- `PacketHeader`, `PacketType`, and `TLVAttributeType`
- `PacketBuilder`, `PacketParser`, and `ParsedPacket`
- `PasswordEncryption` and `KeyManager`
- `NoEncryption`, `XOREncryptionService`, and `AESEncryptionService`
- `HeartbeatEngine`, `PacketIOEngine`, `FragmentQueue`, and `IPFragment`
- `SegrtHeader`, `SegrtSession`, `SegrtReassemblyBuffer`, and
  `SegrtSrmonEngine`

Packet type values were recovered from the raw-value getter table. TLV values
were recovered from the TLV raw-value getter, description table, and
expected-length table.

The `CCCrypt` call sites show the traditional AES parameters:

```text
operation = encrypt/decrypt
algorithm = AES
options   = kCCOptionECBMode
IV        = null
```

The encrypting path zero-pads input to a 16-byte boundary. String construction
and MD5/AES call sites in `CryptoUtils` and `PasswordEncryption` establish the
documented key derivation.

The `IPFragment` parser requires an 8-byte prefix, reads a big-endian fragment
ID, and extracts EOP, offset, and length from bit 0, bits 2 through 14, and bits
15 through 25 of the second 32-bit word.

## Independent Cross-Check

The earlier community project
[`yyy1mu/ustc-iwan`](https://github.com/yyy1mu/ustc-iwan) independently agrees
with the following observations:

- the 8-byte common header
- `MD5(header || "mw")` for control-packet signatures
- the basic OPEN, OPENACK, and OPENREJECT values
- `MD5("mw" || username)` for password wrapping
- `MD5(username || password)` for the session key
- the repeating XOR data plane

`openiwan` is a clean implementation. It does not copy source from that
project; it provides its own parser boundaries, state management, platform
abstraction, error model, and tests.

## Confidence Levels

| Level | Meaning |
|---|---|
| S | Confirmed from constants, control flow, or call parameters in the 2.3.0 binary |
| C | Independently cross-checked against an earlier community implementation |
| L | Exercised against the local synthetic UDP compatibility endpoint |
| R | Requires interoperability testing against an authorized real endpoint |

The common header, packet types, TLVs, signature, key derivation, encryption
parameters, and fragment format reach S and, where applicable, C. The
OPEN-to-OPENACK exchange reaches L.

The following still require R:

- legacy AES exchange with a real endpoint
- real IPv6 and fragmentation behavior
- network transitions and reconnect behavior
- server-specific rejection and configuration branches
- long-running interoperability under packet loss and reordering

## What a Client Binary Cannot Prove

Static analysis of one client version cannot establish:

- server features that the client never invokes
- compatibility differences in other iWAN releases
- private controller APIs, organization-specific OIDC parameters, or hidden
  feature flags
- SEGRT/SR server path selection, replay windows, and failover semantics
- a vendor commitment to protocol naming, stability, or compatibility

The wire document is therefore an engineering reference for interoperability
with behavior observed in client version 2.3.0. It is not an official standard.

## Reproducibility Notes

Contributors extending the protocol should record:

1. the exact application and extension versions
2. cryptographic hashes of analyzed artifacts
3. whether evidence is static, synthetic, or collected from an authorized
   endpoint
4. the smallest synthetic packet or test that demonstrates the claim
5. uncertainty and incompatible observations rather than silently choosing one

Do not commit credentials, private controller responses, or unredacted packet
captures.
