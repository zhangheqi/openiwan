# Reverse-Engineering Evidence and Limitations

OpeniWAN 0.3 uses `reverse/IWAN_PROTOCOL_SPEC.md` as its protocol contract. The
reference was reconstructed from the Android iWAN 2.3.0 APK by static
inspection of DEX/JADX output, APK resources/smali, and Flutter AOT output.

The evidence map in the source reference identifies the relevant recovered
classes and AOT functions for:

- packet and TLV registries;
- control framing and MD5 signature;
- password wrapping and session ciphers;
- OPEN/ACK/REJECT handling;
- traditional and SR fragments;
- SR headers, encryption, reassembly, and monitoring;
- keepalive serializers and HMAC signing;
- lookup and controller-auth request signing;
- the `/config` request construction.

The repository tests the reference document's byte vectors directly. These
cover OPEN, ping, signed close, XOR, traditional AES, SR headers, SR fragment
words, SR outer AES, and keepalive HMAC.

## Evidence rule

A behavior may enter protocol code only when it is supported by the recovered
Android 2.3.0 result or by new authorized interoperability evidence that first
updates the canonical reference. Plausible fields, schemas, endpoint
sequences, and compatibility switches are not sufficient.

This rule is why the current implementation:

- accepts AUTH_VERIFY omission instead of exposing a guessed policy knob;
- fixes XOR cycling to eight key bytes;
- fixes the traditional heartbeat to its 20-byte little-endian body;
- does not apply NETMASK or DUP_PKT from OPEN_ACK;
- leaves aggregate `/config` as dynamic JSON;
- preserves the known SR path and encryption restrictions.

## Remaining unknowns

Static client evidence cannot settle server-side policy or code absent from the
artifacts. The known unresolved items are:

1. authoritative `DUP_PKT` behavior;
2. NETMASK use by other clients;
3. production-preferred OPEN_REJECT form;
4. names for SR monitor bits and marker semantics;
5. relay-side SR path mutation;
6. deployment-specific nested `/config` policy schemas;
7. server requirements for signed versus raw CLOSE;
8. duplicate suppression or scheduling.

Resolve these with authorized captures or server tests. Do not fill them from
another client implementation.

## Contribution requirements

Record the exact client/server versions, evidence source, smallest reproducer,
and any incompatible observations. Never commit credentials, tokens, private
controller responses, proprietary binaries, or unredacted captures.
