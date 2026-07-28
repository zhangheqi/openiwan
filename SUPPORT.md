# Support

OpeniWAN is maintained as an open-source interoperability project. Support is
provided on a best-effort basis; no response time or deployment compatibility
is guaranteed.

## Before opening an issue

1. Check the [README](README.md), [CLI guide](docs/CLI.md), and
   [configuration guide](docs/CONFIGURATION.md).
2. Run `openiwan --version` and confirm that you are reading documentation
   from the matching Git tag.
3. Search existing issues.
4. Reproduce the problem with the smallest authorized test case.
5. Remove credentials, tokens, private controller responses, identifying
   packet data, and unrelated logs.

## Choose the right channel

| Need | Channel |
|---|---|
| Reproducible defect | [Bug report](https://github.com/zhangheqi/openiwan/issues/new?template=bug.yml) |
| Feature proposal | [Feature request](https://github.com/zhangheqi/openiwan/issues/new?template=feature.yml) |
| Authorized protocol observation | [Interoperability report](https://github.com/zhangheqi/openiwan/issues/new?template=interoperability.yml) |
| Documentation correction | [Documentation issue](https://github.com/zhangheqi/openiwan/issues/new?template=documentation.yml) or a focused pull request |
| Suspected vulnerability | Follow [SECURITY.md](SECURITY.md); do not open a public issue |
| Conduct concern | Follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) |

General deployment setup may depend on controller policy, identity-provider
configuration, routing, DNS, and privileges outside this project. Provide
synthetic configuration and reserved example addresses whenever possible.
Maintainers cannot diagnose private production systems from undisclosed data.

## What to include

- OpeniWAN version or commit SHA;
- operating system and architecture;
- exact command with secrets removed;
- expected and observed behavior;
- minimal reproduction;
- whether TUN, routes, DNS, forwarding, managed authentication, or Segment
  Routing is involved;
- redacted logs from the minimum useful verbosity.

Use `-v` or a scoped `RUST_LOG` filter for diagnostics. Do not publish trace
logs until you have verified that they contain no private deployment data.

## Interoperability reports

Protocol observations must come from systems you are authorized to test.
Follow [Protocol Provenance](docs/PROTOCOL_PROVENANCE.md) and state the
evidence level. A deployment-specific workaround is not automatically part of
the general protocol contract.
