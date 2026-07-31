# Support

OpeniWAN is maintained on a best-effort basis. Response times and
deployment-specific compatibility are not guaranteed.

Before opening an issue:

1. Check the [README](README.md), [CLI guide](docs/CLI.md), and
   [configuration guide](docs/CONFIGURATION.md).
2. Search existing issues.
3. Reduce the problem to the smallest authorized reproduction.
4. Remove credentials, tokens, private controller responses, identifying
   packet data, and unrelated logs.

## Where to report

| Need | Channel |
|---|---|
| Reproducible defect | [Bug report](https://github.com/zhangheqi/openiwan/issues/new?template=bug.yml) |
| Feature proposal | [Feature request](https://github.com/zhangheqi/openiwan/issues/new?template=feature.yml) |
| Authorized protocol observation | [Interoperability report](https://github.com/zhangheqi/openiwan/issues/new?template=interoperability.yml) |
| Documentation correction | [Documentation issue](https://github.com/zhangheqi/openiwan/issues/new?template=documentation.yml) or a focused pull request |
| Suspected vulnerability | Follow [SECURITY.md](SECURITY.md); do not report it publicly |
| Conduct concern | Follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) |

Include the OpeniWAN release or commit, operating system and architecture,
redacted command, expected and observed behavior, minimal reproduction, and
the smallest useful diagnostic log. For protocol observations, also follow
[Protocol Provenance](docs/PROTOCOL_PROVENANCE.md).

Use `-v` or a narrowly scoped `RUST_LOG` filter for diagnostics, then review
the output before publishing it. Maintainers cannot diagnose undisclosed
private production systems; use synthetic configuration and reserved example
addresses whenever possible.
