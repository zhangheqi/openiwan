# Embedded Wintun binaries

OpeniWAN redistributes the official prebuilt Wintun 0.14.1 DLLs required by
Windows TUN support:

| Target | Source archive directory | SHA-256 |
|---|---|---|
| `x86_64-pc-windows-msvc` | `bin/amd64/wintun.dll` | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |
| `aarch64-pc-windows-msvc` | `bin/arm64/wintun.dll` | `f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80` |

The files originate from the official Wintun 0.14.1 prebuilt distribution
bundled by `wintun-bindings` 0.7.39. The official archive is published at
<https://www.wintun.net/> with SHA-256
`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`.
`0.14.1/LICENSE.txt` is the unmodified prebuilt binaries license distributed
with those DLLs.

Do not modify, rename, or rebuild these files. Updating Wintun requires copying
the new official binaries and license, updating the versioned runtime path and
both hashes, and validating Authenticode signatures on x86_64 and ARM64
Windows.
