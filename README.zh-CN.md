# OpeniWAN

[![Crates.io](https://img.shields.io/crates/v/openiwan.svg)](https://crates.io/crates/openiwan)
[![docs.rs](https://img.shields.io/docsrs/openiwan.svg)](https://docs.rs/openiwan)
[![CI](https://img.shields.io/github/actions/workflow/status/zhangheqi/openiwan/ci.yml?branch=main&label=CI)](https://github.com/zhangheqi/openiwan/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/crates/msrv/openiwan.svg)](https://crates.io/crates/openiwan)
[![License](https://img.shields.io/crates/l/openiwan.svg)](LICENSE)

开源 iWAN 客户端与 Rust 协议库。

[English](README.md) | [简体中文](README.zh-CN.md)

OpeniWAN 可以直接认证 iWAN UDP 端点并建立原生 TUN 隧道，也可以在不修改主机路由的
情况下转发单个 TCP 或 HTTP(S) 目标，还能通过控制器托管的客户域完成发现、认证和
连接。协议库提供传统与 Segment Routing 线格式、客户端会话运行时、DNS 策略引擎
以及托管控制器模型。

> [!IMPORTANT]
> OpeniWAN 是独立的互操作项目，与 Panabit 或任何网络运营方均无隶属或背书关系。
> 只能将其用于你有权访问的系统和网络。

## 项目状态

`main` 分支可能包含相对于最新正式版本的破坏性变更。本分支文档描述尚未发布的
接口；使用已发布版本时，请查阅对应的 Git tag。

| 范围 | 状态 |
|---|---|
| 传统 iWAN 认证与隧道 | 已实现 |
| Segment Routing 传输与监控 | 已实现 |
| 控制器托管的密码和 OIDC 登录 | 已实现 |
| Linux、macOS、Windows TUN 集成 | 已实现 |
| 不改路由的 TCP 与 HTTP(S) 转发 | 已实现 |
| 厂商认证 | 不提供 |

OpeniWAN 具有防御性解析、有界资源使用、清理事务、测试和跨平台 CI，但不会补充
iWAN 协议本身缺少的密码学安全属性，不同部署的互操作情况也可能不同。投入生产前，
请阅读[安全模型](SECURITY.md)，并在获得授权的端点上验证。

## 安装

OpeniWAN 需要 Rust 1.88 或更高版本。

安装 crates.io 上的最新正式版本：

```console
cargo install openiwan --locked
```

构建 `main` 分支文档所描述的未发布接口：

```console
git clone https://github.com/zhangheqi/openiwan.git
cd openiwan
cargo build --release --locked
```

可执行文件位于 `target/release/openiwan`，Windows 上为 `openiwan.exe`。将当前
checkout 安装到 Cargo 的二进制目录：

```console
cargo install --path . --locked
```

## 快速开始

探测端点：

```console
openiwan ping 192.0.2.10:6001
```

只认证，不修改主机网络：

```console
openiwan auth --server 192.0.2.10:6001 --username alice --encryption xor
```

建立仅包含一条路由的隧道：

```console
sudo openiwan connect --server 192.0.2.10:6001 --username alice --encryption xor --route 10.0.0.0/8
```

Windows 用户应在管理员终端中执行隧道命令，不使用 `sudo`。如果未设置
`OPENIWAN_PASSWORD`，CLI 会无回显地提示输入密码；也可以使用权限受保护的
`--password-file`。密码不能作为命令行值传入。

### 托管连接

创建可复用且不含秘密信息的 profile：

```console
openiwan profile set work --domain iwan.example --username alice
```

查看发现结果，将验证后的认证信息保存到系统凭据库，然后连接：

```console
openiwan managed discover
openiwan managed login --save
sudo openiwan managed connect
```

首个 profile 会自动成为默认项。OIDC 域会输出授权 URL 并要求粘贴完整回调 URL；
密码域从配置的受保护来源读取密码。

### 不改路由的转发

将单个固定目标暴露到 loopback 监听地址，不创建 TUN、不修改主机路由：

```console
openiwan forward --server 192.0.2.10:6001 --username alice --target tcp://db.internal.example:3306 --listen 127.0.0.1:3307
```

目标可以使用 `tcp://`、`http://` 或 `https://`。HTTPS 会验证上游证书，也可以
重复传入 `--ca-cert` 来增加信任根。

完整命令树、权限要求、profile 生命周期、自动化输出、时长格式和环境变量见
[CLI 指南](docs/CLI.md)。

## Rust 库

添加包含托管和转发功能的默认依赖：

```console
cargo add openiwan
```

只使用协议与直接客户端，关闭可选的托管和转发依赖：

```console
cargo add openiwan --no-default-features
```

凭据与可序列化配置相互独立：

```rust
use openiwan::{Client, ClientConfig, EncryptionMethod, Result};

fn client(password: String) -> Result<Client> {
    let mut config = ClientConfig::new("192.0.2.10:6001");
    config.encryption = EncryptionMethod::Xor;
    Client::new(config, "alice", password)
}
```

应用可以实现自己的 `PacketDevice`，使用原生 `TunDevice`，或单独集成 DNS 和协议
模块。公开 API 文档发布在 [docs.rs](https://docs.rs/openiwan)。

### Cargo features

| Feature | 默认 | 内容 |
|---|:---:|---|
| `managed` | 是 | 域发现、密码/OIDC 认证、控制器策略、profile 和 keepalive 模型 |
| `forward` | 是 | 通过用户态 IP 栈进行不改路由的 TCP 与 HTTP(S) 转发 |

核心包、密码、Segment Routing、DNS 策略、客户端和 TUN API 不依赖可选 feature。

## 平台支持

| 平台 | TUN 与路由 | 说明 |
|---|:---:|---|
| Linux | 支持 | 通常需要 root 或等效网络 capability |
| macOS | 支持 | 默认自动分配 `utunN` |
| Windows 10/11 x86_64 | 支持 | 需要管理员终端 |
| Windows 10/11 ARM64 | 支持 | 需要管理员终端 |

Windows x86_64 和 ARM64 使用的已签名 Wintun 0.14.1 二进制嵌入可执行文件。
OpeniWAN 会验证释放出的动态库后再加载。

## 文档

| 文档 | 用途 |
|---|---|
| [CLI 指南](docs/CLI.md) | 命令、凭据、profile、转发、权限与自动化 |
| [配置指南](docs/CONFIGURATION.md) | TOML、路由、DNS 策略、状态和优先级 |
| [托管连接](docs/MANAGED_CONNECTIONS.md) | 域发现、认证、控制器策略、posture 和 keepalive |
| [架构](docs/ARCHITECTURE.md) | 组件、生命周期、信任边界和清理 |
| [协议参考](docs/PROTOCOL.md) | 传统、Segment Routing 和托管 HTTP 线协议 |
| [协议证据](docs/PROTOCOL_PROVENANCE.md) | 证据要求和未解决协议范围 |
| [安全策略](SECURITY.md) | 漏洞报告和运行安全边界 |
| [变更日志](CHANGELOG.md) | 按版本整理的用户可见变更 |

[文档索引](docs/README.md)标明了每篇英文指南的目标读者和权威性。技术文档以英文为
准，中文 README 是项目入口的同步翻译。

## 贡献与支持

欢迎提交 bug、功能建议、文档修复和可复现的互操作证据。重大修改前请阅读
[贡献指南](CONTRIBUTING.md)。通过 [SUPPORT.md](SUPPORT.md) 选择正确的支持渠道；
漏洞必须按照 [SECURITY.md](SECURITY.md) 私下报告。

所有参与者都必须遵守[行为准则](CODE_OF_CONDUCT.md)。

## 许可证

OpeniWAN 使用 [MIT License](LICENSE)。
