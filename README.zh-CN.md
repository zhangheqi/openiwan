# OpeniWAN

[![Crates.io](https://img.shields.io/crates/v/openiwan.svg)](https://crates.io/crates/openiwan)
[![docs.rs](https://img.shields.io/docsrs/openiwan.svg)](https://docs.rs/openiwan)
[![CI](https://img.shields.io/github/actions/workflow/status/zhangheqi/openiwan/ci.yml?branch=main&label=CI)](https://github.com/zhangheqi/openiwan/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/crates/msrv/openiwan.svg)](https://crates.io/crates/openiwan)
[![License](https://img.shields.io/crates/l/openiwan.svg)](LICENSE)

开源 iWAN 客户端与 Rust 协议库。

[English](README.md) | [简体中文](README.zh-CN.md)

OpeniWAN 支持直接 iWAN 认证、原生 TUN 隧道、不改路由的 TCP 和 HTTP(S) 转发，
以及控制器托管连接。crate 同时提供传统与 Segment Routing 线协议、会话运行时、
DNS 策略引擎和托管控制器模型。

> [!IMPORTANT]
> OpeniWAN 是独立的互操作项目，与 Panabit 或任何网络运营方均无隶属或背书关系。
> 只能将其用于你有权访问的系统和网络。

## 功能

- 传统 iWAN 与 Segment Routing 传输
- 直接认证与控制器托管认证
- Linux、macOS 和 Windows 原生 TUN 与路由管理
- Split DNS 策略与加密 DNS 控制
- 面向固定 TCP 或 HTTP(S) 目标的不改路由转发
- 协议、客户端、托管连接、DNS 和 TUN 的 Rust API

iWAN 协议本身存在实现无法消除的安全限制。投入生产前，请先阅读
[安全模型](SECURITY.md)。

## 安装

从 crates.io 安装最新正式版本：

```console
cargo install openiwan --locked
```

从源码构建：

```console
git clone https://github.com/zhangheqi/openiwan.git
cd openiwan
cargo build --release --locked
```

所需 Rust 版本在 [Cargo.toml](Cargo.toml) 中声明。可执行文件位于
`target/release/openiwan`，Windows 上为 `openiwan.exe`。

## 快速开始

探测端点：

```console
openiwan ping 192.0.2.10:6001
```

只认证，不修改主机网络：

```console
openiwan auth --server 192.0.2.10:6001 --username alice --encryption xor
```

建立包含一条路由的隧道：

```console
sudo openiwan connect --server 192.0.2.10:6001 --username alice --encryption xor --route 10.0.0.0/8
```

Windows 用户应在管理员终端中执行隧道命令，并省略 `sudo`。如果未设置
`OPENIWAN_PASSWORD`，CLI 会无回显地提示输入密码；也可以使用权限受保护的
`--password-file`。

### 托管连接

托管连接使用客户域，并可将认证信息保存到操作系统凭据库。在 Unix 上，请用同一个
提权账户创建 profile、认证并连接：

```console
sudo -H -s
openiwan profile set work --domain iwan.example --username alice
openiwan managed login --profile work
openiwan managed connect --profile work
exit
```

Profile 选择、OIDC 登录、路由、DNS 和非交互运行方式见
[CLI 指南](docs/CLI.md)。

### 不改路由的转发

通过 iWAN 转发一个固定目标，不创建 TUN 接口，也不修改主机路由：

```console
openiwan forward --server 192.0.2.10:6001 --username alice --target tcp://db.internal.example:3306 --listen 127.0.0.1:3307
```

目标可以使用 `tcp://`、`http://` 或 `https://`。HTTPS 会验证上游证书；可重复
传入 `--ca-cert FILE` 添加私有信任根。

## 作为 Rust 库使用

添加包含托管与转发功能的默认依赖：

```console
cargo add openiwan
```

关闭可选的托管与转发功能：

```console
cargo add openiwan --no-default-features
```

```rust
use openiwan::{Client, ClientConfig, EncryptionMethod, Result};

fn client(password: String) -> Result<Client> {
    let mut config = ClientConfig::new("192.0.2.10:6001");
    config.encryption = EncryptionMethod::Xor;
    Client::new(config, "alice", password)
}
```

API 文档发布在 [docs.rs](https://docs.rs/openiwan)。

| Feature | 默认 | 内容 |
|---|:---:|---|
| `managed` | 是 | 域发现、控制器认证与策略、profile 和 keepalive 模型 |
| `forward` | 是 | 通过用户态网络栈进行不改路由的 TCP 与 HTTP(S) 转发 |

## 平台支持

| 平台 | TUN 与路由 | 说明 |
|---|:---:|---|
| Linux | 支持 | 需要 root 或等效网络 capability |
| macOS | 支持 | 默认自动分配 `utun` 接口 |
| Windows x86_64 | 支持 | 需要管理员终端 |
| Windows ARM64 | 支持 | 需要管理员终端 |

crate 内含受支持 Windows 架构的已签名 Wintun 二进制，并会在加载前验证。

## 文档

- [命令行指南](docs/CLI.md)
- [配置](docs/CONFIGURATION.md)
- [托管连接](docs/MANAGED_CONNECTIONS.md)
- [架构](docs/ARCHITECTURE.md)
- [协议参考](docs/PROTOCOL.md)
- [安全策略](SECURITY.md)
- [贡献指南](CONTRIBUTING.md)
- [变更日志](CHANGELOG.md)

默认分支上的文档可能包含尚未发布的改动。使用正式版本时，请以该版本的内置帮助、
docs.rs 页面和对应 Git tag 为准。

## 社区

报告问题或寻求帮助请参阅 [SUPPORT.md](SUPPORT.md)。安全问题必须按照
[SECURITY.md](SECURITY.md) 私下报告。所有参与者均须遵守
[行为准则](CODE_OF_CONDUCT.md)。

## 许可证

OpeniWAN 使用 [MIT License](LICENSE)。
