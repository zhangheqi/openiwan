# OpeniWAN

[![Crates.io](https://img.shields.io/crates/v/openiwan.svg)](https://crates.io/crates/openiwan)
[![docs.rs](https://img.shields.io/docsrs/openiwan.svg)](https://docs.rs/openiwan)
[![CI](https://img.shields.io/github/actions/workflow/status/zhangheqi/openiwan/ci.yml?branch=main&label=CI)](https://github.com/zhangheqi/openiwan/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/openiwan.svg)](LICENSE)

用于 iWAN 兼容网络的 Rust 客户端与协议库。

[English](README.md) | [简体中文](README.zh-CN.md)

> [!IMPORTANT]
> OpeniWAN 是独立项目，与 Panabit 或任何网络运营方均无隶属或背书关系。只能在
> 你有权访问的系统和网络中使用。

## 功能

- 完整的标准包类型和 TLV 注册表；
- 带签名的 `OPEN`、`OPEN_ACK`、`OPEN_REJECT`、心跳、ping 和 `CLOSE`；
- Java US-ASCII 凭据转换、密码包装和会话密钥派生；
- 明文、仅循环前 8 字节密钥的 XOR 和 AES-128-ECB 会话数据；
- 传统 IPv4/IPv6 数据类与有界双分片重组；
- SR 头、方向相关路径、内外层加密、分片、重组和监控；
- 客户域发现、主备 lookup、重试、规范域替换、联网授权门禁和可选 7 天缓存；
- 密码认证与 OIDC Authorization Code + PKCE S256；
- 控制器配置、按服务器生成的凭据、posture 与设备绑定门禁、入口探测和
  传统/SR 选择；
- Linux、macOS 和 Windows 的原生 TUN、路由与 DNS 事务；
- 通过用户态 IP 栈实现的不改路由 TCP 和 HTTP(S) 转发；
- 控制器 keepalive 鉴权和指标模型。

部署相关的嵌套策略保留为动态 JSON；稳定的外层字段和服务器/SR 模型使用强类型
API。线协议细节见[协议参考](docs/PROTOCOL.md)。

## 安装

OpeniWAN 需要 Rust 1.88 或更高版本。

```console
cargo install openiwan --locked
```

从源码构建：

```console
cargo build --release --locked
```

只需要 UDP 协议库时，可关闭默认的 `managed` 与 `forward` feature：

```console
cargo add openiwan --no-default-features
```

## 命令行

以下命令均使用单行形式，可直接用于 POSIX shell 和 PowerShell。Unix 上创建 TUN
通常需要 `sudo`；Windows 用户应在管理员 PowerShell 中运行相同命令，不使用
`sudo`。

探测端点：

```console
openiwan ping --server 192.0.2.10:6001
```

仅认证、不创建接口：

```console
openiwan auth --server 192.0.2.10:6001 --username alice --encryption xor
```

未设置 `OPENIWAN_PASSWORD` 时会隐藏输入密码；也可使用权限受保护的
`--password-file`。密码不会作为命令行值传入。

创建 TUN 并添加显式路由：

```console
sudo openiwan connect --server 192.0.2.10:6001 --username alice --encryption xor --route 10.0.0.0/8
```

在管理员 PowerShell 中：

```powershell
openiwan connect --server 192.0.2.10:6001 --username alice --encryption xor --route 10.0.0.0/8
```

Linux/Windows 默认接口名为 `openiwan0`，macOS 自动请求可用的 `utunN`。默认路由
以及包含当前 UDP 端点的路由会被拒绝。

解码传统或 SR 数据报：

```console
openiwan decode 2900ffffffffffff815db7391fcafc3df035553a42cc5db6
```

## 配置

传统连接：

```toml
server = "192.0.2.10:6001"
mtu = 1400
encryption = "xor"
receive_poll_ms = 250

[reconnect]
attempts = 10
initial_delay_ms = 1000
max_delay_ms = 30000
```

认证与心跳时间是协议常量，而不是部署设置。

SR 连接追加：

```toml
[segment_routing]
id = 1
keepalive = true
encrypt_algo = "aes128"
encrypt_key = "0123456789abcdef"
links = [1, 258, 11259375]
```

`links` 使用客户端到网络的逻辑顺序，只有发送 SR 包时才反转。`encrypt_key` 是
原始 UTF-8 字节；AES-128 取前 16 字节，AES-256 取前 32 字节。

使用配置文件：

```console
openiwan auth --config openiwan.toml --username alice
```

## 不改路由的转发

可选 `forward` feature 使用用户态 IP 栈，不创建 TUN、不修改主机路由：

```console
openiwan forward --server 192.0.2.10:6001 --username alice --target tcp://db.internal.example:3306 --listen 127.0.0.1:3307
```

`tcp://` 原样转发字节；`http://`、`https://` 对一个固定 origin 提供 HTTP/1.1
反向代理。HTTPS 会验证上游证书，并支持重复使用 `--ca-cert` 添加 CA。监听地址
必须是 loopback。

## 托管连接

托管连接从客户域开始，并要求显式确认隐私与联网授权。

查询服务和认证方式：

```console
openiwan managed --domain iwan.example --device-id device-identifier --consent discover
```

完成认证和入口选择，但不创建 TUN：

```console
openiwan managed --domain iwan.example --device-id device-identifier --consent login --username alice
```

OIDC 域会忽略 `--username` 并输出 PKCE 授权地址；按提示粘贴完整回调 URL。密码域
会探测可用入口，并使用临时 UDP 会话验证凭据。

在 Unix 上建立持久隧道：

```console
sudo openiwan managed --domain iwan.example --device-id device-identifier --consent connect --username alice
```

在管理员 PowerShell 中：

```powershell
openiwan managed --domain iwan.example --device-id device-identifier --consent connect --username alice
```

本地 posture 结果可通过 `--posture-results` 传入 JSON 数组。托管连接会应用控制器
下发的路由、IP filter、DNS、split DNS 和 MTU 策略。详见
[托管客户端流程](docs/MANAGED_CLIENT_FLOW.md)。

## 代码模块

- `protocol`：标准头、TLV、控制签名、ping 与心跳；
- `crypto`：密码包装和会话加密；
- `fragment`：传统/SR 分片和重组；
- `sr`：SR 封装、加密、数据规划和监控；
- `client`：认证与会话 worker；
- `managed`：lookup、认证、OIDC、控制器配置、posture、入口选择、SR 模型和
  HTTP keepalive；
- `tun`：原生接口、路由和 DNS 集成。

## 开发

运行仓库检查：

```console
cargo test --all-targets --all-features --locked
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
```

在 POSIX shell 中生成 API 文档：

```console
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked
```

在 PowerShell 中生成 API 文档：

```powershell
$env:RUSTDOCFLAGS = "-D warnings"; cargo doc --no-deps --all-features --locked; Remove-Item Env:RUSTDOCFLAGS
```

通过协议向量测试不代表厂商认证；真实部署仍应在获授权端点验证。

## 安全限制

控制签名是 `MD5(header || "mw")`，不覆盖 body。XOR、AES-ECB 与 SR 外层 AES
均不提供数据完整性或重放保护。这些机制只用于互操作，不具备现代 VPN 协议的
安全属性。

漏洞报告与运行建议见 [SECURITY.md](SECURITY.md)。

## 许可证

OpeniWAN 使用 [MIT License](LICENSE)。
