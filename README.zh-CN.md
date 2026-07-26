# OpeniWAN

[![Crates.io](https://img.shields.io/crates/v/openiwan.svg)](https://crates.io/crates/openiwan)
[![docs.rs](https://img.shields.io/docsrs/openiwan.svg)](https://docs.rs/openiwan)
[![CI](https://img.shields.io/github/actions/workflow/status/zhangheqi/openiwan/ci.yml?branch=main&label=CI)](https://github.com/zhangheqi/openiwan/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/crates/msrv/openiwan.svg)](https://crates.io/crates/openiwan)
[![License](https://img.shields.io/crates/l/openiwan.svg)](LICENSE)

iWAN 客户端协议的独立开源 Rust 实现。

[English](README.md) | [简体中文](README.zh-CN.md)

OpeniWAN 提供协议库和命令行客户端，当前面向 macOS iWAN 客户端
`2.3.0 (230)` 中的传统单链路 UDP 数据面。

> [!IMPORTANT]
> 本项目与 Panabit 或任何部署运营方没有隶属或背书关系。它是用于互操作的社区项目，
> 不是官方协议规范或经过厂商认证的客户端。

## 功能

- OPEN、OPENACK、OPENREJECT 认证以及 AUTH_VERIFY 请求关联
- 明文、循环 XOR 和传统 AES-128-ECB 数据模式
- IPv4、IPv6、心跳、CLOSE、有限重连和分片重组
- 通过 `tun` crate 支持 Linux、macOS 与 Windows 原生 TUN
- 不创建 TUN、不修改主机路由的原始 TCP 转发和 HTTP/HTTPS 反向代理
- 严格数据包校验、分片队列上限、路由清理和凭据内存清零
- 配置驱动的 OIDC/JWKS 登录和控制器线路获取
- 可复用 Rust 库，以及 `ping`、`auth`、`connect`、`decode`、`forward`、
  `managed` 命令

## 兼容状态

### 已实现

- 传统单链路认证和 UDP 隧道
- 明文与循环 XOR 数据模式
- IPv4、IPv6、IPFRAG 与 IPFRAG6 下行路径
- 心跳、CLOSE、故障检测和有限重连
- 由 URI 选择的原始 TCP 转发和 HTTP/HTTPS 反向代理
- 配置驱动的 OIDC 和兼容 Panabit 控制器流程
- `forward` 用户态 DNS，包括 UDP、TCP 回退和 TTL 缓存

### 仍需部署验证

- 传统 AES-128 数据模式已经实现，但仍需在获得授权的真实端点上验证。

### 尚未实现

- SEGRT/SR 多路径数据包仅会被识别并安全丢弃。

这里的“面向生产”表示实现包含防御性解析、资源上限、明确错误处理、凭据保护、清理逻辑、
测试和 CI，并不表示已经获得厂商认证。部署前必须在获得授权的测试环境中验证互操作性。

## 安装

OpeniWAN 需要 Rust 1.88 或更新版本。从 crates.io 安装命令行客户端：

```bash
cargo install openiwan --locked
```

Cargo 默认将可执行文件安装到 Linux/macOS 的 `$HOME/.cargo/bin` 或 Windows 的
`%USERPROFILE%\.cargo\bin`。请确保对应目录已加入 `PATH`，然后验证安装：

```bash
openiwan --version
```

## 从源码构建

在仓库目录中构建优化后的可执行文件：

```bash
cargo build --release --locked
```

构建产物位于 `target/release/openiwan`（Windows 为 `openiwan.exe`）。如需将当前
源码安装到 Cargo 的可执行文件目录：

```bash
cargo install --path . --locked
```

开发环境要求和项目检查命令参见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 平台说明

安装本身不需要提升权限。创建 TUN 或修改路由时，Linux/macOS 需要以 root 运行
`connect`、`managed connect` 和 `managed all`，Windows 则需要使用管理员终端。
`ping`、`auth`、`decode`、`forward`、托管登录与线路查看不需要提升权限。

### Windows

支持 Windows 10/11 x86_64 与 ARM64。

官方签名的 Wintun 0.14.1 已嵌入可执行文件。首次建立 TUN 时，OpeniWAN 会验证
SHA-256，原子释放到 `%LOCALAPPDATA%\openiwan\wintun\0.14.1`，加载时验证
Authenticode 签名，之后复用已验证文件。无需另行安装 Wintun 或复制 DLL。

## 使用

探测 iWAN UDP 端点：

```bash
openiwan ping --server 192.0.2.10:6001
```

只进行认证，不修改主机网络：

```bash
openiwan auth \
  --server 192.0.2.10:6001 \
  --username alice \
  --encryption xor
```

如果没有设置 `OPENIWAN_PASSWORD`，客户端会在 Linux、macOS 和 Windows 上隐藏
读取密码。不要把密码直接放在命令行参数中。

为指定目标网段建立隧道：

```bash
sudo openiwan connect \
  --server 192.0.2.10:6001 \
  --username alice \
  --encryption xor \
  --route 10.0.0.0/8 \
  --route 2001:db8::/32
```

Windows 请在管理员终端中运行不带 `sudo` 的等价命令。Linux 与 Windows 的默认接口名
为 `openiwan0`；macOS 自动分配可用的 `utunN`。可用 `--tun` 覆盖，macOS 显式
名称必须是 `utunN`。

`--route` 接受 CIDR，`--route-ip` 创建主机路由，`--route-domain` 在连接前解析一次
域名。Unix 参数都以独立参数调用系统工具，不经过 shell；Windows 使用原生 IP Helper
API。客户端拒绝默认路由以及会覆盖当前 iWAN 数据端点的路由。

### 不修改路由地转发 TCP 或 HTTP(S)

`--target` 必须是 URI，其 scheme 决定转发模式。原始 TCP 服务必须显式指定非零
端口：

```bash
openiwan forward \
  --server 192.0.2.10:6001 \
  --username alice \
  --encryption xor \
  --listen 127.0.0.1:3307 \
  --target tcp://db.internal.example:3306
```

连接 `127.0.0.1:3307` 后，字节流会通过 iWAN 用户态 TCP/IP 栈转发到
`db.internal.example:3306`。OpeniWAN 只进行原样双向透传，不解析应用协议，也不
终止 TLS。若应用需要机密性或服务端身份认证，请在本地客户端与目标服务之间配置 TLS。

对于 HTTP 或 HTTPS origin，本地监听端始终是明文 HTTP/1.1：

```bash
openiwan forward \
  --server 192.0.2.10:6001 \
  --username alice \
  --encryption xor \
  --listen 127.0.0.1:8080 \
  --target https://api.example.edu \
  --ca-cert organization-ca.pem
```

例如，本地请求 `http://127.0.0.1:8080/v1/profile?full=true` 会代理到
`https://api.example.edu/v1/profile?full=true`。请求方法、路径、查询、流式请求
体和响应，以及 `Authorization` 等端到端业务头都会保留。OpeniWAN 会将 `Host`
改写为目标 authority、删除 hop-by-hop 头，并把同源绝对 `Location` 改写为相对
引用。HTTPS 域名目标使用目标主机名进行 TLS SNI 和证书校验；IP 字面量则作为 IP
证书身份进行校验。默认加载系统根证书，也可重复传入 `--ca-cert` 添加私有 CA 文件。
`--ca-cert` 仅可用于 `https://` 目标。`http://` 目标在 iWAN 内使用明文 TCP，
不提供上游 TLS 保护。

`forward` 不打开 TUN，不调用系统路由工具，也不接受 `--route` 参数。监听地址必须是
回环地址，默认为 `127.0.0.1:8080`。裸 `HOST:PORT` 目标会被拒绝：

- `tcp://HOST:PORT` 选择原始 TCP 转发，端口始终必填。
- `http://HOST[:PORT]` 选择 HTTP 反向代理，默认端口为 80。
- `https://HOST[:PORT]` 选择经过校验的 HTTPS 上游，默认端口为 443。

例如，`http://example.com` 与 `https://example.com` 使用默认端口，而
`http://example.com:12345` 与 `https://example.com:12345` 使用自定义端口。

HTTP(S) 目标必须是 origin，不能包含用户信息、非根路径、查询或 fragment。IPv6
字面量需加方括号，例如 `tcp://[2001:db8::10]:3306` 或
`https://[2001:db8::10]`。不支持传入的 `CONNECT`、WebSocket 及其他 HTTP
Upgrade 请求，也不支持 HTTP/2。`--connect-timeout-ms` 限制每个本地连接完成
DNS、TCP 以及适用时 TLS 建连的总时长。转发器最多允许 256 个并发连接；达到上限时
会关闭新连接。

默认 `--dns-mode auto` 会优先通过 iWAN 用户态栈查询 OPENACK 或托管 provider
提供的组织 DNS。它校验 DNS 事务和响应、支持 CNAME、按 TTL 缓存，并在 UDP
响应被截断时自动改用 DNS-over-TCP。这些查询通过 iWAN 使用配置的组织解析器，而
不是宿主机解析路径。每个托管 provider 都必须显式声明组织 DNS；仅依赖 OPENACK
DNS 属性时使用空列表：

```toml
dns_servers = []
```

手动模式或临时覆盖可使用 `--dns-server 192.0.2.53`，每次解析尝试的时限由
`--dns-timeout-ms` 控制。指定 `--dns-mode iwan` 可要求必须存在 iWAN DNS。
`auto` 只有在没有任何 iWAN DNS 配置时才使用系统解析；已经配置的组织 DNS 如果
查询失败会直接失败，不会泄露域名到宿主机解析器。目标 URI 的 host 是传给所选
解析器的名称；对于 HTTPS 域名目标，同一个 host 也用于 TLS SNI 和证书校验。
IPv4 或方括号 IPv6 字面量目标（例如 `tcp://192.0.2.25:22` 或
`https://[2001:db8::25]`）会跳过 DNS；HTTPS IP 字面量仍作为证书身份。

### 统一认证并连接

托管客户域使用外部 TOML 文件，因此认证和控制器参数变化时无需重新编译。
`examples/providers/example.toml` 是结构完整但不能直接部署的中性模板；替换全部
占位值或选用预制 profile 后，再将 provider 安装成仅当前用户可读的文件：

```bash
install -d -m 700 "$HOME/.config/openiwan/providers"
install -m 600 /path/to/provider.toml \
  "$HOME/.config/openiwan/providers/provider.toml"
```

普通用户可完成登录、保存加密线路配置和离线查看：

```bash
openiwan managed \
  --provider "$HOME/.config/openiwan/providers/provider.toml" fetch
openiwan managed \
  --provider "$HOME/.config/openiwan/providers/provider.toml" list
```

选择线路并连接：

```bash
sudo openiwan managed \
  --provider "$HOME/.config/openiwan/providers/provider.toml" \
  connect --route-domain example.edu --route 10.0.0.0/8
```

将动作换成 `all` 可以一次完成登录、选择和连接。`connect`、`all` 和 `forward`
未指定线路选择参数时会先列出线路再提示选择；传入 `--line-index` 或 `--line-name`
时会直接选择目标线路，不打印完整列表。access token 与解密后的线路密码不会写入
磁盘。provider 结构、状态文件和安全模型参见
[托管客户域文档](docs/MANAGED_PROVIDERS.md)；预制配置和部署专属说明参见
[Provider Profiles](docs/providers/README.md)。
托管状态默认位于 Unix 的 `~/.config/openiwan/managed` 或 Windows 的
`%APPDATA%\openiwan\managed`。

也可以使用已经保存的托管线路启动相同的无路由转发器：

```bash
openiwan managed \
  --provider "$HOME/.config/openiwan/providers/provider.toml" \
  forward --line-index 1 \
  --listen 127.0.0.1:3307 \
  --target tcp://db.internal.example:3306
```

也可以使用 TOML 配置。`require_auth_verify_echo` 和 `xor_key_bytes` 的取值取决于
具体部署，因此是必填项：

```toml
server = "192.0.2.10:6001"
mtu = 1400
encryption = "xor"
auth_timeout_ms = 3000
auth_attempts = 3
require_auth_verify_echo = true
xor_key_bytes = 16
heartbeat_interval_ms = 5000
heartbeat_timeout_ms = 30000
receive_poll_ms = 250

[reconnect]
attempts = 10
initial_delay_ms = 1000
max_delay_ms = 30000
```

```bash
openiwan auth --config openiwan.toml --username alice
```

Rust API 在构造客户端或加密器时同样要求显式传入 AUTH_VERIFY 策略和 XOR 密钥宽度；
加密器只接受 `8` 或 `16`，其他值返回错误。

完整命令行参数请运行 `openiwan --help` 或 `openiwan <command> --help`。

## Rust 库

运行 `cargo add openiwan` 将 OpeniWAN 添加到 Rust 项目。如果只需要协议层，不需要
默认启用的 `managed` 与 `forward` 功能，请使用
`cargo add openiwan --no-default-features`。

数据包和 TLV 编解码位于 `openiwan::protocol`，兼容加密位于
`openiwan::crypto`。已有 TUN、虚拟接口或用户态 IP 栈的应用可以实现
`PacketDevice`，并使用 `Client::authenticate`、`ConnectedSession::run` 或有限
重连辅助接口。

## 文档与贡献

技术文档以英语维护：

- [文档索引](docs/README.md)
- [线协议参考](docs/IWAN_PROTOCOL_2_3_0.md)
- [架构](docs/ARCHITECTURE.md)
- [托管客户域](docs/MANAGED_PROVIDERS.md)
- [Provider Profiles](docs/providers/README.md)
- [逆向证据与限制](docs/REVERSE_ENGINEERING.md)
- [安全策略](SECURITY.md)

提交贡献前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)，参与社区即表示同意遵守
[行为准则](CODE_OF_CONDUCT.md)。安全问题请按照 [SECURITY.md](SECURITY.md) 私下报告。

## 安全说明

传统 iWAN 数据面使用 MD5、循环 XOR 或 AES-ECB，控制签名也不是现代消息认证码。这些机制
只用于兼容，不能提供现代 VPN 所预期的机密性、完整性、前向保密和对等方认证。

请仅在获得授权的网络中使用 OpeniWAN，最好配合额外的可信安全层；如果端点支持更强的
协议，应优先使用更强协议。

## 许可证

OpeniWAN 使用 [MIT License](LICENSE)。
