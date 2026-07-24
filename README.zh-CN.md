# openiwan

iWAN 客户端协议的独立开源 Rust 实现。

[English](README.md) | [简体中文](README.zh-CN.md)

`openiwan` 提供协议库和命令行客户端，当前面向 macOS iWAN 客户端
`2.3.0 (230)` 中的传统单链路 UDP 数据面。

> [!IMPORTANT]
> 本项目与 Panabit 或中国科学技术大学没有隶属或背书关系。它是用于互操作的社区项目，
> 不是官方协议规范或经过厂商认证的客户端。

## 功能

- OPEN、OPENACK、OPENREJECT 认证以及 AUTH_VERIFY 请求关联
- 明文、循环 XOR 和传统 AES-128-ECB 数据模式
- IPv4、IPv6、心跳、CLOSE、有限重连和分片重组
- Linux `/dev/net/tun` 与 macOS `utun`
- 不创建 TUN、不修改主机路由的本地 HTTP 到内网 HTTPS 反向代理
- 严格数据包校验、分片队列上限、路由清理和凭据内存清零
- 配置驱动的 OIDC/JWKS 登录和控制器线路获取
- 可复用 Rust 库，以及 `ping`、`auth`、`connect`、`decode`、`managed` 命令

## 兼容状态

| 能力 | 状态 |
|---|---|
| 传统单链路认证和 UDP 隧道 | 已实现 |
| 明文与 XOR 数据面 | 已实现 |
| 传统 AES-128 数据面 | 已实现；仍需真实服务端验证 |
| IPv4 与 IPv6 | 已实现 |
| IPFRAG 与 IPFRAG6 下行重组 | 已实现 |
| 心跳、CLOSE、故障检测和重连 | 已实现 |
| 无路由本地 HTTP 到 HTTPS 反向代理 | 已实现；HTTP/1.1 固定上游 |
| 配置驱动的 OIDC 和兼容 Panabit 控制器流程 | 已实现 |
| USTC 托管登录配置 | 已提供示例；仍需在授权环境中实测 |
| SEGRT/SR 多路径 | 仅识别并安全丢弃；尚未实现 |
| `serve` 用户态 DNS（UDP、TCP 回退、TTL 缓存） | 已实现 |

这里的“面向生产”表示实现包含防御性解析、资源上限、明确错误处理、凭据保护、清理逻辑、
测试和 CI，并不表示已经获得厂商认证。部署前必须在获得授权的测试环境中验证互操作性。

## 构建

最低支持 Rust 1.85。

```bash
cargo build --release
```

运行项目检查：

```bash
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

创建和配置 TUN 通常需要 root 或等效网络权限。`serve` 使用用户态 TCP/IP 栈，不创建
网络接口，也不需要提升权限。

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

如果没有设置 `OPENIWAN_PASSWORD`，客户端会从 `/dev/tty` 隐藏读取密码。不要把密码直接
放在命令行参数中。

为指定目标网段建立隧道：

```bash
sudo openiwan connect \
  --server 192.0.2.10:6001 \
  --username alice \
  --encryption xor \
  --route 10.0.0.0/8 \
  --route 2001:db8::/32
```

`--route` 接受 CIDR，`--route-ip` 创建主机路由，`--route-domain` 在连接前解析一次
域名。所有参数都以独立参数调用系统工具，不经过 shell。客户端拒绝默认路由以及会覆盖
当前 iWAN 数据端点的路由。

### 不修改路由地访问 HTTPS API

将一个固定的组织内 HTTPS origin 暴露为仅本机可访问的 HTTP 服务：

```bash
openiwan serve \
  --server 192.0.2.10:6001 \
  --username alice \
  --encryption xor \
  --upstream https://api.example.edu \
  --listen 127.0.0.1:8080
```

例如，本地请求 `http://127.0.0.1:8080/v1/profile?full=true` 会通过 iWAN 用户态
TCP/IP 栈访问 `https://api.example.edu/v1/profile?full=true`。请求方法、查询参数、
流式请求体和 `Authorization` 等业务头会保留，HTTPS 的 Host、SNI 和证书域名仍使用
原始上游域名。

`serve` 不打开 TUN，不调用系统路由工具，也不接受 `--route` 参数。监听地址必须是
回环地址；上游必须是没有路径、查询或用户信息的 HTTPS origin。默认使用系统根证书，
内部 CA 可通过可重复的 `--ca-cert organization-ca.pem` 添加。

默认 `--dns-mode auto` 会优先通过 iWAN 用户态栈查询 OPENACK 或托管 provider
提供的组织 DNS。它校验 DNS 事务和响应、支持 CNAME、按 TTL 缓存，并在 UDP
响应被截断时自动改用 DNS-over-TCP。这样 Shadowrocket 看不到内层 DNS 查询，
也无法返回 Fake-IP。USTC provider 已配置校内 DNS；旧的本地副本需要重新安装，
或在顶层加入：

```toml
dns_servers = ["202.38.64.1"]
```

手动模式或临时覆盖可使用 `--dns-server 202.38.64.1`。指定
`--dns-mode iwan` 可要求必须存在 iWAN DNS。`auto` 只有在没有任何 iWAN DNS
配置时才使用系统解析；已经配置的组织 DNS 如果查询失败会直接失败，不会泄露域名到
宿主机解析器。系统解析得到 `198.18.0.0/15` Fake-IP 时也会立即拒绝，而不是等待
无意义的 TCP 超时。`--upstream-ip` 仍保留为紧急运维覆盖，但正常生产运行不需要
预查 API 地址。

### 统一认证并连接

托管客户域使用外部 TOML 文件，因此认证和控制器参数变化时无需重新编译。先把仓库中的
USTC 示例安装成仅当前用户可读的文件：

```bash
install -d -m 700 "$HOME/.config/openiwan/providers"
install -m 600 examples/providers/ustc.toml \
  "$HOME/.config/openiwan/providers/ustc.toml"
```

普通用户可完成登录、保存加密线路配置和离线查看：

```bash
openiwan managed \
  --provider "$HOME/.config/openiwan/providers/ustc.toml" fetch
openiwan managed \
  --provider "$HOME/.config/openiwan/providers/ustc.toml" list
```

选择线路并连接：

```bash
sudo openiwan managed \
  --provider "$HOME/.config/openiwan/providers/ustc.toml" \
  connect --route-domain example.edu --route 10.0.0.0/8
```

将动作换成 `all` 可以一次完成登录、列出线路、选择和连接。access token 与解密后的线路
密码不会写入磁盘。provider 结构、状态文件和安全模型参见
[托管客户域文档](docs/MANAGED_PROVIDERS.md)。

也可以使用已经保存的托管线路启动无路由 HTTP 代理：

```bash
openiwan managed \
  --provider "$HOME/.config/openiwan/providers/ustc.toml" \
  serve --line-index 1 --upstream https://api.example.edu
```

也可以使用 TOML 配置：

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

完整命令行参数请运行 `openiwan --help` 或 `openiwan <command> --help`。

## 文档与贡献

技术文档以英语维护：

- [文档索引](docs/README.md)
- [线协议参考](docs/IWAN_PROTOCOL_2_3_0.md)
- [架构](docs/ARCHITECTURE.md)
- [托管客户域](docs/MANAGED_PROVIDERS.md)
- [逆向证据与限制](docs/REVERSE_ENGINEERING.md)
- [安全策略](SECURITY.md)

提交贡献前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)，参与社区即表示同意遵守
[行为准则](CODE_OF_CONDUCT.md)。安全问题请按照 [SECURITY.md](SECURITY.md) 私下报告。

## 安全说明

传统 iWAN 数据面使用 MD5、循环 XOR 或 AES-ECB，控制签名也不是现代消息认证码。这些机制
只用于兼容，不能提供现代 VPN 所预期的机密性、完整性、前向保密和对等方认证。

请仅在获得授权的网络中使用 `openiwan`，最好配合额外的可信安全层；如果端点支持更强的
协议，应优先使用更强协议。

## 许可证

`openiwan` 使用 [MIT License](LICENSE)。
