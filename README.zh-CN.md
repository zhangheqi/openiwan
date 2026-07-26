# OpeniWAN

[![Crates.io](https://img.shields.io/crates/v/openiwan.svg)](https://crates.io/crates/openiwan)
[![docs.rs](https://img.shields.io/docsrs/openiwan.svg)](https://docs.rs/openiwan)
[![CI](https://img.shields.io/github/actions/workflow/status/zhangheqi/openiwan/ci.yml?branch=main&label=CI)](https://github.com/zhangheqi/openiwan/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/openiwan.svg)](LICENSE)

从 Android iWAN 2.3.0 逆向结果独立实现的 Rust 客户端与协议库。

[English](README.md) | [简体中文](README.zh-CN.md)

> [!IMPORTANT]
> OpeniWAN 与 Panabit 或任何网络运营方均无隶属、背书关系。只能在你有权访问的
> 系统和网络中使用。

## 兼容目标

0.3.0 以 Android 2.3.0 的逆向结果作为唯一协议契约，已经实现：

- 完整的标准包类型与 TLV 注册表；
- 带签名的认证、20 字节小端心跳、无状态 ping 和 `CLOSE`；
- Java US-ASCII 凭据转换、密码包装与会话密钥派生；
- 明文、仅循环前 8 字节密钥的 XOR、AES-128-ECB；
- 传统 IPv4/IPv6 数据类与旧式双分片重组；
- SR 头、方向相关路径、内外层加密、双分片发送、按 offset 重组和 SR monitor；
- OIDC Authorization Code + PKCE S256；
- 已确认的 `/config` 请求（响应保留为动态 JSON）；
- HTTP keepalive 的字段图、一次重试、签名规范化与 HMAC。

逆向无法唯一恢复 `/config` 总响应以及 `/lookup`、`/auth` 的完整 schema。因此，
这些内容不进入强类型 API。已知歧义见[协议参考](docs/IWAN_PROTOCOL_2_3_0.md)。

## 安装

需要 Rust 1.88 或更高版本：

```bash
cargo install openiwan --locked
```

从源码构建：

```bash
cargo build --release --locked
```

只依赖 UDP 协议库时可关闭默认的 `managed` 与 `forward` feature：

```bash
cargo add openiwan --no-default-features
```

## 命令行

探测端点：

```bash
openiwan ping --server 192.0.2.10:6001
```

仅认证、不创建接口：

```bash
openiwan auth \
  --server 192.0.2.10:6001 \
  --username alice \
  --encryption xor
```

未设置 `OPENIWAN_PASSWORD` 时会隐藏输入密码；也可使用权限受保护的
`--password-file`。密码不会作为命令行值传入。

创建 TUN 并添加显式路由：

```bash
sudo openiwan connect \
  --server 192.0.2.10:6001 \
  --username alice \
  --encryption xor \
  --route 10.0.0.0/8
```

Linux/Windows 默认接口名为 `openiwan0`，macOS 自动请求可用的 `utunN`。创建
接口和修改路由需要对应平台权限。默认路由以及包含当前 UDP 端点的路由会被拒绝。

解码传统或 SR 数据报：

```bash
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

认证与心跳时间均是 Android 2.3.0 的固定行为，不再作为“部署兼容”开关。

SR 连接追加：

```toml
[segment_routing]
id = 1
keepalive = true
encrypt_algo = "aes128"
encrypt_key = "0123456789abcdef"
links = [1, 258, 11259375]
```

`links` 使用控制器提供的客户端到网络逻辑顺序，只有发送 SR 包时才反转。
`encrypt_key` 是原始 UTF-8 字节；AES-128 取前 16 字节，AES-256 取前 32 字节。

```bash
openiwan auth --config openiwan.toml --username alice
```

## 不改路由的转发

可选 `forward` feature 使用用户态 IP 栈，不创建 TUN、不修改主机路由：

```bash
openiwan forward \
  --server 192.0.2.10:6001 \
  --username alice \
  --target tcp://db.internal.example:3306 \
  --listen 127.0.0.1:3307
```

`tcp://` 原样转发字节；`http://`、`https://` 对一个固定 origin 提供 HTTP/1.1
反向代理。HTTPS 会验证上游证书，并支持重复使用 `--ca-cert` 添加 CA。

## 托管配置

provider 文件只包含已确认的 OIDC、`/config`、keepalive 所需字段，参见
[托管说明](docs/MANAGED_PROVIDERS.md)与[非生产模板](examples/providers/example.toml)。

认证并打印动态 `/config` JSON：

```bash
openiwan managed \
  --provider provider.toml \
  --device-id device-identifier \
  config
```

CLI 不会落盘或猜测解析这个总响应。库调用者可读取
`ControllerConfiguration::raw`，在部署已知的位置反序列化已确认的 `SrEntry`，
再显式构造 `ClientConfig`。

## 代码模块

- `protocol`：标准头、TLV、控制签名、ping 与心跳；
- `crypto`：密码包装和会话加密；
- `fragment`：传统/SR 分片；
- `sr`：SR 封装、加密、数据规划和 monitor；
- `client`：认证与会话 worker；
- `managed`：OIDC、`/config`、SR serializer 模型和 HTTP keepalive；
- `tun`：原生接口与路由集成。

## 验证

仓库包含逆向规范中 OPEN、ping、签名 CLOSE、XOR、AES、SR 头、SR 外层 AES、
分片字、monitor body 和 keepalive HMAC 的逐字节向量测试。

```bash
cargo test --all-targets --all-features
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

通过合成向量不代表厂商认证，真实部署仍应在获授权端点验证。

## 安全限制

控制签名是 `MD5(header || "mw")`，不覆盖 body。XOR、AES-ECB 与 SR 外层 AES
都不提供数据完整性或重放保护，只用于兼容旧协议，不具备现代 VPN 的安全属性。

漏洞报告与运行建议见 [SECURITY.md](SECURITY.md)。

## 许可证

OpeniWAN 使用 [MIT License](LICENSE)。
