# AGENTS.md — FlowTLS 开发指南

## 项目是什么

FlowTLS 是一个「外观是 TCP + TLS、内部是 QUIC 数据报」的代理。
客户端与服务端之间不使用内核 TCP 栈：自己构造 IP/TCP 头，用 raw socket 收发，
所以底层是不可靠的，丢包恢复、多流复用、拥塞控制全部由 quinn-proto 负责。

同端口（默认 8443，生产建议 443）还运行一个内核 TCP 的真证书网站，
用于应对主动端口探测。

## 架构

```
本地入口 (SOCKS5 / HTTP / HTTPS)
        │
        ▼
quinn-proto QUIC 状态机（单连接多流，BBR）
        │  QUIC 数据报
        ▼
FakeTCP 层（src/faketcp）
  - 伪 TLS 记录外观：17 03 03 len + nonce + ChaCha20-Poly1305(QUIC)
  - 裸 SYN + 伪 ClientHello + 首个加密包同批发出，零等待
  - AEAD 密钥 = HKDF-SHA256(password)，解密成功即鉴权
        │  原始 IPv4 报文
        ▼
================ TCP 8443 / 443 ================
        │  原始 IPv4 报文
        ▼
FakeTCP 层（服务端，AEAD 验签失败静默丢弃）
        │
        ▼
quinn-proto QUIC → 出站 TCP
同端口内核 TCP → rustls 真证书 → 内置 HTML 网站
```

## 目录结构

```
src/main.rs        CLI 入口
src/cli.rs         子命令定义
src/config.rs      YAML 配置
src/client.rs      客户端事件循环、流表、本地入口装配
src/server.rs      服务端事件循环、流表、出站任务
src/faketcp/
  packet.rs        IP/TCP 头构造与解析、校验和
  socket.rs        AF_PACKET 收包 / IPPROTO_RAW 发包
  codec.rs         伪 TLS 记录 + AEAD + 伪 ClientHello/ServerHello
src/quic/
  config.rs        传输参数、BBR、自签证书
src/proxy/
  socks5.rs        RFC1928 + RFC1929
  http.rs          CONNECT + 普通 HTTP + Basic 认证；HTTPS 本地入口
src/site/          内核 TCP 真网站（rustls + HTTP/1.1）
src/rules.rs       iptables 规则检测与安装
web/index.html     内置伪装网站页面
deploy/            生产/测试配置
docs/DESIGN.md     协议细节
```

## 开发命令

```bash
cargo build                     # debug
cargo test                      # 单元测试
cargo build --release --target x86_64-unknown-linux-musl   # 静态二进制
```

本机联调：

```bash
./target/debug/flowtls server -c test/server.yaml
./target/debug/flowtls client -c test/client.yaml
curl --socks5-hostname 127.0.0.1:1080 --proxy-user admin:abcd1234 https://example.com/
```

## 部署命令

服务端（需要 root 或 CAP_NET_RAW）：

```bash
flowtls server -c server.yaml
```

客户端：

```bash
flowtls client -c client.yaml
```

`net.mode: auto` 时启动自动写入 iptables 规则；客户端有公网 IP 且配置
`handshake: none` 时可以设 `net.mode: none` 完全不用规则。

## 必须遵守的约束

1. 代码每步写中文注释，说明「做什么」和「为什么」。
2. 改动前输出「改动前总结」，改动后输出「改动后总结」。
3. 每次改动按北京时间更新 CHANGELOG.md、DEVTIPS.md、PROJECT_PLAN.md。
4. 根目录只放 AGENTS.md / CHANGELOG.md / DEPLOY_CREDENTIALS.md / DEVTIPS.md / PROJECT_PLAN.md，其他文档放 docs/。
5. 不要为了省事删除已有功能或绕过 iptables 分支；`net.mode: none` 只适用于客户端公网 IP 场景。

## 已知限制

- FakeTCP 目前只支持 IPv4。
- 需要 root 或 CAP_NET_RAW；需要 iptables（或客户端公网 IP）。
- 服务端与客户端之间的实际丢包率会影响吞吐，BBR 已开启，实测 1.6MB/s（10MB 下载）。
- 客户端的 `tick` 固定 5ms 驱动 QUIC 定时器，RTT 会略高于物理 RTT，后续可改成精确 deadline。
- 内层 QUIC 证书是运行时自签，安全由外层 AEAD 保证。
