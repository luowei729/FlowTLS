# AGENTS.md — FlowTLS 开发指南

## 项目是什么

FlowTLS 是一个「外观是 TCP + TLS、内部是 QUIC 数据报」的代理。
客户端与服务端之间不使用内核 TCP 栈：自己构造 IP/TCP 头，用 raw socket 收发，
所以底层是不可靠的，丢包恢复、多流复用、拥塞控制全部由 quinn-proto 负责。

同端口（默认 8443）还运行一个内核 TCP 的真证书网站，用于应对主动端口探测。
注意 443 端口实测不可用：国内出口设备对 443 的伪造 TCP 检查更严，包发不出去，
因此默认端口是 8443。

## 架构

```
本地入口 (SOCKS5 含 UDP ASSOCIATE / HTTP / HTTPS；HTTPS 默认开启，证书自签或自定义)
        │
        ▼
quinn-proto QUIC 状态机（单连接多流，BBR + 自适应窗口上限）
        │  QUIC 数据报（TCP 走双向流，UDP 走 RFC 9221 DATAGRAM）
        ▼
FakeTCP 层（src/faketcp）
  - 伪 TLS 记录外观：17 03 03 len + nonce + ChaCha20-Poly1305(QUIC)
  - 标准三次握手：SYN → SYN-ACK → ACK，之后才发数据
    （严格 NAT 会丢弃握手完成前的数据包；零等待版本已废弃）
  - AEAD 密钥 = HKDF-SHA256(password)，解密成功即鉴权
  - 伪包识别特征 = TCP 窗口缩放因子 wscale=12
    （IP ID 会被运营商 NAT 改写为 0，不能再用魔数分流）
        │  原始 IPv4 报文
        ▼
================ TCP 8443 ================
        │  原始 IPv4 报文
        ▼
FakeTCP 层（服务端，AEAD 验签失败静默丢弃）
        │
        ▼
quinn-proto QUIC → 出站 TCP（带 pending 字节背压）
同端口内核 TCP → rustls 真证书 → 内置 HTML 网站
```

## 目录结构

```
src/main.rs        CLI 入口
src/cli.rs         子命令定义
src/check.rs       配置校验（两端一致性 / 证书 / 规则）
src/config.rs      YAML 配置
src/client.rs      客户端事件循环、流表、本地入口装配
src/server.rs      服务端事件循环、流表、出站任务
src/faketcp/
  packet.rs        IP/TCP 头构造与解析、校验和
  socket.rs        AF_PACKET 收包 / IPPROTO_RAW 发包
  codec.rs         伪 TLS 记录 + AEAD + 伪 ClientHello/ServerHello
src/quic/
  config.rs        传输参数、自签证书
  capped.rs        带自适应窗口上限的 BBR（受 quinn MAX_CHUNKS 约束）
src/proxy/
  socks5.rs        RFC1928（CONNECT + UDP ASSOCIATE）+ RFC1929
  udp.rs           UDP 会话帧编解码（[session][addrLen][地址][载荷]）
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

配置校验（改配置后、重启前必跑，退出码 1 = 有错误）：

```bash
./target/debug/flowtls check --server server.yaml --client client.yaml
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
- **UDP 不走重传也不分片**：QUIC DATAGRAM 语义，队列满/超 MTU 即丢（对齐 hysteria2）；
  单包上限约 1200 字节，更大的 UDP 报文直接丢弃。
- 需要 root 或 CAP_NET_RAW；需要 iptables（或客户端公网 IP）。
- **必须直接持有公网 IP**：云主机只给内网地址 + NAT 映射时，网关会对 TCP 做状态检查，
  裸 SYN 会被丢弃（实测 Oracle Cloud 完全不可用）。
- **443 端口不可用**：国内出口设备对 443 的伪造 TCP 检查更严，建议用 8443/9443。
- **单流窗口受 quinn `MAX_CHUNKS=1024` 约束**：高丢包时窗口过大会以
  `too many gaps in stream buffer` 断连，因此用自适应窗口（1.5~8MB）规避。
- 跨境链路实测吞吐：单路 3.6MB/s、4 路并发 6.9MB/s、FAST.com 79/64 Mbps（100M 端口）。
- 内层 QUIC 证书是运行时自签，安全由外层 AEAD 保证。
