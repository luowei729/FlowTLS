# FlowTLS

> 外观是 HTTPS 的 TCP 连接，内核是 QUIC。
> 面向跨境高丢包链路的 TCP 伪装代理。

## 它解决什么问题

| 场景 | 传统方案的问题 | FlowTLS 的做法 |
|---|---|---|
| 防火墙对 UDP/QUIC 做 QoS | hysteria2 等纯 UDP 方案被限速、被丢包 | 线上只走 **TCP + TLS 1.3**，和普通 HTTPS 无法区分 |
| 跨境链路丢包 30%~50% | 内核 TCP 拥塞控制过于保守，吞吐暴跌 | 内核换成 **QUIC**，自带丢包恢复、多流复用、低延迟 |
| 主动端口探测 | 简单端口转发会被识破 | **同端口运行真实网站**，真证书、真页面，探测者看到正常 HTTPS |
| 流量特征分析 | 固定包长、固定序列号容易被标记 | 伪 TLS 记录外观 + 递增 IP ID + 可配置窗口缩放因子 |

## 核心设计

```
┌─────────────┐                                    ┌─────────────┐
│  本地应用    │  SOCKS5 / HTTP / HTTPS             │  目标网站    │
└──────┬──────┘                                    └──────▲──────┘
       │                                                  │
┌──────▼──────────────────────────────────────────────────┴──────┐
│                          FlowTLS 客户端                        │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  QUIC 状态机（quinn-proto）：多流复用 / 丢包恢复 / BBR    │  │
│  └──────────────────────────┬───────────────────────────────┘  │
│  ┌──────────────────────────▼───────────────────────────────┐  │
│  │  伪装层：HKDF 派生密钥 + ChaCha20-Poly1305                │  │
│  │  输出 `17 03 03 len + nonce + 密文`（标准 TLS 记录）      │  │
│  └──────────────────────────┬───────────────────────────────┘  │
│  ┌──────────────────────────▼───────────────────────────────┐  │
│  │  FakeTCP：AF_PACKET 收包 + IPPROTO_RAW 手工构造 IP/TCP 头 │  │
│  │  裸 SYN → SYN-ACK → ACK → 数据（标准三次握手）            │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────┬───────────────────────────────┘
                                 │  TCP 8443，线上只见 TLS 记录
┌────────────────────────────────▼───────────────────────────────┐
│                          FlowTLS 服务端                        │
│  FakeTCP 收包 → 伪装层验签解密 → QUIC 状态机 → 出站 TCP        │
│  同端口内核 TCP：真证书网站（防主动探测）                       │
└────────────────────────────────────────────────────────────────┘
```

### 为什么是「FakeTCP」

内核 TCP 在高丢包链路上会不断降窗，跨境 50% 丢包时吞吐几乎归零。
FlowTLS 用 raw socket 绕过内核 TCP 栈，自己构造 IP/TCP 头，把 TCP 只当作**承载 QUIC 的壳**：

- 保留 TCP + TLS 的线上外观（过防火墙、过 QoS）
- 保留 QUIC 的无状态发包、丢包恢复、多流复用（抗丢包、低延迟）
- TCP 的 seq/ack 只是一层伪装，真正的可靠传输由 QUIC 负责

### 为什么握手要「标准三次握手」

早期版本把 SYN、伪 ClientHello、QUIC Initial 同批发出（零等待）。
在宽松网络上这能省一个 RTT，但在**严格 NAT**（如部分移动网络）上会被状态防火墙判定为非法包直接丢弃。

现在改为标准握手：

```
客户端                      服务端
  │── SYN ─────────────────▶│
  │◀────────── SYN-ACK ─────│
  │── ACK + ClientHello ───▶│
  │── QUIC Initial ────────▶│
  │◀────────── 数据 ────────▶│
```

代价只有建连时的 1 个 RTT（约 70ms），之后所有请求都在这条 QUIC 长连接上开新流，**不再握手**。

## 优势

### 1. 线上不可区分

抓包只能看到：

```
TCP 10.0.0.2:44311 → 1.2.3.4:8443  [PSH, ACK]
17 03 03 04 cc 86 23 83 0a de 75 ...   ← 标准 TLS 1.3 ApplicationData
```

没有 UDP、没有 QUIC 明文特征，DPI 看到的是一段普通 HTTPS 会话。

### 2. 抗丢包

底层不可靠，可靠性和重传全部由 QUIC 承担。BBR 拥塞控制 + 自适应窗口，在 30%~50% 丢包的跨境链路上仍能跑满可用带宽。

### 3. 低延迟

- 建连一次，之后全部多路复用
- ACK 频率扩展到 5ms（默认 25ms），降低 RTT 与 PTO 误判
- 单流 8MB / 连接 16MB 接收窗口

### 4. 抗主动探测

服务端在**同一端口**用内核 TCP 运行真实网站（Rustls + 真证书 + 静态页面）。
扫描器访问得到正常的 HTTPS 响应；只有外层 AEAD 能成功解密的包才会进入代理逻辑，失败静默丢弃。

### 5. 自适应，零配置

不需要填带宽。两端每 2 秒采样丢包率，自动调整拥塞窗口：

```
丢包 > 20%  →  窗口 × 0.90（收敛）
丢包 < 5%   →  窗口 × 1.20（探高）
范围        →  1.5MB ~ 8MB
```

同时受 quinn 接收组装器的硬限制约束（单流最多 1024 个乱序空洞），
按 `窗口 ÷ 包大小 × 丢包率 < 1024` 反算安全上限，避免高丢包时直接断连。

### 6. 断线自愈

```
QUIC 断开 → 退避 5s → 重新握手 → 恢复
连续失败 → 10s → 20s → 40s → 60s（封顶）
```

服务端重启、链路中断、QUIC 内部错误都能自动恢复，本地监听端口不会重复绑定。实测约 5 秒恢复。

### 7. 端到端背压

每一路流都有独立的 `pending` 字节计数。下行堵塞时暂停读取目标 socket，
让目标 TCP 窗口收缩，而不是把数据无限堆在内存里。
实测长时间大流量下 `pending` 与收包队列都保持接近 0。

## 快速开始

### 编译

```bash
cargo build --release
# 静态链接（推荐，方便部署到各种发行版）
cargo build --release --target x86_64-unknown-linux-musl
```

### 服务端

```yaml
# server.yaml
listen: ":8443"
password: "换成你自己的密码"
tls:
  cert: "/path/to/fullchain.pem"
  key: "/path/to/privkey.pem"
site:
  dir: ""                # 留空使用内置页面，也可指向静态站点目录
faketcp:
  ip_id_magic: 0xF107
  handshake: symbolic
  # 机器在 NAT 后面时显式指定公网 IP（否则路由探测会拿到内网地址）
  # local_ip: "1.2.3.4"
net:
  mode: "auto"           # 自动写入 iptables 规则
```

```bash
sudo ./flowtls server -c server.yaml
```

> 需要 root（raw socket + iptables），且机器必须**直接持有公网 IP**。

### 客户端

```yaml
# client.yaml
server: "1.2.3.4:8443"
password: "与服务端一致"
sni: "your.domain"
faketcp:
  source_port: 44300     # 固定源端口，用于精确拦截内核 RST
  handshake: symbolic
  ip_id_magic: 0xF107
socks5:
  listen: "0.0.0.0:1080"
  username: "admin"
  password: "abcd1234"
http:
  listen: "0.0.0.0:8080"
  username: "admin"
  password: "abcd1234"
net:
  mode: "auto"
```

```bash
sudo ./flowtls client -c client.yaml
# 之后：curl --socks5-hostname admin:abcd1234@127.0.0.1:1080 https://www.google.com
```

## 实测数据

测试环境：100M 上下行的跨境链路（RTT 约 70ms，链路丢包 20%~44%）。

| 项目 | 结果 |
|---|---|
| 单路下载 | 3.6 MB/s |
| 单路上传 | 3.9 MB/s |
| 4 路并发下载 | 6.9 MB/s（55 Mbps） |
| FAST.com | **下载 79 Mbps / 上传 64 Mbps** |
| 服务端内存 | 20~40 MB |
| 客户端内存 | 空闲 30 MB，50 条并发流时约 120 MB |

## 已知限制

1. **必须直接持有公网 IP**
   云主机只给内网地址 + NAT 映射时，网关会对 TCP 做状态检查，
   FakeTCP 的裸 SYN 会被丢弃（实测 Oracle Cloud 上完全不可用）。

2. **单流窗口受 quinn 空洞上限约束**
   quinn-proto 的接收组装器硬编码 `MAX_CHUNKS = 1024`，
   高丢包时窗口过大会以 `too many gaps in stream buffer` 断连。
   本项目用自适应窗口规避，但这也意味着极端丢包下窗口会被压到 1.5MB。

3. **只支持 IPv4**
   FakeTCP 层目前只处理 IPv4 报文。

4. **需要 root 权限**
   raw socket、AF_PACKET、iptables 都需要 root。

## 项目结构

```
src/
├── main.rs            # 入口与日志初始化
├── cli.rs             # 命令行（server / client）
├── config.rs          # 配置结构与默认值
├── rules.rs           # iptables 规则管理
├── faketcp/
│   ├── socket.rs      # AF_PACKET 收包 + IPPROTO_RAW 发包
│   ├── packet.rs      # IP/TCP 头构造、校验和、选项解析
│   └── codec.rs       # 伪 TLS 记录、HKDF + ChaCha20-Poly1305
├── quic/
│   ├── config.rs      # quinn-proto 传输参数
│   └── capped.rs      # 带自适应窗口上限的 BBR 控制器
├── proxy/
│   ├── socks5.rs      # SOCKS5 入口（含用户名密码）
│   └── http.rs        # HTTP / HTTPS 入口
├── site/mod.rs        # 同端口伪装网站（内核 TCP + 真证书）
├── server.rs          # 服务端主流程
└── client.rs          # 客户端主流程（含自动重连）
```

## 文档

- [`CHANGELOG.md`](CHANGELOG.md) — 每个版本的改动与实测数据
- [`DEVTIPS.md`](DEVTIPS.md) — 踩过的坑与调试方法（强烈建议先读）
- [`docs/DESIGN.md`](docs/DESIGN.md) — 协议与架构设计细节
- [`PROJECT_PLAN.md`](PROJECT_PLAN.md) — 里程碑与后续计划

## 免责声明

本项目仅用于网络协议研究与个人学习。请遵守当地法律法规，不要用于任何非法用途。
