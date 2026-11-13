# FlowTLS

> 外观是 HTTPS 的 TCP 连接，内核是 QUIC。
> 面向跨境高丢包链路的 TCP 伪装代理。

**实现状态**：主分支只维护 Go 实现，形态是 **sing-box 的一个独立协议库**
（与 hysteria2 / anytls 平级），发行版为 `sing-box 1.14.4-rev.N`。
最早验证协议的 Rust 实现已冻结在 `legacy-rust` 分支，仅作参考实现与历史记录
（详见 [`docs/EVOLUTION.md`](docs/EVOLUTION.md)）。

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
│  │  QUIC 状态机（quic-go）：多流复用 / 丢包恢复 / BBR      │  │
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
TCP 192.0.2.10:44311 → 198.51.100.4:8443  [PSH, ACK]
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

服务端在**同一端口**运行一个真实的 HTTPS 网站（真证书 + 真页面）。
扫描器访问得到正常的 HTTPS 响应；只有外层 AEAD 能成功解密的包才会进入代理逻辑，失败静默丢弃。

Rust 版把这个网站做在协议进程内（Rustls 内嵌）；
Go 版里 flowtls inbound 只做隧道，需要另起一个进程监听同端口
（nginx / caddy / 任意 HTTPS 服务，页面素材可用 `web/index.html`）。

### 5. 自适应，零配置

不需要填带宽。两端每 2 秒采样丢包率，自动调整拥塞窗口：

```
丢包 > 20%  →  窗口 × 0.90（收敛）
丢包 < 5%   →  窗口 × 1.20（探高）
范围        →  1.5MB ~ 8MB
```

同时受 quic-go 接收组装器的硬限制约束（单流最多 1024 个乱序空洞），
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

### 8. UDP 转发（不重传，对齐 hysteria2）

UDP 走 QUIC 的 **DATAGRAM 扩展（RFC 9221）**，入口是 SOCKS5 的 `UDP ASSOCIATE`：

```text
客户端 → 服务端：[session u32][addrLen u16][ATYP][ADDR][PORT][payload]
服务端 → 客户端：[session u32][payload]
```

语义与 hysteria2 完全一致——**不重传、不保序、队列满即丢、超 MTU 即丢**，
不做应用层分片。跨境链路 5~10% 丢包率下，DNS/WebRTC/游戏都表现正常
（它们本来就有自己的重试机制）。

注意 DNS 防泄漏要用 `socks5h://` 或 `--socks5-hostname`：域名交给服务端解析，
走 UDP 转发；用普通 `socks5://` 则 DNS 在本地解析。

## 快速开始

### 构建

```bash
# 唯一构建入口：从仓库根目录构建 rev 发行版
make build

# 产物
#   dist/sing-box-1.14.4-rev.1-linux-amd64
```

版本号由根目录 `VERSION` 文件驱动，构建期用 ldflags 注入，
**不改上游任何源码**。二进制名保持 `sing-box`，只靠版本号区分官方版。

```bash
make verify                  # 验收：版本号带 rev、tags 带 with_flowtls
make build GOARCH=arm64      # 交叉编译
make release-musl            # 静态 musl（软路由/NAS）
make upstream-pull TO=v1.15.0  # 同步上游 sing-box
```

### 服务端

```json
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "flowtls",
      "tag": "flowtls-in",
      "listen": "0.0.0.0",
      "listen_port": 8443,
      "password": "换成你自己的密码",
      "local_ip": "1.2.3.4",
      "ip_id_mark": 61687,
      "iptables_mode": "print"
    }
  ],
  "outbounds": [{ "type": "direct", "tag": "direct" }]
}
```

```bash
# 先做配置校验（不需要 root，这是硬要求）
./dist/sing-box-1.14.4-rev.1-linux-amd64 check -c server.json

# 再启动（需要 root 或 CAP_NET_RAW）
sudo ./dist/sing-box-1.14.4-rev.1-linux-amd64 run -c server.json
```

> 需要 root（raw socket + iptables），且机器必须**直接持有公网 IP**。
> `iptables_mode` 当前只支持 `none` / `print`（`auto` 尚未接线，见项目计划）。

### 客户端

```json
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 1080,
      "users": [{ "username": "admin", "password": "abcd1234" }]
    }
  ],
  "outbounds": [
    {
      "type": "flowtls",
      "tag": "flowtls-out",
      "server": "1.2.3.4",
      "server_port": 8443,
      "password": "与服务端一致",
      "source_port": 44300,
      "ip_id_mark": 61687,
      "sni": "your.domain"
    }
  ]
}
```

```bash
sudo ./dist/sing-box-1.14.4-rev.1-linux-amd64 run -c client.json

# SOCKS5 / HTTP 共用 mixed 入口
curl --socks5-hostname admin:abcd1234@127.0.0.1:1080 https://www.google.com
curl -x http://admin:abcd1234@127.0.0.1:1080 https://www.google.com
```

`mixed` 是 sing-box 自带的入口，还能直接换成 `tun`（全局代理）、
`redirect`、`tproxy` 等，不需要改 flowtls 任何代码。

### 从 Rust 版迁移

配置格式从 YAML 变成 JSON，字段有改名。逐字段对照表见
[`docs/MIGRATION.md`](docs/MIGRATION.md)。

### 自检

```bash
bash docs/interop_check.sh    # 冻结向量门禁（不需要 root，不需要 Rust）
bash docs/e2e_matrix.sh       # 真链路矩阵（需要 root）
```

## 实测数据

测试环境：100M 上下行的跨境链路（RTT 约 70ms，链路丢包 20%~44%）。
数据来自 Rust 参考实现（协议相同，wire format 未变）；Go 侧在回环链路上的
吞吐/时延与它一致，跨境链路尚未重测。

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

2. **只支持 IPv4**
   FakeTCP 层目前只处理 IPv4 报文。

3. **UDP 不做重传也不做分片**
   这是刻意选择（UDP 语义 + 对齐 hysteria2）。单包上限约 1200 字节，
   更大的 UDP 报文会被丢弃；5~10% 的包会在跨境链路上丢失，
   依赖应用层自己重试。

4. **需要 root 权限**
   raw socket、AF_PACKET 需要 root 或 `CAP_NET_RAW`；iptables 规则同理。

5. **默认避开 443 端口**
   国内出口设备对 443 的伪造 TCP 检查更严，建议 8443 / 9443。

6. **伪装网站需要另起进程**
   Rust 版把「同端口真证书网站」做在协议进程里；sing-box 的 flowtls inbound
   只做隧道，防主动探测要另外跑一个监听同端口的 HTTPS 服务
   （页面素材可用 [`web/index.html`](web/index.html)）。

7. **iptables 规则尚未自动落地**
   `iptables_mode` 只有 `none` / `print` 生效，`auto` 还没接线，
   部署时需按打印出的规则手工维护。

## 项目结构

```
flowtls/                     ← 独立 Go 模块 github.com/luowei729/flowtls
├── packet.go                # IP/TCP 头构造与解析、校验和、TS/wscale
├── codec.go                 # 伪 TLS 记录 + AEAD + 多用户 authID
├── addr.go                  # 地址帧编解码（流首帧 / DATAGRAM 内嵌）
├── udp.go                   # UDP 会话帧编解码
├── socket_linux.go          # AF_PACKET 收包 / IPPROTO_RAW 发包 / ARP
├── session.go               # 单条会话（net.PacketConn 语义）
├── listener.go              # 服务端：共享 raw socket + 四元组分发 + SYN 状态机
├── quic/
│   ├── client.go            # quic-go 客户端（多流复用 + UDP DATAGRAM）
│   └── server.go            # quic-go 服务端
├── cmd/ftdial/              # 联调：TCP（-streams N）
├── cmd/ftudp/               # 联调：UDP（-sessions N -rounds N）
├── cmd/ftserver/            # 联调：服务端
└── testdata/                # wire format v2 冻结向量（兼容性基线）

sing-box/                    ← git subtree，上游源码 + 最小补丁
├── protocol/flowtls/
│   ├── outbound.go          # 适配 adapter.Outbound
│   └── inbound.go           # 适配 adapter.Inbound
├── option/flowtls.go        # 配置结构
├── constant/flowtls.go      # 类型常量
└── include/flowtls.go       # 编译期开关（with_flowtls tag）

docs/                        # 设计、迁移、演进史、门禁脚本
web/index.html               # 伪装网站页面素材
Makefile + VERSION           # rev 发行版构建
```

Rust 参考实现的源码不在主分支，见 `legacy-rust` 分支。

## 文档

- [`CHANGELOG.md`](CHANGELOG.md) — 每个版本的改动与实测数据
- [`DEVTIPS.md`](DEVTIPS.md) — 踩过的坑与调试方法（强烈建议先读）
- [`docs/DESIGN.md`](docs/DESIGN.md) — 协议与架构设计细节（wire format 权威文档）
- [`docs/EVOLUTION.md`](docs/EVOLUTION.md) — 为什么从 Rust 换到 Go、Rust 冻结在哪
- [`docs/MIGRATION.md`](docs/MIGRATION.md) — Rust YAML → sing-box JSON 字段对照
- [`docs/SINGBOX_INTEGRATION.md`](docs/SINGBOX_INTEGRATION.md) — 接入 sing-box 的工程细节
- [`PROJECT_PLAN.md`](PROJECT_PLAN.md) — 里程碑与后续计划

## 免责声明

本项目仅用于网络协议研究与个人学习。请遵守当地法律法规，不要用于任何非法用途。
