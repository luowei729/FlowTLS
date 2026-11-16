# PROJECT_PLAN — Go v3「原样移植 Rust」

## 0. 这次为什么重来

Go v1/v2 的失败不是个别 bug，而是**架构偏离**：

| 维度 | Rust（唯一基准） | Go v1/v2（已删除） |
|---|---|---|
| 发送 | 事件循环内 `poll_transmit` → **同步 `sendmmsg`** | `WriteTo` 只入队，独立协程批发送 |
| 结果 | RTT = 链路 RTT | 本地排队被 quic-go 计入 RTT（213ms vs 73ms） |
| 存活判定 | 无（只靠 QUIC idle timeout） | 自造 `lastSeenAt` + `Probe`，被内核 RST 欺骗 |
| 通道获取 | `ProxyClient.tx` 单一通道 | `getClient`/`dialing`/`attemptCtx`/`invalidate`/`suspectConn` 五层 |
| 拥塞控制 | BBR + 窗口钳制 | 额外加 Brutal（Rust 没有） |
| 分流 | IP ID 高字节 + `wscale=9` | 改成 `wscale=12` + conntrack 规则 + BPF |

结论：**只做翻译，不做设计**。凡 Rust 没有的机制一律不引入。

## 1. 硬规则（违反即回退）

1. **只用 `legacy-rust` 分支的 `src/` 作为唯一依据**。设计文档以代码为准，
   不以历史 DEVTIPS/CHANGELOG 里的自造结论为准。
2. **不自造机制**。不做 Probe、不做 suspectConn、不做发送队列、不做 Brutal、
   不做 BPF 过滤器、不做 conntrack 规则、不做额外重试层。
3. **wire format 逐字节对齐**，用 `legacy-rust` 的冻结向量做门禁。
4. **参数逐项照抄**：`wscale=9`、`initial_mtu=1332`、窗口 16MB/4MB、
   `keep_alive=10s`、`idle=30s`、`max_bidi=1024`、队列/水位常数。
5. **每个 Go 函数必须能指出它对应 Rust 的哪个函数**。对不上就说明我在发明。

## 2. Rust → Go 文件映射

| Rust | Go | 职责 |
|---|---|---|
| `faketcp/packet.rs` | `packet.go` | IP/TCP 拼装解析、`syn_options`、`TcpClock`、`advertised_window`、`seq_len`、IP ID |
| `faketcp/codec.rs`（1~300 行） | `codec.go` | `Obfs`（HKDF/AEAD/nonce 计数器/首包头）、`parse_records`、`parse_first_header` |
| `faketcp/codec.rs`（300 行后） | `handshake.go` | `build_client_hello`、`build_server_hello` |
| `faketcp/socket.rs` | `socket_linux.go` + `socket_stub.go` | `send`/`send_batch`/`recv`、AF_PACKET、ARP、默认路由 |
| `rules.rs` | `rules.go` + `rules_linux.go`/`rules_stub.go` | iptables 规则构造与落地 |
| `config.rs`（类型部分） | `config.go` | `ClientConfig`/`ServerConfig` |
| `proxy/mod.rs`（`encode_target`/`decode_target`） | `addr.go` | 地址帧 |
| `proxy/udp.rs` | `udp.go` | DATAGRAM 帧 |
| `client.rs::SendCtx` | `session.go` | **net.PacketConn 适配层**（quic-go 接口边界，见 §4） |
| `client.rs::run` + `run_session` | `client.go` | 握手、重连、stream/udp |
| `server.rs::run` + `ServerConn` + `handle_packet` | `server.go` | 四元组分流、会话、流/UDP |
| `quic/config.rs` | `quic/config.go` | quic-go 配置 |
| `quic/capped.rs` | `quic/capped.go` | BBR + 窗口钳制 |
| `proxy/{socks5,http,udp}.rs` | **不移植** | 由 sing-box 的 mixed/socks 入口提供 |
| `check.rs` | **不移植** | 由 `sing-box check` + `New*` 校验替代 |
| — | `sing-box/protocol/flowtls/{inbound,outbound,masquerade}.go` | 纯接线，无业务逻辑 |

## 3. 唯一的架构差异：quinn-proto → quic-go

这是**库边界**，不是设计选择。必须把影响压到最小：

| Rust（`quinn_proto`） | Go（`quic-go`） | 等价性 |
|---|---|---|
| 手动 `poll_transmit()` 取包 | quic-go 内部调 `WriteTo` | **`WriteTo` 内同步 `sendto` 即等价**（无队列、无额外协程） |
| 手动 `handle_timeout()` | quic-go 用 `SetReadDeadline` 驱动 | `ReadFrom` 必须真实实现 deadline |
| 手动 `conn.handle(datagram)` | quic-go 内部 reader 调 `ReadFrom` | `ReadFrom` 返回已解密明文即等价 |
| `Event::Stream(Opened/Readable)` | `conn.AcceptStream(ctx)` + 每流 goroutine | 结构相同（Rust 也是每流一个 task） |
| `datagrams().send/recv` | `conn.SendDatagram`/`ReceiveDatagram` | 一致 |
| `transport_config.ack_frequency(5ms)` | **quic-go 无此配置** | 不可对齐，如实记录 |
| `congestion_controller_factory` | `conn.SetCongestionControl(cc)` | 一致（只装一次，不重装） |

**发送路径的唯一结论**：`Session.WriteTo` = `seal` → `appendSegment` → `raw.Send()`，
全程同步，不排任何队列。这是 v1/v2 最致命的偏离点，v3 直接照 Rust。

批量 `sendmmsg` 只用于**我们自己**一次要发多个包的场合（握手：ACK+ClientHello；
服务端：ServerHello 三段）。quic-go 路径就是单包 `sendto`——与 Rust 的
`drain_transmits(n=1)` 等价。

## 4. `session.go` 允许存在什么

quic-go 要求 `net.PacketConn`，所以必须有一层适配。**只允许**：

- `ReadFrom`：从 `rx chan []byte`（深度 **8192**，同 Rust `mpsc::channel(8192)`）取；
  `select` 三分支：数据 / `readDeadline` / `closed`。
- `WriteTo`：持锁 `seal` + `appendSegment` + `raw.Send()`，**同步返回**。
- `LocalAddr`/`RemoteAddr`/`Close`/`SetReadDeadline`/`SetDeadline`。
- 统计字段（`pktsSent`/`pktsRecv`）供日志。

**不允许**：发送队列、flush 协程、ctrl 队列、`TxStats` 以外的新概念。

收包侧：一个 goroutine 阻塞 `raw.Recv()`（64KB 缓冲，同 Rust `vec![0u8; 65536]`），
按端口过滤 → 解析记录 → AEAD 解密 → `rx <- plain`。对应 Rust 的 recv 线程
（`client.rs:488-518`）。

## 5. 参数与常量对照表（逐项照抄）

```
WSCALE                 = 9               packet.rs
IPID_MARK              = 0xF100          packet.rs
TS_OPT_LEN             = 12              packet.rs
SYN 选项               MSS1460+SACK+TS+NOP+wscale9（20 字节）
advertised_window      = clamp((16MB-unread)>>9, 1, 65535)
initial_mtu            = 1332            quic/config.rs
min_mtu                = 1332
mtu_discovery          = off
receive_window         = 16MB
stream_receive_window  = 4MB
send_window            = clamp(max_cwnd*2, 2MB, 16MB)
keep_alive             = 10s
max_idle               = 30s
max_concurrent_bidi    = 1024
datagram recv/send buf = 1MB
ack 频率               = 5ms（quic-go 不支持，记录差异）
SYN 重传               1/2/4/8s，总超时 15s        client.rs
服务端 pending 复用    10 秒 + ISN 必须相同        server.rs
recv 通道深度          8192                        client.rs
PacketBatch::MAX       32                          socket.rs
pending_high_water     = clamp(max_cwnd/4, 512KB, 1MB)   server.rs
客户端 HIGH_WATER      = 1MB                       client.rs
自适应窗口             2s 周期；>20% ×0.9，<5% ×1.2；
                      safe_cap = 1024*1308/loss*0.7；
                      clamp(1.5MB, 8MB).min(max_cwnd)
```

## 6. 实施阶段与门禁

### P0 骨架
- `flowtls/go.mod`：`sagernet/sing`、`sagernet/quic-go` pseudoversion 与
  `sing-box/go.mod` **逐字节一致**；`GOTOOLCHAIN=local`。
- 从 `legacy-rust` 恢复 `flowtls/testdata/`（冻结向量）。
- **门禁**：`go build ./...`、`GOOS=darwin/windows` 交叉编译。

### P1 报文层
- `packet.go` ← `packet.rs`（含 `build_packet_into` 的追加语义）。
- `codec.go` / `handshake.go` ← `codec.rs`。
- `rules.go` ← `rules.rs`。
- **门禁**：`TestSynOptionsLayout`（20 字节逐字节）、`TestU32ExprHasHexPrefix`、
  `interop_check.sh`（Rust 向量 → Go 解密 → Go 向量 → Rust 解密）。

### P2 raw socket
- `socket_linux.go`：`send` / `send_batch`（sendmmsg）/ `recv`、
  `sockaddr_ll` **手写 20 字节**布局、AF_PACKET 阻塞发送、IPPROTO_RAW 回退、
  默认路由 + ARP。
- **门禁**：`TestSendmmsgAcceptsKernelLayout`（绕过退化路径直接断言内核接受）、
  `TestRecvmmsgActuallyReceives`（真收到包）。

### P3 客户端
- `session.go`（§4 的最小适配）+ `client.go`（握手、重连、stream/udp）。
- `quic/config.go`、`quic/capped.go`。
- 联调：`cmd/ftdial`。
- **门禁**：Go 客户端 ↔ **Rust 服务端** 单流 40MB 与 Rust 基线同量级（±10%）。

### P4 服务端
- `server.go`：四元组分流、SYN-ACK（pending 复用）、每客户端 Transport、
  流处理（`pending` / `flush_pending` / `reset_stream`）、UDP 出站。
- 联调：`cmd/ftserver`。
- **门禁**：**Rust 客户端** ↔ Go 服务端与 Go↔Rust 双向都通；
  4 流 × 10MB 无「背压超过 30 秒」；UDP 6 项 PASS。

### P5 sing-box 接线
- `inbound.go` / `outbound.go` / `masquerade.go`：只做 protocol ↔ sing-box 翻译。
- outbound 的连接获取：**单函数** `channel(ctx)`（Rust `ProxyClient` 单通道的等价物），
  不含 Probe / suspectConn。
- **门禁**：`sing-box check`（不用 root）、`make verify`、真链路 HTTP/HTTPS/UDP。

### P6 横向验证
- `docs/e2e_matrix.sh` 全绿；`bash docs/bench.sh` 延迟分层（纯隧道 = 1 RTT）。
- 连跑 30 分钟，采样 `/proc/net/packet` 确认 raw socket 数恒为 1（无泄漏）。
- **门禁**：`min_rtt` ≈ ICMP RTT；单流 100MB ≥ Rust 同刻结果。

## 7. 必须保留的正确性修正（不是设计，是语言/内核接口硬约束）

已实测确认，属于移植的一部分：

| 项 | 原因 | 不做的后果 |
|---|---|---|
| `sockaddr_ll` 手写 20 字节、family 在首位 | `syscall.SockaddrLinklayer` 布局与内核不符（48 字节、Protocol 在首） | sendmmsg 全静默失败 |
| AF_PACKET 发送 fd **不加 O_NONBLOCK** | Rust 也没加；非阻塞 + EAGAIN 静默丢弃会让握手包随机丢失 | 握手 851ms（链路 73ms） |
| 发送 socket 创建时 `protocol=0` | 传 `ETH_P_IP` 会让发送 fd 同时接收整机 IPv4 包，队列涨到 32MB 无人读 | RTT 随运行时间恶化 |
| recv 缓冲 ≥ 64KB + 检测 `MSG_TRUNC` | 网卡 GRO 聚合包可超 64KB，不足会静默截断（QUIC `lost=0`） | 握手慢、RTT 虚高 |
| `rawSocket` 必须有归属方并在 `Close` 关 fd | Rust 用 `Drop`；Go 无析构，漏关会累积泄漏 | 重连 N 次后 RTT 线性恶化 |
| `sendmmsg`/`recvmmsg` 对 `EINTR`/`ERESTARTSYS(512)` 重试 | Go 异步抢占发 SIGURG 会打断阻塞 syscall | 偶发丢一批包 |

**明确不做**：BPF 过滤器（本机无法验证，曾导致隧道不通）、conntrack 规则、
`wscale=12`、Brutal、Probe、发送队列。

## 8. 如何自证「没有夹带私货」

每个阶段结束时跑：

```bash
# Go 导出符号
grep -hoE '^func (\([^)]*\) )?[A-Z][A-Za-z0-9]*' flowtls/*.go | sed 's/.*[ )]//' | sort -u
# Rust 函数清单
git show legacy-rust:src/client.rs | grep -oE '^(pub )?(async )?fn [a-z_0-9]+' | sort -u
# 没有 Rust 对应物的符号 = 私货，必须能解释成「Go 接口边界」
```

## 9. 里程碑

| 阶段 | 内容 | 状态 |
|---|---|---|
| P0 | 骨架 + go.mod + 冻结向量 | **完成** |
| P1 | packet / codec / handshake / rules | **完成**（冻结向量 PASS） |
| P2 | raw socket | **完成**（sendmmsg 内核布局单测 PASS） |
| P3 | session + client + quic | **完成**（本机回环 45 MB/s） |
| P4 | server | **完成**（4 格矩阵含 UDP 全通） |
| P5 | sing-box 接线 | **完成**（双端 `check` 零 root 通过） |
| P6 | 横向验证 | **部分完成**，见下 |

### P6 剩余项（2026-11-14）

| 项目 | 结果 |
|---|---|
| 4 格互通矩阵（Go/Rust 双向 × TCP/UDP） | **10 / 10 PASS** |
| 冻结向量门禁 / 单测 `-race` / 双端 `check` | PASS |
| 延迟分层：ICMP 73.7ms、纯隧道 p50 75ms、HTTPS p50 160ms | **1 RTT，无额外开销** |
| 同源端口连续重启 2 次 | PASS（修复前必挂） |
| UDP 6 项 / 主动探测只回 1 个 SYN-ACK / 真证书 TLS 1.3 | PASS |
| 30 分钟稳定性 + `/proc/net/packet` 泄漏复查 | **待做** |
| 真链路吞吐追平 Rust | **已达标**（19:10 同窗口）：下载 Go 8.5 / Rust 6.7 MB/s，上传两边约 5.8 MB/s |
| 首字节追平链路 RTT | **已达标**：Go p50 77ms，Rust 同窗口 p50 98ms（链路约 73ms） |

下面「212ms」那条线索已经结案，保留是为了说明它怎么来的，不是现状。
原因见 `DEVTIPS.md` 113：延迟确认只在下一个包到达时才发，QUIC 把这段等待采进了 RTT。

### P6 差异审计结论（2026-11-14 15:30 更新）

逐函数对完 Rust 冻结版后，剩余差异只剩 5 项，逐项处置如下：

| # | 差异 | Rust | Go | 处置 |
|---|---|---|---|---|
| A | 收包批量 256 | 事件循环凑批 | 逐帧 | **已修**（`recvAvailable` + `drainAvailable`） |
| H | 纯 ACK 判定粒度 | 批末判一次 | 逐帧判 | **已修**（`flushDelayedACK`），纯 ACK −26~43% |
| D | ACK 延迟 | 5ms（ACK Frequency） | 25ms（常量） | **受依赖约束**：`quicgo.Config` 无字段可覆盖；且每 2 包立即回 ACK，实际影响仅限稀疏流量 |
| C | BBR 实现 | quinn 原生（`DRAIN_TO_TARGET=true`） | sing-quic `ProfileStandard` | **受依赖约束**：`Profile` 字段未导出，`ProfileConservative` 会同时改坏三个增益参数 |
| E/F | send_window / 初始窗口 | `max_cwnd×2` / 64KB | 无旋钮 / ~42.6KB | **受依赖约束**：`quicgo.Config` 与 `sing-quic` 均无入口 |

结论：A/H 已对齐；C/D/E/F 在「依赖版本必须与 sing-box 逐字节一致」
（`AGENTS.md` 约束 9）下无法对齐，除非改 quic-go / sing-quic 源码。

### 差异 I：丢包率统计失效（2026-11-14 16:15 修复）

**这是移植缺陷，不是库边界差异。** quic-go 的 `ConnectionStats().PacketsLost`
只在 `internal/congestion/cubic_sender.go` 里累加，**BBR 下恒为 0**。
而窗口自适应循环正是用它算丢包率 → 丢包率恒为 0 → 上限每 2 秒 ×1.2
只增不减，「高丢包压窗口」在 Go 里从未生效。

已修：`cappedBbr` 覆写 `OnCongestionEventEx` 自建计数。修复后
`loss_pct` 30（Rust 33）、`win_cap` 8MB → 1.5MB，与 Rust 对齐。

### 本机链路仿真的实测结论（重要）

用 `tc netem` + 端口过滤只对 8443 合成流限速（方法见 `DEVTIPS.md` 107），
200MB 单流下载：

| 条件 | Rust↔Rust | Go↔Go |
|---|---|---|
| 回环无延迟 | 44 MiB/s | 90 MiB/s |
| +70ms 单向延迟 | 13.1 MiB/s | 19.5 MiB/s |
| +2% / 5% / 10% 均匀丢包 | 10.4 / 8.0 / 6.4 MB/s | 9.3 / 7.6 / 6.0 MB/s |
| +突发丢包 gemodel≈5% | 3.3 MB/s | **<0.12 MB/s（停滞）** |

据此修正一个此前的判断：**「Go×Go 只有 Rust 一半」不能用均匀丢包解释**
——均匀丢包下两者差 3~10% 而已；Go 只在**突发丢包**下崩塌。
崩塌点已定位到内层 sing-quic BBR 的带宽估计（cwnd 在 8KB~25KB 震荡，
Rust 内层 cwnd 始终 ≥1.5MB），`ProfileConservative` 替换实验无效。
该行为在依赖内部，改它违反约束 9 → 记为已知限制。

**下一步（若继续）**：在真链路两端同时抓包、同一时钟对齐，
直接量「QUIC 包发出 → ACK 回来」与本地发送时刻的差，
确认真链路是否也是突发丢包模式；否则本机结论无法直接外推。

### 真链路验证结论（2026-11-14 16:35）—— 推翻「恒定慢 2 倍」

上一节的「下一步」已经做了，结论需要修正：

1. **真链路不是突发丢包**。用伪造 TCP 的 `seq:end` 空洞统计（不需要两端对时钟）：
   6543 个空洞 **100% 是单包丢失**。所以「gemodel 突发丢包」那组本机数据**不能外推**。
2. **真链路自身在 5~15 MB/s 之间漂移**：RTT 77ms → 235ms、累计丢包 2.6% → 9.5%。
   隔几分钟的两次测量没有可比性。
3. **交替 A/B（同一时间窗）**：

   | 轮次 | Go×Go | Rust↔Rust |
   |---|---|---|
   | 修 `isSYNACKFor` 前 | 15.5 / 5.0 / 0（握手超时） | 13.6 / 14.5 / 14.7 |
   | 修后 | 11.0 / 12.3 | 5.1 / 5.2 |

   **没有稳定的 2 倍差距**，两个实现互有胜负。历史上的「6~7 vs 15~16」
   基本可判定为非同时刻测量的产物。

4. 唯一确定属于我们代码的偏差已修：`isSYNACKFor` 比 Rust 多一个
   `p.Ack == synISN+1`，会把有效 SYN-ACK 静默丢弃（实测 7 次建连 3 次超时）。
   修复后握手失败 0 次。

17:04 曾把「窗口只钳在途字节、不钳 pacing」当成卡死原因，在 `cappedBbr` 加了
「一个最小 RTT 内最多突发一窗」。这层会把 ACK 也挡住，且部署后抓包仍是 221ms，
18:30 已删除。后来证实的原因是伪 TCP 延迟确认的发送时机，见下一节。

### 真链路结论（2026-11-14 19:10）—— RTT 已经回到链路本身

同一分钟、1080 只走 Go→Go、1081 只走 Rust→Rust，三段各 90 秒、互不抢带宽：

| 项 | Go | Rust |
|---|---|---|
| 首字节 p50 / 失败 | 77ms / 0（337 次） | 98ms / 0（188 次） |
| 下载 100MB p50 | 8.5 MB/s（7 次全完成） | 6.7 MB/s（6 次全完成） |
| 上传 20MB p50 | 5.8 MB/s（24 次全完成） | 5.9 MB/s（26 次全完成） |

不再把「Go 稳定慢一倍」当成未解决项。30 分钟长稳定性仍未单独跑过，
上面这三段各 90 秒不能替代它。

### 发行 rev.9、作废 rev.8（2026-11-17 03:40）

- rev.8 服务端漏写 `idleTimeout`，活会话约 1 秒被关掉。Release 与 tag 删除，
  避免 PassWall `releases/latest` 继续下发这个包。
- rev.9 = rev.8 + 超时赋值修复 + `markOf` 只比高字节。补丁包节点字段不变，
  包版本号升到 `1.14.4-r9`。
- 生产 8443 在替换二进制之前继续跑 rev.3。

### 正式发行流程（2026-11-14 20:19，手动触发）

- 开发者手动同步 sing-box 官方正式 Release 源码及依赖，不自动拉取或更新源码。
- 审查并推送后，在 Actions 手动运行 `Build`；版本留空取 `VERSION`，也可显式输入。
- 测试与所有架构矩阵通过后才创建 tag 和正式 Release；已有 tag 会拒绝覆盖。
- 首次发行 `v1.14.4-rev.1` 已完成：19 个 Linux 架构构建及 CI 验证全部通过，Release 含 SHA-256 校验文件。
- 首次 Build 被 gofmt 门禁拦截，4 个 Go 文件已格式化；`make test`（race）和冻结向量检查通过。
- Linux 覆盖 amd64、arm、386、MIPS/MIPS64、PPC64LE、s390x、riscv64、loong64。
  Windows/macOS/FreeBSD 的 `socket_stub.go` 缺少运行所需的 FakeTCP 定义，不列入当前发行目标。

### 伪装站默认页（2026-11-14 21:19）

- 省略 `site_dir` 时直接使用嵌入二进制的 `protocol/flowtls/web/index.html`，不再返回硬编码 “It works”。
- 显式 `site_dir` 仍优先；目录中缺少请求文件或首页时回退到嵌入页。
- 默认页回归测试及适配层 race 测试通过；需重新构建并部署二进制才会更新运行中的网站。

### 日志统一与加密开销基准（2026-11-15 12:05）

**日志**：`flowtls` 主包原有 11 处标准库 `log.Printf`，绕过 sing-box 的
`log.level`——配置成 `"level": "error"` 也无法安静。新增 `flowtls/log.go`
定义 `Logger` 接口（方法签名与 sing-box `log.ContextLogger` 逐字一致），
由适配层注入，**不新增任何配置项**。`nil` 语义为静默。

产物：`ClientConfig.Logger` / `ServerConfig.Logger`、`Session`/`Listener`/
`rawSocket` 的 logger 字段、`flowtls.StdLogger()`（仅联调工具）。
实测 `level: info` 时 20 次请求 0 条路径统计；`level: debug` 时每 2 秒 1 条。

**加密开销**：新增 `flowtls/codec_bench_test.go`，两端各跑一次。结论：

| 算法 | amd64 | 新加坡 ARM（1 核） |
|---|---:|---:|
| ChaCha20-Poly1305（线上） | 1959 ns | 6753 ns |
| AES-128-GCM | 828 ns | 1305 ns |

ARM 上 AES-GCM 快 5.2 倍，但 6753ns × 9400pps ≈ **6.3% 单核**，
不是「带宽跑不高」的根因。客户端 `utime/stime = 141930/180387`
说明瓶颈在 syscall（**内核态占 56%**），不在用户态加密。

待办（按收益排序）：
1. 查 AF_PACKET 收发的 syscall 批量效率（sendmmsg/recvmmsg 每批包数）；
2. 评估 AES-GCM 切换（收益约 5% 单核，且需处理密码派生与 wire format 兼容）；
3. 「只混淆不加密」不建议：ChaCha20 XOR 在 ARM 上 1742ns，
   相比完整 AEAD 的 6753ns 只省 74%，却完全失去鉴权与抗篡改。

### v3：AEAD 换 AES-128-GCM + 服务端 AF_PACKET 默认（2026-11-15 13:20）

**破坏性变更**：wire format v2 → v3，两端必须同时升级。

1. **AEAD**：ChaCha20-Poly1305 → AES-128-GCM，密钥 32→16 字节，salt/info 同步改 v3。
   记录布局不变（nonce 12 / tag 16 两者相同）。
2. **服务端发送**：默认 AF_PACKET（此前因 ARP 解析 bug 一直实际走 IPPROTO_RAW）。
   客户端默认保持 IPPROTO_RAW（下载方向只发 ACK，实测无收益）。
3. **ARP**：`parseARPFlags` 剥 `0x` 前缀；且只在真要 AF_PACKET 时才查表 →
   IPPROTO_RAW 路径不再白等 514ms。
4. **recvmmsg 批量收包：已回退**。它把 RTT 从 79ms 抬到 220ms（延迟确认心跳被拉长）。

实测（本地 100MB 文件源，交替 A/B，服务端 1 核 ARM）：

| 项 | 旧 | 新 | 变化 |
|---|---|---:|---:|
| 单流 100MB | 12.3 MB/s | 16.8 MB/s | +36% |
| 4 并发合计 | 12.7 MB/s | 17.0 MB/s | +34% |
| 服务端 CPU | 71.8% | 63.1% | −8.7pp |
| 　内核态 | 52.9% | 46.6% | −6.3pp |
| 每 MB/s 的 CPU | 5.49 %/(MB/s) | 3.78 %/(MB/s) | −31% |
| QUIC RTT | 78~80ms | 80~82ms | 无恶化 |
| 客户端建连 | ~514ms+ | 220~241ms | −294ms |

**下一步（按收益排序）**：
1. 内核态仍占 46.6%，是最大项。可动的是 `PACKET_QDISC_BYPASS`
   （本机 e1000 会静默丢包，需真机验证）与每包自建 IP/TCP 头的开销。
2. 加密已经不是瓶颈（ChaCha→AES 已把这一层吃干净），不要再从算法上找收益。

### QDISC_BYPASS 与构包开销（2026-11-15 14:20）—— 内核态优化第一轮

上一轮遗留两条待办，本轮都做了实测，结论一正一否。

#### 1. PACKET_QDISC_BYPASS：做了，−13% CPU/字节

生产服务端 `virtio_net`（1 核 ARM）传 100MB 的服务端 CPU：

| 配置 | CPU秒/MB | 样本 |
|---|---:|---|
| bypass 关闭 | 0.044 | 0.046 / 0.042 / 0.043 / 0.044 |
| bypass 开启 | **0.038** | 0.038 / 0.042 / 0.040 / 0.036 / 0.039 / 0.038 / 0.037 / 0.037 |

**实现方式是驱动白名单**，不是全局默认开启：

```go
var allowedQdiscBypassDrivers = map[string]bool{"virtio_net": true}
```

理由：该开关在 e1000/QEMU 上会让 `sendto` 返回成功而包不上线（DEVTIPS 84），
且完全静默（伪 TCP 层没有重传 → 只表现为「握手永远超时」，无任何日志）。
驱动名读 `/sys/class/net/<if>/device/driver`，读不到就不开（失败方向朝安全侧）。
启动日志会打印 `af_packet+qdisc_bypass`，避免「以为开了/以为没开」。
`FLOWTLS_QDISC_BYPASS=0/1` 可强制覆盖。

#### 2. 每包自建 IP/TCP 头：否掉了，只占约 1% 单核

新增 `flowtls/packet_bench_test.go`：

| 项 | ns/op |
|---|---:|
| `BuildPacketInto`（1332B 载荷，两次校验和） | 1001 |
| 　　其中 `sum16`（1364 字节扫描） | 294 |
| `BuildPacketInto`（纯 ACK，52 字节） | 62 |

9400pps（100Mbps 单向）≈ 0.94% 单核；16 MB/s（15700pps）≈ 1.6%。
**不是瓶颈，不要动它。** 这与「加密是瓶颈」是同一类误判——时间全在内核态。

#### 3. 顺带修正一条错误结论

上一轮把「RTT 从 79ms 恶化到 220ms」归因于 recvmmsg 批量收包并据此回退。
**该归因已证伪**：同一份未改动的 rev.1 二进制只换监听端口（8443 → 9743）
就从 77ms 变成 221ms；把两版本端口对调后，v3 在 8443 也是 221ms、
rev.1 在 9443 也是 220ms。220ms 是跨境链路的流级别/时段性两态，
与本仓改动无关。详见 DEVTIPS 125。

#### 下一步（内核态仍在 46% 上下）

1. **减小包数**：受路径实测 MTU ≥1428 限制，当前总包 1417，
   最多还能提约 1% → **不做**。
2. **接收侧 recvmmsg**：理论收益存在（一轮 256 次 recvfrom → 32 次 syscall），
   但必须先解决「同端口可信 A/B」的方法问题（DEVTIPS 125），
   否则无法判断收益真假 → 暂缓。
3. **AF_PACKET TX_RING（mmap 零拷贝环）**：唯一还有量级收益的方向，
   能省掉每包一次 skb 分配 + 用户态→内核拷贝。代价是环满即丢包，
   要自己实现背压，工程量与风险都显著高于本轮改动 → 记为后续候选。

### 内核态优化第二轮（2026-11-15 16:00）—— 两条待办实测，都不做

上一节列的三条待办里，#1（减小包数，上限 +1%）已判不做；
本轮把 #2（recvmmsg）与 #3（TX_RING）都完整实现并测完。

**方法**：同端口 ABAB 交替（`docs/ab_kernel.sh`），判据用服务端 CPU秒/MB
（与链路状态无关），每档 3 轮 × 3 循环。

| 档 | n | CPU秒/MB 中位 | 范围 | 判定 |
|---|---:|---:|---|---|
| 基线（逐帧 recvfrom + sendmmsg） | 8 | 0.0402 | 0.0378~0.0431 | — |
| recvmmsg（8 槽位 × 128KB） | 6 | 0.0388 | 0.0376~0.0431 | 噪声内，**不成立** |
| TX_RING（mmap 环，SOCK_RAW） | 6 | **0.0426** | 0.0412~0.0486 | **慢 16%** |

**recvmmsg**：理论上限本就只有 ~2%（一轮 55 帧，省 48 次 syscall ≈ 24µs，
而处理这 55 帧要 ~3ms）。实测与上限一致 → **syscall 次数不是瓶颈**。
实现保留为可选（默认关闭，`FLOWTLS_RECVMMSG=1`），无副作用。

**TX_RING**：只省「用户态→内核」一次拷贝，内核 `tpacket_snd` 仍要
`skb_copy_to_linear_data`；且**必须 SOCK_RAW**（SOCK_DGRAM 下无法指定目的 MAC，
4 种布局实测全部静默丢包），要多写 14 字节以太网头。
净效果 −16%，**生产代码已删除**，只留 `flowtls/txring_probe_test.go` 作证据。

#### 待办更新：socket 层已经走到头

内核态仍是最大项（~46%），但剩下的都是**每包必然发生**的工作：
skb 分配、设备 DMA、软中断、部分 netfilter。用户态能动的四件事已逐个量完：

| 项 | 结论 |
|---|---|
| 加密算法 | ChaCha→AES 已做（−8.7pp CPU） |
| 发送路径 | AF_PACKET + QDISC_BYPASS 已做（−13% CPU/字节） |
| 构包开销 | 实测 ~1% 单核，不做 |
| 批量 syscall（收/发） | 发送已 sendmmsg 64/批；接收 recvmmsg 无收益 |

**下一步方向应转向用户态传输层**（quic-go 的 ACK 策略 / 发送调度 / BBR 参数）
或**减少包数**，而不是继续在 socket 层找收益。

### quic-go 用户态路径的可动范围（2026-11-15 17:30）—— 读完代码后的实测结论

上一节写「下一步方向应转向用户态传输层（ACK 策略 / 发送调度 / BBR 参数）」。
逐行读完 `sagernet/quic-go`、`sing-quic/congestion_meta2` 与
`sing-quic/hysteria2` 之后，这个建议要**大幅下调预期**：三样里有两样改不了。

#### 先明确「三方」是谁

```
quic-go 上游 (quic-go/quic-go)
    └─ fork → sagernet/quic-go v0.61.0-sing-box-mod.12   ← 我们与 hy2 共用
            ├─ hy2 (sing-quic/hysteria2)
            └─ flowtls（+ 我们自己的 cappedBbr）
```

**我们和 sing-box 里的 hy2 用的是同一份 quic-go fork、同一个 BBR 库。**
所以差异不在库，而在各自在上面叠了什么。

#### 1. ACK 策略：三方都改不了

| 位置 | 内容 |
|---|---|
| `internal/ackhandler/received_packet_tracker.go:79` | `const packetsBeforeAck = 2` |
| `internal/protocol/params.go:150` | `const MaxAckDelay = 25 * time.Millisecond` |
| `connection.go:536` | `false, // ACK_FREQUENCY is not supported yet` |

`quic.Config` 的 30 个字段里**没有任何 ACK 或 pacing 相关项**。

| 实现 | ACK 可调 |
|---|---|
| 原版 quic-go | ❌ 常量写死 |
| sagernet fork | ❌ 只加了解析，不发 ACK_FREQUENCY 帧 |
| hy2（sing-box 版） | ❌ 同一份 fork，`hysteria2/client.go` grep `ack` 零命中 |
| **我们的 Rust 版** | ✅ quinn 有 `ack_frequency(max_ack_delay=5ms)` |

这是 Go 版与 Rust 版唯一确定无法对齐的项（差异 D）。
要改必须 fork quic-go 改 `internal/` 常量 → 违反 `AGENTS.md` 约束 9。

> 实际影响比看起来小：`packetsBeforeAck=2` 意味着批量传输时每 2 包立即回 ACK，
> 25ms 只是「凑不满 2 包」的兜底，只对稀疏流量（单次 HTTP 请求）生效。

#### 2. 发送调度：差异最大，但不是设计选择

| 实现 | 方式 | 每批 syscall |
|---|---|---|
| 原版 quic-go / hy2 | `WriteTo` 每包 `sendto`，靠内核 **UDP GSO** 合批 | 1 次发 64KB |
| **我们** | `txCh`(64) → `txLoop` 攒批 → **`sendmmsg(64)`** | 1 次发 ~90KB |

根因：**GSO 是 UDP 特性**。我们跑在 `AF_PACKET` 伪造 TCP 上，
`Config.GSO` 无意义，内核不会帮我们 segmentation。
所以 sendmmsg 批量化不是优化选择，是**没有 GSO 后的必然替代品**。

**已知偏离**：`§3` 写的是「`WriteTo` 内同步 sendto（无队列、无额外协程）」，
当前实现是排队的。历史原因是 sendmmsg 必须攒批。
风险有记录（DEVTIPS：v1 用 4096 深队列曾把 RTT 从 73ms 抬到 213ms），
现在 `txQueueDepth=64` + 醒来立即排空把影响压住了（实测 srtt 80~85ms），
**但这个设计是有代价的，不是免费的**。

#### 3. BBR 参数：同库，我们少了两个旋钮

BBR 本体同源（`congestion_meta2` 移植自 quiche `bbr_sender.cc`）。
`ProfileStandard` 实际参数：

```
highGain = 2.885 (2/ln2)   highCwndGain = 2.0
congestionWindowGainConstant = 2.0   numStartupRtts = 3
bytesLostMultiplier = 2
```

| 能力 | hy2 | 我们 |
|---|---|---|
| 选 Profile | ✅ `bbrProfile` 配置项 | ❌ 硬编码 `ProfileStandard` |
| Brutal 拥塞控制 | ✅ | ❌（Rust 也没有，刻意不加） |
| **窗口上限钳制** | ❌ | ✅ **`cappedBbr`** |
| 按丢包率自适应窗口 | ❌ | ✅ 每 2s ×0.9 / ×1.2 |

`cappedBbr` 是我们独有的一层，也是唯一能防止 BBR 把窗口打到虚高的机制。

#### 4. 传输参数差异

| 参数 | 我们 | hy2 | 原因 |
|---|---|---|---|
| `InitialPacketSize` | **1332** | 默认 1280 | 外层封装固定 33 字节算出来的 |
| `DisablePathMTUDiscovery` | **true** | false（Linux 开） | 跨境丢包被 BlackHoleDetector 误判打回 1200 |
| `StreamReceiveWindow` | 4MB | 8MB | quinn 组装器 `MAX_CHUNKS=1024` 约束 |
| `ConnReceiveWindow` | 16MB | 20MB | 同上 |
| `MaxIdleTimeout` | 30s | 30s | 一致 |

#### 结论：能动的只剩常量微调

| 分类 | 项 | 处置 |
|---|---|---|
| ✅ 已动 | 加密算法（AES）、AF_PACKET+QDISC_BYPASS、cappedBbr | 完成 |
| ⚠️ 可尝试 | 换 `ProfileConservative` | **已测失败**：同时改坏三个增益参数，突发丢包下 <0.12 MB/s |
| ⚠️ 可尝试 | 调 `cappedBbr` 自适应阈值 | lossHighMark/LowMark 已调过（15%/0.85 太激进） |
| ⚠️ 可尝试 | 调 `StreamReceiveWindow` | 4MB 是组装器算出的安全值 |
| ⚠️ 可尝试 | 缩短 `txCh` 排队 | 已 64，再小牺牲 sendmmsg 收益 |
| ❌ 卡死 | ACK 策略 / pacing / send_window / 初始窗口 | 无配置入口，改了违反约束 9 |

**以后要探索的方向（按性价比排序）**：

1. **重写 `internal/` 常量**（fork 或 `replace` 到本地副本）——
   唯一能拿到 ACK 5ms 收益的路，但违反约束 9，要单独评估是否值得。
2. **实测 `cappedBbr` 阈值的重新标定**——用真链路多时段数据，
   而不是拍脑袋的 20%/5%。这条不需要改依赖，风险最低。
3. **减少包数**：受路径 MTU 限制，上限约 1% → 不做。
4. **接受现状**：内核态与用户态都已逐个量完，
   单流 16.8 MB/s / 4 并发 17.0 MB/s 已是这条链路 + 这个实现的合理水平。

---

# Windows 支持（B 路线：WinDivert）

> 状态：**真机已跑通**（2026-11-15）。Windows 10 客户端经 SOCKS5 走新加坡服务端，
> 出口为服务器公网地址，下载约 3.1 MB/s。
> 三个只在真机上暴露的问题见 `DEVTIPS.md` 第 140、141、142 条：
> 注入包校验和位要留 0、收包要补以太网头、客户端过滤器要加源端口。
> 本文档其余部分记录设计依据与实现边界。

## W0. 为什么不能走原生 socket

微软自 Vista 起禁止用 raw socket 构造 TCP/UDP 包（防源地址伪造）：

- `IP_HDRINCL` 只对 ICMP 生效，TCP/UDP 被内核拒绝（`WSAEINVAL`）
- 源地址必须存在于本机网卡
- 没有 `AF_PACKET` 的对应物

所以「像 Linux 那样自己写 IP/TCP 头」在 Windows 上**系统层面封死**，
唯一可行路径是内核层的包拦截驱动。

## W1. 选型：WinDivert（复用 sing-box 已有实现）

| 方案 | 结论 |
|---|---|
| **WinDivert** | ✅ 采用 |
| Npcap | ❌ 需要 cgo（破坏 `CGO_ENABLED=0`）、每包跨驱动边界、仍需管理员 |
| WFP 自研驱动 | ❌ 要签名证书，成本远超收益 |
| WSL2 | ⚠️ 不是「Windows 原生」，但作为部署建议保留（见 §W8） |

**关键发现：sing-box 上游已自带 cgo-free 的 WinDivert 绑定，并在生产中使用。**

```
sing-box/common/windivert/            纯 syscall（DeviceIoControl），无 cgo
  ├── handle_windows.go               Open/Recv/RecvBatch/Send/SendBatch/Close
  ├── driver_windows.go               驱动自动安装（SCM + 服务创建）
  ├── driver_asset_windows.go         驱动落盘到 UserCacheDir + SHA256 校验
  ├── filter.go                       过滤器 VM 指令编码（纯逻辑，无 syscall）
  └── assets/WinDivert64.sys          已微软签名，94KB，嵌入二进制
sing-box/common/tlsspoof/raw_windows.go    ← 生产用例：伪造 TCP 包注入
```

`tlsspoof` 做的事与本项目同构（构造伪造 TCP 包、注入、控制时序），
说明这条路径在 Windows 上是被验证过的。

**部署代价为零**：驱动 `.sys` 用 `go:embed` 嵌进二进制，首次 `Open()`
自动落盘到 `%LocalAppData%\flowtls\windivert\v2.2.2\` 并注册服务。
用户只需要 `sing-box.exe` 一个文件。

## W2. 语义差异：Linux 与 Windows 的模型根本不同

这是**最容易写错的地方**，单独成节。

| | Linux (`AF_PACKET`) | Windows (`WinDivert`) |
|---|---|---|
| 收包 | **被动复制**，内核照常处理同一份包 | **扣留**，内核看不到，直到我们放行或丢弃 |
| 「不是我的包」 | 忽略即可，内核已经处理了 | **必须重新注入**，否则包被销毁 |
| 丢弃 | `iptables DROP` + AF_PACKET 照旧收到 | **不重新注入** 就是丢弃 |
| 注入 | 自己构 IP 头 + `sendmmsg` | 同，但走 `WinDivertSend`（`Outbound` 位决定方向） |

由此得到两条结论：

1. **WinDivert 天然合并了「收包 + 阻断内核」两件事**，不再需要
   `iptables` 的 raw/PREROUTING u32 规则，也不再需要客户端 OUTPUT 挡 RST 的规则
   —— 因为内核**从未看到**这些包，不会生成 SYN-ACK / RST。
2. **服务端必须实现「非本协议的包重新注入」**，否则伪装网站的 0.4% 连接
   （IP ID 随机落入 mark 区间）会被静默吞掉。Linux 侧该路径是 no-op。

## W3. 过滤器设计

WinDivert 的过滤器在 `Open()` 时确定，无法动态修改，因此必须一次写准。

字段编号取自 `windivert.h` 的 `WINDIVERT_FILTER_FIELD_*`
（已有实现只导出了十几个，本实现补齐 `ip.Id` / `tcp.Syn` / `tcp.Rst` /
`tcp.PayloadLength`）：

| 字段 | ID | 用途 |
|---|---:|---|
| `inbound` / `outbound` | 1 / 2 | 方向 |
| `ip` / `tcp` | 5 / 8 | 协议判定 |
| `ip.Id` | 18 | **IP ID 标记**（本协议的分流特征） |
| `tcp.SrcPort` / `tcp.DstPort` | 38 / 39 | 端口 |
| `tcp.Rst` / `tcp.Syn` | 46 / 47 | 标志位 |
| `tcp.PayloadLength` | 52 | 载荷长度 |

### 服务端（一个共享句柄，对应 `Listener.raw`）

```
inbound and ip and tcp and tcp.DstPort == <listenPort>
        and ip.Id >= <mark> and ip.Id <= <mark|0xFF>
```

- `mark` 由 `HKDF-SHA256(password)` 派生（`flowtls/mark.go`），低字节是递增序号，
  所以区间是 256 个值。不再支持配置里手填 `ip_id_mark`。
- **不含 outbound**：服务端发出的 SYN-ACK / 数据由我们自己注入，
  若把 outbound 也纳入，注入的包会被再次扣留，形成自环。
- 该过滤器会命中真实浏览器的 SYN 约 1/256（IP ID 随机），
  由 §W4 的重新注入兜底。

### 客户端（一个句柄，对应 `Session.raw`）

```
inbound and ip == 1 and ip.DstAddr == <localIP>
        and tcp == 1 and tcp.DstPort in [sourcePort, sourcePort]
        and tcp.SrcPort == <serverPort>
```

- **`tcp.SrcPort` 那条不能省**。真机上验证过：只有目的端口条件时，本机其它
  进程连同一个服务端端口的回包会撞上固定的 `source_port`，被一并扣留——
  那些连接被掐断，包还混进本会话（看到过 ACK 号完全对不上的 FIN）。
- **不加 IP ID 条件**：客户端不需要面对伪装站。
- **不含 outbound**：同上，避免注入自环。
- 该过滤器覆盖 4 元组的全部入向包，因此内核永远看不到服务端的 SYN-ACK →
  **不会产生 RST**，Linux 那条 `OUTPUT` 规则在 Windows 上没有对应物也不需要。

### 伪装站（masquerade）

WinDivert 只扣留匹配的包，真实浏览器的流量不匹配就直接走内核 TCP 栈，
**不需要** Linux 那套「iptables DROP + AF_PACKET 抢包」的配合。
`masquerade.go` 一行都不用改。

## W4. 「不是我的包」必须重新注入（新增协议语义）

`handlePacket` 现在用「返回 nil」同时表示三种情况，无法区分是否已消费。
改为显式返回 `consumed bool`：

| 路径 | consumed | Windows 动作 |
|---|---|---|
| 纯 SYN（带 mark） | true | 不回注（丢弃内核可见性，我们自己回 SYN-ACK） |
| 已有会话的数据包 | true | 不回注 |
| 首包鉴权成功 | true | 不回注 |
| 首包鉴权失败 / 无载荷非 SYN | **false** | **重新注入**（还给内核） |

`rawSocket.Reinject(pkt)`：
- Linux：no-op，注释说明「AF_PACKET 是被动复制，内核已处理」。
- Windows：`Send` 回去，`Outbound` 保持原值（入向包要以入向身份回注）。

由 `rawSocket.reinjectUnmatched` 布尔位控制，Linux 上只是一次布尔判断。

## W5. 实现文件划分

| 文件 | build tag | 内容 | 可在 Linux 测试 |
|---|---|---|---|
| `flowtls/windivert_filter.go` | 无 | Address / Filter / VM 编码 / 过滤器构造器 | ✅ **是** |
| `flowtls/windivert_filter_test.go` | 无 | 编码字节级断言 | ✅ **是** |
| `flowtls/windivert_windows.go` | `windows && (amd64\|\|386)` | Handle、DeviceIoControl、驱动安装 | ❌ |
| `flowtls/windivert_assets_windows.go` | 同上 | `go:embed` 驱动 + 许可证 | ❌ |
| `flowtls/windivert_assets/` | — | `WinDivert64.sys` / `WinDivert32.sys` / `LICENSE.txt` | — |
| `flowtls/socket_windows.go` | `windows && (amd64\|\|386)` | `rawSocket` 实现 | ❌ |
| `flowtls/socket_stub.go` | `!linux && !windows` | 其余平台空实现 | — |
| `flowtls/rules_windows.go` | `windows` | 空规则（解释为什么不需要） | — |

**为什么把过滤器编码单独拆成无 tag 文件**：VM 指令布局（`field:11 | test:5 |
success:16`、24 字节、小端）是纯字节操作，写错的概率远高于 syscall 部分，
而它**可以在 Linux 上做字节级断言**。这是本项目里唯一能真正验证的 Windows 相关逻辑。

## W6. 与 Linux 的常量/行为差异

| 项 | Linux | Windows | 说明 |
|---|---|---|---|
| 批量发送上限 | `maxSendBatch=64` | `BatchMax=255` | 取 64 保持一致 |
| 批量接收 | 逐帧（`recvmmsg` 默认关） | 逐帧（`RecvBatch` 未启用） | 同 Linux 结论：无收益 |
| 收包缓冲 | 256KB | `MTUMax`=40+65535 | WinDivert 按 IP 总长切分 |
| 堆积队列 | `SO_RCVBUF 8MB` | 驱动默认（未导出调参） | 绑定未导出 `WinDivertSetParam` |
| QDISC_BYPASS | 驱动白名单 | 无对应物 | — |
| ARP / 下一跳 MAC | 必需 | **完全不需要** | 注入在 IP 层 |
| 源地址纠正 | 必需（NAT 云主机） | 不需要 | 非 Linux 场景 |
| 建连固定开销 | 0（已修 ARP 白查） | 0 | — |

**白捡的好处**：`resolveNeighborMAC` / `arpLookup` / `addrOnHost` /
`isLocalDst` / `interfaceDriver` 这一整套在 Windows 上都不需要，
`newRawSocket` 的 Windows 版本只有约 60 行。

## W7. 验证策略（如实记录能力边界）

| 项目 | 状态 | 手段 |
|---|---|---|
| 交叉编译 windows/amd64 + 386 | ✅ 可做 | `GOOS=windows go build ./...` |
| 过滤器 VM 编码 | ✅ 可做 | 字节级单测（无 build tag） |
| 批量收发包拼接（back-to-back + Address 数组） | ✅ 可做 | 抽成纯函数后单测 |
| 全平台编译门禁（含 darwin/freebsd） | ✅ 可做 | CI + `make verify` |
| **WinDivert 驱动交互** | ❌ **阻塞** | 需要 Windows 主机 |
| **Windows 上端到端连通** | ❌ **阻塞** | 需要 Windows 主机 + 服务端 |
| **Windows 性能指标** | ❌ **阻塞** | 同上，且需同链路对照 |

**必须说清的结论**：本轮交付的是「编译通过 + 纯逻辑单测通过」。
**没有一行 Windows 代码在真机上跑过**。首次部署必须按 §W9 的手工清单验证。

## W8. 已知限制与风险

| 项 | 严重度 | 说明 |
|---|---|---|
| **杀软拦截驱动** | ⚠️ 高 | WinDivert 被大量恶意软件滥用，360 / Defender / 火绒常直接拦加载。这是**部署层**问题，代码无法绕过 |
| 需要管理员权限 | ⚠️ 中 | 与 Linux root 对等，`ERROR_ACCESS_DENIED` |
| 性能预期更差 | ⚠️ 中 | 每包一次内核↔用户拷贝 + WFP callout。Linux 侧内核态已占 46%，Windows 只会更高 |
| 仅 amd64 / 386 | ⚠️ 中 | 上游无 arm64 驱动资产；Windows ARM64 不支持 |
| 过滤器无法动态改 | 低 | `source_port` / `listen_port` 变更需重建连接（本来也是） |
| 驱动落盘路径 | 低 | `%LocalAppData%\flowtls\windivert\v2.2.2\`。**不**复用官方 sing-box 的目录：两个产品的驱动版本会一起漂移。若官方 sing-box 已把 WinDivert 服务跑起来，`CreateFile` 会直接成功并复用该服务；版本不匹配时 IOCTL 的 magic/版本校验会明确报错，不会静默错配 |
| 服务端跑在 NAT 后 | 低 | 未做源地址纠正，Windows 服务端部署属非常规场景 |

**WSL2 仍然是更省事的 Windows 方案**：完整 Linux 内核，`AF_PACKET` 可用，
直接跑现有 linux-amd64 二进制，性能与 Linux 一致。仅在需要「真正 Windows 原生
进程 + 不需要 WSL」时才用 B 路线。

## W9. 首次部署的验证（未验证项）

**已经脚本化**：`docs/windows_smoke.ps1`。管理员 PowerShell 里一条命令跑完全部
检查并输出报告：

```powershell
$env:FLOWTLS_SERVER = '203.0.113.10:8443'   # 从环境变量取，不写进仓库
$env:FLOWTLS_SOCKS  = '127.0.0.1:1080'
.\docs\windows_smoke.ps1 -Bin .\sing-box.exe -Config .\client.json
```

覆盖：管理员权限 / CPU 架构 / 端口占用 / 启动与「发送路径」断言 /
驱动落盘 / 服务注册 / SOCKS5 出口 / 8MB 下载 / **同端口伪装站可达**
（专验重新注入）/ CPU 与内存采样 / 进程退出。失败时直接把
`ACCESS_DENIED`、`1275 DRIVER_BLOCKED`、`577 INVALID_IMAGE_HASH` 翻译成结论。

下面的原始清单保留，供脚本无法覆盖的场景手工核对：

```powershell
# 1. 以管理员身份运行，确认驱动能装
.\sing-box.exe run -c client.json
#    期望：日志出现 "发送路径: windivert"
#    失败 ERROR_ACCESS_DENIED  → 不是管理员
#    失败 1275 (ERROR_DRIVER_BLOCKED) → 杀软拦截，需加白名单

# 2. 确认驱动落盘（我们自己的目录，不与官方 sing-box 共用）
dir %LocalAppData%\flowtls\windivert\v2.2.2\

# 3. 确认服务注册
sc query WinDivert

# 4. 端到端
curl -x http://admin:PASSWORD@127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace
#    期望输出服务端 IP

# 5. 服务端伪装站不受影响（服务端在 Windows 时才需要）
curl -k https://<server>:8443/
#    期望真证书站点正常响应（验证 §W4 的重新注入生效）

# 6. 卸载：`sc stop WinDivert ; sc delete WinDivert`（服务名不带版本后缀）
```

## W10. 实施顺序（状态）

| # | 事项 | 文件 | 状态 |
|---|---|---|---|
| 1 | 过滤器 VM + 批量拼接 + Address 布局 + 9 个单测 | `windivert_filter.go` / `windivert_filter_test.go` | ✅ |
| 2 | Handle + IOCTL + 驱动安装/资产 | `windivert_windows.go` / `windivert_assets*` | ✅ 编译通过，未真机运行 |
| 3 | `rawSocket` 实现 | `socket_windows.go` | ✅ 编译通过，未真机运行 |
| 4 | `consumed` 拆分 + `Reinject` | `listener.go` | ✅ （Linux 路径行为不变，由单测覆盖） |
| 5 | `socket_stub.go` build tag 调整 | `socket_stub.go` | ✅ `!linux && !windows` |
| 6 | 空规则层 | `rules_windows.go` | ✅ `init()` 关掉 `rulesBackendEnabled` |
| 7 | Makefile / CI 门禁 | `Makefile` `platforms`，`ci.yml`，`build.yml` | ✅ 8 个平台组合 |
| 8 | 文档 | `AGENTS.md` / `README.md` / `DEVTIPS.md` / `CHANGELOG.md` | ✅ |

### 实施中修正的两个设计细节

1. **不把 `IP ID` 判断写进 WinDivert 过滤器**。原计划想用 `ip.Id` 字段在驱动侧
   过滤掉非本协议的包（省掉每包一次用户态判断）。放弃原因：`windivert.h` 没有
   vendor 进本仓库，`ip.Id` 的字段号无法核对，而字段号错一位的后果是
   **一个包都收不到** —— 与「链路断了」表现完全相同，排查成本极高。
   现在 IP ID 标记仍在用户态 `handlePacket` 里判断，过滤器只按「入向 + TCP +
   端口」粗筛。多一次用户态判断，换来可排查性。
2. **`socketRole` 从 `socket_windows.go` 移到 `socket_common.go`**。
   Linux 的 `newRawSocket` 也要用这个类型，留在 Windows 文件里会让 Linux 编译
   直接失败（`_windows.go` 后缀的文件不参与 Linux 构建）。

### 实现中推翻/修正的设计（**动手之后发现的，比计划更值钱**）

1. **§W4 的「未消费就还给内核」不完整**。判据必须是 IP ID 标记，不是
   「认证是否成功」：带标记但认证失败的包还给内核会引出 RST，中间设备拆
   NAT 映射，而客户端源端口固定、正在重建同一四元组。已抽成
   `shouldReinject` / `protocolOwned` 纯函数 + 真值表单测（`reinject_test.go`）。
   详见 `DEVTIPS.md` 第 136 条。
2. **收包地址不能存字段**。`WINDIVERT_ADDRESS` 必须与帧一起流动
   （`frameHandle`），否则收包协程的下一次 `Recv` 会覆盖它，注入到错误的
   接口上，表现为「伪装站偶发连不上」。详见 `DEVTIPS.md` 第 137 条。
3. **windows/386 发不出去**（上游 `cronet-go` 无 386 实现），发行矩阵只留
   windows/amd64。详见 `DEVTIPS.md` 第 138 条。
4. **内嵌驱动的 LGPLv3 许可证要随包发**（`licenses/WinDivert-LGPLv3.txt`）。
   详见 `DEVTIPS.md` 第 139 条。

### W7 补充：已实际验证到的范围

```
✅ 完整 sing-box windows/amd64 二进制交叉编译（79MB PE32+，全部 windows tag）
✅ flowtls 模块 8 个平台组合编译（make platforms）
✅ windows go vet
✅ 9 个 WinDivert 过滤器/批量拼接单测（在 Linux 上跑）
✅ 3 个 reinject 决策真值表单测
✅ 驱动字节确实内嵌进 exe（.sys 中间 512 字节片段在 exe 中连续命中）
✅ Linux 视角 EmbedFiles 为空（Linux 二进制不含驱动，不需要 LGPL 附录）
❌ 驱动 IOCTL / 安装 / 卸载 / 注入时序 / 端到端 / 性能 —— 全部仍需 Windows 主机
```

### 顺带修掉的既有 bug

`socket_stub.go`（macOS/FreeBSD）**一直编译不过**：上层按**字段**读
`s.raw.localIP`，而 stub 里只有 `LocalIP()` 方法，没有字段。这个文件自己的注释
还写着「保证能交叉编译」。发行目标只有 Linux，CI 也没跑这些平台，所以从未被
发现。现在 `make verify` 与 CI 都跑 8 个平台组合的编译门禁。
