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

### 正式发行流程（2026-11-14 20:19，手动触发）

- 开发者手动同步 sing-box 官方正式 Release 源码及依赖，不自动拉取或更新源码。
- 审查并推送后，在 Actions 手动运行 `Build`；版本留空取 `VERSION`，也可显式输入。
- 测试与所有架构矩阵通过后才创建 tag 和正式 Release；已有 tag 会拒绝覆盖。
- 首次 Build 被 gofmt 门禁拦截，4 个 Go 文件已格式化；`make test`（race）和冻结向量检查通过。
- Linux 覆盖 amd64、arm、386、MIPS/MIPS64、PPC64LE、s390x、riscv64、loong64。
  Windows/macOS/FreeBSD 的 `socket_stub.go` 缺少运行所需的 FakeTCP 定义，不列入当前发行目标。
