# PROJECT_PLAN

## 2026-11-14 当前阶段：Go v2「精简移植」

### 为什么推倒重来（用户决策）

Go v1 功能全通，但**代码结构与 Rust 严重偏离**，导致排障成本不断上升：

| 维度 | Rust v1（冻结基线） | Go v1（归档） |
|---|---|---|
| 传输层 | `faketcp/{packet,codec,socket}` 三层，职责单一 | 同左，但 `session.go` 1229 行、`socket_linux.go` 971 行 |
| 连接模型 | `client.rs` / `server.rs` **一个事件循环 + 显式状态** | `quic/client.go` 897 + `quic/server.go` 289 + 适配层 1267 |
| 抽象层数 | 0 层包装（`drain_transmits` 直接发） | `udpConn`/`udpSession`/`inboundPacketConn`/`streamConn`/`suspectConn`/`dialing`/`attemptCtx`/`invalidate` |
| 故障定位 | 看一处 event loop 的日志 | 需要跨 4 个包、6 层包装反推 |

结论：**继续在 v1 上打补丁，每修一个 bug 都会新增一层抽象**
（`suspectConn` 就是为了绕开「连接已死但未检测到」而加的，结果它自己又引入
「本端 Close 引发的读错误被误判 → 每个请求重建连接」的新 bug）。因此采纳用户建议：

> 重新制定开发计划，Go 代码归档，精简高效地移植 Rust 代码，
> 而不是越写越复杂、排查问题越来越难。

### 归档（已完成）

| 名称 | 内容 |
|---|---|
| tag `go-v1-archive-20261114` | 归档点：发送队列修复后、重构前 |
| 分支 `legacy-go` | 指向同一 commit，长期保留 |
| `legacy-rust` 分支 | Rust 权威实现（wire format 与行为基准） |
| `docs/PROJECT_PLAN-v1.md` | v1 计划原文 |

回滚方式：`git checkout legacy-go`。

### 本轮已定位并修复的三个真根因（v1 上完成，v2 必须保留）

三个都是「Go 移植时丢了 Rust 的关键判断或语义」，不是调参问题：

| # | 缺陷 | 证据 | 修法 |
|---|---|---|---|
| 1 | **服务端分流丢了 IP ID 判断**，任何 SYN 都回 SYN-ACK | 双端抓包：同一四元组收到两个不同 ISN 的 SYN-ACK（内核 + flowtls）；客户端取到内核那个后，后续 ack 全错 | 按 wscale 分流（TCP 选项不被 NAT 改写），见下 |
| 2 | **IP ID 分流本身不可靠** | 掩码匹配 `& 0x1E00 == 0x1E00` 有 1/16 误命中率；部分链路改写 IP ID | 主特征改为 **wscale=12**（`U32WScaleExpr`，偏移 56 = `NOP+kind3+len3+12`） |
| 3 | **发送队列过深且满了丢弃**，本地排队被计入 RTT | quic-go 在打包时记录发送时刻；队列 4096 深时实测 RTT 213ms~1.02s，而 ICMP 73ms | 队列降到 32，满时阻塞生产者；纯 ACK 走独立队列/协程；`sendBatch` 对剩余报文重试 |

**修复后实测（新加坡 ARM，Go↔Go）**

| 指标 | 修复前 | 修复后 |
|---|---|---|
| QUIC min_rtt（客户端） | 213ms | **81.2ms** |
| QUIC min_rtt（服务端） | 213ms | **80.3ms** |
| 伪 TCP 握手（抓包） | 214ms | **80.8ms** |
| 10MB 下载 ×6 | 3.4~17.7 MB/s（抖动大） | **14.7~16.1 MB/s** |
| 普通 curl 访问 8443 | 收到 2 个 SYN-ACK | 只收到内核 1 个 ✅ |

### v2 目标结构（与 Rust 一一对应）

原则：**一个概念只出现在一个文件里，不做「为了通用」的包装。**

```
flowtls/                       传输层（与 v1 相同，仅收窄 API）
  packet.go / codec.go         保持不变（wire format 冻结）
  socket_linux.go              sendmmsg/recvmmsg；只暴露 Send/SendBatch
  session.go                   ← 精简目标：1229 → ~700 行
  listener.go                  四元组分流；按 wscale 判伪 SYN

flowtls/quic/                  QUIC 适配（对外只暴露 Client / Server）
  client.go                   ← 精简目标：897 → ~450 行
  server.go                   289 行，基本不变
  capped_bbr.go               BBR + 窗口上限（逻辑与 Rust capped.rs 对齐）

sing-box/protocol/flowtls/     只有两个文件（无第三个抽象层）
  outbound.go                 ← 精简目标：537 → ~260 行
  inbound.go                  ← 精简目标：730 → ~360 行
  masquerade.go               不变
```

### 具体精简清单

**outbound.go（目标 -50%）**

| 删除 | 理由 | 替代 |
|---|---|---|
| `suspectConn` | 它解决「连接已死未检测到」，但同时引入「本端 Close 引发的读错误被误判 → 每请求重建连接」 | 统一的 `channelAlive()`：只在 `DialConn` 失败或 `Probe` 失败时失效 |
| `dialing chan struct{}` + `attemptCtx` | 三层重试（getClient / attemptCtx / DialContext 各一层）叠加 | 单层：`channel(ctx)` 内部保证「并发建连只建一次」 |
| `invalidate` 的「只失效指定 client」 | 是为修 `suspectConn` 造的 bug 而存在 | 连接失效只有 `channel` 一个入口 |

**inbound.go（目标 -50%）**

| 删除 | 理由 | 替代 |
|---|---|---|
| `inboundPacketConn` 每会话 channel + 协程 | 会话多时 goroutine 爆炸 | 单分发协程 + 每会话 `pipe`（对齐 hy2 `service_packet.go`） |
| `serveConn` 的双 `wg` 嵌套 | 两层 WaitGroup 只为了等 streams/datagrams 结束 | `conn.Context()` 已能判定结束 |

**session.go**

| 删除 | 理由 |
|---|---|
| `txDropped` 的「队列满丢弃」路径 | 改为阻塞后不再需要（保留计数仅用于关闭时） |
| `sendFIN` 的同步发送 | 与 `Close` 顺序耦合，改为入队 + `txStop` 前 flush |

### 验收门禁（每步都要过）

1. `cd flowtls && go test -race ./...`
2. `make build` + `make verify`（版本号带 rev、tags 带 with_flowtls）
3. `./dist/... check -c client.json`（不需要 root，AGENTS.md 硬要求）
4. `bash docs/interop_check.sh`（wire format 未漂移）
5. 真链路：伪 TCP 握手 ≤ 100ms、`min_rtt` ≤ 100ms、10MB 下载 ≥ 10MB/s（≥5 轮报区间）
6. 普通 `curl http://server:8443/` 只收到 1 个 SYN-ACK（分流正确）
7. `GOOS=darwin/windows go build ./...` 能过（交叉编译）

### 里程碑

| 阶段 | 内容 | 状态 |
|---|---|---|
| A | 归档 Go v1（tag + 分支 + 计划原文） | ✅ |
| B | 三个真根因修复（分流 / 队列 / ACK 通道） | ✅ |
| C | 精简 `outbound.go`（删 suspectConn 三件套） | 进行中 |
| D | 精简 `inbound.go`（UDP 会话单分发） | 待办 |
| E | 精简 `session.go`（收窄发送 API） | 待办 |
| F | 文档收敛：AGENTS / DESIGN / DEVTIPS 与代码一致 | 待办 |

---

## 历史（Go v1，已归档）

保留原始里程碑供追溯，详见 `docs/PROJECT_PLAN-v1.md`、`DEVTIPS.md`、`CHANGELOG.md`。

| 阶段 | 内容 | 状态 |
|---|---|---|
| P0 | subtree + 补丁 + stub 注册 + Makefile | ✅ |
| P1 | `flowtls/` 主包：packet/codec/socket/session | ✅ |
| P2 | `quic/` 子包 + Go 客户端打通 Rust 服务端 | ✅ |
| P3 | UDP（QUIC DATAGRAM）+ 多会话路由 | ✅ |
| P4 | `listener.go` + `protocol/flowtls/` 适配层 | ✅ |
| P5 | 打包、CI、配置迁移、冻结 Rust | ✅（Rust 已冻结） |
