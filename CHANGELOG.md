# CHANGELOG

## 2026-11-14 20:19 (北京时间)

### 调整：放弃自动更新上游源码，改为手动触发全架构发布

删除自动同步上游 workflow。开发者手动同步 sing-box 正式 Release 源码与依赖，
检查后在 Actions 手动运行 `Build`；输入版本（默认取 `VERSION`），先跑测试和
全架构矩阵，全部通过才创建 `v<版本>` tag 与正式 Release。已存在的 tag 会被拒绝，
避免覆盖版本。

先前试行自动同步时遇到开发分支依赖冲突和 workflow 派发 403；自动方案已停止，
失败过程没有创建正式 Release。

## 2026-11-14 19:16 (北京时间)

### 核对：测速期间两端日志里的 ERROR 不是故障

用户自己测速后核对了当前进程的日志。客户端（18:55 启动，`client-sg-1080.json`）
182 条 ERROR，服务端（18:55:32 启动，pid 3480954）103 条 ERROR。
两边都是同一种：

```
connection download closed: stream N canceled by local|remote with error code 0
```

客户端是 `by local`，服务端是 `by remote`。目标是测速节点，
持续时间集中在 15 秒和 60 秒，19:12 之前每分钟只有 1~2 条。
同一时段没有 panic、握手失败、收包截断。错误码 0 是 QUIC 的 `NO_ERROR`，
测速程序自己关掉下载就会这样。详见 `DEVTIPS.md` 114。

## 2026-11-14 19:10 (北京时间)

### 实测：修复后的 Go 与 Rust 同窗口完整对比

两端都是当前修复版。1080 只走 Go→Go，1081 只走 Rust→Rust，同一分钟并行，
三段分开跑，互不抢带宽。每段 90 秒。上传接收端会读完请求体并回 `200`。

| 项 | Go | Rust |
|---|---|---|
| 首字节，样本 / 失败 | 337 / 0 | 188 / 0 |
| 首字节 min / p50 / p90 / max | 73 / 77 / 84 / 448 ms | 84 / 98 / 104 / 297 ms |
| 首字节标准差 | 33 ms | 23 ms |
| 下载 100MB，完整次数 | 7 | 6 |
| 下载 min / p50 / max | 6.7 / 8.5 / 9.1 MB/s | 6.1 / 6.7 / 7.2 MB/s |
| 上传 20MB，完整次数 / 失败 | 24 / 0 | 26 / 0 |
| 上传 min / p50 / max | 4.7 / 5.8 / 6.4 MB/s | 5.2 / 5.9 / 7.5 MB/s |

首字节长尾各有一次（Go 448ms、Rust 297ms），其余都贴着 p50。
上传和下载没有失败，也没有中断在半截的样本。

## 2026-11-14 19:30 (北京时间)

### sing-box/protocol/flowtls/web/index.html 已替换为 NGINX 的默认页面

伪装页面默认改为 nginx 官方的默认页面

## 2026-11-14 19:05 (北京时间)

### 修复：延迟确认只在下一个包到达时才发送，单个响应的 ACK 被推迟一个往返

`flushDelayedACK` 原来只在 `Recv` 返回之后调用。一个请求或一个响应之后
没有下一个包，累计未确认的数据段就一直攒着，直到保活或下一次请求。
两端对抓把方向定清了：

| 位置 | 修复前 |
|---|---|
| 服务端网卡：请求到达 → TCP ACK 发出 | 0.08ms |
| 客户端网卡：同一段 | 221ms |

差额是客户端把对端响应的 ACK 压住，QUIC 的 RTT 采样采到的就是这段。

修法：客户端 `recvLoop` 和服务端 `Listener.recvLoop` 都用单独的收包协程，
主循环每 5ms 醒一次。没有新包也调用 `flushDelayedACK`。规则没变
（满 2 段或超过 40ms），只是判断不再依赖下一个包。

验证（修复后，1080 Go→Go 与 1081 Rust→Rust 同时测）：

| 项 | Go | Rust |
|---|---|---|
| 首字节，连续采样 | 74–77ms（6 次） | 86–99ms（3 次） |
| 服务端网卡：请求到达 → ACK → 响应 | 0.06ms / 26ms | — |
| 客户端收到响应 | 80ms | — |

## 2026-11-14 18:30 (北京时间)

### 去掉握手完成后自己加的一轮发送等待

通道只在建立时握手一次。之后每个 QUIC 包都是 `WriteTo` 直接封成
TCP 段，交给 `txLoop` 看到就发，不再看握手状态。

`cappedBbr` 里此前多加了 `HasPacingBudget` / `TimeUntilSend`：
一个窗口发满后要等到下一个 RTT 才放行，ACK 和数据包走同一条判断。
Rust 没有这层。已删除。窗口上限仍由 `GetCongestionWindow` 和
`CanSend` 钳住，发包节奏交回内层 BBR。

部署后复测（1080 → 8443）：请求离开本机到对端 ACK 回来仍是 **221ms**
（Rust 同刻 79ms）。所以这 140ms 不是这层等待造成的。
对端收到后立即回了 TCP ACK，QUIC 的响应是到点才发。

## 2026-11-14 17:45 (北京时间)

### 真链路并行对照：Go 的 RTT 稳定地比 Rust 多约一个往返

经跳板 `198.51.100.11` 连新加坡。两条隧道同时存在、不交叉：

- 1080：本机 Go 客户端 → 远端 Go 服务端（8443），生产进程未动
- 1081：本机 Rust 客户端 → 远端 Rust 服务端（8445），源端口 44321

同一 3 分钟窗口（各约 150~370 次小请求，下载各 9~10 次 100MB，全部 HTTP 200）：

| 项 | Go→Go | Rust→Rust |
|---|---|---|
| 应用层首字节 | p50 **252ms**，最小 227，p90 281，最大 514，标准差 49.5ms | p50 **113ms**，最小 86，p90 134，最大 244，标准差 19.5ms |
| 空闲 QUIC RTT | 服务端稳定报 **220~221ms** | 两端都报 **80~85ms** |
| 下载 | 4.79~5.90 MB/s，p50 5.31 | 4.40~6.85 MB/s，p50 4.96 |

差额约 140ms，接近两条隧道各自的一个往返，不是本机 `netem` 那种链路漂移。
下载速度这次没有稳定差距。上传没跑成：远端 18081 不接收 POST，
直连 SSH 又超时，没有在这次测量里改远端。

**顺手修了一处时钟换算**（`flowtls/quic/capped.go`）：突发窗口的起点原来
经过 `time.Unix` 绕回墙上时间。`monotime` 是单调时钟，NTP 拨一下墙上时间
就会让到期判断提前或推迟。改为直接保存单调时钟的纳秒。
`TestBurstQuota` / `TestBurstFollowsWindow` PASS。
**2026-11-14 18:10 补充**：两端都换成了包含这条修正的二进制。
抓包确认差额不是链路：Rust 请求往返 79ms，Go 216ms，包在本机是立即发出的，
137ms 发生在对端收到之后、ACK 离开之前。给收包循环加 5ms 唤醒的尝试
没有改变这个数字，已撤回。1080 已切到当前代码，旧客户端不再保留。

## 2026-11-14 17:04 (北京时间)

### 修复：窗口上限只钳了在途字节，没有钳发送速率

**对照**：Rust `CappedBbr::window()` 被 quinn 的 pacing 直接拿去算
`capacity = window / rtt`，所以钳窗口同时限制了突发和持续速率。
quic-go 的 pacer 读的是 BBR 自己的带宽估计，`GetCongestionWindow` 只管在途上限。
之前的移植只覆写了 `GetCongestionWindow` 和 `CanSend`，
带宽估计一旦被抬高，会在一个 RTT 内把整窗数据突发打出去，然后干等 ACK——
表现为「连接活着但没速度」。

**修法**（`flowtls/quic/capped.go`，不改依赖、不改自适应参数）：
覆写 `TimeUntilSend` / `HasPacingBudget` / `OnPacketSent`。
每个最小 RTT 内最多突发一个窗口上限的字节，发完等到下一个 RTT。
取「内层 pacing」与「这个上限」里更晚的时刻：估计正常时行为不变，
估计虚高时由窗口上限兜住。RTT 用 `MinRTT`，避免排队延迟把速率越压越低。

**验收**（2026-11-14 17:20，本机）：

| 项 | 结果 |
|---|---|
| `TestBurstQuota` / `TestBurstFollowsWindow` | PASS（一窗发完必须等下一个 RTT；缩窗后下一轮配额跟着变） |
| `go test -race -count=1 ./...` | PASS |
| `docs/interop_check.sh` | PASS |
| `docs/e2e_matrix.sh`（Go↔Go，TCP 200 + UDP DNS） | PASS |
| `make verify` | PASS（`1.14.4-rev.1`，tags 含 `with_flowtls`） |

**RTT 稳定性对照**（2026-11-14 17:25，本机回环，只对 8443 加 `netem delay 70ms`，
Go 与 Rust 交替各 3 轮。单向 70ms，回环两个方向都经过队列，所以基线是 140ms）：

| 项 | Go | Rust |
|---|---|---|
| QUIC RTT | n=24，140~141ms，标准差 0.37ms | n=12，140~141ms，标准差 0.28ms |
| 应用层首字节（各约 150 次，全部 HTTP 200） | p50 142.6 / p90 145.0 / 最大 146.8，标准差 0.99ms | p50 142.8 / p90 144.6 / 最大 146.9，标准差 1.11ms |

没有出现「Go 把 RTT 抬到 212ms」的现象。无丢包的 70ms 链路上，
两边的 RTT 一样稳，pacing 钳制没有引入额外抖动。

同一条件下限时 8 秒下载：Go 7.0 MB/s，Rust 8.8 MB/s（单次，不作倍数结论）。
跨境链路上「变差时偶发卡死」仍未复测：本机 `netem` 不是那条链路。

测量踩坑：发行版进程名会被截成 `sing-box-1.14.4`，`pkill -x sing-box` 杀不掉，
下一轮 curl 会打到还活着的另一个实现上。8443 是 raw socket，`ss` 看不到监听。

## 2026-11-14 16:35 (北京时间)

### 真链路实测：推翻「Go×Go 恒定慢 2 倍」这一结论；修掉 SYN-ACK 判定的多余条件

**背景**：上一阶段遗留的核心疑问是「Go×Go 真链路 6~7 MB/s，Rust↔Rust 15~16 MB/s」，
一直按「实现有 2 倍性能差距」在找原因。这次按建议做了真链路验证。

**1）真链路特征实测（服务端 + 客户端两处 `QUIC 路径统计`，统计口径已在上一版修正）**

| 项 | 观测值 |
|---|---|
| RTT | **77ms ~ 235ms（同一会话内变化）** |
| 丢包 | **2.6% → 9.5%（累计，随链路状态变化）** |
| 丢包突发结构 | 抓包 6543 个序号空洞，**100% 是单包丢失**（最大一次 9 包）→ **不是突发丢包** |

抓包方法：伪造 TCP 的每个数据包在线上是一段连续 `seq:end`，把收到的区间排序合并，
相邻区间之间的空洞就是真正丢掉的字节。**不需要两端对时钟**，也不需要解 QUIC。

**2）交替 A/B（同一时间窗内轮流跑 Go 与 Rust，避免链路漂移污染结论）**

| 轮次 | Go×Go | Rust↔Rust |
|---|---|---|
| 修复 `isSYNACKFor` 前 | 15.5 / 5.0 / **0（握手超时）** MB/s | 13.6 / 14.5 / 14.7 MB/s |
| 修复后 | 11.0 / 12.3 MB/s | 5.1 / 5.2 MB/s |

**结论：不存在稳定的 2 倍差距。** 链路本身在 5~15 MB/s 之间波动，
两个实现在同一窗口内互有胜负（修复后 Go 反而比 Rust 快一倍）。
历史上的「6~7 vs 15~16」几乎可以确定是**非同时刻的两次测量**，
被链路自身漂移放大了。

**3）修掉一个多余判定（与 Rust 不一致）**

```go
// Rust client.rs:767
flags & TCP_SYN != 0 && flags & TCP_ACK != 0 && awaiting_syn_ack
// Go（修复前）
同上 + p.Ack == s.synISN+1        // ← 多出来的，Rust 没有
```

这条只会带来一种后果：ACK 号一旦对不上，**有效的 SYN-ACK 被静默丢弃**，
客户端只能在 1/2/4/8 秒退避后重传 SYN，很容易撞上 sing-box 那侧的建连超时
（实测日志 `flowtls 握手失败: context deadline exceeded`，7 次建连里出现 3 次）。
四元组已由 `matchPeer` 过滤，真正鉴权是后续 AEAD，放宽不降低安全性。

修复后交替验证 2 轮，**握手失败 0 次**，Go 均为 11~12 MB/s。

**4）部署**：服务端已更新为本次构建（`/opt/flowtls/sing-box`，原文件备份为
`sing-box.bak-20261114-1616`，回滚只需 `mv` 回去再重启）。客户端按原状保持运行。

**验收**：`go test -race -count=1` / `make build`（amd64 + arm64）/ `make verify` /
`docs/interop_check.sh` / `docs/e2e_matrix.sh` 全部 PASS。

## 2026-11-14 16:15 (北京时间)

### 修复：`PacketsLost` 在 BBR 下恒为 0，导致「按丢包率收缩窗口上限」是死代码

**根因（读依赖源码确认）**：quic-go 的 `connStats.PacketsLost` **只在
`internal/congestion/cubic_sender.go:200` 里累加**，BBR 路径完全不填。
而我们从 Rust 移植的 `windowController.loop` 正是用它算丢包率：

```go
totalLost += s.PacketsLost   // BBR 下恒为 0
loss = dLost / dSent         // → 恒为 0
case loss < lossLowMark:     // 0 < 5% → 永远命中
    next = cur * 1.20        // 上限每 2 秒 ×1.2，一路涨到 8MB
```

后果：Rust 里「跨境高丢包时把窗口上限压到 1.5MB」这个核心机制，
在 Go 移植里**从未生效过**，上限只增不减。日志里 `lost=0 loss_pct=0`
也一直是假的——这也是上一阶段「Rust 报 80ms / Go 报 212ms」时
没人怀疑丢包统计的原因。

**修法**：`cappedBbr` 覆写 `OnCongestionEventEx`，从 quic-go 交给控制器的
`[]LostPacketInfo` 里自己数丢包（内层行为完全不变，只加计数），
自适应循环与统计改用这个自建计数。`PacketsSent` 无需自建——它在
`sent_packet_handler.go:331` 累加，与拥塞控制器无关，是可靠的。

**修复前后（loopback + `tc netem delay 70ms loss gemodel 40% 87%`，约 33% 突发丢包）**

| 指标 | 修复前 | 修复后 | Rust 参考 |
|---|---|---|---|
| 服务端 `lost` | 0 | 6294 | — |
| 服务端 `loss_pct` | 0 | 30 | 33 |
| `win_cap` | 8388608（只增不减） | **1572864** | 1572864 |

**无回归验证**（同环境，各 3 轮 / 单轮）：无丢包 11.3~12.0s、
5% 均匀丢包 27.0s（修复前 27.7s），与修复前同一量级。

**未解决**：突发丢包下 Go 吞吐仍然塌到 ~0.1 MB/s，而 Rust 是 3.3 MB/s。
修复只让窗口上限对齐，真正坍塌的是**内层 sing-quic BBR 的带宽估计**
（cwnd 在 8KB~25KB 震荡，Rust 的内层 cwnd 始终 ≥1.5MB）。
`ProfileConservative` 替换实验同样失败，说明不是 profile 选择问题。
该行为位于依赖内部，改它违反 `AGENTS.md` 约束 9，因此记录为已知限制。

## 2026-11-14 15:30 (北京时间)

### 对齐 Rust：收包批量 256 + 纯 ACK 批末判定（差异 H）

审计 Rust 冻结版与 Go 移植版的逐函数差异时发现：Rust 的延迟确认判定
（`ack_pending >= 2` 或 40ms 兜底）**只在「一批（最多 256 帧）处理完」之后
做一次**，而 Go 把同一段判定写成了**逐帧**判定。一批 256 个数据帧，
Rust 发 1 个纯 ACK，Go 发 128 个。

**改动**（不涉及 wire format，冻结向量门禁照旧 PASS）

| 文件 | 改动 |
|---|---|
| `flowtls/socket_linux.go` | 抽出 `recvOnce(buf, flags)`；新增非阻塞 `recvAvailable()`（`MSG_TRUNC\|MSG_DONTWAIT`），与 `Recv` 共用同一份截断检测 |
| `flowtls/socket_stub.go` | 补 `recvAvailable` 空实现（非 Linux 对位编译） |
| `flowtls/session.go` | 新增 `maxRecvBatch=256`；`recvLoop` 改为「阻塞收 1 帧 → `drainAvailable` 非阻塞取干 → 批末 `flushDelayedACK`」；把延迟确认判定从 `handleIncoming` 移出 |
| `flowtls/listener.go` | 同一批边界；`handlePacket` 返回被投递的会话，`recvLoop` 在批末对本轮触达的会话各判定一次 |

**实测（本机回环，`iptables none`，抓包按方向分类并排除内核 RST）**

| 指标 | 改动前 | 改动后 | 变化 |
|---|---|---|---|
| 客户端→服务端 纯 ACK | 4167 | 2393 | −42.6% |
| 服务端→客户端 纯 ACK | 1095 | 809 | −26.1% |
| 数据帧（对照组） | 8001 | 8001 | 不变 |
| 10MB 响应耗时（3 轮均值） | 108.3 ms | 98.7 ms | +9% |

**同步纠正两条此前的判断**（详见 `DEVTIPS.md` 第 105 条）

- ACK 延迟 25ms vs 5ms **不是**吞吐差距主因：quic-go 每 2 个 ack-eliciting
  包就立即回 ACK，25ms 只对稀疏流量生效，且 `Config` 无任何字段可覆盖。
- BBR profile / send_window / 初始窗口三项**无合法旋钮**：`sing-quic` 的
  `Profile` 字段全部未导出，`ProfileStandard` 的高增益三参数已与 quinn 一致，
  切 `ProfileConservative` 会同时改坏 `highGain=2.25`、`highCwndGain=1.75`、
  `numStartupRtts=2`、`bytesLostMultiplier=1`。四项均记录为「受依赖约束
  无法对齐」，不再重复投入。

**验收**：`make build` / `make verify` / `sing-box check`（server+client）/
`go test -race ./...` / `docs/interop_check.sh` / `docs/e2e_matrix.sh`（Go↔Go）
全部 PASS。

## 2026-11-14 14:00 (北京时间)

### Go 版从零重移植（wire v2 与 Rust 逐字节一致），并修复五处移植缺陷

用户删除了旧 Go 实现，要求「原样从 Rust 移植，不要自造机制」。本条目记录
重建后的验收结果与过程中修掉的真实缺陷。

**已删除的自造机制**（Rust 里没有，全部移除）：发送队列、Probe 探活、
suspectConn、Brutal 拥塞、内核 BPF 过滤器、`wscale=12` 识别、conntrack 规则、
`iptables_mode=print`、`masquerade.proxy_url` / `rewrite_host`、
`up_mbps` / `brutal_multiplier`。

**修复的移植缺陷**

| # | 缺陷 | 现象 | 修法 |
|---|---|---|---|
| 1 | `serverRules` 的 spec 里已经带了 `-A PREROUTING`，`command()` 又插一次动作词 | 服务端启动即 FATAL：`iptables -t raw -A -A PREROUTING …` | 动作词只由 `command()` 插入；新增 `TestNoDuplicatedAction` 钉住 |
| 2 | 分流层按四元组快查已有会话，且**握手时不清理旧会话** | 客户端源端口固定，重启后「通道已建立但一个字都传不过去」，直到 120s 空闲回收 | `handleSYN` 用 SYN 的 ISN 判断是否同一客户端的新连接，是则先关旧会话；新增两个单测 |
| 3 | 出站 `Start` 里同步做初始建连 | 伪 TCP 握手最长 15s，期间 mixed/socks 入口**还没开始监听**，客户端表现为「刚启动所有请求立即失败」 | 初始建连改到后台协程，入口先起来 |
| 4 | 收包缓冲 64KB 且未真正检测截断 | GRO 聚合的 skb 可超 64KB → `recvfrom` 静默截断，包无声消失 | 256KB + `MSG_TRUNC` 真实长度检测与一次性告警（AGENTS 约束 15） |
| 5 | `SendBatch`（sendmmsg）已实现但**无人调用**，服务端逐包 `sendto` | 真机单次 `sendto` 实测 34µs，回环单流 33 MB/s | 补齐 Rust `drain_transmits` 语义的发送队列（深度 64、立即排空、一次 sendmmsg 最多 32 个）；回环单流 33→45 MB/s |

**部署配置修正**：服务端 `local_ip` 必须填**网卡内网地址**（如 `10.0.0.10`）。
填公网地址时 IPPROTO_RAW 会把它原样写进 IP 头，被 Oracle 网关反欺骗静默丢弃
—— 服务端抓包能看到 SYN-ACK 发出，客户端一个包都收不到。

**验收（本机 + 真链路）**

| 项目 | 结果 |
|---|---|
| 4 格互通矩阵（Go/Rust 双向，TCP + UDP） | **10 / 10 PASS** |
| 冻结向量门禁（wire v2 与 Rust 字节一致） | PASS |
| `go test -race ./...` | PASS |
| 双端 `sing-box check`（零 root） | PASS |
| 延迟分层：ICMP 73.7ms / 纯隧道 p50 75ms / HTTPS p50 160ms | **1 RTT，无额外开销** |
| 同源端口连续两次重启 | HTTP 200，均 ≈165ms |
| UDP 6 项（SOCKS5 UDP ASSOCIATE + 真实 DNS） | 全部 PASS |
| 主动端口探测：普通 curl 只收到 **1 个** SYN-ACK，真证书 TLS 1.3，页面 200 | PASS |

**已知未达标项（如实记录）**

真链路 100MB 单流：Go↔Go **6~7 MB/s**，Rust↔Rust 15~16 MB/s（同时段交替 3 轮）。
但 Go 客户端→Rust 服务端 11.7 MB/s、Rust 客户端→Go 服务端 14.4 MB/s，
只有两端都是 Go 时才慢；且本机回环 Go 比 Rust 快（45 vs 23 MB/s）。
Go 客户端上报的 QUIC RTT 是 212ms，而同一服务端对 Rust 客户端报 80ms，
抓包显示链路单程约 90ms —— 说明 Go 侧把 RTT 估计抬高了约 130ms，
`cwnd/rtt` 因此把吞吐压在 7 MB/s 附近。该问题尚未定位到具体代码路径。

## 2026-11-14 09:30 (北京时间)

### 1080「连不上」问题定位：四个静默丢包/误判根因

用户报「1080 admin abcd1234 连不上」。复现后发现：进程在跑、端口在听、
认证能过，但请求全部超时 —— 典型的「包发出去了但对端收不到」。

四个根因互相叠加，共同点是**日志里没有任何错误**：

| # | 缺陷 | 证据 | 修法 |
|---|---|---|---|
| 1 | AF_PACKET 发送 fd 非阻塞，`Send()` 把 `EAGAIN` 当 UDP 语义 `return nil` | 抓包 `SYN→SYN-ACK` 851ms（链路 73ms），客户端 1s 后才重传 | 阻塞 fd + `SO_SNDTIMEO=200ms`，`Send`/`sendLoop` 重试并上报 |
| 2 | 批量收包缓冲 2048 字节，GRO 聚合包可超 64KB → 内核**静默截断** | 服务端日志「报文被截断」；QUIC `lost=` 恒为 0 但握手 473~682ms、首包 610ms | 缓冲 256KB + `MSG_TRUNC` 检测与告警 |
| 3 | `recvmmsg`/`sendmmsg` 未处理 `ERESTARTSYS(512)`（Go 异步抢占的 SIGURG） | 单测偶发 `recvmmsg: errno 512` | `EINTR`/`ERESTARTSYS` 原样重试 |
| 4 | 客户端把**内核回的 RST** 当成「对端存活」（四元组完全匹配） | `lastSeenAt` 被 RST 推进 → Probe 误判 → 死连接长期复用 | `handleIncoming` 忽略 RST；`probeTimeout` 1s→400ms、`openStreamTimeout` 8s→1s |

第 4 条是「连不上但进程正常」的直接原因：服务端重启后，伪包仍到达
服务端内核，内核为每个包回 RST（src/dst 端口与我们的四元组一致），
`ParseFrame` + `matchPeer` 全部通过，于是探活一直「成功」。

**附带改动**

- 新增 `QuickDstPort` 廉价预筛（只读四字节），避免对整机无关流量做完整解析；
- 新增内核侧 BPF 端口过滤器 —— **默认关闭**：真链路两次实测导致不通，
  且本机虚拟化环境看不到出向包、无法验证（详见 `DEVTIPS.md` 98~100）；
- `rules.go` 服务端新增两条规则：`! --syn + ctstate NEW` 丢伪数据包、
  `OUTPUT` 丢本端 RST。实测 **IP ID 规则命中 0 次**（客户端 NAT 改写 IP ID）；
- 建连/重建/探活失败改为 Info 日志（之前重建是静默的，事后无从追溯）。

**实测（新加坡 ARM，Go↔Go）**

| 指标 | 结果 |
|---|---|
| QUIC min_rtt | **72.2ms**（ICMP 72.7ms） |
| 100MB ×5 | **16.3~24.2 MB/s** |
| 25 轮稳定性（10MB + 204 交替） | **FAIL=0** |
| UDP 6 项 | 全部 PASS |
| panic | 0 |
| 服务端重启后首个请求 | 11.4s → **2~3s** |

> 关于「服务端重启后仍有 2~3s」：其中约 1~2s 是链路丢包后的 QUIC PTO
> 重传（抓包确认握手本身 90~200ms 完成），属于跨境链路特性，不是实现缺陷。

文档：`DEVTIPS.md` 新增 98（四种静默失败复盘）、99（IP ID 分流命中 0 次）、
100（`SO_ATTACH_FILTER` 返回值陷阱）。

## 2026-11-14 03:35 (北京时间)

### 再定位两个 syscall 层根因：服务端批量收包 + AF_PACKET 发送

上一轮修完分流与发送队列后，`min_rtt` 在测试实例上降到 80ms，
但切到生产入口（1080）又回到 216~225ms。按 DEVTIPS 91 的纪律做
**同一时刻对照**，结论明确：问题在 Go 服务端，不在链路。

| 服务端 | min_rtt | srtt | 单流 100MB | 4 并发合计 |
|---|---|---|---|---|
| Rust 8445 | 76.6ms | 79.9ms | 10.6 MB/s | 5.8 MB/s |
| Go 8443（修复前） | 225.4ms | 233.7ms | 5 MB/s | — |
| **Go 8443（修复后）** | **72.4~76.1ms** | **77.7~79.7ms** | **15.2~23.0 MB/s** | **12.3 MB/s** |

**1) 服务端逐包 `recvfrom` → `recvmmsg`**

下行 11000pps 时客户端要回同样速率的纯 ACK；逐包 recvfrom = 每包一次
syscall + 一次协程调度，单核 ARM 上调度延迟被放大，ACK 晚 150ms 发出，
对端把它算成 RTT。服务端 CPU 仅 6%，所以不是算力问题。

`Listener.recvLoop` 改为 `RecvBatch`（一次 32 包），与 `Session.recvLoop`
和 Rust `PacketBatch` 一致。早期 recvmmsg「吞吐崩到 7KB/s」的坑是
`mmsghdr` 布局写错，现已有 `TestRecvmmsgActuallyReceives` 直接断言
「内核真的把包填进来」。

**2) 服务端发送 IPPROTO_RAW → AF_PACKET 默认**

Rust `socket.rs` 早有注释：IPPROTO_RAW + IP_HDRINCL 在 1 核 ARM 上约
35µs/包，是高速率下的第一瓶颈。Go 版一直走 RAW（早期 AF_PACKET 在 NAT
云主机被网关丢包），但源地址自动纠正（DEVTIPS 87）之后 AF_PACKET 可用：

| 发送路径 | 单流 100MB | cwnd |
|---|---|---|
| `ipproto_raw` | 5 MB/s | 1.2~1.7MB |
| `af_packet` | **15~23 MB/s** | **4.7MB** |

默认值：服务端 AF_PACKET、客户端 IPPROTO_RAW（家用 NAT 对旁路 conntrack
的包更挑剔，DEVTIPS 86）。可用 `FLOWTLS_AF_PACKET=1/0` 强制覆盖。
`PACKET_QDISC_BYPASS` 保持默认关闭（DEVTIPS 84）。

**3) 生产入口最终验收（1080，Go↔Go）**

| 用例 | 结果 |
|---|---|
| 出口 IP | 203.0.113.10 ✅ |
| 单流 100MB ×3 | 17.2 / 22.0 / 23.0 MB/s（137~184Mbps） |
| UDP DNS 6 项 | 全部 PASS |
| 普通 curl 访问 8443 | 只收到内核 1 个 SYN-ACK ✅ |
| `sing-box check`（不用 root） | 通过 ✅ |

文档：`DEVTIPS.md` 新增 96（批量收包 + AF_PACKET 的量化对照与教训）、
97（v2 精简原则与文件对照表）。

## 2026-11-14 03:10 (北京时间)

### 高 RTT / 连接不稳定的三个真根因定位与修复；Go v1 归档、v2 精简移植启动

用户判定「Go 版越写越复杂、排查越来越难」，要求重新制定计划、归档 Go 代码、
精简高效地移植 Rust。本轮先定位并修掉三个真根因（都是移植时丢了 Rust 的关键语义，
不是调参问题），再开始精简。

**1) 服务端分流丢了判断：任何 SYN 都回 SYN-ACK**

`listener.go handlePacket` 只判断 `SYN && !ACK && 无载荷`，没有校验这是不是伪包。
Rust `server.rs:659` 是 `(ip_id & mark) == mark && SYN && payload.is_empty()`。

后果（双端抓包确认）：同一四元组上同时发出**两个** SYN-ACK ——
内核（masquerade 网站，源 `10.0.0.10`、MSS 8960）和 flowtls（源公网、MSS 1460）。
客户端取到内核那个 ISN 后，后续所有伪数据包的 ack 全错。

**2) IP ID 不能作为分流主特征（1/16 误命中 + 会被改写）**

改为 **wscale=12**：

| 位置 | 判断 |
|---|---|
| `packet.go` | `WScale = 12`（客户端 SYN 与服务端 SYN-ACK 一致） |
| `listener.go` | `p.WScale == int(WScale)` 才当伪 SYN，否则交给内核 |
| `rules.go` | 新增 `U32WScaleExpr()`：`--tcp-flags SYN,ACK SYN` + u32 偏移 56 = `0x0103030c` |

TCP 选项是端到端字段，NAT / 云网关不改写（实测同路径上 MSS 被 clamp 成 1400，
wscale 原样保留）。IP ID 规则保留为辅助（反方向流量可靠）。

**3) 发送队列过深且满即丢：本地排队被 quic-go 计入 RTT**

quic-go 在**打包时**就调 `sentPacketHandler.SentPacket(now, …)` 记录发送时刻，
然后才交给 `Session.WriteTo`。v1 的 `WriteTo` 只把包放进 4096 深队列就返回，
flushLoop 落后时本地排队时间被当成网络 RTT，污染 BBR 带宽估计与 PTO。

修法：

- `txQueueDepth` 4096 → **32**（与 Rust `PacketBatch` 一致），队列满时**阻塞**生产者；
- 纯 ACK 走独立队列 + 独立发送协程，不排在数据洪峰之后（Rust `send_pure_ack`
  同样是直接发送，从不排数据队列）；
- `sendBatch` 对未发出的剩余报文重试，不再静默丢弃；
- `PathStats` 增加 per-conn 归属（`peer=`）、`MinRTT`、`Cwnd`/`InFlight`、
  发送队列统计（`tx_q`/`tx_wait`/`tx_drop`/`tx_err`）。

**修复后实测（新加坡 ARM，Go↔Go，均为多轮区间）**

| 指标 | 修复前 | 修复后 |
|---|---|---|
| 伪 TCP 握手（抓包） | 214ms | **80.8ms** |
| QUIC min_rtt（客户端） | 213ms | **79.6~81.2ms** |
| QUIC min_rtt（服务端） | 213ms | **80.3ms** |
| 单流 100MB ×3 | 3.4~17.7 MB/s（抖动大） | **15.0~18.3 MB/s** |
| 4 并发 10MB | — | 各 4.4 MB/s，**合计 17.6 MB/s（141Mbps）** |
| 204（IP 直连，稳态） | 0.6~1.8s | **0.162~0.180s（= 2×RTT，理论下限）** |
| 普通 curl 访问 8443 | 收到 2 个 SYN-ACK | 只收到内核 1 个 ✅ |
| UDP DNS 6 项 | — | 全部 PASS |

**4) Go v1 归档 + v2 精简移植启动**

- tag `go-v1-archive-20261114` + 分支 `legacy-go`（可回滚）；
- `docs/PROJECT_PLAN-v1.md` 保存 v1 计划原文；
- 新的 `PROJECT_PLAN.md` 把「精简移植」定为主线，含具体删除清单与验收门禁；
- `outbound.go` 已完成精简：**537 → 406 行**，删掉 `suspectConn` / `attemptCtx` /
  `invalidate` / `dialing` 四层包装，统一为单一 `channel()` 入口
  （4 层里任何一层误判都会导致「每个请求重建一次连接」）。

文档：`AGENTS.md` 与 `docs/DESIGN.md` 的分流特征改为 wscale=12 并写明推导，
`PROJECT_PLAN.md` 重写，v1 计划归档到 `docs/PROJECT_PLAN-v1.md`。

## 2026-11-14 02:00 (北京时间)

### 1080 入口按部署方要求改监听 0.0.0.0；修复批量收包引爆的 panic

**1) 监听地址（用户明确要求）**

`/tmp/live/client-sg-1080.json` 的 `listen` 由 `127.0.0.1` 改为 **`0.0.0.0`**，
理由是要让局域网内其它设备也能用这个入口。我原先按项目既有安全策略选了回环，
这次以部署方要求为准，并把代价写进配置注释与 `DEPLOY_CREDENTIALS.md`：
**弱口令入口因此对整个局域网可达**，不需要时改回 `127.0.0.1`，
要保留就用防火墙限网段，别把口令当唯一防线。

验证（短命令，逐项）：

| 用例 | 结果 |
|---|---|
| `sing-box check -c`（不用 root） | 通过 ✅ |
| 监听 | `0.0.0.0:1080` ✅ |
| `127.0.0.1:1080` 拉 10MB | `code=200` 8.1 MB/s（连接刚建立） |
| **`10.0.0.1:1080`（局域网地址）** | `code=200` **18.5 MB/s** ✅ 0.0.0.0 确实可达 |
| 出口 IP | `203.0.113.10` ✅ |
| 8 连短连接 | 全部 `code=200` |
| 10MB 抽查 | **18.9 MB/s（152Mbps）** |
| 新日志 panic 计数 | `0` ✅ |

**2) 修复一个我上一轮改动引爆的 panic（客户端崩进程）**

```
panic: send on closed channel   deliverOwned session.go:582 ← recvLoop
```

`Close()` 会 `close(s.rx)`，`deliverOwned()` 会 `s.rx <- owned`，两侧只有
`sync.Once` 保证「rx 只关一次」——**Once 不能保证关完之后没人再 send**，
而 Go 对已关闭通道发送是 panic。旧写法每轮处理 1 个包，窗口小到撞不上；
上一轮改成一次 recvmmsg 收 32 包，**把窗口放大 32 倍，关闭时必然还在批内 → 必崩**。

修法（`flowtls/session.go`）：

- 新增 `rxMu sync.RWMutex` + `rxClosed bool`，`deliverOwned` 持读锁、
  新增的 `shutdownRx()` 持写锁，把「发送」与「关闭」真正串行化；
  `Close()` 与 `closeRx()` 都改走 `shutdownRx()`；
- 三个投递分支仍全部非阻塞（`select` 带 `default`），持读锁不会卡住关闭方；
- 批量循环里每包前检查 `closed`，关闭后立刻退出（少做无用功，
  正确性由锁保证）；
- 新增防回归测试 `TestDeliverConcurrentWithCloseNeverPanics`
  （`flowtls/session_test.go`），并**按 DEVTIPS 91 的纪律验证它能证伪**：
  临时去掉 `rxMu` → 立刻 `panic: send on closed channel` + `DATA RACE` + FAIL；
  恢复后 `-race -count=20` 全通过。

**3) 关于「命令卡住」**

上一轮我发的验证命令是 `25 次 ftdial × timeout 20`（最长 500 秒）且中途不输出，
看起来就是卡死。已改为**有界短命令、每步立刻报结果**。教训记进 DEVTIPS 91：
压测要么分步、要么带进度输出，别让使用者无法判断是死了还是在跑。

**4) 回答「Go 有没有丢包自动调窗口」**

**有**，`flowtls/quic/capped_bbr.go` 的 `windowController.loop()` 与 Rust
`server.rs:402-433` 逐条一致：2 秒周期、`loss>20% → ×0.9`、`loss<5% → ×1.2`、
`safe_cap = 1024×1308/max(loss,0.01)×0.7`、`clamp(1.5MB, 8MB).min(cfg_cap)`、
`cfg_cap = max_cwnd.max(1536KB)`。实测两边窗口轨迹形状相同
（Go：8MB ← 9~10% 丢包时 5.42/4.75/4.12MB；Rust：8MB ← 7.72/6.43/5.36/2/1.5MB）。

**但必须说清：这个自适应在 01:25 修复 `Attach()` 之前是空转的**——循环照样算、
日志照样打 `win_cap=`，可因为 BBR 分支没调 `SetCongestionControl`，
**没有任何人读那个值**。铁证是当时把 `max_cwnd` 压到 1MB，日志如实显示
`win_cap=1.50MB` 而吞吐毫无变化。详见 DEVTIPS 88/89。

文档：`DEVTIPS.md` 新增 92（channel close/send 必须互斥 + 批量会放大关闭竞态 +
防回归测试要能证伪），`DEPLOY_CREDENTIALS.md` 更新监听地址与实测表。


## 2026-11-14 01:55 (北京时间)

### Go↔Go 部署到生产入口 127.0.0.1:1080，并按重复测量修正上一轮的性能结论

**部署**（用户要求「go-go 部署到 1080 admin abcd1234」）

- 客户端配置：`/tmp/live/client-sg-1080.json`（由 1081 测试实例迁移而来）
- 入口：`127.0.0.1:1080`，`type: mixed`（SOCKS5 + HTTP 同端口），用户名 `admin`
- 隧道：本地 Go 客户端 → 新加坡 Go 服务端（`203.0.113.10:8443`）
- 参数：`source_port: 44333`、`ip_id_mark: 30583`、`sni: example.com`、
  `iptables_mode: auto`、`max_cwnd: 8388608`；日志级别 `debug → info`

两处刻意选择，都写进了配置注释：

1. **只监听 `127.0.0.1`**：入口带弱口令，绑 `0.0.0.0` 等于把它开放到局域网
   （项目既有安全策略：入口默认只监听回环，需要局域网时显式改）。
   上一轮我起的 1081 实例是 `0.0.0.0`，属不合规范。
2. **停掉 1081 实例**：Go 与 Rust 客户端都用 1080，不能同时跑；
   留两个重复 Go 客户端只会让服务端 `conns>1` 并分掉带宽（见下面的教训）。

**验收（同一组合至少 5 轮，报区间）**

| 用例 | 结果 |
|---|---|
| 无凭据 / 错口令 | 均 `code=000` 被拒 ✅ 鉴权确实生效 |
| 出口 IP | `203.0.113.10` ✅ 流量确实走隧道 |
| 串行 100MB（11 轮） | **11.8~18.7 MB/s（94~150Mbps）** |
| 连续 10MB × 5 | 14.1~17.4 MB/s，全部 `code=200` |
| 4 并发 100MB | 每流 4.32 MB/s，合计 **17.3 MB/s（138Mbps）** |
| 本机回环 Go↔Go 30MB | 80~108 MB/s |
| `sing-box check`（不用 root） | 通过 ✅ AGENTS.md 硬要求 |

对照 Rust 客户端在同一 Go 服务端上的 14.8~15.1 MB/s：**Go↔Go 已在同一量级**。

**撤回上一轮写进文档的两个结论**（都因为只测了几轮就下结论）

1. ~~「Go 客户端仍比 Rust 慢 2.2 倍（5.9~7.2 vs 14.8 MB/s）」~~ →
   按 11 轮重测后不存在，那个数字来自尚未重启到最终版的实例。
2. ~~「服务端测 Go 客户端 RTT 228ms、Rust 78ms，说明 Go 的 ACK 晚了一个数量级」~~ →
   这个数字**属于谁根本无法确定**：服务端统计的 `rtt=` 取的是循环里
   **最后一条连接**的采样值，而当时日志常是 `conns=2/3`（Go 与 Rust 同时在跑），
   且不标对端地址。这个观测缺陷本身已记入 DEVTIPS 88 末尾，
   `PathStats` 需要带 per-conn 归属（与缺 `cwnd`/`inflight` 并列两处硬伤）。

顺带：为验证「是不是残留会话状态污染了测量」专门跑了重复实验——1080 连跑 15 轮后
仍是 15.3~18.7 MB/s，重启新实例也没更快，**该归因同样被证伪**。测量规矩写成
DEVTIPS 91（吞吐至少 5 轮报区间、A/B 同一时刻交替、改动前后同机同目标同轮数、
归因前先做能证伪它的实验、测吞吐时服务端只留一个客户端）。

文档：`DEPLOY_CREDENTIALS.md` 重写为 Go↔Go 部署现状（含服务端 local_ip 过时结论的更正、
Go 版更新/启停命令、u32 规则判读、验收表），`DEVTIPS.md` 更正 88 并新增 91，
`PROJECT_PLAN.md` 补部署与测量规矩。本仓库不记录口令（该文件自身约定）。


## 2026-11-14 01:25 (北京时间)

### 公网传输根因修复：拥塞控制器从未安装 + NAT 源地址陷阱 + 静默丢 ACK

**背景**：用户指出上一轮的「回环 97MB/s 已追平 Rust」并没有解决公网问题
（「上面的工作没有解决问题，你完整阅读 go 和 rust 版本的代码」），
并提示去读 `legacy-rust` 分支里的 md 记录。逐个控制变量实测后，真正的根因有四个，
**全部是「代码写了但没接线」或「本地环境掩盖」**：

| # | 缺陷 | 位置 | 实测影响 |
|---|---|---|---|
| 1 | **拥塞控制器从未安装**：`Attach()` 只在 Brutal 分支调 `SetCongestionControl`，BBR 分支什么都不做 | `quic/capped_bbr.go` | `cappedBbr`/`w.cap` 全是死代码，自适应窗口对真实发送零影响，日志 `cc=bbr` 是谎报。**服务端 254KB/s → 10.1MB/s** |
| 2 | **NAT 云主机的 `local_ip` 陷阱**：网卡只有 `10.0.0.10`，包里填公网 `203.0.113.10` 会被网关反欺骗丢弃 | `socket_linux.go` | 服务端抓包能看到 SYN-ACK 发出、客户端一个包都收不到。改成「配置值不在本机网卡上就自动用探测到的出口地址」 |
| 3 | **MSG_DONTWAIT + EAGAIN 静默丢弃**：发送队列一满，ACK 在本地被丢掉且无任何日志 | `socket_linux.go sendFlags` | 服务端测得 RTT 从 78ms 虚高到 215~228ms，BBR 带宽估计崩一半。改为阻塞 `flags=0`（数据面已全部收敛到 flushLoop 单协程，阻塞等于天然背压，与 Rust 一致） |
| 4 | **收包侧从未批量**：`RecvBatch`(recvmmsg) 写完并有单测，但 `recvLoop` 仍逐包 `recvfrom` | `session.go` | 7700pps 时收包 syscall 成本与发送侧不对等 |

顺带修好交叉编译缺口：`maxSendBatch`/`maxRecvBatch`/`RecvBatch`/`SendMode` 在
`socket_stub.go` 里缺失，`GOOS=darwin/windows go build ./...` 会直接失败
（AGENTS.md 要求必须能交叉编译）。其中 `maxSendBatch` 上一轮就已缺失，当时没跑交叉编译所以没发现。

新增可观测性（都是这次排查中缺失的东西）：

- `rawSocket.SendMode()` → `Listener/Session/Server` 透传，服务端与客户端各打一行启动日志，
  明确「实际走 ipproto_raw 还是 af_packet、源 IP 到底是谁」；
- 服务端 `QUIC 路径统计` 补上 `rtt=` 字段（原来只有 sent/lost/win_cap，
  无法区分「链路慢」和「对端 ACK 不及时」，只能反复改代码二分）；
- `flushLoop` 整批发送失败不再静默：计 `txSendErr`，开关 `FLOWTLS_DEBUG_SEND=1` 下记日志。

**公网实测（本地 ↔ Oracle 新加坡 ARM，100MB）**

| 组合 | 修复前 | 修复后 |
|---|---|---|
| Go 客户端 → Go 服务端 | 握手超时 / 49KB/s | **8.0~9.8 MB/s（64~78Mbps）** |
| Rust 客户端 → Go 服务端 | 连不上（源地址被丢） | **14.8~15.1 MB/s（118~121Mbps）** |
| Rust 客户端 → Rust 服务端 | 10.9 MB/s | 未回归 |
| 本机回环 Go↔Go 30MB | 90~97 MB/s | **80~108 MB/s** |

> **注意：本条上方表格里的 Go↔Go 吞吐已被 01:55 条目更正。**
> 那行数字来自只测了几轮的旧实例，重复测量后实际是 11.8~18.7 MB/s（与 Rust 同量级）。
> 「Go 客户端慢 2.2 倍」与「RTT 215~228ms」两个结论均已撤回，原因见 DEVTIPS 88/91。

### 追加：又修了一个自己引入的回归（`bindRecv`）

回环复测时发现本机 Go↔Go **全部 handshake timeout**：上一轮加的
「客户端 recvFD 绑定出口网卡」用 `dst` 反推角色，而服务端为了探测出口网卡/
网关 MAC 传的 dst 是 `8.8.8.8`（不满足当时假设的 `dst=0.0.0.0`），
于是**服务端也被绑到物理网卡，收不到 lo 上的包**（违反 DEVTIPS 63）。

改为调用方显式声明：`newRawSocket(dst, local, bindRecv)`，
`Dial` 传 true、`Listener` 传 false。修完回环从 0 回到 **80~108 MB/s**。
详见 DEVTIPS 90。教训：新引入的「优化开关」必须同时跑回环和公网两条链路。

**撤销的改动**：把 `recvLoop` 拆成「pump 只 syscall + 处理侧解密」的两级结构后，
吞吐没提升（6.2 vs 6.1 MB/s），却新增一个「处理侧跟不上就丢帧」的风险点，
所以**已回退**，只保留单协程 + `RecvBatch`。

**仍然存在的差距（未解决，下一步入口）**：Go 客户端方向比 Rust 慢 2.2 倍。
已排除：拥塞控制未安装、窗口过大（压到 1.5MB 无效）、CPU 占用（2.1%）、
内核接收队列积压（两级拆分无效）、服务端源地址、iptables 规则、wire format。
未排除且缺工具：**Go 的 `PathStats` 没有 `Cwnd` / `BytesInFlight`**
（Rust 的日志有 `cwnd=` / `inflight=` / `mtu=` / `pending=`），
拿不到这两个值就无法在「拥塞窗口」和「接收流控」之间继续二分。

**推翻了上一轮写进 DEVTIPS 的三个结论**：85（tcpdump 漏包）、86（同机进程伪 SYN
一个通一个不通）、以及「公网不通是被 NAT/运营商 DPI 拦」。实际是服务端发包源地址
配错与拥塞控制器未安装——服务器抓包早已证明 Go 的 SYN 到达并换回了 SYN-ACK。
已在 DEVTIPS 83~86 上标注更正。

**另：`legacy-rust:DEVTIPS.md` 第 20 条「云厂商 NAT 后面的机器不能用 FakeTCP」
是过时结论**（第 21 条「运营商动态封禁」当时也被误用）。实测 NAT 云主机完全可用，
条件是包里填内网地址、让网关做 1:1 SNAT。已在 DEVTIPS 87 记录正确做法。

## 2026-11-13 23:59 (北京时间)

### 传输层性能修复：批量发送 + 零分配 + ARP 解析 bug（回环 31 → 97 MB/s）

**背景**：用户反馈「Go 版传输有问题，带宽要追平 Rust 版」。本地回环对照（同机、同客户端、30MB×3）：

| 组合 | 修复前 | 修复后 |
|---|---|---|
| Go 客户端 → Go 服务端 | 31~50 MB/s（波动） | **90~97 MB/s** |
| Go 客户端 → Rust 服务端 | 42 MB/s | 42 MB/s（未变） |

**改动**

| 项 | 位置 | 说明 |
|---|---|---|
| 发送队列 + sendmmsg 批量 | `session.go` `flushLoop` | 持锁构造（保证 seq 顺序）→ 入队 → 单协程批量 `sendmmsg`（32 包/批），纯 ACK 与数据共用同一队列 |
| 消除每包堆分配 | `codec.go` `Seal`/`OpenTo`/`ForEachRecord` | `make` 改 grow；解密直接用池缓冲；记录解析零分配 |
| `deliverOwned` | `session.go` | 解密后的池缓冲直接投递，省一次拷贝 |
| **ARP 解析 0x 前缀 bug** | `socket.go` `parseHexUint32` | `/proc/net/arp` 的 Flags 列是 `0x2`，旧解析遇 `x` 报错 → `resolveNeighborMAC` **永远失败** → AF_PACKET 发送 fd 从未创建，**所有部署一直在静默退化到 IPPROTO_RAW** |
| `Close` 重复 close 同一 fd | `socket.go` | 默认 RAW 下 `sendFD == rawFD`，旧写法先置 -1 再比较导致二次 close，失败重连后网络状态错乱 |
| 双 fd 策略 | `socket.go` `sendTarget` | 本机地址目标走 RAW（回环走 lo），其余按环境选 AF_PACKET/RAW |
| 发送后默认值 | `socket.go` | 默认 IPPROTO_RAW（兼容 NAT 云主机），`FLOWTLS_AF_PACKET=1` 可选启用；`PACKET_QDISC_BYPASS` 默认关闭（e1000 虚拟网卡上会静默丢包），`FLOWTLS_QDISC_BYPASS=1` 开启 |
| 客户端 recvFD 绑定出口网卡 | `socket.go` | 不绑定时会收到 lo/docker 全部流量，实测可把 SYN-ACK 挤丢 |

**关键教训（详见 DEVTIPS 83~86）**

- `parseHexUint32("0x2")` 遇到 `x` 返错，这个 bug 让 **AF_PACKET 路径从未被真正使用**，回环测试全绿掩盖了它；
- `PACKET_QDISC_BYPASS` 在 e1000/QEMU 虚拟网卡上 sendto 返回成功但包不上线（tcpdump 0 个）；
- Oracle NAT 只放行经过内核 conntrack 的包，AF_PACKET 旁路的 SYN-ACK 被网关静默丢弃；
- tcpdump 的 BPF 在本机虚拟环境下会漏包，排查握手要改用 **Python AF_PACKET 裸抓**。

**公网遗留问题（未闭环）**：同一时刻、同一链路、同一源端口下，**Rust 客户端能建连、Go 客户端握手超时**；两者 SYN 字节逐字段一致（含校验和自洽），Go 的 SYN 在客户端网卡可见，服务器侧收不到。已排除：端口冲突、校验和、非阻塞 fd、MSG_DONTWAIT、recvFD 绑定、ARP、QDISC_BYPASS。待下一轮继续。

---

## 2026-11-13 19:02 (北京时间)

### P6 完成：BBR 拥塞控制 + 自适应窗口（吞吐 15 倍提升）

**根因**

quic-go 默认拥塞控制是 Cubic：把丢包一律当成拥塞信号，丢包即窗口减半。
跨境链路 20~50% 丢包是物理常态、与拥塞无关，Cubic 因此反复把窗口砍到最小。
实测吞吐只有 Rust 版的 1/5~1/10，用户主观感受就是「通道能用但速度低太多」。

Rust 版用的是 quinn 的 BBR，外面再包一层 `CappedBbr` 钳窗口上限。
Go 侧这两件事**都没有**——`flowtls/quic` 里一行拥塞控制代码都没有，
等于直接吃 quic-go 的 Cubic 默认值。

**实现**

| 项 | 位置 | 说明 |
|---|---|---|
| BBR 本体 | `flowtls/quic/capped_bbr.go` | 用 `sing-quic/congestion_meta2`（与 hysteria2/tuic 同一个实现） |
| 窗口钳制 | 同上 `cappedBbr` | 嵌入 `CongestionControlEx`，只在 `GetCongestionWindow`/`CanSend` 截断 |
| 自适应窗口 | 同上 `windowController.loop` | 每 2 秒按实测丢包率调整，逻辑逐行对应 Rust |
| 注入点 | `quic/client.go` `quic/server.go` | `winCtl.Attach(conn)`，服务端所有连接共享一份上限 |

Rust 的 `CappedBbr` 是包一层 `Controller`，在 `window()` 里截断。
Go 没法照抄（`congestion.CongestionControl` 只有 getter，没有 setter），
但**语义可以完全等价**：嵌入 `CongestionControlEx` 后重写
`GetCongestionWindow`/`CanSend`，其余方法全部原样委托。

**为什么不重装控制器**：`Conn.SetCongestionControl` 会把
`firstPacketNumber` 推到当前包号，新实例拿不到此前的发送/确认历史，
带宽估计与 pacing 从头再来。每 2 秒重装一次等于让 BBR 永远停在 startup。
只改共享原子值、让 `GetCongestionWindow` 每次重新 load，才能既实时生效
又保留 BBR 内部状态——这正是 Rust 用 `Arc<AtomicU64>` 的理由。

**统一 `max_cwnd` 配置**（对齐 Rust `net.max_cwnd`）

| Rust | sing-box JSON | 默认 |
|---|---|---|
| `net.max_cwnd` | `max_cwnd` | `8388608`（8MB） |

同时按 Rust 公式推导连接窗口：`send_window = max_cwnd × 2`，钳 [2MB, 16MB]。
Go 侧 `InitialConnectionReceiveWindow` 仍保持 16MB（等于 Rust 的
`receive_window(16MB)`），流窗口 4MB（等于 `stream_receive_window(4MB)`）。

**修复：UDP 会话键用错（串流到错误目标）**

Rust `proxy/socks5.rs` 的反向索引是 `(peer, target) → session`。
Go 侧是「一个本地 socket 一个 session」，`WriteTo` 换目标时仍复用同一
session id，而服务端**只在建会话时读一次目标**——于是发往 1.1.1.1 的包
被送到 8.8.8.8。

`docs/test_udp.py` 的第 3 项正好暴露了它：
发送目标是 `1.1.1.1`，回程地址帧却是 `8.8.8.8`。
（DNS 事务 ID 断言能过，因为 8.8.8.8 确实回答了那个查询——所以这个
缺陷很难靠「能不能通」发现。）

修法：`udpConn` 内部按目标地址帧维护 `map[string]*udpSession`，
每个新目标自动分配 session id；下行合并进单一 `rx` 队列，
`ReadFrom` 带回各自的目标地址；每 30 秒回收空闲 60 秒以上的会话
（对齐 Rust 的 30 秒扫描 + `timeout_secs.max(10)`）。

**实测（203.0.113.10，新加坡，跨境链路）**

| 指标 | 修复前 | 修复后 | 提升 |
|---|---|---|---|
| 下行（单流 100MB） | 5.25 Mbps | **76~87 Mbps** | ~15x |
| 上行（20MB POST） | 10.85 Mbps | **87 Mbps** | ~8x |
| 4 并发下行 | —— | 4 × 2.5MB/s = 80 Mbps | 带宽公平共享 |
| UDP DNS | 目标串流错误 | 目标正确，20/20 无丢包 | 修复 |

**已知差异（刻意不跟）**

Rust `transport_config` 里还有 `ack_frequency_config(max_ack_delay(5ms))`。
quic-go 只能**解析** ACK Frequency 帧，不能发送，且
`MaxAckDelay` 是 `internal/protocol` 里的常量（25ms），
改它必须 fork quic-go——违反「依赖版本与 sing-box 逐字节对齐」的约束。

实际影响很小：quic-go 每收到 2 个 ack-eliciting 包就立刻回 ACK
（`packetsBeforeAck = 2`），25ms 只是「凑不满 2 个包」时的兜底。
批量传输下 ACK 实际间隔远小于 5ms。记为已知差异，不改。

## 2026-11-13 14:45 (北京时间)

### P5-3 完成：CI 落地 + 伪装站反向代理模式

**CI（`.github/workflows/ci.yml`）**

四个 job，按「能不能在没有特权的情况下跑」分层：

| job | runner | 内容 |
|---|---|---|
| `verify` | ubuntu-latest | `make build` + `make verify` + 示例配置 `check`（非 root） |
| `test` | ubuntu-latest | `go vet` + 冻结向量门禁 + `go test -race` + `gofmt -l` 断言 |
| `cross` | ubuntu-latest | flowtls windows/darwin/arm64 + sing-box 协议层交叉编译 |
| `e2e` | `[self-hosted, flowtls-e2e]` | 真链路矩阵，`workflow_dispatch` 手动触发 |

托管 runner 拿不到 raw socket，所以 e2e 独立成 job 并用标签 opt-in；
把它的失败设成「允许」等于没有门禁，不如诚实地不跑。

**新增：伪装站反向代理模式（`masquerade.proxy_url`）**

对齐 hysteria2 的能力，比静态文件更难识破：

| 模式 | 可枚举的特征 |
|---|---|
| `site_dir`（静态） | 目录结构、404 页、ETag 格式、`Last-Modified` 精度 |
| `proxy_url`（反代） | 无——探测者看到的一切与直连目标站点**逐字节相同**（已 `cmp` 验证） |

```json
"masquerade": {
  "certificate_path": "...",
  "key_path": "...",
  "proxy_url": "https://example.com",
  "rewrite_host": true
}
```

**修复**

| 问题 | 原因 | 处理 |
|---|---|---|
| `check` 抓不到 masquerade 配置错误 | 互斥/URL 校验只写在 `newMasquerade`（Start 阶段），而 check 只走构造函数 | 拆成 `validateMasqueradeOptions`（纯字符串，构造函数调）+ `newMasquerade`（读文件/bind，Start 调） |
| 文档脚本在非 root 环境跑不起来 | 写死 `GOPATH=/root/go`、`PATH=/usr/local/go/bin` | 改成探测式：go 不在 PATH 才补 /usr/local/go，GOPATH 未设则取 `go env GOPATH` |
| 伪装站把探测日志写到 stderr | `http.Server.ErrorLog = nil` 的语义是「用标准 logger」而不是「不记录」，注释与代码恰好相反 | 改用 `log.New(io.Discard, "", 0)`；实测探测垃圾不再产生任何日志行 |
| 反代回源第三方站点返回 403 | `rewrite_host` 默认 false，沿用客户端 Host，对方不认 | 文档 + 示例明确：第三方回源必须设 `true`；实测改后与直连逐字节相同 |

**实测**

| 项 | 结果 |
|---|---|
| `check` 两个都填 | FATAL「proxy_url 与 site_dir 只能填一个」 |
| `check` 缺 scheme | FATAL「proxy_url 必须带 http:// 或 https:// 前缀」 |
| 反代 `rewrite_host: true` | 200 / 577 字节，`cmp` 与直连 example.com **完全相同** |
| 反代 `rewrite_host: false` | 403（预期，已写入文档） |
| 启动日志 | `(proxy → https://example.com (rewrite_host))` |
| 脚本可移植性 | `env -i PATH=/usr/bin:/bin` 下也能跑通门禁 |
| 适配层单测 | 新增 `masquerade_test.go`（4 个测试 / 10 个断言），sing-box 侧首次有测试 |
| ErrorLog 修复 | 连发 3 次畸形 TLS，日志行数 9 → 9（无增长） |
| 全量回归 | verify / test / 门禁 / gofmt / 示例 check / 交叉编译 全绿 |
| 真链路矩阵 | 4 通过 / 0 失败 / 3 跳过，无 iptables 残留 |

**文档**

`README.md`（两种模式对比表 + rewrite_host 提示 + CI 说明）、
`docs/MIGRATION.md`（`site.dir` 对应两种模式）、
`deploy.example/server.json`（反代示例）、`DEVTIPS.md` 第 76、77 条。

## 2026-11-13 14:25 (北京时间)

### P5-1/P5-2 完成：iptables 三种模式接线 + 同端口真证书伪装站（证书恢复）

**先说一次事故**：冻结 Rust 时我把 `ssl/` 当成临时联调夹具一起删了，
里面其实是 CloudFlare Origin CA 签发的 `*.example.com` 真证书。
已从 `/root/FlowTCP/ssl/` 恢复，并核对私钥与证书公钥指纹一致（MATCH）。
`/ssl/` 一直在 `.gitignore` 里，所以从未入库，恢复后也不会入库。

**新增：iptables 规则层（`flowtls/rules.go`）**

| 项 | 内容 |
|---|---|
| 规则构造 | `ServerRules` / `ClientRules`，u32 匹配 IP ID 高字节 |
| 三种模式 | `none` / `print`（默认，只打日志）/ `auto`（幂等写入） |
| 平台隔离 | `rules_linux.go` 执行 iptables，`rules_stub.go` 保证交叉编译 |
| 挂载点 | 服务端 `NewListener`（raw socket 之后）、客户端 `Dial`（第一个包之前） |

`print` 模式同时打印**安装与卸载**命令，运维复制粘贴即可。
规则刻意不自动删除：重启期间规则必须继续生效，否则内核会回 RST 打断重建中的隧道。

**新增：同端口真证书伪装站（`protocol/flowtls/masquerade.go`）**

```json
"masquerade": {
  "site_dir": "/var/www/lumen-edge",
  "certificate_path": "/etc/ssl/private/fullchain.pem",
  "key_path": "/etc/ssl/private/privkey.pem"
}
```

恢复 Rust 版行为：inbound 自己 bind 同一个端口跑 HTTPS 站点，
靠 raw/PREROUTING 的 DROP 规则分流——伪造包被 DROP（内核看不到，
AF_PACKET 照旧收包），其余包落到内核 TCP 由站点回应。

**修复**

| 问题 | 原因 | 处理 |
|---|---|---|
| 文档里 `0xF107 = 61687` | 手算错，`0xF107` 其实是 **61703**（61687 = 0xF0F7） | 全仓修正；此类错误在 JSON 里看不出来，两端用同一错值也能互通，但会与旧部署特征失配 |
| `print` 模式静默退化成 `none` | inbound 只解析了模式却没传进 `ListenerOptions` | 解析后保存并传入；`print` 时打 WARN |
| 伪装站 `/` 返回 301 | 自写的路径重写把 `/` 改成 `/index.html`，触发 FileServer 回跳 | 直接用 `http.FileServer`（它本身已处理 `/` 与 pretty URL） |
| 重新连时规则日志刷屏 | `auto` 每次建连都把同一份规则 INFO 一遍 | `Added == 0` 时降为 Debug |

**实测**

| 项 | 结果 |
|---|---|
| `print` 输出 | WARN 级，含安装 + 卸载命令，表达式 `0x4&0xff00ffff=0xf1004000` |
| `auto` 首次 | 新增 2 条（客户端）/ 1 条（服务端），`iptables -C` 命中 |
| `auto` 幂等 | 再启动一次：「新增 0 条，已存在 N 条」，规则仍只有 1 份 |
| DROP 规则在位时隧道 | TCP 4 流 PASS、UDP PASS（证明 AF_PACKET 在 netfilter 之前收包） |
| 伪装站（真证书） | `/` → 200 / 10174 字节 / HTTP/2，证书 CloudFlare Origin CA，ALPN h2 |
| 伪装站 404 | `/nonexistent` → 404 |
| 同端口共存 | 隧道 PASS 的同时站点正常响应 |
| `check` 校验 | 缺 `certificate_path` 时 FATAL，正常配置 PASS（非 root） |
| `e2e_matrix.sh` | 4 通过 / 0 失败 / 3 跳过，跑完无 iptables 残留 |

**验证 auto 的方法**（已写入 DEVTIPS 第 74 条）

```bash
iptables -t raw -C PREROUTING -p tcp --dport 8443 \
  -m u32 --u32 '0x4&0xff00ffff=0xf1004000' -j DROP && echo 已安装
# 装了 DROP 之后流量必须仍然通，否则说明规则写宽了
/tmp/ftdial -server <IP>:8443 -password xxx -target example.com:443 -insecure
```

**文档**

`README.md`（抗探测小节 + 限制）、`AGENTS.md`（架构图 + 约束 12/13）、
`docs/MIGRATION.md`（`tls.cert` → `masquerade.*`）、
`deploy.example/*.json`（两个新配置块）、`DEVTIPS.md`（第 74、75 条）。

## 2026-11-13 13:45 (北京时间)

### 冻结 Rust：主分支转为 Go 单实现

**归档**

| 引用 | 内容 |
|---|---|
| 分支 `legacy-rust` | Rust 源码 + `Cargo.toml`/`Cargo.lock` + Rust 时代测试脚本 |
| 标签 `rust-frozen-2026-11-13` | 同一提交的永久锚点（带说明） |

**删除（主分支）**

| 路径 | 原因 |
|---|---|
| `src/`（22 个 .rs 文件） | 实现已由 `flowtls/` Go 模块取代 |
| `Cargo.toml` / `Cargo.lock` | 同上 |
| `docs/test_udp_recover.py` / `docs/test_udp_stale.py` | 断言的是 Rust 实现内部的重连语义，Go 侧无对应状态机 |
| `deploy.example/*.yaml` | 换成 sing-box JSON 示例 |
| 本地 `target/` `test/` `ssl/` | 构建产物与 Rust 联调夹具 |

**新增**

| 文件 | 内容 |
|---|---|
| `flowtls/testdata/wire_v2_rust.bin` | 冻结前用 Rust 导出的黄金向量（120 字节） |
| `flowtls/testdata/wire_v2_rust_authid.txt` | 同密码派生的 authID（hex） |
| `docs/EVOLUTION.md` | 为什么从 Rust 换到 Go、冻结点在哪、怎么查历史 |
| `docs/MIGRATION.md` | Rust YAML → sing-box JSON 逐字段对照 |
| `deploy.example/server.json` / `client.json` | sing-box 配置示例（`check` 已通过） |
| `Makefile` 新增 `test` / `interop` / `e2e` | 单测、冻结向量门禁、真链路矩阵 |

**改写**

| 文件 | 变化 |
|---|---|
| `flowtls/interop_test.go` | 从「读 /tmp 临时向量、缺失即跳过」改为「读入库向量、缺失即失败」——Rust 删了，门禁反而变硬 |
| `docs/interop_check.sh` | 不再调用 cargo，纯 Go 消费冻结向量；并修掉 `pipefail`+`grep -q` 的假失败 |
| `docs/e2e_matrix.sh` | Rust 单元格改为**可选**：设 `RUST_FLOWTLS` 才跑，否则明确报告跳过；Rust 服务端证书缺失时自动生成 |
| `README.md` / `AGENTS.md` | 全面切到 Go/sing-box 口径，加「实现状态」与演进指引 |
| `.gitignore` | 移除 `/target/`、`/test/` |

**关键设计：删代码不能删基线**

Rust 源码删了，但它产出的**字节**留在 `testdata/`。
`TestInteropRustToGo` 现在钉的是绝对字节：authID 逐字节相同、两条记录必须能解出
`first-datagram` / `second-datagram`。任何改动 HKDF 参数、AAD 组成、nonce 布局
或记录头格式的行为都会立刻变红——不需要 Rust 工具链，不需要 root。

**验证**

| 项 | 结果 |
|---|---|
| `make build` / `make verify` | PASS |
| `make test`（`go test -race`） | PASS |
| `make interop`（冻结向量门禁） | PASS |
| `bash docs/e2e_matrix.sh`（Go↔Go，含 3 格跳过提示） | 3 通过 / 0 失败 / 3 跳过 |
| `sing-box check -c deploy.example/*.json` | PASS（非 root） |
| `GOOS=windows` / `GOOS=darwin` 交叉编译 | PASS |

**怎么查 Rust 历史**

```bash
git switch legacy-rust                     # 切过去看
git worktree add /tmp/flowtls-rust legacy-rust   # 或并行检出
cd /tmp/flowtls-rust && cargo test         # 25 个单测
```

含 Rust 的四向互通矩阵：

```bash
git worktree add /tmp/flowtls-rust legacy-rust
(cd /tmp/flowtls-rust && cargo build)
RUST_FLOWTLS=/tmp/flowtls-rust/target/debug/flowtls bash docs/e2e_matrix.sh
```

## 2026-11-13 13:30 (北京时间)

### Go P4 完成：服务端（共享 raw socket 的 Listener + sing-box inbound）+ 四向互通矩阵全绿

**新增**

| 文件 | 内容 |
|---|---|
| `flowtls/listener.go` | 共享 raw socket + 单收包协程 + 四元组分发；SYN 握手状态机；会话空闲回收 |
| `flowtls/quic/server.go` | 基于 Session 的 QUIC 服务端（`Accept` 返回已握手的 `*quic.Conn`） |
| `flowtls/cmd/ftserver/` | 服务端联调工具（TCP 转发 + UDP DATAGRAM 转发） |
| `sing-box/protocol/flowtls/inbound.go` | 真实 inbound：流首帧解析目标地址 → `RouteConnectionEx`；DATAGRAM → `RoutePacketConnectionEx` |

**修复**

| 问题 | 原因 | 处理 |
|---|---|---|
| 客户端重启后握手超时（首包被吞） | 源端口固定 → 四元组复用；旧会话未回收时新 SYN 被当成乱序包丢弃 | `handlePacket` 把**纯 SYN 判断提到「已有会话」之前**，命中则先 `dropSession` 再重新握手；重传 SYN 仍走 pending 分支复用原 ISN |
| `serveSession` 抢包 | 服务端误启 `Session` 自己的收包协程，直接读同一个共享 raw socket | 服务端只由 `Listener.recvLoop` 收包，`Session` 不启动接收协程 |
| 服务端 `Accept` 永远拿不到连接 | 原实现在连接关闭后才把 conn 交给 `acceptCh` | 先交付、再等关闭 |

**互通矩阵（全部实测通过）**

| 客户端 \ 服务端 | Rust | Go（sing-box 1.14.4-rev.1） |
|---|---|---|
| Rust | ✓ | ✓ TCP 200 / 0.22s，UDP 61B / 1ms |
| Go（sing-box） | ✓ TCP 200 / 0.22s，UDP 61B / 1ms | ✓ 连跑 5 次 0.21s，UDP 61B / 1ms |

**关键设计**

- **每客户端一个 `quic.Transport`，但只共享一个 raw socket**：
  共用 PacketConn 会让 deadline 语义打架（一个客户端的超时打断其他客户端）、
  readLoop 单点排队（快客户端饿死慢客户端）、单会话错误波及全体。
- inbound 的 raw socket 严格放在 `Start(StartStateStart)`，
  `sing-box check` 仍然不需要 root（已实测）。
- 内层 QUIC 证书用运行时自签：安全由外层 AEAD 保证，无需用户配置。

**新增门禁脚本**

| 文件 | 内容 |
|---|---|
| `docs/e2e_matrix.sh` | 一键跑完 4 格互通矩阵（Rust/Go × Rust/Go，TCP+UDP，共 10 条断言）；与编解码门禁 `docs/interop_check.sh` 分工互补 |

```
$ bash docs/e2e_matrix.sh
=== 汇总：10 通过 / 0 失败 ===
PASS
```

**联调命令**

```bash
cd flowtls && go build -o /tmp/ftserver ./cmd/ftserver
/tmp/ftserver -listen 0.0.0.0:8443 -password test-password-123 -local-ip <公网IP>
```

注意：本机互通必须用**真实网卡 IP**，不能用 `127.0.0.1`
（Go 客户端按默认路由选网卡，发到 lo 的包会被送到 ens3）。

## 2026-11-13 12:37 (北京时间)

### Go P3 完成：UDP（QUIC DATAGRAM）与 Rust 服务端互通

**新增**

| 文件 | 内容 |
|---|---|
| `flowtls/udp.go` | DATAGRAM 帧编解码（上行带地址 / 下行只有 session） |
| `flowtls/quic/client.go` | `ListenPacket` + 下行分发协程 + `udpConn`（net.PacketConn） |
| `flowtls/addr.go` | 新增无长度前缀的 `EncodeAddressFrame` / `EncodeDomainFrame` |
| `flowtls/cmd/ftudp/` | UDP 联调工具（`-sessions N`、`-rounds N`） |
| `flowtls/udp_test.go` | 7 个单测 |

**实测（Rust 服务端）**

| 用例 | 结果 |
|---|---|
| 单个会话 5 轮 DNS | PASS，61 字节回程，109ms |
| 4 个并发会话 × 3 轮 | PASS，9ms |
| 不同目标（8.8.8.8 / 1.1.1.1） | PASS |
| 服务端日志确认 | `session=0` 复用、下行 61 字节、回程交给 QUIC |
| TCP 回归（小包 + 4 流 × 5MB） | PASS，0 背压 |

**与 hysteria2 的关键差异（设计要点）**

hy2 的目标地址在会话建立时确定，后续包不再携带。本协议**上行每包都带目标
地址**（多 7~9 字节），换来服务端完全无状态：客户端重连后服务端是新连接、
会话表为空，第一个带地址的包就能自愈，不需要任何会话迁移协议。

Go 侧因此支持**一个 session 发往多个目标**（`WriteTo` 的 addr 可以变），
这与 `net.PacketConn` 的语义天然一致。

**分发的单消费者约束**

`quic.Conn.ReceiveDatagram` 是**单消费者**语义，多个协程同时读会互相抢包。
所以只能用**一个**分发协程按 session 路由到各 udpConn 的通道，而不能让每个
udpConn 自己去读。这一点和流（`AcceptStream`）不同，容易踩。

**UDP 语义的取舍**

| 位置 | 做法 | 理由 |
|---|---|---|
| 分发通道满（64） | 丢新包 | 绝不阻塞分发协程，否则一条慢会话拖死所有会话 |
| 超 MTU | 丢包并返回 `errDatagramTooLarge` | 不做应用层分片（与 Rust 一致）；错误单独定义，让上层能区分「包太大」与「会话坏了」 |
| `Close` | 只注销路由表，不关 rx | 分发协程可能正在写，关掉会 panic |

**验收**

```
cd flowtls && go test ./...  → 24 passed（新增 7 个 UDP 用例）
go vet                       → 干净
GOOS=windows/darwin go build → OK
cargo test                   → 25 passed
bash docs/interop_check.sh   → PASS
```

**未做**：`flowtls/listener.go`（服务端 Accept）、`protocol/flowtls/`（sing-box 适配层）。

## 2026-11-13 12:25 (北京时间)

### Go P2 完成：`quic/` 子包，Go 客户端打通 Rust 服务端

**定位决策**：FlowTLS 的权威实现改为 Go 独立协议库 (`github.com/luowei729/flowtls`)，
与 hy2/anytls 平级；Rust 版后续冻结，只作为互通基准与生产回滚版本。

**新增**

| 文件 | 内容 |
|---|---|
| `flowtls/addr.go` | 地址帧编解码（`[len u16][ATYP][ADDR][PORT]`），支持 IPv4/IPv6/域名 |
| `flowtls/quic/client.go` | `quic.Transport{Conn: session}` 接线、ALPN、`StreamConn`、`DialConn` |
| `flowtls/cmd/ftdial/` | 联调工具（支持 `-streams N` 单连接多流并发） |

**实测结果（本机，Rust 服务端）**

| 用例 | Rust 基线 | Go |
|---|---|---|
| 小包（example.com，928B） | — | PASS，rtt 4.2ms |
| 单流 40MB | 18.7s / 2.14 MB/s | 18.5s / **2.16 MB/s** |
| 单连接 4 流 × 10MB | — | 19.2s / 1.99 MB/s，0 背压 |
| 多用户 alice/bob | — | PASS，服务端正确识别 user |
| 错误密码 | — | 10.5s 明确失败 |
| 8 条独立连接并发 | — | PASS |

**关键 bug 1：`deliver` 不能静默丢包**

第一版接收队列满就丢（照搬 UDP 语义）。但**我们跑在伪造 TCP 上，QUIC 以为下层
是 UDP**：丢掉的包 quic-go 认定已投递，既不发 ACK 也不重传；服务端只能靠 PTO
盲猜，重传进来又被丢，形成死循环。

现象极隐蔽：单流 20MB 正常，2 流 16MB 时服务端报
`背压等待超过 30 秒，放弃该流`（它在等客户端消费，而客户端在丢包）。

改为**阻塞投递**，把背压传导到 recvLoop → raw socket → 内核缓冲。

**关键 bug 2：队列容量必须覆盖连接级接收窗口**

阻塞后仍会丢（转成内核丢包，而 FakeTCP 层没有重传机制）。数学关系：

```
队列容量 = rxQueueDepth × 1340
quic-go 默认 MaxConnectionReceiveWindow = 15MB
队列容量 < 15MB → 窗口允许的在途数据能填满队列 → 必然丢包
```

调优演进（每次都是实测出来的，不是猜的）：

| 队列深度 | 容量 | 结果 |
|---|---|---|
| 256 | 0.3MB | 单流 20MB 勉强，40MB 失败 |
| 8192 | 10.7MB | 单流 40MB ✓、2 流 16MB ✓、4 流 40MB ✗ |
| **16384** | **21.9MB** | **4 流 40MB ✓** |

**关键 bug 3：quic-go 会剥离 ctx 取消**

`transport.Dial(ctx, ...)` 内部调用 `context.WithoutCancel(ctx)`——**故意
剥离取消信号**，只用 ctx 传值。所以传带超时的 ctx 完全无效。

密码错误时格外致命：服务端静默丢弃 Initial，但客户端仍在收 SYN-ACK/纯 ACK，
握手期永不"空闲"，连 `HandshakeIdleTimeout` 都不触发。实测要外部 `timeout`
命令才能杀掉进程。

修复：`dialWithTimeout` 自己起 goroutine 跑 Dial，用 select 抢 ctx.Done()，
超时后主动 `transport.Close()` 结束内部等待。

**关键 bug 4：Close 顺序导致进程不退出**

`transport.Close()` 会等它内部的 reader goroutine 退出，而那个 goroutine
阻塞在 `Session.ReadFrom` 上；`ReadFrom` 只有 `Session.Close()` 才返回。
所以必须**先关 Session 再关 Transport**。反过来写功能完全正常，
但进程永不退出（`exit=124`），只能被 timeout 杀掉。

同时补上：`Session.Close` 必须关 raw socket——recvLoop 阻塞在 `raw.Recv`
的 syscall 上，只标 closed 标志不会唤醒它，会泄漏 goroutine + 2 个 fd。

**关键 bug 5：`SetReadDeadline` 空实现**

quic-go 把握手与 idle 超时都挂在 `SetReadDeadline` 上。空实现会让它永远
收不到超时信号。已实现真正的 deadline（atomic 存绝对时刻 + timer），
并返回实现了 `net.Error`（`Timeout() == true`）的错误——否则 quic-go
会把正常超时当致命错误。

**其他调整**

- `MaxStreamReceiveWindow` 从 8MB 回到 4MB（与 Rust 侧一致）。
- **不设** `MaxConnectionReceiveWindow`：曾设成 16MB，结果单流下载到
  16.7MB 永久卡住（连接级窗口耗尽后没回补）。保持 quic-go 默认的自适应
  连接窗口反而正常。
- 接收缓冲改用 `sync.Pool`：40MB 下载约 3 万次分配，池化后 GC 压力明显下降。
- `Stats` 去掉拥塞窗口：sagernet/quic-go 此版本的 `ConnectionStats`
  没有 `CongestionWindow` 字段。

**验收**

```
cargo test                    → 25 passed
cd flowtls && go test ./...   → 17 passed（含 2 个互通）
go vet                        → 干净
GOOS=windows/darwin go build  → OK
bash docs/interop_check.sh    → PASS
sing-box with_flowtls 编译     → OK
```

**未做**：`flowtls/listener.go`（服务端 Accept）、`protocol/flowtls/outbound.go`
（sing-box 适配层）、UDP。

## 2026-11-13 11:29 (北京时间)

### Go P1：`flowtls/` 传输层移植完成，与 Rust 双向互通已验证

目标：把 Rust 的传输层做成独立 Go module（不 import sing-box），
这是「与 hysteria2/anytls 平级」的地基。

**新增文件**

| 文件 | 内容 |
|---|---|
| `packet.go` | IP/TCP 头构造与解析、校验和、seq/ack、SYN 选项、TcpClock、IP ID、窗口 |
| `codec.go` | v2 记录格式 + ChaCha20-Poly1305 + authID 派生 + 多用户表 |
| `socket_linux.go` / `socket_stub.go` | AF_PACKET 收发 / 非 Linux 返回明确错误 |
| `session.go` | `net.PacketConn` 实现 + 三次握手 + 接收循环 |
| `codec_test.go` / `interop_test.go` | 17 个单测，含两个真实跨语言互通用例 |

**跨语言互通已验证（双向）**

这是本轮最重要的产出——Rust 与 Go 各自自测全绿**不代表**能互通。

| 方向 | 做法 | 结果 |
|---|---|---|
| 密钥派生 | 三个密码导出 authID 对比 | **逐字节一致**（`414707f6…` 等） |
| Rust → Go | Rust 加密首包+后续包，Go 解密 | 通过 |
| Go → Rust | Go 加密，Rust `open_first`/`open` 解密 | 通过 |

固化为 `docs/interop_check.sh`，一条命令跑完双向门禁。

**依赖选型踩的坑**

1. **x/sys/unix 不能用**：当前版本里 `Sendmmsg`、`IfNametoindex` 符号已变
   （`undefined`），且它的 `go` 指令会把整个模块顶到 **1.26.0**，
   而 sing-box 锁的是 1.25.5——直接导致 sing-box 无法编译本模块。
   改用标准库 `syscall`（AF_PACKET / SOCK_RAW / sendto / recvfrom 都齐全），
   只额外依赖 `golang.org/x/crypto`（ChaCha20-Poly1305），钉到 `v0.54.0`。
2. **批量发送暂时退化**：标准库没有 `sendmmsg` 封装，`SendBatch` 先循环
   `sendto`。正确性优先，批量优化留到性能阶段。接口不变，替换实现不影响上层。
3. **HKDF 用标准库**：Go 1.24+ 的 `crypto/hkdf` 足够，不必引 x/crypto/hkdf。

**`net.PacketConn` 设计要点**

- 握手**同步完成**后才返回 Session：quic-go 的 `Dial` 会立刻写 Initial，
  若在 `WriteTo` 里做握手就要在并发读循环里维护状态机，竞态极难排查。
  这与 Rust 版「握手完成前不 drain_transmits」是同一语义。
- `ReadFrom` 返回的 addr 恒为对端：伪造 TCP 是点对点的，不存在一个
  socket 收多对端的情况。
- 接收通道满就丢（UDP 语义）：改成阻塞会让接收协程被上层拖死，
  整条连接的所有流一起卡住。
- SYN 重传必须复用同一个 ISN（真实 TCP 行为），换新值服务端不会回 ACK。

**验收**

```
cargo test                  → 25 passed
cd flowtls && go test ./... → 17 passed（含 2 个互通用例，非 skip）
GOOS=windows/darwin go build → OK（stub 生效）
bash docs/interop_check.sh  → 互通门禁 PASS
```

**未做**：服务端 `Listener.Accept`（P4）、`quic/` 子包与 sing-box 适配层（P2/P4）。

## 2026-11-13 11:20 (北京时间)

### wire format v2：多用户鉴权 + 协议版本位

用户确认「开发阶段、没发过版、不存在兼容问题」，并要求多用户；版本位由我
参与设计（用户原话「1 字节版本位什么作用我不懂」）。

**为什么必须改格式**：现在是「解密成功 = 鉴权通过」，全局一把密钥。
多用户有 N 把钥匙，服务端必须先知道用哪把：

- 遍历所有密钥试解 → 100 用户 = 每包 100 次 ChaCha20-Poly1305，不可接受；
- 所以必须**在包里带一个明文标识**做索引。

**为什么同时加版本位**：既然反正要改格式，版本位几乎零成本（放进 AAD 不占
报文空间），却能把「改协议」从「断网重来」变成「可协商」——将来改
wscale/ack 策略时可以支持新老客户端同时在线，不用再开第二个端口。

**线上格式**：

```
首包：17 03 03 | len | ver(1) | authID(16) | nonce(12) | 密文+tag
后续：17 03 03 | len | nonce(12) | 密文+tag

AAD：首包 = ver|authID，后续 = ver
```

**密钥派生改成两条独立路径**（salt 升到 `flowtls-faketcp-v2`）：

```
authID  = HKDF(password, info="flowtls faketcp auth id v2")[0..16]
aeadKey = HKDF(password, info="flowtls faketcp aead key v2")[0..32]
```

不同 info ⇒ 抓包拿到 authID 既推不出密码，也无法解密任何数据。

**命名参照 sing-box 惯例**：查证了 hysteria2 / anytls / shadowsocks 三个协议，
它们的 `users` 统一是 `name + password`，且 **name 只用于日志，线上传凭证
本身或其派生值**（anytls 传 `sha256(password)`，vless 传 UUID）。所以
flowtls 也是 name 仅日志、线上传 authID，配置结构完全对齐。

**踩到的关键坑（差点酿成线上故障）**：最初把首包设计成「`swap` 一次，
只发一次」。但 QUIC Initial 丢包重传会产生新记录——如果只在第一份上带首包
头，后续重传的包服务端无法识别用户，**全部静默丢弃**，表现为「客户端一直
重传、服务端完全没反应」。已改成：客户端在收到服务端第一个能解开的包之前，
**每个包都带**首包头；确认可达后置 `established` 不再携带。服务端方向从不携带。

**服务端结构变化**：

| 项 | v1 | v2 |
|---|---|---|
| 密钥 | 进程级全局 `Obfs` | `ServerConn.obfs: Option<Arc<Obfs>>` |
| 用户表 | 无 | `HashMap<[u8;16], (name, Arc<Obfs>)>` |
| 包→密钥 | 直接全局 | `by_client: HashMap<SocketAddr, (ch, obfs, name)>` O(1) |
| 解密失败日志 | `warn` | `debug`（公网探测包会刷满 warn） |

`by_client` 必须在 accept 时插入、连接回收时（两处 `retain`）同步删除，
否则会指向已删除的句柄，每包白跑一次 AEAD。

**配置**（`users` 非空时优先，顶层 `password` 保留单用户模式）：

```yaml
password: "single-user-password"   # 单用户模式
# 或
users:
  - name: "alice"
    password: "..."
  - name: "bob"
    password: "..."
```

**check 新增三项校验**（每条都对应一个「配错不报错、只是连不上」的坑）：

- 客户端 password 必须命中服务端用户表之一（原来是两个字段相等）；
- 两个用户密码相同 → auth id 冲突、后者静默覆盖前者 → 报错；
- 同时配了顶层 `password` 和 `users` → 警告前者被忽略。

**验收（本机联调，全部通过）**：

| 用例 | 结果 |
|---|---|
| alice TCP | `http=200` |
| bob TCP（并发） | `http=200` |
| alice 20MB 下载 | 20000000 字节完整，~2.0MB/s |
| bob 20MB 下载 | 20000000 字节完整，~2.0MB/s |
| alice UDP（DNS + session 复用 + 不可达目标） | 全部通过 |
| bob UDP | 全部通过 |
| 错误密码客户端 | 连不上（`http=000`），服务端无首包通过记录 |
| 服务端日志用户区分 | `user=alice` / `user=bob` 正确 |
| 解密失败次数 | 0 |
| 单用户老配置 | 仍可用 |
| `cargo test` | 23 passed |

**测试用例新增**：`first_packet_carries_auth_id`、`subsequent_packet_has_no_header`、
`retransmit_still_carries_header`、`tampered_auth_id_rejected`。

**未做**：Go 侧（`flowtls/` 模块）P1 实现时直接按 v2 写，不需要额外迁移工作。

## 2026-11-13 10:41 (北京时间)

### P0：引入 sing-box v1.14.4，产出 `1.14.4-rev.1` 发行二进制

用户决策链：先把 FlowTLS 做成「与 hy2/anytls 平级的独立协议库」，
再在本仓单独发行一个带 flowtls 的 sing-box 构建（rev 版）。

**名称与版本号**：二进制名**保持 `sing-box` 不改**，只用版本号区分官方版。
版本号定为 `1.14.4-rev.1` 而不是 `1.14.4rev`——后者不是合法 semver，
面板/客户端做 `semver.Parse` 会直接报错，前者可被正常识别。

**引入方式**：`git subtree add --prefix sing-box ... v1.14.4 --squash`。
选 subtree 不选 submodule：补丁要留在自己仓库里、`git log` 可审计、
一个 clone 就能构建。不用 `go mod vendor`（会到 1GB+）。

**上游补丁总敳：2 个文件、7 行**

```
sing-box/constant/proxy.go    +3   ProxyDisplayName 增加 FlowTLS 分支
sing-box/include/registry.go  +4   inbound/outbound 各插一行注册调用
```

刻意把 `TypeFlowTLS` 与全部错误常量放进**新文件** `constant/flowtls.go`，
而不是塞进 `proxy.go`/`err.go`——新文件在 `git subtree pull` 时永不冲突。
（第一版曾是 4 文件 28 行，重构后压到 2 文件 7 行。）

**版本号注入不改上游源码**：

```
-X github.com/sagernet/sing-box/constant.Version=1.14.4-rev.1
```

上游 `release/LDFLAGS` 只含 `godebugDefault` 和 `checklinkname`，
不含 Version，所以追加不会覆盖任何东西。

**build tag 双文件**（照抄 `include/quic.go` / `quic_stub.go`）：
未开 `with_flowtls` 时注册 stub 返回 `ErrFlowTLSNotIncluded`，
而不是干脆不注册——否则用户看到 `unknown inbound type`，
分不清是「没开 tag」还是「type 拼错了」。

**新增文件**：

| 文件 | 作用 |
|---|---|
| `flowtls/` | 独立 Go module（不 import sing-box），只有 doc/config/errors 骨架 |
| `sing-box/protocol/flowtls/` | 适配层，P0 只做参数校验 |
| `sing-box/option/flowtls.go` | 配置结构，内嵌 ListenOptions/DialerOptions/ServerOptions |
| `sing-box/constant/flowtls.go` | 类型常量 + 3 个错误 |
| `sing-box/include/flowtls.go` | `//go:build with_flowtls` |
| `sing-box/include/flowtls_stub.go` | `//go:build !with_flowtls` |
| `Makefile` + `VERSION` | 构建/发行/验收/上游同步 |
| `docs/SINGBOX_INTEGRATION.md` | 设计文档 |

**依赖版本对齐**：`flowtls` 依赖的 `sagernet/sing` 必须与
`sing-box/go.mod` **完全一致**（`v0.9.7-0.20261023115459-5dc452e537bf`），
否则 `M.Socksaddr` 等类型会对不上。第一次误用了 testing 分支的版本，已改正。

**验收结果**：

```
$ ./dist/sing-box-1.14.4-rev.1-linux-amd64 version
sing-box version 1.14.4-rev.1
Tags: with_gvisor,with_quic,...,with_flowtls
CGO: disabled

$ ./dist/sing-box-1.14.4-rev.1-linux-amd64 version --name
1.14.4-rev.1

$ ... check -c flowtls-inbound.json
FATAL initialize inbound[0]: flowtls is registered but the transport layer is not implemented yet

$ 不带 with_flowtls 构建
FATAL initialize inbound[0]: flowtls is not included in this build, rebuild with -tags with_flowtls

$ ... check -c 常规mixed配置
check PASS
```

`check` 不需要 root（硬要求），因为它只走构造函数、不开 raw socket。

**环境**：本机原本没有 Go，已安装官方 `go1.25.5.linux-amd64` 到 `/usr/local/go`。

**未做**：GPLv3 §5(a) 的修改声明（NOTICE）——用户明确表示仓库后续会私有化，
分发义务目前不触发；若将来对外发二进制需补上。

## 2026-11-13 00:15 (北京时间)

### 版本收敛：两端统一到最新版，清理全部旧版本残留

用户要求「确保服务器和客户端都是新版本，清理老版本防止混乱」。

**发现并修复两个真实问题**：

1. **客户端带着实验残留环境变量**
   1080 端口的进程（PID 1510553）二进制确实是新版，但继承了我昨晚做
   DATAGRAM 单变量 A/B 实验时的 `FLOWTLS_NO_DATAGRAM=1`。
   这会让客户端不通告 `max_datagram_frame_size` → **UDP 转发完全失效**。
   排查方法：

   ```bash
   tr '\0' '\n' < /proc/$(pgrep -x flowtls)/environ | grep FLOWTLS
   ```

   已用干净环境重启，UDP 恢复（20/20 通过）。

2. **服务端配置漂移（max_cwnd 2MB vs 8MB）**
   昨晚 A/B 实验时把本地配置 sed 成 2097152 并 scp 到服务器，
   之后本地回退了却**忘记同步回服务器**。
   而实验已经证明 2MB 比 8MB 差（p50 209→303ms，cwnd 被压到 85~266KB，
   低于 BDP 934KB）。已重新同步并重启，`win_cap=8388608` 确认生效。

**清理清单**：

| 位置 | 清理前 | 清理后 |
|---|---|---|
| 服务端 `flowtls.bak.*` | 25 个（128MB） | **1 个**（`bak.last` 回滚点） |
| 本地 `target/` | 2.1GB（debug 1.3G + release 610M + musl 277M） | **8.3MB**（仅留 musl 二进制） |
| 本地实验残留 | `/tmp/flowtls.old`、`deploy/*-old.yaml` | 已删除 |
| git worktree | `/tmp/ft-old` | 已 remove |

**验证可复现构建**：删掉 `deps`/`build` 后重新编译，产物 md5
`aea07ada761cf9d80a518ba25bba7e07` 与运行中进程完全一致。

**最终状态**：

| 项 | 客户端 | 服务端 |
|---|---|---|
| 二进制 md5 | `aea07ad`（x86_64-musl） | `907bd10`（aarch64） |
| 源码 md5 | `dc20626` | `dc20626`（一致） |
| 环境变量 | 干净 | 干净 |
| `max_cwnd` | 8388608 | 8388608（已修正） |
| 进程数 | 1 | 1 |

实测：UDP 20/20 通过，纯隧道 80/81/82ms（= 1 个 RTT，理论最优）。

**教训**（写进 DEVTIPS 53）：实验用的环境变量和配置**必须记录并在实验后清理**。
`FLOWTLS_NO_DATAGRAM=1` 这种开关一旦忘了撤销，功能会静默失效
（UDP 不通但不报错），比崩溃更难发现。

## 2026-11-12 23:40 (北京时间)

### 延迟排查：用旧版本二进制做对照实验，结论是「没有回归」

用户反馈「改完后延迟几百 ms，之前基本 100 左右」。用 git 里的旧版本
（`d887793`，17:13 那版，即改动前的状态）编译出对照二进制，
建独立通道（服务端 9443 + 客户端 44333/11080）与新版本并行对比。

**最终结论：不存在性能回归。**

| 测试项 | 结果 | 判定 |
|---|---|---|
| ICMP 链路（绕过代理） | 74.0 / 74.9 / 76.2，mdev 0.48 | 链路稳定 |
| **纯隧道**（目标=服务端本机，无 DNS 无 TLS） | **min 81 / p50 81~82** | = 1 个 RTT，**理论最优** |
| 204 HTTPS | min 170 / p50 172~174 | 2 RTT 是物理下限（153ms），接近最优 |
| 旧版本纯隧道（同条件对照） | 78~79 | 差距 3ms，在噪声内 |

**关键认知：204/HTTPS 的 200ms 不是性能问题，是物理下限。**

```
TLS 1.3 握手 = 1 RTT（ClientHello → ServerHello..Finished）
HTTP 请求/响应 = 1 RTT
合计 = 2 RTT = 153ms（RTT 76.6ms）
```

截图里 Google 203ms / YouTube 210ms 正是这个量级；GitHub 98ms 是因为
检测工具复用了已建立的连接。**任何代理都无法把「新建 TLS 连接」做到 1 RTT。**

**排查过程中排除了三个假设**（都有数据）：

1. **不是窗口过大**：把 `max_cwnd` 从 8MB 降到 2MB（BDP 的 2.2 倍）后
   p50 从 209ms 恶化到 303ms，cwnd 被压到 85~266KB（低于 BDP 934KB），
   吞吐与延迟双输。已回退到 8MB。
2. **不是目标连接耗时**：服务端实测 `connect_ms = 4~10`（`www.gstatic.com`
   解析出 16 个地址），完全不是瓶颈。
3. **不是 DATAGRAM 扩展**：加 `FLOWTLS_NO_DATAGRAM=1` 开关做单变量 A/B，
   开/关都是 80~81ms。

**真正的变量是链路丢包（晚高峰 15~20%）**：
每丢一个包 = 多等 1 RTT = +76ms。一次 HTTPS 连接需要 2~3 个往返，
按 15% 丢包算 `1-0.85^3 ≈ 39%` 的连接会踩到一次丢包，于是 p90 从 81ms
跳到 246ms。**这是链路属性，不是代理实现问题。**

**过程中自己制造的三个测量陷阱**（都写进 DEVTIPS 50）：

1. 在**同一台 1 核服务器**上同时跑新旧两个服务端做对比 —— CPU 争抢污染结果。
2. 用**已运行数小时的旧连接**测基线 —— cwnd 已被打崩到 4 个包，与刚重启的
   干净连接不可比。
3. 同时跑 4 个客户端进程 —— 每个都开 AF_PACKET 收全量包，互相干扰。

**保留的两项改动**（有价值，不是实验残留）：

- `connect_target()`：多地址域名改为**并发连接取最快**（Happy Eyeballs 思路）。
  tokio 的 `TcpStream::connect(&str)` 对多地址是顺序重试，头一个地址不通
  就要等内核 SYN 超时。**不做任何缓存**，语义与改动前一致。
- `FLOWTLS_NO_DATAGRAM=1` 环境变量：临时关闭 DATAGRAM 扩展，用于二分排查。

**新增 `docs/bench.sh`**：三层延迟体检（链路基线 / 纯隧道 / HTTPS），
自带判定标准，可随时自己复测：

```bash
bash docs/bench.sh        # 20 次
bash docs/bench.sh 50     # 更精确
```

## 2026-11-12 21:55 (北京时间)

### 全量代码审查：修复 11 个缺陷（含 2 个实测复现的致命故障）

对 7736 行代码逐文件审查，除静态阅读外还做了三次现场复现。
按严重程度排序：

**P0：客户端会永久卡死**

1. **SYN 只发一次，且握手阶段没有超时兜底**。
   严格 NAT 要求先完成三次握手，所以握手期间不发送任何 QUIC 包；
   而 quinn 的 idle 定时器要等首次发包后才启动。
   两者叠加 → SYN 或 SYN-ACK 丢一次就永久停在「已发送 SYN」，
   不重传、不超时、不重连。**实测卡死 2 分 43 秒**（手工重启才恢复）。
   修复：SYN 按 1/2/4/8 秒退避重传，15 秒未握手成功则放弃本次会话交给外层重连。
   服务端配套：**对重传的 SYN 复用原 ISN + TSval**（与真实 TCP 一致），
   否则客户端会收到两个不同 seq 的 SYN-ACK，序号被来回拉扯。

**P1：协议外观破绽**

2. **ServerHello 长度错位**：`build_server_hello()` 的加密段长度随机（512~703），
   代码却**又调了一次**取长度去算 `data_seq`，后续所有 TCP 序号偏 0~191 字节。
   中间盒看到 `seq` 与上一包 `seq+len` 不衔接 → 伪造特征。改用实际发送长度。
3. **TSval 在握手阶段非单调**：SYN-ACK、ServerHello、数据包各取一个独立随机数，
   约 50% 概率出现时间戳回退（RFC 7323 的 PAWS 明确禁止）。
   且首个数据包 `TSecr=0`（客户端 SYN 的 TSval 明明已知）。
   修复：`TcpClock::new_at()`，握手生成一次 TSval 贯穿全程，并立刻 observe 对端时间戳。
4. **SNI 是裸 IP**：默认部署用 IP 连接，伪 ClientHello 就把 IP 填进 SNI，
   违反 RFC 6066，任何 DPI 都能一眼命中。修复：SNI 是 IP 时省略该扩展
   （与真实浏览器用 IP 直连的行为一致）。

**P1：功能缺陷**

5. **UDP 死会话永久黑洞**（实测复现）：出站任务退出后会话条目留在表里，
   且 `last_active` 在 `try_send` **之前**刷新 —— 上行包不断给死会话续命，
   空闲超时永不触发。向不可达目标持续发包时 `udp_sessions` 永停在 1，
   客户端那条 `(peer, target)` 从此再也发不出去。修复：区分 `Closed`（删表）
   和 `Full`（仅丢包），只在投递成功时刷新活跃时间。
6. **重连后旧流收尾误杀新流**：stream id 由 quinn 按连接分配、重连从 0 重来；
   `pipe_stream` 的收尾（`stop`）可能迟于重连（reader 卡在本地 `read` 上）。
   一个迟到的 `Stop(0)` 会把新连接上刚建的同号流 RESET。
   修复：动作带 epoch，跨代动作一律丢弃。
7. **HTTP 普通请求路径缺 FIN/STOP**：双向都是「未完成」，流要等 5 分钟空闲回收，
   服务端出站任务一直挂着 —— 资源泄漏。修复：发完请求补 `fin`，响应写完补 `stop`。
8. **重连退避永不重置**：`backoff` 只增不减，跑满 60 秒后**永久停在 60**，
   哪怕链路早就恢复正常。修复：会话活过 60 秒就把退避打回 5 秒。

**P2：安全与健壮性**

9. **SOCKS5 UDP relay 未校验来源**：relay socket 无认证（UDP 无连接），
   同网段任何人都能在猜到端口后白嫖代理。修复：只接受与 TCP 控制连接同源 IP 的包。
10. `find_by_client` 找不到连接时**回退到第一个连接**，会把 stateless reset
    用错误的 seq 发给无关客户端。改为找不到就不发。
11. 服务端 UDP 上行 `try_send` → `send().await`（见下条），
    UDP 异常日志从 `trace` 提到 `debug`。

**审查过程中自己引入又修掉的回归**（值得记一笔）：
把 UDP 出站方向的 `sock.send().await` 改成 `try_send`（理由是「UDP 不该阻塞」），
结果 UDP 成功率从 2/3 直接掉到 **0/6**。原因是 tokio 的 `UdpSocket::try_send`
依赖 socket 在 reactor 里的可写就绪状态，刚 bind+connect 的 socket 直接返回
`WouldBlock`，而那分支日志是 `trace` 级别 → 完全静默。
"会话建好了、connect 成功了、日志全正常，但第一个包（DNS 查询本身）被丢掉"。

**审查未改动的项**（已记录，收益递减）：

- `handle_incoming` / `handle_packet` 每包 `Vec::with_capacity(2048)`、
  `parse_records` 每包一个 Vec、`Obfs::open` 每记录一次分配 —— 热路径可复用缓冲。
- 客户端 `blocked` 标志是全局的：一条流阻塞会暂停所有本地读取（保守但正确）。
- `site` 模块对 POST 请求返回 405 后不读完请求体，连接会挂到 30 秒超时。

**验证**：

| 项目 | 结果 |
|---|---|
| 单元测试 | 20/20 通过，`cargo build` 零告警 |
| UDP 端到端 | 5/5 轮通过（DNS 往返 / session 复用 / 不可达目标 / 控制连接关闭） |
| UDP 会话回收 | `udp_sessions` 由 1 回到 0（修复前会挂满 120 秒） |
| SYN 重传 | 实测首次 SYN-ACK 丢失，1 秒后重传成功（不再卡死） |
| TCP 回归 | 204 = 0.41s，单流 60 Mbps（当前链路丢包 14%，属链路波动） |
| 两端告警 | 服务端 0，客户端仅重连 WARN |

新增 `docs/test_udp_recover.py`（会话回收验证）、`docs/test_udp_stale.py`。

## 2026-11-12 21:05 (北京时间)

### 新增 UDP 代理：QUIC DATAGRAM 承载，不重传不补发（对齐 hysteria2）

之前完全没有 UDP 通路：SOCKS5 只认 `CONNECT`，服务端出站只有 `TcpStream::connect`，
`TransportConfig` 也没开 RFC 9221 的 DATAGRAM 扩展。结果是 DNS 必须靠 TCP 回退、
HTTP/3 用不了、语音/游戏/WireGuard 完全不通。

**设计原则：完全参照 hysteria2 对 UDP 的处理——不做任何可靠性补偿。**

| 方面 | 行为 |
|---|---|
| 传输 | QUIC DATAGRAM（RFC 9221），不可靠、不保序 |
| 丢包 | 就是丢了，**不重传、不补发** |
| 队列满 | `try_send` / `drop=true`，直接丢弃最新的或最旧的，**不背压** |
| 超 MTU | 直接丢，**不做应用层分片** |
| 会话回收 | 空闲超时（默认 120s），UDP 无连接只能靠超时 |

**线上格式**（与 hysteria2 的 `ParseUDPPacket` 一致）：

```text
客户端 → 服务端：[session u32][addrLen u16][ATYP][ADDR][PORT][payload]
服务端 → 客户端：[session u32][payload]
```

上行每包都带目标地址。多占 7~9 字节，换来服务端**完全无状态地重建会话**：
客户端重连后服务端是新连接、会话表是空的，第一个带地址的包就能自愈，
不需要任何会话迁移协议。

**入口**：SOCKS5 `UDP ASSOCIATE`（RFC 1928 CMD=3），
数据面在独立的 UDP socket 上跑 RFC 1928 的 `RSV|FRAG|ATYP|ADDR|PORT|payload` 帧。
控制连接（TCP）只做保活：它一断，整个 relay 立刻结束并注销所有 session。

**改动**：

| 文件 | 内容 |
|---|---|
| `src/proxy/udp.rs`（新增 140 行） | 会话帧编解码 + 4 个单元测试 |
| `src/proxy/mod.rs` | SOCKS5 UDP 头编解码（`parse_socks5_udp` / `build_socks5_udp`） |
| `src/proxy/socks5.rs` | `CMD=3` 分支：bind UDP socket、session 表、上下行 select 循环 |
| `src/quic/config.rs` | `datagram_receive_buffer_size(1MB)` + `datagram_send_buffer_size(1MB)` |
| `src/client.rs` | `ProxyAction::Udp`、`udp_routes` 路由表、`drain_events` 收 datagram |
| `src/server.rs` | `UdpSession` 表、`udp_outbound` 单任务双向 select、`ServerAction::Datagram` |
| `src/config.rs` | `udp` 配置节（`enabled` / `max_sessions` / `timeout_secs`） |
| `src/check.rs` | UDP 开关两端一致性、会话上限非 0、SOCKS5 入口提示 |
| `docs/test_udp.py`（新增） | 端到端测试：DNS 往返、session 复用、不可达目标、控制连接关闭 |

**实测**：

| 项目 | 结果 |
|---|---|
| DNS 往返（8.8.8.8 / 1.1.1.1） | 61~64 字节响应，RTT ≈ 84ms |
| 连续 20 个查询 | 18~20/20 收到（跨境链路 5~10% 丢包，UDP 不重传属正常） |
| 6 轮完整测试 | 全通过 |
| 不可达目标 | 静默超时，relay 不崩 |
| 控制连接关闭 | relay 立即失效 |
| TCP 回归 | 204 = 0.18s，单流下载 80~89 Mbps，无退化 |
| 单元测试 | 20 个全过（新增 6 个） |

**关键实现细节**：

1. **服务端一个会话一个任务**：`udp_outbound` 用 `select!` 同时管上行（`rx.recv`）
   和下行（`sock.recv`）。会话回收时主循环 `remove` 掉 `to_target`，
   `rx.recv()` 立即返回 `None` → 任务退出 → socket 关闭。**不需要取消信号**。
2. **客户端 session id 从随机值递增**：避免客户端重启后与残留会话撞车。
3. **`drop=true` 而不是 `Blocked`**：quinn 的 `Datagram::send(data, drop)`，
   传 `true` 时缓冲满会丢最旧的排队包。实时流里「新包比旧包值钱」，
   而 UDP 本来就没有重传，留旧包毫无意义。
4. **MTU 零影响**：datagram 是 QUIC 帧类型，走现有 `poll_transmit` 路径，
   外层 FakeTCP/AEAD/批量发送一行都没改。单包上限由 `datagrams().max_size()`
   每包检查（约 1200 字节），超了直接丢。

**踩过的坑**（写进 DEVTIPS 44）：

测试脚本一开始要求「20 个包零丢包」，结果每次都在第 12~13 轮卡 10 秒超时。
误以为是实现 bug，查了半天服务端/客户端日志，最后发现是**跨境链路 5~10% 的
真实丢包**——UDP 本来就不该要求不丢包。改成「先全发再按事务 ID 对账」后稳定通过。

**另一个坑**：服务端重启后的 30 秒内跑测试必然失败。客户端要等 `idle_timeout`
才发现断连并重连，这期间它还在往旧连接发 datagram，服务端 `conns` 里
没有对应 `ConnectionHandle`，`ServerAction::Datagram` 的 `get_mut(&ch)`
直接返回 None 丢弃。这不是 bug，是 QUIC 的正常收敛过程。

## 2026-11-12 17:13 (北京时间)

### 新增 `flowtls check` 子命令 + 窗口上限 4MB→8MB（单流 +25%）

**1. `flowtls check`：把「两端不一致导致静默失效」的坑变成显式检查**

这个项目里有几处「两端必须一致、否则静默失效」的约束，排查成本极高，
而且失败现象都不指向真实原因（DEVTIPS 28 / 38 记录的都是这类）：

| 不一致项 | 现象 |
|---|---|
| `password` | 外层 AEAD 全部解密失败，服务端只看到「收到 raw 包 conns=0」 |
| `ip_id_magic` | iptables 打不中伪包 → 内核回 RST → 连接建不起来 |
| 端口 | SYN 发到没人监听的地方，日志里只有「已发送 SYN，等待 SYN-ACK」 |

新增子命令（`src/check.rs`），只做只读检查、不改任何文件：

```bash
flowtls check --server server.yaml --client client.yaml
flowtls check --client deploy/client-cn.yaml     # 只查一端
```

检查项：
- **两端一致性**（核心）：password、`ip_id_magic` 高字节、端口
- 服务端：listen 可解析、证书/私钥**能被 rustls 实际解析**（不只是文件存在）、
  `local_ip` 合法、`site.dir` 存在
- 客户端：`server` 可解析、`source_port` 非 0、各入口 listen 可解析、
  入口是否缺鉴权
- 两端：`net.mode` / `max_cwnd` 合理区间、iptables 规则是否按该 magic 安装
- 提醒：`ip_id_magic` 仍是编译默认值（所有未改配置的部署特征相同）、
  `handshake=none` 的前提、443 端口的已知问题

输出按「通过/警告/错误」分组，**退出码 0=无错误、1=有错误**，可直接放进 CI。
实测能正确抓出故意改坏的配置（password + magic 双不一致 → 2 个错误）。

同时修了两个**同源 bug**：`install-rules` / `check-rules` 之前硬编码 `0xF107`，
与配置派生的 magic 不匹配（上一轮改造后的遗留）。现在两个子命令都从配置读取：

```bash
flowtls install-rules server --config server.yaml
flowtls check-rules server --config server.yaml
```

**2. `net.max_cwnd` 4MB → 8MB**

之前用 4MB 的原因（高丢包 + MTU 塌到 1200 导致 MAX_CHUNKS 空洞超限）已经修掉了，
现在实测 8MB 安全且明显更快：

| 并发 | 4MB | 8MB |
|---|---|---|
| 单流 40s | 109 Mbps | **136 Mbps（+25%）** |
| 单流 60s | — | 135 Mbps（14.6 MB/s） |
| 2 流 | 167 Mbps | — |
| 4 流 | 164 Mbps | — |
| 8 流 20s | 164 Mbps | **175 Mbps** |
| 8 流 30s | — | 173 Mbps |

稳定性验证（60s 单流 + 30s 8 流并发）：客户端与服务端 **0 WARN**、
**0 次 `too many gaps`**、`loss_pct=0`、`mtu` 恒 1332。

安全性来自自适应上限：`safe_cap = 1024×1308/丢包率×0.7`，
丢包 20% 时自动压到 4.7MB、30% 压到 3.1MB。
所以配置里的 8MB 只是「天花板」，高丢包时不会真的用到，
不用担心 MAX_CHUNKS 空洞超限。

**3. 其它**

- 删除 `check-rules` 在 `main.rs` 里的 8443/44300 硬编码
- `RuleArgs` 的 `--port` / `--source-port` 改为可选，缺省从配置推导

**实测汇总（国内家宽 → 新加坡 ARM 1 核）：**

| 指标 | 数值 |
|---|---|
| 单流 200MB 下载 | 完整，135~136 Mbps |
| 单流 60s 长跑 | 14.6 MB/s |
| 上传 100MB | 7.5~8.5s（≈ 96~107 Mbps） |
| 8 流并发 | 173~175 Mbps |
| `204` 延迟 | 0.21~0.23s |
| 两端 WARN/ERROR | **0** |
| 单元测试 | **14 passed** |
| 编译告警 | **0** |

## 2026-11-12 16:53 (北京时间)

### TLS 层伪装修复：ClientHello 74→555 字节，CCS 后不再发明文

前几轮只查了 TCP 层，这次复查 TLS 层，抓到三处一眼可辨的违规。
用真实 Chrome 的握手做对照（`16 03 01 06 a3` = 记录 1699 字节）。

**1. ClientHello 只有 74 字节 / 2 个扩展（真实 1699 字节 / 10+ 扩展）**

改造前的完整内容：
```
16 03 01 00 4a          record: handshake, 74 字节
01 00 00 46             ClientHello, 70 字节
03 03 <32 random>
00                      session_id 长度 0        ← 真实浏览器发 32 字节
00 04 13 01 13 02       只有 2 个 cipher suite
01 00
00 19                   extensions 共 25 字节     ← 真实是 400+ 字节
  0000 ... SNI
  002b ... supported_versions
```

缺失的扩展里有两个是**致命**的：
- **`key_share` / `supported_groups`**：TLS 1.3 的必需扩展。
  没有 key_share 的 ClientHello，服务端根本无法完成密钥交换，
  任何懂 TLS 的 DPI 一眼判定「这不是真客户端」。
- **`early_data`**：我们发完 ClientHello 立刻发 ApplicationData（QUIC 数据），
  没有 early_data 就是明文可见的协议违规（ClientHello 之后不可能有 0-RTT 数据）。
  加上它之后，「ClientHello → 立即 ApplicationData」变成合规的 0-RTT 流程。

重建为 Chrome 风格（`src/faketcp/codec.rs`）：
- `session_id`：32 字节随机（middlebox 兼容）
- cipher suites：GREASE + 3 个 TLS 1.3 + 4 个 ECDHE
- 扩展（按 Chrome 顺序）：GREASE、server_name、extended_master_secret、
  renegotiation_info、supported_groups、ec_point_formats、session_ticket、
  ALPN(h2/http1.1)、status_request、signature_algorithms、
  signed_certificate_timestamp、key_share、psk_key_exchange_modes、
  supported_versions、**early_data**、padding、**pre_shared_key（必须最后）**
- GREASE（RFC 8701）：真实浏览器的固定特征，没有反而可疑
- padding 到 512±48 字节，避免固定长度本身成为新特征

**2. CCS 之后发明文握手记录（协议违规）**

改造前服务器握手的序列：
```
16 03 03 ... ServerHello
14 03 03 00 01 01  CCS
16 03 03 ... Finished    ← 明文！但 CCS 之后必须全是 0x17 加密记录
```

真实 TLS 1.3 里 `ChangeCipherSpec` 之后的所有握手消息都必须加密。
现在改为 `16 03 03` → `14 03 03` → `17 03 03 <586 字节随机密文>`，
长度取真实证书链量级（EncryptedExtensions + Certificate + CertVerify + Finished）。
ServerHello 也补了 `supported_versions` + `key_share` 扩展（TLS 1.3 必需）。

**实测（国内家宽 → 新加坡 ARM 1 核）：**

| 指标 | 改造前 | 改造后 |
|---|---|---|
| ClientHello 记录长度 | **74 字节** | **550 字节**（TCP 包 555~599） |
| ClientHello 扩展数 | 2 | 17 |
| `key_share` / `early_data` | ❌ / ❌ | ✅ / ✅ |
| `session_id` | 空 | 32 字节 |
| CCS 后记录类型 | **0x16 明文** | **0x17 加密**（586 字节）|
| 服务器握手响应 | ~90 字节，3 条记录 | **724 字节**，`16/14/17` 三条 |
| 单流 200MB | 17.1~18.1 MB/s | 16.9~17.8 MB/s（2/2 完整）|
| 上传 100MB | 7.7s | 7.6s |
| 8 流并发 | 170~178 Mbps | 171 Mbps（服务端 77%） |
| 两端 WARN/ERROR | 0 | **0** |
| 单元测试 | 12 | **14**（新增 ClientHello 结构 + 服务器序列测试）|

> 说明：ClientHello 每次连接多约 500 字节，只发生在建连时，对吞吐无影响。

## 2026-11-12 16:42 (北京时间)

### 分流标记改为配置派生（可换特征）+ 控制包复用缓冲 + 日志级别修正

**1. `ip_id_magic` 之前根本没生效**

配置里有 `faketcp.ip_id_magic: 0xF107`，但代码里 `IPID_MARK = 0xF100` 是写死的常量，
iptables 规则也写死 `0xf1004000`。也就是说**所有部署的 IP ID 特征完全相同**，
任何 DPI 加一条「IP ID 高字节 == 0xF1」的通用规则就能一次性命中全部实例。

改成全链路从配置派生：
- `packet::ipid_mark(magic)` → `next_ipid(mark, cur)` / `random_ipid(mark)`
- `SendCtx` / `ServerConn` 增加 `mark` 字段
- `rules::server_rules` / `ensure_client` 用 magic 生成 u32 表达式
- `config::default_magic()` 改为引用 `packet::IPID_MARK`，消除两处魔数

> **差点踩的坑**：`format!("{mark:04x}")` 生成的右值没有 `0x` 前缀。
> iptables u32 的右值走 `simple_strtoul(..., base=0)`，`f1004000` 按十进制解析失败
> → 返回 0 → **规则永不命中**。症状极隐蔽：规则存在、计数为 0、连接被内核 RST 打断
> 但日志看不出异常。已加单元测试 `server_rule_expr_has_hex_prefix` 锁住。

**2. 迁移验证：特征从 0xF1 换成 0x1E**

两端 `ip_id_magic` 改成 `0x1E07` 重启后：
- 新规则自动添加：`0x4&0xff00ffff=0x1e004000`（两端各一条）
- 抓包确认 IP ID 变成 `0x1E76, 0x1E77...`
- **删掉旧规则 `0xf1004000` 后连接仍正常**（200MB 完整下载），
  证明新标记独立生效 —— 这一步才是真正的验证
- 顺手清理了服务端遗留的旧版 wscale 分流规则 `0x2e&0xffffffff=0x3030c01`

**3. 控制包复用缓冲**

`send_pure_ack` / `send_fin` 之前每包一次 `build_packet` → 一次 `Vec` 分配。
纯 ACK 占全部包量的 22.5%，163Mbps 时每秒约 3400 次 malloc/free。
改为 `ctrl_buf: Vec<u8>` 复用（`mem::take` 绕过借用冲突），稳态零分配。

实测收益 ≈ 0（52 字节 malloc 走 tcache，约 20ns，3400 次/s 可忽略）。
CPU/Mbps 效率维持在 2.2 Mbps per %CPU，说明瓶颈在 QUIC 状态机本身而非分配。
保留此改动（无害且为将来更大缓冲铺路），并在 DEVTIPS 记录了这个结论。

**4. 正常路径日志降级**

`对端已停止该流，丢弃待发数据` 在浏览器取消下载 / `curl --max-time` 时
每次都会出现，是设计内的正常路径。`warn!` 导致正常使用就刷屏
（一次 4 流中断刷 14 条），把真正的异常淹没。改为 `debug!`。

**实测（国内家宽 → 新加坡 ARM 1 核，magic=0x1E07）：**

| 指标 | 改造前 | 改造后 |
|---|---|---|
| IP ID 特征 | 所有部署都是 `0xF1xx` | 配置派生，当前 `0x1Exx` |
| 换 magic 后旧规则失效验证 | — | **通过**（删旧规则仍正常） |
| 单流 200MB | 16.0~16.3 MB/s | **17.1~18.1 MB/s** |
| 8 流并发 | 163~172 Mbps | 170~178 Mbps |
| 服务端 CPU | 68~79% | 57~80%（波动，效率持平） |
| 上传 100MB | 7.5~8.5s | 7.7s |
| 服务端 WARN（4 流中断） | 14 条 | **0 条** |
| 客户端 WARN/ERROR | 0 | **0** |
| 单元测试 | 9 | **12**（新增 3 个规则测试） |
| 编译告警 | 7 条 | **0 条** |

## 2026-11-12 16:09 (北京时间)

### 修客户端上传方向背压（pending 78MB → 1.06MB）+ 中断后立即释放流

上一轮伪装改造时复盘浏览器测速日志，发现客户端 `pending` 峰值 **78MB**。
排查后是两处缺失，都已修复并实测验证。

**1. 客户端上传方向从来就没有真正的背压**

上传路径有三层缓冲，但只有第一层有背压：

| 层 | 上限 | 之前有背压？ |
|---|---|---|
| `mpsc::channel(1024)` | 1024 × 16KB ≈ 16MB | 只有通道满时才阻塞 |
| quinn `send_window` | max_cwnd×2 = 8MB | ❌ 应用层看不见 |
| `StreamState.pending` | **无上限** | ❌ |

78MB ≈ 16 + 8 + 54（无上限那层堆出来的）。服务端早就修过同样的问题
（`pending_bytes` / `write_blocked` / `Notify`），客户端一直没同步。

修复（`src/client.rs`）：

- `ProxyClient` 增加 `inflight`（原子计数）、`blocked`（quinn 缓冲满）、
  `notify`（腾空时唤醒）。语义是「已从本地 socket 读出、但还没交给 QUIC 的全部字节」，
  **同时覆盖通道在途和 `st.pending` 两段**——这正是之前失效的关键。
- `send()` 在把数据交给通道**之前**记账；`handle_action` / `flush_pending`
  只在 `write()` 真正被 quinn 接收了多少才扣多少。
- `write()` 返回 `Blocked` 或只写进一部分 → 置 `blocked`；
  `Writable` 事件 / pending 清空 → 清标志并 `notify_waiters()`。
- `pipe_stream` 读取前先 `wait_drain()`：超过 1MB 水位就停在这里不读本地 socket，
  浏览器/测速端被 TCP 窗口反向限速。
- 被清理的流、`Stopped` 事件清掉的 pending，都要同步退掉 `inflight`，
  否则残留数值会永久占着配额把后续流卡死（用 `saturating_sub` 防下溢）。
- 重连时（`set_tx`）把计数器归零。

> 中途踩了个坑：第一版在 `handle_action` 开头就把整笔字节从 `inflight` 扣掉，
> 数据只是转存到 `st.pending` 而已。结果 `inflight` 显示 1MB、
> `pending` 实际堆到 **36MB**，背压等于没做。只有「真正写进 quinn」才能扣。

**2. 客户端中断后不发 STOP_SENDING，服务端干等 30 秒**

本地连接被强制关闭时（浏览器取消下载、`curl --max-time` 退出），
`pipe_stream` 只是结束，没有告诉对端别再写了。服务端于是继续读目标 socket，
堆到背压高水位，然后等满 30 秒兜底超时才放弃——每次中断刷 3~4 条
`背压等待超过 30 秒，放弃该流`。

修复：
- `ProxyAction::Stop(StreamId)` + `ProxyClient::stop()`，
  `pipe_stream` 结束后调用 → `recv_stream().stop()` + `send_stream().reset()`。
- 服务端 `ServerStream` 增加 `abandon` 标志：`Stopped` 事件和 `reset_stream`
  都置位并 `notify_waiters()`，出站任务的读取协程在背压等待循环里检查它后立即退出。
  只把 `to_tcp` 置 None 不够——那个协程等的是原子计数，不看 channel。

**实测（国内家宽 → 新加坡 ARM 1 核）：**

| 指标 | 修复前 | 修复后 |
|---|---|---|
| 客户端 `pending` 峰值（100MB 上传） | **78 MB** | **1.06 MB** |
| 客户端 `inflight` 峰值 | — | 1.06 MB（精确停在水位） |
| 上传 100MB | — | 7.5~8.5s（≈ 99 Mbps） |
| 下载 200MB ×2 | 完整 | **2/2 完整**，16.0~16.3 MB/s |
| 中断后服务端 30 秒超时告警 | 每次中断 3~4 条 | **0 条**（12 秒和 37 秒两次检查均为 0） |
| 客户端 WARN/ERROR | 21 条（历史） | **0** |
| 8 流下载 | 160~174 Mbps | 163 Mbps（服务端 68%、客户端 117%） |
| MTU | 恒 1332 | 恒 1332 |

中断时服务端会打一条 `对端已停止该流，丢弃待发数据 dropped=1064960`，
`dropped` 正好等于一个背压高水位——这是设计内的正确行为，不再是超时。

## 2026-11-12 15:23 (北京时间)

### 伪装改造：TCP 层对齐真实 HTTPS（TS 选项 0%→100%、纯 ACK 0→22%、wscale 12→9）

起因：用 tcpdump 把我们的流量和**同一台服务器的真实 HTTPS（443）**并排对比，
一次抓出 8 处可识别特征。按危险程度：缺 TCP 时间戳 > 数据阶段零纯 ACK >
窗口恒 65535 > 无 FIN > wscale=12 > SYN 选项形态 > IP ID 循环 > 载荷长度固定。

**1. 补上 TCP 时间戳选项（最关键）**

改造前数据包的 TCP 头是 20 字节、零选项——一条双向传几万个包却没有一个 TS，
任何 DPI 一条规则就能判定为伪造（现代 OS 默认全开 `tcp_timestamps`）。

现在每个数据包/纯 ACK 都带 12 字节 `nop,nop,TS val <tsval> ecr <tsecr>`：
- `TSval` = 随机基准 + 连接已过去的毫秒数，单调递增
- `TSecr` 回显对端最近一次的 TSval（RFC 7323 要求）
- SYN 的 `TSecr` 保持 0（符合规范）

**2. SYN/SYN-ACK 选项改成真实 Linux 布局**

```
改造前：mss 1460, sackOK, wscale 12, nop, nop, nop
改造后：mss 1460, sackOK, TS val <随机> ecr 0, nop, wscale 9
```
与抓到的真实握手 `mss 1460,sackOK,TS val 227498442 ecr 0,nop,wscale 9` 逐字节同构。
`wscale` 从 12 改成真实的 9（12 意味着 256MB 窗口，真实系统不会这么声明）。

**3. 延迟确认：数据阶段补纯 ACK**

真实 TCP 是双向确认的，下载方向必须有反向纯 ACK。按 RFC 1122 实现：
每 2 个数据段回 1 个，或距上次确认超 40ms 兜底。
实测纯 ACK 占总包 **22.5%**（真实 HTTPS 抓包 24%）。
> 第一版做成「每批一个」，实测纯 ACK 占到 42%，CPU 抬了数倍——务必用延迟确认。

**4. 窗口动态化**

`(接收缓冲 16MB - 未消费字节) >> wscale`。空载 32768，有积压平滑下降。
抓包里能看到 32748 / 32751 / 32757 / 32765 / 32768 的自然波动。
SYN 阶段仍用 65535（缩放因子在 ESTABLISHED 后才生效）。

**5. 补 FIN 拆除**

会话结束/断线重连前发 `FIN|ACK`（同样带 TS 选项）。实测已抓到
`Flags [F.], cksum correct, options [nop,nop,TS val .. ecr ..]`。

**6. IP ID 保持窄标记（有意为之）**

TCP 选项全部改回真实值后，iptables 只能在 IP ID 上放静态标记。
范围**刻意保持窄**（高字节 0xF1，256 个值 = 0.4% 探测无响应）：
iptables 会把标记包直接 DROP，范围放宽到高四位（6%）会让端口探测行为
前后不一致，反而更容易暴露。残留的「256 周期锯齿」已记入待办。

**7. 配套改动**

- QUIC MTU 1340 → **1332**（每包多 12 字节 TS，总包 1417，与改造前 1413 持平）
- `rules.rs` 服务端匹配依据从 wscale 改回 IP ID 高字节（wscale 现在是真实值，不能再当指纹）
- 客户端 INPUT 规则改为 `--sport 8443` + IP ID（原来的 `--dport 伪源端口` 在 NAT 改写端口后计数为 0）
- 删除无人调用的 `handle_perfunctory_syn` 死代码

**实测（国内家宽 → 新加坡 ARM 1 核）：**

| 指标 | 改造前 | 改造后 |
|---|---|---|
| 报文带 TS 比例 | **0/120** | **120/120** |
| 数据阶段纯 ACK | 0 个 | 90/400 ≈ 22.5% |
| 窗口取值 | 恒 65535 | 32748~32768 波动 |
| SYN 选项 | 缺 TS、wscale 12 | `mss,sackOK,TS,nop,wscale 9` |
| FIN 拆除 | 无 | `Flags [F.]` + TS |
| 单流 200MB | 3/3 完整 | **3/3 完整**，15.4~16.5 MB/s |
| 8 流并发 | 184 Mbps | 160~174 Mbps（-8%，TS+纯ACK 的代价） |
| 服务端 CPU | 22~78%（波动大） | 74~78% |

代价说明：每个包多 12 字节头 + 22% 的纯 ACK 包，吞吐下降约 8%、CPU 上升。
这是伪装必须付的成本——「缺 TS」这个特征一旦被利用就是直接封禁。
改造后服务端 78% CPU 对应 174 Mbps，仍有余量。

## 2026-11-12 14:42 (北京时间)

### 修复 MTU 塌陷 + 三处背压/收尾 bug，单流 200MB 从「下到 6MB 就断」到 4/4 完整

浏览器测速后复盘日志，发现四个串联的 bug，都已修复并部署验证。

**1. 国际线路正常丢包被误判成路径 MTU 变小（`src/quic/config.rs`）**

日志里 `mtu` 从 1340 塌到 1200 后再没爬回来，丢包率随之飙到 21~51%。

根因在 quinn 的 `BlackHoleDetector`：`BLACK_HOLE_THRESHOLD = 3`，
只要连续 4 个「可疑丢包突发」（突发里所有包都大于 `min_mtu`，且之后没有
更大的包被 ACK），就判定路径 MTU 变小，把 `current_mtu` 直接打回
`min_mtu`（默认 1200）。国际线路丢包本来就是常态，这个启发式必然误判。
MTU 掉到 1200 后每包少装 140 字节有效载荷（-10.4%），包数增加 11.7%，
丢包概率进一步上升，形成恶性循环。

修复：`t.mtu_discovery_config(None)` + `t.min_mtu(1340)` 双保险。
我们的路径 MTU 是自己算出来的（5 字节记录头 + 12 nonce + 16 tag + 40 IP/TCP
= 1413），没有需要探测的变量，PMTUD 只会带来误判。
实测修复后 50 次采样全部 `mtu=1340`，`loss_pct=0`。

**2. `ReadableError::ClosedStream` 被当成「流卡死」，误杀目标连接**

`recv.read()` 返回 `Err(ClosedStream)` 只表示「流已不在接收表 / 已读空 / 已停止」，
这是 `Readable` 事件重复投递时的正常状态。但两端代码都把任何 `Err` 当成致命错误，
执行 `stop()` 并把 `to_tcp`/`to_write` 置空 —— 而 `to_tcp` 一断，出站任务立刻退出、
目标 TCP 连接被关闭，正在下载的流直接截断。

实测 curl 报 `transfer closed with 203699359 bytes remaining to read`，
200MB 单流只能下到 6~8MB。客户端日志里 21 次
`recv.read 失败，停止该流释放窗口` 全是误报。

修复：`ClosedStream` 什么都不做（等下一个 `Readable`）；
`IllegalOrderedRead` 只记日志；真正的 `ReadError::Reset` 走正常 EOF 路径。

**3. quinn 内部 `send_window` 是看不见的 16MB 缓冲**

`pending_bytes` 只统计我们自己暂存的数据，quinn 还有个按连接算的
`send_window`（原来固定 16MB）。目标是本地回环服务（几百 MB/s）时，
出站任务会先无声灌满这 16MB，再灌满 `pending`，最后触发
「pending 超过上限」保护把流 reset。这解释了为什么修完第 2 点后
截断点从 8MB 前移到 25MB —— 只是把缓冲加厚了。

修复三件事：
- `send_window` 改成 `max_cwnd × 2`（clamp 到 2~16MB），让它在写爆之前就返回
  `Blocked` / 部分写入；
- 新增 `write_blocked` 标志：`write()` 返回 `Blocked` 或只写进一部分就置位，
  出站任务与 `pending` 水位一起检查，`Writable` 事件到达时清除并 `notify`；
- `pending_bytes` 语义改为「从目标 socket 读出、但还没交给 QUIC 的全部字节」，
  把还在 `action_tx` 通道里排队的那段（1024×16KB≈16MB）也算进去。
  用 `fetch_update` + `saturating_sub` 防下溢（`reset_stream` 会清零计数器）。

**4. FIN 越过未写出的数据，末尾丢约 1MB**

`ServerAction::Fin` / `ProxyAction::Fin` 处理时先 `flush_pending` 再**无条件**
`finish()`。一旦 `pending` 还有残留（正好一个背压高水位 ≈1MB），
FIN 就跑到数据前面，客户端提前看到流结束：
`transfer closed with 1014706 bytes remaining`。

修复：新增 `fin_pending` 标志，`Fin` 只登记意图，
真正 `finish()` 由 `flush_pending` 在 `pending` 清空时执行。两端都改。

**实测（国内家宽 → 新加坡 ARM 1 核，服务端 busybox httpd 作纯净源）：**

| 指标 | 修复前 | 修复后 |
|---|---|---|
| 单流 200MB 完整下载 | **0/4**（断在 6~25MB） | **4/4 全成功** |
| 单流吞吐 | — | 15.8~16.9 MB/s（127~135 Mbps） |
| 8 流并发 | 146~199 Mbps（`mtu` 会塌到 1200） | 184 Mbps，`mtu` 恒 1340 |
| `mtu` 采样 | 73 次 `1200` + 106 次 `1340` | 50/50 全 `1340` |
| 客户端 `loss_pct` | 最高 51% | **0** |
| 客户端 `pending` | 74 MB | **0** |
| 客户端 WARN/ERROR | 21 条误报 | **0** |

> 遗留：curl 超时中断后，服务端要等满 30 秒背压兜底才放弃该流
> （客户端此时没有及时发 `STOP_SENDING`）。不影响正常请求，
> 已记录为待办。

## 2026-11-12 13:54 (北京时间)

### 高速率 CPU 打满与吞吐调研：定位到系统调用 + 自造 bufferbloat（100→190 Mbps，CPU 100%→22%）

背景：speedtest.net 下行只到 100 Mbps 且新加坡服务器 CPU 打满；同机 hysteria1
能跑 300+ Mbps，怀疑是加密栈问题。

**1. 加密结论：不是瓶颈，换算法救不了**

线上是 **2 层 AEAD**：

| 层 | 算法 | 实现 |
|---|---|---|
| 外层（伪装/鉴权） | ChaCha20-Poly1305 | RustCrypto 纯软件 |
| 内层（QUIC） | TLS 1.3 → AES-128-GCM | ring，ARM 走 `aes`+`pmull` 硬件指令 |

`openssl speed` 在 Neoverse-N1 上实测：AES-128-GCM **2404/2531 MB/s**，
ChaCha20-Poly1305 **796/818 MB/s**（AES-GCM 快 3.1 倍）。
但 100 Mbps 只有 12.5 MB/s，ChaCha 也只占 **1.6% CPU**，两层合计不到 5%。
→ hy1 只跑 1 层（QUIC 自带 TLS 1.3），per-packet 开销天然比我们少一半，
但这不是我们掉到 100 Mbps 的原因。

**2. 真正的瓶颈：每包一次系统调用**

压测时采样 `/proc/<pid>/stat`：`utime=52 / stime=166` ticks —— **76% 在核态**，
15260 pps 下每包约 83µs，几乎全在 `sendto`。

改动（`src/faketcp/socket.rs`、`packet.rs`、`codec.rs`、`client.rs`、`server.rs`）：
- 发送从 `IPPROTO_RAW + IP_HDRINCL` 换成 `AF_PACKET / SOCK_DGRAM` +
  `PACKET_QDISC_BYPASS`，跳过 IP 路由、netfilter、MTU 检查、qdisc（不可用时自动回退）。
  踩坑：`SOCK_DGRAM` 只让内核补以太网头，**不做 ARP**，必须自己从
  `/proc/net/arp` 取下一跳 MAC，否则包发成全零地址被网关静默丢弃
  （表现为客户端一直等 SYN-ACK）。
- `sendmmsg` 批量发送（32 包/次）+ `PacketBatch` 复用缓冲池，稳态零分配。
- `build_packet_into` / `seal_into` 去掉每包的 3~5 次 malloc 和 `pseudo` 临时 Vec。
- `poll_transmit(now, 32, buf)` 而非传 1：一次调用封好整批等长数据报
  （按 `segment_size` 切开逐包加外层记录），事件循环不再按包数空转。
- nonce 改递增计数器，不再每包 `rand::thread_rng()`。

**3. 背压设计错误（自造 bufferbloat）**

服务端 `pending` 一度堆到 **214MB**，随后 cwnd 从 8MB 崩到 1.2MB，吞吐掉回 81 Mbps：
- 水位取 `max_cwnd * 2` = 每流 16MB（12 流 192MB）→ 改成 `max_cwnd/4` 封顶 1MB。
- 等待用 `sleep(5ms)` 轮询 + 每次只读 16KB → 拥塞时吞吐死锁在 3MB/s，
  单流实测掉到 20 Mbps → 改成 `Notify` 事件驱动（`flush_pending` 归还字节即唤醒）。
- 溢出阈值低于「一轮动作批量能推进的量」（64×16KB=1MB）会误杀正常流 → 阈值改 8 倍，
  动作批量 256→64。
- `net.max_cwnd` 语义修正：之前只当初始值（丢包<5% 会 1.2 倍放大到 8MB），
  现在是真的硬上限。

**实测（国内家宽 → 新加坡 ARM 1 核，服务端 busybox httpd 作纯净源）：**

| 指标 | 优化前 | 优化后 |
|---|---|---|
| 8 流下行 | 100 Mbps（CPU 打满） | **174~196 Mbps** |
| 服务端 CPU | **100%** | **22%** |
| 客户端 CPU | — | 28% |
| `pending` 峰值 | 214 MB | ~18 MB |
| 单流长跑 | 125 Mbps | 87 Mbps（cwnd 只到 97KB，BBR 爬升偏慢，待优化） |

两端 CPU 都没饱和，瓶颈已经回到链路上（iperf3 UDP 同链路 274 Mbps / 4.8% 丢包）。
遗留项：单流 BBR 爬升偏慢、`stream_receive_window` 与单流吞吐的关系需要单独调。

## 2026-11-12 12:06 (北京时间)

### 服务端切到新加坡 ARM 千兆机（203.0.113.10）+ 全量重新部署
- 背景：客户端按新的 `deploy/client-cn.yaml` 指向 `203.0.113.10:8443` 后，
  日志一直停在 `已发送 SYN，等待 SYN-ACK`，30 秒内没有 `三次握手完成`。
- 排查：
  - 新机 ICMP 74ms 可达，8443 内核真网站 `HTTP 200`，`ip route get 8.8.8.8`
    显示源地址是内网 `10.0.0.10`（Oracle NAT），`faketcp.local_ip` 已正确写公网 IP。
  - 新机 raw 表规则正常（`u32 "0x4&0xff00ffff=0xf1004000"`），
    `server.log` 能看到 `收到 raw 包 client=... payload=125`，但同期
    `conns=0` —— 包收到了却没建连。
  - 对比源码 md5：`/opt/flowtls-src` 有 9 个文件与本地不一致
    （`client.rs`、`config.rs`、`faketcp/packet.rs`、`quic/capped.rs`、
    `server.rs` 等），二进制是 01:23 编的旧版本。**根因就是服务端代码没同步**。
- 部署（全部在服务器上原生 aarch64 编译）：
  - `tar | ssh` 推送 `src`、`Cargo.toml`、`Cargo.lock`、`web`（远端无 rsync）。
  - `cargo build --release` 1m02s，12 个 `never used` 警告，无 error。
  - 旧二进制备份为 `flowtls.bak.HHMM`，重启后 `LISTEN 0.0.0.0:8443`。
  - 本地客户端同步用最新源码重编 musl 静态版。
- 实测（国内家庭宽带 → 新加坡，SOCKS5 admin:abcd1234）：
  - `三次握手完成` → `QUIC 连接已建立` 用时约 0.2s，无重传。
  - `http://gstatic/204` 0.10s、`https://gstatic/204` 0.45s、`api.ipify` 200。
  - 出口 IP 确认 `203.0.113.10`。
  - 下载 20MB ×3：**7.6 / 7.9 MB/s**（约 61~63 Mbps），`cwnd` 爬满 8MB，
    `loss_pct=0`；服务端侧 `lost=3886`（0.6%），`rtt_ms=94`。
  - `rtt_ms` 由切机前的 333ms 降到 **92~95ms**。

## 2026-11-12 11:01 (北京时间)

### 修复客户端发送侧无背压（pending 峰值 125MB → 13MB）+ 日志可观测性
- 排查 8 小时长跑日志（北京时间 02:55~10:55，累计下行 2.6GB / 上行 1.3GB）：
  - 零断线、零重连、零 ERROR；RSS 客户端 11MB / 服务端 9MB，无内存泄漏。
  - 但客户端 `pending` 峰值 **125MB**、服务端 80MB，都出现在测速并发时。
- 根因：客户端 `ProxyAction` 用无界 mpsc，`pending` 是无上限 Vec，
  `pipe_stream` 读本地 socket 多快就往里塞多快，QUIC 写不下去时全部堆在内存。
  服务端早有 `pending_high_water` + 暂停读目标 socket 的背压，客户端一直缺这一层。
- 改动（`src/client.rs`、`src/proxy/http.rs`）：
  - `ProxyAction` 通道改 `mpsc::channel(1024)`（1024 × 16KB ≈ 16MB 上限）。
  - `ProxyClient::send` / `fin` 改 `async`，内部 `tx.send().await`；`open` 同样 await。
  - `pipe_stream` 的读取任务在 `send().await` 挂住 → 停止读本地 socket →
    对端 TCP 窗口收缩 → 浏览器/测速端自然降速，形成端到端背压。
  - `http.rs` 两处 `client.send(...)` 补 `.await`。
- 日志（`src/main.rs`、`src/client.rs`）：
  - `tracing` 关闭 ANSI 颜色码。之前字段被 `\033[3m..\033[0m` 包裹，
    `grep 'rtt_ms='` 一条都匹配不到，排查时只能肉眼翻几十 MB 日志。
  - `收到 QUIC 数据` 由 `info` 降为 `trace`：8 小时 44 万条、62MB，
    格式化 + 写 stdout 的开销在高速传输时不可忽略。
- 实测（香港 100M，部署后）：
  - 20MB 上传：`pending` 峰值 **13.6MB**（修复前 125MB），13MB 卡在 16MB 上限内，无 WARN。
  - 10MB 下载 ×2：3.05 / 3.80 MB/s；服务端 `pending` 峰值 2.2MB 后回落。
  - 客户端日志 **61 行 / 6.7KB**（修复前 62MB），`grep 'rtt_ms='` 正常命中。
  - 代理可用性：Google 204 / 0.44s。

## 2026-11-12 03:10 (北京时间)

### 文档全面校正（AGENTS / PROJECT_PLAN / DESIGN / DEPLOY_CREDENTIALS）
- 用户反馈部分 md 描述已过时。逐份核对当前代码后修正：
  - `AGENTS.md`：架构图里的「零等待」改为标准三次握手；补充 wscale=12 识别、背压、
    `capped.rs`、HTTPS 默认开启；更新吞吐数据（3.6MB/s、79/64 Mbps）与已知限制
    （必须直连公网 IP、443 不可用、quinn MAX_CHUNKS 约束）。
  - `PROJECT_PLAN.md`：状态更新到 v0.2.0；已完成项补齐标准握手、自适应窗口、自动重连、
    背压、wscale 识别、读取失败 stop、流表清理、HTTPS 默认；删除重复的旧章节。
  - `docs/DESIGN.md`：重写。包格式（MTU 1340）、伪包识别（wscale=12）、
    标准三次握手时序、iptables 新规则、流控与背压、读取失败处理、断线自愈、
    传输参数（4MB/16MB）全部按当前实现重写。
  - `DEPLOY_CREDENTIALS.md`：修正客户端实际指向（香港 100M）、HTTPS 默认入口、
    当前 source_port 44311、INPUT/OUTPUT 两条规则；服务端启动命令改为 setsid + stdbuf。
- 修正历史记录中的错误表述：香港是 100M 上下行，千兆机器是新加坡 ARM（但云 NAT 不可用）。

## 2026-11-12 03:00 (北京时间)

### HTTPS 入口默认开启，证书可自签或自定义
- 需求：SOCKS5 / HTTP / HTTPS 三个入口，HTTPS 默认就要开；证书默认自签，也允许指定。
- 改动：
  - `InboundFile` 新增可选 `cert` / `key`（PEM 路径）。
  - `proxy/http.rs::run_tls` 支持两种模式：配置了 cert/key 就加载用户的证书，
    否则运行时用 rcgen 生成自签证书（启动日志会标明用的是哪种）。
  - HTTPS 入口默认启动：未配置 `https` 时监听 `127.0.0.1:8443`（仅本机，安全），
    用户名密码沿用 `socks5` 配置；需要局域网访问或换证书时在配置里显式写 `https`。
  - CLI `--https` 只覆盖监听地址时，会保留配置文件里已有的 cert/key。
- 实测：
  - 启动日志：`HTTPS 入口已启动 addr=127.0.0.1:8443` + `HTTPS 入口使用自签证书`
  - 带鉴权：`curl -x https://admin:***@127.0.0.1:8443 --proxy-insecure` → **204 / 0.62s**
  - 不带鉴权：正确返回 **407 Proxy Authentication Required**
- 文档：`README.md` 与 `deploy.example/client.yaml` 补充三种入口用法。

## 2026-11-12 02:55 (北京时间)

### 完善 README 并推送仓库
- 重写 `README.md`：项目定位、架构图、7 项核心优势、快速开始、配置说明、实测数据、已知限制、项目结构。
- 新增 `.gitignore`：排除 `target/`、`ssl/`（证书私钥）、`deploy/`、`test/`、`DEPLOY_CREDENTIALS.md`、IDE 缓存与日志。
- 新增 `deploy.example/`：脱敏的服务端/客户端示例配置，README 可直接引用。
- 安全处理：将 `CHANGELOG` / `DEVTIPS` / `AGENTS` / `PROJECT_PLAN` / `docs/DESIGN` 中的
  服务器 IP、客户端出口 IP、内网地址全部替换为描述性占位（如“香港服务器”“客户端出口 IP”）；
  真实密码与证书仅保留在本地 `deploy/` 与 `ssl/`，不入库。
- 已推送到 `origin/main`（commit `3418ab9`）。

## 2026-11-12 02:48 (北京时间)

### 流表增加 5 分钟空闲清理（解决测速后流数残留）
- 现象：测速结束后客户端 `streams` 停在 44~52 不回落，`RSS` 从 28MB 涨到 117MB。
- 分析：
  - 流表只按「双向都结束」清理，而部分流双方都没发 FIN，会永久残留。
  - RSS 高主要是测速时 40~50 条并发流各自的接收缓冲，属于浏览器渲染慢导致的正常缓冲。
- 改动：
  - `StreamState` / `ServerStream` 新增 `last_active` 时间戳，读写活跃时更新。
  - 流表 `retain` 增加 5 分钟空闲超时：既未双向结束、又长时间无数据的僵尸流强制清理。
  - `to_local` 保持无界：改成有界会背压回 QUIC，但浏览器渲染慢时会直接中断正在加载的流，
    取舍不划算；RSS 在浏览结束、缓冲消费完后会自然回落。
- 部署后：google 204 / 0.44s，`streams=6 pending=0 rx_queue=0`。

## 2026-11-12 02:42 (北京时间)

### 复查测试日志：修复 stop 后重复触发与 pending 残留
- 日志检查发现：
  - 客户端同一毫秒内对 StreamId(544) 连续 9 次 `recv.read 失败`；服务端同样（`接收流已卡死` 重复 2~3 次）。
  - 客户端 `pending` 仍在 14.5MB → 3.9MB 之间波动。
- 根因：`recv_stream(id).stop(0)` 之后，quinn 仍会继续为该流投递 `Readable` 事件，
  每次回调都重新 `read` → 失败 → 再 `stop`，形成空转：浪费 CPU、刷日志，窗口释放不彻底。
- 修复：`StreamState` / `ServerStream` 新增 `stopped` 标志，读取失败并 stop 后置位，
  `read_stream` 开头直接忽略已停止的流，不再重复尝试。
- 部署后：google 204 / 0.44s，`pending=0 rx_queue=0`，日志无重复告警。
- 其余指标正常：自适应窗口在两端均按预期工作（上行 8MB、下行 1.5~5MB），无断连。

## 2026-11-12 02:36 (北京时间)

### 修复 recv.read 失败导致流控窗口泄漏（pending 20MB）
- 用户实测：FAST.com 下载 75 / 上传 65 Mbps，未崩溃；后台却发现客户端 `pending=20.3MB`。
- 定位：两端日志都有 `recv.read 失败，本轮回调跳过`。quinn 的 `Chunks` 会锁住流的
  组装器，一旦某次 `finalize` 未正常完成，该流的 `read(true)` 就会永久返回
  `IllegalOrderedRead`；此时静默跳过意味着数据不再被读、`MAX_STREAM_DATA` 永不发送，
  20MB 未确认数据就是这样堆出来的。
- 修复（两端）：读取失败时不再静默跳过，而是标记该流 `remote_finished` 并
  `recv_stream(id).stop(0)`，主动释放流控额度；该请求由上层重试，不再拖累整条连接。
  同时解决借用检查：`match recv.read(..) { .. };` 加尾分号让临时值提前析构。
- 部署后验证：google 204 / 0.44s，客户端 `pending=0 rx_queue=0 win_cap=8388608`。
- 当前自适应表现：客户端上行不丢（`loss_pct=0`）→ 窗口探到 8MB；
  服务端下行丢包 23~44% → 窗口收敛到 1.5MB 下限，不再触发空洞断连。

## 2026-11-12 02:28 (北京时间)

### 放宽自适应收敛力度（上轮实测上下行都有损失）
- 现象：上次测速不崩了，但下载 61.18 / 上传 22.59 Mbps（之前 76.52 / 75.94）。
- 分析：
  - 下载：服务端 `loss_pct` 在 13~26% 波动，自适应从 15% 阈值就持续 ×0.85，
    窗口被压到 2.1MB；同时 BBR 频繁进入 ProbeRTT（cwnd 瞬时掉到 12KB）。
  - 上传：客户端 `cwnd` 顶在 8MB、`loss_pct=0`（上行几乎不丢），
    瓶颈不在客户端发送侧，更可能是链路瞬时丢包或 speedtest 实测波动。
- 调整（两端同步）：
  - 收敛阈值 15% → **20%**，恢复阈值 3% → **5%**
  - 步长 0.85/1.15 → **0.90/1.20**（收敛更温和、恢复更快）
  - 窗口下限 1MB → **1.5MB**，安全系数 0.6 → **0.7**
  - 崩了仍有外层自动重连兜底（5s 退避）
- 验证：重启后 google 204 / 0.44s，客户端 `win_cap=8388608`（低丢包已探到 8MB）。
- 待用户再测确认上传是否恢复。

## 2026-11-12 02:24 (北京时间)

### 自适应窗口 + 断线自动恢复（零配置）
- 背景：每次服务器带宽/丢包不同，固定窗口要么跑不动要么崩；且崩溃后需要手动重启客户端。
  用户明确要求**不增加配置复杂度**，要全自动。
- 实现：
  1. **自适应窗口**：`CappedBbr.max_window` 改为 `Arc<AtomicU64>`，运行中可改。
     两端每 2 秒采样丢包率：>15% → 窗口 ×0.85，<3% → ×1.15。
     并用 quinn 硬限制反算安全上限：`safe = 1024 × 1308 / 丢包率 × 0.6`，
     再 clamp 到 1MB~8MB。低丢包时可探到 8MB，高丢包时自动降到 1~2MB。
  2. **断线自动恢复**：`run()` 拆为外层重连循环 + `run_session()` 单次会话；
     `drain_events` 返回断开标志；退避 5s → 10s → 20s → 40s → 60s 封顶。
     本地代理入口（1080/8080）只启动一次，通过 `ProxyClient` 的 `Mutex<Option<Sender>>` 重绑通道。
  3. **实时监测**：统计日志新增 `loss_pct`（本周期丢包率）和 `win_cap`（当前窗口上限），
     直接观察自适应收敛过程。
- 实测：重启服务端后，客户端 `TimedOut` → 退避 5s → 重新 SYN/握手，**5.3 秒全自动恢复**，
  google 204 / 0.53s。服务端日志显示 `loss_pct=0 win_cap=8388608`，低丢包时窗口已探到 8MB。
- 当前配置：stream 4MB / conn 16MB / send 16MB，`net.max_cwnd` 仅作为自适应初始值（4MB）。
  用户仍不需要填带宽，旧配置文件保持兼容。

## 2026-11-12 02:14 (北京时间)

### 定位「测速后必崩」：quinn MAX_CHUNKS=1024 硬限制，窗口降到 4MB
- 现象：每次 speedtest 跑到上下 70Mbps 后连接必断，客户端日志：
  `ConnectionClosed(INTERNAL_ERROR, reason=b"too many gaps in stream buffer")`。
- 根因：quinn-proto 的接收组装器（`connection/assembler.rs`）有硬编常量
  `MAX_CHUNKS = 1024`，即单流最多容忍 1024 个乱序空洞，**无法通过配置调整**。
  公式：`窗口 ÷ 包大小 × 丢包率 < 1024`。
  - 8MB 窗口 ≈ 6400 个在途包，丢包 30~50% → 1900~3200 个空洞，必超限
  - 4MB 窗口 ≈ 3200 个在途包，丢包 30% → 约 960 个空洞，安全
- 改动：
  - `stream_receive_window` 8MB → **4MB**，`receive_window` / `send_window` 32MB → **16MB**
  - `max_cwnd` 8MB → **4MB**（减少乱序，实测每降一档丢包都明显下降）
  - 保留 `ServerAction` 2048 / `to_tcp` 4096（用户观察正确，这两项无副作用）
- 容量核算：本链路 BDP = 70Mbps × 141ms ≈ 1.23MB，4MB 窗口是它的 3 倍，跑满 70Mbps 足够。
- 验证：重启后 google 204 / 0.47s，客户端 pending=0、rx_queue=0。
- 已告知用户自行测速验证；若仍触发则继续降到 3MB / 2.5MB。

## 2026-11-12 02:10 (北京时间)

### 参数上调至千兆以上；实测上下行各 70Mbps
- 按用户观察调整（`ServerAction` 256 项在 70Mbps 下只有 0.46 秒缓冲，确实偏小）：
  - `ServerAction` 256 → **2048**（约 32MB），`to_tcp` 1024 → **4096**（约 64MB）
  - QUIC 窗口：stream 8MB → **16MB**、connection 20MB → **64MB**、send 20MB → **64MB**
  - `max_cwnd` 默认 8MB → **16MB**（千兆 BDP ≈ 8.75MB 的 2 倍），背压水位改为 32MB
- 实测（香港 香港服务器，16MB 窗口）：
  - 单路下载 10MB：2.93 / **3.86** / 2.93 MB/s
  - 单路上传 10MB：3.52 / 3.75 MB/s，HTTP 200
  - 4 路并发下载：每路 1.56MB/s，合计 6.24MB/s（比 8MB 窗口的 6.86MB/s 略低）
  - **用户 speedtest：下载 69.50 Mbps / 上传 71.73 Mbps，上下行对称跑满**
- 结论：当前链路（实际约 50Mbps）上 16MB 与 8MB 速度基本持平，16MB 峰值略高、并发略低；
  保留 16MB 作为千兆默认值，小带宽机器可用 `net.max_cwnd` 覆盖。
- 遗留：服务端日志存在块缓冲，`>> server.log` 时可能滞后几分钟，排查时以客户端日志和抓包为准。

## 2026-11-12 01:58 (北京时间)

### 改为标准三次握手 + 用 TCP wscale 识别伪包，实测下载 70Mbps
- 触发原因：客户端换到江苏移动新网关（客户端出口 IP）后，FakeTCP 完全连不上。
  定位结论：该网关对 TCP 做严格状态检查——**只放行 SYN，SYN-ACK 之前的数据包全部丢弃**。
  旧网关（客户端旧出口 IP）允许「SYN + 数据同批发」，所以之前能跑 3MB/s。
- 另一个关键发现：**客户端 NAT 会把 IP ID 改写成 0x0000**，
  服务端原先靠 `ip_id == magic` 识别伪标志、靠 `u32` 规则阻止内核响应，在真实链路上完全失效。
- 改动：
  1. **标准三次握手**：客户端启动只发 SYN，收到 SYN-ACK 后才回 ACK、发伪 ClientHello 并放行 QUIC 数据；
     服务端收到 wscale=12 的 SYN 立即回 SYN-ACK（记录 ISN），`NewConnection` 时复用同一 ISN，不重复发。
     握手未完成时客户端不调 `drain_transmits`，避免产生任何握手前数据包。
  2. **识别特征从 IP ID 改成 TCP 窗口缩放因子（wscale=12）**：
     `parse_frame` 解析 TCP 选项；服务端 iptables 规则改为 `u32 "46&0xFFFFFFFF=0x03030C01"`；
     客户端 INPUT 规则改为按 `--sport 8443 --dport 44311` 五元组匹配。
  3. `to_tcp` 出站通道 128 → **1024**：7MB/s 上传时 128 项（2MB）几毫秒就满，会把正常流误杀。
- 验证（香港 香港服务器，千兆窗口 8MB）：
  - 服务端日志：`标准握手：已回 SYN-ACK` → `新的 QUIC 连接`，链路建立正常
  - 单路下载 10MB：2.97 / 3.02 / **3.60MB/s**（历史最好）
  - 单路上传 10MB：3.67 / 3.89MB/s，HTTP 200
  - 4 路并发下载：每路 1.71MB/s，合计 **6.86MB/s（55Mbps）**，全部完整
  - 用户 speedtest 实测：**下载 70Mbps**
- 延迟影响：握手只发生一次（客户端启动建立那条 QUIC 长连接时），
  所有 SOCKS5/HTTP/HTTPS 请求都在这条连接上开新流，不再握手；实测首字节仍为 0.43s。

## 2026-11-12 01:36 (北京时间)

### 香港服务器同步千兆配置；ARM 机器因云 NAT 不可用
- 香港 香港服务器 已更新到最新二进制并按千兆配置运行：
  - `deploy/server-hk.yaml` 删除 `max_cwnd`，使用默认 8MB（对齐 hysteria2）；
  - 包含 `pending_bytes` 背压、`join!` 双向搬运、建连清理旧连接、`Finished` 语义修正。
- 客户端 `deploy/client-cn.yaml` 同步改为 `max_cwnd: 8388608`。
- ARM 机器 新加坡 ARM 服务器 结论：**不可用**。该机器是内网 服务端内网地址 + 云 NAT，NAT 对 TCP 做状态检查，
  FakeTCP 的裸 SYN 和不等握手的数据包全部被丢（服务端抓不到任何 SYN，真实 TCP 正常）。
  已在 DEVTIPS 20 记录。另新增 `faketcp.local_ip` 配置项，支持 NAT 机器指定公网源 IP（但本例即便指定也过不了 NAT）。
- 副作用：对 ARM 的大量重传后，客户端出口出现临时封禁 —— 真实 TCP 正常，伪造包全丢。
  已在 DEVTIPS 21 记录，需要等封禁过期或更换出口 IP。已挂每 3 分钟自动探测 `/tmp/ban-check.log`。

## 2026-11-12 01:05 (北京时间)

### 按 hysteria2/quic-go 的阻塞写模型重做背压，修复下载中断与测速崩溃
- 现象：下载 10MB 只能传 49~500KB 就报 `transfer closed`；speedtest 多线并发必崩；服务端 `pending` 一度到 58MB。
- 根因（全部是实现问题，与 quinn-proto 无关）：
  1. `outbound` / `pipe_stream` 用 `tokio::select!`：任一方向结束就把另一方向 drop，客户端半关闭后目标数据没读完就发 FIN。hysteria2 用两个独立 `io.Copy`，任一方真正 EOF 才结束。
  2. `ServerAction` 是无界队列，`handle_action` 把数据塞进 `pending` 后立即返回，出站任务完全感知不到下游堵塞，目标数据单向堆积。quic-go 靠**阻塞式 `Stream.Write`** 天然背压，quinn-proto 的同步 `write()` 没有。
  3. 客户端重建连接后服务端不清理旧连接，同一五元组下 `conns=2`，旧连接带着 56 条流持续重传，和新连接抢 seq/ack。
  4. `StreamEvent::Finished` 被误当成「对端接收结束」，实际是「本地发送方向已被 ACK」，导致还在下载的流被误删并 stop。
- 修复：
  - `select!` → `join!`（服务端 outbound、客户端 pipe_stream）。
  - 新增每流 `pending_bytes` 原子计数 + 高水位轮询：`pending` 超过高水位就暂停读目标 socket，目标 TCP 窗口收缩，形成端到端背压；30 秒无缓解则放弃该流。
  - `ServerAction` 改有界 256 + `send().await`；建新连接时清理同客户端旧连接；修正 Finished/Stopped 语义。
  - 窗口恢复 hysteria2 千兆默认（stream 8MB / conn 20MB / send 20MB）；新增配置项 `net.max_cwnd`（默认 8MB，千兆直接可用），背压高水位 = 2×max_cwnd。
- 验证（当前 30Mbps 跨境链路，`max_cwnd: 1048576`）：
  - 单路下载 10MB ×3 全部完整：3.0MB/s / 24Mbps（之前峰值 2.57MB/s）。
  - 4 路并发下载各 10MB 全部完整：每路 940KB/s，合计 3.76MB/s。
  - 单路上传 10MB：3.58MB/s / 28.6Mbps，HTTP 200。
  - 服务端 `pending=0`、`rx_queue=0`、RSS 5~6MB，背压生效。
- 待用户实测：speedtest 多线并发上传/下载是否还会崩。监控：本地 `/tmp/mon-local.log`、服务端 `/tmp/mon-server.log`（每 2 秒）。

## 2026-11-12 00:42 (北京时间)

### 修复测速上传导致整条连接卡死（事件循环吞吐 + 有界队列）
- 现象：用户用 speedtest.net 测速，上传显示 0、下载 30M，随后代理完全不可用；两端 cwnd 顶满（客户端 949KB / 服务端 1MB），服务端发包降到 4 包/秒。
- 根因（与 QUIC 内核无关）：
  - `src/server.rs` / `src/client.rs` 主循环原来每轮 `recv()` 只处理 **1 个包**，收包 channel 还是 `unbounded`。speedtest 上传时包速率从几百/秒涨到几千/秒，队列迅速积压，QUIC ACK 延迟到秒级，客户端 PTO、上传归零，随后整条连接卡死。
  - 服务端流表从不清理，高并发（直播/测速）后每条流的 `pending` / `target_buf` 一直累积，RSS 曾到 77MB。
- 修复：
  - 两端收包 channel 改为**有界 8192**（`tokio::sync::mpsc::channel` + `blocking_send`）：突发时积压有上限，持续过载时收包线程阻塞，由内核 socket 缓冲兜底丢包，QUIC 重传，内存不再无限涨。
  - 两端主循环改为**批量处理**：每轮把队列里已到达的包一次消化，上限 256 个（`pkt_rx` 和 `action_rx` 都改）。
  - 服务端新增流表清理：`local_finished && remote_finished` 的流立即释放。
  - cwnd 上限从 1MB 降到 **512KB**（71ms RTT 下约 57Mbps，给 100M 端口留重传余量）。
- 验证：连接恢复后上传 10MB **4.6MB/s（37Mbps）/ 2.27s / HTTP 200**，证明「上传为 0」确实是崩溃症状而非链路问题；下载 1.47MB/s；服务端 RSS 6.3MB。
- 已知待调：512KB 窗口下服务端 RTT 从 68ms 抬到 200ms+（排队），说明实际链路能力约 30Mbps，窗口仍偏大；可以往下试 256KB，或加自动重连后逐步回调。
- 再次确认：本项目从未修改 quinn-proto 源码，Cargo.toml 用 crates.io 0.11.19，无 vendor/path 覆盖；`src/quic/capped.rs` 只是实现公开 `Controller` trait 的包装器。

## 2026-11-12 00:33 (北京时间)

### 修复「突然连不上」：BBR 窗口失控 + 窗口硬上限
- 现象：两端进程都在、QUIC 连接也活着（服务端持续回 ACK），但所有新请求无响应，10 秒超时。
- 定位过程与证据：
  - 客户端 lost=5，服务端 lost=202809/385779（52.6%），cwnd 卡在 17855959（17.8MB）。
  - 服务端 sent 只有 2~3 包/秒，只是 PTO 单包重传；服务端出站正常（google 204 / 131ms）。
  - 服务端 tcpdump 确认收到请求后会去连目标（1.1.1.1:53/443、8.8.8.8:443 均发出 SYN 并收到 SYN-ACK），但回程数据发不出去。
  - 结论：原生 BBR 在跨境高丢包链路上把 ACK 聚合误算成高带宽，cwnd 涨到 17.8MB（68ms RTT 下约 2Gbps 的 BDP），远超 100M 端口，自己把下行链路打爆。
- 修复：新增 `src/quic/capped.rs`，用 `CappedBbr` 包装 quinn-proto 原生 BBR，只把 `window()` 截断到上限，其余逻辑全部委托。
  - quinn 的 pacing 速率由 `window / RTT * 1.25` 推导，所以钳住窗口就同时限制了突发和持续发送速率，**没有修改 quinn 源码**。
  - 默认上限 1MB（68ms RTT 下约 117Mbps，覆盖 100M 端口），可用环境变量 `FLOWTLS_MAX_CWND`（字节）现场覆盖，不用重新编译。
- 验证：重启两端后 google 204 / 0.52s，10MB 下载 2.12MB/s；服务端 cwnd 192KB，不再无限膨胀。
- 运维注意：服务端日志用 `>> server.log` 重定向时是块缓冲，可能出现「日志停更但服务正常」，排查时以客户端日志和抓包为准。

## 2026-11-12 00:45 (北京时间)

### 443 端口测试与回退
- 按要求停掉 openresty（Docker 容器 1Panel-openresty-CIc2），flowtls 接管 443。
- 结果：客户端到 443 的伪造包全部发不出去。用独立 Python raw socket 测试确认：带 TCP 选项的 SYN（data_offset=8）在 443 目标上被客户端出口设备丢弃，8443 目标正常。
- 结论：443 是运营商/出口设备重点监控端口，对伪造 TCP 的检查比 8443 严格，TCP 伪装在 443 上反而不可用。这是纯 UDP 的 hysteria 没有的限制。
- 已回退：服务端 listen 8443、客户端 server 8443、旧 443 规则清理；openresty 容器已重启，443 网站恢复。
- 当前配置：quinn 原生 BBR，stream 8MB / connection 20MB（hysteria2 默认），WS shift 12，ack 单调，IP ID 0xF1xx 递增。实测 10MB 1.94MB/s，冒烟 204/0.5s。

## 2026-11-12 00:05 (北京时间)

### 恢复原生 BBR，按 hysteria2 参数调优
- 用户实测固定窗口并未更流畅，以实测为准删除 `src/quic/steady.rs`，恢复 quinn-proto 原生 BBR，不改内核源码。
- 参照 hysteria2 官方默认（v2.hysteria.network Full-Server-Config）：
  - `initStreamReceiveWindow` / `maxStreamReceiveWindow` = 8MB
  - `initConnReceiveWindow` / `maxConnReceiveWindow` = 20MB
  - `congestion.type = bbr`
  - MTU 探测开启（我们的 initial_mtu 取实测安全的 1340）
- FakeTLS 层继续修真实性：ack 字段只增不减（乱序时回退会被中间设备当非法包）；IP ID 从固定 0xF107 改为 0xF100-0xF1FF 递增，iptables 规则同步改为 `4&0xFF00FFFF=0xF1xx4000` 匹配。
- 实测 10MB 下载 2.57MB/s，为目前最好；重传率仍约 52%，但 WS/ack/IP ID 三个可疑点全部排除，确认是跨境链路对 8443 大流量的客观丢包。
- 发现服务端 443 被 openresty 占用，若要验证 443 的 QoS 需与 openresty 共享端口。

## 2026-11-11 23:55 (北京时间)

### 按实测恢复固定窗口控制器
- 用户实测：固定窗口版本看直播比原生 BBR 更流畅，以实测为准恢复。
- 窗口默认 1MB，可用环境变量 `FLOWTLS_CWND` 调整（单位字节，不用改代码）。
- 保留 FakeTLS 层的 WS 窗口缩放修复，两者叠加：单流 10MB 2.34MB/s，4 路并发总 3MB/s，重传率 23%，cwnd 稳定在 1MB 不漂移。
- 说明：固定窗口是通过 quinn-proto 公开的 `ControllerFactory` 接口替换策略，没有修改 quinn-proto 源码。

## 2026-11-11 23:50 (北京时间)

### 根因确认：FakeTLS 的 TCP 窗口缩放缺失，恢复 quinn 原生 BBR
- 对比实验：同一链路内核 TCP+TLS 下载 100MB 只有 265KB/s（30 秒超时只完成 8.7MB），FakeTLS 10MB 下载 2.2MB/s。FakeTLS 比内核 TCP 快约 8 倍，说明 QUIC/BBR 的重传能力正常，瓶颈不在 QUIC 源码。
- 真正的 FakeTLS 层 bug：SYN/SYN-ACK 没有带 TCP 窗口缩放（WS）选项，窗口字段固定 65535，而在途数据可达几百 KB，中间设备按 64KB 窗口校验后丢弃超窗包。
- 修复：SYN/SYN-ACK 携带 MSS 1460 + SACK permitted + WS shift 12（窗口 256MB），外观也更接近真实握手。
- 按要求删除自定义固定窗口控制器 src/quic/steady.rs，恢复 quinn-proto 原生 `congestion::BbrConfig`，未修改 quinn-proto 任何源码。
- 保留的 FakeTLS 层修复：WS 选项、IP ID 魔数分流、单轮发送上限 64 包、客户端 INPUT 规则、ACK 5ms。
- 网站新增静态文件支持（用于带宽对比测试），测试文件已清理。

## 2026-11-11 23:40 (北京时间)

### Twitch 直播卡顿二次优化
- 定位：Twitch 网页会同时开 40+ 条连接，全部复用一个 QUIC 连接。BBR 把 cwnd 撑到 15MB（BDP 的 5 倍），突发打满链路后重传率 50%，cwnd 在 94KB~15MB 间剧烈波动，视频分片下载时快时慢。
- 新增 `src/quic/steady.rs`：固定窗口控制器，丢包不减窗，只有持续拥塞才收缩 10%。
- 窗口选型实测：768KB 丢包 18%/单流 2.06MB/s；1MB 丢包 24%/单流 1.89MB/s；3MB 丢包 69%/单流 1.14MB/s。取 1MB。
- QUIC 载荷 MTU 从 1200 提到 1340（路径 MTU 实测 >= 1428），包数少 12%。
- tokio worker 从 1 提到 4，缓解 1 核服务器上 40+ 出站流的调度饥饿。
- 复测：10MB 1.89MB/s，4 路并发每路 835KB/s，cwnd 稳定在 1MB，网站探测 200。

## 2026-11-11 23:30 (北京时间)

### 直播卡顿排查与优化
- 现象：看直播偶尔卡顿重载。双端日志显示 QUIC 连接全程未断（只有一次建立记录），无 OOM，服务端 CPU 5%、内存 12MB。
- 定位：ICMP 0% 丢包、RTT 79ms；但服务端 QUIC lost 比例约 55%，cwnd 在 134KB~4.2MB 间剧烈波动，属于跨境链路对突发流量的丢包 + PTO 误判。
- 优化 1：客户端新增 INPUT 规则，直接 DROP 服务端魔数包，消除内核对每个包回 RST（此前累计 70 万个出向丢弃）。
- 优化 2：通过 ACK Frequency 扩展把对端 ACK 延迟从默认 25ms 降到 5ms，降低 RTT 和 PTO 误判。
- 优化 3：`drain_transmits` 每轮最多发 64 个包，避免一次排空上千包时入向 ACK 积压。
- 优化 4：客户端 `net.mode: auto` 自动安装上述两条规则，重启不再丢失。
- 复测：10MB 下载 1.0MB/s，Google 204/0.55s，连接稳定。

## 2026-11-11 23:10 (北京时间)

### 新增
- 完成 FlowTLS v0.1.0：FakeTCP（raw socket 手工 IP/TCP 头）+ quinn-proto QUIC 内核。
- 伪 TLS 记录外观：`17 03 03` + 12B nonce + ChaCha20-Poly1305(QUIC 数据报)。
- 外层 AEAD 由密码 HKDF 派生，解密成功即鉴权，失败静默丢弃。
- 裸 SYN + 伪 ClientHello + 首个 QUIC 加密包同批发出，不等待 SYN-ACK。
- 象征性三次握手：SYN-ACK seq 与后续数据 seq 连续，客户端回 ACK，保证 NAT/conntrack 进入 ESTABLISHED。
- 同端口内核 TCP 真证书网站（rustls + HTTP/1.1 + 内置 Lumen Edge 页面）。
- SOCKS5（RFC1928/1929）、HTTP（CONNECT + 普通请求 + Basic）、HTTPS 本地入口。
- iptables 规则自动检测/安装，`net.mode: auto|none` 可关。
- QUIC 使用 BBR 拥塞控制，10MB 下载实测 1.6MB/s。

### 修复
- `poll_transmit` 输出缓冲区未 clear 导致无限增长、CPU 100% 空转。
- raw 层对所有 SYN 回 SYN-ACK，与内核真 SYN-ACK 冲突，导致真网站 TLS 握手失败；改为只处理带 IP ID 魔数的 SYN。
- iptables u32 表达式取错位（`4&0xFFFF` 取到 Flags/Frag），规则从未命中；改为 `4&0xFFFF0000`。
- raw 表 conntrack INVALID 规则误伤正常 SYN，删除该规则，只用 IP ID 魔数匹配。
- 服务端用收包目标 IP 作为回包源 IP，支持多网卡/回环。
- HTTP Basic 认证对 Base64 值误做小写化，导致 407；改为只对头名大小写不敏感。
- `pipe_stream` 改为泛型，兼容 tokio-rustls 的 TLS 流。

### 测试
- 本机：SOCKS5 / HTTP / HTTPS 入口全部 200。
- 香港 香港服务器:8443 → 国内 客户端内网地址：
  - 官网探测 200（10174 字节，Lumen Edge 页面）。
  - Google 204 / 0.55s，GitHub 200 / 525KB / 1.8s，YouTube 200 / 869KB / 2.5s。
  - 10MB 测速 1.6MB/s。
  - 错误密码被 SOCKS5 拒绝。
