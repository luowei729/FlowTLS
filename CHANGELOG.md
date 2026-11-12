# CHANGELOG

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
