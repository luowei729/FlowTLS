# PROJECT_PLAN

## 当前状态（2026-11-13 12:37 北京时间）

### 定位调整（用户决策）

**FlowTLS 的权威实现改为 Go 独立协议库** `github.com/luowei729/flowtls`，
与 hysteria2 / anytls 平级。**Rust 版后续冻结**，只保留两个职责：

1. 互通门禁的「另一个独立实现」（防止自测全绿、上线全挂）
2. 生产环境的回滚版本（新加坡机当前跑的是 Rust）

策略是「先开发，后冻结」：Go 侧 P3~P4 开发期间 Rust 不动；
Go 通过全部互通与压测后再冻结 Rust。

### 里程碑

| 阶段 | 内容 | 状态 |
|---|---|---|
| P0 | subtree + 补丁 + stub 注册 + Makefile | ✅ |
| P1 | `flowtls/` 主包：packet/codec/socket/session | ✅ |
| P2 | `quic/` 子包 + Go 客户端打通 Rust 服务端 | ✅ |
| **P3** | **UDP（QUIC DATAGRAM）+ 多会话路由** | ✅ |
| P4 | `listener.go`（服务端 Accept）+ `protocol/flowtls/` 适配层 | 待办 |
| P5 | 打包、CI 互通矩阵、配置迁移文档、冻结 Rust | 待办 |

### P3 实测（Rust 服务端）

| 用例 | 结果 |
|---|---|
| 单会话 5 轮 DNS | PASS，61 字节回程，109ms |
| 4 并发会话 × 3 轮 | PASS，9ms |
| 多目标（8.8.8.8 / 1.1.1.1） | PASS |
| 服务端 session 复用 | 日志确认 `session=0` |
| TCP 回归 | 小包 + 4 流 × 5MB，0 背压 |

**P3 的设计要点**（与 hysteria2 不同）：上行每包带目标地址，服务端完全无状态，
客户端重连后第一个包就能自愈。副作用是 Go 的 `net.PacketConn` 语义更自然——
一个 session 可以同时发往多个目标。

**踩到的坑**：`quic.Conn.ReceiveDatagram` 是单消费者语义，只能有一个分发
协程按 session 路由，不能让每个 `udpConn` 自己去读（会互相抢包）。
投递到会话通道时必须允许丢弃，否则一条慢会话会拖死整条连接的所有流。

### P4 起点

`flowtls/listener.go` 是本项目最后一个大件：服务端要按四元组分流、
自己做三次握手、**每客户端一个 Session + 一个 quic.Transport**
（这点与 hy2 不同，因为伪造 TCP 的 seq/ack 空间是每连接独立的）。

---

## 上一阶段状态（2026-11-13 12:25 北京时间）

### P2 实测（Rust 服务端，本机）

| 用例 | Rust 基线 | Go |
|---|---|---|
| 小包 928B | — | PASS，rtt 4.2ms |
| 单流 40MB | 18.7s / 2.14 MB/s | 18.5s / **2.16 MB/s** |
| 单连接 4 流 × 10MB | — | 19.2s / 1.99 MB/s，0 背压 |
| 多用户 alice/bob | — | PASS，服务端正确识别 |
| 错误密码 | — | 10.5s 明确失败 |

**协议层已与 Rust 等价，单流性能 1:1。** 剩下的差距在 QUIC 集成层，
本轮已修掉 5 个真实 bug（详见 DEVTIPS 64~68）：

1. `deliver` 静默丢包 → 改为阻塞投递（QUIC 认为包已送达，永不重传）
2. 队列容量 10.7MB < 连接级窗口 15MB → 提到 21.9MB
3. quic-go 剥离 ctx 取消 → 自建 `dialWithTimeout`
4. `Close` 顺序导致进程不退出（exit=124）
5. `SetReadDeadline` 空实现 → quic-go 永不知超时

### P3 起点

`flowtls/quic` 加 `ListenPacket`；服务端方向仍用 Rust，
先验证 Go 客户端 UDP 能通（DNS 查询）。

---

## 上一阶段状态（2026-11-13 11:29 北京时间）

### Go P1 完成：`flowtls/` 传输层移植 + 双向互通门禁

| 阶段 | 内容 | 状态 |
|---|---|---|
| P0 | subtree + 补丁 + stub 注册 + Makefile | ✅ |
| **P1** | **`flowtls/` 主包：packet/codec/socket/session + 单测** | ✅ |
| P2 | `quic/` 子包 + `protocol/flowtls/outbound.go` | 待办 |
| P3 | UDP（udpnat2 + session 映射） | 待办 |
| P4 | `Listener.Accept` + inbound 适配 | 待办 |
| P5 | 打包脚本、CI 互通矩阵、配置迁移文档 | 待办 |

**P1 产出**：`packet.go`（报文/校验和/时钟/窗口）、`codec.go`（v2 记录 +
AEAD + 多用户表）、`socket_linux.go`/`socket_stub.go`、`session.go`
（`net.PacketConn` + 三次握手）。

**关键验证（这是 P1 真正的价值）**：Rust 与 Go 各自 17/25 个单测全绿，
但真正的结论来自**交换真实字节**：

- authID 派生：三个密码两端**逐字节一致**
- Rust 加密 → Go 解密：通过
- Go 加密 → Rust 解密：通过
- 固化为 `bash docs/interop_check.sh`

**依赖教训**：x/sys/unix 的当前版本符号缺失且把 go 指令顶到 1.26（sing-box
是 1.25.5），已改用标准库 `syscall`；`SendBatch` 暂时退化循环 sendto，
批量优化留到性能阶段。

**P2 起点**：`flowtls/quic/service.go` 用 `quic.Transport{Conn: session}`
直接接单条 Session，先做客户端 outbound（能打通 Rust 服务端即可验证线路）。

---

## 上一阶段状态（2026-11-13 11:20 北京时间）

### wire format v2：多用户鉴权（已完成并联调通过）

用户决策：开发阶段无兼容包袱，直接切 v2；需要多用户。
版本位的加入理由：既然反正要改格式，1 字节成本换来「将来可协商」。

**格式**：首包 `ver(1)+authID(16)+nonce(12)+密文`，后续包只有 `nonce+密文`；
AAD 首包 `ver|authID`、后续 `ver`。authID 与 AEAD 密钥用不同 HKDF info 派生。

**配置**：`users: [{name, password}]`（name 仅日志，与 sing-box 惯例一致），
`users` 为空时退回顶层 `password` 单用户模式。

**联调结果**（本机，全部通过）：alice/bob 双用户并发 TCP 各 20MB 完整下载、
双用户 UDP 全套（DNS/会话复用/不可达目标）、错误密码被拒、服务端日志正确
区分 user、解密失败 0 次、单用户老配置兼容、`cargo test` 23 passed。

**关键教训**：首包头不能用「只发一次」的 swap 写法——QUIC Initial 重传时
会发不带首包头的包，服务端无法鉴权，且只在真实丢包时复现（DEVTIPS 59）。

**待办**：`docs/DESIGN.md` 已更新；`AGENTS.md` 与 `README.md` 里仍有
过时的 `wscale=12` 描述（实际已是 wscale 9 + IP ID 高字节标记），
属于既有技术债，与本轮改动无关，后续单独修。

---

### 新增方向：sing-box 协议库 + rev 发行版（P0 已完成）

用户决策：把 FlowTLS 做成「与 hysteria2 / anytls 平级的独立协议库」，
并在本仓单独发行一个带 flowtls 的 sing-box 构建。

**已落地（P0）**：

| 项 | 内容 |
|---|---|
| 上游基线 | `git subtree` 引入 sing-box **v1.14.4** 到 `sing-box/` |
| 版本号 | `1.14.4-rev.1`（合法 semver，二进制名保持 `sing-box`） |
| 上游补丁 | **2 文件 7 行**（`constant/proxy.go` +3、`include/registry.go` +4） |
| 独立模块 | `flowtls/`（不 import sing-box，仅 doc/config/errors 骨架） |
| 适配层 | `sing-box/protocol/flowtls/`（P0 只做参数校验） |
| 构建 | `make build` → `dist/sing-box-1.14.4-rev.1-linux-amd64`（78MB） |
| 设计文档 | `docs/SINGBOX_INTEGRATION.md` |

验收通过：`version` 显示 `1.14.4-rev.1` + `with_flowtls`；
`check` 对 flowtls 配置给出明确「未实现」；不带 tag 的构建给出「未编入」；
常规 mixed 配置 `check` 仍 PASS；`check` 不需要 root。

**后续里程碑**：

| 阶段 | 内容 | 估时 |
|---|---|---|
| P1 | `flowtls/` 主包：packet/socket/codec/session/listener + 单测 | 8~10 天 |
| P2 | `quic/` 子包 + outbound 适配，TCP 打通 Rust 服务端 | 5~7 天 |
| P3 | UDP（udpnat2 + session 映射），dig 通 | 5~7 天 |
| P4 | inbound 适配 + 与 Rust 客户端互通 | 5~7 天 |
| P5 | 打包脚本、CI 互通矩阵、配置迁移文档 | 5 天 |

P2 是分水岭：Go 客户端跑通 Rust 服务端的 `curl` + `dig`，才能证明线路兼容。

**待决策**：① wire format 是否加版本位（建议 P2 之前定）；
② 是否支持多用户（影响 `session.go` 密钥结构）；③ `REV` 是否自动递增。

**注**：Rust 版继续作为生产可用版本与互通基准，Go 重写期间两者并行。

---

## 上一阶段状态（2026-11-13 00:15 北京时间）

v0.2.0：在 v0.1.0 基础上完成稳定性与自适应优化，已通过跨境实测（100M 端口 79/64 Mbps）。

**生产服务端已切到新加坡 ARM 千兆机 `203.0.113.10:8443`**（2026-11-12 12:06 全量重编部署）。
国内家宽实测：单流 200MB **3/3 完整下载**（15.4~16.5 MB/s），8 流 160~174 Mbps，
`mtu` 恒 1332、`loss_pct=0`。香港 `203.0.113.12` 保留为备用。

**2026-11-12 15:23 完成伪装改造**：TCP 层已与真实 HTTPS 对齐——
时间戳选项覆盖 100%（改造前 0%）、数据阶段纯 ACK 22.5%（改造前 0）、
窗口动态变化、wscale 9、有 FIN 拆除。代价是吞吐 -8%、CPU 上升。

**2026-11-12 16:09 补齐客户端背压**：上传方向 `pending` 峰值 78MB → **1.06MB**；
中断后不再干等 30 秒（补 `STOP_SENDING` + 服务端 `abandon` 标志）。
双向实测：下载 200MB 2/2 完整（16.0~16.3 MB/s），上传 100MB ≈ 99 Mbps，
8 流 163 Mbps（服务端 68%），两端 WARN 归零。

**2026-11-12 16:42 分流标记改为配置派生**：之前 `ip_id_magic` 配置项根本没生效
（代码写死 `0xF100`），所有部署的特征完全相同。现全链路从配置派生，
当前值 `0x1E07`（IP ID 表现为 `0x1Exx`）；已验证换值后清理旧规则仍正常。

**2026-11-12 17:13 新增 `flowtls check` + 窗口上限 8MB**：把「两端不一致导致
静默失效」的坑变成显式检查（password / magic / 端口 / 证书真实可解析 /
iptables 规则 / 退出码语义）；`max_cwnd` 4MB→8MB，单流 109→136 Mbps（+25%），
8 流 164→175 Mbps，长跑 0 告警 0 空洞错误。单元测试 14 个，编译零告警。

**2026-11-12 21:05 新增 UDP 代理**：之前完全不通（SOCKS5 只认 CONNECT、
服务端只有 `TcpStream::connect`、QUIC 没开 DATAGRAM 扩展）。现在用
QUIC DATAGRAM（RFC 9221）承载，**完全对齐 hysteria2：不重传、不保序、
队列满即丢、超 MTU 即丢**，不做任何应用层分片。入口是 SOCKS5
`UDP ASSOCIATE`（RFC 1928 CMD=3）。实测 DNS 往返 61~64 字节 / RTT 84ms，
连续 20 查询 18~20/20（跨境链路 5~10% 丢包属正常），6 轮完整测试全通过，
TCP 无回归（204 = 0.18s，单流 80~89 Mbps）。单元测试 20 个。

**2026-11-12 21:55 全量代码审查**：逐文件审完 7736 行，修掉 11 个缺陷。
两个 P0/P1 都是实测复现的：
① **客户端 SYN 只发一次 + 握手阶段无超时兜底** → SYN 或 SYN-ACK 丢一次就永久卡死
（实测 2 分 43 秒，手工重启才恢复）。现按 1/2/4/8 秒重传，15 秒放弃交给外层重连；
② **UDP 死会话永久黑洞** → 出站任务退出后条目残留且被上行包续命，
`udp_sessions` 永停在 1，那条 (peer, target) 从此发不出去。
其余：ServerHello 长度错位导致 TCP 序号偏移、TSval 握手阶段可回退、
SNI 使用裸 IP、HTTP 普通请求路径缺 FIN/STOP、重连退避永不重置、
跨会话陈旧 stop 误杀新流（已用 epoch 隔离）、UDP relay 未校验来源 IP。
验证：单元测试 20/20，UDP 端到端 5/5，TCP 无回归。

**2026-11-12 23:40 延迟排查结论：没有回归**。用 git 旧版二进制（d887793）
建独立通道做对照，最终数据：

| 测试项 | 当前版本 | 旧版本（对照） | 理论值 |
|---|---|---|---|
| 纯隧道（无 DNS 无 TLS） | **p50 81~82ms** | 78~79ms | 1 RTT = 76.6ms |
| 204 HTTPS | p50 172~174ms | — | 2 RTT = 153ms |
| ICMP 链路 | 74.0 / 74.9 / 76.2（mdev 0.48） | — | — |

差距 3ms 在噪声内，**当前实现已到物理下限**。
用户看到的 200ms 是 TLS(1 RTT) + HTTP(1 RTT) 的必然结果，不是性能问题。
晚高峰 15~20% 丢包把 p90 从 81ms 拉到 246ms（每丢一包 +1 RTT），
属链路属性。

排查中排除了三个假设（均有数据）：`max_cwnd` 过大（降到 2MB 反而更差）、
目标连接耗时（4~10ms）、DATAGRAM 扩展（开/关均 80ms）。
新增 `docs/bench.sh` 三层延迟体检脚本与 `FLOWTLS_NO_DATAGRAM` 二分开关。

**2026-11-13 00:15 版本收敛**：两端统一到最新版，清理全部旧版本残留。
修复两个实际问题：① 客户端 1080 端口带着 `FLOWTLS_NO_DATAGRAM=1`
（实验残留）导致 **UDP 静默失效**；② 服务端 `max_cwnd` 漂移成 2MB
（实验后未同步回退）。清理：服务端 25 个旧备份 → 1 个回滚点，
本地 `target/` 2.1GB → 8.3MB。验证可复现构建（重编后 md5 与运行进程一致）。
最终：UDP 20/20，纯隧道 80/81/82ms，两端进程各 1 个、环境变量干净、
配置完全一致。

## 已完成

### v0.3.0 代码审查（2026-11-12）

- [x] **SYN 重传 + 握手超时**：1/2/4/8 秒退避，15 秒放弃；服务端对重传 SYN
      复用原 ISN/TSval（P0，原先会永久卡死）
- [x] **UDP 死会话回收**：区分 `Closed`/`Full`，只在投递成功时刷活跃时间
      （P1，原先 (peer,target) 会变永久黑洞）
- [x] **ServerHello 长度与 data_seq 对齐**：不再因随机长度导致 TCP 序号偏移
- [x] **TSval 整条连接单调**：`TcpClock::new_at`，首包不再 TSecr=0
- [x] **SNI 为 IP 时省略扩展**（RFC 6066）
- [x] **跨会话 epoch 隔离**：陈旧 `Stop` 不再误杀同号新流
- [x] **HTTP 普通请求补 FIN/STOP**，不再泄漏流
- [x] **重连退避可重置**（会话 >60s 则回到 5s）
- [x] **UDP relay 只接受控制连接同源 IP**（安全）
- [x] `find_by_client` 不再回退到无关连接

### v0.1.0 基础能力

- [x] Cargo 工程、CLI、YAML 配置、日志
- [x] FakeTCP：IP/TCP 头构造、校验和、AF_PACKET 收 / IPPROTO_RAW 发
- [x] 伪 TLS 记录 + HKDF + ChaCha20-Poly1305 外层鉴权
- [x] quinn-proto 0.11.19 单连接多流 + BBR
- [x] SOCKS5（用户名密码）、HTTP（CONNECT/普通请求/Basic）、HTTPS 本地入口
- [x] 同端口内核 TCP 真证书网站 + 内置 HTML
- [x] iptables 规则自动安装（net.mode auto/none）
- [x] 单元测试、本机联调、跨境联调、错误密码拒绝

### v0.2.0 稳定性优化

- [x] **标准三次握手**：严格 NAT 只放行 SYN-ACK 之后的数据，零等待版本已废弃
- [x] **伪包识别改用 wscale=12**：NAT 会把 IP ID 改写为 0，旧魔数分流失效
- [x] **自适应窗口**：按丢包率 1.5~8MB 自动调整，零配置
- [x] **断线自动重连**：5s→60s 指数退避，实测 5.3 秒恢复
- [x] **端到端背压**：pending 字节高水位，避免目标数据无限堆积
- [x] **quinn 空洞上限规避**：按 MAX_CHUNKS 反算安全窗口
- [x] **读取失败 stop + 去重**：避免窗口泄漏与 CPU 空转
- [x] **流表 5 分钟空闲清理**：解决测速后流数残留
- [x] **HTTPS 入口默认开启**：证书自签或自定义，鉴权沿用 SOCKS5
- [x] 批量收包（256/轮）、有界通道、`join!` 双向搬运
- [x] `faketcp.local_ip`：支持 NAT 机器指定公网源 IP
- [x] **云 NAT 机器恢复可用**：Oracle 新加坡机靠 `local_ip` 显式指定公网源地址，FakeTCP 已跑通
- [x] **发送路径零系统调用瓶颈**：AF_PACKET + QDISC_BYPASS + sendmmsg + GSO 批量取包，
      服务端 CPU 从 100%（@100Mbps）降到 22%（@190Mbps）
- [x] **背压模型修正**：水位绑 BDP、Notify 事件驱动等待，消除自造 bufferbloat（pending 214MB→18MB）
- [x] **关闭 PMTUD**：跨境丢包会触发 quinn 黑洞检测，把 MTU 永久塌到 1200
- [x] **收尾三连修复**：`ReadableError::ClosedStream` 不再误杀流、
      `send_window`/channel 在途数据计入背压、`finish()` 延到 pending 清空后
      （单流 200MB 从「下到 6MB 就断」到 4/4 完整）
- [x] **伪装改造**：补 TCP 时间戳选项、延迟确认纯 ACK、窗口动态化、
      wscale 12→9、补 FIN 拆除、SYN 选项逐字节对齐真实 Linux
- [x] **客户端上传背压**：`inflight` 水位含通道在途 + pending，只按 quinn 实际接收量退账
- [x] **中断即时释放**：客户端发 `STOP_SENDING`/`RESET`，服务端 `abandon` 标志唤醒等待协程
- [x] **分流标记配置化**：`ip_id_magic` 真正生效，换值即可换特征；
      iptables u32 右值带 `0x` 前缀（否则规则静默失效）
- [x] **日志级别修正**：对端主动停止流属于正常路径，从 warn 降为 debug
- [x] **TLS 层伪装**：ClientHello 重建为真实结构（key_share / early_data /
      17 个扩展 / GREASE / padding）；CCS 后改用 0x17 加密记录
- [x] **`flowtls check` 子命令**：两端一致性 / 证书真实解析 / 规则检查 /
      退出码 0|1；同时修掉 `install-rules` 硬编码 `0xF107` 的遗留 bug
- [x] **窗口上限 8MB**：单流 109→136 Mbps，长跑验证无空洞断连
- [x] **UDP 代理（QUIC DATAGRAM）**：SOCKS5 `UDP ASSOCIATE` 入口，
      **不重传、不保序、队列满即丢、超 MTU 即丢**（对齐 hysteria2），
      会话空闲超时回收；TCP 无回归

## 待办（按优先级）

1. [ ] **跨境链路丢包（晚高峰 15~20%）**：这是当前唯一实质性的体验瓶颈。
      每丢一包 = 多等 1 RTT。可选方向：换更稳定的线路、或加 FEC
2. [ ] **IP ID 标记的残留特征**（低优先级，见下方「设计权衡」）
2. [ ] 真 GSO：当前 `sendmmsg` 每包仍是独立 skb，可试 `PACKET_VNET_HDR`
3. [ ] 载荷长度分布：满包固定 1365 字节，真实 TCP 批量传输也以满 MSS 为主，
       优先级较低（已确认不是明显特征）
4. [ ] 热路径内存复用：`handle_incoming` / `handle_packet` 每包
       `Vec::with_capacity(2048)`，`parse_records` 每包一个 Vec，
       `Obfs::open` 每记录一次分配（CPU 目前不是瓶颈，收益有限）
5. [ ] 可选：QUIC 0-RTT 会话复用，降低重连延迟
6. [ ] 可选：多用户（users map）与服务端用户隔离
7. [ ] 可选：伪装网站反向代理真实站点
8. [ ] 可选：FEC 前向纠错，减少高丢包下的重传
9. [ ] 可选：UDP 会话上的「域名目标」不做 DNS 缓存，高频场景可加（当前每次
       新建会话都会 `lookup_host`，DNS 场景会话复用后不受影响）

## 已知问题

- 跨境链路丢包 20%~44%，BBR 靠重传硬跑，仍有带宽浪费。
- **UDP 不做重传也不做应用层分片**：这是刻意选择（UDP 语义 + 对齐 hy2）。
  后果有两个：① 大于约 1200 字节的 UDP 报文会被丢弃（DNS/游戏/QUIC 都够）；
  ② 5~10% 的包会丢，依赖应用层自己重试（DNS 解析器、WebRTC 都有）。
- 服务端 1 核，outbound 任务与事件循环共享 worker，重负载下 RTT 抖动。
- 云主机在 NAT 后面时必须显式配 `faketcp.local_ip` 为公网地址，否则客户端会丢包
  （路由探测只能拿到内网 10.x）。已在新加坡机上验证可用。
- 单流 136 Mbps / 8 流 175 Mbps，同链路 iperf3 UDP 上限约 274 Mbps，还有空间；
  瓶颈已从 CPU（改造后 8 流只用 77%）转到单连接 pacing 收敛与链路本身。
- 同机 hysteria1 能跑 300+ Mbps：它只有 1 层 AEAD（QUIC 自带 TLS1.3）
  且用 UDP + GSO；我们 2 层（外层 ChaCha20 + 内层 AES-GCM）合计仅 5% CPU，
  差距不在加密，而在单流拥塞控制与是否用真 GSO。
- CloudFlare Origin 证书浏览器不信任，仅适合代理伪装；生产建议换 Let's Encrypt 或商业证书。

## 设计权衡：IP ID 分流标记无法做到完全隐蔽

这是当前唯一残留的**可自动化识别**特征，记录清楚为什么没「修掉」。

**为什么必须有标记**：服务端同一端口 8443 上跑着真网站（抗主动探测），
而伪包必须在内核 TCP 栈之前被 DROP，否则内核会回 RST/SYN-ACK。
iptables 需要一个**静态可匹配**的字段。
TCP 选项（TS / wscale）在伪装改造后必须与真实 Linux 一致，不能再当指纹，
所以只剩 IP ID 可用。

**为什么不能完全隐蔽**：任何静态字段都是可统计的。
IP ID 高字节固定 → 长连接的 IP ID 只落在 256 个连续值里，
统计直方图一眼可见；而真实协议栈是 16 位单调递增，覆盖全范围。
换成低 8 位或别的字节只是换个位置，本质相同。

**两个能彻底解决的方案**（都需要额外资源，暂未实施）：

1. **给隧道单独一个 IP**（推荐，零协议改动）：
   客户端连 `tunnel.example.com`（独立公网 IP），iptables 用
   `-d <tunnel_ip>` 匹配，IP ID 恢复成完整的 16 位递增，特征彻底消失。
   要求机器有两个公网 IP —— 当前 Oracle 实例只有一个，所以没做。
2. **动态规则**：静态规则只匹配 SYN（把口令派生的 tag 放进 SYN 的 ISN 低位，
   ISN 本身在真实 TCP 里就是随机的，不可检测），进程看到 SYN 后
   按 `(客户端 IP, NAT 后源端口)` 插入临时规则，连接结束时删除。
   代价：每条连接都要改 iptables、有规则泄漏风险、依赖 `NFQUEUE`/时序配合。

**当前风险评级：低**。可检测，但需要观测方对单条连接采集上千个包的 IP ID
并做分布分析；不是「一条规则就能判定」的等级（对比：缺 TCP 时间戳、
ClientHello 无 key_share 都是秒级可判）。已在 `flowtls check` 里对
「使用编译默认 magic 值」给出警告，避免所有部署共用同一特征。

---

## 2026-11-13 13:30（北京时间）更新：P4 完成

### 已完成

| 项 | 状态 |
|---|---|
| `flowtls/listener.go`（共享 raw socket + 四元组分发 + SYN 状态机） | ✅ |
| `flowtls/quic/server.go`（服务端 QUIC） | ✅ |
| `sing-box` inbound 适配层（流 → `RouteConnectionEx`，DATAGRAM → `RoutePacketConnectionEx`） | ✅ |
| 四向互通矩阵（Rust/Go × Rust/Go，TCP+UDP） | ✅ 全绿 |
| `sing-box check` 非 root 通过（raw socket 只在 Start 阶段申请） | ✅ |

### 剩下的事（P5）

1. **iptables 规则在 sing-box 侧落地**
   `option.FlowTLSInboundOptions.IPTablesMode` 已定义（none/print/auto），
   但还没接上 Rust 版 `src/rules.rs` 的等价逻辑。当前部署仍需手工维护规则。
2. **同端口真证书网站**
   sing-box 的 flowtls inbound 只做协议，没有伪装站点。
   需要复用 `web/index.html` + 一个内嵌 rustls/https 的等价实现，
   或者在 README 里明确要求另起一个 nginx/caddy 监听同端口。
3. **CI 互通矩阵**（进度：本地脚本已完成）
   `docs/e2e_matrix.sh` 已覆盖 4 格全链路（TCP+UDP，10 条断言）；
   剩余工作只是把它接进 GitHub Actions（需要 runner 具备 CAP_NET_RAW）。
4. **配置迁移文档**
   Rust 的 YAML 与 sing-box 的 JSON 字段对照表（`docs/MIGRATION.md`）。
5. ~~**冻结 Rust**~~ —— ✅ 2026-11-13 已完成
   Rust 源码归档到 `legacy-rust` 分支 + `rust-frozen-2026-11-13` 标签，
   主分支只维护 Go；黄金向量已入库（`flowtls/testdata/`），
   兼容性门禁不再依赖 Rust 工具链。详见 `docs/EVOLUTION.md`。

---

## 2026-11-13 13:45（北京时间）更新：Rust 冻结完成

### 本次做完的事

| 项 | 状态 |
|---|---|
| Rust 归档到 `legacy-rust` 分支 + 标签 | ✅ |
| 主分支删除 `src/` / `Cargo.*` / Rust 时代脚本 / YAML 示例 | ✅ |
| 黄金向量入库 `flowtls/testdata/`（120B 记录 + authID） | ✅ |
| 互通门禁改造成「纯 Go 消费冻结向量」，不再需要 cargo | ✅ |
| `docs/EVOLUTION.md`（演进史 + 怎么查历史） | ✅ |
| `docs/MIGRATION.md`（YAML→JSON 逐字段对照） | ✅ |
| `deploy.example/*.json`（`sing-box check` 已通过） | ✅ |
| `Makefile` 新增 `test` / `interop` / `e2e` | ✅ |
| `docs/e2e_matrix.sh` Rust 单元格改为可选（`RUST_FLOWTLS`） | ✅ |

### 剩余待办（P5，按优先级）

1. ~~**`iptables_mode: auto` 接线**~~ —— ✅ 2026-11-13 完成
   `flowtls/rules.go` + `rules_linux.go` / `rules_stub.go`，三种模式全部可用；
   规则文本与 Rust 版逐字一致（便于从旧部署延续）。
2. ~~**同端口真证书网站**~~ —— ✅ 2026-11-13 完成
   选了方案 a：`protocol/flowtls/masquerade.go`，用真证书 + `site_dir`，
   与隧道同端口共存已验证。
3. **CI**
   把 `make test` + `make interop` 接进 GitHub Actions（不需要特权，容易）；
   `e2e_matrix.sh` 需要 `CAP_NET_RAW`，可以只跑在自托管 runner 上。
4. **跨境链路重测**
   README 的实测数据来自 Rust 版。协议相同，但 Go 的 quic-go 参数
   （InitialPacketSize / 流窗口 / 自适应策略）需要在自己的链路上重新跑一遍
   `docs/bench.sh`，把真实数字补上。
---

## 2026-11-13 14:25（北京时间）更新：P5-1 / P5-2 完成

### 本次做完的事

| 项 | 状态 |
|---|---|
| iptables 规则层（`none`/`print`/`auto`） | ✅ |
| 服务端规则在 raw socket 之后落地 | ✅ |
| 客户端规则在第一个包之前落地 | ✅ |
| `print` 输出含卸载命令 | ✅ |
| 同端口真证书伪装站（`masquerade`） | ✅ |
| 伪装站与隧道同端口共存实测 | ✅ |
| 恢复被误删的 `ssl/` 真证书 | ✅ |
| 修正 `0xF107` 十进制值（61703，不是 61687） | ✅ |

### 剩余待办（P5）

1. ~~**CI**~~ —— ✅ 2026-11-13 完成
   `.github/workflows/ci.yml`：verify / test / cross 三个 job 跑在托管 runner，
   e2e 独立成 job 用 `[self-hosted, flowtls-e2e]` 标签 opt-in。
2. **跨境链路重测**
   README 的实测数据来自 Rust 版。协议相同，但 quic-go 的参数
   （InitialPacketSize / 流窗口 / 自适应策略）需要在真实链路上重跑
   `docs/bench.sh`，把数字换成 Go 版的。
3. ~~**伪装站细节打磨**~~ —— 部分完成
   - ✅ 反向代理模式（`masquerade.proxy_url` + `rewrite_host`，对齐 hysteria2）
   - ⬜ HTTP/3（当前只有 h2 + http/1.1）—— 优先级低：
     探测者用 HTTP/3 探测的成本高，且 h2 已经与真实站点无差别。

---

## 2026-11-13 14:45（北京时间）更新：P5-3 完成

### 本次做完的事

| 项 | 状态 |
|---|---|
| GitHub Actions CI（4 个 job，分特权/非特权） | ✅ |
| 伪装站反向代理模式（`proxy_url` + `rewrite_host`） | ✅ |
| 校验分层重构（check 能抓到的放构造函数） | ✅ |
| 文档脚本可移植性（不再写死 /root/go） | ✅ |

### 剩余待办

1. **跨境链路重测**（唯一还需要真实环境的事）
   README 的实测数据来自 Rust 版。协议相同，但 quic-go 的参数
   （InitialPacketSize / 流窗口 / 自适应策略）需要在真实链路上重跑
   `docs/bench.sh`，把数字换成 Go 版的。
   没有链路访问权时无法进行——这是唯一的外部阻塞项。

2. **HTTP/3 伪装**（可选，优先级低）
   当前 `NextProtos: ["h2", "http/1.1"]`。真实 CDN 站点会通告 `h3`，
   但服务端要支持 h3 需要 QUIC-over-UDP 的 443/8443 监听，
   而 UDP 8443 上跑的是我们的 DATAGRAM 通路，两者会打架。
   结论：**保持不支持**，并在文档里说明原因比硬加更诚实。

## 2026-11-13 19:02（北京时间）更新：P6 完成 —— BBR 拥塞控制，吞吐 15 倍

### 背景：用户的原始判断是对的

用户说「是不是 没用bbr 你要完整的移植啊」。查证结果：

- Rust 最终版用 quinn 的 BBR，外面包 `CappedBbr` 钳窗口上限；
- **Go 侧一行拥塞控制代码都没有**，直接吃 quic-go 的 Cubic 默认值。

这就是「功能全对但就是慢」的唯一根因。

### 本次做完的事

| 项 | 状态 |
|---|---|
| BBR 拥塞控制（客户端 + 服务端） | ✅ |
| `CappedBbr` 等价实现（窗口上限钳制） | ✅ |
| 自适应窗口（每 2 秒按丢包率调整，逐行对齐 Rust） | ✅ |
| `max_cwnd` 配置项（inbound / outbound / 示例 / 文档） | ✅ |
| QUIC 路径统计日志（对齐 Rust「QUIC 路径统计」） | ✅ |
| **修复 UDP 会话键错误**（`(socket, target)`，之前会串流到错误目标） | ✅ |

### 实测（新加坡服务器，跨境链路）

| 指标 | 之前 | 现在 |
|---|---|---|
| 下行 | 5.25 Mbps | **76~87 Mbps** |
| 上行 | 10.85 Mbps | **87 Mbps** |
| UDP 目标正确性 | 错（发 1.1.1.1 送到 8.8.8.8） | 正确，20/20 无丢包 |

### 剩余待办（重新排序）

1. **提交代码**：本轮 BBR + UDP 修复全部未提交（`capped_bbr.go` 是新文件）。
2. **HTTP/3 伪装**（可选，优先级低，结论仍是「不做并说明原因」）。
3. **ACK 频率 5ms**（已知差异，不做）：quic-go 只能解析 ACK Frequency 帧，
   不能发送，`MaxAckDelay` 是内部常量；改它必须 fork quic-go，
   违反「依赖版本与 sing-box 逐字节对齐」。实际影响小（每 2 包立刻回 ACK）。
4. **`send_window` 无对应项**（已知差异，不做）：quinn 的 `TransportConfig`
   独有概念，quic-go 用接收窗口反压，语义不等价但效果接近。
   已确认 `InitialConnectionReceiveWindow=16MB` / `InitialStreamReceiveWindow=4MB`
   与 Rust 的 `receive_window(16MB)` / `stream_receive_window(4MB)` 一致。
5. **sendmmsg 批量发送**（性能项，非功能缺失）：
   Rust `send_batch` 一次最多 32 包，实测能把内核态时间降 32 倍。
   Go 侧 `SendBatch` 目前是循环 `Sendto`，而且**从未被调用**（全走 `Send`）。
   当前 87Mbps 下 CPU 不是瓶颈，但 1 核 ARM 机器上跑满千兆会撞墙。
6. 真链路矩阵 `docs/e2e_matrix.sh` 需要 root，本地无特权时跳过。

## 2026-11-13 23:59（北京时间）更新：传输层性能修复，回环追平并超过 Rust

### 本次做完的事

| 项 | 状态 |
|---|---|
| 批量发送队列 + sendmmsg（32 包/批，纯 ACK 与数据同队列保序） | ✅ |
| 消除每包堆分配（Seal/OpenTo/ForEachRecord/deliverOwned） | ✅ |
| **ARP 解析 `0x` 前缀 bug**（AF_PACKET 从未真正启用） | ✅ |
| `Close` 重复 close 同一 fd | ✅ |
| 双 fd 策略（本机地址走 RAW / 其余按环境） | ✅ |
| 默认 IPPROTO_RAW，`FLOWTLS_AF_PACKET=1` 可选；QDISC_BYPASS 默认关 | ✅ |
| 客户端 recvFD 绑定出口网卡 | ✅ |
| 两端清理核对（服务器旧备份/旧源码/旧二进制，本地 iptables 残留） | ✅ |
| Rust 服务端用 legacy-rust 分支重新构建并部署（md5 与源码产物一致） | ✅ |

### 回环实测（同机 16 核，30MB × 3，同客户端对照）

| 组合 | 修复前 | 修复后 |
|---|---|---|
| Go → Go | 31~50 MB/s | **90~97 MB/s** |
| Go → Rust | 42 MB/s | 42 MB/s |

**回环目标已达成**（用户核心诉求：Go 版带宽追上 Rust 版）。

### 公网遗留（下一步唯一事项）

同一时刻、同一链路、同一源端口：**Rust 客户端建连成功、Go 客户端握手超时**；
SYN 字节逐字段一致、校验和自洽、客户端网卡可见，但服务器侧 rawcap 收不到 Go 的 SYN。
已排除端口冲突/校验和/非阻塞/MSG_DONTWAIT/recvFD 绑定/ARP/QDISC_BYPASS（详见 DEVTIPS 86）。
下一步：bpftrace 观察 NAT 表，或对两个客户端做全量 syscall 对比。

## 2026-11-14 01:25（北京时间）更新：公网传输根因修复，Go↔Go 从不通到 5.9~7.2 MB/s

### 本次做完的事

| 项 | 状态 |
|---|---|
| **拥塞控制器从未安装**：`Attach()` 补 BBR 分支 `SetCongestionControl(newCappedBbr(...))` | ✅ 服务端 254KB/s → 10.1MB/s |
| **NAT 云主机源地址**：配置值不在本机网卡上时自动改用探测出口地址 | ✅ Go 服务端从「不通」到可用 |
| `SendMode()` 全链路透传 + inbound/outbound 各一行启动日志（发送路径 + 生效源 IP） | ✅ |
| **去掉 MSG_DONTWAIT**：RAW 发送改阻塞 flags=0（数据面已收敛到 flushLoop 单协程），不再静默丢 ACK | ✅ |
| 延迟 ACK 条件补 `ackPend > 0`，与 Rust `client.rs:808` / `server.rs:501` 逐条对齐 | ✅ |
| **接上 RecvBatch**：`recvLoop` 由逐包 recvfrom 改为一次 recvmmsg 32 包 | ✅ |
| `flushLoop` 整批发送失败不再吞 err：计 `txSendErr`，`FLOWTLS_DEBUG_SEND=1` 打日志 | ✅ |
| 服务端统计补 `rtt=` 字段（Rust 有、Go 没有，是本轮最大的排查障碍） | ✅ |
| 补 `socket_stub.go` 的 `maxSendBatch`/`maxRecvBatch`/`RecvBatch`/`SendMode`（darwin/windows/android 交叉编译） | ✅ |
| 两级 recvLoop（pump + 处理）实验 | ❌ 吞吐无提升（6.2 vs 6.1）却多一个丢帧风险点，**已回退** |
| 服务器配置回归：删掉实验用的 `up_mbps`，`max_cwnd` 恢复 8388608 | ✅ |
| 文档更正：`legacy-rust` 第 20/21 条「云 NAT 不可用 / 运营商封禁」标记为过时；本仓库 DEVTIPS 85/86 标注推翻 | ✅ |

### 公网实测（本地 ↔ Oracle 新加坡 ARM，100MB，同一时刻对照）

| 组合 | 本轮开始时 | 本轮结束 |
|---|---|---|
| Go 客户端 → Go 服务端 | 握手超时 / 49KB/s | **8.0~9.8 MB/s（64~78Mbps）** |
| Rust 客户端 → Go 服务端 | 连不上 | **14.8~15.1 MB/s（118~121Mbps）** |
| Go 客户端 → Rust 服务端 | 87Mbps（旧代码） | 未回归（下一步要测） |
| 本机回环 Go↔Go 30MB | 90~97 MB/s | **80~108 MB/s**（修掉 bindRecv 回归后） |

### 原记「Go 客户端方向仍比 Rust 慢 2.2 倍」——已撤回，见下方 01:55 部署段

唯一剩下的硬线索：**服务端测 Go 客户端 RTT 215~228ms，测 Rust 客户端 78ms**
（真实链路 89ms）。多出的 ~140ms 是 Go 客户端的 ACK 延迟，但已排除并试过：
窗口大小、CPU、拥塞算法选择、内核接收队列（拆两级收包无效）、服务端源地址、iptables。

**下一步第一动作（不要再从黑盒猜）**：给 `PathStats` 补 `Cwnd` 与 `BytesInFlight`。
quic-go 的 `ConnectionStats` 不暴露这两个值，只能在 `cappedBbr` 里用 atomic 记录
`GetCongestionWindow()` / `CanSend(bytesInFlight)` 最近一次的入参，再由 `windowController`
按连接聚合输出。Rust 日志早就有 `cwnd=` `inflight=` `mtu=` `pending=` `rx_queue=`，
字段不对齐就是本轮排查绕远路的直接原因（详见 DEVTIPS 88/89）。

补完之后按这个顺序二分：
1. 传输期间（不是结束后）同时抓两端 `cwnd`/`inflight` → 判断是窗口受限还是接收流控受限；
2. 若是窗口受限：对比 cappedBbr 与 quinn BBR 在 89ms RTT 下的 startup→drain 判据；
3. 若是流控受限：查 `AdvertisedWindow`/`rxBytes` 与 QUIC 流级 `MaxStreamReceiveWindow`。

### 追加：本轮最后一次修复（回环回归）

上一轮加的「客户端 recvFD 绑定出口网卡」用 dst 反推角色，而服务端探测 dst 是 `8.8.8.8`，
于是服务端也被绑到物理网卡，**收不到 lo 上的包**，本机回环从 90~97 MB/s 变成全超时。
改成显式参数 `newRawSocket(dst, local, bindRecv)`：Dial 传 true、Listener 传 false
（DEVTIPS 90）。修完回环 80~108 MB/s，公网 Go↔Go 稳定后 8.0~9.8 MB/s（64~78Mbps）。

## 2026-11-14 01:55（北京时间）更新：Go↔Go 部署到 127.0.0.1:1080，性能结论按重复测量修正

### 部署现状（生产用这一套）

| 角色 | 位置 | 说明 |
|---|---|---|
| 服务端 | 新加坡 203.0.113.10 `/opt/flowtls/sing-box`（arm64） | 配置 `server.json`，监听 `*:8443`，规则 `u32 "0x4&0xff00ffff=0x1e004000"` |
| 客户端 | 本机 `dist/sing-box-1.14.4-rev.1-linux-amd64` | 配置 `/tmp/live/client-sg-1080.json`，入口 **`127.0.0.1:1080`**（mixed），用户 `admin` |
| 入口参数 | `source_port 44333` / `ip_id_mark 30583` / `max_cwnd 8388608` / `iptables_mode auto` | `check -c` 不需要 root ✅ |

启停与验收细节在 `DEPLOY_CREDENTIALS.md`（口令不入库，按该文件约定只记用户名）。

### 实测（每格至少 5 轮，报区间）

| 组合 | 吞吐 |
|---|---|
| Go↔Go 串行 100MB × 11 | **11.8~18.7 MB/s（94~150Mbps）** |
| Go↔Go 4 并发 100MB | 合计 17.3 MB/s（138Mbps） |
| Rust 客户端 → 同一 Go 服务端 | 14.8~15.1 MB/s |
| 本机回环 Go↔Go 30MB | 80~108 MB/s |

结论：**Go 版隧道带宽已追平 Rust**，本条目标题里的「达到 rust 版」诉求达成。

### 本节撤回的旧结论（都因单次测量）

| 旧结论 | 撤回原因 |
|---|---|
| Go 客户端比 Rust 慢 2.2 倍 | 11 轮重测后不存在；旧数字来自未重启到最终版的实例 |
| 服务端测 Go 客户端 RTT 215~228ms、Rust 78ms → Go 的 ACK 慢 | 统计里 `rtt=` 是「循环中最后一条连接」的值，当时 `conns=2/3` 且日志不标对端，数字归属不明 |
| 「跑久了会退化，之前低值是残留会话污染」 | 已证伪：连跑 15 轮后仍 15.3~18.7 MB/s，新实例也不更快 |

### 下一步（仍未做的两件事，都在观测层）

1. `PathStats` 补 **`Cwnd` / `BytesInFlight`**：quic-go 的 `ConnectionStats` 不暴露，
   只能在 `cappedBbr.GetCongestionWindow()` / `CanSend()` 里用 atomic 记最近值再聚合。
2. `PathStats` 补 **per-conn 归属**（对端地址、连接数与 rtt/sent 一一对应）：
   现在多连接共存时 `rtt=` 归属不明，已经因此得出过错误结论。

做完这两件事才有资格再谈「还剩多少差距」。测量纪律本身已固化进 DEVTIPS 91。
