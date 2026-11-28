# DEVTIPS — 踩坑与调试手册

> **阅读提示**：第 1~68 条记录的是 **Rust 参考实现**时期的坑（quinn-proto、
> Rustls、tokio、rusqlite 等），对应源码已冻结在 `legacy-rust` 分支；
> 第 69 条起是 **Go 实现**（quic-go / sing-box 适配层）。
> 两类坑在原理上常常相通（例如窗口、乱序、NAT 行为），所以历史条目保留。
> 演进的来龙去脉见 `docs/EVOLUTION.md`。

## 173. `hk1→tk3` 不是普通 NAT，而是透明 TCP 代理；IPv6 二层隧道已验证（2026-11-28 北京时间）

### 一、纠正前两轮的结论

第 171、172 条把 `hk1 → tk3` 判断成「改写 IP ID / ISN 的设备」。
进一步做**同一次运行的双点抓包**后，发现它其实是**透明 TCP 代理 / 归一化器**：

| 字段 | hk1 发出 | tk3 收到 | 结论 |
|---|---|---|---|
| 源端口 | 42190 | **42190** | 保留 |
| 窗口 / wscale | 64240 / 7 | **64240 / 7** | 保留 |
| seq | 2138644571 | 2268649368 | 双向映射 |
| TSval | 3772772255 | 237637220 | 双向映射 |
| MSS | 1460 | 1394 | 按后端 MTU 钳制 |
| TLS payload | `16 03 01 02 03…` | **逐字节一致** | 不改 |

普通 TCP 在这条路上完全正常，因为它本来就由这个代理终结并重建。
FlowTLS 的 raw 回程包却不会被代理送回客户端 —— 这才是「识别成功了、
双向也有流量，但 QUIC 始终超时」的真正原因。

### 二、为什么只换识别字段不够

依次实验了：

1. **源端口低 10 位**：nft 规则成功记账、服务端成功建会话；
2. **TCP 初始窗口**：中间设备把 `46209` 重算成 `45260`，规则不命中；
3. **ISN / IP ID / TOS**：全部被改写或清零。

源端口方案证明「识别」可以解决，但服务端 raw 响应仍被透明代理截断。
因此**仅靠换一个头字段无法解决这条路径**，必须绕过代理本身。

### 三、已验证的绕过方案：二层 GRE-over-IPv6

同一对机器走 IPv6 时，seq / TSval 逐字节保留，RTT 约 48ms（IPv4 约 62ms）。
建立 `ip6gretap` 二层隧道后，现有 rev.17 FlowTLS **无需改协议**即可工作。

四个必要条件，缺一不可：

1. **必须用 `ip6gretap`，不能用 `ip6gre` / `ip6tnl`**：
   AF_PACKET 解析器假设有二层以太网头；三层隧道解封装后没有这个头，
   nft 能看到 SYN，但 FlowTLS 监听层解析不了。
2. **tk3 服务端必须走 `IPPROTO_RAW`**（`FLOWTLS_AF_PACKET=0`）：
   AF_PACKET 发送绕过路由表，回包不会进入隧道。
3. **QUIC MTU 必须降到 1200**：外层 IPv6 路径 MTU 实测只有 1436，
   扣除 IPv6+GRE+以太网头后，内层路由 MTU 约 1370；
   MTU 1332 产生 1434 字节包、MTU 1280 产生 1382 字节包，都会
   `sendto/sendmmsg: message too long`。
4. **relay 的 SNAT 必须写成隧道内地址**：hk1 `10.253.0.1` →
   tk3 `10.253.0.2`，否则回程不会进入隧道。

实测结果（hk1 客户端 → 隧道 → tk3:29443）：

```
SIZE=20655372  code=200  t=22.999s
rtt=48ms  lost=0  loss_pct=0
```

这证明方案本身成立。完整 relay 还需用**真实 Windows 客户端**验证第一跳；
sg1→hk1 也有代理，不能代替 Windows。

### 四、落地清单（尚未部署）

1. hk1 / tk3 各建持久 `ip6gretap` 接口，私网 `10.253.0.0/30`；
2. tk3 起第二个 FlowTLS 监听（隧道地址 `10.253.0.2:29443`），
   `IPPROTO_RAW` + QUIC MTU 1200；原 `8443` 直连监听保持不动；
3. hk1 的 `7443` 转发改为 `10.253.0.2:29443`，SNAT `10.253.0.1`；
4. 订阅里的 `hk1-tk3` 节点增加 `mtu: 1200`（需给 FlowTLS 增加可选 MTU 配置）；
5. 用 Windows GUI 做最终端到端验证。

所有临时接口、规则、进程均已清理；生产保持 rev.17 原状。

## 172. payload 方案也走不通 —— 中间设备禁止握手完成前发数据（2026-11-28 北京时间）

### 一、思路与它的死因

rev.17 的 TCP ISN 在 `hk1 → tk3` 上被改写。既然 TCP/IP 头字段全不可靠，
下一个明显的候选是 **TLS 载荷**：payload 是唯一「改了应用层就坏」的字段。

实现方式（rev.18，已试并**回滚**）：把 16 位标记埋进 ClientHello 的
`random` 字段（TLS 载荷偏移 12），nft 用 `@th,352,16 <mark>` 匹配
（352 = TCP 头 32 字节 + 偏移 12，单位 bit），客户端在 **SYN 之后立刻**
发这个 ClientHello，服务端收到时才回 SYN-ACK。

**它失败得更彻底：连干净路径都不通。**

### 二、死因一：中间设备在握手完成前丢弃（并 RST）数据包

hk1 侧抓包（`tcpdump -vv`）：

```
1. hk1 → tk3  Flags [S]   seq 1045687105
2. hk1 → tk3  Flags [P.]  seq 1045687106:1045687642  length 536   ← ClientHello
3. tk3 → hk1  Flags [R]   ← RST，来自中间设备而非 tk3
4. tk3 → hk1  Flags [S.]  ack 1045687106
```

tk3 侧**同时**抓包：

```
1. hk1 → tk3  Flags [S]    seq 1954671359（被改写）
2. tk3 → hk1  Flags [S.]   ← tk3 内核（masquerade socket）
3. hk1 → tk3  Flags [.]
4. tk3 → hk1  Flags [F.]
```

**那个 536 字节的 ClientHello 在 tk3 侧根本没有出现。** 中间设备把它
吞掉了，并代 tk3 回了 RST —— 标准的状态防火墙行为：
不允许「握手未完成就传数据」（TFO / 0-RTT）通过。

### 三、死因二：SYN 不再被 DROP 后，内核会抢先应答

rev.18 要求 SYN 不被 DROP（标记在载荷里，SYN 上没有），于是：

- SYN 走到最后一条 `notrack` 兜底规则 → **内核看到 SYN**
- 同端口有 masquerade 的内核 socket → **内核回 SYN-ACK**（用它自己的 ISN）
- 客户端收到这个 SYN-ACK，以为握手完成
- 后续 ACK 的 seq 与内核协商的值不符 → 内核回 RST → 连接废

所以 rev.18 **连干净路径都必然失败**。根因不是中间设备，而是
「**SYN 必须被 DROP**」这条硬约束被破坏了（内核抢答）。
masquerade 关闭时更糟：内核直接回 RST。

### 四、结论：这条路径在「不用内核 TCP」前提下无解

三次实测汇总：

| 路径 | SYN 上可用的字段 | 载荷可用 | 结论 |
|---|---|---|---|
| 家宽 → tk3 | 全部保留 | 是 | 任何方案都可以 |
| hk1 → sg1 | 全部保留 | 是 | 任何方案都可以 |
| hk1 → tk3 | **只有 sport / win / wscale 保留** | **仅握手后** | **无解** |

`hk1 → tk3` 的中间设备是一个**完整的 TCP 代理 / 归一化器**：
改写 seq 与 TSval、钳制 MSS、改写 IP ID，但保留源端口、窗口、wscale，
并且双向映射 seq（所以真实 TCP 在这条路上完全正常）。它禁止握手前的
数据，因此三条路同时被堵死：

- 不能用 TCP/IP 头字段标 SYN（都被改写）
- 不能用载荷标首包（首包被丢弃）
- 不能让 SYN 不被 DROP（内核会抢先应答）

### 五、剩下三条路（成本从低到高）

1. **改走 IPv6**（推荐）：同一对机器 v6 路径**逐字节干净**
   （seq/TSval 原样、只有 MSS 按 PMTU 调整），RTT 47.8ms vs v4 62.3ms。
   这是 rev.17「标记从 IP ID 移到 TCP ISN」的**直接红利** ——
   IPv6 头里根本没有 IP ID 字段。改动范围：v6 头构造/解析、
   AF_PACKET ethertype `0x86DD`、`ip6` 表规则、放开 `Is4()` 校验。
2. **放弃这条路径**：用 `hk1 → sg1`（实测 40MB / 8.7s）或直连 tk3。
3. **服务端对所有 SYN 回 SYN-ACK 并自己终结 TLS**（anytls 形态）：
   能穿透任何中间设备，但要放弃「内核看不到连接」的隐蔽性，
   且与 masquerade 的内核 socket 互斥，属架构级改动。

**不要再用「换个头字段」的思路试第四条** —— sport / win / wscale
合计不足 20 位、且窗口必须「像真的」，误判率与指纹风险都不可接受。

## 171. 分流标记从 IP ID 换成 TCP ISN；序列号也会被中间设备改写（2026-11-28 北京时间）

旧方案把分流标记放在 **IP ID 高字节**，靠 `ip id & 0xff00 == mark` 匹配。
三角测量实测（同一客户端二进制，只换目标服务器）：

| 路径 | IP ID | 结果 |
|---|---|---|
| 家宽 `198.51.100.7` → tk3:8443 | 保留 | ✅ |
| hk1 `203.0.113.10` → sg1:8443 | 保留 | ✅ |
| hk1 `203.0.113.10` → tk3:8443 | **被随机化** | ❌ 握手超时 |

同一条 hk1 出向链路，差别只在中间路径。被改写后的表现极隐蔽：
nft 的 drop 规则不命中 → 伪包进内核 → 内核抢答 SYN-ACK / 逐包回 RST
→ 两端日志都「正常」，只有隧道不通。

**教训**：判断「某个头字段能否当分流依据」时，不能只看它在我们自己的
代码里是否受控，必须验证它在真实路径上是否被改写。IP ID 恰好是
被改写概率最高的字段（RFC 6528 要求做防侧信道 hash，多数 NAT / 云网关
直接随机化）。

### 二、换成 TCP ISN 低 16 位（`@th,48,16` 的单位是 bit 不是 byte）

字段选型要求三条同时成立：不被改写、不改变语义、内核能静态匹配。

| 字段 | 不被改写 | 语义无影响 | 可静态匹配 |
|---|---|---|---|
| IP ID | ❌ | ✅ | ✅ |
| TCP 窗口 | ⚠️ NAT 可能改 | ✅ | ✅ |
| wscale | ❌ 必须像真 Linux | — | — |
| TCP 时间戳 | ✅ | ⚠️ 破坏 PAWS | ⚠️ 要算选项偏移 |
| **TCP ISN** | **✅** | **✅** | **✅** |

nft 匹配写法（**offset 单位是 bit**）：

```nft
tcp flags syn @th,48,16 0xb481   # 序列号低 16 位
```

TCP 头位布局：0..15 源端口、16..31 目的端口、32..47 序列号**高**16、
48..63 序列号**低**16。写成 `@th,32,16` 读的是高 16 位，规则永不命中 ——
而且 nft 不会报错，只是把它优化显示成 `tcp sequence 1694498816/16`
（那个数字是 `0x65000000`，是唯一的线索）。
**验证办法**：发一个已知 seq 的探针包，看计数器是否 +1。

iptables 回落路径用 **byte** 偏移：`-m u32 --u32 "24&0x0000FFFF=0x<mark>"`
（TCP 头从 IP 头偏移 20 开始，seq 在 TCP 头内偏移 4）。

### 三、只有 SYN 带标记 → 数据包必须靠动态集合

ISN 标记只在 SYN 一个包上；后续数据包的 seq 从 ISN+1 递增，低位打散。
但数据包同样必须被 DROP（否则内核逐包回 RST）。解法：

```nft
# 1. 纯 SYN 命中标记 → 记账 + DROP
... tcp flags syn @th,48,16 <mark> update @ft_8443 { ip saddr . tcp sport } drop
# 2. 同一条流的后续包 → 按集合 DROP
... ip saddr . tcp sport @ft_8443 drop
# 3. 其它（真实浏览器）→ notrack 交给内核，伪装站正常工作
... notrack
```

集合的**超时必须 ≥ 会话空闲回收时间**（默认 120s）：QUIC 连接在低流量时
可能几十秒没有数据包，集合提前过期会让内核重新看到数据包并回 RST。
这里取 10m，靠每次新 SYN 的 `update` 刷新。

`-m recent`（iptables 回落）只能按**源 IP** 索引，模块不支持端口，
所以粒度比 nft 集合粗 —— 同一台客户端访问该端口的其它流量会被短时丢弃。

### 四、还有比 IP ID 更狠的：ISN 也会被改写

`hk1 → tk3` 路径除了改写 IP ID，还改写 TCP ISN。**单次同步双点抓包**
（同一条连接，源端口两端一致）：

| 字段 | hk1 发出 | tk3 收到 | 结论 |
|---|---|---|---|
| 源端口 | 42190 | **42190** | 保留 |
| 窗口 | 64240 | 64240 | 保留 |
| wscale | 7 | 7 | 保留 |
| **seq** | `2138644571` | `2268649368` | **改写** |
| **TS val** | `3772772255` | `237637220` | **改写** |
| **MSS** | `1460` | `1394` | **钳制** |

**怎么区分「改写器」和「TCP 代理」**（这一步判错会走错方向）：

| 现象 | TCP 代理（终止并重建） | 改写器（TCP 归一化） |
|---|---|---|
| 源端口 | **会变**（代理自己的端口） | 保留 |
| 窗口 / wscale | 变（代理自己的栈） | 保留 |
| seq / TS val | 变 | **变** |
| MSS | 可能是代理的值 | 常被钳制到路径 MTU |

本次实测是**改写器**：端口与窗口原样保留，只动 seq / TSval / MSS。

同类设备在运营商国际出口上以「TCP 加速」「TCP 归一化」名义部署，
作用是防 off-path 序列号预测攻击，副作用是**所有依赖 TCP/IP 头字段的
分流方案在这里全部失效**。

**诊断口诀**：看到「握手超时不报错、两端日志都正常」时，先在**两端
同时抓同一个源端口的 SYN**（必须是同一次运行，跨运行对比源端口会得出
完全错误的结论），对比 sport / win / seq / mss：
- 全部一致 → 标记字段没问题，查规则 / 集合
- sport 与 win 保留、seq 变 → TCP 归一化改写器，**任何头字段都不能用**
- sport 与 win 都变 → 透明 TCP 代理，同上（但可以改用 payload 识别）

**结论：这类路径上伪 TCP 从原理上无法工作。** 唯一能穿透的方向是把
识别依据放进 **payload**（内核完成真实三次握手，服务端读首条 TLS 记录
的明文头判断是隧道还是浏览器），也就是 anytls 那种形态 —— 代价是失去
「内核看不到连接」的隐蔽性，属另一个量级的架构改动。

### 四之补充：IPv6 路径是干净的（这是绕开改写器的正确出路）

同一对机器（hk1 → tk3）走 **IPv6** 时，单次同步双点抓包：

| 字段 | hk1 发出 | tk3 收到 | 结论 |
|---|---|---|---|
| seq | `1972178030` | **`1972178030`** | **一致** |
| TS val | `4215378078` | **`4215378078`** | **一致** |
| MSS | 1440 | 1436 | 仅按路径 MTU（正常 PMTUD） |
| RTT | — | **48ms** | 比 IPv4 的 80ms 更快 |

**改写器只针对 IPv4。** 运营商在国际出口部署的 TCP 归一化设备绝大多数
只处理 IPv4（IPv6 流量占比低，且 v6 头里根本没有 IP ID 字段可供它
「修」IP ID 相关的侧信道问题）。

因此「让 hk1→tk3 这条路径可用」的正确做法不是继续找 IPv4 头字段，
而是 **给 FlowTLS 增加 IPv6 支持**。附带两个好处：
- 该路径 RTT 从 80ms 降到 48ms；
- IPv6 头**没有 IP ID 字段**，而 rev.17 已经把分流标记移到 TCP ISN，
  所以这次标记迁移恰好是 IPv6 支持的**前置条件**（若还用 IP ID，
  IPv6 上根本没有地方放标记）。

实现范围（供评估，未开始）：`packet.go` 增加 40 字节定长 v6 头的
构造/解析（无校验和、无 IP ID）、`socket_linux.go` 的 AF_PACKET
（ethertype `0x86DD`）与 `IPV6_HDRINCL`、`rules.go` 的 `ip6` 表、
`config.go` 的 `Is4()` 校验放开。WinDivert 侧另一套。



### 五、测脚本里的自杀陷阱（把我坑了半小时）

`pkill -f hk.json` 会**把执行这条命令的 shell 自己也匹配到**
（它的命令行含 `hk.json`），于是 shell 被自己杀掉，后面所有命令都不执行，
表现为「日志文件不存在、进程没起来」。

正确写法：用锚定模式 `pgrep -f "^/tmp/sb17" | xargs -r kill`，
或者用 pidfile。同理 `pkill -f "sb17 run"` 也中招过。

## 170. 跳板机内核计数零丢包、服务端却报 35%：`loss_pct` 曾经是全局聚合值（2026-11-28 北京时间）

### 一、现象与定位过程

Windows 客户端经跳板机（9443 → sg1:8443）时，sg1 日志持续显示高丢包：

```
peer=203.0.113.10:3972  sent=809570  lost=283984  loss_pct=35
```

同一客户端**直连** sg1 时两种模式都不丢，但**经跳板机 + 系统代理**就丢。
用户明确纠正过：「都是跳板到 sg1，只是模式不同」，所以入站模式本身
不是原因，只是**更容易暴露配置缺陷的放大器**（见第四节）。

判定「链路到底丢没丢」必须用内核计数，不能用抓包：

```bash
# 跳板机上布两对计数器：最早（prerouting priority -400）与最晚（postrouting priority 400）
nft add table inet ftx
nft "add chain inet ftx rx { type filter hook prerouting priority -400; policy accept; }"
nft "add chain inet ftx tx { type filter hook postrouting priority 400; policy accept; }"
nft "add rule inet ftx rx ip saddr <客户端IP> tcp dport 9443 counter"
nft "add rule inet ftx tx ip saddr 203.0.113.10 ip daddr <服务端IP> tcp dport 8443 counter"
```

一轮 8 路并发 320MB 负载后：

| 测量点 | 包数 | 字节 |
|---|---|---|
| 收到（客户端 → 9443） | 255,984 | 28,616,221 |
| 转发（跳板机 → sg1:8443） | 255,968 | 28,615,011 |
| **差值** | **16（0.006%）** | 1,210 |

`ip -s link` 的 `dropped=0 errors=0`。**转发率 99.994%，链路完全干净。**

同期服务端却报 `lost_pct=35`，`inflight` 从空闲 43KB 堆到 **3.8MB**，
`rtt` 从 79ms 涨到 **132ms**。三个数字指向同一个机制：**兜底超发**
（第 169 条）让包在中间设备排队，延迟抖动使后发的包先到，
quic-go 的 `packetThreshold = 3`（`internal/ackhandler/sent_packet_handler.go:26`，
**const 不可调**）把乱序判成丢包。

配上 `up_mbps: 30` / `down_mbps: 150` 后，高丢包显示消失，速度从 5.83
回到 12.77 MB/s。**没有改一行传输代码。**

### 二、`loss_pct` 曾经是全局聚合值（rev.16 已修）

排查中先发现一个**荒谬日志**，它差点把我引向错误方向：

```
peer=198.51.100.7:3657 ... sent=1368  lost=0  loss_pct=26   ← 一个包没丢却报 26%
peer=203.0.113.10:4053 ... sent=784609 lost=411510 loss_pct=11
三个不同 peer 在同一采样周期同时显示 loss_pct=38
```

原因：`flowtls/quic/capped.go` 与 `brutal.go` 的统计循环算的是
**全部连接加总**的 `Δlost/Δsent`，然后打印到**每一行**。

rev.16 的改法：`connEntry` / `brutalEntry` 各加 `prevSent`/`prevLost`
基线，上报时用本连接自己的增量；全局聚合的 `loss` 保留，但只供
`windowController` 做窗口自适应（窗口本身是全局的，语义不变）。

**判断丢包真伪的可靠依据是 `lost`（每连接累计，只增不减），
不是 `loss_pct`（每周期增量，受采样边界影响）。**

### 三、这条日志里的 `win_cap` 是判断「哪个节点」的指纹

`win_cap` 在 Brutal 下**不是窗口字节数，而是协商后的发送速率（字节/秒）**。
所以它能直接看出客户端配了/没配带宽：

| `win_cap` | 含义 |
|---|---|
| `125000000` | 1000 Mbps（兜底或显式配置） |
| `62500000` | 500 Mbps（显式配置，PassWall 侧用过） |

排查时看到 TUN 报 125000000、系统代理报 62500000 —— 这说明两次对比
**不是同一个节点/配置**，对比前提本身就不成立。多客户端时先按 `peer=`
分组，再比 `win_cap` 和 `lost`，否则数据会被污染。

### 四、为什么「系统代理丢、TUN 不丢」

两种模式的 flowtls 出站路径**完全相同**（都走 `quic-go` 的同一份
`BrutalSender`），差别在流量灌入的节奏：

- **TUN**：经 gvisor 用户态栈重新分片，把应用层突发摊平，包到达速率更平滑。
- **系统代理**：内核 TCP 栈直接灌入，拥塞窗口一放开就是陡峭突发。

所以在 `inflight` 已经堆到 3.8MB 的高位上，系统代理更容易把包排到
队列深处、产生更大的乱序，从而**更容易触发 `packetThreshold=3` 的误判**。

**不是 TUN 更正确，而是系统代理更容易暴露「没配带宽」这个配置缺陷。**
反过来说：如果只测 TUN 就下结论「链路没问题」，会漏掉真实存在的配置隐患。

## 169. 不配带宽时静默按 1000 Mbps 发（hy2 是直接报错）；OFO 改造为何回退（2026-11-28 北京时间）

### 一、hy2 不允许「不配带宽」，我们允许且静默兜底成千兆

hy2 在 `sing-quic/hysteria/client.go:82-91` **直接报错拒绝启动**：

```go
if options.SendBPS == 0 {
    return nil, E.New("missing upload speed")
} else if options.SendBPS < MinSpeedBPS {   // 16384 B/s
    return nil, E.New("invalid upload speed")
}
```

sing-box 传的是 `SendBPS = UpMbps × 125000`，`UpMbps` 无默认值
（`option/hysteria2.go` 是 `int` 零值）。所以 **hy2 不配带宽 = 起不来，
不存在「默认 1000M」**。

我们的 `flowtls/quic/brutal.go` 做了静默兜底：

```go
if bps == 0 {
    bps = defaultBrutalRate        // 1 Gbps，静默生效
}
```

后果（跳板机路径，1 核 + 两跳）：目标 1000 Mbps 但链路只有 ~100 Mbps
→ 数据堆在跳板机队列 → RTT 79ms 涨到 4.2 秒 → Brutal 用这个假 RTT
算出 `cwnd=1.3GB` → 更严重（正反馈）。

实测 `down_mbps` 对速度的影响（40MB × 2 流，经跳板机）：

| down_mbps | 速度 |
|---|---|
| 不配（1000） | 5.83 MB/s |
| 100 | 10.99 MB/s |
| **150** | **12.77 MB/s** |
| 200 | 11.55 MB/s |
| 300 | 5.43 MB/s |

**部署时必须按实际带宽填 `up_mbps` / `down_mbps`**（填实测值的 80~90%，
宁可保守：填大了全浪费在重传上）。

### 二、OFO 乱序重排改造已试并回退（握手从 12/12 掉到 4~5/12）

`peerSeq` 的推进（Rust 与 Go 相同）是「next 更靠前就更新」，
一个乱序包就把 ACK 推到缺口之后。真实 TCP 的 `rcv_nxt` 只随连续字节推进，
所以这**确实是设计妥协**，我据此实现了完整版 OFO 重排 + 累积确认
（`pushInOrder` / `drainOOO` / `flushOOO`，约 250 行）。

结果：经跳板机握手成功率从 12/12 掉到 4~5/12，**已整体回退**。

诊断日志的铁证（客户端收到的包序列）：

```
seq=2626416895 span=7    明文条=0
seq=796389761 span=1365  明文条=1     ← 完全不同的 ISN 基线
seq=796391126 span=1365  明文条=1
```

同一客户端 4 元组收到了**属于不同服务端会话**的包：跳板机 SNAT 端口会被
复用，上一轮连接的残留包落入新一轮的同一四元组。重排逻辑把「落后于基准」
的包当重复丢弃 → 本轮真实数据全被丢弃 → 连接永久卡住。
（rev.14 没这么致命，因为它对每个能解密的包都无条件 `deliver`。）

试过两版补救都不够：首包绕开重排→服务端基准落后（伪 ClientHello 占位）
4/8；握手未完成时丢弃载荷包 + 基准取 `max(peerSeq, seq)` → 仍 5/12。

**要正确解决必须引入接收窗口校验**（只接受窗口内序号，窗口外触发重新
同步），属协议层改造，超出最小侵入范围。**ACK 语义保持 rev.14 不变。**

### 三、收包交接队列 1 → 8192 是真实移植疏漏

Go 是 `make(chan recvResult, 1)`，Rust 是
`mpsc::channel::<...>(8192)`（`legacy-rust:src/client.rs:485`，注释写明
「下行大流量时最多积压 8192 个包」）。

容量 1 时主循环一旦卡在 `deliver`（rx 满），读协程最多再塞 1 个包就阻塞，
socket 不再被读 → 内核 AF_PACKET 队列积压丢包；主循环也回不到 select，
5ms 心跳失效，延迟确认跟着停摆。

已随 rev.15 发布。但它**不改变判丢率**（实测都在 45~62% 区间），
也不稳定提升吞吐（第一轮 A/B 全部高速、第二轮又出现低速档）——
所以它只是「对齐参考实现」，**不要当成性能优化**。

### 四、量测方法上的教训（这几条都让我误判过）

- 跳板机只有 1 核、负载常达 1.0+，**`tcpdump -w` 自己会漏抓**。
  判断链路丢包必须用 `nft counter`（内核态）交叉验证。
  我此前用 seq 空洞算出 16~21% 丢包，而内核计数显示 99.96% 转发成功。
- 用「seq 重复数 = 0」证明「链路干净」是错的：伪 TCP 层本身不重传，
  重复数永远 0。要看 seq **空洞**，且必须按单个四元组过滤。
- 吞吐受运营商 ECMP 双路径支配（约 6 MB/s 与 11.5 MB/s），
  小样本极易把路径运气当成代码收益。必须交替 A/B 且样本足够大。

## 168. 跳板机端口转发只支持三层；DNAT 与 SNAT 必须成对，并要放宽 conntrack 窗口校验（2026-11-27 北京时间）

需求形态：客户端连 A 机（`203.0.113.20`），A 用 nft 把 `9443` 转发到
B 机（`198.51.100.20`）的 `8443`。**能做**，但只能是三层改地址，不终止连接。

```
table ip nat {
  chain PREROUTING  { type nat hook prerouting priority dstnat;
                      meta l4proto tcp tcp dport 9443 counter dnat to 198.51.100.20:8443 }
  chain POSTROUTING { type nat hook postrouting priority srcnat;
                      meta l4proto tcp ip daddr 198.51.100.20 tcp dport 8443 \
                      counter snat to 203.0.113.20 }
}
```

四条硬约束：

1. **DNAT 与 SNAT 必须成对**。只做 DNAT 时 B 的回程包按源地址直接发给
   客户端，源变成 `B:8443`；而客户端 `Session.matchPeer` 只认
   `p.Src == peer.Addr() && p.SrcPort == remotePort && p.DstPort == localPort`，
   地址或端口任一不符就整包丢弃 → 客户端只会反复重发纯 SYN。
   指纹：A 的 PREROUTING counter 在涨、字节数 ≈ 包数 × 60（全是无载荷 SYN），
   而 B 的日志里连一条 `connection from` 都没有。

2. **不能从跳板机本机测 `A:9443`**。DNAT 挂在 PREROUTING，本机产生的流量
   走 OUTPUT，永远不经过它 → 本机 curl/telnet 必然超时，很容易误判成
   「不支持端口转发」。要从第三方机器测。

3. **必须是三层转发，不能是终止型**。socat / nginx stream / haproxy /
   gost `-L tcp` 都会先用内核 TCP 接住连接再另起一条，B 看到的是内核发的
   无标记 SYN：握手能成，但数据进不了 AF_PACKET 收包路径（B 的 `in_8443`
   只对带 mark 的包放行），表现为「连上了但没数据」。

4. **不要给转发端口加 `notrack`**。B 机（服务端自己）可以加，A 机不行：
   没有 conntrack 条目时 `nf_nat_inet_fn()` 直接 NF_ACCEPT，DNAT/SNAT 会
   一起失效。A 机要的是 `be_liberal=1`，不是 `notrack`。

A 机必设的两条 sysctl（写 `/etc/sysctl.d/99-flowtls-relay.conf`）：

```
net.netfilter.nf_conntrack_tcp_be_liberal = 1   # 伪 TCP 序号不符窗口时不判 INVALID
net.netfilter.nf_conntrack_max = 65536          # 默认 8192，多设备转发容易满
```

`be_liberal=0`（默认）时，超出 conntrack 窗口跟踪的段会被判 INVALID 丢弃，
而伪造 TCP 的序号/窗口是协议自己造的，不保证符合窗口跟踪。症状是
**「隧道时通时不通，换个源端口重连又好」**——客户端重连换四元组，
产生新 conntrack 条目，于是恢复。

排查手法（避免把「本来就通」误判成自己修好了）：记录 `nft -a` 的 handle
与 counter 的两次读数。handle 不变说明规则没被重建；counter 在涨而本地
一个包都没发，说明是设备自己的流量在通。

### 一键脚本 `deploy.example/relay.sh`

跳板机上直接跑，不用再手敲规则。**持久化是默认行为**，不用额外步骤：

```bash
./relay.sh add 9443 198.51.100.20 8443    # 加转发（立刻生效 + 自动持久化）
./relay.sh list                           # 配置 + 实时规则 + 计数
./relay.sh status                         # 体检：ip_forward / conntrack / 冲突 / 持久化
./relay.sh del 9443
./relay.sh install                        # 只重新安装持久化（修复 / 手动同步）
./relay.sh uninstall [--purge]
```

`add` 会自动：装自己到 `/usr/local/sbin/flowtls-relay`、写
`/etc/sysctl.d/99-flowtls-relay.conf`、写并启用并**启动** systemd unit。三个
文件**内容没变就不重写**（不磨损 flash、不白跑 `daemon-reload`），所以重复
`add` / 重复 `install` 都是零副作用。只做临时试验时加 `--no-persist`。

两个容易踩的细节：

- unit 是 `Type=oneshot` + `RemainAfterExit=yes`，**必须 start 过一次才 active**，
  否则 `systemctl reload flowtls-relay` 会报 `is not active, cannot reload`。
  所以 `install` / `add` 会顺手把它拉起来。
- conf 为空时**不留空表**：渲染结果是 `add table` + `delete table`，两者在同一个
  `nft -f` 事务里必定成功，跑完内核里干干净净（否则空 base chain 会让 `status`
  看起来像「有配置却不出规则」）。

脚本的三条设计要点（改它之前必读）：

1. **规则写在自己的 nft 表里**（`table ip flowtls_relay`），**绝不写 `ip nat` 表的
   PREROUTING/POSTROUTING**。1Panel 的 `dnat.service`
   （`/usr/local/bin/dnat.sh`）会 `iptables -t nat -F PREROUTING` +
   `-F POSTROUTING` 后重写全部规则——**不是每 60 秒都 flush**（只在服务重启、
   首轮、或它自己的 `/etc/dnat/conf` 变化时触发），但每次触发都会把别人写在
   那两个链里的规则一并抹掉，表现为「重启一下 dnat 服务，我的规则就没了」。
   独立表不受 iptables 兼容层 flush 影响。
2. SNAT 源地址用 `ip route get <目标>` 推导，不用「排除私有网段」的启发式——
   后者在 NAT 云主机（网卡只有内网地址）上挑不到地址。
3. DNAT 带 `fib daddr type local`，只劫持「目的地就是本机」的包，
   不误伤经过本机、目的端口恰好相同的**转发**流量。
   （这与第 167 条方向相反：那条是想**排除**转发流量，在 prerouting 阶段
   靠 `fib` 判不出来，所以改挂 input 钩子。）

验证过的判读方法：`list` 里同一映射的 **DNAT 与 SNAT 计数应同量级**。
SNAT 远低于 DNAT = 回程没走通；DNAT 在涨但 `bytes ≈ packets × 60` = 全是
无载荷 SYN，服务端回程到不了客户端。

### 从 1Panel `dnat.service` 迁到 `flowtls-relay` 的正确顺序

**先加新的、再摘旧的**，全程零中断：

```bash
# 1. 先加到自己的表（此时两套并存，安全）
flowtls-relay add 9443 <服务端IP> 8443
# 2. 实测新连接已被新表接住（新表 counter +1，旧表 counter 停住）
# 3. 从 1Panel 的 conf 里摘掉，并重启它的服务立刻触发重写
cp -a /etc/dnat/conf /etc/dnat/conf.bak.$(date +%Y%m%d-%H%M%S)
grep -v '^9443>' /etc/dnat/conf > /tmp/c && cat /tmp/c > /etc/dnat/conf
systemctl restart dnat      # 不等 60 秒轮询
# 4. 清理 1Panel 留下的陈旧标记文件
rm -f /etc/dnat/9443IP
```

两套并存的为什么安全：两条都是 DNAT，先匹配的那条改完地址后，后一条的
匹配条件（端口 / `fib daddr type local`）自然不再成立，**不会双重 DNAT**。
SNAT 重复执行也是幂等的（同一个源地址）。

三个实测细节：

- `dnat.service` 重启后 **flush 真的会发生**，且**只作用于 `ip nat` 表的
  PREROUTING/POSTROUTING**，`table ip flowtls_relay` 完全不受影响
  （重启两次后新表仍完整持有 4 条规则）。这条是独立表方案的核心收益。
- 判断 flush 到底跑没跑，看 handle：`nft -a` 里被重建的规则 handle 会变。
  本次 1Panel 的 34444 拿到新 handle、9443 保留旧 handle → 说明当时
  flush 尚未发生（服务还在 `apt install dnsutils` 阶段，约 3 秒），
  等到日志出现 `更新iptables规则[DONE]` 后 9443 才真正消失。
  **不要用 `sleep 3` 然后下结论**，要盯 journal 里那一行。
- 迁移后要清 `/etc/dnat/<端口>IP` 这类缓存文件，否则下次排查会被它误导。

迁移结果（本跳板机现状）：`9443 → flowtls-relay`（`/etc/flowtls-relay/conf`），
`34444 → 1Panel dnat.service`（`/etc/dnat/conf`），两者互不干扰。

## 167. 客户端入向规则必须挂 input 钩子；`fib daddr type local` 在 NAT 后无效（2026-11-26 北京时间）

现场拓扑（用户的多层环回路由，简化版）：

```
10.0.0.253（开发机）
  -> 10.0.0.1   （傻瓜路由）
  -> 10.0.100.1 （op / OpenWrt，**跑着 flowtls 客户端**）
  -> 192.168.100.1 -> 10.0.0.1 -> 192.168.1.1 -> ...
```

op 是**必经的转发设备**。它自己的客户端连服务端时写的 nft 规则：

```
chain cin_<hash>_8443 {
        type filter hook prerouting priority raw; policy accept;
        ip saddr <服务端> tcp sport 8443 notrack
        ip saddr <服务端> tcp sport 8443 ip id & 65280 == 25856 drop
}
```

25856 = 0x6500 = `HKDF(password)` 派生的 mark。而**服务端发的 SYN-ACK 的
IP ID 就是服务端自己凭据的 mark**（`listener.go` 的
`IPID: RandomIPID(mark)`）。LAN 里另一台机器用**同一个密码**连**同一台
服务端** -> 同 mark -> 它的 SYN-ACK 被 op 在 prerouting 丢掉了。

现象：LAN 侧「握手超时 / context deadline exceeded」，服务端日志里 SYN
到达、SYN-ACK 也发了，两端都说自己没错。

### 第一个错误修法（rev.13）：加 `fib daddr type local`

想当然地认为「伪包目的是本机，加 local 限定就能只作用于本机回程」。
**实测完全无效** —— 带 counter 的两条等价规则计数一模一样：

```
规则 A  ip saddr <服务端> tcp sport 8443                    counter -> 2
规则 B  ip saddr <服务端> tcp sport 8443 fib daddr type local counter -> 2
```

原因：客户端做了 NAT。转发给 LAN 主机的回程包，在 prerouting 阶段
（raw 优先级，**早于 dstnat**）目的地址**仍然是本机 WAN 地址**，
`fib daddr type local` 对本机回程和转发回程同时成立。

### 正确修法（rev.14）：入向规则挂 input 钩子

`input` 钩子只在内核判定「这个包交给本机」之后执行，转发路径根本不进它。
实测对比：

```
流量来源            prerouting 计数   input 计数
LAN 主机（转发）          2              0
本机自己                  9              9
```

所以客户端的「挡内核处理回程包」规则必须挂在 input 钩子上，
并且**去掉入向的 notrack**：
- 它在 input 钩子已经晚于 conntrack，做了也没用；
- 它在 prerouting 时会误伤转发流量（绕过 conntrack -> fw4 判 untracked ->
  forward policy drop）。

去掉 notrack 后伪包回程会被 conntrack 判 INVALID，但本规则在 input 钩子的
raw 优先级（-300）就丢掉了包，早于 fw4 的 filter 链（0）；AF_PACKET 更是
在 netfilter 之前就取走了数据，收包不受影响。fw4 的 input 本身是
`policy drop`，多一层兜底。

**服务端侧相反，`fib daddr type local` 要保留**：服务端不做 NAT，
转发流量的 daddr 不是本机，local 判定有效（软路由上做服务端时确实需要）。

### 排查要点

1. **两端日志都说正常、服务端能看到 SYN 却没有 SYN-ACK 回来时，先查
   中间设备的 prerouting/input**，不要只盯两端。
2. 用 `fib daddr type local` 之前先想清楚：这台设备做 NAT 吗？做 NAT 就无效。
3. `nft list` 把数值渲染成**十进制**（`ip id & 65280 == 25856`）。写脚本
   按 `0x[0-9a-f]+` 去正则抠 mark 会全部失败，导致「只 flush 不重写」——
   链被清空、客户端失去 RST 防护。改规则务必先 dump 再逐条构造。
4. 用 counter 做二分：先只计数不 drop，确认规则到底命中哪些包，再决定
   drop 条件。这一轮就是靠 counter 才发现 `fib local` 完全没有区分能力。
5. 这类规则**写后不清理**，客户端关了规则还在。排查时先
   `nft delete table inet flowtls` 再复测，能一刀切掉所有嫌疑。

## 166. 去掉用户名，凭据收敛成 password / passwords（2026-11-26 北京时间）

需求来自真实部署：**多台设备要共用一个默认密码**。原来的 `users[]`
形态有两个毛病：

1. `name` 被当成「用户」来理解，但服务端从来只有凭据——线上只传
   `HKDF(password)` 派生的 authID，`name` 连日志之外没有任何用处。
   多一个字段就多一处「填了以为有用」的误解。
2. `newUserTable` 以 authID 为 map key，**重复密码会静默覆盖**前一条：
   `t.byAuthID[c.AuthID()] = &userEntry{...}`。症状是「配了 5 条、
   启动日志说只有 4 条」，而且不说少的是哪条。
   而「共用一个默认密码」最常见的误用就是把同一条密码复制成多行。

现在的形态：

| 写法 | 含义 | 状态 |
|---|---|---|
| `"password": "x"` | 一条凭据，**支持任意多个客户端共用** | 推荐 |
| `"passwords": ["a","b"]` | 每条一条凭据，各自派生 authID 与 mark | 推荐 |
| `"users": [{"password":"x"}]` | 等价于 `passwords`，`name` 被忽略 | 已废弃，仅为兼容 |

- 三者**互斥**，同填报错。判断收在 `flowtls.NormalizePasswords` 一处：
  `sing-box check` 走 option 层、真正启动走传输层，两份规则一旦走偏就会
  出现「check 通过但起不来」。
- **重复密码直接报错**，不再静默去重。空元素也报错（空密码 = 谁都能连）。
- 日志里的身份标识改为 `u` + authID 前 4 字节（形如 `u3f1c2d4`）：
  跨重启稳定、不额外汇漏（authID 本来就明文在首包里）、
  且语义正确——它标识的是**凭据**，共用一条密码的设备天然同名。
- `Listener.Users()` → `Credentials()`，启动日志「用户 N 个」→「凭据 N 条」。
  它数的是密码条数，不是在线设备数。

配套改动（都在这轮里）：

- `option.FlowTLSInboundOptions` 增加 `passwords`，`users` 保留但标记废弃。
  **不能删** `users` / `name` 字段：sing-box 以 unknown field 拒绝启动，
  删了会让所有旧 `server.json` 起不来（`max_cwnd` 是同一个道理）。
- PassWall 节点表单删掉「认证方式」与「用户名」：前者从未影响生成的配置，
  后者不会发送；密码提示改成一条 **FlowTLS 专属**的 DummyValue 只读行。
  **不能直接改共享的 `password` 控件说明**：那是 `1_sing-box.lua` 给所有
  sing-box 协议共用的同一个对象，我们的措辞里有「IP ID 标记」这种
  FlowTLS 专有名词，改它会弄脏 hysteria2 / vless / trojan 的界面。
- `luatest.lua` 的假 CBI 曾忽略 `Section:option` 的 class 参数，只调
  `mkopt`，于是「控制器传进来的 class 是否被用上」这件事根本没被测到——
  `DummyValue` 那条分支就这样静默失效过一次。现在改成与真实 CBI 一致：
  `option(self, ...)` 委托给值对象构造，并用 `package.preload` 注入假
  `luci.cbi` 把那条分支真正跑到。
- `ftserver` 的 `-password` 改为可重复（每次一条凭据），便于联调多密码。

对应单测：`TestCredentialSources`、`TestDuplicatePasswordRejected`、
`TestCredentialIDStable`、`TestMarksMultiUser`。

## 165. 拥塞控制换成 hysteria2 的 Brutal，速率写在 up_mbps（2026-11-18 21:25）

BBR 在常年 15% 丢包的链路上会停在 recovery，窗口被减到 4 个包，
吞吐掉到 1~3 Mbps，直播就卡。换成 `sing-quic/hysteria/congestion.BrutalSender`，
和 hysteria2 客户端、服务端调用的是同一个函数，没有自己改参数。

配置与协商（和 hysteria2 同一公式）：

- `up_mbps`：本端发送上限。`down_mbps`：本端接收上限。单位 Mbps。
- 省略或 0 = 1000（千兆）。换算 `mbps * 1_000_000 / 8` 字节/秒。
- QUIC 握手后客户端开一条流，带上自己的 down，服务端回自己的 down。
  发送速率 = min(本端 up, 对端 down)。对端回 0 或更大，就用本端 up。
- hysteria2 把这两个数放在认证请求的 HTTP 头里。flowtls 没有那次
  HTTP 认证（第一条流就是代理流），所以用一条专门的 QUIC 流，公式不变。
- 旧的 `max_cwnd` 仍能解析，Brutal 不读。删掉这个字段会让旧配置
  以 `unknown field` 拒绝启动（2026-11-18 21:21 新加坡就这样挂过）。

Brutal 自己的常数不要动：送达率低于 0.8 就按 0.8 算
（丢包超过 20% 不再加码，最多补到 1.25 倍）。这是它的实现，不是我们加的上限。

服务端必须谈完再装 Brutal。谈妥前按本端 up 发，会在「客户端 down 更小」
的那几秒超发。hysteria2 也是认证响应回来之后才 `NewBrutalSender` 一次。

这条流是 rev.11 起才有的。rev.10 客户端连 rev.11 服务端，服务端等 8 秒
收不到带宽帧就关掉连接。两端要一起换，不能只升一边。

**带宽要按实际线路填，不是一律千兆。** 填大了 Brutal 就按那个速率往外打，
链路撑不住时丢包会集中在瓶颈队列上。2026-11-18 两台分别是千兆与 300M，
客户端对应节点也按 1000 / 300 分开填。

**管 154 只能走 `ssh -J`。** 直连它的 22 端口在国内出口会连接超时；
从跳板直连又是 `Permission denied (publickey)`——跳板的密钥没进 154 的
authorized_keys。正确姿势是 `ssh -J root@<跳板> root@154...`：
TCP 走跳板，认证仍用本机密钥。scp 同理加 `-J`。

## 164. 卡顿先分「链路丢包」还是「我们丢流」，用 ICMP 对照（2026-11-18 20:00）

用户反馈看 Twitch 直播「有时候卡一下」。按下面顺序排，十分钟能有结论。

### 第一步：确认是不是我们中止了流

这一步能直接排除 8 秒零进展那套逻辑。服务端 `log.level: debug` 时：

```bash
journalctl -u sing-box --since "13 min ago" --no-pager \
  | grep -cE "放弃该流|零进展"                 # 应为 0
journalctl -u sing-box --since "13 min ago" --no-pager \
  | grep -c "connection \(download\|upload\) finished"   # 正常结束数
journalctl -u sing-box --since "13 min ago" --no-pager \
  | grep -E "connection (download|upload) closed:"       # 应为空
```

2026-11-18 19:52 实测：267 条流全部正常结束，中止 0、带错误 0。

### 第二步：看隧道自己的丢包和 RTT 形状

`QUIC 路径统计` 每 2 秒一条：

```bash
journalctl -u sing-box --since "13 min ago" --no-pager | grep "QUIC 路径统计" | tail -6
```

判据是**丢包率与 RTT 抖动的关系**：

| 形状 | 含义 |
|---|---|
| 丢包高 + RTT 最大值远超最小值 | 队列溢出（拥塞），可以对症限速 |
| 丢包高 + RTT 几乎不动（max−min < 5ms） | 策略丢弃/链路随机丢包，任何协议都躲不掉 |

实测 19:57：`loss_pct=15`，RTT min 74ms / max 78ms —— 典型第二种。

### 第三步：ICMP 对照，这一步才是决定性的

在同一台客户端上 ping 服务端，用**同样的路径**测原始丢包：

```bash
ssh root@10.0.100.1 'ping -c 40 -q "$FLOWTLS_SERVER"'
```

实测：ICMP 丢 25%，隧道自报 12~15%，两者同量级。
**ICMP 不是伪 TCP，它也不通我们的代码路径**，所以丢包与协议是否被识别无关，
就是链路在丢。两台服务端同时测都丢 17~25%，说明损失共用在客户端出口。

反过来，如果 ICMP 几乎不丢而隧道丢得多，才要去查我们自己（伪包被中间设备
针对、MTU 不对、收包缓冲不够）。

### 第四步：确认客户端没有积压

只测客户端出口的套接字队列，不动正在看的流：

```bash
ssh root@10.0.100.1 'netstat -ant | awk "/:2001 /{r+=\$2; s+=\$3; n++} END{print n, r, s}"'
```

60 次采样 Recv-Q 全 0，说明数据一进来就交给浏览器了，
卡的是「数据没到」，不是「到了没人读」。

### 结论模板

四步都对上就写「链路丢包，非实现问题」，并给两个可操作建议：
降画质让码率离开瓶颈，或换时间/线路。不要改代码——
20% 丢包下任何协议都会卡，改窗口、改拥塞算法都变不出带宽。

## 163. 本地侧不读时，超时要加在被写的那一端（2026-11-18 01:50）

01:30 的写超时只覆盖「QUIC 流的 Write 堵在流控上」。
01:28 的卡死不走那条路：

```
01:28:29  5 条连接收队列合计约 4.7MB，发队列 0
01:28:57  峰值约 6.0MB
01:30:11  自己清空，全程约 100 秒
```

数据已经在本机内核里。relay 的下载拷贝是 `Copy(本地入口, QUIC 流)`，
浏览器不读时堵的是**本地连接的 Write**，堵在内核发送缓冲，
QUIC 流的 `Read` 和 `Write` 都不会再被调用。
所以把超时加在 `StreamConn.Read` 上是没用的：那一次 Read 根本不会发生。

超时只能加在真正被写的那一端：

- 客户端包本地入口（浏览器）；
- 服务端包 dial 出去的目标。

`route/conn.go` 只做类型断言，协议自己决定怎么包。
一次写入有字节出去就当成功，避免再把慢但活着的下载误杀
（第 161 条）。超时后 `Close` 这一条流，`CancelRead` 归还窗口。

## 1. quinn-proto 0.11.19 的 poll_transmit 会追加写 buf

`Connection::poll_transmit(now, max_datagrams, &mut buf)` **不会清空** buf。
循环排空时必须每次 `buf.clear()`，否则 buf 无限增长，加密越来越慢，
表现为主线程 100% CPU、看起来像死循环。

## 2. quinn-proto 0.11.19 没有 Endpoint::poll_transmit

0.11.19 把发送逻辑放在 `Connection` 上：
`conn.poll_transmit(now, 1, &mut buf)`，返回 `Transmit { size, destination, .. }`，
数据在 buf 里。`Endpoint` 只负责分发入向报文。

## 3. iptables u32 的位偏移

匹配 IP ID（IP 头偏移 4，2 字节）必须写：
```
-m u32 --u32 "4&0xFFFF0000=0xF1070000"
```
写成 `4&0xFFFF=0xF107` 取到的是 Flags/Frag，规则永远不命中。

> 后续变更：运营商 NAT 会把 IP ID 改写为 `0x0000`，该规则在真实链路上已失效。
> 现在改为按 TCP wscale 匹配：`--u32 "46&0xFFFFFFFF=0x03030C01"`（详见第 22 条）。

## 4. raw 表里不要用 conntrack INVALID

`iptables -t raw -A PREROUTING ... -m conntrack --ctstate INVALID -j DROP`
会误伤正常 SYN，导致同端口真网站 TLS 握手失败。
正确做法：所有伪造包 IP ID 用固定魔数，只 DROP 魔数包。

## 5. AF_PACKET 与 netfilter 的顺序

AF_PACKET 在 netfilter 之前收包，所以 iptables DROP 不影响 raw socket 收包。
这正是「内核看不到、我们能看到」的实现基础。

## 6. raw 层不能替所有 SYN 回 SYN-ACK

如果对正常浏览器的 SYN 也回 SYN-ACK，会和内核的真 SYN-ACK 打架，
客户端可能选中伪造的那个 seq，TLS 握手直接失败。
必须同时满足：IP ID == 魔数 && flags 含 SYN && 载荷为空。

## 7. NAT 需要完整三次握手

只发 SYN 就发数据，NAT/conntrack 会停在 SYN_RECV，服务端的数据包可能被丢弃，
表现为 QUIC 反复 PTO、首字节延迟十几秒。
服务端 SYN-ACK 的 seq 必须与后续数据 seq 连续，客户端收到后要回一个纯 ACK。

## 8. 跨境丢包必须用 BBR

Cubic 在 4-7% 随机丢包下窗口反复减半到 3-4KB，吞吐只有 20KB/s。
quinn-proto 0.11.19 自带 `congestion::BbrConfig`，开启后 10MB 下载 1.6MB/s。
配置方式：`transport.congestion_controller_factory(Arc::new(BbrConfig::default()))`。

## 9. 服务端 1 核要注意运行时

tokio multi_thread 默认 worker = CPU 核数。1 核机器上主 future + outbound 任务
共享一个 worker，重负载时会互相等待。必要时设置 `worker_threads(2)` 或减少日志。

## 10. 同机测试

同机跑客户端和服务端时：
- 服务端 raw socket 不能绑定固定网卡，否则收不到 loopback 包。
- 服务端回包源 IP 必须用「收到报文的目标 IP」，不能用探测外网得到的 IP。
- 客户端 iptables 规则 `--sport 44300 --tcp-flags RST RST -j DROP`
  用来屏蔽内核对伪造连接的 RST。

## 11. 直播卡顿排查路径

现象：看直播偶尔卡顿重载。按以下顺序排查：

1. `grep -E "连接已建立|连接断开" 客户端和服务端日志`：确认 QUIC 是否掉线重连。
2. `grep "路径统计"`：看 rtt / cwnd / lost 趋势。lost 持续增长且 cwnd 剧烈波动，说明重传多。
3. `ping 服务端`：ICMP 0% 丢包但 QUIC lost 高，说明是突发流量下的中间设备丢包或 PTO 误判，不是链路完全不通。
4. `netstat -s | grep "outgoing packets dropped"`：客户端该计数暴涨说明内核对每个服务端包回 RST。
   解决：客户端加 INPUT 规则 DROP 魔数包（AF_PACKET 仍在 netfilter 之前收包）。
5. `/proc/net/packet` 的 Rmem 持续大于 0：AF_PACKET 接收队列积压，需要调大 SO_RCVBUF 或多线程收包。
6. 服务端 `free -m` / `dmesg | grep -i oom`：排除 1GB 小内存 OOM。

## 12. 单轮排空要有上限

BBR 窗口可能到几 MB，一次 `drain_transmits` 发上千个包会长时间占住事件循环，
入向 ACK 在 channel 里积压，RTT 虚高、PTO 误判丢包。
每轮最多发 64 个包，剩余交给下一次 tick，吞吐不受影响。

## 13. BBR 在多流 + 高丢包下会放大丢包

Twitch 网页会开 40+ 条连接，全部复用一个 QUIC 连接。BBR 的带宽估计会把重传也算进去，
形成正反馈：丢包 → 重传 → 带宽估计↑ → cwnd↑ → 更多丢包。实测 cwnd 冲到 15MB，
重传率 50%，cwnd 在 94KB~15MB 间漂移，视频分片下载时快时慢。

固定窗口控制器（src/quic/steady.rs）更稳：丢包不减窗，只靠 QUIC 重传兜底。
窗口实测：768KB → 丢包 18%/单流 2.06MB/s；1MB → 24%/1.89MB/s；3MB → 69%/1.14MB/s。
直播场景取 1MB。

> **后续演进（最终版已推翻本条的部分结论）**：
> 这是 Rust 中期加 `steady.rs`（固定窗口、丢包不减窗）时的记录。
> 最终版删掉了 `steady.rs`，改用 **BBR + 窗口上限**（`src/quic/capped.rs`
> 的 `CappedBbr`）——因为「丢包不减窗」在真正的拥塞下会把链路打爆，
> 而 BBR 的自我修正能力更强，只要把上限钳住就能避免正反馈。
>
> 所以本条「多流会放大丢包」的现象仍然成立，但**处置方式变了**：
> 不是换成固定窗口，而是钳住窗口上限（`net.max_cwnd`），
> 让 BBR 在这个上界之下自由调整。Go 版按最终版的 `CappedBbr` 移植，
> 见第 79、80 条。

## 14. FakeTCP 必须带 TCP 窗口缩放

SYN/SYN-ACK 如果不带 WS 选项，窗口字段只有 65535，而 QUIC 在 250ms RTT 下
在途数据可达几百 KB。中间设备（运营商/防火墙）会按 TCP 窗口语义校验，
把超出窗口的包直接丢弃，表现为“ICMP 0% 丢包但 QUIC 重传 50%”。

修复：`src/faketcp/packet.rs` 的 `SYN_OPTIONS` 带 MSS + SACK + WS。
shift 至少 7（8MB），实际取 12（256MB），避免 BBR 窗口超过它。

验证方法：同链路用内核 TCP 下载大文件对比。实测内核 TCP 265KB/s，FakeTLS 2.2MB/s，
说明丢包主要是链路客观条件，QUIC 重传已经抄底，不是 FakeTLS 实现问题。

## 15. 拥塞窗口：已改为自适应（旧的环境变量已移除）

早期版本用 `FLOWTLS_CWND` 环境变量调固定窗口，现已**删除**。
当前由两端每 2 秒按实测丢包率自动调整：

```
丢包 > 20% → 窗口 × 0.90；< 5% → × 1.20；范围 1.5MB ~ 8MB
并受 quinn MAX_CHUNKS=1024 约束反算安全上限（见第 23 条）
```

配置里的 `net.max_cwnd` 仅作为自适应起点，不决定最终窗口。
观察方式：日志里的 `loss_pct`（本周期丢包率）和 `win_cap`（当前窗口上限）。

## 16. hysteria2 的 QUIC 参数参照

官方默认（Full-Server-Config）：

```yaml
quic:
  initStreamReceiveWindow: 8388608   # 8MB
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520     # 20MB
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false
congestion:
  type: bbr          # 默认 BBR，另有 reno
  bbrProfile: standard
```

对应 quinn-proto：
- `stream_receive_window(8MB)`
- `receive_window(20MB)` / `send_window(20MB)`
- `max_idle_timeout(30s)` / `keep_alive_interval(10s)`
- `initial_mtu(1340)`（hysteria 默认 1200，我们实测路径支持更大）
- `congestion::BbrConfig`

hysteria 还有 Brutal 控制器：固定速率 + 丢包时提高发送速率补偿，
需要用户配置带宽。效果类似“掠奇带宽”，可考虑后续实现。

## 17. 443 端口对伪造 TCP 更严格

实测：客户端到服务端 443 的伪造包全部发不出去（客户端 tcpdump、服务端 tcpdump、iptables 计数均为 0），
而同一套代码换 8443 正常。用独立 Python raw socket 复现，确认是客户端出口设备对 443 的 TCP 检查更严格。

结论：不要把 FakeTCP 伪装端口设成 443；即使设了，也可能在客户端侧就出不去。
选 8443、9443 等非常规 HTTPS 端口反而更容易通过。纯 UDP 的 hysteria 不受此限制。

服务端的 openresty 是 Docker 容器（1Panel-openresty），`systemctl` 管不了，
停/启要用 `docker stop/start 1Panel-openresty-CIc2`。

## 18. 原生 BBR 在跨境高丢包链路上会窗口失控

现象：跑一段时间后「突然连不上」，但两端进程都在、QUIC 连接也活着（服务端持续回 ACK），
只是所有请求 10 秒超时。

判据：
- 服务端 `cwnd` 远大于带宽时延积（曾到 17855959 = 17.8MB，68ms RTT 下约 2Gbps）。
- `lost / sent` 超过 50%，且 `sent` 只有每秒 2~3 包（全是 PTO 单包重传）。
- 客户端 `lost` 很小，说明上行不丢、下行被打爆，是非对称故障。
- 服务端出站正常（能发 SYN 并收到 SYN-ACK），但回程数据发不出去。

原因：BBR 按「被 ACK 的字节 / 时间」估计带宽，高丢包时 ACK 聚合会让估计值虚高，
cwnd 一路膨胀，超过物理端口后在瓶颈处排队丢包，形成「越丢越发、越发越丢」的死循环。

修复：`src/quic/capped.rs` 的 `CappedBbr` 只把 `Controller::window()` 截断到上限，
其余全部委托原生 BBR。quinn 的 pacing 由 `window / RTT * 1.25` 推导，
所以钳窗口等于同时钳速率，不用改 quinn 源码。

调参：`FLOWTLS_MAX_CWND`（字节，默认 1MB）。链路稳定后若能跑满可调大，
丢包仍高则调小（512KB / 384KB）。

重启两端后 `cwnd` 会重置，所以「重启就好」本身就是这个故障的特征之一。

## 19. FakeTCP 没有内核 TCP 的流控，事件循环必须批量收包

现象：speedtest 上传时上传显示 0、随后整条连接卡死，两端 cwnd 顶满，服务端发包降到几包/秒。

原因：FakeTCP 用 AF_PACKET 收包后送进 tokio 单事件循环，主循环原来每轮只处理 1 个包。
上传测速时包速率从几百/秒涨到几千/秒，channel（当时是 unbounded）迅速积压，
QUIC ACK 延迟到秒级，客户端 PTO，吞吐归零。这正是「没有内核 TCP 流控」的代价：
内核有接收窗口和软中断分发，我们必须自己在应用层做背压和批量处理。

修复要点（`src/server.rs` / `src/client.rs`）：
- 收包 channel 用有界的 `tokio::sync::mpsc::channel(8192)`，收包线程用 `blocking_send`。
  满时阻塞，由内核 socket 缓冲兜底丢包（QUIC 重传），内存不会无限涨。
- 主循环每轮把 `try_recv` 能取到的包一次处理完，上限 256 个；`action_rx` 同样批量。
- 流表要清理：服务端之前从不删流，直播/测速跑久了 `pending` 会一直累积（RSS 曾到 77MB）。

判断指标：服务端 `sent` 每秒只有几包 + 两端 cwnd 顶满 + 客户端 `lost` 很小，
就是「处理不过来/窗口过大」而非链路丢包。

## 20. 云厂商 NAT 后面的机器不能用 FakeTCP

实测：ARM 机器 新加坡 ARM 服务器（Debian 11，内网 服务端内网地址，公网 IP 由云 NAT 映射）。

现象：
- 客户端本地 tcpdump 能看到 SYN 和后续数据包正常发出。
- 服务端 tcpdump **收不到任何 SYN，也收不到 IP ID 0xF1xx 的包**。
- 但真实 TCP（curl https://IP:8443）完全正常。
- 服务端看到的 8443 流量全是别人的真实 TLS 连接（IP ID=0、flags=ACK）。

原因：云厂商的 NAT/安全网关对 TCP 做状态检查（甚至应用层代理）。FakeTCP 的核心就是
「不完成三次握手、SYN 和数据一起发」，这种包会被判为非法 TCP 直接丢弃。

判断方法：
```bash
# 服务端抓不到任何 SYN 就是被中间设备拦了
 tcpdump -i any -nn 'tcp dst port 8443 and tcp[tcpflags] & tcp-syn != 0'
```

结论：FakeTCP 必须部署在**直接持有公网 IP** 的机器上（如香港 香港服务器）。
云主机只给内网 IP + NAT 映射的，换什么端口都不行。

## 21. 高强度伪造流量可能触发运营商临时封禁

实测：短时间内对不可达目标重传大量伪造包后，切回原本正常的香港服务器也不通了：
- 客户端 tcpdump 能看到包发出，服务端收不到，双向无回包。
- 真实 TCP 到同一 IP:8443 仍然正常（200 / 69ms / 0% 丢包）。
- 换源端口（44300/44311/44399）、换目标端口（8443/8444/9443/443）、
  换 IP ID（0xF1xx / 0x1234）、去掉 TCP 选项，全部无效。
- 客户端本机 iptables/conntrack 均正常，包确实出了网卡。

结论：运营商的 DPI/安全设备识别到异常的伪造 TCP 行为后做了全量拦截，
特征是「真实 TCP 能过、raw 伪造包一律不能过」。只能等待封禁过期（分钟到小时级）
或更换出口 IP。压测时不要对不可达目标反复重传。

补充（换 IP 后的实测，江苏移动）：
- 重启光猫后公网 IP 从 客户端旧出口 IP 变为 客户端出口 IP。
- **换 IP 后的第一次伪造 SYN 成功到达服务端**（服务端 tcpdump 看到 客户端出口 IP.14257）。
- 但紧接着的后续测试（换端口/换 IP ID/等 60 秒后单发）全部被拦。
- 同时间真实 TCP（curl 到同一 IP:8443）始终 200。
- 结论：不是静态 IP 黑名单，而是新网关对伪造 TCP 做了**动态识别**：
  首个异常包可能放行，行为一旦被确认就持续拦，封禁时间超过 2 分钟。
- 这也解释了为什么同一套代码在旧网关上能跑 3MB/s，在新网关上连握手都过不去。

对代码的启示：降低失败后的重试频率（指数退避）能减少被识别的机会，
但无法绕过持续流量下的 DPI；FakeTCP 的可用性最终取决于用户所在网关的策略。

## 22. NAT 会改写 IP ID；严格 NAT 要求先完成三次握手

两个坑同时出现，导致换网络后 FakeTCP 完全不可用：

**坑一：IP ID 被改写**
客户端发出的 SYN 是 IP ID=0xF107，服务端收到时变成 0x0000。
后果：`if ip_id == magic` 判断失效、`iptables -m u32` 按 IP ID 的规则也失效，
内核会去处理伪包（回 SYN-ACK/RST），干扰握手。
解决：识别特征改用 **TCP 窗口缩放因子 wscale=12**（`parse_frame` 解析 TCP 选项），
NAT 不会改它；iptables 规则改成 `u32 "46&0xFFFFFFFF=0x03030C01"`。
客户端 INPUT 规则改成按 `--sport 8443 --dport <伪源端口>` 五元组匹配。

**坑二：严格 NAT 丢弃「握手完成前的数据」**
新网关（江苏移动 客户端出口 IP）只放行 SYN，SYN-ACK 之前的 PSH 数据包全丢。
旧网关（客户端旧出口 IP）允许 SYN 和数据同批发。
解决：改成标准三次握手——客户端只发 SYN，收到 SYN-ACK 后再回 ACK、发 ClientHello、放行 QUIC 数据；
服务端收到 wscale=12 的 SYN 立即回 SYN-ACK，`NewConnection` 时复用同一 ISN。
代价仅 1 个 RTT，且只发生在客户端启动建立长连接时，所有请求都多路复用。

判断方法：服务端 tcpdump 能抓到 SYN、抓不到后续数据包，就是坑二；
抓到 SYN 但代码没反应，看收到的 IP ID 是不是 0，就是坑一。

## 23. quinn 的 MAX_CHUNKS=1024 是硬限制，窗口必须跟着丢包率走

quinn-proto 的接收组装器（`connection/assembler.rs`）有硬编常量 `MAX_CHUNKS = 1024`，
表示单流最多容忍 1024 个乱序空洞，**无法通过配置调整**。超过就断连：
`ConnectionClosed(INTERNAL_ERROR, reason=b"too many gaps in stream buffer")`。

判定公式：`窗口(字节) ÷ 包大小(1308) × 丢包率 < 1024`。
- 8MB 窗口 + 30% 丢包 → 1900 个空洞 → 必崩
- 4MB 窗口 + 50% 丢包 → 1600 个空洞 → 也会崩
- 2.5MB 窗口 + 50% 丢包 → 1000 个空洞 → 勉强安全

所以窗口不能写死：本项目用自适应算法，每 2 秒按实测丢包率
反算安全上限 `1024 × 1308 ÷ 丢包率 × 0.6`，再限制在 1MB~8MB。
低丢包（<1%）时能探到 8MB 跑千兆，高丢包（>20%）时自动降到 3MB 以内。

判断方法：客户端日志搜 `too many gaps in stream buffer`，有就是窗口超了。

## 24. 断线自愈：把会话循环与常驻入口分开

客户端必须能在服务端重启、链路中断、QUIC 内部错误后自动恢复。实现要点：
- `run()` 只做一次：解析、raw socket、iptables、收包线程、本地代理入口（1080/8080）。
- `run_session()` 负责单次连接：QUIC 握手 + 标准三次握手 + 事件循环，断线返回 Ok。
- 外层循环指数退避（5s→60s）重连，成功后不重置也无妨（下次断线继续用大退避）。
- `ProxyClient` 持有 `Mutex<Option<Sender>>` 而不是固定 Sender，
  重连时用 `set_tx` 换通道，本地监听不会重复绑定端口。
- `drain_events` 返回 `disconnected` 标志，`ConnectionLost` 后主循环 break。

实测：重启服务端到客户端恢复可用约 5 秒（idle timeout 30s + 退避 5s）。

## 25. recv.read 失败不能静默跳过，必须 stop 释放窗口

quinn-proto 的 `Chunks` 会锁定所在流的组装器。一旦某次 `finalize` 未正常完成，
该流的 `read(true)` 就会永久返回 `IllegalOrderedRead`。

如果代码只是 `continue` / `return` 跳过，后果是：
- 数据不再被读走，流控窗口（`MAX_STREAM_DATA`）永不发送
- 对端在途数据持续堆积（实测客户端 `pending=20.3MB`）
- 内存与延迟一起上涨，但 CPU 和 rx_queue 都很低，容易误判为“链路问题”

正确做法：读失败时标记流结束并 `recv_stream(id).stop(0)`，
主动释放流控额度，让这个请求失败重试，而不是拖死整条连接。

**注意：stop 不是终点。** quinn 在 `stop` 后仍会继续为这条流投递 `Readable` 事件，
如果每次回调都重新 `read` → 失败 → 再 `stop`，会形成空转：
日志里表现为同一 StreamId 在一毫秒内重复几十次告警，CPU 白白升高，
且窗口释放不彻底（实测客户端 pending 仍会残留十几 MB）。
所以必须给流状态加 `stopped` 标志，置位后在 `read_stream` 开头直接返回。

借用检查小坑：`match recv.read(true) { .. }` 的结果是临时值，
默认析构晚于 `recv`，会报 `recv does not live long enough`；
在 `}` 后加一个分号 `};` 让临时值提前 drop 即可。

## 26. 客户端发送侧必须自己做背压，不能只靠 QUIC 流控

quinn-proto 的 `send_stream().write()` 是同步的，返回 `Blocked` 表示窗口满，
它不会阻塞调用方。如果本地读取任务收到 `Blocked` 后只是把数据堆进 `Vec` 就继续读，
就等于把流控完全失效：本地读多快、内存就胀多快。

实测（8 小时长跑，跨境 100M）：
- 客户端 `pending` 峰值 **125MB**，服务端峰值 80MB，都出现在测速多线并发时
- RSS 随之暴涨到 117MB，但进程不崩、也没有 ERROR，很容易被忽略

正确做法与服务端一致：**在本地 socket 读取处制造阻塞**。

```rust
// ProxyAction 用有界 channel；满时 send().await 挂住
let (action_tx, mut action_rx) = mpsc::channel::<ProxyAction>(1024);

pub async fn send(&self, id: StreamId, data: Vec<u8>) {
    if let Some(tx) = self.sender() {
        let _ = tx.send(ProxyAction::Data(id, data)).await;
    }
}
```

通道满 → `pipe_stream` 的读取任务停住 → 不再 `read` 本地 socket →
内核接收缓冲堆满 → TCP 窗口收缩 → 浏览器/测速端降速。
这就是 hysteria2 靠阻塞式 `Write` 自动获得的效果。

容量选择：`1024 × 16KB ≈ 16MB`，对齐 `max_cwnd` 的 4 倍；
太小（如 256）会把测速多线误杀，太大等于没做背压。

服务端对应位置是 `outbound` 里的 `pending_high_water` 循环，两者缺一不可。

## 27. 日志必须关 ANSI，高频路径不能用 info

`tracing_subscriber::fmt()` 默认开启 ANSI 颜色码。输出到文件后字段名会被包成
`\033[3mrtt_ms\033[0m=`，带来两个问题：

1. `grep 'rtt_ms='` 一条都匹不到，排查时只能肉眼翻几十 MB 日志；
2. 多余转义字节让日志体积膨胀。

修复：`.with_ansi(false)`。只在终端直连时才需要颜色。

另一个坑：**每条数据都打 info**。实测客户端 `收到 QUIC 数据` 8 小时写 44 万条 / 62MB，
格式化 + 写 stdout 的开销在高速传输时不可忽略，且把真正的 WARN 淹没。
原则：数据面日志用 `trace`，只留统计（每 2 秒一条）和状态变为 `info`。

## 28. 换服务器/接管机器时，源码和二进制必须核对版本

症状：客户端日志停在 `已发送 SYN，等待 SYN-ACK`，30 秒后仍然不出现
`三次握手完成`；服务端 `server.log` 里能看到

```
INFO 收到 raw 包 client=x.x.x.x:PORT ip_id="0x0000" flags="0x10" payload=125
INFO 服务端队列统计 rx_queue=0 conns=0
```

包确实收到了、IP/iptables/路由都对，但 `conns` 永远是 0，说明**两端代码不兼容**
（伪包格式或握手逻辑对不上）。

2026-11-12 新加坡机就踩到这个：机器上 `/opt/flowtls-src` 有 9 个文件与本地不一致，
二进制是几小时前编的老版本。核对方法只有比对 md5：

```bash
# 本地
find src -name '*.rs' | sort | xargs md5sum
# 远端
ssh root@HOST 'cd /opt/flowtls-src && find src -name "*.rs" | sort | xargs md5sum'
```

远端没有 rsync，用 tar 走 ssh：

```bash
tar czf - --exclude=target --exclude=.git src Cargo.toml Cargo.lock web \
  | ssh root@HOST 'tar xzf - -C /opt/flowtls-src'
ssh root@HOST 'export PATH=$HOME/.cargo/bin:$PATH; cd /opt/flowtls-src && cargo build --release'
```

注意远端 `cargo` 在 `~/.cargo/bin`，非交互 ssh 的 PATH 里没有，必须先 export。

部署后验证顺序：`pgrep -af "flowtls server"` → `ss -lntp | grep 8443` →
客户端日志出现 `QUIC 连接已建立` → curl 走 SOCKS5 拿 204。

## 29. 高速率下 CPU 打满：先怀疑系统调用，不要怀疑加密

2026-11-12 在 1 核 ARM（Neoverse-N1）千兆机上排查「speedtest 只跑 100Mbps
且服务端 CPU 100%」，结论与加密完全无关。

**加密开销实测（`openssl speed -evp <alg>`，同一台机器）：**

| 算法 | 1024B | 8KB | 说明 |
|---|---|---|---|
| AES-128-GCM | 2404 MB/s | 2531 MB/s | ARMv8 有 `aes` + `pmull` 专用指令 |
| ChaCha20-Poly1305 | 796 MB/s | 818 MB/s | 只有 NEON/AVX2 向量化，无专用指令 |

AES-GCM 快 3.1 倍，但 100 Mbps = 12.5 MB/s，ChaCha 也只占 1.6% CPU。
**两层 AEAD 合计不到 5%，换算法最多省 4%，救不了 CPU 100%。**

所以：`/proc/<pid>/stat` 里 `stime` 远大于 `utime` 才是关键信号。
实测 15260 pps 时 `utime=52 / stime=166` ticks —— 76% 的时间在内核态，
瓶颈是「每包一次系统调用」，不是 CPU 算力。

**三层逐级优化（按收益排序）：**

1. 发送从 `IPPROTO_RAW + IP_HDRINCL` 换成 `AF_PACKET / SOCK_DGRAM`
   - 跳过 IP 层路由、netfilter OUTPUT/POST_ROUTING、MTU 检查、qdisc 排队
   - 加 `PACKET_QDISC_BYPASS`（常量 20，libc 未导出）直交驱动
   - **坑**：`SOCK_DGRAM` 只让内核补以太网头，**不做 ARP**。
     不给目的 MAC 会发成全零地址，包在网关被静默丢弃，
     表现是客户端一直停在「等待 SYN-ACK」。必须自己从 `/proc/net/arp`
     取下一跳（默认网关）MAC，邻居表空时先用 UDP 包触发一次 ARP。
   - 效果：同 65 Mbps 下服务端 CPU 73% → **10.6%**
2. `sendmmsg` 批量发送（一次最多 32 包）+ 复用缓冲池，稳态零分配
3. `poll_transmit(now, 32, buf)` 而不是 `poll_transmit(now, 1, buf)`
   - 传 1 等于每个数据报走一遍完整状态机 + pacing 检查；高速率下
     pacing 每包拦一次，每次唤醒只发一个包，事件循环按包数空转
   - `enable_segmentation_offload` 默认 true，传 N 时 quinn 会把 N 个
     **等长且按 segment_size 对齐**（末包已补齐）的数据报连续写进 buf，
     返回 `segment_size = Some(mtu)`，`size = N × mtu`
   - 我们按 segment_size 切开，逐包加外层 TLS 记录 + IP/TCP 头，
     再一次性 `sendmmsg` 发出。**线上格式完全不变。**

**测速源也很关键**：`python3 -m http.server` 在 1 核机上服务 15 MB/s 就吃掉
小半个核，会把「隧道慢」和「源站慢」混在一起。用 `busybox httpd` 或 nginx
（sendfile）做源。另外 `speed.cloudflare.com` 有 IP 级限流，
连续测几次就 429（Retry-After 近一小时），不要拿它做对照实验。

## 30. 自造 bufferbloat：背压水位不能绑窗口上限，等待不能轮询

调完系统调用后（见第 29 条）8 流跑到 169 Mbps，但服务端 `pending` 一度飙到
**214MB**，紧接着 cwnd 从 8MB 崩到 1.2MB，吞吐掉回 81 Mbps。这是两处叠加的错误：

**错误一：背压水位取了窗口上限的 2 倍。**

```rust
// 错：千兆 8MB → 每流 16MB，12 条并发流就是 192MB
let pending_high_water = cfg.net.max_cwnd * 2;
```

目标 TCP 被读得飞快，QUIC 发不出去，全堆在内存。等 cwnd 一旦放松，
几百 MB 一次性灌进链路 → 瓶颈队列溢出 → 大量丢包 → BBR 大幅缩窗。
正确做法是绑 **BDP** 而不是窗口上限：

```rust
// 对：每流封顶 1MB，100ms RTT 下已足够填满 80Mbps 在途数据
let pending_high_water = (cfg.net.max_cwnd / 4).clamp(512 * 1024, 1024 * 1024);
```

**错误二：等待用固定 sleep 轮询，把吞吐死锁在「一次读量 ÷ 轮询间隔」。**

```rust
// 错：拥塞时吞吐上限 = 16KB ÷ 5ms ≈ 3MB/s
while pending > high_water {
    sleep(5ms).await;
}
read(&mut buf).await;   // 每次只读 16KB
```

实测单流从 125 Mbps 掉到 **20 Mbps**，而且 BBR 看到流量受限会一直待在低速区，
永远爬不出来。改成 `Notify` 事件驱动：`flush_pending` 每归还一批字节就
`notify_waiters()`，等待变成微秒级；50ms 的 timeout 只作兜底。

**错误三（配套）：溢出判断阈值不能低于「一轮批量能推进的量」。**
动作批量是 64 项 × 16KB = 1MB，如果 `pending > high_water * 2`（2MB）就 reset，
正常下载的流会被成批误杀（日志里连续 `重置该流 reason="pending 超过上限"`）。
阈值取 8 倍，同时把批量从 256 降到 64。

修完的结果（同一台 1 核机、同一时段）：
| 指标 | 修复前 | 修复后 |
|---|---|---|
| 8 流吞吐 | 100 Mbps | **174~196 Mbps** |
| 服务端 CPU | 100% | **22%** |
| pending 峰值 | 214 MB | ~18 MB |
| cwnd | 崩到 1.2MB | 稳定在 4MB 上限 |

另外记一笔：`net.max_cwnd` 文档写的是「上限」，但代码只把它当初始值，
丢包率 < 5% 时会按 1.2 倍一路放大到 8MB，用户按小带宽链路设的值完全失效。
已改成真正的硬上限（`upper = upper.min(cfg.net.max_cwnd)`）。

## 31. 跨境链路必须关掉 quinn 的 PMTUD，否则 MTU 会永久塌到 1200

`quinn-proto` 的 `BlackHoleDetector` 用 `BLACK_HOLE_THRESHOLD = 3`：
连续 4 个「可疑丢包突发」（突发内所有包都大于 `min_mtu`，且之后没有更大的包
被 ACK）就判定路径 MTU 变小，把 `current_mtu` 打回 `min_mtu`（默认 1200）。
国际线路丢包 20~50% 是常态，这个启发式**必然误判**。

后果是连锁的：MTU 1200 比 1340 每包少装 140 字节（-10.4%），
包数增加 11.7%，丢包概率上升 → 更容易再次触发 → 永远爬不回 1340。
实测日志里 73 次 `mtu=1200` + 106 次 `mtu=1340`，丢包率 21~51%。

```rust
// 我们的路径 MTU 是自己算的：5 记录头 + 12 nonce + 16 tag + 40 IP/TCP = 1413
// 没有需要探测的变量，PMTUD 只会带来误判
t.initial_mtu(1340);
t.mtu_discovery_config(None);  // 关掉 PMTUD
t.min_mtu(1340);               // 双保险：将来重开也不允许降
```

修复后 50 次采样全部 `mtu=1340`，`loss_pct=0`。

## 32. `ReadableError::ClosedStream` 是正常状态，不是致命错误

```rust
// 错：任何 Err 都当「流卡死」，执行 stop() 并置空 to_tcp
match recv.read(true) {
    Ok(c) => { ... }
    Err(_) => { st.to_tcp = None; conn.recv_stream(id).stop(0)?; }
}
```

`read()` 返回 `Err(ClosedStream)` 的三种情况**全是正常的**：
流已不在接收表、数据已被上一次 `Readable` 读空、或已调用过 `stop()`。
`Readable` 事件会重复投递，所以这条路径一定会走到。

危险在于配套动作：`to_tcp = None` 会让出站任务立刻退出、**目标 TCP 连接被关闭**，
正在下载的流直接被截断。实测 `curl: (18) transfer closed with 203699359 bytes remaining`，
200MB 只能下到 6~8MB。

正确写法：

```rust
Err(ReadableError::ClosedStream) => {}          // 什么都不做，等下一个 Readable
Err(ReadableError::IllegalOrderedRead) => warn!(),  // 编程错误，不杀流
```

真正代表「对端放弃」的是 `Chunks::next()` 返回的 `ReadError::Reset(code)`。

## 33. quinn 的 send_window 是应用层看不见的缓冲，背压必须显式接出来

`pending_bytes` 只统计我们自己 `Vec` 里暂存的数据，
而 quinn 内部还有 `send_window`（默认十几 MB，按**连接**算）的发送缓冲。
目标是本地回环服务时（几百 MB/s），出站任务会先无声地灌满这层，
再灌满我们的 `pending`，最后触发「pending 超过上限」把流 reset。

三个必做：
1. `send_window` 设成 `max_cwnd × 2`（clamp 2~16MB），别留 16MB 默认值；
2. `write()` 返回 `Blocked` **或只写进一部分**时置位 `write_blocked`，
   出站任务的背压等待要同时检查它和 `pending` 水位；
   `Writable` 事件到达时清除并 `notify_waiters()`；
3. `pending_bytes` 要算「从目标 socket 读出、但还没交给 QUIC 的全部字节」，
   **包括还在 channel 里排队的**。漏掉这段等于凭空多出
   `channel_capacity × chunk_size`（1024×16KB≈16MB）的隐形缓冲。

记账要用 `fetch_update` + `saturating_sub`：`reset_stream` 会把计数器清零，
此时队列里可能还有在途数据，直接 `fetch_sub` 会下溢成 `usize::MAX`。

## 34. `finish()` 必须在 pending 清空后调用

```rust
// 错：先 flush 再无条件 finish
flush_pending(c, id);
conn.send_stream(id).finish()?;   // pending 没写完时 FIN 会跑到数据前面
```

FIN 一旦越过还没写出的数据，对端就提前看到流结束。
实测末尾稳定少掉约 1MB —— 正好是一个背压高水位，
`curl: (18) transfer closed with 1014706 bytes remaining to read`。

正确做法：`Fin` 只登记 `fin_pending = true`，
由 `flush_pending` 在 `pending.is_empty()` 时执行真正的 `finish()`。

## 35. 伪装的 8 处可识别特征：抓包对照真实 HTTPS 才看得出来

伪装成 HTTPS 不能只看「有 `17 03 03` 记录头」，TCP 层必须真的像一条 TCP 连接。
用 `tcpdump` 把我们的流量和**同一台服务器的真实 HTTPS**（443 端口）并排对比，
一次就暴露出 8 处差异。按危险程度排序：

### 改造前 vs 真实 HTTPS

| # | 特征 | 真实 HTTPS | 改造前 | 危险 |
|---|---|---|---|---|
| 1 | TCP 时间戳 | 每个包都有 `nop,nop,TS val .. ecr ..` | **一个都没有** | 🔴 最强指纹 |
| 2 | 数据阶段纯 ACK | 有（约 22% 的包） | **0 个** | 🔴 |
| 3 | 窗口值 | 122/128/62636，随缓冲变化 | **恒 65535** | 🔴 |
| 4 | 拆除 | 有 FIN | **0 个**（静默消失） | 🟠 |
| 5 | wscale | 9 | **12**（且这是分流指纹） | 🟠 |
| 6 | SYN 选项 | `mss 1460,sackOK,TS val .. ecr 0,nop,wscale 9` | `mss,sackOK,wscale 12,nop×3` | 🟠 |
| 7 | IP ID | 7700,7701,7702…（16 位递增） | **0xF100~0xF1FF 循环** | 🟡 |
| 8 | 载荷长度 | 受拥塞窗口影响，杂乱 | 11 个包精确 1373 字节 | 🟡 |

**为什么 #1 是致命的**：现代 Linux / Windows / macOS / Android 默认全部开启
`tcp_timestamps`。一条双向传了几万个包、却连一个 TS 都没有的 TCP 连接，
在真实世界里不存在。任何 DPI 一条规则（「连接包数 > N 且 TS 数 == 0」）就能判死。
`openssl`/`curl` 抓包对比 5 秒就能确认。

### 改造要点

1. **每个数据包/纯 ACK 带 12 字节 TS 选项**：`01 01 08 0a <TSval><TSecr>`。
   - `TSval = 随机基准 + 连接已过去的毫秒数`，单调递增（真实栈也是）
   - `TSecr` 回显对端最近一次的 TSval（RFC 7323 要求，不匹配会被中间盒丢弃）
2. **SYN/SYN-ACK 选项改成真实 Linux 的 20 字节布局**：
   ```
   02 04 05 b4            MSS 1460
   04 02                  SACK permitted
   08 0a <tsval> <tsecr>  TS（SYN 的 TSecr 必须为 0）
   01                     NOP
   03 03 09               wscale 9
   ```
3. **延迟确认**：每 2 个数据段回 1 个纯 ACK，或距上次确认超 40ms 兜底。
   不要「每批一个」——实测那样纯 ACK 会占到总包的 **42%**，
   真实 TCP 是 22% 左右，而且每包一次 `Vec` 分配 + `sendto` 把 CPU 抬了数倍。
4. **窗口按真实语义计算**：`(接收缓冲总量 - 未消费字节) >> wscale`。
   16MB 缓冲空载时正好 32768（真实 Linux 在 16MB `tcp_rmem` 下就是这个值），
   有积压时平滑下降，抓包里能看到 32748 / 32751 / 32757 / 32765 / 32768 这种自然波动。
   **SYN 阶段仍用 65535**（缩放因子要 ESTABLISHED 后才生效）。
5. **FIN**：会话结束/断线重连前补一个 `FIN|ACK`（同样带 TS 选项）。

### MTU 要跟着让出 12 字节

每个包多了 12 字节 TS 选项，QUIC 载荷必须从 1340 降到 **1332**：
`1332 + 33(外层) + 20(IP) + 32(TCP) = 1417`，与改造前的 1413 基本持平。
若保持 1340，总包会到 1425，逼近服务端通告 MSS 1400 对应的 1440 上限，没有余量。

### 分流标记的取舍（重要）

TCP 选项全部改回真实值后，iptables 只能在 **IP ID** 上放静态标记。
标记范围**不能随便放大**：iptables 会把这些包 DROP，内核看不到就没有任何响应。
- 高字节固定 0xF1 → 256/65536 = **0.4%** 的普通端口探测会「无响应」
- 高四位固定 0xF  → 4096/65536 = **6%**，异常率高 15 倍，会让探测行为前后不一致

所以刻意保持窄范围。残留特征：单连接 IP ID 以 256 为周期锯齿递增。
彻底消除需要换掉 iptables 的匹配依据（例如把口令派生的 12 bit 放进 SYN 的
TSval 低位、TSecr 保持 0 以符合 RFC 7323），已记入 PROJECT_PLAN。

## 36. 背压记账：只有「真正写进 quinn」的字节才能从水位里扣掉

上传方向的背压很容易做成假的。三条缓冲一个都不能漏：
动作通道、quinn 内部的 `send_window`、我们自己的 `pending`。

```rust
// 错：一进 handle_action 就扣掉整笔
client.inflight.fetch_sub(n, Relaxed);
let Some(st) = streams.get_mut(&id) else { return };
match conn.send_stream(id).write(&data) {
    Ok(m) if m < data.len() => st.pending.extend_from_slice(&data[m..]),  // 数据还在这儿！
    ...
}
```

这样 `inflight` 只反映「通道里还没被取出」的部分，`pending` 完全隐身。
实测 `inflight` 显示 1MB，`pending` 实际堆到 **36MB**，背压等于没做。

正确做法——**只扣 quinn 真正接收的量**：

```rust
match conn.send_stream(id).write(&data) {
    Ok(m) if m == data.len() => { subtract_inflight(client, m); /* 全部收下 */ }
    Ok(m)                     => { subtract_inflight(client, m); st.pending.extend_from_slice(&data[m..]); }
    Err(WriteError::Blocked)  => { /* 一个字节都没收，不扣 */ st.pending.extend_from_slice(&data); }
    Err(_)                    => { subtract_inflight(client, n); /* 流已死，整笔退回 */ }
}
```

`flush_pending` 同理：累加本轮 `accepted`，循环结束后一次性扣。

还有三个容易漏的退账点，漏一个就会永久卡住后续所有流：
- 流被 `streams.retain` 清理时，`pending` 里残留的字节要退；
- `Stopped` 事件清空 `pending` 时，被清掉的部分要退；
- 重连时（`set_tx`）计数器要归零。

扣减一律用 `fetch_update` + `saturating_sub`：清零之后队列里可能还有在途数据，
直接 `fetch_sub` 会下溢成 `usize::MAX`，背压就彻底失效了。

水位取值与服务端一致：`max_cwnd / 4` clamp 到 512KB~1MB。
100ms RTT 下 1MB 已足够跑满 80Mbps，再多只是把数据堆在内存里排队。

## 37. 对端停止时，光把 Sender 置 None 唤不醒等背压的协程

出站任务的读取协程等待的是**原子计数**（`pending_bytes` / `write_blocked`），
不看 channel。所以 `Stopped` 事件里只写 `st.to_tcp = None` 是不够的：
目标 socket 那边不会收到任何信号，协程会一直在水位上等到 30 秒兜底超时。

必须显式给一个「放弃」信号：

```rust
// ServerStream 增加
abandon: Arc<AtomicBool>,

// Stopped 事件 / reset_stream 里
s.pending_bytes.store(0, Relaxed);
s.write_blocked.store(false, Relaxed);
s.abandon.store(true, Relaxed);
s.drain_notify.notify_waiters();   // 唤醒等待者

// 出站读取协程的背压等待循环里
if abandoned.load(Relaxed) { return; }
```

客户端侧对应的是：本地连接被强制关闭时（浏览器取消、`curl --max-time` 退出）
必须发 `STOP_SENDING` + `RESET_STREAM`，否则服务端不知道你不再收了。
`pipe_stream` 在 `join!` 结束后调用 `client.stop(id).await` 即可。

判断修复成功的标志：中断后服务端只打一条
`对端已停止该流，丢弃待发数据 dropped=<水位值>`，
而不是刷 `背压等待超过 30 秒，放弃该流`。

## 38. 分流标记必须来自配置，不能写死在代码里

iptables 需要一个「静态可匹配」的特征来把伪包挡在内核 TCP 栈之外。
TCP 选项在伪装改造后必须与真实 Linux 一致（TS、wscale 9），不能再当指纹，
所以标记只能落在 **IP ID 高字节**上。

**关键：这个值必须从 `faketcp.ip_id_magic` 派生，不能写死。**

```rust
// 错：写死意味着任何 DPI 加一条「IP ID 高字节 == 0xF1」的规则
// 就能一次性命中所有部署。
let mark = 0xF100;

// 对：每个部署的标记不同，检测方必须逐条链路采集学习
let mark = cfg.faketcp.ip_id_magic & 0xFF00;
```

### iptables u32 的右值必须带 `0x` 前缀（差点踩坑）

```rust
// 错：内核解析器是 simple_strtoul(..., base=0)，
// "f1004000" 按十进制解析失败 → 返回 0 → 规则永不命中。
// 症状极具迷惑性：连接能建但一直被内核 RST 打断，
// 日志里看不出任何异常（规则存在、计数为 0）。
let expr = format!("0x4&0xff00ffff={mark:04x}4000");

// 对
let expr = format!("0x4&0xff00ffff=0x{mark:04x}4000");
```

已加单元测试 `server_rule_expr_has_hex_prefix` 锁住这一点。

### 改标记的迁移步骤（已验证）

改 `ip_id_magic` 会同时影响线上一字节和 iptables 匹配式，
**两端必须一起改**，否则内核回 RST、连接永远建不起来：

1. 两端配置改成同一个新值（例如 `0x1E07`）
2. 重启两端；新规则会被自动添加（旧的还在，不影响）
3. 确认连通正常：`curl --socks5-hostname ... https://www.gstatic.com/generate_204`
4. 抓包核对 IP ID 已变成新值：`tcpdump -i eth0 -n -c 4 -v 'tcp port 8443'`
5. **清理旧规则**（这一步才是真正的验证——旧规则删掉后连接仍正常，
   说明新规则独立生效）：

```bash
# 客户端
iptables -D INPUT -p tcp --sport 8443 -m u32 \
  --u32 "0x4&0xff00ffff=0x<旧值>4000" -j DROP
# 服务端
iptables -t raw -D PREROUTING -p tcp --dport 8443 -m u32 \
  --u32 "0x4&0xff00ffff=0x<旧值>4000" -j DROP
```

### 为什么标记范围必须窄

这里 DROP 的包内核看不到，对外表现为「完全无响应」。
标记只固定高字节 = 256/65536 = 0.4% 的端口探测会无响应，与正常丢包率难以区分；
固定高 4 位 = 4096/65536 = 6%，会让探测行为前后不一致，反而更容易暴露。
所以牺牲一点可见性换探测行为一致。

残留的「单连接 IP ID 以 256 周期锯齿递增」需要换掉 iptables 匹配依据才能消除
（把口令派生的 12 bit 放进 SYN 的 TSval 低位、TSecr 保持 0 以符合 RFC 7323）。

## 39. 正常路径的日志不要用 WARN

`对端已停止该流，丢弃待发数据` 在浏览器取消下载、`curl --max-time` 超时时
**每次都会出现**，完全正常。用 `warn!` 的结果是正常使用就刷屏，
真正的异常被淹没（实测一次 4 流中断刷 14 条）。

判断标准：这条日志在不做任何异常操作时会不会出现？
会 → `debug!` / `info!`；只在真实故障时出现 → `warn!` / `error!`。

## 40. 只看 TCP 层不够：TLS 层有三处一眼可辨的违规

伪装成 HTTPS 时分两个层次检查，缺一个都会被抓：

| 层 | 检查手段 | 典型问题 |
|---|---|---|
| TCP | `tcpdump` 看 flags/options/窗口 | 缺时间戳、窗口恒定、无 FIN |
| **TLS** | 看记录类型序列、ClientHello 结构、长度 | **缺 key_share、CCS 后明文、ClientHello 过小** |

抓真实 Chrome 握手对照最直观：
```bash
tcpdump -i any -n -s 0 -w /tmp/real.pcap \
  'tcp port 443 and tcp[((tcp[12] & 0xf0) >> 2):1] = 0x16'
curl -s -o /dev/null https://www.cloudflare.com/
tcpdump -r /tmp/real.pcap -n -X | grep -oE '1603 01[0-9a-f]{4}'
# → 1603 0106 a3   记录 1699 字节
```

### 坑一：ClientHello 必须含 `key_share`

改造前我们的 ClientHello 只有 74 字节、2 个扩展（SNI + supported_versions）。
缺少 `key_share` 的 TLS 1.3 ClientHello **在协议上根本无法完成握手** ——
服务端拿不到客户端的 ECDHE 公钥，无从派生密钥。
不需要解密，只看扩展列表就能判定「这不是真客户端」。

必须有的 TLS 1.3 扩展：`supported_versions`、`key_share`、`supported_groups`、
`signature_algorithms`。真实浏览器还会有 `ALPN`、`status_request`、
`ec_point_formats`、`psk_key_exchange_modes`、`session_ticket`、
`extended_master_secret`、`renegotiation_info`，以及 GREASE（RFC 8701）。

长度也要对：真实 Chrome 是 1699 字节（带 PQ 混合 key share），
传统浏览器 300~600。**74 字节这个量级在真实世界里不存在。**

### 坑二：ClientHello 后立刻发数据必须声明 `early_data`

我们的设计是「ClientHello + QUIC 数据同批发出」以省一个 RTT。
但 TLS 1.3 里 ClientHello 之后**不允许**出现 ApplicationData，
除非 ClientHello 里有 `early_data` 扩展（0-RTT）。

没有 `early_data` 就是明文可见的协议违规：
「一个没请求 0-RTT 的客户端，发完 ClientHello 立刻发加密应用数据」。

修法：在 ClientHello 里加 `early_data`（空体）+
`psk_key_exchange_modes`（`psk_dhe_ke`）+ `pre_shared_key`（伪造 ticket +
随机 binder）。binder 是随机字节也没关系——DPI 没有 PSK，无法验证真伪。
注意 RFC 8446 要求 **`pre_shared_key` 必须是最后一个扩展**，可以校验。

### 坑三：CCS 之后不能出现明文握手记录

```text
错：16 03 03 ... ServerHello
    14 03 03 00 01 01  CCS
    16 03 03 ... Finished     ← 明文，违规

对：16 03 03 ... ServerHello
    14 03 03 00 01 01  CCS
    17 03 03 ... 加密数据      ← 586 字节随机密文
```

真实 TLS 1.3 在 `ChangeCipherSpec` 之后，所有握手消息
（EncryptedExtensions / Certificate / CertificateVerify / Finished）
都包在 0x17 记录里加密传输。在 CCS 后再看到 0x16 明文是明确的违规信号。

密文用随机字节即可（DPI 无密钥无法验证），但**长度要对**：
一张 ECDSA 自签证书链 + 三个签名结构约 500~700 字节，
发几十字节的"加密数据"同样可疑。

### 回归测试要锁住这些结构

```rust
#[test] fn client_hello_looks_real()        // 长度区间 + 必需扩展 + psk 在最后
#[test] fn server_hello_sequence_is_valid() // 记录类型必须是 [0x16, 0x14, 0x17]
```

## 41. 两端不一致的问题「静默失效」，所以要有机检

这个项目有三处「两端必须一致」的强约束，不一致时的现象**完全指向别处**：

| 不一致项 | 现象 | 第一反应会去查什么 |
|---|---|---|
| `password` | 服务端只看到 `收到 raw 包 ... conns=0` | 握手逻辑、NAT、iptables |
| `ip_id_magic` | 内核回 RST，连接建不起来 | 防火墙、端口、证书 |
| 端口 | 停在「已发送 SYN，等待 SYN-ACK」 | 网络可达性、运营商封锁 |

三条我们都实际踩过（DEVTIPS 28 / 38）。人工排查一次要几十分钟，
而机器检查是毫秒级——所以 `flowtls check` 是必需品而非锦上添花。

```bash
flowtls check --server server.yaml --client client.yaml   # 两端一起查（推荐）
flowtls check --client deploy/client-cn.yaml              # 只查一端
flowtls check    # 自动探测当前目录的 server.yaml / client.yaml
```

设计要点：

1. **只读**。不写文件、不动 iptables，随时可以跑。
2. **退出码有意义**：0=无错误、1=有错误 → 能直接放进 CI / 部署脚本的
   `&&` 链里。
3. **证书要真解析**，不能只 `exists()`：
   路径对但文件是空的时候，服务端会静默回退到自签证书，
   伪装网站从此不被浏览器信任，而进程没有任何报错。
   ```rust
   rustls_pemfile::certs(&mut data.as_slice())   // 真的解析一遍
   ```
4. **查「配置默认值」**：`ip_id_magic` 还是编译默认值时给警告。
   所有没改过配置的部署特征相同，一个通用 DPI 规则就能全打掉（见第 38 条）。

`install-rules` / `check-rules` 也从配置读 magic 了。之前它们硬编码
`0xF107`，改造后 magic 变成配置派生，这两个子命令就静默失效了——
同一个坑换了个地方，说明「常量散落多处」本身就是缺陷源。

## 42. 窗口上限 8MB 现在安全了，但安全的前提是自适应逻辑还在

`net.max_cwnd` 从 4MB 调到 8MB，单流从 109 → 136 Mbps（+25%），8 流 164 → 175。

之前不敢用 8MB 是因为会撞 quinn 的 `MAX_CHUNKS = 1024` 空洞上限而断连。
但那时的根因是 **PMTUD 把 MTU 误降到 1200**（第 31 条）——
包变小 10%，同样窗口下的空洞数增加 11.7%，才超限。MTU 修好后 8MB 就没问题了。

关键：8MB 只是**天花板**，真正生效的上限是自适应的：

```rust
let safe_cap = ((1024.0 * 1308.0) / loss.max(0.01) * 0.7) as u64;
let upper = safe_cap.clamp(1536 * 1024, 8 * 1024 * 1024).min(cfg_cap);
```

丢包 20% → 4.7MB，30% → 3.1MB，1% → 8MB（被 cfg_cap 拦住）。
所以**别在改配置时把这段自适应删掉**，否则高丢包 + 大窗口必然断连。

验证方式：60s 单流 + 30s 8 流并发，检查
`grep -c 'too many gaps'` 必须为 0。

## 43. UDP 就该允许丢包：别用 TCP 的思维写测试和实现

加 UDP 支持时踩了一个典型的思维惯性：**测试脚本要求 20 个包零丢包**，
结果每轮都在第 12~13 个卡 10 秒超时。查了两端日志、加了 debug 日志、
甚至怀疑 `session` 冲突，最后发现是**这条跨境链路 5~10% 的真实丢包**。

UDP 的正确测试方式是：

```python
# 错误：发一个等一个，丢一个就阻塞到超时
for i in range(20):
    udp.sendto(pkt); udp.recvfrom(...)

# 正确：先全发，再按事务 ID 对账，只断言「大部分到达」
for i in range(20):
    udp.sendto(pkt_with_id(i))
got = set()
while time.time() < deadline:
    data, _ = udp.recvfrom(...)
    got.add(parse_txid(data))
assert len(got) >= n // 2
```

同样的思路贯穿实现：

| 位置 | 做法 | 原因 |
|---|---|---|
| 客户端上行 | `tx.try_send()` | 通道满就丢，绝不阻塞 relay 收包循环 |
| 客户端 QUIC 发送 | `datagrams().send(pkt, drop=true)` | 缓冲满丢最旧，新包更值钱 |
| 服务端上行 | `to_target.try_send()` | 目标写不过来就丢 |
| 服务端回程 | `action_tx.try_send()` | 主循环跟不上就丢 |
| 超 MTU | 直接丢 | 不做应用层分片（序号/重组/内存放大都不值得） |

**反过来也有一个陷阱**：`drop=true` 只影响「还在本地排队、没被 `poll_transmit`
取走」的包。已经进 QUIC 状态机的包不会因为后来的包被挤掉——
它们会正常发出去，只是如果链路丢了就真丢了。

## 44. 服务端重启后 30 秒内测 UDP 必然失败（不是 bug）

服务端重启、客户端要等 `max_idle_timeout`（30 秒）才会发现断连。
在这段时间里：

1. 客户端仍认为连接有效，UDP datagram 照常发；
2. 服务端是新进程，`conns` 是空的重建过程中，收不到对应 `ConnectionHandle`；
3. `ServerAction::Datagram(ch, pkt)` 里 `conns.get_mut(&ch)` 返回 None → 丢弃。

**现象**：服务端日志有 `新建 UDP 会话`（说明上行到了），但客户端收不到任何回程。
**这就是「链路断开」的正常表现**，等客户端重连（日志出现 `三次握手完成`）后自动恢复。

排查时可先看 `grep "三次握手完成" /tmp/ft-cn.log | tail -1` 的时间戳，
如果测试跑在这之前，所有失败都是预期的。

**顺带**：`session id` 跨重连不复用也能自愈——因为上行每包都带目标地址，
服务端在新连接上收到第一个包就会重建会话。这是「每包带地址」这个
看似冗余的设计换来的最大好处。

## 45. SYN 只发一次 = 一次丢包就永久卡死（最严重的一次审查发现）

客户端的裸 SYN 只发一次，而且**握手阶段完全不发送 QUIC 包**
（这是对的：严格 NAT 会丢弃 SYN-ACK 之前的包）。
两个事实撞在一起就是死锁：

- 严格 NAT 要求先完成三次握手才能发数据 → 握手期间 `drain_transmits` 被跳过；
- quinn 的 idle 定时器**在首次发包之后**才开始计时 → `handle_timeout` 永远不触发。

结果：**SYN 或 SYN-ACK 任意一个丢了，客户端就永远停在「已发送 SYN，等待 SYN-ACK」**，
进程活着、CPU 为 0、不重连、不报错。实测在这条 5%~30% 丢包的链路上，
一次部署后客户端卡了 2 分 43 秒（最后是手工重启才恢复）。

修法照抄真实 TCP：

```rust
// 1/2/4/8 秒退避重传 SYN，总时长 15 秒就放弃本次会话，交给外层重连
_ = tick(Some(next_syn_at.into())), if awaiting_syn_ack => {
    if handshake_start.elapsed() >= HANDSHAKE_TIMEOUT { break }
    ... 重发 SYN（序号不变，只有 TSval 推进）...
}
```

服务端配套改了一处：**对重传的 SYN 复用原来的 ISN 和 TSval**。
真实栈就是这样（同一个 SYN 重传，回的 SYN-ACK 一模一样）。
如果每次给新 ISN，客户端先收到旧 SYN-ACK、再收到新 SYN-ACK 时，
`peer_seq` 会被两个不同的 seq 来回拉扯，ServerHello 的序号与握手包不连续。

教训：**任何「等一个不会重传的包」的状态机都必须自带超时**。
不能指望下层的 idle/PTO 兜底——它们可能压根没启动。

## 46. 同一个随机函数调用两次 = TCP 序号错位

`build_server_hello()` 里的加密段落长度是**随机**的（512~703，
模仿真实证书链的量级）。服务端原来是这么写的：

```rust
let hello = build_server_hello();
let _ = raw.send(&build_packet(..., payload: &hello));   // 发出去 L1 字节
...
let hello_len = build_server_hello().len() as u32;        // ← 又调了一次，拿到 L2
let data_seq = isn.wrapping_add(1).wrapping_add(hello_len);
```

L1 ≠ L2，于是后续所有数据包的 TCP 序号都偏了 0~191 字节。
功能上不炸（客户端按实际收到的包推导 ack，服务端不看 ack），
但**线上字节流和序号对不上**：中间盒看到一个包的 `seq` 与上一包的
`seq + len` 不衔接，这是伪造 TCP 的硬特征。

修法：用**实际发出去的那个缓冲**的长度。

教训：任何 `build_xxx()` 只要带随机长度，就绝不能再调一次取长度。
写随机化伪装代码时，这类 bug 特别容易溜过去——因为它只在
「长度恰好不同」时才可见，而两边逻辑看起来完全对称。

## 47. TSval 必须整条连接单调，握手包也要算进去

RFC 7323 的 PAWS 依赖 TSval 单调递增，真实栈用的是全局时钟。
改造前服务端是：

| 包 | TSval |
|---|---|
| SYN-ACK | `rand()` |
| ServerHello | `rand()` |
| 之后的数据包 | `TcpClock::new()` 的 `rand() + 毫秒` |

三个独立随机数 → 后一个比前一个小是常态（约 50% 概率），
时间戳类 DPI 一看就知道这不是真 TCP。

另外 `TcpClock.peer_ts` 初始为 0，而 SYN 里的 TSval 明明已经知道了，
导致连接建立后的**第一个数据包 TSecr=0**——已建立的连接上出现 TSecr=0
同样不合理。

修法：`TcpClock::new_at(base)`，握手时生成一次 TSval 贯穿全程。

## 48. UDP 会话「出站任务已退出」必须删表，否则是永久黑洞

服务端每个 UDP 会话一个有界通道 + 一个出站任务。任务会因为
目标解析失败 / ICMP port unreachable / socket 绑定失败而退出，
但主循环的会话表里那条记录还在。原来的写法：

```rust
if let Some(st) = c.udp.get_mut(&session) {
    st.last_active = Instant::now();          // ← 先刷新活跃时间
    st.to_target.try_send(payload)...         // ← 失败了也只是丢包
    continue;
}
```

两个错误叠加：

1. `try_send` 失败（通道已关闭）只当成「队列满」，没删会话；
2. `last_active` 在 `try_send` 之前刷新，**上行包会一直给死会话续命**，
   空闲超时永远不触发。

实测：向一个不可达目标持续发包，`udp_sessions` 永远停在 1。
对客户端来说那条 `(peer, target)` 就是永久黑洞——DNS 目标暂时不可用、
游戏服务器重启，之后再也连不上，直到客户端重启。

修法：区分 `TrySendError::Closed`（删表）和 `Full`（只丢包），
并且只在投递成功后才刷新 `last_active`。

验证方法：`docs/test_udp_recover.py` —— 向服务端的关闭端口连发 8 个包，
修好后 `udp_sessions` 会立刻回到基线（建-死-建-死循环），
修之前会稳定停在 +1。

## 49. tokio 的 `UdpSocket::try_send` 在新 socket 上会返回 WouldBlock

修上面第 48 条时顺手把出站方向的 `sock.send(&d).await` 改成了
`try_send`（理由是「UDP 不该阻塞」）。结果 **UDP 从 2/3 成功率掉到 0/6**。

根因：tokio 的 `UdpSocket::try_send` 依赖 socket 在 reactor 里的可写就绪状态。
刚 `bind` + `connect` 的 socket 还没被 poll 过，直接返回 `WouldBlock`，
而当时那条分支的日志是 `trace!` 级别（默认看不到），于是完全静默。

后果特别隐蔽：会话建好了、`connect` 成功了、日志一切正常，
**但第一个包（也就是 DNS 查询本身）被丢掉**，客户端只看到「发出去没有回音」。

教训两条：

1. **UDP socket 用 `send().await`**。sendto 正常情况下不会阻塞，
   真要阻塞时短暂等一下也比丢包好。
2. **丢包分支的日志不要用 `trace!`**。丢包本来就难查，
   日志级别再压到默认看不见，就等于没有日志。现在这类分支统一用 `debug!`。

## 50. 测延迟必须分三层，否则会把「物理下限」当成「性能回归」

用户报「延迟从 100ms 变成几百 ms」时，如果只测 `curl https://xxx`，
你会永远查不出结论——因为**新建 TLS 连接天然需要 2 个 RTT**：

```
TLS 1.3 握手：ClientHello → ServerHello..Finished   = 1 RTT
HTTP 请求/响应                                      = 1 RTT
合计 = 2 RTT
```

RTT 76.6ms 的链路上，204 的**下限就是 153ms**。看到 200ms 不是 bug。
同理，抓包里 Google 203ms / GitHub 98ms 的差异也不代表谁快谁慢——
GitHub 快只是因为它复用了已建立的连接。

正确的分层测法：

| 层 | 命令 | 理论值 | 说明 |
|---|---|---|---|
| 0 链路 | `ping -c 20 server` | — | 拿到 RTT 基准，**必须做** |
| 1 纯隧道 | `curl http://server_ip:port/`（目标在服务端本机） | **1 RTT** | 隧道的真实成本，等于 RTT 才是实现合格 |
| 2 HTTPS | `curl https://target/generate_204` | **2 RTT** | TLS + HTTP 各一次往返 |

脚本见 `docs/bench.sh`。判据：

- 纯隧道 p50 ≈ ICMP RTT → 实现无额外开销
- 纯隧道 p50 > ICMP RTT + 20ms → 真的有问题，继续查
- 204 p50 ≈ 纯隧道 × 2 → 正常
- p90 明显高于 p50 → 链路丢包，不是代理问题

**丢包的放大效应要算清楚**：每丢一包 = 多等 1 RTT。一次 HTTPS 要 2~3 个
往返，15% 丢包下 `1-0.85^3 ≈ 39%` 的连接会踩到丢包 → p90 从 81ms 跳到 246ms。
这就是「晚高峰延迟变差」的全部原因。

## 51. A/B 对照实验的四个陷阱（我全踩了一遍）

用 git 旧版本编二进制做对照，方向是对的，但我连续五次得出错误结论，
每次都因为实验设计有缺陷。记录下来，下次别再犯：

**陷阱 1：在同一台机器上同时跑新旧两个服务端**

服务端只有 **1 核**。两个实例抢同一核，谁被调度到谁就快，结果随机。
正确做法：**单实例**，测完一个换另一个，用 ABBA 顺序（A→B→B→A）抵消时段漂移。

**陷阱 2：用不同新鲜度的连接做对比**

「新版 96ms」是在跑了几小时、`cwnd` 已被打崩到 5328（4 个包）的连接上测的；
「旧版 78ms」是刚重启的干净连接。**这两个数不可比。**
测量前必须：服务端和客户端都重启 → 先热身若干次 → 再采样。

**陷阱 3：同时跑多个客户端进程**

每个客户端都开 `AF_PACKET / SOCK_RAW` 收**全量**入站包（不绑定网卡），
再在上层做端口过滤。4 个客户端 = 4 倍收包开销，在 1 核机上直接拖慢热路径。
对比测试时只留一个客户端。

**陷阱 4：把「我以为的改动」当成唯一变量**

我看 `quic/config.rs` 的 diff 只有 DATAGRAM 两行，就断定是它。
实际上 `datagram_send_buffer_size` / `receive_buffer_size` 只影响握手期
传输参数（`max_datagram_frame_size`），与每包路径无关。
用 `FLOWTLS_NO_DATAGRAM=1` 做单变量 A/B 后，开/关都是 80~81ms，假设不成立。

**通用做法**：改一个变量 → 只重编 → 两端都重启 → 热身 → 采样 → 再改回去重测。
宁可多花 3 分钟，也不要在一堆混淆变量里猜。

## 52. 实验用的环境变量和配置必须「做完就撤」

为了二分排查加了一个开关：

```rust
if std::env::var_os("FLOWTLS_NO_DATAGRAM").is_none() {
    t.datagram_receive_buffer_size(Some(1024 * 1024));
    t.datagram_send_buffer_size(1024 * 1024);
}
```

实验做完后我重新启动客户端时**忘了不带这个变量**，于是 1080 端口跑的进程
一直带着 `FLOWTLS_NO_DATAGRAM=1`。后果：

- 客户端不通告 `max_datagram_frame_size`
- 服务端认为对端不支持 DATAGRAM
- **UDP 转发静默失效**：不报错、不告警、日志里一个字都没有
- 用户表现为「DNS 能解析（走 TCP 回退）但语音/游戏不通」

比崩溃更难发现，因为进程看起来完全正常。

**排查方法**（进程启动后第一件事就该查这个）：

```bash
# 看运行中进程的真实环境变量
tr '\0' '\n' < /proc/$(pgrep -x flowtls)/environ | grep -E 'FLOWTLS|RUST_LOG'

# 看运行中的二进制是不是磁盘上那个
md5sum /proc/$(pgrep -x flowtls)/exe
md5sum ./target/x86_64-unknown-linux-musl/release/flowtls
```

**规范**：

1. 实验开关一律用 `FLOWTLS_*` 前缀，方便 `grep` 一次查全。
2. 实验结束后**立即**用不带变量的命令重启，并核对 `/proc/PID/environ`。
3. 改配置做 A/B 时，**本地和服务端两边都要记着回退**——我这次就是
   本地 `max_cwnd` 回退成 8MB 了，却忘了它已经被 scp 上传过，
   服务器还停在实验用的 2MB。

## 53. 版本收敛检查清单

每次部署或排查完，用这套流程确认两端一致（防止旧版本/实验残留混进来）：

```bash
# 1. 源码一致（跨架构编译产物 md5 必然不同，所以比源码不比二进制）
find src -name '*.rs' | sort | xargs md5sum | md5sum

# 2. 二进制与磁盘一致（防止改了没重新部署）
md5sum /proc/$(pgrep -x flowtls)/exe
md5sum ./target/x86_64-unknown-linux-musl/release/flowtls   # 客户端
# 服务端同理，在 /opt/flowtls 下执行

# 3. 环境变量干净
tr '\0' '\n' < /proc/$(pgrep -x flowtls)/environ | grep FLOWTLS

# 4. 进程唯一（防止反复启停堆积，多个实例会抢 CPU 并互相干扰）
pgrep -c -x flowtls

# 5. 配置一致（本地仓库 vs 远端实际生效）
ssh root@server 'cat /opt/flowtls/server.yaml' | diff - deploy/server-giga.yaml

# 6. 两端一致性机检
./flowtls check --server deploy/server-giga.yaml --client deploy/client-cn.yaml
```

第 5 步这次就抓到了 `max_cwnd` 2MB vs 8MB 的漂移——
**「本地回退了配置但忘了同步服务器」是最容易犯的错**。

## 54. sing-box 集成：为什么补丁必须压到「新建文件」

集成方案是 `git subtree` 引入上游 + 少量补丁。`git subtree pull` 的冲突面
**完全等于「改动了上游多少个已有文件」**，所以纪律是：

1. 新功能、新常量、新错误 → **全部新建文件**（新文件永不冲突）；
2. 确实得改已有文件时，只做最小的插入，位置选上游极少变动的地方；
3. 绝不改 `route/`、`common/`、`adapter/` 这类核心目录。

第一版把 `TypeFlowTLS` 和 3 个错误分别塞进 `constant/proxy.go`、
`constant/err.go`，得到「4 个文件 28 行」。重构后：

| 做法 | 上游改动 |
|---|---|
| 常量/错误内联进已有文件 | 4 文件 28 行 |
| 常量/错误搬到 `constant/flowtls.go` | **2 文件 7 行** |

剩下必须改的两处：

- `include/registry.go`：inbound/outbound 各插一行注册调用（插在
  `registerStubForRemoved*` 之前，这块上游很稳定）；
- `constant/proxy.go`：`ProxyDisplayName` 加一个 `case`（不加就显示 Unknown，
  只影响日志可读性，属于可接受损失）。

## 55. 未编入的可选协议要注册 stub，不能「干脆不注册」

`include/quic_stub.go` 的做法值得照抄：未开 `with_quic` 时依然注册，
只是构造函数直接返回 `ErrQUICNotIncluded`。

如果改成完全不注册，用户配置里写 `type: hysteria2` 会得到
`unknown inbound type`，他分不清是：

- 「这个构建没开 tag」
- 「type 字符串拼错了」

注册 stub 后错误信息直接告诉你 `rebuild with -tags with_flowtls`，
差一个字的成本，排查时间差一个量级。

## 56. `sing-box check` 会跑完整构造流程，构造函数里不能申请权限

`check` 不是纯静态分析，它执行的是：

```go
box.New(...)  →  各 inbound/outbound 的 NewXxx(...)  →  instance.Close()
```

所以只要在 `NewInbound` / `NewOutbound` 里做了任一有副作用的动作：

- 开 raw socket / AF_PACKET
- 写 iptables
- bind 端口

`check` 就会失败，而且是在**普通用户**下失败——用户会以为配置写错了。

正确切分：

| 阶段 | 允许做的事 |
|---|---|
| `NewXxx()` | 参数校验、结构体组装、纯内存初始化 |
| `Start(StartStateInitialize)` | 创建 client 对象（anytls 就把 `anytls.NewClient` 放这里） |
| `Start(StartStateStart)` | bind 端口、开 raw socket、装防火墙规则 |

这条对 flowtls 是硬约束：它的 inbound 不 bind 内核端口，全部靠 AF_PACKET。

## 57. `sagernet/sing` 版本必须与 sing-box 逐字一致

独立协议 module（如 `flowtls/`）不 import sing-box，但会 import
`sagernet/sing`。这个依赖的版本**不能用 `go mod tidy` 自己选**。

原因：协议适配层要和 sing-box 互相传递 `M.Socksaddr`、`N.PacketConn`、
`buf.Buffer` 等类型。同一个包的两个不同 commit，在 Go 的模块图里是
**两个不同的包路径实例**，类型不兼容，报错是这种：

```
cannot use xxx (variable of type metadata.Socksaddr)
  as metadata.Socksaddr value in argument
```

看起来完全废话，实际是版本不一致。正确做法：

```bash
# 1. 先看 sing-box 锁的是哪个版本
grep "sagernet/sing " sing-box/go.mod

# 2. 把协议 module 钉到同一版本（注意：这是 pseudoversion，
#    随手抄 testing 分支的值会错）
cd flowtls
go get github.com/sagernet/sing@v0.9.7-0.20261023115459-5dc452e537bf
```

我在 P0 就踩了一次：先抄了 `testing` 分支 go.mod 的
`v0.9.7-0.20261110095940-...`，而 `v1.14.4` 锁的是
`v0.9.7-0.20261023115459-...`。

## 58. 版本号用 `1.14.4-rev.1`，不要用 `1.14.4rev`

`1.14.4rev` 看着更简洁，但它**不是合法 semver**：
`rev` 既不是 `-prerelease` 也不是 `+build`，严格解析器直接报错。

三方面板、订阅转换、GUI 的「检查更新」大量用 `semver.Parse` 处理
`sing-box version --name` 的输出，非法的版本号会让这些工具报错或判定异常。

| 写法 | 合法 | 与 1.14.4 排序 | 备注 |
|---|---|---|---|
| `1.14.4rev` | ❌ | 无法比较 | 部分工具报错 |
| **`1.14.4-rev.1`** | ✅ | 低于 1.14.4 | **推荐**，不会被误判成比官方新 |
| `1.14.4+rev.1` | ✅ | 等于 1.14.4 | 很多工具会丢弃 metadata |
| `1.14.5-rev.1` | ✅ | 高于 1.14.4 | 易被误认为官方有新版本 |

第二个区分标志是 `Tags:` 里带 `with_flowtls`——官方构建永远不会有这个 tag。

## 59. 首包头不能「只发一次」，必须「确认可达前每包都带」

多用户需要每条连接的首包带一个明文身份标识（authID）。第一版实现用
`AtomicBool::swap(true)` 做「只发一次」的开关，看起来天衣无缝：

```rust
// 错误写法
let first = !self.sent_first.swap(true, Ordering::Relaxed);
```

**这个写法和 QUIC 的重传语义直接冲突**：Initial 丢包重传时会用新 nonce
重新 `seal`，此时 `sent_first` 已经是 true，重传包就**不带首包头**了。
服务端在新连接状态下收到的第一个包没有 authID → 无法查表 → 静默丢弃。
现象是：

```
客户端：已发送 SYN → 三次握手完成 → 一直重传 Initial
服务端：收到 raw 包，但 conns=0，日志里只有"外层 AEAD 解密失败"
```

而且因为丢包才触发，本地回环永远复现不出来，只在跨境链路上偶发。

正确写法是「等对端证明能解我们的包」：

```rust
// 发送：确认可达前，每包都带首包头
let first = self.send_first_header && !self.established.load(Ordering::Relaxed);

// 客户端收到第一个能解开的服务端包时调用
pub fn mark_established(&self) { self.established.store(true, Relaxed); }

// 服务端：send_first_header = false，established 直接为 true
```

代价是握手期多带 17 字节 × 2~3 个包 ≈ 50 字节，可以忽略。

## 60. 多用户为什么必须带明文索引，不能遍历试解

单用户时代「解密成功即鉴权」很优雅：一把密钥试一次，失败就丢。
多用户下这个方法直接崩：

| 方案 | 每包成本 |
|---|---|
| 遍历 N 把密钥试解 | N 次 ChaCha20-Poly1305（含 poly1305 校验，比 AES 慢） |
| 明文索引查表 | 1 次哈希查找 + 1 次 AEAD |

100 用户时前者是 100 倍 CPU，11000 pps 直接打死单核。而且「试解次数」
本身会随用户数变化，是一个可计时的侧信道。

所以 hysteria2 / anytls / shadowsocks 全都这么做：**线上带一个从凭证派生的
明文标识**（anytls 直接传 `sha256(password)` 32 字节，vless 传 UUID）。
flowtls 的做法是 16 字节 authID。

关键是这个标识**必须用独立的 HKDF info 派生**：

```rust
hk.expand(b"flowtls faketcp aead key v2", &mut key);      // 加密密钥
hk.expand(b"flowtls faketcp auth id v2", &mut auth_id);   // 明文标识
```

如果图省事直接用 `sha256(password)` 当标识，就等于把「密钥的哈希」明文发到
线上了：弱密码场景下拿到 hash 就能跑彩虹表。两个 info 不同 ⇒ 密码学上互相
不可推导，泄露 authID 既推不出密码也解不开数据。

## 61. 明文索引要参与 AAD，否则可以被改成别人的槽位

authID 是明文，攻击者可以篡改（虽然不知道正确值）。如果不把它纳入 AAD，
理论上可以把别人的 authID 抄过来，让服务端拿别人的密钥去解，产生一个
「用错误密钥成功解密」的假象（实际上概率极低，但这是免费防护）。

flowtls v2 的 AAD：

```
首包  = ver(1) | authID(16)
后续  = ver(1)
```

顺便把版本号也纳入 AAD：将来出 v3 时，v2 的包在 v3 下必然认证失败，
不会出现跨版本误判。

两者都不写进报文，因此**零额外开销**——这是 AAD 相比「加字段」的最大优势。

## 62. 跨语言移植必须用「加密向量」验证，单测全绿不代表能互通

把协议从 Rust 移植到 Go 时，最危险的不是编译错误，而是：

```
Rust 单测全过 + Go 单测全过 → 联调时 AEAD 全部解密失败
```

因为两端都只在自己内部自洽。任何一处不一致都会这样：

| 不一致点 | 现象 |
|---|---|
| HKDF 的 salt 或 info 差一个字符 | 两边 authID 不同，服务端查不到用户 |
| AAD 组成不同（首包带不带 authID） | 首包能解，后续包全挂 |
| nonce 是 `prefix+counter` 还是 `counter+prefix` | 全部解密失败 |
| 记录长度字段是否包含 nonce | 解析越界或错位 |

**唯一可靠的验证方式是交换真实字节**：

```
Rust 加密 → 写文件 → Go 读取并解密      （Rust→Go）
Go   加密 → 写文件 → Rust 读取并解密     （Go→Rust）
```

两个方向都要做，单个方向只能证明一半。具体实现见
`docs/interop_check.sh` 与两端的 `interop_*` 测试模块，向量走 `/tmp`。

补充一条：**固定住派生结果**。在测试里打印/断言 authID 的十六进制值，
参数一改立刻红，而不是等到联调。这比只断言「长度是 16」有用得多。

## 63. 独立 Go module 的依赖版本必须服从宿主项目

把协议库抽成独立 module 后，很容易犯这个错：

```bash
go get golang.org/x/sys/unix
# go: upgraded go 1.25.5 => 1.26.0     ← 灾难
```

x/sys 新版本的 `go` 指令会把整个模块的最低 Go 版本顶高，而宿主
（sing-box）锁的是 1.25.5，结果就是**宿主无法编译这个模块**。
pseudoversion 依赖（如 `sagernet/sing`）同理：抄错分支会让类型不兼容。

纪律：

1. 新增依赖后必须检查 `go.mod` 的 `go` 指令有没有被动过；
2. 用 `GOTOOLCHAIN=local` 构建，禁止自动升级工具链；
3. 依赖优先对齐宿主 go.mod 里的版本，而不是 `go get` 的默认最新；
4. 能用标准库就用标准库——本轮 x/sys 的 `Sendmmsg`/`IfNametoindex`
   在当前版本里已不可用，换回 `syscall` 反而更稳。

## 64. 在「可靠的伪造传输」上跑 QUIC，绝不能主动丢包

把 FlowTLS 移植到 Go 时，接收队列最初照搬 UDP 语义：满了就丢。
**这个类比是错的**，而且错得很隐蔽。

QUIC 认为下层是 UDP，会自己处理丢包重传。但我们的下层是伪造 TCP——
socket 层不重传，而 QUIC 又只对「它能感知到的丢包」重传。于是：

```
Session 主动丢包 → quic-go 认为已投递成功 → 不发 ACK、不重传
                                    ↓
                          服务端 PTO 盲猜、重传
                                    ↓
                          重传的包又被丢 → 死循环
```

现象非常难查，因为它**只在数据量达到某个阈值时出现**：

| 场景 | 结果 |
|---|---|
| 单流 20MB | 正常（队列够用） |
| 2 流 16MB | 服务端报 `背压等待超过 30 秒，放弃该流` |
| 单流 40MB | 正常 |

服务端那句「背压等待」具有误导性——它在等客户端消费，而客户端在丢包。
第一反应会去查服务端的窗口/背压逻辑，方向完全错了。

**正确做法：阻塞投递，让背压传导下去。**（`deliver` 里去掉 `default` 分支，
只留 `case s.rx <-` 和 `case <-s.closeCh`）

阻塞的代价是 recvLoop 停读 raw socket、内核缓冲填满后由内核丢包。
那比我们主动丢好：内核丢的是**整个加密 TCP 段**，服务端伪造 TCP 与 QUIC
两侧都能感知并重传；而我们主动丢的是一个已解密、QUIC 已认定送达的数据报，
永久丢失。

## 65. 接收队列容量必须覆盖 QUIC 连接级接收窗口

改成阻塞投递后仍然会丢——只是变成了内核丢包。根因是**队列装不下窗口允许的
在途数据**：

```
队列容量 = rxQueueDepth × 单包大小(≈1340)
若 队列容量 < MaxConnectionReceiveWindow，则窗口一填满队列就阻塞，
进而内核丢包；而 FakeTCP 层没有重传，丢了就是永久丢。
```

quic-go 默认 `MaxConnectionReceiveWindow = 15MB`，所以队列至少要 15MB。
实测演进（**每一步都是压测出来的，不要凭感觉设**）：

| rxQueueDepth | 容量 | 结果 |
|---|---|---|
| 256 | 0.3MB | 单流 20MB 勉强，40MB 失败 |
| 8192 | 10.7MB | 单流 40MB ✓、2 流 16MB ✓、4 流 40MB ✗ |
| 16384 | 21.9MB | 4 流 40MB ✓ |

顺带一条反直觉的结论：**连接级接收窗口不要手动设**。
曾把 `MaxConnectionReceiveWindow` 设成 16MB，结果单流下载到 16.7MB
永久卡死（窗口耗尽后 MAX_DATA 没回补）。保持 quic-go 默认的自适应窗口
反而正常；只有 stream 级窗口需要显式调大（默认初始 512KB，爬升太慢会
触发对端背压判定）。

## 66. quic-go 会剥离 ctx 的取消信号

`transport.Dial(ctx, ...)` 内部第一件事是 `context.WithoutCancel(ctx)`——
**故意不让 ctx 取消生效**，只用它传值。所以：

```go
ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
defer cancel()
conn, err := transport.Dial(ctx, ...)   // 15 秒后不会返回！
```

为什么这个坑在代理场景下特别致命：密码错误时服务端会**静默丢弃**所有
Initial（这正是设计要求的，不暴露探测面），但客户端仍在正常收 SYN-ACK
和纯 ACK，所以握手期永远不会「空闲」，`HandshakeIdleTimeout` 也不触发。
实测必须用外部 `timeout` 命令才能杀掉进程。

正确写法是自己包一层：

```go
ch := make(chan result, 1)          // 容量 1：先超时返回也不会泄漏 goroutine
go func() { c, e := transport.Dial(...); ch <- result{c, e} }()
select {
case r := <-ch:            return r.conn, r.err
case <-ctx.Done():         transport.Close(); return nil, ctx.Err()
}
```

## 67. 包装 net.PacketConn 的三个关闭陷阱

**陷阱一：关闭顺序**。`quic.Transport.Close()` 会等它内部的 reader goroutine
退出，而那个 goroutine 阻塞在我们 `ReadFrom` 上；`ReadFrom` 只有
`Session.Close()` 才返回。所以：

```go
// 错误：功能完全正常，但进程永不退出（exit=124）
transport.Close()
session.Close()

// 正确
conn.CloseWithError(0, "")   // 先发 CONNECTION_CLOSE
session.Close()              // 唤醒阻塞的 ReadFrom
transport.Close()            // 现在才不会卡
```

**陷阱二：`Close` 必须真的关掉底层 fd**。接收协程阻塞在 `raw.Recv()` 的
syscall 上，它不看任何标志位，等的是 syscall 返回。只 `closed.Store(true)`
不会唤醒它，结果是泄漏一个 goroutine 和两个 fd。必须在 `Close` 里
`raw.Close()`。

**陷阱三：`closeCh` 与 `close(rx)` 要分开保护**。两者都用同一个 `sync.Once`
会导致「先到者执行，后者再也关不了」，让另一方永久阻塞。

## 68. `SetReadDeadline` 不能是空实现

quic-go 把握手超时、idle 超时全部挂在 `PacketConn.SetReadDeadline` 上。
空实现等于「永不超时」。

而且返回的错误必须是 `net.Error` 且 `Timeout() == true`：

```go
type timeoutError struct{}
func (timeoutError) Error() string   { return "flowtls: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
```

否则 quic-go 会把正常超时当成致命错误直接关闭连接。

## 69. QUIC DATAGRAM 的接收是单消费者语义

流（stream）可以多个 goroutine 各自 `AcceptStream`，但 **DATAGRAM 不行**：

```go
// 错误：多个 udpConn 各自去读，会互相抢包
for each session {
    go func() { data, _ := conn.ReceiveDatagram(ctx) }()   // 抢包！
}

// 正确：一个分发协程读，按 session 路由
go func() {
    for {
        data, err := conn.ReceiveDatagram(ctx)
        if err != nil { break }
        session, payload, ok := ParseServerDatagram(data)
        routes[session] <- payload      // 投递到对应会话
    }
}()
```

这不是 quic-go 的缺陷，是 DATAGRAM 的设计：它没有「流 ID」那样的
天然分流键，quic-go 只能提供「下一个数据报」这一个队列。

配套的两个细节：

1. **`data` 由 quic-go 复用**，必须拷贝出来再投递，否则下一轮会被覆盖。
2. **投递到会话通道时不能阻塞**（用 `select ... default` 丢弃）。
   一条慢会话如果阻塞了分发协程，会拖死这条连接上的所有会话——
   包括 TCP。这里丢包是正确的（UDP 不重传），阻塞是错误的。

## 70. 上行每包带目标地址：换来服务端无状态

hysteria2 的 UDP 是在会话建立时确定目标，后续包不带地址。
FlowTLS 反其道而行：**上行每包都带**（多 7~9 字节）。

收益不是省代码，而是**服务端完全无状态**：

```
客户端重连 → 服务端是全新连接、会话表为空
          → 第一个带地址的上行包就能自愈，不需要会话迁移协议
```

排查时也省事：一行日志就能看出这个包发给谁，不需要回溯会话创建时的记录。

代价只有每包几个字节。对 DNS（61 字节）来说是 11% 开销，对游戏/视频包
（几百到上千字节）可以忽略。这个取舍在 Rust 版就验证过，Go 侧直接沿用。

副作用是 Go 的 `net.PacketConn` 语义更自然了：`WriteTo(p, addr)` 的 `addr`
可以每次不同——一个 session 同时发往多个目标是被协议支持的，
而不是像 hy2 那样需要「一个目标一个会话」。

## 71. 常用调试命令

```bash

```bash
# 看线上外观：应只有 TCP 8443 + 17 03 03
tcpdump -i eth0 -n -X 'tcp port 8443'

# 看规则命中计数
iptables -t raw -vnL PREROUTING --line-numbers

# 看 QUIC 统计（服务端每 2 秒打印 rtt/cwnd/lost）
grep "路径统计" /opt/flowtls/server.log | tail

# 长跑体检：流表峰值、pending 峰值、累计丢包（字段可 grep，无需去 ANSI）
grep 'rtt_ms=' /tmp/ft-cn.log | grep -oE 'pending=[0-9]+' | cut -d= -f2 | sort -n | tail -1
grep 'rtt_ms=' /tmp/ft-cn.log | grep -oE 'streams=[0-9]+' | cut -d= -f2 | sort -n | tail -1
grep -cE 'WARN|ERROR' /tmp/ft-cn.log

# UDP：看会话数（应随时间自然回落到 0）
grep '服务端 QUIC 路径统计' /opt/flowtls/server.log | grep -oE 'udp_sessions=[0-9]+' | tail -5

# UDP：看完整链路（需要 RUST_LOG=debug）
grep -E 'UDP 已交给 QUIC|收到 UDP 回程' /tmp/ft-cn.log | tail -10
grep -E '新建 UDP 会话|UDP 下行|UDP 回程已交给 QUIC' /opt/flowtls/server.log | tail -10

# UDP 端到端测试（DNS 往返 / session 复用 / 不可达目标 / 控制连接关闭）
python3 docs/test_udp.py

# 延迟分层体检（链路基线 / 纯隧道 / HTTPS，自带判定标准）
bash docs/bench.sh 20

# 临时关闭 DATAGRAM 扩展（用于二分排查延迟/握手问题）
FLOWTLS_NO_DATAGRAM=1 ./flowtls server -c server.yaml
```

## 69. 服务端共享 raw socket：收包只能有一个协程

`flowtls.Listener` 用一个 AF_PACKET socket 收所有客户端的包，按四元组分发。
这带来一条硬规则：

> **服务端模式下，`Session` 绝不能启动自己的 `recvLoop`。**

`Session.recvLoop` 会直接读同一个 raw socket。两个协程抢同一个 fd 时，
包会被随机分给其中一方——属于 A 会话的包被 B 的协程读走后，
`matchPeer` 判定不匹配就丢掉，A 的 QUIC 就永远收不到 ACK。
现象是「TCP 能通但大文件卡死」或「握手随机超时」，极难定位。

客户端侧没有这个问题（一个会话独占一个 raw socket），
所以这段代码在客户端是正确的、在服务端是致命的。

```go
// 服务端：只有 Listener 收包
// ❌ sess.StartReceiver()
transport := &quicgo.Transport{Conn: sess}
listener, err := transport.Listen(tlsConf, quicConf)
```

## 70. 源端口固定会撞四元组：纯 SYN 必须优先于已有会话

客户端为了实现 iptables 精确匹配，会固定 `source_port`（默认 44300）。
结果是：**客户端每重启一次，用的都是完全相同的四元组**。

如果服务端的分发逻辑是「先查已有会话，再判断 SYN」，那么：

1. 旧会话还没到空闲回收时间（默认 120s），仍在表里；
2. 新客户端发来的 SYN 被投给旧会话；
3. 旧会话的序号窗口对不上，当成乱序包丢弃；
4. 客户端一直重传 SYN，直到握手超时——**服务端日志里一条记录都没有**。

抓包能看到：SYN 发了，没回应，1 秒后重传，这才有 SYN-ACK。

正确顺序（`listener.go` 的 `handlePacket`）：

```go
// 1) 纯 SYN 最先判：命中则清掉旧会话，重新握手
if p.Flags&TCPSYN != 0 && p.Flags&TCPACK == 0 && len(p.Payload) == 0 {
    if l.sessionFor(client) != nil { l.dropSession(client) }
    l.handleSYN(client, p)
    return
}
// 2) 已有会话 → 投递
// 3) 都不是 → 首包
```

重传的 SYN 由 `handleSYN` 内部的 `pending` 分支处理，仍然回**一模一样**的
SYN-ACK（ISN 不变），不会打乱客户端状态，也不会误杀已建立的会话。

## 71. 本机联调必须用真实网卡 IP，不能用 127.0.0.1

Go 客户端按**默认路由**选网卡（`defaultRouteInterface()`）。
目标写 `127.0.0.1` 时，路由查询仍然返回 `ens3`，包被送到物理网卡，
loopback 上根本没有——表现是 `handshake timeout` 而服务端毫无反应。

```bash
# ❌ 本机互通
/tmp/ftdial -server 127.0.0.1:8443 ...
# ✓ 用这台机器的真实地址
/tmp/ftdial -server 10.0.0.1:8443 ...
```

另外 `net.mode: none` 时内核没有 8443 的监听 socket，
会对每个伪造包回 RST（抓包能看到 `Flags [R]`）。
这些 RST 不影响已建立的会话，但会让第一条 SYN 的路径更曲折——
正式部署请让 iptables 规则生效（`net.mode: auto`）。

## 72. 删掉一种语言的实现前，先把它的「字节」留下来

Rust 冻结时最容易犯的错是：源码一删，兼容性基线也跟着没了。
之后 Go 侧改 HKDF 参数或 AAD 组成，测试全绿，但再也无法和老版本互通。

正确顺序（本次执行的就是这个）：

1. 用**待删实现**的单测导出黄金向量到 `testdata/`：
   - `wire_v2_rust.bin`（两条记录，120 字节）
   - `wire_v2_rust_authid.txt`（authID，32 字节 hex）
2. 把互通测试从「读 `/tmp` 的临时文件、缺失就跳过」改成「读入库向量、缺失即失败」。
3. 确认 `go test` 在没有 Rust 的环境里也能跑这道门禁。
4. **然后**才 `git rm` 源码。

判定标准很简单：删完之后，`bash docs/interop_check.sh` 必须是 PASS，
而不是「跳过」。

## 73. `set -o pipefail` + `grep -q` 会把成功判成失败

门禁脚本里这个写法是坑：

```bash
# ❌ 偶发假失败
if ! go test ./... | grep -q '^ok'; then echo FAIL; exit 1; fi
```

`grep -q` 命中第一行就退出，管道读端关闭 → `go test` 写入时收到 `EPIPE`
（退出码 141）→ `pipefail` 让整条管道返回非零 → 判定失败。
输出量小的时候靠内核缓冲可能侥幸不触发，所以表现为「有时红有时绿」。

```bash
# ✅ 先落变量，再判断
if ! out=$(go test ./... 2>&1); then printf '%s\n' "$out"; exit 1; fi
printf '%s\n' "$out" | grep -q '^ok' || { echo FAIL; exit 1; }
```

同一原则适用于任何「长命令 | grep -q」的检查。

## 74. iptables 规则的两条硬约束

`flowtls/rules.go` 里有两件事看着能简化，实际一简化就出错。

### u32 的右值必须带 `0x` 前缀

```bash
# ✓ 正确
-m u32 --u32 "0x4&0xff00ffff=0xf1004000"
# ✗ 规则能装上，但永不命中
-m u32 --u32 "0x4&0xff00ffff=f1004000"
```

内核解析器用 `simple_strtoul(..., base=0)`：不带 `0x` 就按十进制解析，
`f1004000` 解析失败返回 0，而左边算出来的是几千，永远不相等。

失败现象极其隐蔽——`iptables -C` 报告规则**存在**，`iptables -L` 也看得见，
但内核照旧回 RST 把连接打断，日志里一点异常都没有。
`TestU32ExprHasHexPrefix` 钉住了它。

### 规则必须在 raw socket 就绪**之后**落地

`NewListener` 的顺序是：申请 raw socket → 成功后才装规则。

反过来（先装规则再申请 socket）会在申请失败时留下一堆指向
「一个根本不会运行的服务端」的 DROP 规则。运维看到启动失败，
通常会立刻重试，不会想到去 `iptables -t raw -S` 清理残留。

客户端顺序相反但不是矛盾：规则必须在**第一个包发出之前**就位
（`Dial` 一开头就装），因为 SYN-ACK 一回，内核就会因为没有对应
socket 而回 RST。

### 规则刻意不删

`ApplyRules` 只在 `-C` 判不存在时 `-A`，任何时候都不 `-D`（与 Rust 版一致）：

- 规则是部署级静态属性，每次启动都一样；
- 进程重启期间规则必须继续生效，否则那段时间内核会回 RST
  打断正在重建的隧道；
- 被 `kill -9` 时不会留下「规则已删」的半状态。

代价是升级/卸载后要手工清。所以 `IPTablesPrint` 模式的输出里
**同时给了安装和卸载两种命令**，复制粘贴即可。

### 验证 auto 的正确姿势

```bash
# 1. 服务端 auto
sudo ./dist/sing-box-1.14.4-rev.1-linux-amd64 run -c server.json   # iptables_mode: auto

# 2. 规则真的进了内核
iptables -t raw -C PREROUTING -p tcp --dport 8443 \
  -m u32 --u32 '0x4&0xff00ffff=0xf1004000' -j DROP && echo 已安装

# 3. 最关键：装了 DROP 之后流量还通吗？
#    AF_PACKET 在 netfilter 之前收包，所以必须仍然 PASS。
#    如果这一步失败，说明规则写宽了（把非伪包也丢掉了）。
/tmp/ftdial -server <IP>:8443 -password xxx -target example.com:443 -insecure

# 4. 幂等：再启动一次，日志应是「新增 0 条，已存在 N 条」，规则只有一份
iptables -t raw -S PREROUTING | grep -c 0xf1004000   # 必须是 1

# 5. 清理
sudo iptables -t raw -D PREROUTING -p tcp --dport 8443 \
  -m u32 --u32 '0x4&0xff00ffff=0xf1004000' -j DROP
```

`ftserver -iptables print|auto` 和 `ftdial -iptables print|auto`
可以不启动 sing-box 就单独验证规则。

## 75. `0xF107` 不是 61687

写文档时把 `0xF107` 手算成十进制 `61687`，实际是 **`61703`**
（`61687` = `0xF0F7`）。

这种错误在 JSON 里完全看不出来——配置合法、能启动、能互通
（两端用同一个错值），但：
- 规则与 Rust 版部署**不一致**，从旧版迁移过来的机器会失配；
- 所有按文档手工配的部署特征都相同，正好破坏「每部署一个标记」的初衷。

抓出它的方式很偶然：`iptables_mode=print` 打出来的表达式是
`0xf0004000` 而不是 `0xf1004000`——**高字节看着不对**。
`print` 模式的价值就在这里：它把内部派生值暴露到了日志里。

教训：文档里的进制换算不要手算，`python3 -c "print(0xF107)"`。

## 76. 校验要分两层：check 能抓到的 vs 只能启动时抓到的

sing-box 的 `check` 只走**构造函数**，不走 `Start`。所以校验放错层，
就变成「配置错了必须真的启动一次才知道」。

| 层 | 该放什么 | 不该放什么 |
|---|---|---|
| `NewInbound` / `NewOutbound` | 纯字符串/结构校验：必填字段、枚举值、互斥关系、URL 格式 | 读文件、bind 端口、申请 raw socket |
| `Start(StartStateStart)` | 读证书、建 listener、申请特权资源 | 那些「不启动也能判断对错」的检查 |

判据很简单：**这条校验需要访问文件系统或内核吗？**
不需要就放构造函数，需要就放 Start。

划错层的真实代价（本次踩的）：`proxy_url` 与 `site_dir` 互斥的检查
一开始只写在 `newMasquerade`（Start 里），结果：

```bash
$ sing-box check -c bad.json
$ echo $?
0        # 静默通过，什么都看不出来
```

两个都填的配置能过 check，启动时才 FATAL。现在拆成
`validateMasqueradeOptions`（纯字符串，构造函数调）+
`newMasquerade`（读文件、bind，Start 调）两层。

同一个教训在 `iptables_mode` 上也适用：拼错 `"atuo"` 必须在
构造函数里就报错，而不是等到 Start 里试着执行 iptables。

## 77. 反向代理做伪装站：rewrite_host 的坑

`masquerade.proxy_url` 指向第三方站点（如 `https://example.com`）时，
如果 `rewrite_host` 保持默认的 `false`，转发会**沿用客户端的 Host 头**，
也就是 `Host: 你的域名:8443`。目标站点不认识这个 Host：

```bash
$ curl -sk https://<你的IP>:8443/
HTTP/2 403        # 403 Forbidden（来自 example.com，不是我们）
```

修法是把 `rewrite_host` 设为 `true`，转发时改用 `proxy_url` 里的 Host。
改完之后实测与直连**逐字节相同**（`cmp` 无差异），这才是伪装站该有的样子。

反过来，回源指向**自己的**站点时保持 `false` 更自然：
自己的站点通常靠 Host 做虚拟主机分流。

响应头里唯一还能看出差别的只有**头的顺序**（Go 的 http 包按 key 排序输出，
nginx/CDN 按自己的顺序）。这属于任何 Go 写的 HTTPS 服务都有的特征，
不针对本项目，先不处理。

## 78. `http.Server.ErrorLog = nil` 不是「不写日志」

直觉上 `nil` 像是「关掉」，实际语义相反：

```go
// net/http 文档：If nil, logging is done via the log package's standard logger.
srv := &http.Server{ErrorLog: nil}   // ← 全部写到 stderr
```

最初的注释写着「不打印任何东西」，代码也是 `ErrorLog: nil`，
注释和代码恰好相反。后果在伪装站上尤其严重：

- 主动探测者会**故意**发畸形 TLS，每次握手失败 `Serve` 都会打一行
  `http: TLS handshake error from <对方IP>: ...`；
- 这些行会冲掉 sing-box 自己的日志；
- 还会把探测者的 IP 落到磁盘上——伪装站最不该做的就是记录访客。

正确写法：

```go
ErrorLog: log.New(io.Discard, "", 0)
```

验证方式（DEVTIPS 里所有「日志噪声」问题都能这么查）：

```bash
before=$(wc -l < server.log)
for i in 1 2 3; do printf 'GARBAGE\r\n\r\n' | timeout 3 openssl s_client -connect <IP>:8443 -quiet; done
sleep 2
echo "$before → $(wc -l < server.log)"   # 行数必须不变
```

教训：Go 里「零值 = 关闭」并不普遍成立。`ErrorLog`、`http.Client.Timeout`、
`tls.Config.MinVersion` 的零值都是**更宽松**而不是更严格，
对安全敏感的组件要逐个查文档确认语义，别靠直觉。

## 79. quic-go 默认是 Cubic，不换 BBR 吞吐会差一个数量级

这是 Go 版移植里**唯一一个「功能全对但就是慢」**的问题，也最容易漏。

### 症状

- 连通性、DNS、UDP、伪装站全部正常；
- 首字节延迟也正常（`generate_204` 150ms）；
- 但大文件速度只有 Rust 版的 1/5~1/10，且**高丢包时段更差**。

这种「都对但就是慢」最难查，因为没有任何报错。

### 根因

quic-go 的默认拥塞控制是 Cubic。Cubic 的假设是「丢包 = 拥塞」，
丢一个包就把窗口减半。跨境链路丢包 20~50% 是物理常态（与拥塞无关），
于是 Cubic 永远在「涨一点、被砍半」之间循环，有效窗口停在很小。

Rust 版用 quinn 的 BBR：BBR 用带宽×RTT 建模，**不把丢包当拥塞信号**，
丢包只影响重传不影响窗口。这正是跨境链路需要的。

### 怎么换

`conn.SetCongestionControl` 是 quic-go fork 的公开 API，
`sing-quic/congestion_meta2` 里有完整 BBR 实现（hysteria2 / tuic 都用它）：

```go
conn.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(
    conn.InitialPacketSize(), congestion_meta2.ProfileStandard))
```

注意两件事：

1. **必须传 `conn.InitialPacketSize()`**，不能用
   `protocol.InitialPacketSize` 包默认值。quic-go 的注释写得很明确：
   播种值偏高时，路径 MTU 发现报告一个中间值会被控制器当成「变小」。
2. **服务端也要换**。只换一端等于「一端 BBR 猛发、另一端 Cubic 丢包减半」，
   有效吞吐取小值。

### 光有 BBR 不够：还要钳窗口

纯 BBR 在跨境链路上会把 ACK 聚合误算成「一次送达大量字节」，
带宽估计被抬高，cwnd 一路涨到 17MB（68ms RTT 下 2Gbps 的 BDP），
而服务器只有 100M 端口。结果是自己把链路打爆，丢包 50%+，
QUIC 只能靠 PTO 单包重传——表现是「连接活着但完全没速度」。

Rust 用 `CappedBbr` 包一层钳上限。Go 侧见 `flowtls/quic/capped_bbr.go`。

### 验证

```bash
# 换之前
curl -o /dev/null -w '%{speed_download}\n' --socks5-hostname u:p@127.0.0.1:1080 \
     https://<server>:8443/100m.bin -k
# 5.25 Mbps

# 换之后（同一台机器、同一条链路）
# 87 Mbps
```

数字差十几倍才算对上。差 10~20% 是链路抖动，不用追。

---

## 80. 想给 quic-go 的控制器「加个上限」，不要重装控制器

`Conn.SetCongestionControl` 看起来是「换一个带新参数的控制器」的完美入口，
但**不能每 2 秒用一次**。

### 为什么

```go
func (h *sentPacketHandler) SetCongestionControl(cc congestionExt.CongestionControl) {
    ...
    installed.firstPacketNumber = protocol.PacketNumber(h.nextCongestionPacketNumber.Load()) + 1
    h.congestion = installed
}
```

装了新控制器后，`reports()` 只把 **`firstPacketNumber` 之后**的包报给它：

```go
func (cc congestionControl) reports(p *packet) bool {
    return cc.injected && p.congestionPacketNumber >= cc.firstPacketNumber
}
```

也就是说新实例看不到「已经在途的包」，带宽估计从零开始。
每 2 秒重装一次 = BBR 永远停在 startup 阶段，吞吐比不换还差。

### 正确做法：嵌入接口 + 只重写 getter

```go
type cappedBbr struct {
    congestion.CongestionControlEx   // 注意是 Ex，不是基础的 CongestionControl
    cap *atomic.Uint64
}

func (c *cappedBbr) GetCongestionWindow() congestion.ByteCount {
    w := c.CongestionControlEx.GetCongestionWindow()
    if limit := c.limit(); w > limit { return limit }
    return w
}
```

实例只装一次，上限用共享原子值；自适应循环只 `Store`，不碰控制器。
BBR 的带宽估计与 pacing 状态完整保留，窗口改动立即生效。

**为什么必须嵌 `CongestionControlEx`**：`SetCongestionControl` 里会做
`cc.(congestionExt.CongestionControlEx)` 类型断言，嵌基础接口会失败并降级到
逐包回调的 `ccAdapter` 路径，丢包/ACK 信息更少，BBR 判断变差。

**为什么还要重写 `CanSend`**：`sent_packet_handler` 有两条判断路径
（`CanSend` 和 `cwndPackets = GetCongestionWindow()/size`），
只改 `GetCongestionWindow` 时 `CanSend` 仍按 BBR 的原窗口返回 true，
在途字节会短暂超过上限。

---

## 81. UDP 会话必须以 `(本地 socket, 目标)` 为键

`docs/test_udp.py` 的第 3 项就是为了抓这个：先查 8.8.8.8，再查 1.1.1.1，
然后断言**回程地址帧是 1.1.1.1**。

### 症状很隐蔽

- 查询能通、DNS 事务 ID 对得上，所以「看起来一切正常」；
- 只是回程地址帧里的目标不对；
- 更糟的版本：包被发到**错误的主机**，而对端恰好也回答了。

之所以事务 ID 能对上，是因为我们发往 1.1.1.1 的查询实际被送到了 8.8.8.8，
而 8.8.8.8 当然会正常回答它。**「能通」在这里完全不能证明正确。**

### 根因

服务端按 session id 建一条出站 UDP socket，**目标只在建会话时读一次**：

```go
pc, exists := session[id]
if !exists { pc = newInboundPacketConn(..., target, ...) }  // target 只在这里用
```

客户端如果「一个本地 socket 一个 session」，`WriteTo` 换目标时复用同一 id，
后续包就全发到首包的目标上。SOCKS5 UDP ASSOCIATE 一个 relay 访问多个目标
（DNS + QUIC + P2P）时必然踩到。

### 正确做法（对齐 Rust `proxy/socks5.rs`）

Rust 的反向索引写得很清楚：

```rust
// 反向索引：(peer, target) → session，同一个目标不必重复建会话
let mut index: HashMap<(SocketAddr, Vec<u8>), u32> = HashMap::new();
```

Go 侧 `udpConn` 内部维护 `map[string]*udpSession`（key = 目标地址帧），
每个新目标自动分配 id；下行合并进单一 `rx` 队列，
`ReadFrom` 带回各自的目标地址。

**顺手要加空闲回收**：一个 relay 可能先后访问上千个目标，
不回收会让客户端路由表无限增长，服务端每个会话常驻一个 UDP socket。
Rust 每 30 秒扫一次、空闲 `timeout_secs.max(10)`；Go 侧用 30 秒扫描 + 60 秒空闲。

## 82. `syscall.SockaddrLinklayer` 不能直接传给 sendmmsg

这是本轮最隐蔽的 bug：**代码编译通过、单测全绿、TCP 三次握手成功，
但 QUIC 永远握手超时**。

### 现象

客户端日志：

```
ERROR outbound/flowtls: flowtls 初始建连失败: QUIC 握手失败: timeout: no recent network activity
```

抓包看得到 SYN / SYN-ACK / ACK / ClientHello 全部正常，
**之后一个数据包都没有**。服务端日志显示 `conns=0`。

### 根因

为了做 sendmmsg 批量发送，我把 Go 的 `syscall.SockaddrLinklayer`
指针直接填进 `msghdr.msg_name`。两个致命错误：

```go
// 错误写法
namePtr = uintptr(unsafe.Pointer(&syscall.SockaddrLinklayer{...}))
nameLen = uint32(unsafe.Sizeof(syscall.SockaddrLinklayer{}))  // 48！
```

1. **字段顺序不对**：`SockaddrLinklayer` 的第一个字段是 `Protocol`，
   不是 `Family`。内核按 `sockaddr_ll` 解析时会把协议号（`0x0008`）
   当成地址族，返回 `EAFNOSUPPORT`。
2. **大小不对**：它末尾有个 `raw RawSockaddrLinklayer` 字段，
   `unsafe.Sizeof` 得到 48；内核 `struct sockaddr_ll` 只有 **20** 字节。
   `msg_namelen` 传大了，内核会读到结构体之外的内存。

再加上调用方把错误吞掉（`n, _ := s.raw.SendBatch(...)`），
报文就全部静默丢失——TCP 层看起来一切正常，QUIC 层完全收不到东西。

### 正确做法

按内核 uapi 手写结构体，逐字段对照：

```go
type rawSockaddrLL struct {
    Family   uint16  // sll_family = AF_PACKET
    Protocol uint16  // sll_protocol = htons(ETH_P_IP)
    Ifindex  int32   // sll_ifindex
    Hatype   uint16
    Pkttype  uint8
    Halen    uint8
    Addr     [8]byte
}   // 共 20 字节
```

`SockaddrInet4` 同理（它的 `Port` 在前、`family` 藏在 `raw` 里）。

### 怎么验证

**不要靠「跑起来看起来正常」验证**。写一个只验证「内核接受这批报文」的测试：

```go
n, err := s.sendmmsg(pkts, dst)   // 绕过 SendBatch 的退化兜底
if err != nil { t.Fatalf("sockaddr 布局与内核不匹配: %v", err) }
if n != count { t.Fatalf("只发出 %d/%d", n, count) }
```

关键点：**必须绕过退化兜底**。如果 `SendBatch` 里写
「sendmmsg 失败就逐包 sendto」，布局错误会被完全掩盖——
功能正常但批量优化等于没做，而且你会以为它在工作。

### 教训

1. `unsafe.Pointer` 传给内核的结构体，必须按内核 uapi 手写，
   不能用 Go 标准库的同名类型「凑合」——它们的布局只为 `syscall.Socket`
   等少数调用服务，不保证与内核 uapi 逐字节一致。
2. **任何 `unsafe` + syscall 的代码，必须有一个直接断言 syscall 返回值的测试**。
   这类 bug 不会在任何「功能测试」里暴露，因为退化路径太容易掩盖它。
3. 吞错误要有明确理由。`flushLocked` 里 `n, _ := SendBatch(...)` 是对的
   （UDP 语义允许丢包），但它让这个 bug 多活了两轮调试。

## 83. `/proc/net/arp` 的 Flags 是 `0x2`，十六进制解析忘了剥前缀

这是**从 P1 就存在、被回环测试掩盖了整整一天**的 bug。

### 症状链

- 回环互通矩阵 10/10 全绿；
- 但真实链路上：源 IP 是公网地址时 **SYN-ACK 发不出去、握手永远超时**，
  源 IP 是内网地址时吞吐只有 0.7Mbps、QUIC 丢包 10%+。

### 根因

`resolveNeighborMAC` 依赖 `arpLookup`，后者用 `parseHexUint32(f[2])`
解析 Flags 列。而 `/proc/net/arp` 的 Flags 列是 **`0x2`**（带前缀），
`parseHexUint32` 遇到 `x` 直接返回错误：

```go
if err != nil || flags&0x2 == 0 { return zero, false }  // 永远走这里
```

→ 拿不到网关 MAC → `nextHop == [6]byte{}` → **AF_PACKET 发送 fd 不创建**
→ 静默回退 `IPPROTO_RAW`。

所以「AF_PACKET 发送」这条代码路径**从未被真正执行过**，回环全绿
只是因为 IPPROTO_RAW 在 lo 上也能工作。

### 顺带的发现：Rust 版有同一个 bug

`src/faketcp/socket.rs` 的 `u32::from_str_radix(flags, 16)` 对 `"0x2"` 同样失败。
也就是说 **Rust 生产版一直跑在 IPPROTO_RAW 回退路径上**，这解释了为什么
它用公网源 IP（203.0.113.10）能工作：IPPROTO_RAW 经过内核路由/conntrack，
Oracle 网关正常转发；而 AF_PACKET 旁路 conntrack，SYN-ACK 会被网关静默丢弃。

### 教训

1. 退化分支（fallback）必须打日志或计数。它让一个「永远失败」的探测
   看起来完全正常。
2. 回环测试覆盖不到「真实网卡 + NAT」的组合。**e2e 矩阵必须包含一次
   跨机验证**，否则 AF_PACKET / ARP / conntrack 这类路径等于没测。

## 84. `PACKET_QDISC_BYPASS` 在虚拟网卡上会静默丢包

`setsockopt(SOL_PACKET, PACKET_QDISC_BYPASS, 1)` 后，`sendto` 返回成功、
**包却不上线**（tcpdump 抓不到）。实测矩阵（本机 e1000/QEMU 网卡，TCP SYN 到 8443）：

| QDISC_BYPASS | 非阻塞 | ens3 抓到 |
|---|---|---|
| 关 | 关 | 3/3 |
| **开** | 关 | **0/3** |
| 关 | 开 | 3/3 |
| **开** | 开 | **0/3** |

virtio_net 上正常（Rust 版在服务器上验证过），但 e1000/QEMU 不支持。
由于运行时无法可靠判定驱动能力，**默认关闭**，`FLOWTLS_QDISC_BYPASS=1` 手动开启。

## 85. tcpdump 的 BPF 在本机虚拟环境会漏包

> **⚠ 本条结论已于 2026-11-14 推翻，见第 87/88 条。**
> 当时用 tcpdump 抓到 0 包、改用 Python AF_PACKET 抓到包，就断定「BPF 漏包」。
> 实际原因是服务端发包时 IP 头里写了 NAT 公网地址、被云网关反欺骗丢弃（第 87 条），
> 以及拥塞控制器从未安装（第 88 条）。这条误判把排查方向引向了
> 「运营商/NAT 拦包」的错误方向整整半天。**抓包工具计数不一致时，先验工具本身，
> 但不要把「工具看不到」当成结论** —— Python AF_PACKET 当时能抓到本地 TX 包，
> 只能证明包交给了驱动，不能证明包上了网线。

排查握手时出现过「sendto 返回 60 成功、`tcpdump -i ens3` 一个包都抓不到」，
换成 **Python AF_PACKET 裸 socket**（`socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))`
+ `bind(("ens3", 0))` + 手工解析）立刻看到 3 个 SYN。

结论：**怀疑抓包结果之前，先用第二种手段交叉验证**。
排查脚本里 `python3 -u` 必须加，否则重定向到文件时输出被块缓冲，
看起来像「什么都没抓到」。

## 86. 同机不同进程的伪 SYN 可以一个通一个不通

> **⚠ 本条结论已于 2026-11-14 推翻，见第 87/88 条。**
> 「同端口 Rust 通、Go 不通」是真的，但原因不是 NAT 映射冲突也不是进程差异，
> 而是两个实现的**发送路径与源地址处理不同**：Rust 的 ARP 解析也有同一个 bug，
> 一直跑在 IPPROTO_RAW 上，内核会把包里的公网源地址**回填成网卡内网地址**，
> 意外地符合网关要求；Go 修好 ARP 后发的包保留了公网源地址 → 被丢弃。
> 教训：「两个实现一个通一个不通」时，先分别把两边的**上线字节和 fd 类型**抓出来，
> 不要先去找环境因素。

最后一轮公网排查的核心现象（截至本条目仍未闭环）：

- 同一台机器、同一网关、同一目标 203.0.113.10:8443、同一源端口 44355；
- Rust 客户端发起 → 服务器回 SYN-ACK → 建连成功；
- Go 客户端（`ftdial`）发起 → 服务器侧 rawcap **收不到任何 SYN**。

已逐项排除：

| 假设 | 排除方式 |
|---|---|
| 端口冲突 / NAT 残留 | 换全新端口 44355，Rust 通、Go 不通 |
| TCP/IP 校验和错误 | 裸抓包验证 `tcpcksum` 与实算一致 |
| 握手伪装（ClientHello/TS/wscale） | SYN 阶段就失败，且字节逐字段与 Rust 一致 |
| 非阻塞 fd | 阻塞/非阻塞两种都试过 |
| `MSG_DONTWAIT` | 去掉后仍不通 |
| recvFD 未绑定网卡（被 lo/SSH 流量淹没） | 绑定 ens3 后 recvfrom 能收到 SSH 包，仍无 SYN-ACK |
| ARP 解析 | 已修复，网关 MAC 正确 |

下一步方向：用 `bpftrace`/`kprobe` 在网关侧观察「SYN 是否进了 NAT 表」，
或对两个客户端做 `strace` 全量 syscall 对比（不止 sendto/recvfrom）。

## 87. NAT 云主机的 local_ip：包里必须填网卡上的内网地址，填公网地址会被网关静默丢弃

这是「Go 版公网完全不通、Rust 版同一份配置却正常」的**第一个真因**。

### 现象

- 服务端日志一切正常，服务端抓包能看到它发出了 SYN-ACK；
- 客户端网卡上**一个 sport=8443 的入向包都收不到**，表现是握手永远超时；
- 服务端配置里 `local_ip` 写的是公网 `203.0.113.10`（Rust 与 Go 写的是同一个值）。

### 根因

这台 Oracle ARM 机器 `ip -4 addr show enp0s6` 只有 `10.0.0.10/24`，公网地址由网关做 1:1 映射。
抓包对比两端**上线的 IP 头源地址**：

| 实现 | 配置文件里的 local_ip | 线上实际源地址 | 对端能否收到 |
|---|---|---|---|
| Rust | 203.0.113.10 | **10.0.0.10** | 能 |
| Go（修复前） | 203.0.113.10 | **203.0.113.10** | 不能 |

Rust 之所以变成内网地址，是因为它走 `IPPROTO_RAW + IP_HDRINCL`：内核做路由查找后
**会用出接口地址回填 `iph->saddr`**。在服务器上用最小程序验证过（Python 与 Go 各测四种
socket 选项组合，线上源地址一律是 `10.0.0.10`）。

也就是说：配置里写公网地址在 RAW 路径上是**无效的**，只是恰好被内核兜底成了正确值。
一旦包不经内核 IP 层（AF_PACKET）或某些路径不改写，同一个配置立刻失效——
包以「源=公网地址、从内网侧送出」的形态撞上网关反欺骗检查，**静默丢弃**。

网关 SNAT 之后，客户端看到的源地址仍然是公网，所以客户端 `p.Src == peer.Addr()` 的
校验不会失败。内网源地址才是正确写法。

### 修复

`socket_linux.go newRawSocket`：配置值**只有真的配在本机网卡上时才用**（`localHasAddr`），
否则退回 `localIPFor(dst)` 探测到的出口地址，并把替换动作写进 `SendMode()`：

```
flowtls 发送路径: ipproto_raw; 配置的 local_ip 203.0.113.10 不在本机网卡上
（NAT 云主机的公网地址），已改用出口地址 10.0.0.10 发包 源 IP=10.0.0.10
```

看到这行就知道实际生效的源地址，不必再抓包。

### 推翻旧结论

`legacy-rust:DEVTIPS.md` 第 20 条「云厂商 NAT 后面的机器不能用 FakeTCP」、
以及 AGENTS.md 里「必须直接持有公网 IP（实测 Oracle Cloud 完全不可用）」都要修正：
**NAT 云主机可用**，条件是包里填内网地址、让网关做 1:1 SNAT。
第 21 条「运营商动态封禁」在本次排查中也被误当成结论用过，实际链路的
伪造包一直能通过（真实 TLS 与伪 TCP 同时可达）。

## 88. 拥塞控制器从未安装：`Attach()` 只在 Brutal 分支调 `SetCongestionControl`

这是「Go 版吞吐只有 Rust 的几十分之一」的真因，比第 87 条更致命。

### 现象

Go 服务端（修好源地址之后）：

```
BRUTAL 模式  → Rust 客户端 10.7 MB/s
BBR   模式  → Rust 客户端  0.25 MB/s   ← 相差 40 倍
```

丢包 0、CPU 空闲、窗口 8MB 没被压缩，只发 ~35pps。日志写着 `cc=bbr`，看起来像是 BBR 调参问题。

### 根因

`quic/capped_bbr.go` 的 `Attach()`：

```go
if w.brutalBPS > 0 {
    conn.SetCongestionControl(newBrutalSender(...))
}
// BBR 分支什么都没有 —— conn 仍然用 quic-go 的默认控制器
w.conns[conn] = struct{}{}
```

后果链：

1. 整个 `cappedBbr` 是**死代码**（`grep newCappedBbr` 只有定义没有调用，这就是发现它的方法）；
2. `windowController.loop()` 每 2 秒算出的 `w.cap` 没人读，**自适应窗口对真实发送零影响**；
3. `cc=bbr` 只是根据 `brutalBPS` 推出来的字符串，与实际控制器无关 → 日志主动误导排查。

修复就是补上 else 分支：`conn.SetCongestionControl(newCappedBbr(conn.InitialPacketSize(), &w.cap))`。
传 `&w.cap`（共享原子值地址）而不是当前值快照，自适应之后改窗口立刻生效且不清空 BBR 历史
（原因见本文件里「为什么不能靠 SetCongestionControl 重装」那段）。

效果：Go 服务端 BBR 从 **254KB/s → 10.1MB/s**（Rust 客户端）。

### 修复后实测（Go 客户端部署到 127.0.0.1:1080，同一 Go 服务端、同一时刻）

| 客户端 | 100MB 实测 |
|---|---|
| Rust | 14.8~15.1 MB/s |
| Go   | **11.8~18.7 MB/s**（4 并发合计 17.3 MB/s = 138Mbps） |

**本条目刚写完时记录的「Go 5.9~7.2 MB/s、仍差 2.2 倍」是错的**：那个数字来自
一个尚未重启到最终版客户端的实例，且只测了少数几轮。按第 91 条的规矩重测后，
Go↔Go 与 Rust 已在同一量级。教训已写进第 91 条。

已用实验排除：窗口过大（`max_cwnd` 压到 1MB 无效）、CPU（客户端 2.1%）、
内核接收队列（把 recvLoop 拆成 pump + 处理两级无效，已回退）、
拥塞算法选择（Brutal 下差距依旧）、服务端源地址、iptables、wire format。

曾被当作「硬事实」的一句——「服务端测 Go 客户端 RTT 215~228ms、测 Rust 客户端 78ms」——
**同样不可信，已撤回**。原因在统计代码本身：

```go
// capped_bbr.go loop()
for _, c := range conns {
    s := c.ConnectionStats()
    ...
    rtt, srtt = s.LatestRTT, s.SmoothedRTT   // 循环结束后只剩「最后一条连接」的值
}
```

服务端常常同时挂着 Go 与 Rust 两条连接（日志里 `conns=2/3`），而这行日志既不标连接
也不标是哪条，于是 `rtt=` 到底是哪个客户端的完全看不出来。那两次「228ms」的读数
正发生在两条连接共存期间，不能用来证明 Go 客户端 ACK 慢。

**这是可观测性的第二处硬伤**（第一处是缺 `cwnd`/`inflight`），修法：
`PathStats` 增加 per-conn 列表或至少把 rtt 归属带上（对端地址 + 连接数一致时再报单值）。
在补上之前，任何「某客户端 RTT 虚高」的结论都不成立。

**仍缺的观测**：Go 的 `PathStats` 只有 RTT/sent/lost/loss%/win_cap，
**没有 `Cwnd` 和 `BytesInFlight`**，也没有 per-conn 归属；而 Rust 的日志有
`cwnd=` `inflight=` `mtu=` `pending=` `streams=` `rx_queue=`，且每条连接单独一行。
拿不到这些就无法在「拥塞窗口」和「接收流控」之间二分。
下一步第一件事应是给 `cappedBbr` 加 `lastCwnd/lastInFlight` 原子记录
（quic-go 的 `ConnectionStats` 不暴露这两个值，只能在我们自己的控制器里记），
把它带进 `PathStats` 和两端日志。

## 89. 「写了但没接线」是本项目的反复缺陷模式，可观测性必须与 Rust 对齐

一天之内三次踩到同一形态：代码写完、有单测、看起来在用，但**调用点是空的**。

| 实例 | 症状 | 发现方法 |
|---|---|---|
| `SendBatch`（sendmmsg）没被任何发送路径调用 | 1 核 ARM 服务端 10% 丢包、0.7Mbps | 服务端/客户端 Rust 逐行对照发送链 |
| `RecvBatch`（recvmmsg）写完只有单测在用 | 收包 syscall 成本与发送侧不对等 | 同上 |
| `Attach()` 的 BBR 分支不设控制器 | 吞吐差 40 倍，日志还写着 `cc=bbr` | `grep newCappedBbr` → 只有定义没有调用 |

对策（已经落地的部分）：

1. **启动日志必须打出「这条路径实际用的是什么」**：新增 `rawSocket.SendMode()`，
   经 `Listener/Session/Server` 透传到 sing-box 的 inbound/outbound 各一行。
   以后再遇到「包发出去了但对端收不到」，先看日志而不是抓包半天。
2. **统计字段要与 Rust 一一对应**，缺一个字段就少一种二分能力。
   本轮补了服务端日志的 `rtt=`（区分「链路慢」和「对端 ACK 不及时」的唯一手段）；
   `cwnd`/`inflight`/`mtu`/`pending` 仍缺，见第 88 条。
3. **失败分支不许静默**：`flushLoop` 整批发送失败以前直接吞掉 err，
   现在计 `txSendErr`，`FLOWTLS_DEBUG_SEND=1` 时打日志。
4. 新加一个抽象层（队列、包装器、控制器）时，必须同时回答「谁调用它」，
   并用 `grep -rn '<新符号>'` 确认调用点存在；只有定义没有调用的代码等于没有代码。

## 90. 不要用「dst 是什么」推断角色：服务端探测地址是 8.8.8.8，不是 0.0.0.0

上一轮为了治「Go 客户端握手超时」，在 `newRawSocket` 里加了一条：
dst 是具体远端地址且不等本机时，把接收 fd 绑到出口网卡（避开 lo / docker 的无关流量
淹没 AF_PACKET 接收队列）。方向是对的，条件写错了：

```go
// 当时以为「服务端 dst=0.0.0.0，所以不会命中」
if dst.IsValid() && !dst.IsUnspecified() && dst != localIP && ifindex > 0 { bind }
```

但服务端为了让内核帮忙选出口网卡与网关 MAC，传进来的 dst 是
**`8.8.8.8`（listener.go，DEVTIPS 早期就规定的设计）**，完全满足上面的条件
→ 服务端接收 fd 也被绑到物理网卡 → **收不到 lo 上的包 → 本机回环联调全部 handshake timeout**。
这条回归是在本轮最后跑回环复测时才暴露的，回环从 90~97 MB/s 直接变成 0 字节。

正确做法：把「谁需要绑定」变成**调用方显式声明的参数**，不要靠数据反推角色。

```go
func newRawSocket(dst, local netip.Addr, bindRecv bool)
// Dial      → bindRecv=true （客户端只跟一个对端）
// Listener  → bindRecv=false（服务端要同时收多张网卡和 lo）
```

教训两条：

1. **服务端的收包 socket 永远不能绑定网卡**（DEVTIPS 63 已写过，但这次是用
   「条件判断」间接违反了它，所以旧条目没能提醒我）。
2. 每引入一个"优化开关"，必须同时跑**回环**和**公网**两条链路再下结论。
   本轮公网一路测到 6~7 MB/s，回环却在超时，如果没做最后那次回环复测，
   这个回归就随发行版出去了。

## 91. 性能数字必须重复测量：本轮两次被自己的单次测量误导

同一份代码、同一条链路，一天内测出过 **254KB/s、0.7Mbps、3.5、6~7、8~9、12~18 MB/s**
六个数量级的数字，其中至少两次直接把排查方向带偏：

1. **误判「Go 客户端慢 2.2 倍」**：只测了 3 轮就下了结论，还据此去改 `recvLoop`
   拆两级结构（改完吞吐没变，反而多一个丢帧风险点，只好回退）。
   后来按 11 轮重测，Go↔Go 是 11.8~18.7 MB/s，与 Rust 同量级，那个差距根本不存在。
2. **误判「残留会话污染了下一轮测量」**：为了解释「1080 新实例 15~18MB/s、
   1081 老实例 8~9MB/s」，我归因成连接状态污染。证伪方法很简单——
   **1080 连跑 15 轮后再测仍是 15.3~18.7 MB/s，而重启的新实例也没更快**。
   也就是说这个归因当时只是「能自圆其说的猜测」，写文档前必须做重复实验。

规矩（以后按这个来）：

| 场景 | 最低要求 |
|---|---|
| 声称「吞吐 X MB/s」 | 同一组合至少 **5 轮**，报**区间**不报单次 |
| 声称「A 比 B 慢 N 倍」 | A/B **同一时刻交替**测（各 ≥3 轮），避免链路时段差异 |
| 声称「某改动带来提升」 | 改前改后**同一台机器、同一目标、同一轮数**，否则不算 |
| 归因某个未复现的低值 | 先做能**证伪**它的实验（本例就是「跑久了会不会退化」），证伪不了才写进文档 |

还有一条与本条同源：**测吞吐/测 RTT 时服务端必须只有一个客户端**。本轮多次测量在
服务端有 `conns=2/3`（Go 与 Rust 客户端同时在跑）时做，两条流真的在分 100M 带宽，
横向比就会得出错误的「实现差距」。

更隐蔽的是 RTT：服务端统计里 `rtt=` 取的是**循环中最后一条连接**的采样值，
日志不标对端地址，多连接共存时根本不知道这个数字属于谁（详见第 88 条末尾）。
**「客户端 ACK 慢导致对端 RTT 虚高」这个结论就是被它骗出来的**，
而它当时看起来证据确凿。规矩补一条：读聚合日志里的标量字段前，
先确认该字段是「每条」还是「最后一条/平均值」，并保证采样时只有一路流量。

## 92. 批量收包把「向已关闭通道发送」的潜伏竞态引爆成 panic

部署到 1080 后客户端**直接崩进程**：

```
panic: send on closed channel
  deliverOwned  session.go:582
  handleIncoming  → ForEachRecord → deliverOwned
  recvLoop        session.go:909
```

这不是批量收包本身有 bug，而是它**把一个一直潜伏的竞态窗口放大了 32 倍**：

- `Close()` 会 `close(s.rx)`，`deliverOwned()` 会 `s.rx <- owned`；
- 两侧只用 `sync.Once` 保证「rx 只关一次」，**Once 不能保证「关完之后没人再 send」**；
- Go 对已关闭通道发送是 `panic`，不是返回 error，所以只要投递方在 close 之后走到 send，
  整个进程就挂；
- 旧写法每轮只处理 1 个包、且循环顶部先看 `closed`，窗口小到几乎撞不上，
  所以「看起来是安全的」；改成一次 recvmmsg 收 32 包后，关闭瞬间必然还在批内 → 必崩。

**修法**：让「发送」与「关闭」真正互斥，而不是依赖时序巧合。

```go
rxMu     sync.RWMutex   // deliverOwned 拿 RLock，shutdownRx 拿 Lock
rxClosed bool
```

三个投递分支都是非阻塞的（`select` 带 `default`），所以持读锁不会卡住关通道的一方。

### 教训（与前两条同族）

1. **`sync.Once` 用来做「只关一次」时，一定要问：还有人在 close 之后 send/recv 吗？**
   channel 的 close 与 send 必须用同一把锁串行化，否则就是 panic。
2. **任何「把逐包处理改成批量」的改动，都会放大所有与关闭时序有关的竞态。**
   批越大，`closed` 标志检查与实际处理之间的窗口越大。改批量的同时必须复查
   所有「检查标志 → 操作共享资源」的路径。
3. 防回归测试要**能证伪**才算有效：临时去掉 `rxMu` 后 `TestDeliverConcurrentWithCloseNeverPanics`
   立刻 `panic: send on closed channel` + `DATA RACE` + FAIL，恢复后通过。
   只写一个「跑过去就算」的并发测试等于没写（参见 DEVTIPS 91 的测量纪律）。

## 93. 服务端分流不能靠 IP ID：1/16 误命中 + 会被改写，必须用 wscale

这是「RTT 偶发 3×链路值、连接状态抖动」的真根因，也是**移植时丢判断**的典型。

### 现象

- 伪 TCP 握手时快时慢：抓包 80ms 与 214ms（≈3×73ms）交替出现；
- 客户端 QUIC `min_rtt` 常驻 213ms，而同时刻 `ping` 是 72ms；
- 用**普通 curl** 访问 `http://server:8443/` 时，抓包能看到**两个** SYN-ACK：

```
203.0.113.10.8443 > 10.0.0.1.49326: Flags [S.], seq 437198242   ← 内核
203.0.113.10.8443 > 10.0.0.1.49326: Flags [S.], seq 4040626910  ← flowtls
```

### 根因（两层）

**第一层：Go 版丢了 IP ID 判断。**
Rust `server.rs:659` 是：

```rust
if (ip_id & mark) == mark && flags & TCP_SYN != 0 && payload.is_empty()
```

Go 版 `listener.go handlePacket` 只判断 `SYN && !ACK && 无载荷`，
于是**任何** SYN（包括真实浏览器的）都会拿到一个 flowtls 的 SYN-ACK。

**第二层：即使补上 IP ID 判断也不可靠。**

- `ip_id & 0x1E00 == 0x1E00` 有 **1/16 误命中率** —— 伪装站每 16 个访客
  就有 1 个会收到伪造的 SYN-ACK；
- 部分运营商 NAT 会改写 IP ID（DEVTIPS 早前已经记录过）；
- u32 规则还依赖 DF 位，某些路径会清掉它。

### 为什么丢判断的后果这么大

服务端开着 `masquerade`（同端口真证书网站）时，内核里有一个 8443 的 listener。
伪 SYN 一旦没被 iptables 拦住，内核会**创建 request_sock 并回自己的 SYN-ACK**。
于是客户端收到两个不同 ISN 的 SYN-ACK：

- 取到 flowtls 那个 → 一切正常（80ms）；
- 取到内核那个 → 后续伪数据包的 ack 全部对不上，服务端内核还会因为
  「收到不属于自己 socket 的段」回 RST，与 flowtls 的流互相打断（214ms 抖动）。

### 正确做法：按 TCP 选项（wscale）分流

TCP 选项是**端到端字段**，运营商 NAT / 云网关不改写。
实测同一条路径上 MSS 会被 clamp（1460 → 1400），但 wscale 原样保留：

```
服务端收到：mss 1400,sackOK,TS val …,nop,wscale 9     ← 真实 curl（被 clamp）
服务端收到：mss 1400,sackOK,TS val …,nop,wscale 12    ← 伪 SYN（未被改写）
```

三处必须一致：

| 位置 | 内容 |
|---|---|
| `packet.go` | `const WScale uint8 = 12` |
| `listener.go` | `if p.WScale != int(WScale) { return }`（交给内核） |
| `rules.go` | `U32WScaleExpr()`：`--tcp-flags SYN,ACK SYN` + `0x38&0xffffffff=0x0103030c` |

u32 偏移推导（IP 20 + TCP 20 = 40）：偏移 56 起四字节 = `NOP + kind3 + len3 + 12`。

### 验收方法（必须两端抓包）

```bash
# 客户端
tcpdump -i <iface> -nn -s0 -c6 'tcp port 44313 and tcp[tcpflags] & (tcp-syn|tcp-ack) != 0' -v
# 期望：一次伪连接只看到 1 个 SYN-ACK，选项里 wscale 12
curl -s -o /dev/null http://<server>:8443/     # 普通访问应只看到内核的 1 个
```

### 教训

1. **移植时「少一个 if」比「多一个抽象」危险得多**。这行判断在 Rust 里只有
   一个条件表达式，Go 版却整个丢了，而且功能看起来正常（能连上、能跑满带宽），
   只在同端口有内核 listener 时表现为「偶发慢」。
2. 任何「按包内容分流」的特征都必须满足：**不被中间设备改写、误命中率可接受**。
   IP ID 三条都不满足；TCP 选项满足前两条。
3. 分流规则要**同时**落在 iptables 和应用层判断上。只改一处时另一种流量会漏进来
   （只改 iptables → 应用层仍会给真实 SYN 回包；只改应用层 → 内核仍会回 SYN-ACK）。

---

## 94. quic-go 在打包时记录发送时刻：发送队列过深会被算成 RTT

这是「Go 版 RTT 虚高、吞吐抖动」的第二个真根因，与拥塞算法无关。

### 机制

`quic-go` 的发送链路是：

```
appendOneShortHeaderPacket → registerPackedShortHeaderPacket(now, …)   ← 记录发送时刻
    → sendQueue.Send(buf)  → 协程 → conn.Write(buf) → Session.WriteTo
```

也就是说 **`SentPacket(now)` 发生在 `WriteTo` 之前**。如果 `WriteTo` 只是把包
塞进一个深队列就返回，而 flushLoop 落后，包在本地排队几百毫秒；
这段排队时间在收到 ACK 时被算成**网络 RTT**，进而：

- BBR 的带宽估计被 RTT 污染，cwnd/pacing 忽高忽低；
- PTO 与丢包判定基于被污染的 RTT，队列里的包可能被提前判丢并重传，
  重传又加剧积压 —— 正反馈。

### 实测证据

- 链路 ICMP RTT 72.7ms；
- v1（队列 4096）客户端抓包 outer ACK p50 = **213ms**；
- 服务端日志 `rtt=166ms ~ 1.02s` 抖动，`tx_q=32/32`、`tx_wait=1.6s`；
- 队列降到 32 并阻塞生产者后：`min_rtt=79.6~81.2ms`，`tx_wait` 只剩毫秒级。

### 正确做法

1. **队列深度必须小**（32，与 Rust `PacketBatch` 一致）。最坏本地排队 =
   一批报文的上线时间（100Mbps 下约 3.5ms），远小于一个 RTT。
2. **队列满时必须阻塞生产者**，把背压传回 quic-go 的 pacing；
   「满了就丢」在伪造 TCP 上等于永久丢包（下层没有重传）。
3. **纯 ACK 必须走独立队列/协程**。下载方向数据队列经常满，
   ACK 若排在几千个数据包后面，对端测到的 RTT 会凭空多出数百毫秒。
   Rust 的 `send_pure_ack` 就是直接发送，从不进数据队列。
4. `SendBatch` 返回 `sent < len(batch)`（驱动队列满）时**必须重试剩余报文**，
   不能 break 后静默丢弃。

### 教训

1. **异步化之前先想清楚「谁在计时」**。把同步 sendto 改成「入队 + 独立协程」
   能省 syscall，但如果上层已经记了发送时刻，队列延迟就变成了假的网络延迟。
2. 队列深度不是越大越好。深队列只吸收「生产速度 > 消费速度」的瞬时差额，
   持续过载时排队等于把延迟藏进内存。
3. 判断「RTT 高」的真伪只需两个字段：`min_rtt` 与 `tx_q/tx_wait`。
   `min_rtt` 接近链路值而 `latest_rtt` 高 → 本地排队或对端 ACK 慢；
   两者都高 → 链路问题。这就是本轮给 `PathStats` 补 `MinRTT`/`Cwnd`/`tx_*` 的原因。

---

## 95. 删抽象比加抽象难：四层包装里任何一层误判都会「每请求重建连接」

`outbound.go` 的 v1 有四个互相叠加的机制，全部为了同一个目的
（「QUIC 连接已死但 quic-go 没检测到」）：

| 机制 | 位置 | 副作用 |
|---|---|---|
| `getClient` 探活 | 取通道 | 正常 |
| `dialing chan` | 并发建连去重 | 正常但增加状态 |
| `attemptCtx` 首次 8s 超时 | 开流 | 正常 |
| `suspectConn` 包装返回的 net.Conn | 捕获读错误 | **对本端 Close 引发的读错误也会误判** → 标记通道失效 → 每个请求重建一次 QUIC 连接（实测每请求多 0.4s、服务端鉴权次数翻倍） |

**精简后的结构（唯一入口 `channel()`）：**

```go
for {
    c := o.client
    if c != nil {
        if c.Done() 已关闭        { drop; continue }
        if 空闲>5s && !Probe成功  { drop; continue }
        return c
    }
    if o.dialing != nil { 等它; continue }
    // 建连（只此一处，并发请求共享同一次握手）
}
```

开流失败由调用方 `drop(c)` 后重试一次，**不再包装返回的 net.Conn**：
正常关闭一条流时 Read 必然返回错误，那与通道健康无关，
包装层无法可靠区分「本端关闭」与「链路故障」。

### 教训

1. 修 bug 时优先**删掉误判的层**，而不是再加一层来判断「这次错误是不是真的」。
2. 每层包装都要能回答：它捕获的信息是否**只有它能看到**？
   `suspectConn` 看到的只是 `stream.Read` 的错误，而 `channel()` 已经能用
   `c.Done()` + `Probe` 判断连接死活 —— 信息重复且更不可靠。
3. 精简的量化指标不是行数，而是**从「请求进来」到「发出第一字节」经过的函数数**。
   v1 是 6 层，v2 是 3 层（DialContext → channel → DialConn）。

## 96. 服务端必须批量收包 + 用 AF_PACKET 发送：两项各让吞吐差 2~4 倍

这是本轮最后两个真根因，都是**Go 版与 Rust 版在 syscall 层不一致**造成的，
而不是算法或参数问题。

### 6.1 收包：逐包 recvfrom 让 ACK 迟滞 150ms

同一时刻对照（Go 客户端，同一条链路，ICMP 72.7ms）：

| 服务端实现 | QUIC min_rtt | srtt |
|---|---|---|
| Rust 8445（`recvmmsg`） | 76.6ms | 79.9ms |
| Go 8443（逐包 `recvfrom`） | **225.4ms** | 233.7ms |
| Go 8443（改 `recvmmsg` 后） | **72.4ms** | 77.7ms |

服务端 CPU 只有 6%，所以不是算力。差异来自 **syscall 与协程调度粒度**：

- 下行 15MB/s ≈ 11000pps，客户端要回约 11000pps 纯 ACK；
- 逐包 `recvfrom` = 每包一次 syscall + 一次协程调度；
- 单核 ARM 上调度延迟被放大，ACK 晚 150ms 发出，对端把它算成 RTT。

`Listener.recvLoop` 现在与 `Session.recvLoop` 一样用 `RecvBatch`（一次 32 包）。
早期 recvmmsg「吞吐崩到 7KB/s」的坑是 `mmsghdr` 布局写错，
现在 `TestRecvmmsgActuallyReceives` 直接断言「内核真的把包填进来」，风险已消除。

### 6.2 发送：IPPROTO_RAW 是 1 核 ARM 的第一瓶颈

Rust `socket.rs` 的注释写得很清楚：

> 原先用 IPPROTO_RAW + IP_HDRINCL，实测在 1 核 ARM 上约 35µs/包
> （15260 pps 时内核态吃掉 54% CPU），是高速率下的第一瓶颈。

Go 版一直走 IPPROTO_RAW（因为早期 AF_PACKET 在 NAT 云主机上被网关丢包）。
现在源地址已自动纠正为内网地址（DEVTIPS 87），AF_PACKET 可以正常工作：

| 服务端发送路径 | 单流 100MB | cwnd |
|---|---|---|
| `ipproto_raw` | 5 MB/s | 1.2~1.7MB |
| `af_packet` | **15~23 MB/s** | **4.7MB** |

**默认值取舍**：

```go
usePacket := !bindRecv        // 服务端默认 AF_PACKET，客户端默认 IPPROTO_RAW
if v := os.Getenv("FLOWTLS_AF_PACKET"); v != "" { usePacket = v == "1" }
```

客户端保持 RAW 的原因：家用/办公 NAT 对「没有 conntrack 状态却凭空出现的
TCP 包」更挑剔（DEVTIPS 86），而客户端上行主要是纯 ACK，包量小，不是瓶颈。

### 6.3 最终对照（同一链路、同一时段，多轮）

| 指标 | Rust 服务端 | Go 服务端（修复后） |
|---|---|---|
| QUIC min_rtt | 76.6ms | **76.1ms** |
| 单流 100MB | 10.6 MB/s | **15.2~23.0 MB/s** |
| 4 并发 10MB 合计 | 5.8 MB/s | **12.3 MB/s** |
| 伪 TCP 握手（抓包） | — | 80.8ms |
| UDP DNS 6 项 | — | 全 PASS |

### 教训

1. **「CPU 不高所以不是性能问题」是错的**。逐包 syscall 的代价不是 CPU 占用，
   而是**延迟**：每个 syscall 之间进程可能被调度走，1 核上这个间隔是毫秒级。
2. 用户态伪造 TCP 栈的性能几乎完全由 syscall 形态决定：
   `recvmmsg`/`sendmmsg` 批量 + `AF_PACKET` 旁路内核 IP 层，两者缺一不可。
3. 对照实验必须**同一时刻、同一链路、同一条客户端**。
   本轮多次被「几分钟前的数字」误导（例如以为 4 并发退化，
   实际是链路波动；同一时刻对照后 Go 反而是 Rust 的两倍）。

---

## 97. Go v1 归档之后：v2 的精简原则

用户判定「越写越复杂、排查越来越难」后，v2 的重构按三条原则执行：

1. **一个概念只出现在一个文件**。通道获取只有 `Outbound.channel()` 一个入口，
   不再有 `getClient` + `dialing` + `attemptCtx` + `invalidate` 四层。
2. **删除误判的层，而不是再加一层判断**。`suspectConn` 想用「读错误」判断
   连接死活，但正常关闭一条流时 Read 必然报错，无法区分；改为
   `c.Done()` + `Probe()`，信息更可靠且只有一处。
3. **量化指标是「请求到首字节经过的函数数」**，不是行数。
   v1 是 6 层，v2 是 3 层（`DialContext` → `channel` → `DialConn`）。

`outbound.go` 537 → 406 行（其中约 55% 是解释「为什么」的中文注释）。
`inbound.go` 保持与 hysteria2 同构的最小结构（UDP 会话生命周期必须如此：
`ctx` + `cancel` + `readDeadline` + `canceler.NewPacketConn`），不做进一步拆分。

对照表（v2 目标与实测进展）：

| 文件 | v1 | v2 | 说明 |
|---|---|---|---|
| `sing-box/protocol/flowtls/outbound.go` | 537 | **406** | 删掉 4 层包装 |
| `sing-box/protocol/flowtls/inbound.go` | 730 | 730 | 已是 hy2 同构最小结构，不动 |
| `flowtls/quic/client.go` | 897 | 897 | 待办：与 Rust `client.rs` 的 `run_session` 对齐 |
| `flowtls/session.go` | 1229 | 1229 | 待办：收窄发送 API |

## 98. 「包发出去了但没上线」的四种静默失败（2026-11-14 事故复盘）

用户报「1080 连不上」。查下来是四个**互相叠加**的缺陷，共同点是
**日志里没有任何错误**，因为包被静默丢弃或状态被误判。

### 4.1 AF_PACKET 发送 fd 非阻塞 + EAGAIN 被当 UDP 语义

```go
// 错误写法
_ = syscall.SetNonblock(fd, true)   // AF_PACKET 发送 fd
...
if errors.Is(err, syscall.EAGAIN) { return nil }  // 静默丢弃
```

Rust 版的 AF_PACKET fd **没有** `O_NONBLOCK`，所以 `sendto` 会等待。
Go 版多写了一句「必须非阻塞」的优化，配上「EAGAIN 按 UDP 语义丢弃」，
就成了「握手包随机丢失」。

抓包证据：`SYN 0.000 → SYN-ACK 0.851s`（链路 RTT 仅 73ms），
客户端的 SYN 重传定时器是 1s，所以每次都卡 ~850ms。

修法：阻塞 fd + `SO_SNDTIMEO=200ms`（防止真拥塞时永久卡死），
`Send`/`sendLoop` 对 EAGAIN/ENOBUFS 重试，仍失败则**上报错误**。

### 4.2 批量收包缓冲小于 GRO 聚合包 → 内核静默截断

```go
bufs[i] = make([]byte, 2048)   // ← 以为「伪包最大 1417 字节」
```

网卡开着 GRO（默认开），内核会把同一 TCP 流的多个段合并成一个 skb，
**而且 GRO 聚合包可以超过 64KB**（IP total_len 是 16 位，但 skb 长度
由 `gro_size` 决定，不受它约束）。

缓冲不够时 `recvmmsg` 会**截断并丢弃多余部分且不返回错误**，
只在 `msg_flags` 里置 `MSG_TRUNC`。后果：

- QUIC 的 `lost=` 恒为 0（包死在收包缓冲，QUIC 完全不知道）；
- 伪 TCP 握手 473~682ms、QUIC 握手 3.7s、首包延迟 610ms；
- 反复修「发送队列」「拥塞控制」都没用。

修法：`recvBufSize = 256KB`（32 × 256KB = 8MB/端），
并在 `RecvBatch` 里检查 `MSG_TRUNC`——**这个检测是必须的**，
否则下次又会「lost=0 但吞吐上不去」。

排查方法：把 `MSG_TRUNC` 计数打一条 Warn。第一次出现时立刻就知道
是收包缓冲问题，不用再抓包二分。

### 4.3 ERESTARTSYS(512)：Go 异步抢占打断 syscall

单测偶发 `RecvBatch 失败: recvmmsg: errno 512`。

`512 = ERESTARTSYS`，**不在标准 errno 表里**（最大约 133），
所以 `syscall` 包的常量中没有它。触发条件是进程在阻塞的系统调用中
收到信号，且该调用需要重启：**Go 运行时的异步抢占正是这种情形**
（GC/调度器向线程发 SIGURG）。

修法：

```go
const erestartSys = syscall.Errno(512)
for {
    r0, _, errno = syscall.Syscall6(...)
    if errno == 0 || (errno != syscall.EINTR && errno != erestartSys) { break }
}
```

内核没有消费数据，重试完全安全。不重试的后果：
收包侧白等一轮（延迟抖动），**发送侧更严重——一次打断就丢一批报文**。

### 4.4 内核回的 RST 被当作「对端存活」

这是「隧道已死但客户端一直可用」的直接原因：

1. 服务端重启/会话被回收后，伪包仍到达服务端内核；
2. 内核在 8443 上找不到匹配 socket，为**每个**伪包回一个 RST；
3. 这些 RST 的 src/dst 端口与我们的四元组**完全一致**，
   `ParseFrame` + `matchPeer` 全部通过；
4. `handleIncoming` 更新 `lastSeenAt` → `Probe` 判定「链路存活」；
5. 客户端一直复用死连接，请求全部超时，直到用户手动重启。

修法：`handleIncoming` 开头直接忽略 RST——**本协议从不发 RST**
（只有 SYN/SYN-ACK/ACK/PSH/FIN），收到 RST 只可能来自对端内核。

配套把 `probeTimeout` 1s→400ms、`openStreamTimeout` 8s→1s：
服务端重启后首个请求从 11.4s 降到 2~3s。

### 教训

1. **「日志没有错误」不等于「没有丢包」**。用户态伪造 TCP 栈有三处
   会静默丢弃：非阻塞 fd 的 EAGAIN、收包缓冲截断、信号打断的 syscall。
   三处都必须有计数或告警。
2. 移植时**每一句「优化」都要对照 Rust 版确认是否需要**。
   `SetNonblock` 这一句没有任何收益（发送已收敛到单协程），
   却引入了随机丢包。
3. 缓冲大小不能按「我们构造的包有多大」来定，要按**内核可能给的包有多大**来定。
   GRO 是默认开启的，它会重写游戏规则。
4. 生存判定（`lastSeenAt`）必须只接受**本协议真的会发的包**。
   任何「四元组匹配就算活着」的判据都会被对内核对端的 RST 欺骗。

---

## 99. iptables 的 IP ID 分流在真实链路上命中 0 次

实测数据（服务端跑了 6 小时）：

```
-A PREROUTING ... --tcp-flags SYN,ACK SYN -m u32 --u32 "0x38&0xffffffff=0x103030c" -j DROP
   pkts 9,352,020              ← wscale 规则（SYN）命中正常

-A PREROUTING ... -m u32 --u32 "0x4&0xff00ffff=0x1e004000" -j DROP
   pkts 0                      ← IP ID 规则**从未命中**
```

原因：**客户端的 NAT 会改写 IP ID**。客户端发出时 IP ID 是 7697，
服务端收到时变成 7753 —— 已经是 NAT 自己的计数器。

结论：
- **SYN 靠 wscale**（TCP 选项端到端不变）——有效；
- **数据包不能靠 IP ID**——必须用状态机特征。

数据包的正确拦法（不依赖任何可被改写的字段）：

```bash
# filter/INPUT：真实浏览器完成过三次握手 → ESTABLISHED；
# 伪连接的 SYN 已在 raw 表被丢 → 数据包到达时 conntrack 视为 NEW。
iptables -A INPUT -p tcp --dport 8443 ! --syn \
  -m conntrack --ctstate NEW -j DROP
# filter/OUTPUT：内核为伪数据包回的 RST 不出网卡。
# 否则每个下行包引出一个 RST，包量翻倍，云网关还可能对小包限速。
iptables -A OUTPUT -p tcp --sport 8443 --tcp-flags RST RST -j DROP
```

`! --syn` 在 iptables 里是**两个参数**（`"!"` 与 `"--syn"`），
拼成 `"!--syn"` 会报错。`-A`/`-D` 的一致性比较也要注意：
以 `-A ` 开头的字符串没有前导空格，`strings.Replace(s, " -A ", ...)` 匹配不到。

---

## 100. `SO_ATTACH_FILTER` 的返回值被当 int：0xFFFFFFFF 等于「丢弃」

为了减少「收包协程处理整机无关流量」的开销，实现了经典 BPF 端口过滤。
第一次写的时候 accept 分支返回 `0xFFFFFFFF`（「整包长度」），结果
**socket 一个包都收不到**，而 `setsockopt` 返回成功、无任何日志。

内核把 BPF 返回值当 `int` 用：`0xFFFFFFFF` 即 -1，被判为丢弃。
tcpdump 生成的代码用的是 `0x00040000`（262144）。

即便如此，这个优化**仍默认关闭**，原因：

1. 两次真链路部署都导致「隧道一个包都收不到」；
2. 本机无法验证：这台虚拟化机器上 AF_PACKET 看不到自己的出向包
   （基准测试收到 0 个），所以「过滤器到底写对没」在本地测不出来。

保留完整实现 + 单测（`bpf_linux_test.go`，环境不支持时 skip），
需要时用 `FLOWTLS_BPF=1` 启用。

**教训**：纯优化如果不能验证，就不要默认开启。这条优化的收益
（减少无关包解析）远小于它带来的风险（整条隧道不通）。

## 101. 逐函数原样移植时，最容易错的是「拼装」而不是「算法」

Go 版从零重移植（2026-11-14）后，算法层面全部一次通过（AEAD、HKDF、
握手、伪造 ClientHello/ServerHello、IP/TCP 构包都与冻结向量字节一致），
但真机部署时仍然一条都跑不通。五个缺陷全是**胶水层**的：

1. `rule.spec` 里写了 `-A PREROUTING`，而 `command(op)` 又无条件插入动作词
   → 真机执行 `iptables -t raw -A -A PREROUTING ...`，服务端 FATAL 起不来。
   单测当时只 `strings.Join(spec, " ")` 判断内容，看不出重复。
   **现在用「完整参数列表里动作词必须恰好出现一次」来断言。**
2. 分流层是「按四元组快查会话」，而 Rust 是「每个包都先解密再交给 quinn，
   新连接时 `conns.retain(|_, c| c.client != client)`」。
   移植时只在 `handleFirstPacket` 里清了旧会话，但 `handlePacket` 的第 2
   分支**先**命中旧会话，新连接的首包被当乱序包吞掉。
   现象极具误导性：客户端日志「通道已建立」，之后所有请求超时，
   直到 120 秒空闲回收才自己好。**客户端源端口是固定的，所以每次重启必现。**
3. 出站 `Start` 里同步做初始建连。伪 TCP 握手最长 15 秒才判失败，
   而 sing-box 是串行启动——outbound 的 Start 不返回，mixed/socks 入口
   就不会开始监听。于是「客户端刚起来时所有请求立即失败」。
   这也让 `docs/e2e_matrix.sh` 偶发 000（脚本只 sleep 3 秒）。
4. 收包缓冲沿用 Rust 的 64KB，且 `Recvfrom` 没带 `MSG_TRUNC`。
   GRO 聚合出来的 skb 带上 IP/TCP 头就可以超过 64KB，`recvfrom` **静默截断**，
   包无声消失。必须用 `MSG_TRUNC` 拿真实长度才能发现（返回值会大于缓冲长度）。
5. `SendBatch`（sendmmsg）实现了却没人调用，服务端逐包 `sendto`。
   Oracle ARM 实测单次 `sendto` **34µs**，`sendmmsg` 32 个/批降到 20.6µs。
   回环单流因此从 33 MB/s 提升到 45 MB/s。

**结论**：移植的正确性检查不能只看「算法对不对」，必须有一个
「真链路跑通 + 断言可执行产物」的门禁。只看单测绿就以为通了，会在这里翻车。

## 102. 同一台机器上 `sendto` 比 `sendmmsg` 贵 1.65 倍（Oracle ARM 实测）

```
sendto              : 29 322 包/s（每包 34.10 µs）
sendmmsg(32/批)     : 48 597 包/s（每批 658 µs，每包 20.6 µs）
connect + write     : 30 025 包/s（每包 33.31 µs）—— connect 并不省
connect + sendmmsg  : 31 363 包/s —— 反而更慢，别用
```

所以**别指望 `connect()` 缓存路由能省时间**；唯一的杠杆是批量。
`sendmmsg` 的每个 message 必须自带 `sockaddr`（不要先 connect），否则更慢。

按这个数字反推：1 核 ARM 上单方向 1.2 万包/秒就吃掉 ~0.4 秒 CPU，
所以伪 TCP 层的发送**必须**批量，否则吞吐会被 syscall 卡在个位数 MB/s。

## 103. `local_ip` 填公网地址会「看起来正常但完全不通」

Oracle Cloud 的实例只有内网地址（如 `10.0.0.10`），公网地址由网关 1:1 映射。
走 IPPROTO_RAW 时，IP 头里的 `saddr` 是**我们写进去的值，内核不会改写**：

- 写内网地址 → 网关做 SNAT → 客户端正常收到；
- 写公网地址 → 网关反欺骗**静默丢弃**。

最迷惑的地方：服务端 `tcpdump` 能看到 SYN-ACK **已经发出**（抓的是本机网卡），
客户端却一个包都收不到，双方日志都没有任何错误。

排查手法：`grep 发送路径 sing-box.log`，确认 `源 IP=` 是内网地址。
`deploy.example/server.json` 与 `DEPLOY_CREDENTIALS.md` 都已按此更正。

## 104. 纯 ACK 的判定必须在「一批收完」之后，不能逐包判

Rust 的事件循环是「阻塞收 1 帧 + `try_recv` 再凑最多 256 帧」，
`ack_pending >= 2 || (ack_pending > 0 && last_ack.elapsed() >= 40ms)`
这个 `due` 判定**只在整批处理完之后做一次**。

Go 移植一开始把同一段判定写进了 `handleIncoming`，也就是**每帧判一次**。
后果：一批 256 个数据帧会发出 128 个纯 ACK，而 Rust 只发 1 个。
回环实测（200MB 下载、抓包按方向分类，排除内核 RST）：

| 指标 | 逐帧判定（旧） | 批末判定（新） | 变化 |
|---|---|---|---|
| 客户端→服务端 纯 ACK | 4167 | 2393 | −42.6% |
| 服务端→客户端 纯 ACK | 1095 | 809 | −26.1% |
| 数据帧 | 8001 | 8001 | 不变 |

吞吐（同一份 10MB 响应、各 3 轮）：旧 111/108/106 ms，新 103/96/97 ms，
平均 **108.3 → 98.7 ms（+9%）**，且两轮都没有回归。

**怎么在 Go 里做出同样的批边界**：给 raw socket 加一个
`recvAvailable()`（`MSG_TRUNC | MSG_DONTWAIT`，队列空返回 `ok=false`），
收包协程改成「阻塞收 1 帧 → 非阻塞再取干（上限 `maxRecvBatch=256`）→
本轮结束才调一次 `flushDelayedACK()`」。
`MSG_DONTWAIT` 是**单次调用**语义，不改 fd 的阻塞属性，
所以不影响「发送 fd 必须阻塞」那条约束（那约束说的是 sendFD）。

顺带纠正一个常见误判：批大小**不会**总是跑到 256。回环上收方不是瓶颈，
一轮平均只凑到 ~3.3 帧（8001 帧 → 2393 个 ACK），所以这次的收益是
「少发 30~40% 的 ACK」，不是「少发 99%」。真要凑满 256，得让收方处理
慢于到达速率——这正是 Rust 那条 `pkt_rx.len()` 统计想观测的状态。

## 105. 「差异清单」里的 ACK 延迟一项，影响被高估了

审计 Rust↔Go 差异时曾把 `ack_frequency_config(max_ack_delay=5ms)`
列为头号嫌疑。核对 quic-go 源码后可以确定它**不是**吞吐差距的主因：

- `internal/ackhandler/received_packet_tracker.go` 的 `shouldQueueACK`
  里，`ackElicitingPacketsReceivedSinceLastAck >= packetsBeforeAck(2)`
  会**立即**回 ACK。25ms 的 `maxAckDelay` 只对稀疏流量（握手尾包、
  单个探测包）生效。
- `protocol.MaxAckDelay = 25ms` 是常量，`quicgo.Config` **没有任何字段**
  可以覆盖它；`AckFrequencyFrame` 只被 `frame_parser.go` 解析后丢弃，
  既不发送也不生效。
- 想对齐只能改 quic-go 源码 → 违反 `AGENTS.md` 约束 9（依赖版本必须与
  sing-box 逐字节一致）。**结论：接受差异，不要在这上面花时间。**

## 106. `ConnectionStats().PacketsLost` 在 BBR 下恒为 0（只在 cubic 里累加）

排查「Go×Go 真链路只有 Rust 一半」时，日志里一直有个没人在意的细节：
两端的 `lost` 和 `loss_pct` **永远打印 0**，哪怕链路实测丢包 30%。

原因在依赖里：

```
$ grep -rn "connStats.PacketsLost" quic-go@v0.61.0-sing-box-mod.12/
connection.go:868:   PacketsLost: c.connStats.PacketsLost.Load(),   // 只读
internal/congestion/cubic_sender.go:200: c.connStats.PacketsLost.Add(1)  // 唯一写入
```

也就是说**只有用 Cubic 时这个计数器才会动**。用 BBR 时它恒为 0。
`PacketsSent` 不同——它在 `internal/ackhandler/sent_packet_handler.go:331`
累加，与拥塞控制器无关，是可靠的。

这不是显示问题。`quic/quic/capped.go` 的窗口自适应循环靠它算丢包率：

```go
loss = (PacketsLost 增量) / (PacketsSent 增量)   // 恒为 0/非0 = 0
case loss < lossLowMark:  next = cur * 1.20      // 每 2 秒 ×1.2
```

于是从 Rust 移植过来的「高丢包压窗口」机制**在 Go 里是死代码**，
`win_cap` 只会从 8MB 往上顶（被 cfg 封住），从不收缩。

修法：在 `cappedBbr` 里覆写 `OnCongestionEventEx`，从
`[]congestion.LostPacketInfo` 自己数包数和字节数，然后**原样委托给内层**：

```go
func (c *cappedBbr) OnCongestionEventEx(priorInFlight, eventTime, acked, lost) {
    if len(lost) > 0 { c.lostPackets.Add(len(lost)); ... }
    c.CongestionControlEx.OnCongestionEventEx(...)   // 内层行为不变
}
```

修完 `loss_pct` 立刻变成 30（Rust 是 33），`win_cap` 从 8MB 掉到 1.5MB，
与 Rust 一致。

**教训**：移植一个依赖的统计量之前，先 `grep` 它是谁写的。
「字段存在」不等于「字段有值」——尤其当它只被某个非默认实现填充时。

## 107. 本机复现跨境链路的方法：`tc netem` + 端口过滤

真链路两端的吞吐数字**不可重复**（跨境链路波动极大、且两次测量往往相隔数天），
所以要么并发测，要么本机复现。本机复现的关键是**只对合成流限速**：

```bash
# 错：整块 lo 加 netem，会把 curl↔SOCKS5、服务端↔目标这些本地 TCP 一起限速，
#     10% 丢包下 curl 直接卡死，测的是本地 TCP 而不是隧道。
tc qdisc add dev lo root netem delay 70ms loss 10%

# 对：prio 分流，只把 8443 的包送进 netem 子队列
tc qdisc add dev lo root handle 1: prio bands 3
tc qdisc add dev lo parent 1:3 handle 30: netem delay 70ms loss 10% limit 5000
tc filter add dev lo protocol ip parent 1:0 prio 1 u32 match ip sport 8443 0xffff flowid 1:3
tc filter add dev lo protocol ip parent 1:0 prio 1 u32 match ip dport 8443 0xffff flowid 1:3

# 收尾一定要删，否则会一直挂着
tc qdisc del dev lo root
```

已知偏差：`lo` 的 qdisc 是**双向共用**的，而真实链路两个方向各有队列。
所以这个仿真对「发送方把队列打满」的场景偏悲观。看到某一端 `sent` 停住时，
先用 `tc -s qdisc show dev lo` 确认 `backlog`（积压）而不是 `dropped`，
再用 `/proc/<pid>/task/*/wchan` 看进程到底阻塞在哪（`__skb_wait_for_more_packets`
= 正常等包，`sk_wait_data` 类 = 卡在发送）。

本机实测（200MB 单流下载，Rust 用 `cargo build --release`）：

| 条件 | Rust↔Rust | Go↔Go |
|---|---|---|
| 回环无延迟 | 44 MiB/s | 90 MiB/s |
| +70ms 单向延迟（≈140ms RTT） | 13.1 MiB/s | 19.5 MiB/s |
| +2% 均匀丢包 | 10.4 MB/s | 9.3 MB/s |
| +5% 均匀丢包 | 8.0 MB/s | 7.6 MB/s |
| +10% 均匀丢包 | 6.4 MB/s | 6.0 MB/s |
| +突发丢包 gemodel(40%,87%)≈5% | 3.3 MB/s | **<0.12 MB/s（停滞）** |

**结论**：均匀丢包下两者几乎重合（Go 慢 3~10%），
**只有突发丢包才把 Go 打崩**。所以「Go×Go 只有 Rust 一半」这个结论
不能用均匀丢包解释，必须用突发丢包（或别的因素）去查。

## 108. 每次建连固定多花 ~514ms：`resolveNeighborMAC` 的 25×20ms 死等

`flowtls.Dial` 里有一段恒定 514ms 的耗时（回环上实测 510~518ms，
QUIC 握手本身只要 3ms、RTT 1.4ms）。用临时探针把两段分开计时可以确认：
**这段延迟发生在 `newRawSocket()` 里，与握手无关**
（把 `handshake` 设成 `none` 仍然是 514ms）。

来源是 `resolveNeighborMAC`：

```go
if mac, ok := arpLookup(nextHop, ifname); ok { return mac, true }
triggerARP(nextHop)
for i := 0; i < 25; i++ {              // ← 25 × 20ms = 500ms
    time.Sleep(20 * time.Millisecond)
    if mac, ok := arpLookup(nextHop, ifname); ok { return mac, true }
}
```

而 `arpLookup` 因为**刻意保留 Rust 的 `from_str_radix("0x2", 16)` 解析缺陷**
（`/proc/net/arp` 的 Flags 列带 `0x` 前缀，解析必然失败）而**永远返回 false**，
所以这 500ms 是纯粹的等待，之后照样回退到 IPPROTO_RAW。

Rust 侧 `socket.rs:445` 是一模一样的 25×20ms，所以这是**忠实移植**，
不是新引入的 bug；也正因为 Rust 也这样，「Go 慢」与它无关。
但它确实是每次重连都要付的固定成本——如果要消除，
需要同时决定「是否放弃与 Rust 的行为一致」，属于需要产品决策的改动，
不要顺手改掉。

另外注意：`IPPROTO_RAW` 第一次发送偶尔返回 `EPERM`（`sendmmsg: operation
not permitted`），只出现 1 次、不影响建连，暂未定位，记录在案。

## 109. 跨境链路吞吐必须**交替**测，隔几分钟的两次数据没有可比性

这一条纠正了一个影响了两三天的错误前提。

之前一直拿「Go×Go 6~7 MB/s，Rust↔Rust 15~16 MB/s」当基准，去追 2 倍的实现差距。
真链路实测发现：**这条链路自己就在 5~15 MB/s 之间来回摆**。

同一条连接、同一台机器上连续采样：

```
rtt=77ms   srtt=77ms   cwnd=2.39MB  sent=84261  lost=2213  loss_pct=2   win_cap=8MB
（几分钟后）
rtt=235ms  srtt=234ms  cwnd=3.27MB  sent=274025 lost=25992 loss_pct=0   win_cap=4.05MB→8MB
```

RTT 从 77ms 涨到 235ms（3 倍），累计丢包从 2.6% 涨到 9.5%。
在这种链路上，先测 Go、过 5 分钟再测 Rust，得到的「差距」几乎全是链路漂移。

**正确做法**：交替测，同一时间窗内轮流跑两边。

```bash
for r in 1 2 3; do
  跑 Go   → 记录
  跑 Rust → 记录
done
```

交替实测（100MB 单流下载，脚本 `/tmp/ft-bench/ab-real.sh`）：

| 轮次 | Go×Go | Rust↔Rust |
|---|---|---|
| 1 | 15.5 MB/s | 13.6 MB/s |
| 2 | 5.0 MB/s | 14.5 MB/s |
| 3 | 0（握手超时） | 14.7 MB/s |
| 换新版客户端后 1 | 11.0 MB/s | 5.1 MB/s |
| 换新版客户端后 2 | 12.3 MB/s | 5.2 MB/s |

**互有胜负，没有稳定的 2 倍差距。**

## 110. 抓包量丢包**突发结构**不需要两端对时钟

真链路要回答的问题往往不是「丢了多少」，而是「丢得均匀还是成串」。
伪造 TCP 在这里帮了大忙：每个数据包在线上就是一段连续的 `seq:end`。

做法：

```bash
tcpdump -n -i ens3 -s 96 "host <服务端IP> and tcp port 8443" > cap.txt
python3 gapstats.py cap.txt     # 把收到的区间按 seq 排序合并，区间之间的空洞=丢包
```

脚本 `/tmp/ft-bench/gapstats.py` 会输出空洞个数、丢失字节、以及
**每个空洞折算成「连续丢了几个包」的分布**。

实测结论（真链路，一次 100MB 下载）：

```
空洞(丢包事件): 6543
突发长度分布：连续丢 1 包 = 6543 次（100%）
单次丢包字节：中位 1365，最大 12732
```

→ **真链路是均匀的单包丢失，不是突发丢包。**
这一条直接排除了「突发丢包导致 Go 崩塌」的外推可能
（`tc netem loss gemodel` 造出来的突发丢包在真链路上并不存在）。

注意：抓包本身会拖慢链路（实测 12 MB/s → 4.4 MB/s），
所以**抓包那一轮的数字不能用来比较性能**，只用来分析结构。

## 111. 比 Rust 多出来的「更严格」校验，往往是移植缺陷

`isSYNACKFor` 在 Go 里是：

```go
p.Flags&TCPSYN != 0 && p.Flags&TCPACK != 0 && p.Ack == s.synISN+1
```

Rust `client.rs:767` 只有前两个条件。多出来的 `Ack` 校验看起来更严谨，
实际只会制造一种故障：ACK 号对不上 → **有效的 SYN-ACK 被静默丢弃** →
客户端等 1/2/4/8 秒退避后重传 SYN → 撞上 sing-box 的建连超时，
日志表现为 `flowtls 握手失败: context deadline exceeded`。
实测 7 次建连里出现 3 次，而且全都集中在链路较差的窗口。

四元组已由 `matchPeer` 过滤（源 IP/端口全对得上），真正的鉴权是后续 AEAD，
所以这个字段校验没有任何安全收益。

**规律**：逐行移植时，凡是「比参考实现多出来的判断」都要能说出为什么。
说不出来就是 bug——它只会拒绝本该接受的输入。

## 113. Go 的 QUIC RTT 比 Rust 稳定地多约一个往返（2026-11-14 17:45）

同一时刻两条隧道并行：1080 是 Go→Go（8443），1081 是 Rust→Rust（8445）。
空闲时 Rust 两端都报 80~85ms，Go 服务端稳定报 220~221ms。
应用层首字节 p50 是 252ms 对 113ms。差额约 140ms，接近一个往返，
连续 3 分钟都这样，不是链路漂移。

下载速度这次没有拉开（都在 4.4~6.9 MB/s）。所以「RTT 高」和「吞吐低」
不是同一件事，不要用下载速度反过来证明 RTT 正常。

抓包后把差额缩到了一个地方（2026-11-14 18:05，两端都是当天最新二进制）：

| 方向 | 请求离开本机 → 对端 ACK 回来 |
|---|---|
| Rust 44321 → 8445 | **79ms** |
| Go 44323 → 8443 | **216ms** |

本机发出是立即的（两个包间隔 0.1ms）。多出来的约 137ms 全在
「对端收到之后、ACK 离开之前」。首字节也一样：Go 223~228ms，Rust 约 85ms。

试过给收包循环加 5ms 唤醒（服务端、客户端都加了）。假设是
「quic-go 的 ACK 要等下一次 Recv 返回才写得出去」。部署后往返仍是
216ms，**假设不成立，改动已撤回**。不要再从这个方向改：
它会给每条连接多一个协程和一次拷贝，而 RTT 不变。

quic-go 的 ACK 闹钟是 25ms（`protocol.MaxAckDelay`），也对不上 137ms。

给 `Session.ReadFrom` 加 5ms 超时也试过（2026-11-14 18:55，两端都部署）。
假设是 quic-go 堵在读取上，醒不过来就看不到到期的 ACK。
部署后抓包仍是 221ms，假设不成立，改动已撤回。

真正的原因在更外面（2026-11-14 19:05 两端对抓）：

`flushDelayedACK` 只在 `Recv` 返回后调用。单个请求/响应之后没有下一个包，
ACK 就一直攒着。服务端网卡上「请求到达 → ACK 发出」是 0.08ms，
客户端网卡上看同一段却是 221ms：客户端把对端响应的 ACK 压到了下一次收包。
QUIC 的 RTT 采样采的就是这个被推迟的 ACK。

修法不是去叫醒 quic-go，而是让收包循环自己每 5ms 醒一次，
没有新包也跑 `flushDelayedACK`。客户端 `recvLoop` 和服务端
`Listener.recvLoop` 都要加，单加一边只修半个方向。
修复后首字节 74–77ms，Rust 同时是 86–99ms。
19:10 再跑了 90 秒：Go p50 77ms（337 次），Rust p50 98ms（188 次）。

这一轮走过的错路，以后不要再试：

1. 在 `cappedBbr` 自己加「一个 RTT 发满一窗」。ACK 和数据走同一条判断，
   确认也被挡住。Rust 没有这层。
2. 给 `Session.ReadFrom` 加 5ms 超时去叫醒 quic-go。部署后仍是 221ms，
   还会每秒空转约 200 次。
3. 每 5ms 新开一次 raw `Recv`。收包 fd 是共享的，两个 Recv 会抢包；
   用 `SetReadDeadline` 也会覆盖 quic-go 自己的握手超时。
   留下来的写法是：一个长期收包协程，主循环只在 channel 和 5ms 定时器上选择。

## 112. 握手完成后不要再加自己的发送等待（2026-11-14 18:30）

通道只握手一次。`awaitingSYNACK` 在收到 SYN-ACK 后就清掉，
之后 `WriteTo` 直接封包，`txLoop` 凑到多少发多少，没有定时器。

曾在 `cappedBbr` 上按「一个 RTT 发满一窗」自己挡过 `HasPacingBudget`。
这会让 ACK 也跟着等。Rust 没有这层，已删除。
删掉之后抓包仍是 221ms（Rust 79ms），所以它不是这 140ms 的原因，
但也不该留着。

抓包还能看出：对端的 **TCP ACK 是 221ms 才回来的纯 ACK**，
不是随数据包一起回来。也就是说对端收到请求后没有立刻产生 QUIC 响应，
而是等到下一次发送机会。这个时机在 quic-go 内部，不在 `WriteTo`。

## 112-old. 钳窗口在 quic-go 里不等于钳速率（2026-11-14 17:04，结论已过时）

Rust 的注释写「只钳 window 就够」，因为 quinn 的 pacing 是
`capacity = window / rtt`，读的就是被钳过的 `window()`。

quic-go 拆成了两条独立路径：

- `GetCongestionWindow` / `CanSend`：在途字节上限
- `TimeUntilSend` / `HasPacingBudget`：pacer 的令牌桶，带宽来自
  BBR 自己的估计，**完全不读窗口**

只覆写前一条时，估计被抬到数 Gbps 后，一个 RTT 内就把整窗突发打出去，
随后干等 ACK。连接不掉、进程也在，吞吐接近 0。这和「窗口上限没生效」
看起来一样，但日志里 `win_cap` 是正常的。

修法是在 `cappedBbr` 上再覆写发送路径，按 `窗口上限 / MinRTT`
限制**一个 RTT 内的突发量**（不是把每个包均匀拉开——均匀拉开会把
8MB 窗口压成每秒几千包）。内层估计正常时，取两者更晚的那个，行为不变。

**不要**改成「每字节间隔 = RTT/窗口」：那个公式把突发也拆掉了，
吞吐会塌一个数量级。Rust 允许的是一个 RTT 发满一窗。

上面这条修法本身已经撤回，见 112。留在这里只说明 quic-go 的 pacer
确实不读窗口；不要再按这条去给 `cappedBbr` 加 `TimeUntilSend`。

## 114. 测速客户端主动断流，日志会刷一片 `error code 0`（2026-11-14 19:16）

用户自己跑测速时，客户端和服务端会同时出现：

```
connection download closed: stream N canceled by local with error code 0
connection download closed: stream N canceled by remote with error code 0
```

客户端写 `by local`，服务端写 `by remote`，是同一件事的两面。
测速程序拿够样本就关掉自己的下载，quic-go 用错误码 0
（`NO_ERROR`）取消流。sing-box 的 `IsClosedOrCanceled` 不认这种
取消，所以打成 ERROR，不是握手失败、也不是丢包。

判断依据（2026-11-14 19:12–19:16 这一次）：

- 目标全是测速节点（`:8080` 下载、`:443`），持续时间聚在 15s 和 60s。
- 同一时段没有 `panic`、握手失败、收包截断、超时。
- 19:16 之后密度回落，隧道还在。

只有出现 `by remote` 但客户端没有对应的 `by local`、或者错误码不是 0、
或者同时有握手失败，才值得再查。

## 118. direct 入站改写到 127.0.0.1 必须先于私网直连规则（2026-11-14 22:15）

用 `direct` 入站做端口映射（`override_address: 127.0.0.1`）时，路由规则
`{"inbound": ["<该入站tag>"], "outbound": "flowtls-out"}` **必须放在
`ip_is_private → direct` 之前**。漏掉这条规则时，改写后的目标是 127.0.0.1，
命中"私网直连"，sing-box 去连**自己**监听的同一端口 → 回到自己的入站 → 无限自环。

自环的特征（2026-11-14 跳板实测）：

- journal 里连环出现 `inbound connection from 127.0.0.1:<临时端口>` 到自己；
- 几秒内 `connection upload/download closed: too many open files`（fd 被循环耗尽）；
- curl 表现为连上但无数据。重启进程能临时恢复，不删自环源头必然复发。

另一个陷阱：以为「改成 80 能访问」说明映射通了——实际 `127.0.0.1:80` 命中的
是本机自己的 80 端口服务，根本没走隧道。验证映射必须用能区分两端的页面或
在服务端抓 sing-box 日志确认出站方向是 `outbound/flowtls` 而不是 `outbound/direct`。

## 115. 手动同步正式版并触发全架构发布（2026-11-14 20:19）

自动同步源码方案已放弃。开发者先手动将 `sing-box/` 更新到官方正式 Release tag，
核对 `sing-box/go.mod` / `go.sum`，并把 Go、`quic-go`、`sing`、`sing-quic`
版本逐字节同步到 `flowtls/go.mod` / `go.sum`。完成审查和测试后推送 `main`。

之后在 Actions 手动运行 `Build`，版本留空则读取 `VERSION`，也可输入
`<上游正式版>-rev.N`。Build 先跑测试，再构建全部受支持的 Linux 架构；通过后才创建
`v<版本>` tag 和正式 Release。已存在的 tag 会在构建前被拒绝，不能覆盖发行版。

不要运行或重新添加定时上游拉取。曾试过同步 `stable`（引入开发版依赖冲突）
和自动派发（多 remote 导致 403），自动方式已经移除。Android 不纳入矩阵：
FakeTCP 需要 Linux raw socket。首轮矩阵还实测 Windows、macOS、FreeBSD 会因
`socket_stub.go` 缺少 `localIP` / `maxSendBatch` 编译失败，因此这些系统不是当前发行目标。

首次正式发行 `v1.14.4-rev.1` 于 2026-11-14 20:38 完成：19 个 Linux 包和
`sha256sum.txt`，测试与所有架构构建均通过。后续上游同步必须由开发者手动进行。

## 117. 默认伪装页来自嵌入的 web/index.html（2026-11-14 21:19）

`masquerade.site_dir` 是可选覆盖项：设置后静态文件和该目录的 `index.html` 优先；
省略该字段时使用编译进二进制的 `sing-box/protocol/flowtls/web/index.html`。
不要在代码里再维护一份不同的首页常量，否则服务器重启后展示内容会与仓库文件不一致。
修改 `web/index.html` 后必须重新构建、部署服务端二进制；旧二进制仍含旧页面。

## 119. 真实 IP 写进文档等于永久泄露（2026-11-15 01:10）

public 仓库放了 5 天，`CHANGELOG.md` / `DEVTIPS.md` / `docs/bench.sh` /
测试注释里的三台服务器公网 IP、内网地址、`ip_id_mark`、客户端源端口和伪装域名
全是明文。FakeTCP 的抗主动探测优势来自「攻击者不知道 IP、不知道 mark、不知道
SNI」，这三样一起公开，等于把部署指纹交出去，可以针对性扫描、指纹识别和封锁。

脱敏用 `git-filter-repo` 重写全部 ref（三分支 + 五 tag + 2899 个提交）：

```bash
git-filter-repo --replace-text rules.txt --force
git-filter-repo --force --message-callback 'return message.replace(b"真域名", b"example.com")'
git push --force --all && git push --force --tags
```

踩到的四个坑：

1. **`git grep -I` 会把二进制当「无匹配」跳过**。第一次扫私钥时带了 `-I`，
   结果是假阴性；换 `grep -a` 才看到内容。扫「有没有私钥」时不能用 `-I`。
2. **纯数字参数不能裸替换**。`ip_id_mark` 与 `source_port` 的值都是纯数字，
   而同样的数字在 commit/tree/blob 的 SHA 和 `go.mod` 的伪版本校验和里到处都是，
   直接裸替换会把依赖哈希改坏。只能用锚定正则：
   `regex:ip_id_mark:\s*<旧值>`、`regex:source_port:\s*<旧值>`。
   （本节刻意不再写出真实旧值——讲脱敏的文档自己写回真实值，
   等于换个地方泄露。）
3. **commit message 也会泄露**。本次有一条 message 写着「CloudFlare Origin CA
   真证书（通配真实域名）」，blob 全干净了它还在，必须配 `--message-callback`。
4. **强推后旧对象仍可读**。`raw.githubusercontent.com/<owner>/<repo>/<旧SHA>/…`
   照样返回 200，因为对象只是「未被引用」而没被 GC。只有 GitHub Support 清理
   或删库重建才能彻底删除——所以**发现泄露的第一时间是改密码/换参数，
   而不是重写历史**。

预防：`docs/leak_check.sh` 用白名单扫描被跟踪文件（回环 / 私网 / CGNAT /
链路本地 / 组播 / RFC 5737 文档段 / RFC 2544 / 公共 DNS / 占位地址之外一律
报错），CI 每次提交都跑；文档里统一写 `203.0.113.x` 和 `example.com`。
`deploy/` 与 `DEPLOY_CREDENTIALS.md` 靠 `.gitignore` + 本门禁双重保护。

## 120. 库自己往 stderr 写字 = 绕过宿主的日志级别（2026-11-15 12:05）

现场「默认启动产生大量没必要日志」，第一反应是加一个 `debug: true` 开关。
**错的**：问题不是缺开关，而是两套日志体系并存。

`flowtls` 主包的 11 处诊断日志全用标准库 `log.Printf`，这些行无条件写 stderr，
完全绕过 sing-box 的 `log.level`：

```json
{ "log": { "level": "error" } }   // 用户以为安静了
```

但「发送失败（累计 N 次）」「收包缓冲不足」照样刷；与此同时 `QUIC 路径统计`
走的是 `logger.Debug`，于是同一份日志里一半受控、一半不受控——
用户无法用一个开关关掉全部噪声。实测服务端 `level: debug` 攒了 15MB
（83596 条 DEBUG，其中 35189 条路径统计）。

正确做法是**注入**而不是新增参数：

```go
// flowtls/log.go —— 签名与 sing/log/logger.Logger 逐字一致
type Logger interface {
	Debug(args ...any)
	Info(args ...any)
	Warn(args ...any)
	Error(args ...any)
}
```

关键点：`sing-box` 的 `log.ContextLogger` **天然满足这个接口**，
适配层写 `Logger: h.logger` 就完事，不需要适配器代码。
级别过滤全部交给宿主，flowtls 自己不判断级别。

三条设计约束：

1. **nil = 静默，不回退标准库**。回退会让「不注入」等于「照样吵」，
   注入就失去意义。回环日志只在联调工具里显式 `flowtls.StdLogger()`。
2. **不要在 `Validate()` 里给 `Logger` 赋默认值**。静默是刻意默认。
3. **测试手工构造对象要显式填 `nopLogger{}`**。手工构造绕过构造函数的
   `loggerOr` 归一，nil 接口调方法会 panic——本次就有 4 个测试因此炸掉。

诊断这类问题的快速判据：

```bash
# 有没有绕过宿主的日志？按 tag 前缀检查
grep -c '^flowtls:' app.log        # 非 0 = 有日志没走宿主 logger
```

## 121. 换加密算法前先算「它到底占多少单核」（2026-11-15 12:05）

「CPU 高、带宽跑不高」时，第一个怀疑对象常是 AEAD。先用基准量化，
别猜。`flowtls/codec_bench_test.go` 在两端各跑一次（ARM 用交叉编译）：

```bash
go test -run '^$' -bench . -benchtime 2s .
GOARCH=arm64 go test -c -o /tmp/b.test . && scp /tmp/b.test ... && /tmp/b.test -test.bench .
```

实测（1332B，一次 Seal + 一次 Open）：

| 算法 | amd64 | ARM（新加坡，有 aes/pmull） |
|---|---:|---:|
| ChaCha20-Poly1305（线上） | 1959 ns | **6753 ns** |
| AES-128-GCM | 828 ns | 1305 ns |

AES-GCM 在 ARM 上快 5.2 倍，看起来很有吸引力。但换成「每包耗时」：

```
6753ns/包 × 9400 包/秒（100Mbps 单向）≈ 6.3% 单核
```

**6.3% 解释不了「带宽跑不高」**。换算法是确定收益的优化（能省约 5% 单核），
但真正的瓶颈要往别处找：本机客户端 `/proc/PID/stat` 显示
`utime=141930 / stime=180387`，**内核态占 56%**——syscall（AF_PACKET 收发与
sendmmsg/recvmmsg）比用户态加密贵得多。

教训：先看 `utime` vs `stime` 的比值，再决定优化方向。
比值说明是 syscall 问题就调批量与缓冲，说明是用户态问题才去动算法。

## 122. 批量收包会把 RTT 抬高一整个往返（2026-11-15 13:20）

为了压 CPU，把收包从「一帧一次 `recvfrom`」改成「一次 `recvmmsg` 取 8 帧」。
吞吐确实涨了，**RTT 却从 79ms 变成 220ms**，两端对称复现。

分叉实验（这一步不能省）：怀疑对象有两个——换 AES、换发送路径到 AF_PACKET。
所以起了第三个服务端实例，用 `FLOWTLS_AF_PACKET=0` 强制 raw：

| 组合 | 客户端 RTT | 结论 |
|---|---:|---|
| v2 + raw（基线） | 78ms | — |
| v3 + af_packet | 217ms | ✗ |
| v3 + **raw** | 225ms | ✗ → 与发送路径无关，是 v3 代码 |

排除了发送路径后只剩 recvmmsg。回退后 RTT 立刻回到 80ms。

**机制**：延迟确认（RFC 1122 的「每 2 段或 40ms」）能及时发出，靠的是主循环
每 5ms 醒一次的心跳。批量收包让 `drainAvailable` 在一次循环里连转几十轮、
连续处理几百帧，**主循环长时间回不到 `select`**，5ms 心跳被拉长成「等这一批收完」。
于是无新包时的 ACK 只能等到下一批——退税成一个往返。

这与 2026-11-14 19:05 修的是**同一个 bug**，只是载体变了：
那次是「只在 `Recv` 返回后判定」，这次是「批量的批变长了」。教训是：

> 「省 syscall」的优化必须连带检查它有没有改变**主循环的返回频率**。
> 心跳类机制（延迟确认、定时 flush、超时判定）全部依赖这个频率。

**另外**：`session.go` 与 `listener.go` 两处 `drainAvailable` 都留了注释，
写明「不要改成 recvmmsg」以及代价数据，避免下次有人重复这个实验。

## 123. 服务端发送路径：AF_PACKET 才是默认值，RAW 只是回退（2026-11-15 13:20）

`arpLookup` 里那句照抄 Rust 的 `from_str_radix("0x2", 16)` 让 AF_PACKET
**从来没被启用过**（`/proc/net/arp` 的 Flags 是 `"0x2"`，带前缀，解析必然失败）。
副作用有两笔，这次一起清掉：

| 项 | RAW | AF_PACKET | 说明 |
|---|---:|---:|---|
| 单流吞吐（1 核 ARM） | 5 MB/s | 15~23 MB/s | DEVTIPS 96 早量到 |
| 每次建连固定等待 | ~514ms | 0 | ARP 查不到时的 25×20ms 轮询 |

修法不是简单「剥掉 0x 就开 AF_PACKET」，必须同时满足三个前提，否则会静默不通：

1. **源地址必须是本机网卡地址**。AF_PACKET 不像 IPPROTO_RAW 那样用出接口地址
   回填 `iph->saddr`，NAT 云主机填公网地址会被网关反欺骗静默丢弃（DEVTIPS 87）。
   → `addrOnHost()` 检测 + 自动换成探测到的出口地址。
2. **发往本机/回环的目标必须走 RAW**。AF_PACKET 的下一跳是从默认路由算的
   （网关 MAC + 物理网卡），把发往 `127.0.0.1` 的包按那个下一跳送出去会跑到网关，
   本机联调直接断。→ `isLocalDst()` 判断。
3. **`PACKET_QDISC_BYPASS` 默认关闭**。e1000/QEMU 上它让 `sendto` 返回成功但包
   不上线（DEVTIPS 84）。→ 只留 `FLOWTLS_QDISC_BYPASS=1` 手动开。

最后一个选择：**客户端默认仍用 IPPROTO_RAW**。下载方向客户端只发 ACK，
实测把客户端也换成 AF_PACKET 后吞吐无差别（19.8 vs 18.4 MB/s，链路漂移内），
却要付旁路 conntrack 的风险。所以 `newRawSocket` 增加 `wantAFPacket` 参数，
由调用方按方向决定：服务端 true、客户端 false。用 `FLOWTLS_AF_PACKET=0/1` 可强制覆盖。

顺带：ARP 只在真要 AF_PACKET 时才查，**IPPROTO_RAW 路径完全不碰 `/proc/net/arp`**，
那笔 514ms 的纯等待自然消失（实测建连 220~241ms）。

## 124. 换 AEAD 算法要看目标 CPU 有没有硬件加速（2026-11-15 13:20）

`codec_bench_test.go` 在两端各跑一次的结果：

| 算法 | amd64 | ARM（有 aes+pmull+sha2） |
|---|---:|---:|
| ChaCha20-Poly1305 | 1959 ns | **6753 ns** |
| AES-128-GCM | 828 ns | 1305 ns |
| AES-256-GCM | 1045 ns | 1589 ns |

ARM 上 AES-GCM 快 **5.2 倍**，amd64 只快 2.4 倍。差别在于：x86 的 AES-NI 与
ARMv8 的 Crypto Extension 都是硬件指令，而 ChaCha20 两边都只有 SIMD 实现
（NEON 的收益远小于 x86 的 AVX）。

**但别把 5.2 倍当成吞吐的 5.2 倍**：6753ns/包 × 9400pps（100Mbps 单向）≈ 6.3% 单核，
加密本来就不是主要瓶颈。实测换完之后服务端 CPU 只从 71.8% 降到 63.1%
（−8.7pp），吞吐涨 36%——涨得比 CPU 降幅多，因为省下的用户态时间
让包处理更快、在途数据更早被 ACK，间接把窗口利用起来了。

真正的瓶颈仍然是**内核态**（46.6%）：伪 TCP 要自己构 IP/TCP 头、
每包一次 `sendmmsg`/`recvfrom`、过 qdisc 与驱动。要再压就动这一层，
不是继续换加密算法（ChaCha20 换成 AES 已经把这层的收益吃干净了）。

## 125. 「同一份旧二进制换个端口」是排除代码嫌疑的最快办法（2026-11-15 14:05）

本轮差点把一个**链路属性**当成自己引入的回归写进文档。

**现场**：换 AES + AF_PACKET 之后，交替测量显示旧通道（rev.1→8443）
77~82ms、新通道（v3→9443）220~228ms，12 轮全部稳定。
我据此判定「RTT 恶化一个往返」，并归因于 recvmmsg 批量收包（已回退）。

**证伪**：起第三组——**同一份未改动的 rev.1 二进制**，只把监听端口从 8443
换成 9743：

```
8443=0.0765s   9743=15.1s → 1.19s → 0.222s → 0.221s …
```

**同代码换端口就从 77ms 变 221ms**。再把两个版本的端口对调：

| 拓扑 | v3 | rev.1 |
|---|---:|---:|
| 原：rev1@8443 / v3@9443 | 226ms | 77ms |
| 换：v3@8443 / rev1@9443 | **221ms** | **220ms** |

**两个端口都变成 220ms，旧代码也一样慢。** 说明 220ms 是这条跨境链路的
**流级别/时段性两态**（历史记录里也见过「77ms ~ 235ms，同一会话内变化」），
与本仓任何改动无关。

**教训**：

> 判断「这个改动有没有引入回归」时，对照组必须**只变一个变量**，
> 而「变代码」这一侧往往还偷偷带了别的东西（这里是监听端口、5 元组、NAT 映射）。
> 最省事的对照是**让旧二进制去占新端口**：一行配置，代码零改动。
> 如果旧代码在新端口上一样差，那这条链路就根本不能用来证明回归。

顺带一条：**先确认链路本身有没有两态，再谈实现差异**。
本轮若不去做这次对照，就会把一个错误结论固化进 `drainAvailable`
的注释里，以后每次有人想用 recvmmsg 都会被这条假结论挡住。

验证 `recvmmsg` 是否真的有害，正确做法是在**同一端口上交替重启两个二进制**，
而不是各占一个端口并行测。

## 126. PACKET_QDISC_BYPASS：有效，但要按驱动白名单开（2026-11-15 14:20）

**有效**：生产服务端 `virtio_net`（1 核 ARM）传 100MB 的服务端 CPU 从
**0.044 → 0.038 CPU秒/MB（−13%）**，交替 ABAB 各 3~5 轮，结论稳定。

**但不能无条件开**：它在 e1000/QEMU 上会让 `sendto` 返回成功而包不上线
（DEVTIPS 84）。那种失败**完全静默**——伪 TCP 层没有重传，现象只是
「握手永远超时」，日志里一个字都没有。

所以用**驱动白名单**：

```go
var allowedQdiscBypassDrivers = map[string]bool{"virtio_net": true}
```

驱动名读 `/sys/class/net/<if>/device/driver` 符号链接的 basename。
读不到就返回空串，空串不在白名单里 → 保持关闭（**失败方向朝安全的一侧**）。

三个附带决定：

1. **启动日志如实报告**：`SendMode()` 输出 `af_packet+qdisc_bypass`。
   这个开关在错误驱动上会静默丢包，「以为开了/以为没开」是排查时必须
   一眼看清的信息。
2. **不用全局默认值**。将来验证了新驱动就往白名单里加，
   而不是把默认改成 true——默认值一改，所有未验证的部署一起承担风险。
3. `SetsockoptInt` 的返回值不再忽略：失败就不打 `+qdisc_bypass`，
   避免日志谎报。

## 127. 「每包自建 IP/TCP 头」只占约 1% 单核，别优化它（2026-11-15 14:20）

曾把「构包开销」列进内核态优化的待办。实测后否掉：

| 项 | ns/op |
|---|---:|
| `BuildPacketInto`（1332B 载荷，两次校验和） | 1001 |
| 　　其中 `sum16` 扫描 1364 字节 | 294 |
| `BuildPacketInto`（纯 ACK，52 字节） | 62 |

9400pps（100Mbps 单向）= 0.94% 单核；16 MB/s（15700pps）≈ 1.6%。
**它不是瓶颈**，和当初误判「加密是瓶颈」是同一个错误类型：
真正的时间全在 syscall 与内核态（46.6%）。

结论：构包这一层不要动。想继续压 CPU，只能从下面三条里选：

1. **减小包数**（提高 QUIC MTU）——受路径实测 MTU ≥1428 限制，
   当前总包 1417，最多还能提 ~1%，不值得。
2. **减少 syscall 次数**——发送侧已经是一次 `sendmmsg` 交 64 个包；
   接收侧若改 `recvmmsg` 必须先解决「怎么在同一端口上做可信 A/B」，
   见 DEVTIPS 125。
3. **绕开内核拷贝**——`AF_PACKET` 的 TX_RING（mmap 零拷贝环），
   能省掉每包一次 skb 分配 + 用户态→内核拷贝，但工程量与风险都大得多，
   且 TX_RING 满了会直接丢包，需要自己处理背压。

## 128. 本地入口一律 `0.0.0.0`，写回环 = 只有本机能连（2026-11-15 14:35）

这条是**部署要求**，不是风格偏好，写进 `AGENTS.md` 约束 19。

写 `"listen": "127.0.0.1"` 的后果：

| 使用场景 | 结果 |
|---|---|
| 本机浏览器 / curl | ✅ 正常 |
| 局域网里的手机、平板、另一台电脑 | ❌ 连不上 |
| Docker 容器（`host.docker.internal` / 网桥 IP） | ❌ 连不上 |
| WSL2 / Hyper-V 虚机 | ❌ 连不上 |
| 手机热点共享给本机再用 | ❌ 连不上 |

**为什么容易被误判**：现象只有「Connection refused」，`sing-box check`
完全通过，客户端日志里隧道看起来一切正常（`通道已建立`）。于是第一反应
是「隧道坏了」或「服务端挂了」，实际只是入口没监听在可达地址上。

代价必须讲清：绑 `0.0.0.0` 等于把带口令的 SOCKS5/HTTP 入口开放给整个
局域网。所以两条一起做：

1. `users` 里的口令**必须改掉示例值**（它与外层 AEAD 的 `password`
   是两套东西：前者是本地入口凭据，后者是隧道密钥）；
2. 只需要本机时，用防火墙限网段（`iptables -A INPUT -p tcp --dport 1080
   ! -s 192.168.0.0/16 -j DROP`），**不要**改回 `127.0.0.1`。

已同步：`deploy.example/client.json`、`README.md`、`docs/MIGRATION.md`、
`AGENTS.md` 约束 19。

## 129. 内核态优化实测：recvmmsg 无收益，TX_RING 负收益（2026-11-15 16:00）

上一轮把「接收侧 recvmmsg」与「AF_PACKET TX_RING」列为内核态优化的两条待办。
两条都完整实现并做了同端口 ABAB 交替测量，**结论是两个都不值得做**。

### 判据选择：CPU秒/MB，而不是吞吐

吞吐受跨境链路两态影响（77ms ↔ 220ms），CPU秒/MB 只取决于「每字节花多少 CPU」，
是唯一稳定的指标。两者同时记录，但只用前者下结论。

### recvmmsg（一次 8 帧）：0.0388 vs 基线 0.0402

| 档 | n | CPU秒/MB 中位 | 范围 |
|---|---:|---:|---|
| 逐帧 recvfrom | 8 | 0.0402 | 0.0378 ~ 0.0431 |
| recvmmsg 8 槽位 | 6 | 0.0388 | 0.0376 ~ 0.0431 |

差 3.5%，但**两组范围几乎完全重叠** → 噪声内，不成立。

理论上限也能对上：一轮约 55 帧（15 MB/s ÷ 1417），
逐帧 55 次 syscall vs 批量 7 次，省 48 次 ≈ 24µs；
而处理 55 帧共约 3ms（0.0402 × 55 × 1417 / 1e6…），
省下的占 **不到 2%**。所以「批量收包能省很多」这个直觉是错的——
**syscall 次数本来就不是瓶颈，每包的内核处理才是**。

处置：实现保留（默认关闭，`FLOWTLS_RECVMMSG=1` 开启），
因为它是惰性的、无副作用的，留作高 pps 场景（>50k pps）的备选。
默认路径仍是逐帧。

### TX_RING（mmap 零拷贝环）：0.0426，比基线**慢 16%**

| 档 | CPU秒/MB 中位 |
|---|---:|
| recvmmsg | 0.0368 |
| txring | **0.0426** |
| both | 0.0423（≈ txring，说明 TX_RING 主导且是拖累） |

原因：TX_RING 只省掉「用户态→内核」那一次拷贝，而内核在 `tpacket_snd` 里
**仍要** `skb_copy_to_linear_data` 把帧拷进 skb。同时它要求：

1. **必须 SOCK_RAW**：SOCK_DGRAM 下 TX_RING 无法指定目的 MAC
   （环里没有放 sockaddr_ll 的地方，sendto 的 sll 只用于选网卡）。
   实测 4 种 `tp_mac`/`dataOff` 组合全部「提交成功但包不上线」——
   与 QDISC_BYPASS 同类静默失败（DEVTIPS 84）。
2. SOCK_RAW 要自己写 14 字节以太网头，内核再解析一遍链路层。
3. 多一个 fd + 1.7MB mmap，环满即丢包要自己处理。

**净效果是负的**。生产代码已删除，只保留 `flowtls/txring_probe_test.go`
作为可执行的证据（它自包含常量与结构体，不依赖生产代码）。

### 教训

> 「零拷贝」这个词容易骗人：要看清省的是**哪一次**拷贝。
> 用户态→内核省掉了，内核→skb 那一份照样在，反而多付了链路层头的开销。

> 优化前先算理论上限。recvmmsg 的理论上限是 2%，实际测出 3.5% 噪声——
> 两者一致说明「没收益」是对的结论，不是测量失败。

## 130. 内核态 A/B 必须 ABAB 交替，AAA-BBB 会测出假收益（2026-11-15 16:00）

本轮第一次测 recvmmsg 用的是「6 轮 off → 6 轮 on → 6 轮 off」：

```
off  0.0418 0.0401 0.0405 0.0397 0.0414 0.0415   中位 0.0414
on   0.0399 0.0371 0.0392   --   0.0330 0.0369   中位 0.0371
off2 0.0353 0.0357 0.0395 0.0359 0.0379 0.0383   中位 0.0379
```

看起来「on 比 off 快 10.4%」。但 **off2 与 on 几乎一样**（0.0379 vs 0.0371），
说明差异来自**时间漂移**（后跑的组更快：链路状态变化 / 服务端预热 /
BBR 学习），不是 recvmmsg。

改成 ABABAB 交替（每档 3 轮 × 3 循环）后，两组中位变成 0.0402 vs 0.0388，
差异缩到噪声内。

**必须 ABAB 的理由**：漂移是单调的（随时间变好或变坏），
AAA-BBB 会把漂移**全部记在 A/B 差值上**；ABAB 则把它均摊到两组。

配套的两个坑（都会让某一档全部测成 0，看起来像「代码跑不动」）：

1. **服务端切换后 sleep 2 不够**：`server.json` 带 `masquerade`，
   它会 bind 内核 TCP 8443。上一个进程刚退出时端口仍被占，
   新进程 bind 失败直接 FATAL 退出 → 该档全部 0。要 sleep 5 并校验进程存在。
2. **客户端切换后要等 1080 真的 LISTEN**：同样的问题，且
   `ss -tln | grep :1080` 轮询比固定 sleep 可靠。
3. `env $env cmd` 在 `env` 为空时会去执行名为 `":"` 的程序
   （如果把档位写成 `"base: :"`）→ 客户端直接不启动。空档要显式分支。

脚本已固化为 `docs/ab_kernel.sh`（ABAB + 两处启动校验）。

## 131. 测量脚本里写死 `ssh -J 跳板 目标` = 换个地方泄露（2026-11-15 17:10）

新增 `docs/ab_kernel.sh` / `docs/ab_recvmmsg.sh` 时，为了方便直接把
`SSH="ssh -J root@<跳板> root@<服务端>"` 写进了脚本。CI 的
`docs/leak_check.sh` 立刻报出两个可疑公网 IPv4 并失败。

**为什么我犯了同样的错**：门禁是在脚本**写完之后**才想到要跑的，
而提交前的最后一次 `make verify` 当时**不含** leak_check——
`verify` 只校验版本号与 tags，leak_check 只在 CI 里跑。
于是「本地全绿 → 推送 → CI 红」。

两个修正：

1. **脚本一律参数化**：连接哪台机器从环境变量取，不写死在仓库里。
   ```bash
   : "${FLOWTLS_SERVER:?请设置 FLOWTLS_SERVER（例如 root@203.0.113.10）}"
   SSH="ssh ${FLOWTLS_SSH_OPTS:-} -o ConnectTimeout=15 ${FLOWTLS_SERVER}"
   ```
   必填变量用 `:?` 展开，漏设时给出一条能直接照抄的示例，
   而不是让脚本带着空地址跑出诡异结果。
2. **leak_check 接进 `make verify`**：本地验收入口能拦住的事不该等 CI。
   同时加 `make leak` 单独入口（不需要 build，随时可跑）。

**通用规则**：任何**脚本/配置/文档**里出现机器地址的地方，都要问一句
「这个地址是不是只对某个部署成立」。是的话它就不能进仓库，
哪怕只是「临时测量用」。

另外：真实的跳板与服务端 IP 之前已被判定为**已泄露并应按泄露处置**
（CHANGELOG 2026-11-15 01:10），所以这次复发没有额外扩大暴露面，
但它仍然是错的——门禁存在的意义就是不让「反正已经泄露了」变成习惯。

## 132. 「转向 quic-go 用户态路径」这个待办，三样里两样改不了（2026-11-15 17:30）

上一轮在 `PROJECT_PLAN` 里留了一条「下一步应转向用户态传输层
（ACK 策略 / 发送调度 / BBR 参数）」。逐行读完依赖后必须收回一半：
**ACK 策略和 pacing 根本没有配置入口**。

查证位置（都是硬常量，不是配置）：

```
quic-go/internal/ackhandler/received_packet_tracker.go:79
    const packetsBeforeAck = 2
quic-go/internal/protocol/params.go:150
    const MaxAckDelay = 25 * time.Millisecond
quic-go/connection.go:536
    false, // ACK_FREQUENCY is not supported yet
```

`quic.Config` 的 30 个字段里没有一个是 ACK 或 pacing 相关。

**连带结论：hy2（sing-box 版）也改不了。** 它和我们用同一份
`sagernet/quic-go` fork，`hysteria2/client.go` 里 grep `ack` 零命中。
所以「hy2 比我们 ACK 更激进」这个猜测不成立——两边一样。

**我们比 hy2 少的**：`bbrProfile` 配置项（我们硬编码 `ProfileStandard`）
与 Brutal 拥塞控制（Rust 版也没有，刻意不加）。
**我们比 hy2 多的**：`cappedBbr` 窗口上限钳制 + 丢包率自适应窗口。

**发送调度的差异不是设计选择**：hy2 靠内核 UDP GSO 合批（1 次 64KB），
我们跑在 AF_PACKET 上**没有 GSO**，所以只能手写 `sendmmsg(64)`。
换句话说 sendmmsg 不是「优化」，是「没有 GSO 的必然替代品」。

顺带记一处**实现与设计文档的偏离**：`PROJECT_PLAN §3` 写的是
「`WriteTo` 内同步 sendto（无队列、无额外协程）」，实际实现有
`txCh`(64) + 独立 `txLoop`。历史原因是 sendmmsg 必须攒批。
这个偏离有代价——quic-go 在调 `WriteTo` **之前**就记录了发送时刻，
本地排队会被算成网络 RTT。v1 用 4096 深队列曾把 RTT 从 73ms 抬到 213ms，
现在 64 深 + 醒来立即排空把影响压到 srtt 80~85ms（≈ 链路 74ms + 延迟确认）。
**知道它是有代价的设计，比以为它免费要好。**

以后要探索的方向已写进 `PROJECT_PLAN`，按性价比排序：
重写 `internal/` 常量（违反约束 9，需单独评估）> 重标定 `cappedBbr` 阈值
（不改依赖、风险最低）> 减少包数（上限 1%，不做）。

---

## 133. WinDivert 是「扣留」不是「旁听」：不是我的包必须还回去（2026-11-15 18:30）

移植最大的坑不是编码或 IOCTL，是**语义**。两条路径对「这个包不是我的」的处理
完全相反：

| | Linux `AF_PACKET` | Windows `WinDivert` |
|---|---|---|
| 内核看到这个包吗 | **看到**（我们是旁路复制） | **看不到**（包被驱动摘走） |
| 「不是我的包」正确动作 | **忽略即可** | **必须 `Send` 回去** |
| 忘记处理的后果 | 无（内核照旧处理） | 包被销毁：同端口真实网站静默失效 |

所以 `listener.go` 的 `handlePacket` 返回了第二个值 `consumed`：

```go
// handlePacket 报告这个包是否被本协议消费。
// 未消费的包在 Windows 上必须重新注入（AF_PACKET 上 Reinject 是空操作）。
func (l *Listener) handlePacket(p []byte) (*Session, bool)
```

`recvFrame` 里只要 `!consumed && l.raw.reinjectUnmatched` 就调 `Reinject`。
`Reinject` 在 Linux 上是**语义正确的空实现**（返回 nil，不是「不支持」）：
AF_PACKET 是被动复制，内核本来就有这个包，再注入一次会发重复包。

顺带一个反直觉的结论：**Windows 不需要任何 iptables 等价物**。Linux 上必须用
`raw/PREROUTING` 把伪包 DROP 掉，否则内核会对「不存在的连接」回 RST，而 RST 会
让中间设备拆 NAT 映射。Windows 上被扣留的包内核从没看见，RST 根本不会产生。
Linux 需要「DROP 规则 + 旁路收包」两个机制配合，Windows 一个过滤器就同时办到了。
（`rules_windows.go` 的 `init()` 把 `rulesBackendEnabled` 置 false 就是这个道理。）

### 注入会不会形成自环

不会。WinDivert 文档明确「同一优先级的包只被扣留一次」，而我们只开一个句柄。
若为了「收发分离」拆成两个句柄，第二个句柄会收到第一个句柄注入的包 → 自环 →
每包被复制一次，表现为 QUIC 疯狂重传。**不要拆。**

---

## 134. 无法核对的驱动字段号，宁可不写进过滤器（2026-11-15 18:30）

原设计想在 WinDivert 过滤器里直接用 IP ID 标记筛包（省掉每包一次用户态判断）：

```
inbound and ip and tcp.DstPort == 8443 and ip.Id >= 0xf100 and ip.Id <= 0xf1ff
```

放弃原因值得单独记一条：**`windivert.h` 没有 vendor 进本仓库**，
`ip.Id` 的字段号（18）无法在本仓库内核对。而字段号错一位的后果不是报错，是
**一个包都收不到** —— 与「服务端没开」「防火墙挡了」「链路断了」的表现完全
相同。这类故障在 Windows 上没有 `tcpdump` 那种一眼看穿的排查手段。

最终方案：过滤器只按「入向 + IPv4 + TCP + 端口」粗筛，IP ID 标记继续在用户态
`handlePacket` 里判断（`(ip_id & mark) == mark`）。代价是每包多一次内存读取，
换来「出问题时能加日志看清是收不到还是判断错」。

**一般化**：只把能对着仓库里源码或文档逐字核对的常量写进内核侧/驱动侧。
核对不了的，放用户态。用户态多花的那点 CPU，永远比「静默收不到包」便宜。

字段号现在只用这几个（都在 `windivert_filter.go` 里带注释）：
`Zero=0 Inbound=1 Outbound=2 IP=5 TCP=8 TCPSrcPort=38 TCPDstPort=39`。

**后续（2026-11-15 21:00）**：`TCPSrcPort=38` 已在真机上验证可用。
当时的测量是在「注入包校验和位设错」的版本上做的（见第 140 条），
那时所有手工构造的包都被中间设备丢弃，因此「加了 38 就收不到包」的结论不成立。
教训：**在链路上有已知 bug 时做的 A/B 对比不可信**，要先修好链路再验证参数。

---

## 135. 全平台编译门禁：字段名不一致能让 macOS 坏半年没人发现（2026-11-15 18:30）

`socket_stub.go`（macOS/FreeBSD 空实现）自己的注释写着「保证能交叉编译」，
实际**从来没编译过**：

```go
// 上层代码（client.go:129 / listener.go:175）：
if s.raw.localIP.IsValid() { ... }   // 按**字段**读
// socket_stub.go 里只有：
func (s *rawSocket) LocalIP() netip.Addr { ... }   // 方法，不是字段
```

`GOOS=darwin go build` 报的是 `s.raw.localIP undefined (type *rawSocket has no
field or method localIP, but does have method LocalIP)`。

为什么半年没人发现：发行目标只有 Linux，CI 也只编 Linux。而 macOS 上的
`sing-box check` 是真实场景（Mac 用户写配置要先校验），编译不过等于适配层白写。

修法两层：

1. 空实现的**字段/方法集合必须与真实实现对齐**，不是「能过编译就行」。
   `rawSocket` 的 `localIP` 是字段，stub 就也必须是字段。
2. `make verify` 与 CI 都跑 `make platforms`（8 个组合，只要几秒）：

```
linux/amd64 linux/arm64 linux/arm
windows/amd64 windows/386
darwin/amd64 darwin/arm64 freebsd/amd64
```

只编不跑，不需要任何特权。**darwin/freebsd 永远不会运行，但必须能编译。**

同一类问题的另一个来源：`listener_test.go` 曾直接 `&rawSocket{sendFD: -1, ...}`
构造对象，而 Windows 的 `rawSocket` 没有 `sendFD` 字段。现在测试辅助按平台
拆成 `socket_linux_test.go` / `socket_windows_test.go` 各一份 `newTestRawSocket`，
公共断言留在 `listener_test.go`（无 build tag）。

---

## 136. 「未消费」不等于「不是我的」：还给内核的判据是 IP ID 标记（2026-11-15 19:10）

第 133 条说了「未消费的包必须还给内核」。**这条说它不完整**，第一版实现就踩了。

第一版写的是：

```go
sess, consumed := l.handlePacket(p)
if !consumed && l.raw.reinjectUnmatched {
    l.raw.Reinject(raw)     // 错
}
```

看起来天经地义，实际会把隧道打断。`consumed == false` 有两类完全不同的情况：

| 情况 | 带 IP ID 标记 | consumed | 该怎么做 |
|---|---|---|---|
| 伪装站的真实浏览器流量 | 否 | false | **还给内核**（否则伪装站死了） |
| 探测器扫端口 / 我们自己的客户端认证失败 / 乱序首包 | **是** | false | **丢弃**（还给内核会引出 RST） |
| 已关闭会话的残留包 | 是 | 我第一版返回 false → 也是错的 | 丢弃 |
| 正常数据 / SYN | 是 | true | 不还 |

第二、三类还给内核的后果：内核里没有对应 socket → 回一个 **RST** → RST 是协议
合法的终止信号 → 中间设备立刻拆 NAT 映射 → 而客户端源端口固定，正在重建的
**同一个四元组**，于是隧道断了，且现象是「莫名其妙掉线，重连有时好有时不好」。

正确判据就是 Linux 侧 iptables 用的那一条：

```
0x4&0xff00ffff=0x<mark>4000      # u32：IP ID 高字节 == mark
```

所以代码改成 `shouldReinject(p, consumed)`：

```go
if !l.raw.reinjectUnmatched || consumed { return false }
return !l.protocolOwned(p)   // p.IPID&l.mark == l.mark 就是本协议族
```

顺带纠正一个概念混淆：**带标记 ≠ 认证通过**。标记只是「这个包被本协议占用」
的声明（防探测靠 IP+mark+SNI 三者不公开），真正的鉴权是首包的 AEAD 认证。
两件事必须在代码里分开表达。

这条决策在 Linux 上永远跑不到（`reinjectUnmatched` 恒为 false），所以抽成纯函数
加真值表单测（`reinject_test.go`）。写测试时第一版用例用了 `mark+1` 当「不带
标记」，被测试当场拦住——低字节是每包递增的序号，本来就不参与判定。

---

## 137. 收包元数据必须跟帧配对：存字段必然错配（2026-11-15 19:10）

WinDivert 注入入向包时要带原始 `WINDIVERT_ADDRESS`（里面含 `IfIdx`）。
第一版把它存在 `rawSocket.lastAddr` 字段上，注释还写着「只有 recvLoop 一个协程
会立刻用，不需要加锁」。

**这是错的。** 收包和处理不在同一个协程里：

```
goroutine: Recv → 复制 frame → 取 lastAddr → channel(cap=1) ─┐
主协程:                                        └→ recvFrame → Reinject(lastAddr)
```

goroutine 在把 frame 塞进 channel 后立刻开始下一次 `Recv`。只要它比主协程处理
快一步，`lastAddr` 就被下一帧覆盖了 —— `Reinject` 注入到**别的网卡**的地址上，
包落到不存在的接口，丢弃。表现为「伪装站偶发连不上」，TCP 会重传所以不是彻底
坏，反而更难查。

修法是让元数据跟着帧走，而不是存在对象上：

```go
type frameHandle any                      // socket_common.go

h := l.raw.TakeFrameHandle()              // Recv 一返回就取快照
frames <- recvResult{frame: frame, h: h}  // 与 frame 一起传递
l.recvFrame(buf[:n], h)                   // 处理时用同一个 h
l.raw.Reinject(raw, h)                    // 注入用 h，不读字段
```

`TakeFrameHandle` 的语义被写死成「**只保证 Recv 返回后、下一次 Recv 之前有效**」，
`lastAddr` 的字段注释也改成「直接读这个字段是 bug」。

一般化：**跨协程的「最近一次」状态都是定时炸弹**。管道里流动的东西必须整体流动，
不要拆成「数据走管道、元数据走字段」。这个坑在 Linux 上不存在（AF_PACKET 不需要
注入），只在 Windows 出现，所以特别值得记。

---

## 138. 发行矩阵不能凭「我们支持」来填：windows/386 是上游编不出来（2026-11-15 19:10）

我们的 `windivert_assets/` 有 `WinDivert32.sys`，flowtls 模块的 build tag 也是
`windows && (amd64 || 386)`，于是很自然地把 `windows/386` 加进了 `build.yml`
的发行矩阵。

**编不出来**，而且不是我们的问题：

```
package github.com/sagernet/sing-box/cmd/sing-box
    imports github.com/sagernet/sing-box/protocol/naive
    imports github.com/sagernet/cronet-go/all: build constraints exclude all Go files
```

`DEFAULT_BUILD_TAGS_WINDOWS` 含 `with_naive_outbound`，它依赖 `cronet-go`，
而 `cronet-go` 没有 386 的实现。不能靠去掉这个 tag 来绕过 —— 那会发出一个比官方
版少特性、同一个版本号却能力不同的二进制（Makefile 里已经为 windows tag 列表
踩过一次坑）。

所以发行矩阵只有 `windows/amd64`，并在 yaml 里写清原因和「上游补齐后加回来」。
我们自己的模块仍然支持 386（交叉编译门禁里有 `windows/386`），一旦上游补上就能
直接开。

**教训**：「我们的代码支持 X」不等于「发行版能出 X 产物」，发行矩阵必须真的构建
一次才能确认。这次是靠本地 `go build` 完整二进制才发现的——`make platforms` 只编
flowtls 模块，看不到这类上游依赖问题。

---

## 139. 内嵌的 LGPLv3 驱动必须随包附许可证（2026-11-15 19:10）

`WinDivert64.sys` 以 `//go:embed` 变成字节数组进二进制，运行时落盘成 `.sys` 加载。
它和我们的代码是**聚合**关系（独立的内核模块，不是衍生物），但 LGPLv3 对再分发
二进制有硬要求：**必须附许可证原文**。

第一版只在仓库里放了 `windivert_assets/LICENSE.txt`，用户解包后看不到，等于没附。
现在打包步骤在 windows 产物里多放：

```
licenses/WinDivert-LGPLv3.txt
licenses/WinDivert-SHA256SUMS.txt
```

只对 windows 产物加：`go list -f '{{.EmbedFiles}}'` 在 Linux 视角是空的，
Linux 二进制里没有这些字节，附上反而是误导。

## 140. WinDivert 注入的包，校验和位要留 0 让驱动重算（2026-11-15 21:00）

第一版发送时把 `WINDIVERT_ADDRESS` 的 `IPChecksum` / `TCPChecksum` 位置 1，
本意是「我们已经算好了，别动」。真机上的结果是网卡抓到的出向包
IP 校验和恒为 `0x0000`：这两位置 1 会让驱动走 `WINDIVERT_HELPER_NO_*_CHECKSUM`
分支（`sys/windivert.c` 的写路径），跳过重算；而网卡开了校验和卸载，会把软件
填的值清成 0 再交给硬件。中间设备直接丢掉校验和为 0 的包，服务端一个 SYN 都收不到。

位留 0 后驱动会调 `WinDivertHelperCalcChecksums` 重算再注入，网卡上仍然显示 0
（卸载之后的显示），但线上是正确的。判断依据是服务端能不能回 SYN-ACK，不是网卡抓包。

## 141. WinDivert 给的是裸 IP 包，ParseFrame 只认以太网帧（2026-11-15 21:00）

Linux 的 `AF_PACKET` 收到的是带 14 字节以太网头的帧，`ParseFrame` 先读 EtherType 再找 IPv4。
WinDivert 的 NETWORK 层直接给裸 IP 包。原样送进去，解析出来是 `ok=false`、空 IP，
于是 SYN-ACK 到了驱动、日志里也看得到，但握手永远完不成。

修法是收包时补上 14 字节以太网头（MAC 全 0，EtherType `0x0800`），让上层解析不变；
重新注入给驱动时再剥掉，驱动要的是裸 IP 包。

## 142. 客户端过滤器只按目的端口会扣下别人的回包（2026-11-15 21:00）

客户端用固定的 `source_port`。过滤器如果只匹配「入向 + 目的端口 == source_port」，
本机上其它进程连同一个服务端端口时，回包的目的端口是系统随机分配的，
有概率撞上这个固定值。撞上后那个连接的回包被我们扣下、内核收不到，对端连接被掐断，
而且这些包会混进本会话（真机上看到过序号对不上的 `[AF]` 包）。

加上 `tcp.SrcPort == serverPort`（字段号 38，来自 sing-box 已验证的 `fieldTCPSrcPort`）后，
只收来自我们服务端端口的回包。第 134 条曾记「字段号 38 测不通」，那次测量是在校验和
bug 没修时做的，结论不成立。

## 143. 「Windows 不需要防火墙规则」只对伪包成立，对代理端口不成立（2026-11-15 22:40）

`rules_windows.go` 里那句结论被验证过一半就写进了文档，代价是用户第一次在手机上
连不上代理时完全无从下手。

**两套机制在不同层，必须分开看**：

| | 伪包收发（隧道本体） | 入站代理端口 |
|---|---|---|
| 机制 | WinDivert 扣留/注入 | 内核 TCP socket |
| 与防火墙关系 | 子层权重 `UINT16_MAX`，在过滤之前 | 一视同仁，局域网入向会被拦 |
| 需要规则吗 | **不需要** | **需要**（否则局域网连不上） |

真机实测（进程正常、监听 `0.0.0.0:1099`）：

| 规则状态 | 从局域网 `10.0.0.2:1099` 连 |
|---|---|
| 无任何规则 | 超时（**静默丢弃**，不报拒绝连接） |
| 有程序级放行规则 | `http=200`，0.3s |

注意「静默丢弃」这个现象：它和断网、服务端没开、链路不通完全同形，是最难自查的
一类故障。所以不要把「超时」自动解读成链路问题。

### 为什么可以自动放行而不用弹窗

加载 WinDivert 驱动本来就要求管理员，进程一定有权写防火墙规则。规则只要在
任何 `listen()` **之前**就存在，Windows 连那个「是否允许此应用访问网络」的框都
不会弹。实测：删光规则 → 启动 → 规则自动出现 → 局域网立即 200。

### 放行的位置有硬约束

- **不能放在构造函数里**：`sing-box check` 会完整走一遍 `box.New()` 再 `Close()`
  而不调 `Start()`。放在构造函数里会让纯语法检查也要求管理员。
  实测验证：`check` 后规则数仍为 0。
- **不能放在 inbound 启动之后**：那时 Windows 已经弹过框了。
- 所以位置只能是 `box.start()` 里、`startComponents(inbound)` 之前。

### 覆盖范围是刻意的安全取舍

`profile=any`（域+专用+公用）。覆盖「公用」是为了让用户在酒店/咖啡馆 Wi-Fi 下
不用重新配置；代价是代理端口在不信任网络上也可达。防线是 inbound 的 `users`
口令——**部署时不要留默认口令**。

## 144. netsh 的子命令是两级的，`netsh add rule` 会静默返回 1（2026-11-15 22:40）

第一版写成 `exec.Command("netsh", "add", "rule", ...)`，漏了 `advfirewall firewall`
前缀。真机现象：规则没创建，日志只有一句 `exit status 1`，而 netsh 的错误文本在
中文系统上是乱码（`determine` → `确定?`），完全看不出是参数问题。

当时误判成「引号问题」并改了一轮，浪费了一个来回。教训有两条：

1. **`net/http` 式的 argv 传参不会替你补子命令层级**：手工在 PowerShell 里敲
   `netsh advfirewall firewall add rule ...` 成功，不代表去掉中间两级也能成功。
2. **报错时必须带上子进程输出**。现在失败时会返回
   `exit status 1: <netsh output>`，下次一眼就能看出「命令找不到」还是「权限不足」。

另外 `program=` 后面**不要加引号**：`exec` 把每个参数作为独立 argv 传下去，路径
里的空格本来就安全。加了引号反而让 netsh 把引号当成路径的一部分。
实测覆盖：`C:\Program Files\FlowTLS Test\sing-box.exe` 能正常创建规则。

## 145. rev.5 的防火墙只写 iptables，在 nftables 系统上等于没有（2026-11-16 23:10）

真机（ImmortalWrt 25.12，fw4/nftables）现象：

```
ERROR outbound/flowtls: 发送失败（累计 1 次）: sendmmsg: operation not permitted
ERROR outbound/flowtls: flowtls 初始建连失败: flowtls 握手失败: context deadline exceeded
```

`EPERM` 看起来像权限或 SELinux 问题，实际是 **fw4 主动 DROP**：
`accept_to_wan` 链里有 `ct state invalid ... drop`（防 NAT 泄漏），
我们的伪包没有对应内核 socket，被判定成 ct invalid，
而 netfilter 的 DROP 在 `sendto` / `sendmmsg` 里就翻译成 `-EPERM`
（`nf_hook_slow()` 把 `NF_DROP` 映射成 `-EPERM`）。

判据很简单，但必须先想到去查：

```sh
iptables-save | grep -c 44312      # 1  ← 规则"写进去了"
nft list ruleset | grep -c 44312   # 0  ← 但 nft 规则集里什么都没有
```

两条命令的差异说明规则落在 **xtables-legacy** 的表里，而 nftables 系统
根本不走那条 hook。所以 rev.5 在 nft 系统上是"看起来正常、实际不通"。

修法是优先用 nft 原生 `notrack`（priority raw，在 conntrack 之前），
不碰 iptables；nft 不可用时才回落。

## 146. PassWall 的版本号比较会被字母 v 截断，导致永远检测不到更新（2026-11-16 23:10）

`api.lua:to_check()` 里是：

```lua
local has_update = compare_versions(local_version:match("[^v]+"), "<",
    remote_version:match("[^v]+"))
```

`[^v]+` 不是"去掉前缀 v"，它是**在第一个字母 v 处截断**。
我们的版本号 `1.14.4-rev.5` 截断后变成 `1.14.4-re`，
`1.14.4-rev.6` 也变成 `1.14.4-re` —— 两者相等，`<` 恒为假。

所以补丁必须同时改两端，只改一端仍然不通：

- 本机：`cmd_version` 追加 `sed "s/-rev\./-r/"`，得 `1.14.4-r5`
- 远程：元数据里的 `tag_name` 写成 `1.14.4-r6`（不带 v）

## 147. PassWall 的共享字段 depends 是逐协议登记的，新协议必须手动补（2026-11-16 23:10）

`1_sing-box.lua` 末尾：

```lua
local protocols = s.fields["protocol"].keylist
for _, v in ipairs(protocols) do
    if not v:find("^_") then
        s.fields["address"]:depends({ protocol = v })
        s.fields["port"]:depends({ protocol = v })
        s.fields["domain_resolver"]:depends({ protocol = v })
        s.fields["domain_strategy"]:depends({ protocol = v })
    end
end
```

这段循环按当时的 `keylist` 展开。如果补丁在这之后才 `protocol:value("flowtls", ...)`，
选中 FlowTLS 时 `address` / `port` 这四个字段**一个 depends 都不命中，
整行不渲染**。

真机现象：协议能选 FlowTLS，密码也能填，但**服务器地址和端口整行消失**——
而密码能填是因为它有自己的一行 depends（补丁已单独补过），
这种"部分字段在、部分字段没了"最容易误判成"字段没创建"。

定位方法（比猜快得多）：在注入点把 `s.children` 的 `option` 逐行 dump 出来，
确认字段确实创建了 → 那问题一定在渲染阶段的 deps 过滤，不在创建。

## 148. 从 dofile 加载的 Lua 看不到 CBI 注入的全局名（2026-11-16 23:10）

补丁块第一版写：

```lua
local _ok, _f = pcall(dofile, "/usr/lib/lua/luci/passwall/flowtls_fields.lua")
```

结果 `attempt to call global 'translate' (a nil value)`。
因为 `dofile` 恒定用 `_G`，而 `translate` / `Value` / `ListValue` 是
LuCI 的 CBI 控制器**注入到当前 chunk 环境**里的，不在 `_G`。

正确写法（PassWall 自己也这么干）：

```lua
local _src = loadfile(path)
setfenv(_src, getfenv(1))
local _f = _src()
_f(m, s, s1)
```

另加一层 `xpcall` + 写 `/tmp` 与 syslog：注入点的 `pcall` 会吞掉所有异常，
"界面上少几个字段"本身不报错，不留痕就只能靠猜。

## 149. `password` 与 `users` 同填时顶层密码是死配置（2026-11-17 00:40）

> **已被第 166 条取代**：从 rev.12 起没有 `users[].name`，且 `password` /
> `passwords` / `users` 三者互斥，重复密码直接报错。本文记录的是当时的
> 二选一形态与为什么必须报错，结论（"不要静默忽略"）仍然成立。

服务端的凭据有两条路径，`effectiveUsers()` 里是**二选一**：

```go
if len(s.Users) > 0 { return 从 users 构造 }   // users 非空 → 只看 users
if s.Password != "" { return 单用户 }          // 否则才看 password
```

第一版实现是「以 users 为准，静默忽略 password」。这形成一个很难发现的陷阱：

- 顶层 `password` 既**不能登录**（authID 只登记在 users 表里），
- 也**不参与 ip_id_mark 派生**（`Marks()` 只遍历 effectiveUsers），
- 但配置文件里它明明白白写着，运维会以为它是兜底凭据或备用口令。

而 ip_id_mark 不一致的症状是**隧道完全不通**（伪包被内核层规则当垃圾丢掉），
排查成本极高——不会有人第一时间去怀疑"那个我没在用的密码"。

所以现在改为**直接报错**：

```
flowtls: password 与 users 不能同时配置 —— 只配 password 表示单用户；
配 users 表示多用户，此时 password 会被完全忽略（既不能登录、也不参与
ip_id_mark 派生）
```

附带的行为对照（都有单测钉住，见 `listener_test.go` 的
`TestPasswordAndUsersAreMutuallyExclusive`）：

| 配置 | 生效用户 | 派生出的 mark |
|---|---|---|
| 只填 `password` | 1 个 | 1 个（从它派生） |
| 只填 `users` | N 个 | N 个（各从自己的 password 派生，重复的会去重） |
| 两者都填 | —— | **报错** |
| 显式 `ip_id_mark` | —— | 单值，所有用户共用（覆盖派生） |

顺带一条**不用**拦的：多个用户用同一个 password 只是 authID 相同、
日志里的名字变成后一个，功能上完全正常（同一份凭据），所以不做校验。

### 150. 升级服务端时必须先杀旧进程——AF_PACKET 允许重复绑同一端口

`AF_PACKET` 没有 `SO_REUSEADDR` 那种互斥语义，**两个进程可以同时绑
`ETH_P_IP` 并各自收到每一份包**。所以「新版本先起、再停旧版本」的升级方式
会得到两个服务端同时响应同一个 SYN：各回一个 SYN-ACK（IP ID 标记、
TCP 序号都不同），客户端的伪 TCP 层只认一个，另一个变成持续的乱序/重复包，
表现为**随机比例**的连接失败。这种失败在服务端日志里完全看不出来
（两个进程都认为自己正常）。

查法：`ps w | grep "[s]ing-box run"` 看有没有两个 `-c` 指向同一个端口；
`ss -lunp | grep 8443` 看不到两个（raw 层不占端口）**不能**作为没重复的依据。
升级流程必须是：**先 `kill -9` 旧进程 → 确认进程数 0 → 再起新进程**。

### 151. `ip_id_mark` 两端必须逐位一致，rev.8 起的正确做法是两边都别配

客户端会用它给伪造 SYN 的 IP ID 置高字节标记，服务端**只认**这个标记
（`(ip_id & 0xFF00) == mark`）。两端不一致时：服务端 nft 规则不命中 →
伪造 SYN **不被 DROP**，于是落到本机内核，被 conntrack / masquerade
接住并回 RST，症状是「有时通、有时通不了」而不是「完全不通」。

rev.8 之后 `ip_id_mark` 由 password 派生（`DeriveIPIDMark`），所以两端
**都不要写** `ip_id_mark` 就是一致的。要写就必须两边写同一个值。
PassWall 节点里以前手工填的 `ip_id_mark` 一定要删掉，否则会覆盖派生值
（补丁包的 `flowtls_outbound.lua` 现在会强制 `result.ip_id_mark = nil`）。

### 152. 跨 SSH 用 `pkill -f` 会把自己的 shell 一起杀掉

`ssh host 'pkill -f sing-box'` 里，远端 shell 的命令行本身就含有
`sing-box` 这个字符串，`pkill -f` 匹配到自己 → 连接被自己中断，
命令后半段永远不执行，看起来像「卡住」或「没输出」。

正确写法：`pgrep -x sing-box-rev8`（按进程名精确匹配），或方括号技巧
`pkill -f "[s]ing-box run"`。同理，设备上清理残留测试客户端**不要**用
宽泛的 `pkill -f "sing-box run -c /tmp"`——PassWall 的实例配置也写在
`/tmp/etc/passwall/` 下，会被一起杀掉导致设备断网（本次已踩过）。
用精确的文件名模式，例如 `pgrep -f "/tmp/[a-z0-9]*\.json"`。

### 153. 手算 `ip_id_mark` 时只看高字节，`0xF107` 不是 61607

配置里的 `ip_id_mark` 是完整的 16 位，但真正参与匹配的只有高字节
（`IPIDMarkOf` 做 `& 0xFF00`）。rev.6 的默认值是 `IPIDMark|0x07` = `0xF107`
= **61703**，高字节 `0xF100`。

对照实验里把 `0xF107` 错算成 61607（那是 `0xF0A7`，高字节 `0xF000`），
客户端规则就写成了 `ip id & 0xff00 == 0xf000`，服务端仍是 `0xF100`。
结果是 15 次全失败、服务端 `inbound connection` 计数为 0——看起来像
「rev.6 也不通」，其实只是两端标记差了一个高字节。
写测试配置时用 `printf '%d' $((0xF107))` 算十进制，不要心算。

### 154. 重组结构体字面量时，算好的字段必须抄进去

`NewListener` 开头把 `opts.IdleTimeout` 默认成 120 秒、
`HandshakeTimeout` 默认成 5 秒，rev.6 在 `&Listener{...}` 里写了

```
idleTimeout:      opts.IdleTimeout,
handshakeTimeout: opts.HandshakeTimeout,
```

rev.8 为了加 `marks` 重排这个字面量，这两行丢了。字段停在 0。
`maintainLoop` 每秒做 `idleFor() > l.idleTimeout`：右值是 0，
刚收到包的会话空闲只有几毫秒，比较成立，会话被 `Close`。

现象和「标记不一致」「nft 丢包」几乎一样：客户端 `inflight` 卡住、
`lost=0`、请求随机超时，服务端没有新的 `inbound connection`。
差别是握手本身是成功的（抓得到 SYN-ACK），过大约 1 秒会话才消失。

修法两层：字面量把算好的值抄回去；比较前再要求超时 `> 0`，
这样以后再漏赋值，最坏是不回收，而不是把活会话杀掉。
`listener_test.go` 的 `TestMaintainLoopHonorsIdleTimeout` 钉住第二种。

### 155. PassWall 节点是匿名 section 时，名字会被 uci 换掉

`/etc/config/passwall` 里网页新建的节点长这样：

```
config nodes
        option protocol 'flowtls'
        option address '203.0.113.10'
```

`config nodes` 后面**没有名字**，这是匿名 section。`uci show` 会把它
显示成 `passwall.cfg051c7e`，但那个名字是 **uci 现场合成的临时名**，
不是配置文件里存在的东西。实测同一个节点在不同时刻叫过
`cfg041c7e`、`cfg331c7e`、`cfg051c7e`：只要配置被重写（排序、保存、
改任何一个字段）就可能换一个新的。

后果（PassWall 的 haproxy 功能会中招）：

- `haproxy_config.lbss` 把那个临时名当永久引用存起来；
- `haproxy.lua` 用 `api.uci_get_c(lbss)` 查节点，名字一变就取不到；
- 回落分支 `get_ip_port_from(lbss)` 把 **section 名当服务器地址**、
  端口给空串；
- 控制台里出现 `M1-cfgXXXXXX:`（尾巴那个冒号就是空端口），
  域名解析失败、后端永远 DOWN。

用户的描述会是「调一下节点上下顺序就连不上了」。

修法：把匿名节点改成**显式命名**（`uci rename passwall.@nodes[i]=名字`）。
名字一旦写进配置文件，uci 就不再重写它，之后怎么排序都不影响。
本项目由 `passwall-flowtls repair`（`apply` 与 cron 自愈都会跑）完成，
并用 `uci -N export`（`-N` = 不给匿名 section 起名）识别哪些还是匿名的：

```sh
uci -N export passwall | awk 'index($0,"config nodes")==1 { if (substr($0,13)=="") print n; n++ }'
```

**不要**用 `uci show` 报出来的 `cfgXXXXXX` 当稳定标识：它随时会变。

### 162. 零进展只放弃这一条流，拆整条通道会让所有下载一起停（2026-11-18 01:30）

01:05 的版本能自愈，但体验差。真机记录：

```
01:11:43 开始积压（透明代理 1041，约 60 条连接）
01:12:23 峰值 8 条大连接、合计约 7.2MB
01:12:39 一次清空，连接数从 60 掉到 29 再重新爬上来
```

清空是因为写超时触发了 `Client.Close()`，整条 QUIC 通道被拆掉，
同通道上所有下载一起中断，56 秒里用户什么都打不开。

不该拆通道。QUIC 的流控按流独立：一条流窗口卡在 0，
只占它自己的 4MB，其它流照常发。`CancelWrite` 发 RESET_STREAM，
对端归还的就是这 4MB。所以：

- 零进展 → 只放弃这一条流，relay 关掉这一对连接，浏览器重试这一个；
- 其它流一个都不碰，不重建 QUIC 连接；
- 有进展的超时仍当成功（第 161 条），否则正常下载会被掐断。

### 161. 零进展才算通道死亡，有进展的写超时必须当成功（2026-11-18 01:05）

不走 haproxy 也会卡，所以与负载均衡无关。透明代理（入口 1041）的
监控显示 4 条连接的 Recv-Q 两分钟不动，总积压却每 3 秒涨约 530 字节：
数据到了内核缓冲，relay 的写方向堵在流控上不返回，没人去读。

判定不能一刀切：

| 一次 Write 的结果 | 含义 | 处理 |
|---|---|---|
| 8 秒内写完 | 正常 | 原样返回 |
| 超时但 `n > 0` | 通道还活着，只是这一笔没写完 | **当成功返回**，调用方续写 |
| 超时且 `n == 0` | 窗口卡死，保活 ACK 让 idle 永不触发 | 两端都只放弃这一条流（第 162 条）。关整条通道会让所有下载一起停 |

把第二行当错误是 2026-11-17 23:45 的事故：正常下载每条都死在第 8 秒。
`TestPartialWriteIsNotAnError` 钉住这条。

### 160. 死连接靠「开新流写地址帧超时」来发现，不要给数据 Write 加超时（2026-11-18 00:25）

三边同版本后仍然卡死，栈把双方都拍下来了：

```
客户端 39 × SendStream.write（窗口为 0）+ 38 × ReceiveStream.readImpl
       发送队列空、recvLoop 没堵
服务端 同一时刻 AcceptStream 空闲，sendQueue 与 txLoop 都在等
```

窗口更新没回来，但保活 ACK 还在走，所以 QUIC 的 30 秒 idle 永不触发，
`Outbound.channel` 看到 `Done()` 没关就继续把新请求塞进去。
新请求的 ctx 没有 deadline，而 `Stream.Write` 不看 ctx，
写地址帧这一步就永久堵上了。

判据要加在**开新流**上，不能加在数据传输上：

- 地址帧只有几十字节，健康连接微秒级写完。等满 8 秒就是这条通道死了，
  异步 `Close()` 整条通道，让 `channel()` 重建。这一条只针对地址帧。
- 数据 `Write` 后来也加了超时，但判据不同（第 161、162 条）：
  有进展当成功，零进展只放弃这一条流。不能把「8 秒没写完」当失败，
  大响应跨过几个 RTT 是常态。

### 159. 给 Write 加固定超时会误杀正常下载，且取消后窗口不归还（2026-11-17 23:55）

第 158 条的 8 秒写超时部署后，卡死没有消失，日志说明它是加害者：

```
ERROR connection download closed: stream 856 canceled by local with error code 0
```

时间戳与建连时刻**正好差 8.0 秒**，而且被取消的是下载方向。
`CancelWrite` 只放弃写方向，服务端已经发出、占着接收窗口的那些数据
不会因此归还。16MB 窗口一旦被这种半途取消的流占满，新流就打不开，
表现为套接字队列是 0、新请求全部超时。

所以**不要**用固定的写超时来解决流控阻塞。写路径保持 quic-go 原样。

真正要满足的不变量是：收包队列容量 ≥ 连接级接收窗口。
`rxQueueDepth = 8192` 时只有约 10.9MB，小于 16MB 窗口，
`deliver` 会堵住 `recvLoop`，ACK 发不出去，对端的 `MAX_DATA` 永远不来。
现为 16384（约 21.8MB），由 `TestReceiveWindowFitsInRxQueue` 钉住。

### 158. 写协程堵在 Write 里时，关闭时的唤醒根本执行不到（2026-11-17 23:40）

第 157 条的修复部署后，无限刷新照样卡死。现场比上次更明确：

```
tcp  6212728  0  127.0.0.1:2002 → :54880   FIN_WAIT2
tcp  6153114  0  127.0.0.1:2002 → :50352   FIN_WAIT2
tcp  6118824  0  127.0.0.1:2002 → :40802   FIN_WAIT2
tcp  6007692  0  127.0.0.1:2002 → :50276   FIN_WAIT2
对端 LAST_ACK / CLOSING，Send-Q 分别 3.5MB / 2.3MB / 3.0MB
间隔 3 秒再采一次：字节数与状态一个都没变
```

半关闭已经发生了（否则不会是 FIN_WAIT2），所以缺 `CloseWrite` 不是
这次的原因。真正堵住的是 **relay 的写协程还在 `Stream.Write` 里**：
quic-go 在流控窗口为 0 时永远等 `writeChan`，`connectionCopy` 不返回，
`CloseWrite` 那一行（包括第 157 条加的唤醒）永远执行不到。

所以超时必须加在 `Write` 自己身上，不能加在关闭路径上：

- 每次 `Write` 前设 8 秒写超时，返回后立刻清掉；
- **只有 `n == 0` 且是超时**才 `CancelWrite`（发 RESET_STREAM，
  对端停发并归还连接级窗口）；
- `n > 0` 说明有进展，原样返回，调用方重试。这一条是为了不误伤
  正常的大文件下载。

不要把它做成发送 fd 的 `SO_SNDTIMEO`：那一版把下载速度打下来了。
8 秒只限制「一条流等窗口更新」，发送路径与 `rxQueueDepth` 不变。

### 157. 流关闭必须唤醒卡在流控上的写（2026-11-17 23:25）

测速时节点挂死的现场是成对的半关闭连接，Recv-Q 数分钟不动：

```
4 × CLOSE_WAIT + 4 × FIN_WAIT2，Recv-Q 合计约 2.4MB，ESTABLISHED = 0
```

有人会先去加发送超时或加大接收队列。**不要**：2026-11-17 那一版
（`SO_SNDTIMEO` 3 秒、队列满 8 秒关会话、`rxQueueDepth` 8192 → 16384）
部署后下载速度明显变差，已整批撤回。挂死不在发送路径上。

真正的两层原因：

1. **没有 `CloseWrite`**。sing-box relay（`route/conn.go`）靠它决定
   半关闭还是整条关闭。没有就走 `Close()`，一个方向结束把整条流关掉，
   另一个方向的数据没人读。
2. **`Stream.Close()` 不唤醒阻塞的 `Write`**。quic-go 只在写超时里
   `signalWrite()`（`send_stream.go` 的 `SetWriteDeadline`）。
   对端那条流的 4MB 接收窗口被没读走的数据占满时，写协程永远堵在
   `<-writeChan` 上，收尾逻辑走不到，窗口也永远不恢复。

修法只动关闭路径：`Close` 和 `CloseWrite` 之后设一个**已经过去**的
写超时。它只让被堵住的那次 `Write` 返回错误，已经拷进 STREAM 帧的数据
和 FIN 不受影响（deadline 不碰发送队列）。hysteria2 的
`clientConn.Close` / `serverConn.Close` 用的是同一做法，注释也写了原因。

单测在 `flowtls/quic/duplex_test.go`：把接收窗口耗尽后分别调
`Close` 和 `CloseWrite`，两条都必须在时限内返回。

### 156. 443 和 8443 会被链路封锁，9443 能过（2026-11-17 15:10）

同一台机器（`203.0.113.10`）、同一个 rev.9 二进制、同一份配置、同一张证书，
只换 `listen_port`，从国内实测：

| 端口 | 结果 |
|---|---|
| 443 | **超时** |
| 8443 | **超时** |
| 9443 | 200 |
| 48443 | 200 |
| 49443 | 200 |

对照实验的关键是**必须同时有多个端口在监听**再测：先前只起 8443 时，
测 48443/49443 得到的超时是「没进程监听」，不是被拦，很容易误判。

诊断时曾经怀疑 rev.8 的 `notrack` 规则，实测把它删掉后 443 照旧超时，
排除。也试过让 rev.3 接管 443 —— **rev.3 在 443 上一样超时**，
证明与版本无关。

抓包特征（服务端 tcpdump）：

```
In  198.51.100.7 > 203.0.113.10.443: Flags [S]     ← SYN 到达
Out 203.0.113.10.443 > 198.51.100.7: Flags [S.]    ← 服务器已回 SYN-ACK
In  198.51.100.7 > 203.0.113.10.443: Flags [S]     ← 客户端重传
```

服务器正常生成并发出 SYN-ACK，客户端收不到。丢包在服务器网卡之后，
是链路对特定端口的行为，本机任何防火墙/内核配置都改不了。

**注意这次的新事实**：443 上不只是伪造 TCP 隧道不通，**同端口的真证书
伪装站也打不开**（`curl -k` 也超时）。第 17 条只记了「伪造包发不出去」，
实际连真实 TLS 连接也建立不起来。

结论：部署时避开 443 与 8443。9443 / 48443 / 49443 实测可用。
