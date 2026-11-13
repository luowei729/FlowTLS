# DEVTIPS — 踩坑与调试手册

> **阅读提示**：第 1~68 条记录的是 **Rust 参考实现**时期的坑（quinn-proto、
> Rustls、tokio、rusqlite 等），对应源码已冻结在 `legacy-rust` 分支；
> 第 69 条起是 **Go 实现**（quic-go / sing-box 适配层）。
> 两类坑在原理上常常相通（例如窗口、乱序、NAT 行为），所以历史条目保留。
> 演进的来龙去脉见 `docs/EVOLUTION.md`。

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
