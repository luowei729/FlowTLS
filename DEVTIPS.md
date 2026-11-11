# DEVTIPS — 踩坑与调试手册

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

## 15. 拥塞窗口可用环境变量调

固定窗口默认 1MB，不改代码可调：

```bash
export FLOWTLS_CWND=2097152   # 2MB
./flowtls server -c server.yaml
```

启动日志会打印 `拥塞控制：固定窗口 cwnd=...`。窗口越小丢包越少但吞吐上限低，
窗口越大单流越快但突发会导致中间设备丢包。跨境直播建议 1MB；
大文件下载可试 2-3MB；弱网可降到 512KB。

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

## 26. 常用调试命令

```bash
# 看线上外观：应只有 TCP 8443 + 17 03 03
tcpdump -i eth0 -n -X 'tcp port 8443'

# 看规则命中计数
iptables -t raw -vnL PREROUTING --line-numbers

# 看 QUIC 统计（服务端每 2 秒打印 rtt/cwnd/lost）
grep "路径统计" /opt/flowtls/server.log | tail
```
