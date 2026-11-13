# FlowTLS 协议设计

## 1. 线上包格式

每个 UDP 意义上的数据报被包装成一个 IPv4 + TCP 报文。

**首包**（每条连接的第一条 ApplicationData，仅客户端→服务端）：

```
IP 头(20) | TCP 头(20) | 17 03 03 | len(2) | ver(1) | authID(16) | nonce(12) | ChaCha20-Poly1305(QUIC 数据报 + 16B tag)
```

**后续包**：

```
IP 头(20) | TCP 头(20) | 17 03 03 | len(2) | nonce(12) | ChaCha20-Poly1305(QUIC 数据报 + 16B tag)
```

- TLS 记录头 `17 03 03` 只是外观，载荷是 AEAD 密文。
- TCP flags 使用 PSH+ACK，窗口固定 65535，seq/ack 按字节数推进。
- IP ID 在 `0xF100~0xF1FF` 内递增（**仅作外观**，真实链路上会被运营商 NAT 改写为 0，不能用于分流）。
- 后续包每包额外开销 37 字节，首包 54 字节；QUIC 初始 MTU 1340，加上外层后总包约 1417/1434，仍不分片。
- **首包头只在鉴权完成前携带**：客户端在收到服务端第一个能解开的包之前，每个包都带
  `ver + authID`（QUIC Initial 丢包重传时仍能被服务端识别）；确认可达后不再携带。
  服务端方向从不携带。

### 1.1 AAD（附加认证数据）

版本号与 authID 都参与 AEAD 认证，但**不占额外字节**：

| 包类型 | AAD |
|---|---|
| 首包 | `ver \| authID`（17 字节） |
| 后续包 | `ver`（1 字节） |

作用：

- 版本号入 AAD → 将来出 v3 时，v2 的包在 v3 下必然解密失败，不会跨版本误判；
- authID 入 AAD → 篡改首包里的用户标识去撞别人密钥槽位会直接认证失败；
- 两者都不写进报文，所以没有额外开销。

## 1.2 多用户与鉴权

鉴权模型与 sing-box 的 hysteria2 / anytls / shadowsocks 一致：**配置里是
`name + password`，`name` 只用于日志，线上传的是 password 派生出的不透明标识**。

```
authID  = HKDF-SHA256(salt="flowtls-faketcp-v2", ikm=password,
                      info="flowtls faketcp auth id v2")[0..16]
aeadKey = HKDF-SHA256(salt="flowtls-faketcp-v2", ikm=password,
                      info="flowtls faketcp aead key v2")[0..32]
```

两个派生值用**不同的 info**，密码学上互不可推导：抓包拿到 authID 既推不出
密码，也无法解密任何数据。

服务端流程：

1. 读首包明文 `ver + authID`，`ver != 2` 直接丢；
2. 用 authID 查表得到该用户密钥（O(1)；**不遍历试解**，否则 100 用户就是 100 倍 CPU）；
3. `open_first` 做 AEAD 认证，失败静默丢弃——解析明文本身不构成信任。

每条连接独立持有用户密钥（`ServerConn.obfs`），因为不同连接的客户端可能不同。
服务端维护 `client 地址 → (连接句柄, 密钥, 名字)` 索引，后续包用它选密钥，
避免每包 O(n) 遍历连接表。

### 1.3 为什么不兼容旧格式

v1（无版本位、单密码、解密成功即鉴权）**从未发布过**，因此直接废弃。
Rust 与 Go 两端同步升级，不做双版本共存。

## 2. 伪包识别（重要）

早期版本用 `IP ID == 0xF107` 识别自己的包，实测在部分运营商网络下**完全失效**：
NAT 会把 IP ID 改写为 `0x0000`，导致：

- 服务端 `ip_id == magic` 判断不成立，raw 层不认 SYN；
- `iptables -m u32` 按 IP ID 的规则也不命中，内核会去处理伪包（回 SYN-ACK/RST）。

现在改用 **TCP 窗口缩放因子 `wscale = 12`** 作为识别特征：

- 客户端 SYN 固定携带 `MSS 1460 + SACK permitted + WS 12`；
- NAT 不改写 TCP 选项，因此该特征稳定；
- 正常浏览器/curl 的 wscale 是 8~9，不会误伤。

`parse_frame` 会解析 TCP 选项并返回 `wscale`，服务端据此判断是否为伪包。

## 3. 握手时序（标准三次握手）

严格 NAT/状态防火墙只放行「SYN → SYN-ACK → ACK」之后的数据包。
早期「SYN + 数据同批发」的零等待版本在这种网络下会被直接丢弃，现已废弃。

```
客户端                                  服务端
  │── SYN（wscale=12, ISN=c_isn）──────▶│  记录 c_isn，立即回 SYN-ACK
  │◀──────── SYN-ACK（ISN=s_isn）───────│  记录 s_isn
  │── ACK（seq=c_isn+1, ack=s_isn+1）──▶│
  │── 伪 ClientHello（16 03 01 + SNI）─▶│
  │── QUIC Initial（17 03 03 封装）────▶│  endpoint.handle → NewConnection
  │◀──────── 伪 ServerHello + 数据 ─────│  复用 s_isn，seq 连续
```

关键点：

- 服务端在收到 SYN 时就把 ISN 记入 `syn_isns`，`NewConnection` 时复用同一个值，**不重复发 SYN-ACK**；
- 客户端在 `awaiting_syn_ack` 期间不调用 `drain_transmits`，保证握手完成前不产生任何数据包；
- 代价是建连多 1 个 RTT（约 70ms），之后所有请求在这条 QUIC 长连接上开新流，不再握手。

## 4. 鉴权

详见 1.2。要点：

- 密钥与身份标识都由 HKDF-SHA256 从密码派生，salt 为 `flowtls-faketcp-v2`；
- 身份标识（authID，16 字节）明文出现在首包，仅用于服务端查表；
- 真正的鉴权是首包的 AEAD 认证：认证失败静默丢弃，不回任何响应；
- 后续包不再携带身份，靠连接自身持有的密钥解密。

## 5. 端口分流

| 流量 | 处理 |
|---|---|
| 真实 SYN（wscale 8~9） | 内核 TCP → rustls 真证书 → 内置 HTML 网站 |
| 伪 SYN（wscale=12） | iptables raw 表 DROP（阻止内核回 SYN-ACK）+ raw socket 记录 ISN 并回 SYN-ACK |
| 伪数据包 | raw socket 验签 → QUIC；内核侧会回 RST，客户端 iptables 将其丢弃 |
| 其它垃圾包 | 内核 TCP 处理，网站返回正常响应或 RST |

服务端 iptables 规则（按 TCP 选项匹配 WS=12）：

```bash
# IP 头 20 + TCP 头 26（MSS 4 + SACK 2 之后）= 偏移 46
iptables -t raw -A PREROUTING -p tcp --dport 8443 \
  -m u32 --u32 "46&0xFFFFFFFF=0x03030C01" -j DROP
```

客户端规则（不再依赖会被改写的 IP ID）：

```bash
# 1. 阻止内核对服务端 SYN-ACK 自动回 RST
iptables -A OUTPUT -p tcp --sport 44300 --tcp-flags RST RST -j DROP
# 2. 服务端发来的包交给 raw 层，内核不要处理
iptables -A INPUT -p tcp --sport 8443 --dport 44300 -j DROP
```

## 6. 流协议

每条 QUIC 双向流的首个载荷是目标地址帧：

```
[总长 u16][ATYP u8][地址][端口 u16]
ATYP: 1=IPv4(4B), 4=IPv6(16B), 3=域名(1B 长度 + nB)
```

服务端先读 2 字节长度，再读满地址帧，然后建立出站 TCP 并双向拷贝。
地址帧之后的字节原样转发，因此 SOCKS5 CONNECT、HTTP CONNECT、普通 HTTP 请求都走同一套流。

出站方向使用 `tokio::join!` 而非 `select!`：任一方向结束不能把另一方向直接 drop，
否则会出现「客户端半关闭后目标数据没读完就发 FIN」，下载几十 KB 就中断。

## 6.1 UDP 协议（QUIC DATAGRAM）

UDP 不走 QUIC 流，走 **RFC 9221 DATAGRAM 扩展**。设计目标是与 hysteria2 完全一致：
**不重传、不保序、队列满即丢、超 MTU 即丢**，不做任何应用层分片。

### 线上格式

```text
客户端 → 服务端：[session u32 BE][addrLen u16 BE][ATYP][ADDR][PORT][payload]
服务端 → 客户端：[session u32 BE][payload]
```

**上行每包都带目标地址**（多 7~9 字节）。这个冗余换来两个关键性质：

1. 服务端**完全无状态地重建会话**——客户端重连后服务端是新连接、会话表为空，
   第一个带地址的包就能自愈，不需要任何会话迁移协议；
2. 服务端不需要记忆「这个 session 上次的目标是谁」，排查时一行日志就能看出
   包是发给谁的。

### 会话生命周期

| 侧 | 键 | 值 | 回收 |
|---|---|---|---|
| 客户端 | `(本地应用地址, 目标地址帧)` | `session id` + 下行通道 | 120s 空闲 / 控制连接关闭 |
| 服务端 | `session id` | UDP socket + 目标 + `last_active` | 120s 空闲 |

服务端每个会话对应一个 `udp_outbound` 任务，`select!` 同时管上行（`rx.recv`）
和下行（`sock.recv`）。会话被主循环 `remove` 后，`to_target` sender 被 drop，
`rx.recv()` 立即返回 `None` → 任务退出 → socket 关闭。**不需要取消信号**。

### 丢包策略

| 位置 | 做法 |
|---|---|
| 客户端上行 | `tx.try_send()`，通道满即丢 |
| 客户端 QUIC 发送 | `datagrams().send(pkt, drop=true)`，缓冲满丢最旧 |
| 服务端上行 | `to_target.try_send()`，通道满即丢 |
| 服务端回程 | `action_tx.try_send()`，主循环跟不上即丢 |
| 超过 `datagrams().max_size()`（约 1200B） | 直接丢，不分片 |

`drop=true` 的语义是「丢掉还在本地排队、未被 `poll_transmit` 取走的包」，
已经进 QUIC 状态机的包不会被挤掉。

### SOCKS5 入口

`UDP ASSOCIATE`（RFC 1928 CMD=3）：

1. 控制连接（TCP）完成认证后发 `CMD=3`，返回 `BND.ADDR:BND.PORT`；
2. 客户端把 UDP 包发到 `BND` 地址，格式 `RSV(2)|FRAG(1)|ATYP|ADDR|PORT|payload`；
3. `FRAG != 0` 的分片包直接丢弃（与绝大多数实现一致，不做重组）；
4. 控制连接断开 → 整个 relay 立刻结束并注销所有 session（RFC 要求）。

### MTU 影响

**零影响**。datagram 是 QUIC 帧类型，与 stream 数据共用同一个 QUIC 包，
外层 FakeTCP / AEAD / 批量发送路径一行都没改。单包上限由
`conn.datagrams().max_size()` 每包检查（等于 `path MTU - 1RTT overhead - 帧头`，
当前 MTU 1332 下约 1200 字节）。

## 7. 流控与背压

### 接收侧（quinn 硬限制）

quinn-proto 的接收组装器有硬编码常量 `MAX_CHUNKS = 1024`，
即单流最多容忍 1024 个乱序空洞，超过会以
`ConnectionClosed(INTERNAL_ERROR, "too many gaps in stream buffer")` 断开整条连接。

约束公式：

```
窗口(字节) ÷ 包大小(1308) × 丢包率 < 1024
```

因此窗口不能写死。两端每 2 秒按实测丢包率反算安全上限：

```
安全上限 = 1024 × 1308 ÷ 丢包率 × 0.7
最终窗口 = clamp(当前值 × 系数, 1.5MB, min(安全上限, 8MB))
系数：丢包 >20% → 0.90；<5% → 1.20；其余保持不变
```

### 发送侧（应用层背压）

服务端每条流维护 `pending_bytes`（与出站任务共享的原子计数）。

- 目标 socket 读到数据后，主循环尝试写入 QUIC；
- 流控窗口满时数据进入 `pending`，`pending_bytes` 增加；
- 出站任务的 reader 发现 `pending_bytes` 超过高水位（2×max_cwnd）就暂停读目标 socket；
- 目标 TCP 接收缓冲随之填满，目标发送方降速 —— 这就是端到端背压。

没有这层背压时，目标以 30Mbps 灌入、QUIC 只能 3Mbps 发出，差值会全部堆在内存里
（实测堆积 58MB，最终触发 reset）。

## 8. 读取失败的处理

`RecvStream::read(true)` 可能返回 `IllegalOrderedRead`：一旦某次 `finalize` 未正常完成，
该流的组装器被锁定，之后每次读取都失败。

错误做法是静默跳过——数据不再被读、`MAX_STREAM_DATA` 永不发送，
对端在途数据会堆到几十 MB。

正确做法：

1. 标记该流 `stopped`，后续 `Readable` 事件直接忽略（否则会反复 read/失败/stop 空转）；
2. 调用 `recv_stream(id).stop(0)` 释放流控额度；
3. 该请求由上层重试，不影响整条连接。

## 9. 断线自愈

客户端 `run()` 只做一次：解析、raw socket、iptables、收包线程、本地代理入口。
每次连接由 `run_session()` 负责，断线返回 `Ok(())`，外层按 5s→60s 指数退避重连。

`ProxyClient` 持有 `Mutex<Option<Sender>>`，重连时用 `set_tx` 替换通道，
本地监听（1080/8080/8443）不会重复绑定端口。

## 10. 与 quinn-proto 的对接

- `quinn_proto::Endpoint::new(EndpointConfig, Some(ServerConfig), false, None)`
- 入向：`endpoint.handle(now, client_addr, None, None, BytesMut, &mut buf)`
- 新连接：`endpoint.accept(incoming, now, &mut buf, Some(server_config))`
- 出向：`conn.poll_transmit(now, 32, &mut buf)`，**每次循环前 buf.clear()**
- 定时器：`conn.poll_timeout()` + `conn.handle_timeout(now)`
- 传输参数：`initial_mtu 1332`、`receive_window 16MB`、`stream_receive_window 4MB`、
  `send_window max_cwnd×2`、`keep_alive 10s`、`max_idle_timeout 30s`、ACK 频率 5ms、
  `datagram_receive_buffer_size 1MB`
- UDP：`conn.datagrams().send(bytes, drop=true)` / `.recv()` / `.max_size()`
- 拥塞控制：`CappedBbr` 包装原生 BBR，只在 `window()` 处按自适应上限截断

## 11. 安全边界

- 外层 AEAD 提供身份验证与加密，密码即凭据。
- 内层 QUIC 使用运行时自签证书，客户端跳过校验；这是安全的，因为外层已经加密并鉴权。
- 未授权方无法通过 AEAD 校验，连 QUIC 状态机都进不去。
- 同端口的真网站使用真实证书，主动探测者看到的是正常 HTTPS 站点。
