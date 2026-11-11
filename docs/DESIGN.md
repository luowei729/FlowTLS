# FlowTLS 协议设计

## 1. 线上包格式

每个 UDP 意义上的数据报被包装成一个 IPv4 + TCP 报文：

```
IP 头(20) | TCP 头(20) | 17 03 03 | len(2) | nonce(12) | ChaCha20-Poly1305(QUIC 数据报 + 16B tag)
```

- IP ID 固定为配置的魔数（默认 0xF107），用于服务端 iptables 分流。
- TCP flags 使用 PSH+ACK，窗口固定 65535，seq/ack 按字节数推进。
- TLS 记录头 `17 03 03` 只是外观，载荷是 AEAD 密文。
- 每包额外开销 37 字节，QUIC 数据报上限 1200，总包 < 1300，不分片。

## 2. 握手时序（纯表演，零等待）

客户端在同一个事件循环里连续 sendto：

1. SYN（40 字节，零载荷，IP ID=魔数，随机 ISN）
2. 伪 ClientHello（`16 03 01`，SNI=配置域名）
3. 首个 QUIC Initial（已封装为 `17 03 03` 记录）

客户端不等 SYN-ACK、不等 ACK，也不进入握手状态机。

服务端：

1. 收到 SYN：记录客户端 ISN，不回包。
2. QUIC 连接建立时：用记录的 ISN 回 SYN-ACK，seq 连续；紧跟伪 ServerHello。
3. 收到任意 AEAD 验签通过的数据包立即交给 QUIC，不依赖握手时序。
4. 客户端收到 SYN-ACK 后回一个纯 ACK，完成三次握手，NAT/conntrack 进入 ESTABLISHED。

## 3. 鉴权

- 外层密钥：`HKDF-SHA256(salt="flowtls-faketcp-v1", ikm=password, info="flowtls faketcp aead key")` → 32 字节。
- 每包随机 12 字节 nonce，ChaCha20-Poly1305 加密。
- 服务端解密失败直接丢弃，不回任何响应。
- 解密成功即视为鉴权通过；无需额外首帧 token。

## 4. 端口分流

| 流量 | 处理 |
|---|---|
| 正常 SYN（IP ID != 魔数） | 内核 TCP → rustls 真证书 → 内置 HTML 网站 |
| 魔数 SYN | iptables raw 表 DROP，raw socket 记录 ISN |
| 魔数数据包 | iptables raw 表 DROP，raw socket 验签 → QUIC |
| 非魔数垃圾包 | 内核 TCP 处理，网站返回正常响应或 RST |

iptables 规则（服务端）：

```bash
iptables -t raw -A PREROUTING -p tcp --dport 8443 -m u32 --u32 "4&0xFFFF0000=0xF1070000" -j DROP
```

客户端规则：

```bash
iptables -A OUTPUT -p tcp --sport 44300 --tcp-flags RST RST -j DROP
```

## 5. 流协议

每条 QUIC 双向流的首个载荷是目标地址帧：

```
[总长 u16][ATYP u8][地址][端口 u16]
ATYP: 1=IPv4(4B), 4=IPv6(16B), 3=域名(1B 长度 + nB)
```

服务端先读 2 字节长度，再读满地址帧，然后建立出站 TCP 并双向拷贝。
地址帧之后的字节原样转发，因此 SOCKS5 CONNECT、HTTP CONNECT、普通 HTTP 请求都走同一套流。

## 6. 与 quinn-proto 的对接

- 使用 `quinn_proto::Endpoint::new(EndpointConfig, Some(ServerConfig), false, None)`。
- 入向：`endpoint.handle(now, client_addr, None, None, BytesMut, &mut buf)`。
- 新连接：`endpoint.accept(incoming, now, &mut buf, Some(server_config))`。
- 出向：`conn.poll_transmit(now, 1, &mut buf)`，**每次循环前 buf.clear()**。
- 定时器：`conn.poll_timeout()` + `conn.handle_timeout(now)`。
- 传输参数：initial_mtu 1200、receive_window 16MB、stream_receive_window 4MB、send_window 16MB、BBR、keep_alive 10s。

## 7. 安全边界

- 外层 AEAD 提供身份验证与加密，密码即凭据。
- 内层 QUIC 使用运行时自签证书，客户端跳过校验；这是安全的，因为外层已经加密并鉴权。
- 未授权方无法通过 AEAD 校验，连 QUIC 状态机都进不去。
