// Package flowtls 实现「外观是 TCP+TLS、内部是 QUIC 数据报」的传输层。
//
// 分层（对应 Rust 原型 src/faketcp 与 src/quic）：
//
//	packet.go   IP/TCP 头构造与解析、校验和、seq/ack 维护
//	socket_*    AF_PACKET 收包 / AF_PACKET 或 IPPROTO_RAW 发包
//	codec.go    伪 TLS 记录外观 + ChaCha20-Poly1305 AEAD
//	session.go  Session：把一条伪造 TCP 连接抽象成 net.PacketConn
//	listener.go 按四元组分流、完成三次握手后交给上层
//	quic/       唯一依赖 quic-go 的子包（服务端 Service / 客户端 Client）
//
// 核心约束（与 Rust 版必须保持一致，否则两端无法互通）：
//
//   - 外层报文 = IP(20) + TCP(20) + 17 03 03 + len(2) + nonce(12) + 密文(+16 tag)
//   - AEAD 密钥 = HKDF-SHA256(salt="flowtls-faketcp-v1", ikm=password,
//     info="flowtls faketcp aead key")
//   - 伪包识别特征 = TCP 窗口缩放因子 wscale=12（IP ID 会被运营商 NAT 改写，不能用）
//   - 流首帧 = [总长 u16][ATYP u8][地址][端口 u16]，之后是裸数据、**没有响应头**
//   - UDP 上行 = [session u32][addrLen u16][ATYP][ADDR][PORT][payload]
//     UDP 下行 = [session u32][payload]
//
// 平台限制：目前只支持 Linux + IPv4，需要 root 或 CAP_NET_RAW。
package flowtls
