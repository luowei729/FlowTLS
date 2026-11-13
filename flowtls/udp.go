package flowtls

import "encoding/binary"

// UDP 会话帧编解码：用 QUIC DATAGRAM（RFC 9221）承载 UDP。
//
// 设计与 Rust 版完全一致（对齐 hysteria2 的做法）：
//   - 不重传、不重排、不重放：DATAGRAM 本身就是不可靠帧，丢了就是丢了；
//   - 不做背压：发送队列满就丢新包，绝不让 UDP 反压到本地应用；
//   - 超 MTU 直接丢：不做应用层分片。
//
// 线上格式：
//
//	客户端 → 服务端：[session u32 BE][addrLen u16 BE][ATYP][ADDR][PORT][payload]
//	服务端 → 客户端：[session u32 BE][payload]
//
// **上行每包都带目标地址**是本协议与 hysteria2 的关键差异之一。
// hysteria2 的目标地址在 UoT/stream 建立时确定，后续包不再携带；
// 这里每个包都带，换来的是服务端**完全无状态地重建会话**——
// 客户端重连后服务端是新连接、会话表为空，第一个带地址的包就能自愈，
// 不需要任何会话迁移协议。代价是每包多 7~9 字节。
//
// session 由客户端分配，作用域是「一条 QUIC 连接内的一个本地 UDP 五元组」。

// UDPHeaderLen 是上行帧固定头长度：session(4) + addrLen(2)
const UDPHeaderLen = 6

// EncodeClientDatagram 编码一帧「客户端 → 服务端」的 UDP 数据报。
//
// target 是**不含长度前缀**的地址帧 `[ATYP][ADDR][PORT]`
// （与 QUIC 流首帧去掉 2 字节总长后相同，可直接复用 DecodeAddress）。
// 结果追加到 dst，便于调用方复用缓冲。
func EncodeClientDatagram(dst []byte, session uint32, target, payload []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, session)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(target)))
	dst = append(dst, target...)
	dst = append(dst, payload...)
	return dst
}

// ParseClientDatagram 解析「客户端 → 服务端」帧，返回 (session, 地址帧, 载荷)。
// 任何不合法输入都返回 false，调用方应静默丢弃（UDP 语义）。
func ParseClientDatagram(buf []byte) (session uint32, target, payload []byte, ok bool) {
	if len(buf) < UDPHeaderLen {
		return 0, nil, nil, false
	}
	session = binary.BigEndian.Uint32(buf[0:4])
	addrLen := int(binary.BigEndian.Uint16(buf[4:6]))
	// addrLen 必须 > 0：上行每包都带地址，0 说明对端实现不匹配
	if addrLen == 0 || len(buf) < UDPHeaderLen+addrLen {
		return 0, nil, nil, false
	}
	target = buf[UDPHeaderLen : UDPHeaderLen+addrLen]
	payload = buf[UDPHeaderLen+addrLen:]
	return session, target, payload, true
}

// EncodeServerDatagram 编码一帧「服务端 → 客户端」的 UDP 数据报：session + 载荷。
func EncodeServerDatagram(dst []byte, session uint32, payload []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, session)
	return append(dst, payload...)
}

// ParseServerDatagram 解析「服务端 → 客户端」帧，返回 (session, 载荷)。
func ParseServerDatagram(buf []byte) (session uint32, payload []byte, ok bool) {
	if len(buf) < 4 {
		return 0, nil, false
	}
	session = binary.BigEndian.Uint32(buf[0:4])
	return session, buf[4:], true
}
