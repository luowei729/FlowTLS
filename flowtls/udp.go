package flowtls

// 本文件是 legacy-rust:src/proxy/udp.rs 的逐函数翻译。
//
// UDP 走 QUIC DATAGRAM（RFC 9221），设计完全对齐 hysteria2：
//   - **不重传、不重排、不重放**：DATAGRAM 本身就是不可靠帧，
//     丢了就是丢了，绝不补发——这是 UDP 的语义；
//   - **不做背压**：发送队列满就直接丢弃新包，绝不让 UDP 反压到本地应用；
//   - **超 MTU 直接丢**：不做应用层分片（分片会引入序号、重组超时和内存放大，
//     而 DNS/游戏/QUIC 报文本来就基本在 1200 字节以内）。
//
// 线上格式：
//
//	客户端 → 服务端：[session u32 BE][addrLen u16 BE][ATYP][ADDR][PORT][payload]
//	服务端 → 客户端：[session u32 BE][payload]
//
// 上行每个包都带目标地址：不多占几字节，换来服务端完全无状态地重建会话
// （客户端重连后服务端是新连接、会话表是空的，第一个带地址的包就能自愈）。

import "encoding/binary"

// udpHeaderLen 是上行帧头长度：session(4) + addrLen(2)。
const udpHeaderLen = 6

// EncodeClientDatagram 编码一帧「客户端 → 服务端」的 UDP 数据报。
//
// target 是地址帧 `[ATYP][ADDR][PORT]`（不含长度前缀，见 EncodeAddressFrame），
// 每个包都带。写入调用方提供的缓冲，稳态零分配。
func EncodeClientDatagram(out []byte, session uint32, target, payload []byte) []byte {
	need := udpHeaderLen + len(target) + len(payload)
	if cap(out) < need {
		out = make([]byte, need)
	} else {
		out = out[:need]
	}
	binary.BigEndian.PutUint32(out[0:4], session)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(target)))
	copy(out[udpHeaderLen:], target)
	copy(out[udpHeaderLen+len(target):], payload)
	return out
}

// ParseClientDatagram 解析「客户端 → 服务端」帧，返回 (session, 地址帧, 载荷)。
// 任何不合法的输入都返回 ok=false，调用方应静默丢弃（UDP 语义）。
func ParseClientDatagram(buf []byte) (session uint32, target, payload []byte, ok bool) {
	if len(buf) < udpHeaderLen {
		return 0, nil, nil, false
	}
	session = binary.BigEndian.Uint32(buf[0:4])
	addrLen := int(binary.BigEndian.Uint16(buf[4:6]))
	// addrLen 必须 > 0：上行每包都带地址，0 长度说明对端实现不匹配
	if addrLen == 0 || len(buf) < udpHeaderLen+addrLen {
		return 0, nil, nil, false
	}
	return session, buf[udpHeaderLen : udpHeaderLen+addrLen], buf[udpHeaderLen+addrLen:], true
}

// EncodeServerDatagram 编码一帧「服务端 → 客户端」的 UDP 数据报：
// 只有 session + 载荷。
func EncodeServerDatagram(out []byte, session uint32, payload []byte) []byte {
	need := 4 + len(payload)
	if cap(out) < need {
		out = make([]byte, need)
	} else {
		out = out[:need]
	}
	binary.BigEndian.PutUint32(out[0:4], session)
	copy(out[4:], payload)
	return out
}

// ParseServerDatagram 解析「服务端 → 客户端」帧，返回 (session, 载荷)。
func ParseServerDatagram(buf []byte) (session uint32, payload []byte, ok bool) {
	if len(buf) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(buf[0:4]), buf[4:], true
}
