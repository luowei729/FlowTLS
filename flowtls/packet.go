package flowtls

// 本文件是 legacy-rust:src/faketcp/packet.rs 的逐函数翻译。
//
// 对应关系：
//
//	TCP_FIN/TCP_SYN/TCP_RST/TCP_PSH/TCP_ACK  → TCPFIN/TCPSYN/TCPRST/TCPPSH/TCPACK
//	IPID_MARK / IPID_LOW_MASK                → IPIDMark / IPIDLowMask
//	ipid_mark / next_ipid / random_ipid      → IPIDMarkOf / NextIPID / RandomIPID
//	ParsedPacket                             → ParsedPacket
//	sum16 / fold                             → sum16 / fold
//	parse_frame                              → ParseFrame
//	TS_OPT_LEN / TCP_HDR_WITH_TS / WSCALE    → TSOptLen / TCPHdrWithTS / WScale
//	write_ts_option                          → writeTSOption
//	syn_options                              → SynOptions
//	TcpSeg                                   → TcpSeg
//	TcpClock::{new,new_at,tsval,observe}     → TcpClock/{NewTcpClock,NewTcpClockAt,TSVal,Observe}
//	advertised_window                        → AdvertisedWindow
//	seq_len                                  → seqLen
//	build_packet / build_packet_into         → BuildPacket / BuildPacketInto
//
// 刻意**不**引入 Rust 没有的抽象：没有 AppendPacket，没有"零拷贝视图"之类。
// Rust 的 build_packet_into 是「把 out 调整到 total_len 再从偏移 0 覆写」，
// 本实现同样如此（不是追加）。

import (
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand/v2"
	"net/netip"
	"time"
)

// TCP 标志位定义，构造和解析时共用，避免魔法数字散落各处。
const (
	TCPFIN uint8 = 0x01
	TCPSYN uint8 = 0x02
	// TCPRST 当前不主动发（连接拆除用 FIN），保留常量供解析侧比对。
	TCPRST uint8 = 0x04
	TCPPSH uint8 = 0x08
	TCPACK uint8 = 0x10
)

// ---- IP ID 分流标记 ----
//
// 必须在两端用 iptables 把伪造包挡在内核 TCP 栈之外（服务端防止内核回
// SYN-ACK/RST，客户端防止内核回 RST），而 iptables 需要一个「静态可匹配」的
// 特征。TCP 选项已经全部改回真实值（含时间戳、wscale=9），不能再当指纹，
// 因此静态标记只能留在 IP ID 上。
//
// 标记值来自配置（`ip_id_mark`），不写死：写死意味着任何 DPI 只要加一条
// 「IP ID 高字节 == 0xF1」的通用规则就能一次命中所有部署。
//
// 标记范围刻意很窄（只固定高字节 = 256 个值）：iptables 会把这些包直接 DROP，
// 内核看不到就没有任何响应。若范围过宽，普通端口探测只要 IP ID 落进该范围
// 就会得到「完全没有响应」，反而暴露这里有一层过滤。
// 高字节固定 → 约 0.4% 的探测无响应，与正常丢包率难以区分。
const (
	// IPIDMark 是默认标记高字节（等价于配置 ip_id_mark: 0xF107 的高字节）。
	IPIDMark uint16 = 0xF100
	// IPIDLowMask 是可递增的低 8 位。
	IPIDLowMask uint16 = 0x00FF
)

// IPIDMarkOf 从配置的 ip_id_mark 取出标记高字节（只有高字节参与标记）。
func IPIDMarkOf(magic uint16) uint16 { return magic & 0xFF00 }

// NextIPID 取下一个 IP ID：高字节保持标记，低字节 +1 回绕。
func NextIPID(mark, cur uint16) uint16 {
	return mark | ((cur + 1) & IPIDLowMask)
}

// RandomIPID 随机起始 IP ID：让每条连接的起点不同。
func RandomIPID(mark uint16) uint16 {
	return mark | (uint16(mrand.Uint32()) & IPIDLowMask)
}

// ParsedPacket 是解析后的 IPv4 + TCP 报文视图。
//
// Payload 直接借用接收缓冲区，零拷贝。
// 部分字段当前没有读取（Ack/Window/TSecr），但保留它们是有意的：
// 排查伪装效果时要能直接从解析结果核对窗口值和时间戳回显。
type ParsedPacket struct {
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	Seq, Ack         uint32
	Flags            uint8
	IPID             uint16
	// Window 是 TCP 窗口字段（未经 wscale 放大）
	Window uint16
	// WScale 是 TCP 选项里的窗口缩放因子（kind=3）；-1 表示未携带。
	//
	// 与 Rust 的 Option<u8> 对应：Go 用 -1 表示 None。
	// 服务端靠它分流（客户端的 NAT 会改写 IP ID，但不动 TCP 选项）。
	WScale int
	// TSVal/TSecr 是 TCP 时间戳选项；HasTS 表示是否存在。
	// TSVal 必须回显到回包的 TSecr 里，否则对端/中间盒会认为时间戳不合法。
	TSVal, TSecr uint32
	HasTS        bool
	Payload      []byte
}

// sum16 做 16 位反码求和，IP 头和 TCP 伪头校验共用。
func sum16(data []byte) uint32 {
	var sum uint32
	n := len(data) &^ 1
	for i := 0; i < n; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	// 奇数长度时最后一个字节补到高 8 位
	if len(data)&1 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	return sum
}

// fold 把 32 位累加和折叠成 16 位反码，作为最终校验和。
func fold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ParseFrame 解析 AF_PACKET 收到的以太网帧，提取 IPv4 + TCP 视图。
// 只支持无分片的 IPv4 单播报文；分片、IPv6、非 TCP 一律返回 false。
func ParseFrame(frame []byte) (ParsedPacket, bool) {
	var zero ParsedPacket
	// 以太网头最短 14 字节
	if len(frame) < 14 {
		return zero, false
	}
	// 跳过目的 MAC(6) + 源 MAC(6)，读 EtherType
	off := 12
	etherType := binary.BigEndian.Uint16(frame[off : off+2])
	off += 2
	// 处理单层 802.1Q VLAN 标签，部分云主机/虚拟化环境会带
	if etherType == 0x8100 {
		if len(frame) < off+4 {
			return zero, false
		}
		etherType = binary.BigEndian.Uint16(frame[off+2 : off+4])
		off += 4
	}
	// 只关心 IPv4
	if etherType != 0x0800 || len(frame) < off+20 {
		return zero, false
	}

	ip := frame[off:]
	if ip[0]>>4 != 4 {
		return zero, false
	}
	// IHL 以 4 字节为单位，正常是 5（20 字节）
	ihl := int(ip[0]&0x0F) * 4
	if ihl < 20 || len(ip) < ihl {
		return zero, false
	}
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen < ihl || totalLen > len(ip) {
		return zero, false
	}
	// 分片报文直接丢弃：QUIC 数据报必须保持单包，否则无法按记录解析
	if binary.BigEndian.Uint16(ip[6:8])&0x3fff != 0 {
		return zero, false
	}
	// 协议号必须为 6（TCP）
	if ip[9] != 6 {
		return zero, false
	}
	var srcOct, dstOct [4]byte
	copy(srcOct[:], ip[12:16])
	copy(dstOct[:], ip[16:20])

	tcp := ip[ihl:totalLen]
	if len(tcp) < 20 {
		return zero, false
	}
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || len(tcp) < dataOff {
		return zero, false
	}

	p := ParsedPacket{
		Src:     netip.AddrFrom4(srcOct),
		Dst:     netip.AddrFrom4(dstOct),
		SrcPort: binary.BigEndian.Uint16(tcp[0:2]),
		DstPort: binary.BigEndian.Uint16(tcp[2:4]),
		Seq:     binary.BigEndian.Uint32(tcp[4:8]),
		Ack:     binary.BigEndian.Uint32(tcp[8:12]),
		Flags:   tcp[13],
		IPID:    binary.BigEndian.Uint16(ip[4:6]),
		Window:  binary.BigEndian.Uint16(tcp[14:16]),
		WScale:  -1,
	}
	// 解析 TCP 选项里的窗口缩放因子（kind=3）与时间戳（kind=8）。
	// 解析器与 Rust 逐条一致：EOL 直接 break，NOP 前进一字节，
	// 长度非法也 break（宽松，宁可放过不可错杀）。
	for i := 20; i < dataOff; {
		kind := tcp[i]
		if kind == 0 { // EOL
			break
		}
		if kind == 1 { // NOP
			i++
			continue
		}
		if i+1 >= dataOff {
			break
		}
		l := int(tcp[i+1])
		if l < 2 || i+l > dataOff {
			break
		}
		if kind == 3 && l == 3 {
			p.WScale = int(tcp[i+2])
		}
		// 时间戳：kind=8 len=10，后跟 TSval(4) + TSecr(4)
		if kind == 8 && l == 10 {
			p.TSVal = binary.BigEndian.Uint32(tcp[i+2 : i+6])
			p.TSecr = binary.BigEndian.Uint32(tcp[i+6 : i+10])
			p.HasTS = true
		}
		i += l
	}
	p.Payload = tcp[dataOff:]
	return p, true
}

const (
	// TSOptLen 是数据段携带的 TCP 时间戳选项长度：
	// `nop,nop,kind=8,len=10,TSval(4),TSecr(4)`，12 字节，正好 4 字节对齐。
	TSOptLen = 12
	// TCPHdrWithTS 是帧里数据段的最大 TCP 头长度（20 基础 + 12 时间戳）。
	TCPHdrWithTS = 20 + TSOptLen
	// IPHdrLen 是 IPv4 基础头长度。
	IPHdrLen = 20

	// WScale 是伪 SYN / SYN-ACK 携带的 TCP 窗口缩放因子。
	//
	// **必须与 Rust 一致（9），不要改。**
	// 真实 Linux 实测值就是 9；早期用 12（256MB 窗口）是明显异常值，
	// 任何 DPI 都能一眼判定。分流由 IP ID 高字节承担（见 IPIDMark）。
	WScale uint8 = 9
)

// writeTSOption 写一个 TCP 时间戳选项到 dst（必须正好 12 字节）。
// 开头两个 NOP 是为了对齐，和 Linux 的 `nop,nop,TS val .. ecr ..` 逐字节一致。
func writeTSOption(dst []byte, tsval, tsecr uint32) {
	dst[0] = 0x01 // NOP
	dst[1] = 0x01 // NOP
	dst[2] = 0x08 // kind = 时间戳
	dst[3] = 0x0a // len = 10
	binary.BigEndian.PutUint32(dst[4:8], tsval)
	binary.BigEndian.PutUint32(dst[8:12], tsecr)
}

// SynOptions 构造 SYN / SYN-ACK 的 TCP 选项（20 字节，与真实 Linux 开启
// 时间戳后完全一致）：MSS 1460 + SACK permitted + TS + NOP + wscale 9。
//
// 字节布局（相对选项起点）：
//
//	 0..4   02 04 05 b4             MSS 1460
//	 4..6   04 02                   SACK permitted
//	 6..16  08 0a <tsval> <tsecr>   TCP 时间戳
//	16..17  01                      NOP
//	17..20  03 03 09                window scale = 9
func SynOptions(tsval, tsecr uint32) [20]byte {
	var o [20]byte
	copy(o[0:4], []byte{0x02, 0x04, 0x05, 0xb4}) // MSS 1460
	copy(o[4:6], []byte{0x04, 0x02})             // SACK permitted
	o[6] = 0x08                                  // TS kind
	o[7] = 0x0a                                  // TS len = 10
	binary.BigEndian.PutUint32(o[8:12], tsval)
	binary.BigEndian.PutUint32(o[12:16], tsecr)
	o[16] = 0x01 // NOP 对齐
	o[17] = 0x03 // wscale kind
	o[18] = 0x03 // wscale len = 3
	o[19] = WScale
	return o
}

// TcpSeg 是构造一个 TCP 段所需的全部可变字段。
// 用结构体而不是十几个参数，避免调用点错位。
type TcpSeg struct {
	Seq, Ack uint32
	Flags    uint8
	IPID     uint16
	// Window 是通告窗口（未经 wscale 放大）
	Window uint16
	TSVal  uint32
	TSecr  uint32
	// Options 是 SYN / SYN-ACK 的完整选项表；数据包与纯 ACK 留空，
	// 由构造函数自动追加 12 字节时间戳选项。
	Options []byte
	Payload []byte
}

// TcpClock 是一条伪造 TCP 连接的时间戳时钟。
//
// 真实 TCP 的 TSval 是「内核启动以来的毫秒数 + 随机偏移」，单调递增；
// TSecr 回显对端最近一次的 TSval。中间盒与时间戳校验类 DPI 会检查：
// 1) TSval 单调不回退；2) TSecr 必须等于自己最近发出的 TSval。
type TcpClock struct {
	// t0 是连接建立时刻，用于计算已过去的毫秒数
	t0 time.Time
	// base 是随机基准值，让每条连接的 TSval 起点不同
	base uint32
	// PeerTS 是对端最近一次的 TSval，回包时填进 TSecr
	PeerTS uint32
}

// NewTcpClock 用随机基准构造（客户端用）。
func NewTcpClock() *TcpClock {
	return &TcpClock{t0: time.Now(), base: mrand.Uint32()}
}

// NewTcpClockAt 用指定的 TSval 基准构造（服务端用）。
//
// 为什么需要它：同一条连接里所有报文的 TSval 必须**单调不减**
// （RFC 7323 的 PAWS 靠这个丢旧包）。握手阶段的 SYN-ACK 与 ServerHello
// 由服务端直接发、不走时钟；如果连接建立后再取随机基准，
// 第一个数据包的 TSval 就可能小于握手包，出现「时间戳回退」——
// 这是时间戳类 DPI 最容易抓的伪造特征。传握手用的 TSval（+2 留空隙）即可。
func NewTcpClockAt(base uint32) *TcpClock {
	return &TcpClock{t0: time.Now(), base: base}
}

// TSVal 返回当前应发送的 TSval，步长是真实毫秒数（不回退）。
func (c *TcpClock) TSVal() uint32 {
	return c.base + uint32(time.Since(c.t0).Milliseconds())
}

// Observe 记录对端的时间戳，供后续回包回显。
func (c *TcpClock) Observe(tsval uint32, ok bool) {
	if ok {
		c.PeerTS = tsval
	}
}

// AdvertisedWindow 根据「已收下但还没被上层消费的字节数」计算要通告的窗口
// （未缩放值）。
//
// 恒为 65535 是明显的伪造特征：真实 TCP 的窗口会随接收缓冲占用持续变化。
// 按真实语义计算：接收缓冲总量（与 QUIC 的 receive_window 一致，16MB）
// 减去未消费字节，再换算回未缩放值。空载时正好是 16MB >> 9 = 32768，
// 与真实 Linux 在 16MB rmem 下的通告值一致。
func AdvertisedWindow(unread int) uint16 {
	// 接收缓冲总量，与 quic/config.go 里的 receive_window 对齐
	const rcvTotal = 16 * 1024 * 1024
	free := rcvTotal - unread
	if free < 0 {
		free = 0
	}
	// 换算回未缩放值；至少保留 1，避免声明零窗口把对端卡死
	w := free >> WScale
	if w < 1 {
		return 1
	}
	if w > 65535 {
		return 65535
	}
	return uint16(w)
}

// seqLen 计算一个 TCP 段占用的序号长度（SYN 与 FIN 各占 1）。
func seqLen(flags uint8, payloadLen int) uint32 {
	n := uint32(payloadLen)
	if flags&(TCPSYN|TCPFIN) != 0 {
		n++
	}
	return n
}

// BuildPacket 构造一个完整的 IPv4 + TCP 报文（不含以太网头）。
//
// 分配一块刚好够用的缓冲；热路径请用 BuildPacketInto 复用缓冲。
func BuildPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seg TcpSeg) []byte {
	optsLen := TSOptLen
	if len(seg.Options) != 0 {
		optsLen = len(seg.Options)
	}
	out := make([]byte, 0, IPHdrLen+20+optsLen+len(seg.Payload))
	return BuildPacketInto(out, srcIP, dstIP, srcPort, dstPort, seg)
}

// BuildPacketInto 把一个完整的 IPv4 + TCP 报文写进 out。
//
// **语义与 Rust `build_packet_into` 一致：把 out 调整到 total_len，
// 然后从偏移 0 覆写（不是 append）。** 这样稳态可以复用同一块缓冲：
// 传入 out[:0] 或已用过的切片都能工作（cap 足够时不重新分配）。
//
// 选项为空 = 数据包/纯 ACK，统一带 12 字节时间戳；
// 否则用调用方给的完整选项表（SYN / SYN-ACK）。
func BuildPacketInto(out []byte, srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seg TcpSeg) []byte {
	autoTS := len(seg.Options) == 0
	headerLen := TCPHdrWithTS
	if !autoTS {
		headerLen = 20 + len(seg.Options)
	}
	tcpLen := headerLen + len(seg.Payload)
	totalLen := IPHdrLen + tcpLen

	// 复用容量：resize 只改长度，已分配的堆内存保留；下面每个字节都会被覆盖，
	// 因此不需要先清零（少一次 memset）。
	if cap(out) < totalLen {
		out = make([]byte, totalLen)
	} else {
		out = out[:totalLen]
	}

	srcOct := srcIP.As4()
	dstOct := dstIP.As4()

	// ---- IPv4 头 ----
	out[0] = 0x45 // 版本 4，头长 5*4=20
	out[1] = 0    // TOS 普通
	binary.BigEndian.PutUint16(out[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(out[4:6], seg.IPID)
	binary.BigEndian.PutUint16(out[6:8], 0x4000) // DF 位，禁止分片
	out[8] = 64                                  // TTL
	out[9] = 6                                   // TCP
	out[10], out[11] = 0, 0                      // 校验和先占位
	copy(out[12:16], srcOct[:])
	copy(out[16:20], dstOct[:])
	binary.BigEndian.PutUint16(out[10:12], fold(sum16(out[:IPHdrLen])))

	// ---- TCP 头 ----
	t := out[IPHdrLen : IPHdrLen+headerLen]
	binary.BigEndian.PutUint16(t[0:2], srcPort)
	binary.BigEndian.PutUint16(t[2:4], dstPort)
	binary.BigEndian.PutUint32(t[4:8], seg.Seq)
	binary.BigEndian.PutUint32(t[8:12], seg.Ack)
	// 数据偏移按 4 字节为单位，包含选项
	t[12] = byte(headerLen/4) << 4
	t[13] = seg.Flags
	// 窗口必须随接收缓冲变化，恒为 65535 是明显的伪造特征。
	binary.BigEndian.PutUint16(t[14:16], seg.Window)
	t[16], t[17] = 0, 0 // 校验和占位
	t[18], t[19] = 0, 0 // 紧急指针
	if autoTS {
		writeTSOption(t[20:TCPHdrWithTS], seg.TSVal, seg.TSecr)
	} else {
		copy(t[20:], seg.Options)
	}

	// 载荷拷贝到 TCP 头之后
	copy(out[IPHdrLen+headerLen:], seg.Payload)

	// ---- TCP 校验和（伪头 + TCP 头 + 载荷，全程零额外拷贝）----
	// 伪头 12 字节放栈上：源 IP(4) + 目的 IP(4) + 0 + 协议(1) + TCP 长度(2)
	var pseudo [12]byte
	copy(pseudo[0:4], srcOct[:])
	copy(pseudo[4:8], dstOct[:])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen))
	// TCP 头里的校验和字段此刻是 0，正好符合反码求和规则；
	// TCP 头与载荷在 out 中是连续的，一次遍历覆盖两段
	sum := sum16(pseudo[:]) + sum16(out[IPHdrLen:totalLen])
	binary.BigEndian.PutUint16(out[IPHdrLen+16:IPHdrLen+18], fold(sum))

	return out
}

// randomUint32 生成一个随机 32 位值。
//
// 用途：伪造 TCP 的初始序号（ISN）。真实 TCP 的 ISN 是随机化的，
// 固定值会让连接可被预测，也是中间盒判定「非真实栈」的明显特征。
func randomUint32() uint32 { return mrand.Uint32() }

// newNoncePrefix 生成 4 字节随机 nonce 前缀（供 codec 使用）。
func newNoncePrefix() [4]byte {
	var p [4]byte
	if _, err := rand.Read(p[:]); err != nil {
		// crypto/rand 在 Linux 上不会失败；真失败时退回数学随机，
		// 至少保证进程能起来（nonce 唯一性由计数器单调性兜底）。
		binary.BigEndian.PutUint32(p[:], mrand.Uint32())
	}
	return p
}
