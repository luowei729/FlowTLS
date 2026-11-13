package flowtls

import (
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand/v2"
	"net/netip"
	"time"
)

// TCP 标志位。构造与解析共用，避免魔数散落。
const (
	TCPFIN uint8 = 0x01
	TCPSYN uint8 = 0x02
	TCPRST uint8 = 0x04
	TCPPSH uint8 = 0x08
	TCPACK uint8 = 0x10
)

// ---- IP ID 分流标记 ----
//
// 两端都要用 iptables 把伪造包挡在内核 TCP 栈之外（服务端防止内核回
// SYN-ACK/RST，客户端防止内核回 RST），iptables 需要一个静态可匹配的特征。
// TCP 选项已全部改为真实值（含时间戳、wscale 9），不能再当指纹，
// 因此静态标记只能留在 IP ID 上。
//
// 标记值必须来自配置，不能写死：写死一个固定值意味着任何 DPI 只要加一条
// 通用规则就能一次命中所有部署。从配置派生后，检测方必须逐条链路学习。
//
// 范围刻意保持「高字节固定」：iptables 会直接 DROP，内核看不到就没有任何
// 响应。若标记覆盖过宽，普通端口探测只要 IP ID 落进该范围就会得到
// 「完全没反应」，反而暴露有一层过滤。高字节固定 = 256 个值 ≈ 0.4% 的
// 探测无响应，与正常丢包率难以区分。
const (
	// IPIDMark 是默认标记高字节（等价于配置 ip_id_magic: 0xF107 的高字节）
	IPIDMark uint16 = 0xF100
	// IPIDLowMask 是可递增的低 8 位
	IPIDLowMask uint16 = 0x00FF
)

// WScale 是交换端口的 TCP 窗口缩放因子。
//
// 真实 Linux 实测值是 9；早先版本用 12（256MB 窗口）是明显异常值，
// 任何 DPI 都能一眼判定。改回 9 后分流改由 IP ID 高字节承担。
const WScale uint8 = 9

const (
	// TSOptLen 是数据段自动追加的时间戳选项长度：nop,nop,kind=8,len=10,val,ecr
	TSOptLen = 12
	// TCPHdrWithTS 是数据段的最大 TCP 头长度（20 基础 + 12 时间戳）
	TCPHdrWithTS = 20 + TSOptLen
	// IPHdrLen 是 IPv4 基础头长度
	IPHdrLen = 20
)

// IPIDMarkOf 从配置的 ip_id_magic 取出标记高字节。
func IPIDMarkOf(magic uint16) uint16 { return magic & 0xFF00 }

// NextIPID 取下一个 IP ID：高字节保持标记，低字节 +1 回绕。
func NextIPID(mark, cur uint16) uint16 {
	return mark | ((cur + 1) & IPIDLowMask)
}

// RandomIPID 生成随机起始 IP ID，避免所有连接都从同一值开始。
func RandomIPID(mark uint16) uint16 {
	return mark | (uint16(mrand.Uint32()) & IPIDLowMask)
}

// ParsedPacket 是解析后的 IPv4 + TCP 报文视图。
// Payload 直接借用接收缓冲区，零拷贝。
type ParsedPacket struct {
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	Seq, Ack         uint32
	Flags            uint8
	IPID             uint16
	// Window 是未经 wscale 放大的原始窗口值
	Window uint16
	// WScale 是 TCP 选项里的窗口缩放因子（kind=3），-1 表示未携带
	WScale int
	// TSVal / TSecr 是 TCP 时间戳选项，HasTS 表示是否存在
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

// fold 把 32 位累加和折叠成 16 位反码。
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
	if etherType != 0x0800 || len(frame) < off+IPHdrLen {
		return zero, false
	}

	ip := frame[off:]
	if ip[0]>>4 != 4 {
		return zero, false
	}
	ihl := int(ip[0]&0x0F) * 4
	if ihl < IPHdrLen || len(ip) < ihl {
		return zero, false
	}
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen < ihl || totalLen > len(ip) {
		return zero, false
	}
	// 分片报文直接丢弃：QUIC 数据报必须保持单包，否则无法按记录解析
	if binary.BigEndian.Uint16(ip[6:8])&0x3FFF != 0 {
		return zero, false
	}
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
	// 解析 TCP 选项：wscale（kind=3）与时间戳（kind=8）
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

// writeTSOption 写入 12 字节时间戳选项。
// 开头两个 NOP 是对齐用，与 Linux 的 nop,nop,TS val .. ecr .. 逐字节一致。
func writeTSOption(dst []byte, tsval, tsecr uint32) {
	dst[0] = 0x01
	dst[1] = 0x01
	dst[2] = 0x08
	dst[3] = 0x0a
	binary.BigEndian.PutUint32(dst[4:8], tsval)
	binary.BigEndian.PutUint32(dst[8:12], tsecr)
}

// SynOptions 构造 SYN / SYN-ACK 的 TCP 选项（20 字节）：
// MSS 1460 + SACK permitted + TS + NOP + wscale 9，与真实 Linux 一致。
func SynOptions(tsval, tsecr uint32) [20]byte {
	var o [20]byte
	copy(o[0:4], []byte{0x02, 0x04, 0x05, 0xb4}) // MSS 1460
	copy(o[4:6], []byte{0x04, 0x02})             // SACK permitted
	o[6] = 0x08
	o[7] = 0x0a
	binary.BigEndian.PutUint32(o[8:12], tsval)
	binary.BigEndian.PutUint32(o[12:16], tsecr)
	o[16] = 0x01 // NOP 对齐
	o[17] = 0x03
	o[18] = 0x03
	o[19] = WScale
	return o
}

// TcpClock 是一条伪造 TCP 连接的时间戳时钟。
//
// 真实 TCP 的 TSval 是「内核启动毫秒数 + 随机偏移」，单调递增；
// TSecr 回显对端最近一次的 TSval。中间盒与时间戳 DPI 会检查
// 1) TSval 不回退；2) TSecr 等于自己最近发过的 TSval。
type TcpClock struct {
	t0     time.Time
	base   uint32
	PeerTS uint32
}

// NewTcpClock 用随机基准构造（客户端用）。
func NewTcpClock() *TcpClock {
	return &TcpClock{t0: time.Now(), base: mrand.Uint32()}
}

// NewTcpClockAt 用指定基准构造（服务端用）。
//
// 同一条连接里所有报文的 TSval 必须单调不减（RFC 7323 的 PAWS 靠这个）。
// 握手包的 TSval 由握手逻辑直接发、不走时钟，若连接建立后再取随机基准，
// 第一个数据包的 TSval 就可能小于握手包，出现「时间戳回退」——
// 这是时间戳类 DPI 最容易抓的伪造特征。传握手用过的值（+2 留空隙）即可。
func NewTcpClockAt(base uint32) *TcpClock {
	return &TcpClock{t0: time.Now(), base: base}
}

// TSVal 返回当前应发送的 TSval，步长为真实毫秒数且不回退。
func (c *TcpClock) TSVal() uint32 {
	return c.base + uint32(time.Since(c.t0).Milliseconds())
}

// Observe 记录对端时间戳，供后续回包回显。
func (c *TcpClock) Observe(tsval uint32, ok bool) {
	if ok {
		c.PeerTS = tsval
	}
}

// AdvertisedWindow 按「已收下但还没被上层消费的字节数」计算通告窗口（未缩放）。
//
// 恒为 65535 是明显伪造特征：真实 TCP 的窗口随接收缓冲占用持续变化。
// 这里按 16MB 接收缓冲计算，与 QUIC 的 receive_window 对齐：
// 空载时是 16MB>>9 = 32768（真实 Linux 在 16MB rmem 下的取值），
// 有积压时平滑下降。
func AdvertisedWindow(unread int) uint16 {
	const rcvTotal = 16 * 1024 * 1024
	free := rcvTotal - unread
	if free < 0 {
		free = 0
	}
	w := uint16(free >> WScale)
	if w == 0 {
		w = 1 // 不能声明零窗口把对端卡死
	}
	return w
}

// seqLen 计算一个 TCP 段占用的序号长度（SYN 与 FIN 各占 1）。
func seqLen(flags uint8, payloadLen int) uint32 {
	n := uint32(payloadLen)
	if flags&(TCPSYN|TCPFIN) != 0 {
		n++
	}
	return n
}

// TcpSeg 构造一个 TCP 段所需的全部字段。
// 用结构体而不是十几个参数，避免调用点错位。
type TcpSeg struct {
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	Seq, Ack         uint32
	Flags            uint8
	IPID             uint16
	Window           uint16
	TSVal, TSecr     uint32
	// Options 为 nil 时自动追加 12 字节时间戳选项（数据包/纯 ACK）；
	// 非 nil 时按给定内容使用（SYN / SYN-ACK）。
	Options []byte
	Payload []byte
}

// AppendPacket 构造 IPv4 + TCP 报文并追加到 dst（不含以太网头）。
//
// 追加语义而不是「写入固定缓冲」：调用方可以复用底层数组，
// 稳态下零分配。TCP 校验和直接在 dst 上分段累加，
// 不拼临时伪头切片，载荷只被遍历一次。
func AppendPacket(dst []byte, seg TcpSeg) []byte {
	autoTS := len(seg.Options) == 0
	headerLen := TCPHdrWithTS
	if !autoTS {
		headerLen = 20 + len(seg.Options)
	}
	tcpLen := headerLen + len(seg.Payload)
	totalLen := IPHdrLen + tcpLen

	base := len(dst)
	dst = append(dst, make([]byte, totalLen)...)
	out := dst[base:]

	srcOct := seg.Src.As4()
	dstOct := seg.Dst.As4()

	// ---- IPv4 头 ----
	out[0] = 0x45 // 版本 4，头长 5*4=20
	out[1] = 0
	binary.BigEndian.PutUint16(out[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(out[4:6], seg.IPID)
	binary.BigEndian.PutUint16(out[6:8], 0x4000) // DF，禁止分片
	out[8] = 64                                  // TTL
	out[9] = 6                                   // TCP
	out[10], out[11] = 0, 0
	copy(out[12:16], srcOct[:])
	copy(out[16:20], dstOct[:])
	binary.BigEndian.PutUint16(out[10:12], fold(sum16(out[0:20])))

	// ---- TCP 头 ----
	t := out[IPHdrLen : IPHdrLen+headerLen]
	binary.BigEndian.PutUint16(t[0:2], seg.SrcPort)
	binary.BigEndian.PutUint16(t[2:4], seg.DstPort)
	binary.BigEndian.PutUint32(t[4:8], seg.Seq)
	binary.BigEndian.PutUint32(t[8:12], seg.Ack)
	t[12] = byte(headerLen/4) << 4 // 数据偏移（4 字节为单位，含选项）
	t[13] = seg.Flags
	binary.BigEndian.PutUint16(t[14:16], seg.Window)
	t[16], t[17] = 0, 0 // 校验和占位
	t[18], t[19] = 0, 0 // 紧急指针
	if autoTS {
		writeTSOption(t[20:TCPHdrWithTS], seg.TSVal, seg.TSecr)
	} else {
		copy(t[20:], seg.Options)
	}

	copy(out[IPHdrLen+headerLen:], seg.Payload)

	// ---- TCP 校验和（伪头 + TCP 头 + 载荷，零额外拷贝）----
	// 伪头 12 字节放栈上：源 IP(4) + 目的 IP(4) + 0 + 协议(1) + TCP 长度(2)
	var pseudo [12]byte
	copy(pseudo[0:4], srcOct[:])
	copy(pseudo[4:8], dstOct[:])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen))
	// 此刻 TCP 头里的校验和是 0，正好符合反码求和规则
	sum := sum16(pseudo[:]) + sum16(out[IPHdrLen:totalLen])
	binary.BigEndian.PutUint16(out[36:38], fold(sum))

	return dst
}

// newNoncePrefix 生成 4 字节随机 nonce 前缀。
//
// 用 crypto/rand 而不是 math/rand：前缀决定 nonce 空间，
// 同一密钥下 nonce 不重复是 AEAD 安全性的前提。
func newNoncePrefix() [4]byte {
	var p [4]byte
	if _, err := rand.Read(p[:]); err != nil {
		// crypto/rand 在 Linux 上不会失败；真失败时退回数学随机，
		// 至少保证进程能起来（安全性由计数器单调性兜底）。
		binary.BigEndian.PutUint32(p[:], mrand.Uint32())
	}
	return p
}
