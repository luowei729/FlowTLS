package flowtls

// 本文件是 WinDivert 的**用户态协议层**，刻意**不带 build tag**：
// 它全是纯字节操作，不碰任何 syscall，因此可以在 Linux 上跑单测。
//
// # 为什么这样分层
//
// Windows 支持的其余部分（DeviceIoControl、驱动安装、rawSocket 实现）都必须
// 在 `//go:build windows` 下编译，而本机没有 Windows 环境，那些代码**无法执行验证**。
// 把它们与「能验证的部分」分开，就能至少把最容易写错的部分钉住：
//
//	过滤器 VM 指令编码（field:11 | test:5 | success:16，24 字节，小端）
//	批量收发的包拼接 / 切分（驱动要求 back-to-back，没有长度前缀）
//	Address 的位域布局（80 字节，Outbound 在 bit17 等）
//
// 这三样一旦写错，现象都是「驱动行为诡异」而不是编译错误，在没有真机时
// 极难定位，所以必须靠字节级断言兜住。
//
// # 来源与许可
//
// 协议常量与结构布局取自 WinDivert 2.2.2 的 `windivert.h` / `windivert_device.h`，
// 与 sing-box 的 `common/windivert` 同源（本项目复用该实现的经验，代码独立编写）。
// 驱动二进制 `windivert_assets/*.sys` 为 WinDivert 官方发行版，
// 按 LGPL v3 再分发，许可证见同目录 `LICENSE.txt`。

import (
	"encoding/binary"

	"net/netip"
)

// ---- WinDivert 驱动常量（来自 windivert_device.h）----

// wdivLayerNetwork 是 WINDIVERT_LAYER_NETWORK：拦截本机进/出的 IP 包。
const wdivLayerNetwork uint32 = 0

// Address 位域。WINDIVERT_ADDRESS 的前 16 字节是：
//
//	UINT64 Layer:8 | Event:8 | Sniffed:1 | Outbound:1 | Loopback:1 |
//	       Impostor:1 | IPv6:1 | IPChecksum:1 | TCPChecksum:1 | UDPChecksum:1
//
// 之后是 64 字节的 union（NETWORK/FLOW/SOCKET/REFLECT），总共 80 字节。
const (
	wdivBitSniffed     = 16
	wdivBitOutbound    = 17
	wdivBitLoopback    = 18
	wdivBitImpostor    = 19
	wdivBitIPv6        = 20
	wdivBitIPChecksum  = 21
	wdivBitTCPChecksum = 22
	wdivBitUDPChecksum = 23
)

// wdivAddressSize 是 sizeof(WINDIVERT_ADDRESS)。驱动按这个步长遍历地址数组，
// 写错会让整个批量接口错位。
const wdivAddressSize = 80

// wdivMTUMax 是 WINDIVERT_MTU_MAX = 40 + 0xFFFF：单包上限（IPv6 头 + 最大载荷）。
const wdivMTUMax = 40 + 0xFFFF

// wdivAddr 是 WINDIVERT_ADDRESS 的 Go 视图。
//
// 前 16 字节是位域，之后 64 字节是 layer union。**大小必须是 80 字节**：
// 驱动按这个步长遍历地址数组，写错会让整个批量接口错位。
// 布局由 TestWindivertAddressLayout 用 unsafe.Sizeof 钉住。
type wdivAddr struct {
	Timestamp int64
	Bits      uint32
	_         uint32
	// Union 是 WINDIVERT_ADDRESS_NETWORK 等结构的联合体。
	//
	// 我们只需要前 8 字节（IfIdx + SubIfIdx）：**注入入向包时驱动要求
	// IfIdx 有效**（windivert.h 明确写了这一点），所以「重新注入一个收到的
	// 入向包」必须原样带上它，否则包会被丢到一个不存在的接口上。
	Union [64]byte
}

// IfIdx 返回收到该包时所在的接口索引（NETWORK 层 union 的第一个字段）。
func (a *wdivAddr) IfIdx() uint32 { return binary.LittleEndian.Uint32(a.Union[0:4]) }

// SubIfIdx 返回子接口索引。
func (a *wdivAddr) SubIfIdx() uint32 { return binary.LittleEndian.Uint32(a.Union[4:8]) }

func wdivBitGet(bits uint32, pos uint) bool { return bits&(1<<pos) != 0 }

func wdivBitSet(bits uint32, pos uint, v bool) uint32 {
	if v {
		return bits | (1 << pos)
	}
	return bits &^ (1 << pos)
}

// Outbound 报告这个包的方向（true = 从本机发出）。
func (a *wdivAddr) Outbound() bool { return wdivBitGet(a.Bits, wdivBitOutbound) }

// Impostor 报告这个包是否由注入产生。
//
// 我们**不主动设置**它：单句柄在 priority=0 上注入的包不会被同一句柄再次扣留
// （驱动保证「同一优先级只扣留一次」），所以不存在注入自环。
// 保留读取能力只为排查时能看出一帧是原生的还是注入回来的。
func (a *wdivAddr) Impostor() bool { return wdivBitGet(a.Bits, wdivBitImpostor) }

// SetChecksumsValid 声明 IP/TCP 校验和已经正确，驱动不要重算。
//
// **这是注入正确性的关键**：我们构包时已经算好校验和（`BuildPacketInto`），
// 若让驱动重算，它会按自己的解析覆盖我们写好的值；更糟的是驱动只对
// `*Checksum == 0` 的包重算，行为依赖未文档化的细节。
// 明确置 1 = 「这两个校验和有效，别动」。
func (a *wdivAddr) SetChecksumsValid() {
	a.Bits = wdivBitSet(a.Bits, wdivBitIPChecksum, true)
	a.Bits = wdivBitSet(a.Bits, wdivBitTCPChecksum, true)
}

// ---- 过滤器 VM ----

// 过滤器指令布局（windivert.h WINDIVERT_FILTER，24 字节，packed）：
//
//	word 0 (LE): field:11 | test:5 | success:16
//	word 1 (LE): failure:16 | neg:1 | reserved:15
//	word 2..5  : arg[4]（各 32 位，主机序）
//
// 驱动把它当判定树走：第 i 条指令成立 → 跳 success；不成立 → 跳 failure。
// success/failure 的 0x7FFE / 0x7FFF 是 ACCEPT / REJECT 终结符。
const (
	wdivInstBytes = 24
	wdivMaxInsts  = 256

	// 字段编号。**只收录本实现用到、且能从生产代码交叉验证的项**。
	//
	// 刻意不收录 ip.Id：它的编号无法在本仓内验证（windivert.h 未入库），
	// 写错会让过滤器直接不匹配（现象是「收不到任何包」，与「链路不通」
	// 无法区分）。所以本实现的分流特征仍放在**用户态**判断
	// （IP ID 高字节，见 handlePacket），过滤器只按方向 + 端口收紧。
	wdivFieldZero       = 0
	wdivFieldInbound    = 1
	wdivFieldOutbound   = 2
	wdivFieldIP         = 5
	wdivFieldTCP        = 8
	wdivFieldTCPSrcPort = 38
	wdivFieldTCPDstPort = 39

	wdivTestEQ  = 0
	wdivTestLEQ = 3
	wdivTestGEQ = 5

	wdivAccept uint16 = 0x7FFE
	wdivReject uint16 = 0x7FFF
)

// 过滤器 flags 与编译好的指令一起交给驱动。**驱动只按这里声明的方向/协议族
// 安装 WFP callout**，漏了对应位就永远收不到那个方向的包。
const (
	wdivFilterFlagInbound  uint64 = 0x0010
	wdivFilterFlagOutbound uint64 = 0x0020
	wdivFilterFlagIP       uint64 = 0x0040
	wdivFilterFlagIPv6     uint64 = 0x0080
)

// wdivInst 是一条过滤器指令。
type wdivInst struct {
	field   uint16
	test    uint8
	success uint16
	failure uint16
	arg     [4]uint32
}

// wdivFilter 是带顺序 AND 语义的过滤器。
type wdivFilter struct {
	insts []wdivInst
	flags uint64
}

func (f *wdivFilter) add(field uint16, test uint8, arg uint32) {
	f.insts = append(f.insts, wdivInst{field: field, test: test, arg: [4]uint32{arg}})
}

// encode 把判定链编成驱动认识的字节流。
//
// 语义：所有指令依次 AND；全部成立 → ACCEPT，任一失败 → REJECT。
// 因此第 i 条的 success 指向 i+1，最后一条指向 ACCEPT。
func (f *wdivFilter) encode() ([]byte, uint64, error) {
	if len(f.insts) == 0 {
		// 空过滤器 = 永假（不扣留任何包）。
		return wdivEncodeInst(wdivInst{
			field: wdivFieldZero, test: wdivTestEQ,
			success: wdivReject, failure: wdivReject,
		}), 0, nil
	}
	if len(f.insts) > wdivMaxInsts-1 {
		return nil, 0, errWindivertFilterTooLong
	}
	buf := make([]byte, 0, wdivInstBytes*len(f.insts))
	for i, inst := range f.insts {
		if i == len(f.insts)-1 {
			inst.success = wdivAccept
		} else {
			inst.success = uint16(i + 1)
		}
		inst.failure = wdivReject
		buf = append(buf, wdivEncodeInst(inst)...)
	}
	return buf, f.flags, nil
}

// wdivEncodeInst 按 24 字节 packed 布局编码单条指令。
func wdivEncodeInst(inst wdivInst) []byte {
	out := make([]byte, wdivInstBytes)
	word0 := uint32(inst.field&0x7FF) | uint32(inst.test&0x1F)<<11 | uint32(inst.success)<<16
	binary.LittleEndian.PutUint32(out[0:4], word0)
	binary.LittleEndian.PutUint32(out[4:8], uint32(inst.failure))
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(out[8+4*i:12+4*i], inst.arg[i])
	}
	return out
}

// --- 两个具体过滤器 ---

// wdivServerInboundFilter 是服务端的过滤器。
//
//	inbound and ip and tcp and tcp.DstPort == listenPort
//
// **只收入向**：服务端发出的 SYN-ACK / 数据由我们自己注入，
// 把 outbound 也纳入会让注入的包形成自环（虽然同优先级不会重复扣留，
// 但白白多一次驱动往返）。
//
// **不含 IP ID 条件**（见 wdivFieldZero 处注释的原因）。
// 代价是**同端口上的真实流量也会被扣留**（伪装站的浏览器请求），
// 因此 Listener 必须实现「不是我的包 → 重新注入」，
// 否则伪装站会有约 0.4%…不，是 100% 的请求被静默吞掉。
// 这与 Linux 完全不同：AF_PACKET 是被动复制，忽略即可。
func wdivServerInboundFilter(listenPort uint16) *wdivFilter {
	f := &wdivFilter{flags: wdivFilterFlagInbound | wdivFilterFlagIP}
	f.add(wdivFieldInbound, wdivTestEQ, 1)
	f.add(wdivFieldIP, wdivTestEQ, 1)
	f.add(wdivFieldTCP, wdivTestEQ, 1)
	f.add(wdivFieldTCPDstPort, wdivTestEQ, uint32(listenPort))
	return f
}

// wdivClientInboundFilter 是客户端的过滤器。
//
//	inbound and ip and tcp and tcp.SrcPort == serverPort and tcp.DstPort == sourcePort
//
// 4 元组里 IP 两端不用过滤器表达（客户端只有一个服务端地址，但域名解析结果
// 可能在重连时变化），端口组合已足够精确：`source_port` 是配置里固定的，
// 撞上本机其它连接的概率可以忽略（Linux 侧也是同样的假设）。
//
// **只收入向**：客户端发出的伪造包由我们自己注入。
// 收全了这个 4 元组的入向包，内核就永远看不到服务端的 SYN-ACK，
// 也就**不会生成 RST** —— Linux 侧那条 `iptables OUTPUT` 规则在 Windows 上
// 没有对应物，也不需要。
func wdivClientInboundFilter(serverPort, sourcePort uint16) *wdivFilter {
	f := &wdivFilter{flags: wdivFilterFlagInbound | wdivFilterFlagIP}
	f.add(wdivFieldInbound, wdivTestEQ, 1)
	f.add(wdivFieldIP, wdivTestEQ, 1)
	f.add(wdivFieldTCP, wdivTestEQ, 1)
	f.add(wdivFieldTCPSrcPort, wdivTestEQ, uint32(serverPort))
	f.add(wdivFieldTCPDstPort, wdivTestEQ, uint32(sourcePort))
	return f
}

// --- 批量收发的包拼接 / 切分 ---
//
// 驱动要求 SendBatch 的载荷是**所有包首尾相接**（无长度前缀、无 padding），
// 边界靠每个包的 IP total length 字段还原；RecvBatch 同理。
// 这两件事都在用户态完成，且**是本实现里最容易写错的地方**（错一位就错位），
// 所以抽成纯函数并单测。

// wdivPackBatch 把若干完整 IP 报文首尾相接地写进 dst，返回写入的字节数与
// 每个包的偏移长度。
//
// dst 容量不足时不写半截：返回 ok=false，调用方应缩小批量重试。
func wdivPackBatch(dst []byte, pkts [][]byte) (buf []byte, lens []int, ok bool) {
	total := 0
	for _, p := range pkts {
		total += len(p)
	}
	if total > cap(dst) {
		return nil, nil, false
	}
	buf = dst[:0]
	lens = lens[:0]
	for _, p := range pkts {
		buf = append(buf, p...)
		lens = append(lens, len(p))
	}
	return buf, lens, true
}

// wdivSplitBatch 按每个包的 IPv4 total length 字段切分驱动回填的缓冲区。
//
// 驱动保证「精确拷贝每个包的 IP total length 字节、首尾相接」，
// 所以切分只能靠这个字段。若某个字段读出来是 0 或越界，说明驱动回填异常，
// 直接停止切分并返回已切出的部分（不 panic、不静默产生畸形切片）。
func wdivSplitBatch(buf []byte) [][]byte {
	out := make([][]byte, 0, 16)
	off := 0
	for off+20 <= len(buf) {
		// IPv4 total length 在 IP 头偏移 2，2 字节大端。
		total := int(binary.BigEndian.Uint16(buf[off+2 : off+4]))
		// 最小合法 IPv4 头是 20 字节；total 必须能覆盖头部且不越界。
		if total < 20 || off+total > len(buf) {
			break
		}
		out = append(out, buf[off:off+total])
		off += total
	}
	return out
}

// wdivIPIDMarkRange 返回 IP ID 标记的取值区间（闭区间）。
//
// `NextIPID` 保持高字节不变、低字节递增回绕，所以一条连接的 IP ID 落在
// `[mark, mark|0xFF]`。目前只用于日志与文档，不作为过滤器条件
// （原因见 wdivFieldZero 处注释）。
func wdivIPIDMarkRange(mark uint16) (lo, hi uint16) {
	m := mark & 0xFF00
	return m, m | IPIDLowMask
}

// wdivSrcAddrOf 从完整 IP 报文里读源地址（仅用于日志/诊断）。
func wdivSrcAddrOf(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 {
		return netip.Addr{}, false
	}
	var b [4]byte
	copy(b[:], pkt[12:16])
	return netip.AddrFrom4(b), true
}
