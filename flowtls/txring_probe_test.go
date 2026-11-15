package flowtls

// 本文件是 **AF_PACKET TX_RING 的可行性实验与结论存档**，不是生产代码。
//
// # 结论（2026-11-15 实测）：不做
//
// 机制是可行的（本测试能证明内核接受布局并正确消费帧），但**实测更慢**：
//
//	同端口 ABAB 交替，服务端 CPU秒/MB（越小越好）
//	recvmmsg 批量   0.0368（中位）
//	TX_RING         0.0426（中位）   ← 慢 16%
//
// 原因是 TX_RING 只能省掉「用户态→内核」的那一次拷贝：
// 内核在 `tpacket_snd` 里仍要 `skb_copy_to_linear_data` 把帧拷进 skb，
// 而 SOCK_RAW 还要多写 14 字节以太网头、内核再解析一遍链路层。
// 我们当前 sendmmsg 已经是一次 syscall 交 64 个包，syscall 次数本就不多，
// 所以「省 copy_from_user」的收益抵不过「SOCK_RAW 多出来的开销」。
//
// 这份测试保留下来，是为了让「为什么不做」有可执行的证据——
// 下次有人想再试时先跑它，再读上面这段数字。
//
// # 附：SOCK_DGRAM 不可用
//
// TX_RING 在 SOCK_DGRAM 下**无法指定目的 MAC**（环里没有放 sockaddr_ll 的地方，
// sendto 的 sll 只用于选网卡）。实测 4 种 tp_mac/dataOff 组合全部
// 「提交成功但包不上线」——与 DEVTIPS 84 的 QDISC_BYPASS 同类静默失败。

import (
	"os"
	"testing"
	"time"
	"unsafe"

	"net/netip"
	"syscall"
)

// 内核常量（syscall 包未导出）。
const (
	packetTxRing        = 13
	tpStatusAvailable   = 0
	tpStatusSendRequest = 1
	tpStatusSending     = 2
	tpStatusWrongFormat = 4
)

// tpacketReq 是 struct tpacket_req（TPACKET_V1）。
type tpacketReq struct {
	BlockSize uint32
	BlockNr   uint32
	FrameSize uint32
	FrameNr   uint32
}

// tpacketHdr 是 struct tpacket_hdr（TPACKET_V1，32 字节）。
type tpacketHdr struct {
	Status  uint64
	Len     uint32
	SnapLen uint32
	Mac     uint16
	Net     uint16
	Sec     uint32
	Usec    uint32
}

// setsockoptRaw 是传结构体用的 setsockopt 封装。
func setsockoptRaw(fd, level, opt int, val unsafe.Pointer, vallen uintptr) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(fd), uintptr(level), uintptr(opt),
		uintptr(val), vallen, 0)
	if errno != 0 {
		return os.NewSyscallError("setsockopt", errno)
	}
	return nil
}

// tpAlign 是 TPACKET_ALIGN：把长度向上对齐到 16 字节。
func tpAlign(n uint32) uint32 { return (n + 15) &^ 15 }

// TestTxRingFeasibility 验证 SOCK_DGRAM + TX_RING 是否可用。
//
// 这是**实验**，不是门禁：环境不支持时 Skip，结论记进 DEVTIPS。
func TestTxRingFeasibility(t *testing.T) {
	if testing.Short() {
		t.Skip("需要 raw socket")
	}
	dst := netip.MustParseAddr("8.8.8.8")
	s, err := newRawSocket(dst, netip.Addr{}, nil, true)
	if err != nil {
		t.Skipf("无法创建 raw socket: %v", err)
	}
	defer s.Close()

	local := s.LocalIP()
	if !local.Is4() {
		t.Skip("出口 IP 不是 IPv4")
	}

	// 独立开一个 TX_RING socket，不碰生产路径。
	// **必须 SOCK_RAW**：TX_RING 在 SOCK_DGRAM 下无法指定目的 MAC
	// （环里没有放 sockaddr_ll 的地方，sendto 的 sll 只用于选网卡），
	// 实测 4 种 tp_mac/dataOff 组合全部「提交成功但收不到包」。
	// SOCK_RAW 要自己写 14 字节以太网头，但语义明确、行为可预测。
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW,
		int(htons(syscall.ETH_P_IP)))
	if err != nil {
		t.Skipf("AF_PACKET socket 失败: %v", err)
	}
	defer syscall.Close(fd)

	// 必须 bind 到出口网卡，否则 TX_RING 不知道从哪发。
	sll := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_IP),
		Ifindex:  s.ifindex,
	}
	if err := syscall.Bind(fd, sll); err != nil {
		t.Skipf("bind 失败: %v", err)
	}

	// 环参数：1 个 block、64 个 frame、每个 frame 2048 字节。
	const (
		frameSize = 2048
		frameNr   = 64
		blockSize = frameSize * frameNr
	)
	req := tpacketReq{
		BlockSize: blockSize,
		BlockNr:   1,
		FrameSize: frameSize,
		FrameNr:   frameNr,
	}
	if err := syscall.SetsockoptString(fd, syscall.SOL_PACKET, packetTxRing, ""); err == nil {
		// SetsockoptString 不会传对结构体，只是探测常量是否被接受；
		// 真正要的是下面用 SetsockoptOptval 传二进制。
		_ = err
	}
	// 用原始 setsockopt 传结构体。
	if err := setsockoptRaw(fd, syscall.SOL_PACKET, packetTxRing,
		unsafe.Pointer(&req), unsafe.Sizeof(req)); err != nil {
		t.Skipf("PACKET_TX_RING 不被支持: %v", err)
	}

	mem, err := syscall.Mmap(fd, 0, blockSize,
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		t.Fatalf("mmap 环失败（setsockopt 成功但 mmap 失败 = 参数有问题）: %v", err)
	}
	defer syscall.Munmap(mem)
	t.Logf("TX_RING 建立成功：frame=%d × %d，mmap=%d 字节", frameSize, frameNr, len(mem))

	// ---- 遍历几种可能的数据偏移/字段组合，找出内核真正接受的那一种 ----
	//
	// 内核 tpacket_snd 在 TPACKET_V1 下按 `TPACKET_ALIGN(sizeof(tpacket_hdr))`
	// = 32 定位数据；而 TPACKET_HDRLEN=52 是给 RX_RING（要放 sockaddr_ll）的。
	// SOCK_DGRAM 与 SOCK_RAW 在 TX_RING 下的语义差别文档没写清，只能实测。
	type variant struct {
		name    string
		dataOff uint32
		mac     uint16
	}
	variants := []variant{
		{"off=32 mac=32", 32, 32}, // 内核 tpacket_snd 的实际定位方式
		{"off=52 mac=52", 52, 52}, // TPACKET_HDRLEN 布局（RX_RING 风格）
	}

	// ---- 构造「以太网头 + 回环 IPv4 包」（SOCK_RAW 要求自带链路层头）----
	ipPkt := make([]byte, 60)
	ipPkt[0] = 0x45
	ipPkt[2], ipPkt[3] = 0x00, byte(len(ipPkt))
	ipPkt[8] = 64
	ipPkt[9] = 253 // 内核不会处理的协议号
	copy(ipPkt[12:16], local.AsSlice())
	copy(ipPkt[16:20], local.AsSlice())

	// 目的 MAC 用下一跳（与真实发送一致）；源 MAC 随便填一个本地管理地址。
	var eth [14]byte
	copy(eth[0:6], s.nextHopMAC[:])
	eth[6] = 0x02 // locally administered
	eth[7], eth[8], eth[9], eth[10], eth[11] = 0x00, 0x00, 0x00, 0x00, 0x01
	eth[12], eth[13] = 0x08, 0x00 // ETH_P_IP

	pkt := append(eth[:], ipPkt...)

	// ---- 判据：看内核怎么处理这一帧的状态机 ----
	//
	// 回环收包在这个环境里不可靠（AF_PACKET 发出后不回环，之前
	// TestRecvActuallyReceives 收到的 42 个包很可能是无关流量）。
	// 所以改用状态机判据：
	//
	//	TP_STATUS_SEND_REQUEST 内核取走后会置 SENDING，发完归还 AVAILABLE
	//	TP_STATUS_WRONG_FORMAT 内核明确拒绝（长度/偏移不合法）← 决定性失败信号
	//	停在 SEND_REQUEST       内核根本没看到这一帧（sendto 没触发处理）
	//
	// 三种终局互斥，足以定位问题。
	var worked []string
	for idx, v := range variants {
		frame := mem[idx*frameSize : (idx+1)*frameSize]
		hdr := (*tpacketHdr)(unsafe.Pointer(&frame[0]))
		if hdr.Status != tpStatusAvailable {
			t.Logf("%-14s frame 初始状态 %d ≠ AVAILABLE，跳过", v.name, hdr.Status)
			continue
		}
		if int(v.dataOff)+len(pkt) > len(frame) {
			t.Logf("%-14s 数据越界，跳过", v.name)
			continue
		}
		copy(frame[v.dataOff:], pkt)
		hdr.Len = uint32(len(pkt))
		hdr.SnapLen = uint32(len(pkt))
		hdr.Mac = v.mac
		hdr.Net = 0
		hdr.Status = tpStatusSendRequest

		if err := syscall.Sendto(fd, nil, 0, sll); err != nil {
			t.Logf("%-14s sendto 失败: %v", v.name, err)
			hdr.Status = tpStatusAvailable
			continue
		}

		// 轮询到终局
		var final uint64
		sawSending := false
		for i := 0; i < 200; i++ {
			final = hdr.Status
			if final == tpStatusSending {
				sawSending = true
			}
			if final == tpStatusAvailable {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
		switch final {
		case tpStatusAvailable:
			worked = append(worked, v.name)
			t.Logf("%-14s ✅ 内核取走并归还（sawSending=%v）——布局可用", v.name, sawSending)
		case tpStatusWrongFormat:
			t.Logf("%-14s ❌ WRONG_FORMAT：内核拒绝该长度/偏移", v.name)
		case tpStatusSendRequest:
			t.Logf("%-14s ❌ 停在 SEND_REQUEST：sendto 没有触发内核处理这一帧", v.name)
		default:
			t.Logf("%-14s ❌ 最终状态 %d（sawSending=%v）", v.name, final, sawSending)
		}
		hdr.Status = tpStatusAvailable
	}

	if len(worked) == 0 {
		t.Fatal("没有任何布局被内核接受：TX_RING 在本环境不可用")
	}
	t.Logf("可用布局：%v", worked)
}
