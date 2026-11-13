//go:build linux

package flowtls

import (
	"net/netip"
	"testing"
	"time"
)

// TestSendmmsgAcceptsKernelLayout 直接校验 sendmmsg 的返回值。
//
// **这个测试的存在理由**：sendmmsg 的 msg_name / msg_namelen 布局极其容易写错：
//
//   - Go 的 syscall.SockaddrLinklayer 字段顺序**不是** family 开头
//     （第一个字段是 Protocol），直接传指针会把协议号当地址族；
//   - 它的 unsafe.Sizeof 是 48，而内核 struct sockaddr_ll 只有 20，
//     msg_namelen 传大了内核会读到结构体之外。
//
// 两种错误都会让内核返回 EINVAL，而如果调用方吞掉错误，
// 报文就静默全丢——现象是「TCP 三次握手成功，但 QUIC 永远握手超时」，
// 单看代码完全看不出问题（本轮就踩了这个坑）。
//
// 这里不验证「对端收到」，只验证「内核接受这批报文」：
// 前者依赖真实链路与路由，后者才是布局正确性的判据。
func TestSendmmsgAcceptsKernelLayout(t *testing.T) {
	if testing.Short() {
		t.Skip("需要 raw socket（root 或 CAP_NET_RAW）")
	}

	// 目的地址用 8.8.8.8：它必然走默认路由，与生产环境的
	// 「发往服务器公网 IP」是同一条路径。
	dst := netip.MustParseAddr("8.8.8.8")
	s, err := newRawSocket(dst, netip.Addr{}, false)
	if err != nil {
		t.Skipf("无法创建 raw socket（可能缺 CAP_NET_RAW）: %v", err)
	}
	defer s.Close()

	const count = 8
	pkts := make([][]byte, count)
	for i := range pkts {
		// 构造一个最小合法 IPv4 头 + 载荷。内容不重要，
		// 内核只按 IP 头做路由，不做协议校验。
		pkt := make([]byte, 100)
		pkt[0] = 0x45                         // version=4, IHL=5
		pkt[2], pkt[3] = 0x00, byte(len(pkt)) // total length
		pkt[8] = 64                           // TTL
		pkt[9] = 253                          // 一个内核不会处理的协议号
		copy(pkt[16:20], dst.AsSlice())       // dst
		pkts[i] = pkt
	}

	// 直接调 sendmmsg，绕过 SendBatch 的退化兜底——
	// 否则「布局写错 → 退化成功」会掩盖问题。
	n, err := s.sendmmsg(pkts, dst)
	if err != nil {
		t.Fatalf("sendmmsg 返回错误 %v——"+
			"sockaddr 布局与内核 struct sockaddr_ll 不匹配", err)
	}
	if n != count {
		t.Fatalf("sendmmsg 只发出 %d/%d 个报文", n, count)
	}
}

// TestSendBatchFallsBackOnBadDst 验证不支持的目的地址会报错而不是静默丢包。
func TestSendBatchFallsBackOnBadDst(t *testing.T) {
	if testing.Short() {
		t.Skip("需要 raw socket")
	}
	dst := netip.MustParseAddr("8.8.8.8")
	s, err := newRawSocket(dst, netip.Addr{}, false)
	if err != nil {
		t.Skipf("无法创建 raw socket: %v", err)
	}
	defer s.Close()

	// IPv6 目的地址：AF_INET 路径不支持，必须返回错误而不是假装成功。
	_, err = s.SendBatch([][]byte{{0x45}}, netip.MustParseAddr("::1"))
	if err == nil {
		t.Fatal("IPv6 目的地址应当报错，实际返回 nil——" +
			"上层会以为报文已发出，实际全丢")
	}
}

// TestRecvmmsgActuallyReceives 验证 recvmmsg 真的能收到报文。
//
// 与 TestSendmmsgAcceptsKernelLayout 是同一类测试：recvmmsg 的 mmsghdr
// 布局写错时内核返回 EINVAL，若调用方当成「暂时没包」继续循环，
// 表现就是「隧道完全收不到数据」而没有任何错误日志。
//
// 做法：自己给自己发几个包（同一个 rawSocket 的 sendFD → recvFD 走内核回环），
// 断言 RecvBatch 能一次取回全部。
func TestRecvmmsgActuallyReceives(t *testing.T) {
	if testing.Short() {
		t.Skip("需要 raw socket（root 或 CAP_NET_RAW）")
	}
	dst := netip.MustParseAddr("8.8.8.8")
	s, err := newRawSocket(dst, netip.Addr{}, false)
	if err != nil {
		t.Skipf("无法创建 raw socket: %v", err)
	}
	defer s.Close()

	// 构造发往本机的包（源/目的都写本机出口 IP），
	// 这样内核会把它们回环到本地，我们自己的 recvFD 能收到。
	local := s.LocalIP.As4()
	const count = 4
	pkts := make([][]byte, count)
	for i := range pkts {
		pkt := make([]byte, 200)
		pkt[0] = 0x45
		pkt[2], pkt[3] = 0x00, byte(len(pkt))
		pkt[8] = 64
		pkt[9] = 253
		copy(pkt[12:16], local[:])
		copy(pkt[16:20], local[:])
		pkt[100] = byte(i) // 标记
		pkts[i] = pkt
	}

	// 发到本机地址（不是 8.8.8.8），才会回环
	if _, err := s.SendBatch(pkts, s.LocalIP); err != nil {
		t.Skipf("发送失败（环境不支持回环）: %v", err)
	}

	const bufSize = 2048
	bufs := make([][]byte, maxRecvBatch)
	for i := range bufs {
		bufs[i] = make([]byte, bufSize)
	}
	lens := make([]int, maxRecvBatch)

	// 最多等 1 秒：AF_PACKET 是异步的，包可能还没进队列。
	deadline := time.Now().Add(time.Second)
	total := 0
	seen := make(map[byte]bool)
	for time.Now().Before(deadline) && total < count {
		n, err := s.RecvBatch(bufs, lens)
		if err != nil {
			t.Fatalf("RecvBatch 失败: %v——mmsghdr 布局可能与内核不匹配", err)
		}
		if n == 0 {
			continue
		}
		for i := 0; i < n; i++ {
			// 过滤掉系统上的其它流量
			if lens[i] < 101 || bufs[i][9] != 253 {
				continue
			}
			seen[bufs[i][100]] = true
			total++
		}
	}
	if total == 0 {
		t.Skip("没有收到回环包（本机 AF_PACKET 不回环，属环境限制）")
	}
	t.Logf("RecvBatch 收到 %d 个报文", total)
}
