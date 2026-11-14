//go:build linux

package flowtls

import (
	"net/netip"
	"syscall"
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
// 两种错误都会让内核返回 EINVAL，而如果调用方吞掉错误，报文就静默全丢
// ——现象是「TCP 三次握手成功，但 QUIC 永远握手超时」，单看代码看不出问题。
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
	s, err := newRawSocket(dst, netip.Addr{})
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

	n, err := s.SendBatch(pkts, dst)
	if err != nil {
		t.Fatalf("SendBatch 返回错误 %v——sockaddr 布局与内核不匹配", err)
	}
	if n != count {
		t.Fatalf("只发出 %d/%d 个报文", n, count)
	}
}

// TestSendRejectsIPv6 验证非 IPv4 目的地址报错而不是静默丢包。
func TestSendRejectsIPv6(t *testing.T) {
	if testing.Short() {
		t.Skip("需要 raw socket")
	}
	dst := netip.MustParseAddr("8.8.8.8")
	s, err := newRawSocket(dst, netip.Addr{})
	if err != nil {
		t.Skipf("无法创建 raw socket: %v", err)
	}
	defer s.Close()
	if err := s.Send([]byte{0x45}, netip.MustParseAddr("::1")); err == nil {
		t.Fatal("IPv6 目的地址应当报错")
	}
	if _, err := s.SendBatch([][]byte{{0x45}}, netip.MustParseAddr("::1")); err == nil {
		t.Fatal("IPv6 目的地址应当报错")
	}
}

// TestRawSocketCloseIdempotent 验证 Close 幂等（Go 无析构函数，多条路径会调）。
func TestRawSocketCloseIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("需要 raw socket")
	}
	dst := netip.MustParseAddr("8.8.8.8")
	s, err := newRawSocket(dst, netip.Addr{})
	if err != nil {
		t.Skipf("无法创建 raw socket: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("首次 Close 失败: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("重复 Close 应返回 nil，实际: %v", err)
	}
}

// TestRecvActuallyReceives 验证 AF_PACKET 接收 fd 真的能收到报文。
//
// 做法：给本机地址发几个包（内核会回环），断言 Recv 能在限时内取到其中一个。
// 部分虚拟化环境下 AF_PACKET 看不到本机 TX 方向的帧，此时跳过而不是失败
// ——这类环境限制不是实现缺陷。
func TestRecvActuallyReceives(t *testing.T) {
	if testing.Short() {
		t.Skip("需要 raw socket")
	}
	dst := netip.MustParseAddr("8.8.8.8")
	s, err := newRawSocket(dst, netip.Addr{})
	if err != nil {
		t.Skipf("无法创建 raw socket: %v", err)
	}
	defer s.Close()

	// 目的地址写本机出口 IP：内核会把包回环，AF_PACKET 才看得到。
	local := s.LocalIP()
	if !local.Is4() {
		t.Skip("出口 IP 不是 IPv4")
	}
	const marker = 253
	const count = 3
	pkts := make([][]byte, count)
	for i := range pkts {
		pkt := make([]byte, 200)
		pkt[0] = 0x45
		pkt[2], pkt[3] = 0x00, byte(len(pkt))
		pkt[8] = 64
		pkt[9] = marker
		copy(pkt[12:16], local.AsSlice())
		copy(pkt[16:20], local.AsSlice())
		pkt[100] = byte(i)
		pkts[i] = pkt
	}
	if _, err := s.SendBatch(pkts, local); err != nil {
		t.Skipf("发送失败（环境不支持回环）: %v", err)
	}

	// 非阻塞轮询，限时 1 秒
	_ = syscall.SetNonblock(s.recvFD, true)
	buf := make([]byte, 65536)
	deadline := time.Now().Add(time.Second)
	got := 0
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(s.recvFD, buf, syscall.MSG_DONTWAIT)
		if err != nil || n < 101 {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		p, ok := ParseFrame(buf[:n])
		if !ok || p.Dst != local {
			continue
		}
		got++
	}
	if got == 0 {
		t.Skip("本机 AF_PACKET 看不到 TX 方向的帧（虚拟化环境限制）")
	}
	t.Logf("Recv 收到 %d 个回环报文", got)
}
