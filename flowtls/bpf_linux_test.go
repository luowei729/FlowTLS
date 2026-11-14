//go:build linux

package flowtls

import (
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"
	"unsafe"
)


// requireTXCapture 先确认本机 AF_PACKET 能看到自己的出向包。
//
// 这个前置步骤是必须的：虚拟化环境（本项目开发机即是）里 AF_PACKET
// 收不到 TX 方向的帧，所有过滤器测试都会「收到 0 个包」而误报失败。
func requireTXCapture(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("需要 raw socket")
	}
	dst := netip.MustParseAddr("8.8.8.8")
	s, err := newRawSocket(dst, netip.Addr{}, false)
	if err != nil {
		t.Skipf("无法创建 raw socket: %v", err)
	}
	defer s.Close()
	_ = syscall.SetNonblock(s.recvFD, true)

	const dstPort = 65529
	pkt := make([]byte, 60)
	pkt[0] = 0x45
	pkt[2], pkt[3] = 0x00, byte(len(pkt))
	pkt[8] = 64
	pkt[9] = 6
	src := s.LocalIP.As4()
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst.AsSlice())
	pkt[20], pkt[21] = 0x30, 0x39
	pkt[22], pkt[23] = byte(dstPort>>8), byte(dstPort&0xFF)
	pkt[32] = 0x50
	pkt[33] = 0x18
	for i := 0; i < 3; i++ {
		_ = s.Send(pkt, dst)
	}
	buf := make([]byte, recvBufSize)
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(s.recvFD, buf, syscall.MSG_DONTWAIT)
		if err != nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		if p, ok := ParseFrame(buf[:n]); ok && p.DstPort == dstPort {
			return // 环境支持
		}
	}
	t.Skip("本机 AF_PACKET 看不到出向包（虚拟化环境限制），无法验证 BPF")
}

// attachFilter 是测试用的 BPF 附加器，与 rawSocket.SetPortFilter 的实现
// 保持逐字节一致，方便隔离验证「附加方式」与「过滤逻辑」哪一环出问题。
func attachFilter(t *testing.T, fd int, prog []syscall.SockFilter) error {
	t.Helper()
	fprog := &syscall.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(fd), uintptr(syscall.SOL_SOCKET), uintptr(syscall.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(fprog)), unsafe.Sizeof(*fprog), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// TestBPFPassAllKeepsPackets 验证「无条件放行」的 BPF 不会弄丢报文。
//
// 这条测试是 2026-11-14 那次事故的回归防线：把 accept 的返回值写成
// 0xFFFFFFFF 时，内核按 int 解释成 -1，**所有包被判为丢弃**，
// 而 setsockopt 仍返回成功——现象是「隧道一个包都收不到、日志无异常」。
func TestBPFPassAllKeepsPackets(t *testing.T) {
	requireTXCapture(t)
	pkts := captureWithFilter(t, []syscall.SockFilter{
		{Code: syscall.BPF_RET | syscall.BPF_K, K: 0x00040000},
	})
	if pkts == 0 {
		t.Fatal("无条件放行的 BPF 之后一个包都收不到——" +
			"检查 accept 返回值是否为负数（0xFFFFFFFF 会被当 -1）")
	}
	t.Logf("收到 %d 个包", pkts)
}

// TestBPFDropAllDropsPackets 反向验证：ret 0 确实会丢包。
// 没有这条，「放行测试通过」不能证明过滤器真的生效（可能压根没附加）。
func TestBPFDropAllDropsPackets(t *testing.T) {
	requireTXCapture(t)
	pkts := captureWithFilter(t, []syscall.SockFilter{
		{Code: syscall.BPF_RET | syscall.BPF_K, K: 0},
	})
	if pkts != 0 {
		t.Fatalf("ret 0 的过滤器之后仍收到 %d 个包，说明过滤器未生效", pkts)
	}
}

// TestBPFPortFilterKeepsMatchingTraffic 验证真实的端口过滤器
// 能放行我们的出向报文（dst port 就是这里指定的端口）。
func TestBPFPortFilterKeepsMatchingTraffic(t *testing.T) {
	requireTXCapture(t)
	// 用一个「一定不会与真实服务冲突」的端口，但报文本身是发往
	// 外部地址的普通 IP 包；BPF 只看 dst port 字段。
	const port = 65530
	pkts := captureWithFilter(t, portFilterProg(port, false))
	if pkts == 0 {
		t.Fatal("端口过滤器把匹配的报文也丢了")
	}
}

// TestBPFPortFilterDropsOtherTraffic 验证端口过滤器会丢弃不匹配的报文。
func TestBPFPortFilterDropsOtherTraffic(t *testing.T) {
	requireTXCapture(t)
	const port = 65530
	// 过滤器只放行 443（不是我们要发的 65530），所以应当一个都收不到。
	pkts := captureWithFilter(t, portFilterProg(443, false))
	if pkts != 0 {
		t.Fatalf("端口过滤器未拦截不匹配的报文（收到 %d 个）", pkts)
	}
}

// portFilterProg 与 rawSocket.SetPortFilter 里的程序等价，
// rawDest 为 true 时用原始目的端口字段（测试用，逻辑相同）。
func portFilterProg(localPort uint16, rawDest bool) []syscall.SockFilter {
	_ = rawDest
	return []syscall.SockFilter{
		{Code: syscall.BPF_LD | syscall.BPF_H | syscall.BPF_ABS, K: 12},
		{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, Jt: 10, Jf: 0, K: 0x8100},
		{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, Jt: 0, Jf: 8, K: 0x0800},
		{Code: syscall.BPF_LD | syscall.BPF_B | syscall.BPF_ABS, K: 23},
		{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, Jt: 0, Jf: 6, K: 6},
		{Code: syscall.BPF_LD | syscall.BPF_B | syscall.BPF_ABS, K: 14},
		{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, Jt: 0, Jf: 4, K: 0x45},
		{Code: syscall.BPF_LD | syscall.BPF_H | syscall.BPF_ABS, K: 20},
		{Code: syscall.BPF_JMP | syscall.BPF_JSET | syscall.BPF_K, Jt: 2, Jf: 0, K: 0x1FFF},
		{Code: syscall.BPF_LD | syscall.BPF_H | syscall.BPF_ABS, K: 36},
		{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, Jt: 1, Jf: 0, K: uint32(localPort)},
		{Code: syscall.BPF_RET | syscall.BPF_K, K: 0},
		{Code: syscall.BPF_RET | syscall.BPF_K, K: 0x00040000},
	}
}

// captureWithFilter 建一个绑在出口网卡上的 AF_PACKET socket，附加给定过滤器，
// 然后自己发一个 TCP 报文到外部地址，返回在 500ms 内收到的属于该流的包数。
//
// 为什么能收到自己的出向包：AF_PACKET 的 tap 在 dev_queue_xmit 之后同样会
// 看到本机发出的帧（tcpdump 就是这么工作的）。
func captureWithFilter(t *testing.T, prog []syscall.SockFilter) int {
	t.Helper()
	dst := netip.MustParseAddr("8.8.8.8")

	// 复用生产代码的 socket 创建逻辑（含出口网卡/源地址探测）。
	s, err := newRawSocket(dst, netip.Addr{}, false)
	if err != nil {
		t.Skipf("无法创建 raw socket: %v", err)
	}
	defer s.Close()

	if err := attachFilter(t, s.recvFD, prog); err != nil {
		t.Fatalf("附加 BPF 失败: %v", err)
	}
	// 非阻塞，便于限时轮询。
	_ = syscall.SetNonblock(s.recvFD, true)

	// 构造一个发往 65530 端口的 TCP 报文（内容不重要，BPF 只看头部）。
	const dstPort = 65530
	pkt := make([]byte, 60)
	pkt[0] = 0x45
	pkt[2], pkt[3] = 0x00, byte(len(pkt))
	pkt[8] = 64
	pkt[9] = 6 // TCP
	src := s.LocalIP.As4()
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst.AsSlice())
	pkt[20], pkt[21] = 0x30, 0x39       // sport 12345
	pkt[22], pkt[23] = byte(dstPort>>8), byte(dstPort&0xFF)
	pkt[32] = 0x50                      // data offset 20
	pkt[33] = 0x18                      // PSH|ACK

	// 连发几个，降低单包丢失导致的误判。
	for i := 0; i < 3; i++ {
		if err := s.Send(pkt, dst); err != nil {
			t.Skipf("发送失败（环境不支持）: %v", err)
		}
	}

	buf := make([]byte, recvBufSize)
	deadline := time.Now().Add(500 * time.Millisecond)
	got := 0
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(s.recvFD, buf, syscall.MSG_DONTWAIT)
		if err != nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		p, ok := ParseFrame(buf[:n])
		if !ok || p.DstPort != dstPort {
			continue
		}
		got++
	}
	return got
}

// 确保 os 被引用（部分平台分支下上面只用 t.Skip）。
var _ = os.Getpid
