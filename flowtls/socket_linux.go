//go:build linux

package flowtls

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"
)

// packetQdiscBypass 把发送直接交给驱动的 ndo_start_xmit，绕过 qdisc。
// syscall 包未导出该常量，按内核头文件取值 20。
// 队列满时直接丢包而不是排队——QUIC 会重传，排队反而把延迟和内存拖坏。
const packetQdiscBypass = 20

// rawSocket 是裸 socket 收发封装。
//
// 接收用 AF_PACKET：它在 netfilter 之前拿到报文，因此即使 iptables 把
// 这些包 DROP 掉（不让内核协议栈处理），我们依然能收到。
//
// 发送优先 AF_PACKET/SOCK_DGRAM：内核只按包里的 IP 头做 ARP，
// 直接把帧交给驱动，跳过 IP 层路由、netfilter OUTPUT 与 qdisc 排队。
// AF_PACKET 不可用时回退 IPPROTO_RAW。
//
// 只用标准库 syscall 而不是 x/sys/unix：sing-box 锁定的 x/sys 版本里
// Sendmmsg 等符号已变动，且其 go 指令会顶高整个模块的 Go 版本
// （sing-box 是 1.25.5）。标准库足够覆盖本层所需，且没有额外依赖。
type rawSocket struct {
	sendFD   int
	isPacket bool // 发送 fd 是否 AF_PACKET 模式
	ifindex  int
	// nextHopMAC 是下一跳 MAC。
	//
	// AF_PACKET/SOCK_DGRAM 让内核帮我们补以太网头，**但内核不会替我们做 ARP**：
	// 不给目的 MAC 就会发成全零地址，包在网关直接被丢
	// （表现为客户端一直停在「等待 SYN-ACK」）。
	// 所以启动时从邻居表取一次网关 MAC，之后固定复用：所有包都发给同一个下一跳。
	nextHopMAC [6]byte
	recvFD     int
	// LocalIP 是本机出口 IP，构造 IP 头时作为源地址
	LocalIP netip.Addr
}

// newRawSocket 创建收发 socket。
// dst 用于探测出口 IP 与出口网卡；服务端可传任意外部地址。
// local 有效时直接用它作为源 IP（服务端在 NAT 后面时必须显式指定）。
func newRawSocket(dst netip.Addr, local netip.Addr) (*rawSocket, error) {
	if !dst.Is4() {
		return nil, ErrPlatformUnsupported
	}
	localIP := local
	if !localIP.IsValid() {
		var err error
		localIP, err = localIPFor(dst)
		if err != nil {
			return nil, fmt.Errorf("探测出口 IP 失败: %w", err)
		}
	}

	ifindex := 0
	var nextHop [6]byte
	if route, err := defaultRoute(); err == nil {
		ifindex = route.ifindex
		if mac, ok := resolveNeighborMAC(route.gateway, dst, route.ifname); ok {
			nextHop = mac
		}
	}

	// ---- 发送 fd：优先 AF_PACKET / SOCK_DGRAM / ETH_P_IP ----
	// SOCK_DGRAM 模式下内核自己补以太网头并按 IP 头做 ARP，
	// 我们只管交出完整 IPv4 报文，比自己拼 14 字节以太网头更省事也更稳。
	sendFD := -1
	isPacket := false
	// 没有下一跳 MAC 时不能用 SOCK_DGRAM：内核补的以太网头目的地址会是全 0
	if ifindex > 0 && nextHop != ([6]byte{}) {
		fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(syscall.ETH_P_IP)))
		if err == nil {
			sll := &syscall.SockaddrLinklayer{
				Protocol: htons(syscall.ETH_P_IP),
				Ifindex:  ifindex,
			}
			if err = syscall.Bind(fd, sll); err == nil {
				// 绕过 qdisc：少一次入队/出队和软中断唤醒
				_ = syscall.SetsockoptInt(fd, syscall.SOL_PACKET, packetQdiscBypass, 1)
				// 发送缓冲调大，减少突发时的 ENOBUFS
				_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 8*1024*1024)
				sendFD = fd
				isPacket = true
			} else {
				_ = syscall.Close(fd)
			}
		}
	}

	// ---- 回退：AF_INET / SOCK_RAW / IPPROTO_RAW ----
	if sendFD < 0 {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			return nil, os.NewSyscallError("socket", err)
		}
		// 开启 IP_HDRINCL，告诉内核「IP 头我自己写」
		if err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
			_ = syscall.Close(fd)
			return nil, os.NewSyscallError("setsockopt IP_HDRINCL", err)
		}
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4*1024*1024)
		sendFD = fd
	}

	// ---- 接收 fd：AF_PACKET / SOCK_RAW / ETH_P_IP ----
	recvFD, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))
	if err != nil {
		_ = syscall.Close(sendFD)
		return nil, os.NewSyscallError("socket AF_PACKET", err)
	}
	// 不绑定特定网卡：服务端可能收多个网卡/回环，绑定 ifindex 会漏包。
	// 端口过滤交给上层逻辑，性能损失可忽略。
	_ = syscall.SetsockoptInt(recvFD, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 8*1024*1024)

	return &rawSocket{
		sendFD:     sendFD,
		isPacket:   isPacket,
		ifindex:    ifindex,
		nextHopMAC: nextHop,
		recvFD:     recvFD,
		LocalIP:    localIP,
	}, nil
}

// htons 把主机序的 16 位常量转成网络序（AF_PACKET 的 protocol 字段要求）。
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Close 关闭两个 fd。
func (s *rawSocket) Close() error {
	var firstErr error
	if s.sendFD >= 0 {
		if err := syscall.Close(s.sendFD); err != nil {
			firstErr = err
		}
		s.sendFD = -1
	}
	if s.recvFD >= 0 {
		if err := syscall.Close(s.recvFD); err != nil && firstErr == nil {
			firstErr = err
		}
		s.recvFD = -1
	}
	return firstErr
}

// destSockaddr 构造发送用的目的地址（两种 fd 各有一套规则）。
func (s *rawSocket) destSockaddr(dst netip.Addr) (syscall.Sockaddr, error) {
	if s.isPacket {
		sa := &syscall.SockaddrLinklayer{
			Protocol: htons(syscall.ETH_P_IP),
			Ifindex:  s.ifindex,
			Halen:    6,
		}
		copy(sa.Addr[:6], s.nextHopMAC[:])
		return sa, nil
	}
	if !dst.Is4() {
		return nil, ErrPlatformUnsupported
	}
	return &syscall.SockaddrInet4{Addr: dst.As4()}, nil
}

// Send 发送一个完整的 IPv4 报文（不含以太网头）。
func (s *rawSocket) Send(pkt []byte, dst netip.Addr) error {
	sa, err := s.destSockaddr(dst)
	if err != nil {
		return err
	}
	if err := syscall.Sendto(s.sendFD, pkt, 0, sa); err != nil {
		return os.NewSyscallError("sendto", err)
	}
	return nil
}

// SendBatch 依次发送多个报文。
//
// 标准库没有封装 sendmmsg，这里退化为循环 sendto：
// 正确性优先，批量优化留到性能阶段（需要引入带 build tag 的 syscall 封装）。
// 接口保持一致，替换实现不影响上层。
func (s *rawSocket) SendBatch(pkts [][]byte, dst netip.Addr) (int, error) {
	sa, err := s.destSockaddr(dst)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, pkt := range pkts {
		if err := syscall.Sendto(s.sendFD, pkt, 0, sa); err != nil {
			// 已发出部分就直接返回成功计数，避免上层把已发的包再发一遍
			if sent > 0 {
				return sent, nil
			}
			return 0, os.NewSyscallError("sendto", err)
		}
		sent++
	}
	return sent, nil
}

// Recv 阻塞接收一个以太网帧，返回实际长度。
func (s *rawSocket) Recv(buf []byte) (int, error) {
	n, _, err := syscall.Recvfrom(s.recvFD, buf, 0)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// defaultRouteInfo 是默认路由信息。
type defaultRouteInfo struct {
	ifindex int
	ifname  string
	gateway netip.Addr
}

// defaultRoute 取默认路由所在的网卡索引与网关。
//
// AF_PACKET 发送必须指定 ifindex，而服务端常处于 NAT 后面（本机地址 10.x、
// 出口是公网 IP），不能靠「接口地址等于 LocalIP」去找。直接读内核路由表
// 取默认路由那一块最可靠。
func defaultRoute() (defaultRouteInfo, error) {
	content, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return defaultRouteInfo{}, err
	}
	var best *defaultRouteInfo
	bestMetric := ^uint32(0)
	for _, line := range strings.Split(string(content), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 8 || f[1] != "00000000" {
			continue
		}
		metric, _ := parseUint32(f[6])
		// 网关字段是 8 位十六进制、主机字节序（小端），例如 0100000A → 10.0.0.1
		gw, err := parseHexUint32(f[2])
		if err != nil {
			continue
		}
		var gwOct [4]byte
		binary.LittleEndian.PutUint32(gwOct[:], gw)
		// 用 net.InterfaceByName 而不是 syscall.IfNametoindex：
		// 后者在这个 Go 版本的 syscall 包里已不导出。
		iface, err := net.InterfaceByName(f[0])
		if err != nil || iface.Index <= 0 {
			continue
		}
		if metric < bestMetric {
			bestMetric = metric
			best = &defaultRouteInfo{
				ifindex: iface.Index,
				ifname:  f[0],
				gateway: netip.AddrFrom4(gwOct),
			}
		}
	}
	if best == nil {
		return defaultRouteInfo{}, fmt.Errorf("无默认路由")
	}
	return *best, nil
}

func parseUint32(s string) (uint32, error) {
	var v uint32
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("非数字: %q", s)
		}
		v = v*10 + uint32(c-'0')
	}
	return v, nil
}

func parseHexUint32(s string) (uint32, error) {
	var v uint32
	for _, c := range s {
		var d uint32
		switch {
		case c >= '0' && c <= '9':
			d = uint32(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint32(c-'A') + 10
		default:
			return 0, fmt.Errorf("非十六进制: %q", s)
		}
		v = v<<4 | d
	}
	return v, nil
}

// resolveNeighborMAC 解析下一跳的 MAC 地址。
//
// 下一跳判定：目的 IP 与默认网关同网段直接用目的本身，否则走网关。
// 实际场景（家庭宽带 ↔ 云主机）几乎总是走网关。
// 邻居表里没有条目时先发一个 UDP 包触发内核 ARP，再轮询一会儿。
func resolveNeighborMAC(gateway, dst netip.Addr, ifname string) ([6]byte, bool) {
	var zero [6]byte
	if !gateway.Is4() || !dst.Is4() {
		return zero, false
	}
	g := gateway.As4()
	d := dst.As4()
	nextHop := gateway
	if g[0] == d[0] && g[1] == d[1] && g[2] == d[2] {
		nextHop = dst
	}
	if mac, ok := arpLookup(nextHop, ifname); ok {
		return mac, true
	}
	// 触发内核 ARP：UDP connect + 发一个字节，内核会解析邻居
	triggerARP(nextHop)
	// 最多等 500ms；ARP 通常 10ms 内回来
	for i := 0; i < 25; i++ {
		time.Sleep(20 * time.Millisecond)
		if mac, ok := arpLookup(nextHop, ifname); ok {
			return mac, true
		}
	}
	return zero, false
}

// arpLookup 从 /proc/net/arp 查指定 IP 的 MAC。
func arpLookup(ip netip.Addr, ifname string) ([6]byte, bool) {
	var zero [6]byte
	content, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return zero, false
	}
	// 格式：IP address  HW type  Flags  HW address  Mask  Device
	// Flags 0x2 表示 ATF_COM（已完成），0x0 是未完成
	for _, line := range strings.Split(string(content), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 6 || f[5] != ifname {
			continue
		}
		addr, err := netip.ParseAddr(f[0])
		if err != nil || addr != ip {
			continue
		}
		flags, err := parseHexUint32(f[2])
		if err != nil || flags&0x2 == 0 {
			return zero, false
		}
		parts := strings.Split(f[3], ":")
		if len(parts) != 6 {
			return zero, false
		}
		var mac [6]byte
		for i, p := range parts {
			v, err := parseHexUint32(p)
			if err != nil || v > 0xFF {
				return zero, false
			}
			mac[i] = byte(v)
		}
		return mac, true
	}
	return zero, false
}

// triggerARP 用 UDP 包触发内核做一次 ARP 解析（不关心是否送达）。
func triggerARP(target netip.Addr) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return
	}
	defer syscall.Close(fd)
	sa := &syscall.SockaddrInet4{Port: 9, Addr: target.As4()} // discard 端口
	_ = syscall.Sendto(fd, []byte{'x'}, 0, sa)
}

// localIPFor 通过一个临时 UDP socket 让内核选路，拿到出口 IP。
func localIPFor(dst netip.Addr) (netip.Addr, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return netip.Addr{}, err
	}
	defer syscall.Close(fd)
	// UDP connect 不会真的发包，只触发路由查询
	sa := &syscall.SockaddrInet4{Port: 443, Addr: dst.As4()}
	if err = syscall.Connect(fd, sa); err != nil {
		return netip.Addr{}, err
	}
	raw, err := syscall.Getsockname(fd)
	if err != nil {
		return netip.Addr{}, err
	}
	in, ok := raw.(*syscall.SockaddrInet4)
	if !ok {
		return netip.Addr{}, fmt.Errorf("意外的 sockaddr 类型 %T", raw)
	}
	return netip.AddrFrom4(in.Addr), nil
}
