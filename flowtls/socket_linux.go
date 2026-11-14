//go:build linux

package flowtls

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
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
	sendFD int
	// rawFD 是 IPPROTO_RAW 回退 fd，**即使 AF_PACKET 创建成功也保留**。
	//
	// 用途：目的地址是本机地址时（联调回环），必须交给内核路由走 lo。
	// AF_PACKET 会把包直接发到默认路由网卡（物理链路），目的 IP 是本机时包一去不回。
	// 生产环境（两机互联）永远走 AF_PACKET，不受影响。
	rawFD    int
	isPacket bool // sendFD 是否 AF_PACKET 模式
	ifindex  int
	// sendNote 是发送路径上值得运维知道的调整（例如配置源地址不可用被替换）。
	// 空字符串表示一切按配置走。
	sendNote string
	// nextHopMAC 是下一跳 MAC。
	//
	// AF_PACKET/SOCK_DGRAM 让内核帮我们补以太网头，**但内核不会替我们做 ARP**：
	// 不给目的 MAC 就会发成全零地址，包在网关直接被丢
	// （表现为客户端一直停在「等待 SYN-ACK」）。
	// 所以启动时从邻居表取一次网关 MAC，之后固定复用：所有包都发给同一个下一跳。
	nextHopMAC [6]byte
	// recvFD 是收包 fd。
	recvFD int
	// truncRecv 统计因缓冲不足被内核截断丢弃的报文数。
	//
	// 这类丢包不会体现在 QUIC 的 lost 统计里（它死在收包缓冲），
	// 是「握手偶发丢失 / 吞吐减半但 lost=0」的典型成因。
	truncRecv atomic.Uint64
	// LocalIP 是本机出口 IP，构造 IP 头时作为源地址
	LocalIP netip.Addr
	// portFilter 记录已附加 BPF 过滤器的本端端口，0 表示未附加。
	// 只用于 SendMode 日志，便于确认「内核侧过滤是否真的生效」。
	portFilter uint16
}

// newRawSocket 创建收发 socket。
// dst 用于探测出口 IP 与出口网卡；服务端可传任意外部地址。
// local 有效且真的配在本机网卡上时用它作为源 IP；
// 否则退回内核探测到的出口地址（NAT 云主机写公网地址就属于这种情况，
// 详见下面源地址选择一段的注释）。
//
// bindRecv 控制接收 fd 是否绑定到出口网卡：**只有客户端该传 true**，
// 服务端必须保持不绑定（见下方注释与 DEVTIPS 63）。
func newRawSocket(dst netip.Addr, local netip.Addr, bindRecv bool) (*rawSocket, error) {
	if !dst.Is4() {
		return nil, ErrPlatformUnsupported
	}
	// ---- 源地址选择：配置值必须真的配在本机网卡上 ----
	//
	// 为什么不能无条件信任配置里的 local_ip：
	//
	// NAT 型云主机（Oracle Cloud 等）的网卡只有内网地址，公网地址由网关做 1:1
	// 映射。这种机器上出向包的源地址**必须等于网卡上的内网地址**：网关把它
	// SNAT 成公网地址后，对端看到的才是公网 IP。
	// 如果把公网地址手工写进 IP 头，包会以「源=公网地址、从内网侧送出」的形态
	// 撞上网关的反欺骗检查，被**静默丢弃**：服务端日志一切正常、抓包能看到
	// SYN-ACK 确实发出去了，客户端却一个包都收不到，表现就是「握手超时 / 吞吐为 0」。
	//
	// 实测对比（同一台 Oracle ARM 机器）：
	//   - 用 IPPROTO_RAW 发：内核会把源地址回填成出接口地址（10.0.0.10），所
	//     以「配公网地址」看起来也能工作——但那是内核在兜底，不是配置生效；
	//   - 用 AF_PACKET 发：不经内核 IP 层，公网源地址原样上线 → 被网关丢弃。
	// 两者失败与成功的现象完全一样，光看日志分不出来，所以这里统一收敛成
	// 「只在本机确实持有该地址时才用配置值」，并把替换动作记进 SendMode 日志。
	localIP := local
	var sendNote string
	if !localIP.IsValid() {
		probed, err := localIPFor(dst)
		if err != nil {
			return nil, fmt.Errorf("探测出口 IP 失败: %w", err)
		}
		localIP = probed
	} else if !localHasAddr(localIP) {
		// 配置值不在本机任何网卡上：典型就是 NAT 云主机上写了公网地址。
		// 退回内核探测到的出口地址，不然包会在线上被网关默默丢掉。
		probed, err := localIPFor(dst)
		if err == nil && probed != localIP {
			sendNote = fmt.Sprintf(
				"配置的 local_ip %s 不在本机网卡上（NAT 云主机的公网地址），已改用出口地址 %s 发包",
				localIP, probed)
			localIP = probed
		} else {
			sendNote = fmt.Sprintf(
				"配置的 local_ip %s 不在本机网卡上，且出口地址探测失败，仍按配置值发包", localIP)
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

	// ---- 发送 fd：服务端默认 AF_PACKET，客户端默认 IPPROTO_RAW ----
	//
	// **发送路径的选择直接决定吞吐**（实测，新加坡 1 核 ARM 服务端）：
	//
	//	IPPROTO_RAW  → Go↔Go 5 MB/s，cwnd 卡在 1.2~1.7MB
	//	AF_PACKET    → Go↔Go **21 MB/s**，cwnd 涨到 4.7MB
	//
	// 原因与 Rust `socket.rs` 的注释完全一致：IPPROTO_RAW + IP_HDRINCL 每包
	// 都要走内核的完整 IP 层（路由查找、conntrack、netfilter、qdisc），
	// 1 核 ARM 上约 35µs/包，是高速率下的**第一瓶颈**。
	// AF_PACKET 把帧直接交给驱动，只做一次 ARP。
	//
	// **为什么客户端仍然默认 RAW**：家用/办公网络的 NAT 设备对
	// 「没有 conntrack 状态却凭空出现的 TCP 包」更挑剔，AF_PACKET 旁路
	// conntrack 可能让回包被网关丢弃（DEVTIPS 86 的教训）。客户端的
	// 上行主要是纯 ACK，包量小，RAW 的 syscall 成本不是瓶颈。
	//
	// 覆盖方式：`FLOWTLS_AF_PACKET=1` 强制开启，`=0` 强制关闭。
	usePacket := !bindRecv // 服务端（bindRecv=false）默认 AF_PACKET
	if v := os.Getenv("FLOWTLS_AF_PACKET"); v != "" {
		usePacket = v == "1"
	}
	sendFD := -1
	isPacket := false
	if usePacket && ifindex > 0 && nextHop != ([6]byte{}) {
		// **protocol 必须传 0，不能传 ETH_P_IP。**
		//
		// AF_PACKET 的第三个参数（protocol）决定 socket 是否**注册接收**
		// 该类型的帧。传 ETH_P_IP 会让这个「发送专用」socket 同时把
		// 整机所有 IPv4 包复制进自己的接收队列——而我们从不去读它。
		//
		// 实测后果（2026-11-14，新加坡 ARM 服务端跑 1 小时后）：
		//   /proc/net/packet 显示该 socket 的 Rmem = 33554816（32MB，已满）
		//   即堆了 32MB 无人读取的包；队列满后内核为**每个包**尝试入队、
		//   发现超限、丢弃、计数——纯浪费；同时每个包多一次内存拷贝。
		//   表现为伪 TCP 握手从 80ms 恶化到 240ms、QUIC min_rtt 从 72ms
		//   涨到 260ms~1.4s，而链路 ICMP / 内核 TCP 全部正常。
		//
		// protocol=0 时 socket 不加入任何 ptype 的接收链，
		// 但 sendto 仍可工作（sendto 的 sockaddr_ll 里已显式带 sll_protocol）。
		fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, 0)
		if err == nil {
			sll := &syscall.SockaddrLinklayer{
				Protocol: htons(syscall.ETH_P_IP),
				Ifindex:  ifindex,
			}
			if err = syscall.Bind(fd, sll); err == nil {
				// 绕过 qdisc：少一次入队/出队和软中断唤醒。
				//
				// **默认关闭，必须显式用环境变量开启**。原因：实测在 e1000/QEMU 一类
				// 虚拟网卡上，PACKET_QDISC_BYPASS 会让报文被驱动**静默丢弃**——
				// sendto 返回成功、tcpdump 抓不到任何包，现象就是「握手永远超时」。
				// virtio_net 上则正常（Rust 版在服务器上验证过）。
				// 运行时无法可靠判定驱动能力，所以正确性优先：默认走 qdisc 排队，
				// 确认环境支持（物理网卡/ virtio）时用 FLOWTLS_QDISC_BYPASS=1 开启。
				if os.Getenv("FLOWTLS_QDISC_BYPASS") == "1" {
					_ = syscall.SetsockoptInt(fd, syscall.SOL_PACKET, packetQdiscBypass, 1)
				}
				// 发送缓冲调大，减少突发时的 ENOBUFS
				_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 8*1024*1024)
				// 接收缓冲压到最小：这个 fd 只用于发送（protocol=0 已不注册接收）。
				// 万一将来内核行为变化导致它开始收包，小缓冲能让浪费有界，
				// 而不是像实测那样悄悄堆到 32MB。
				_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 2048)
				// **必须是阻塞 fd（带发送超时兜底）**，绝不能用 O_NONBLOCK。
				//
				// 2026-11-14 实测事故：这里曾是 `SetNonblock(fd, true)`，
				// 而 Send() 把 EAGAIN 当成「UDP 语义」静默 return nil。
				// 后果是**伪 TCP 层的包被本地静默丢弃**，而 QUIC 完全不知道
				// （它以为包已上线），于是：
				//   - SYN-ACK 丢失 → 客户端 1s 后重传 SYN（抓包实测握手 851ms，
				//     而链路 RTT 只有 73ms）；
				//   - 数据包丢失 → 只能等 PTO 重传，`lost=` 恒为 0（因为丢在本机），
				//     表现为 RTT 206~435ms、吞吐掉到 1/3。
				// Rust 版的 AF_PACKET fd 是阻塞的（没有 fcntl O_NONBLOCK），
				// 所以它没有这个问题——这是「移植时多写了一句优化」的典型。
				//
				// 用 SO_SNDTIMEO 而不是完全阻塞：驱动/队列极端拥塞时，
				// 阻塞最多 200ms 就会返回 EAGAIN，由 Send 侧重试，
				// 不会把收包协程永久卡死。
				_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO,
					&syscall.Timeval{Sec: 0, Usec: 200000})
				sendFD = fd
				isPacket = true
			} else {
				_ = syscall.Close(fd)
			}
		}
	}

	// ---- 回退：AF_INET / SOCK_RAW / IPPROTO_RAW ----
	// **总是创建**（即使 AF_PACKET 成功）：本机地址目标需要内核路由引导到 lo。
	rawFD, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		if sendFD >= 0 {
			_ = syscall.Close(sendFD)
		}
		return nil, os.NewSyscallError("socket", err)
	}
	// 开启 IP_HDRINCL，告诉内核「IP 头我自己写」
	if err = syscall.SetsockoptInt(rawFD, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		_ = syscall.Close(rawFD)
		if sendFD >= 0 {
			_ = syscall.Close(sendFD)
		}
		return nil, os.NewSyscallError("setsockopt IP_HDRINCL", err)
	}
	_ = syscall.SetsockoptInt(rawFD, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4*1024*1024)
	// **rawFD 刻意不设 O_NONBLOCK**。
	//
	// 实测（本机 -> 新加坡）：非阻塞的 IPPROTO_RAW socket 上 sendto 返回成功，
	// 但 SYN / SYN-ACK 这类首个握手包会被内核异步丢弃——对端永远收不到，
	// 表现为「握手超时」；同机同网关的 Rust 版用阻塞 fd 则正常。
	// 不阻塞收包线程的语义改由单次发送的 MSG_DONTWAIT 保证（见 Send）。
	if sendFD < 0 {
		// AF_PACKET 不可用：发送全部走回退 fd
		sendFD = rawFD
	}

	// ---- 接收 fd：AF_PACKET / SOCK_RAW / ETH_P_IP ----
	recvFD, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))
	if err != nil {
		_ = syscall.Close(sendFD)
		_ = syscall.Close(rawFD)
		return nil, os.NewSyscallError("socket AF_PACKET", err)
	}
	// 客户端（bindRecv=true）绑定出口网卡。
	//
	// 原因：不绑定时 AF_PACKET 会收到**所有网卡**的流量。开发机/服务器上
	// lo 与 docker 的回环流量很大（SSH 隧道、IDE 网关等），实测会把 packet
	// socket 的接收队列淹没，握手期的 SYN-ACK 被内核挤丢，表现为「同机同网关
	// 下 Rust 客户端能连、Go 客户端永远握手超时」。
	//
	// **服务端绝不能绑**（DEVTIPS 63）：服务端要同时收多张网卡和 lo 的包。
	// 这个判断不能靠「dst 是不是监听地址」——服务端为了探测出口网卡与网关 MAC，
	// 传进来的是 8.8.8.8（一个必然走默认路由的外部地址），拿它当条件会把
	// 服务端也绑到物理网卡，回环联调的 SYN 从此收不到（实测就是这样回归的）。
	// 另外目的地址就是本机时（联调回环）也不绑，否则同样收不到 lo 的包。
	if bindRecv && dst.IsValid() && !dst.IsUnspecified() && dst != localIP && ifindex > 0 {
		_ = syscall.Bind(recvFD, &syscall.SockaddrLinklayer{
			Protocol: htons(syscall.ETH_P_IP),
			Ifindex:  ifindex,
		})
	}
	// 接收缓冲调大，减少高速流量下的丢包
	_ = syscall.SetsockoptInt(recvFD, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 8*1024*1024)

	rawOpened.Add(1)
	return &rawSocket{
		sendFD:     sendFD,
		rawFD:      rawFD,
		isPacket:   isPacket,
		ifindex:    ifindex,
		nextHopMAC: nextHop,
		recvFD:     recvFD,
		LocalIP:    localIP,
		sendNote:   sendNote,
	}, nil
}

// SendMode 返回发送路径的简短描述，供上层打进启动日志。
//
// 为什么要把这个暴露出来：这一层的「RAW 还是 AF_PACKET」「源地址到底用了谁」
// 直接决定链路能不能通，而两者的失败现象完全一样（对端收不到包）。
// 之前排查时只能靠 strace + 双端抓包反推，代价极高。
func (s *rawSocket) SendMode() string {
	mode := "ipproto_raw"
	if s.isPacket {
		mode = "af_packet"
	}
	// 把「内核侧是否只收本端端口」也带上：这一条直接决定高负载下
	// 收包延迟，而失败时现象与链路丢包一模一样（只能抓包区分）。
	if s.portFilter != 0 {
		mode += fmt.Sprintf("; bpf_dport=%d", s.portFilter)
	} else {
		mode += "; bpf=off(收包侧会处理整机流量)"
	}
	// **fd 存活数**：泄漏自检。格式 `raws=存活/累计创建`。
	// 客户端正常情况下存活恒为 1；若持续增长，说明某条重连路径没关 socket，
	// 此时 RTT 会随泄漏数量线性恶化（泄漏的接收 fd 仍在复制整机流量）。
	live, total := RawSocketStats()
	mode += fmt.Sprintf("; raws=%d/%d", live, total)
	if s.sendNote != "" {
		return mode + "; " + s.sendNote
	}
	return mode
}

// localHasAddr 判断地址是否真的配置在本机某个接口上。
func localHasAddr(target netip.Addr) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		cidr, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(cidr.IP)
		if ok && ip.Unmap() == target {
			return true
		}
	}
	return false
}

// htons 把主机序的 16 位常量转成网络序（AF_PACKET 的 protocol 字段要求）。
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Close 关闭全部 fd。
func (s *rawSocket) Close() error {
	var firstErr error
	// 幂等：重复调用直接返回。两个效果：
	//   1. 防止同一 fd 被 close 两次（repeat close 可能命中内核刚复用的 fd）；
	//   2. 让存活计数准确（close 两次会让 live 变成负数）。
	if s.recvFD < 0 {
		return nil
	}
	rawClosed.Add(1)
	// 必须先保存原值再清字段：默认 RAW 模式下 sendFD 与 rawFD 是同一个 fd，
	// 早期写法先把 sendFD 置 -1 再比较 rawFD != sendFD，两个值永远不等，
	// 导致同一 fd 被 close 两次。第二次可能关掉内核刚复用给别的对象的 fd，
	// 后果是失败重连后整个进程的网络状态错乱（实测：首次握手失败后再也连不上）。
	sendFD, rawFD := s.sendFD, s.rawFD
	s.sendFD, s.rawFD = -1, -1
	if sendFD >= 0 {
		if err := syscall.Close(sendFD); err != nil {
			firstErr = err
		}
	}
	if rawFD >= 0 && rawFD != sendFD {
		if err := syscall.Close(rawFD); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.recvFD >= 0 {
		if err := syscall.Close(s.recvFD); err != nil && firstErr == nil {
			firstErr = err
		}
		s.recvFD = -1
	}
	return firstErr
}

// sendTarget 按目的地址选择发送 fd 与地址格式。
//
// 规则只有一条额外的特例：**目的地址等于本机源 IP 时走 IPPROTO_RAW**。
// AF_PACKET 会把帧直接交给默认路由网卡（物理链路），目的 IP 是本机时
// 包一去不回（联调回环用例全部超时）；IPPROTO_RAW 交给内核路由，
// 本机地址会自动走 lo。生产环境（两机互联）永远走 AF_PACKET。
//
// 返回的 packetMode 表示应使用 sockaddr_ll 还是 sockaddr_in。
func (s *rawSocket) sendTarget(dst netip.Addr) (fd int, packetMode bool, err error) {
	if !dst.Is4() {
		return -1, false, ErrPlatformUnsupported
	}
	if dst == s.LocalIP && s.rawFD >= 0 {
		return s.rawFD, false, nil
	}
	if s.isPacket {
		return s.sendFD, true, nil
	}
	return s.sendFD, false, nil
}

// destSockaddr 构造发送用的目的地址（两种 fd 各有一套规则）。
func (s *rawSocket) destSockaddr(dst netip.Addr, packetMode bool) (syscall.Sockaddr, error) {
	if packetMode {
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

// sendFlags 返回单次发送应使用的 flags。
//
// **一律返回 0（阻塞语义），绝不能用 MSG_DONTWAIT。**
//
// 历史：早期把 RAW 发送设成 MSG_DONTWAIT，是为了「不让收包协程卡在 sendto 上」
// （recvLoop 里会直接发纯 ACK）。配套地，Send 又把 EAGAIN 当 UDP 语义丢弃
// （return nil）。上公网之后这条组合变成灾难：
//   - 发送队列一满，ACK 被**本地静默丢掉**，日志里一个错都看不到了；
//   - 服务端等不到确认 → PTO 重传 → RTT 估计从 89ms 虚高到 213ms；
//   - BBR 带宽估计随 RTT 一起崩，吞吐从 10MB/s 掉到 3~4MB/s。
//   - 回环测试完全看不出来（本地没有发送队列压力），所以当时误判为「已追平 Rust」。
//
// 现在所有数据面发送都收敛到 flushLoop 单协程（WriteTo 与 sendPureACK 都先入队），
// recvLoop 不再直接 sendto，所以阻塞不会卡住收包：队列满时在内核里排队
// 就是最正确的背压（Rust 版也是阻塞 fd + flags=0，实测不丢包）。
//
// 保留 packetMode 参数是为了不改调用点：将来若 AF_PACKET 与 RAW 需要不同标志，
// 只需改这一处。
func (s *rawSocket) sendFlags(packetMode bool) int {
	return 0
}

// Send 发送一个完整的 IPv4 报文（不含以太网头）。
//
// ### 为什么允许在这里阻塞
//
// 阻塞发送本身不是问题，**在哪个协程里阻塞才是问题**。
// 数据面（QUIC 包与纯 ACK）全部经 enqueueLocked 入队，由唯一的 flushLoop
// 发送；recvLoop 不再直接调到这里，所以就算 sendto 在内核队列里等几毫秒，
// 收包也不会停。握手阶段的 SYN / SYN-ACK / ClientHello 和 Close 的 FIN 确实
// 在业务协程里直发，但它们都是单包、对端不在发送高峰，阻塞时间可忽略。
//
// ### 为什么不能再丢包
//
// 伪造 TCP 层**没有重传**（它只是外观），丢一个 ACK 就得等对端 PTO 重传，
// 代价是一个 RTT；丢一个数据包则直接拉高 RTT 估计并让 BBR 降速。
// 内核队列满时的正确做法是「等」而不是「丢」：背压会一路传回 quic-go 的
// pacing，它自然会把发送速率调下来，不会造成任何丢包。
//
// EAGAIN/ENOBUFS 分支保留作为防御（比如 AF_PACKET 非阻塞模式），但正常运行
// 不应该命中；一旦命中就是丢包，必须能在统计里看到（所以不再默默 return nil）。
func (s *rawSocket) Send(pkt []byte, dst netip.Addr) error {
	// 协议只支持 IPv4：AF_PACKET 分支不经过内核路由，不会自己拒绝 IPv6，
	// 必须在这里显式拦。否则上层会把「发往 IPv6 地址的 IPv4 报文」当成成功。
	fd, packetMode, err := s.sendTarget(dst)
	if err != nil {
		return err
	}
	sa, err := s.destSockaddr(dst, packetMode)
	if err != nil {
		return err
	}
	// **绝不能静默丢弃**。这里的调用方是握手包（SYN / SYN-ACK /
	// ClientHello）与 FIN——伪 TCP 层没有重传，丢一个 SYN-ACK 就要等
	// 客户端重传 SYN（1 秒），丢一个 FIN 会让连接悬挂。
	//
	// 早期写法把 EAGAIN/ENOBUFS 直接 return nil（「UDP 语义」），
	// 在 AF_PACKET 非阻塞 fd 上这会静默丢掉握手包：抓包实测握手 851ms。
	// 现在 fd 是阻塞 + SO_SNDTIMEO，EAGAIN 只会在极端拥塞时出现，
	// 这里再重试几次，仍失败则**上报错误**（由调用方计数/记录）。
	const maxRetry = 5
	for attempt := 0; ; attempt++ {
		err = syscall.Sendto(fd, pkt, 0, sa)
		if err == nil {
			return nil
		}
		if attempt < maxRetry &&
			(errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) ||
				errors.Is(err, syscall.ENOBUFS)) {
			// 队列暂时没空间：让出 CPU 后重试。
			time.Sleep(200 * time.Microsecond)
			continue
		}
		return os.NewSyscallError("sendto", err)
	}
}

// SendBatch 用 sendmmsg 一次系统调用发送多个报文（同目的地址）。
//
// ### 为什么这是本层最关键的优化
//
// Rust 版 `faketcp/socket.rs` 的注释：
// 「实测单包 sendto 在 1 核 ARM 上约 40~50µs/包（进程 76% CPU 落在内核态），
// 11197 pps 就把 CPU 打满。sendmmsg 一次最多发 32 个包，系统调用次数
// 按 32 倍下降，直接对应内核态时间的 32 倍缩减。」
//
// Go 版实测（本机 amd64，AF_PACKET + QDISC_BYPASS）：
//
//	单包 sendto   : 3.265µs/包
//	sendmmsg ×32  : 1.287µs/包   ← 降低 2.5 倍
//
// 注意只有 2.5 倍而不是 32 倍：内核仍要逐包处理 skb，sendmmsg 省掉的是
// 用户态/内核态切换与 syscall 入口开销。但在 1 核 ARM + 真实网卡的服务器上，
// 这两项正是大头（Go 实测 94µs/包中约 45µs 是 syscall）。
//
// ### 返回值的语义
//
// 返回成功递交的报文数。内核发送队列满（ENOBUFS）时可能小于 len(pkts)，
// 调用方应把余下的留到下一轮。已经发出部分时**不报错**——
// 报错会让上层把已发的包重发一遍，造成重复。
func (s *rawSocket) SendBatch(pkts [][]byte, dst netip.Addr) (int, error) {
	// 同 Send：AF_PACKET 分支不校验地址族，必须显式拦住 IPv6。
	if _, _, err := s.sendTarget(dst); err != nil {
		return 0, err
	}
	total := 0
	for len(pkts) > 0 {
		n := len(pkts)
		if n > maxSendBatch {
			n = maxSendBatch
		}
		got, err := s.sendmmsg(pkts[:n], dst)
		total += got
		if err != nil {
			// 已经发出部分就直接返回成功计数，避免上层把已发的包再发一遍
			if total > 0 {
				return total, nil
			}
			return 0, err
		}
		// 内核没全收下：qdisc/驱动队列满，剩下的留给下一轮
		// （QUIC 会重传，不会丢数据）
		if got < n {
			break
		}
		pkts = pkts[n:]
	}
	return total, nil
}

// maxSendBatch 是一次 sendmmsg 最多带多少个报文。
//
// 32 是折中（与 Rust 一致）：太小收益不明显，太大在突发时会一次性
// 占满 qdisc 队列反而增加丢包。
const maxSendBatch = 32

// sysSendmmsg 返回当前架构上 sendmmsg 的 syscall 编号。
//
// 标准库 syscall 包的 SYS_* 常量不能直接用：amd64 的
// zsysnum_linux_amd64.go 只生成到 303（对应 4.x 内核时代的表），
// 而 sendmmsg 是 307；arm64 上倒是有（269）。
// 因此这里按架构硬编码，取值来自各架构的 unistd.h。
func sysSendmmsg() uintptr {
	switch runtime.GOARCH {
	case "amd64":
		return 307
	case "arm64", "riscv64", "loong64":
		return 269
	case "arm":
		return 374
	case "386":
		return 345
	case "ppc64", "ppc64le":
		return 349
	case "s390x":
		return 358
	default:
		return 0
	}
}

// msgHdr 是内核 struct msghdr 的精确布局。
//
// 不能直接用 syscall.Msghdr：它带 cgo padding 字段，且字段顺序按
// 编译器对齐规则排列，用它构造 sendmmsg 的数组容易踩到偏移错误。
// 这里按内核 uapi 定义逐字段复刻（所有 64 位架构一致）。
type msgHdr struct {
	Name       uintptr // void *msg_name
	Namelen    uint32  // socklen_t msg_namelen
	_          [4]byte // 对齐填充
	Iov        uintptr // struct iovec *msg_iov
	Iovlen     uint64  // size_t msg_iovlen
	Control    uintptr // void *msg_control
	Controllen uint64  // size_t msg_controllen
	Flags      int32   // int msg_flags
	_          [4]byte // 对齐填充
}

// mmsgHdr 是 struct mmsghdr：msghdr + 内核实际发出的字节数。
type mmsgHdr struct {
	Hdr    msgHdr
	MsgLen uint32
	_      [4]byte // 对齐到 8 字节（mmsghdr 共 64 字节）
}

// iovec 是 struct iovec。
type iovec struct {
	Base uintptr
	Len  uint64
}

// rawSockaddrLL 是内核 struct sockaddr_ll 的精确布局（20 字节）。
//
// **不能用 syscall.SockaddrLinklayer 代替**，两个原因都是致命的：
//
//  1. 它的字段顺序不是 family 开头（第一个字段是 Protocol），
//     直接传给内核会把协议号当成地址族，调用返回 EAFNOSUPPORT；
//  2. 它末尾带一个 `raw` 字段（RawSockaddrLinklayer），
//     unsafe.Sizeof 得到 48 而内核只认 20。msg_namelen 传大了，
//     内核会读到结构体之外的内存。
//
// 实测后果：sendmmsg 每次返回错误，而如果调用方吞掉错误，
// 报文就全部静默丢失——表现是「TCP 握手成功但 QUIC 永远超时」。
type rawSockaddrLL struct {
	Family   uint16 // sll_family = AF_PACKET
	Protocol uint16 // sll_protocol = htons(ETH_P_IP)
	Ifindex  int32  // sll_ifindex
	Hatype   uint16 // sll_hatype
	Pkttype  uint8  // sll_pkttype
	Halen    uint8  // sll_halen
	Addr     [8]byte
}

// rawSockaddrIn 是内核 struct sockaddr_in 的精确布局（16 字节）。
//
// 同样不能用 syscall.SockaddrInet4：它的第一个字段是 Port，family 在末尾的
// `raw` 里，直接传会得到 EAFNOSUPPORT。
type rawSockaddrIn struct {
	Family uint16 // sin_family = AF_INET
	Port   uint16 // sin_port（sendto 时可为 0）
	Addr   [4]byte
	Zero   [8]byte
}

// sendmmsg 一次系统调用发送多个报文（同一个目的地址）。
//
// 出错时**必须**回退到逐包 sendto：sendmmsg 的失败模式（EINVAL、
// EAFNOSUPPORT、结构体布局不匹配）会让所有报文一起丢，
// 而 QUIC 会把「一个包都没到」当成链路故障，握手永远超时。
// 逐包发送至少能保证功能正确，只是慢一点。
func (s *rawSocket) sendmmsg(pkts [][]byte, dst netip.Addr) (int, error) {
	trap := sysSendmmsg()
	if trap == 0 {
		return s.sendLoop(pkts, dst)
	}

	// 按目的地址选 fd 与地址格式（本机地址回环走 IPPROTO_RAW）。
	fd, packetMode, err := s.sendTarget(dst)
	if err != nil {
		return 0, err
	}

	// 目的地址必须按内核布局重建，见 rawSockaddrLL / rawSockaddrIn 的注释。
	var (
		namePtr uintptr
		nameLen uint32
		sll     rawSockaddrLL
		sin     rawSockaddrIn
	)
	if packetMode {
		sll = rawSockaddrLL{
			Family:   syscall.AF_PACKET,
			Protocol: htons(syscall.ETH_P_IP),
			Ifindex:  int32(s.ifindex),
			Halen:    6,
		}
		copy(sll.Addr[:6], s.nextHopMAC[:])
		namePtr = uintptr(unsafe.Pointer(&sll))
		nameLen = uint32(unsafe.Sizeof(sll))
	} else {
		if !dst.Is4() {
			return 0, ErrPlatformUnsupported
		}
		sin = rawSockaddrIn{Family: syscall.AF_INET, Addr: dst.As4()}
		namePtr = uintptr(unsafe.Pointer(&sin))
		nameLen = uint32(unsafe.Sizeof(sin))
	}

	// iovec 与 mmsghdr 都放栈上：批量发送本身不能引入分配，
	// 否则省下的 syscall 开销又被 malloc 吃掉。
	var iovs [maxSendBatch]iovec
	var msgs [maxSendBatch]mmsgHdr

	n := len(pkts)
	if n > maxSendBatch {
		n = maxSendBatch
	}
	for i := 0; i < n; i++ {
		if len(pkts[i]) > 0 {
			iovs[i].Base = uintptr(unsafe.Pointer(&pkts[i][0]))
		}
		iovs[i].Len = uint64(len(pkts[i]))
		msgs[i].Hdr.Name = namePtr
		msgs[i].Hdr.Namelen = nameLen
		msgs[i].Hdr.Iov = uintptr(unsafe.Pointer(&iovs[i]))
		msgs[i].Hdr.Iovlen = 1
		msgs[i].Hdr.Control = 0
		msgs[i].Hdr.Controllen = 0
		msgs[i].Hdr.Flags = 0
		msgs[i].MsgLen = 0
	}

	// 与 RecvBatch 同样的重试理由：Go 的异步抢占会让 sendmmsg 返回
	// ERESTARTSYS(512)。发送侧更敏感——一次打断就丢一批报文，
	// 而伪 TCP 层没有重传（QUIC 只能等 PTO）。
	var (
		r0    uintptr
		errno syscall.Errno
	)
	for {
		r0, _, errno = syscall.Syscall6(trap,
			uintptr(fd),
			uintptr(unsafe.Pointer(&msgs[0])),
			uintptr(n),
			uintptr(s.sendFlags(packetMode)),
			0, 0)
		if errno == 0 || !isInterrupted(errno) {
			break
		}
	}
	if errno != 0 {
		// 关键兜底：不能把错误往上抛就完事，也不能静默丢弃。
		//
		// **r0 > 0 时不能回退**：那说明前 r0 个已经发出去了，
		// 再走 sendLoop 会把它们重发一遍（对端看到重复序号，
		// 且浪费带宽）。只把剩余部分交给退化路径。
		if r0 > 0 {
			return int(r0), nil
		}
		// 一个都没发出：退化成逐包 sendto，功能优先。
		return s.sendLoop(pkts, dst)
	}
	return int(r0), nil
}

// sendLoop 是 sendmmsg 不可用时的退化路径：逐包 sendto。
func (s *rawSocket) sendLoop(pkts [][]byte, dst netip.Addr) (int, error) {
	fd, packetMode, err := s.sendTarget(dst)
	if err != nil {
		return 0, err
	}
	sa, err := s.destSockaddr(dst, packetMode)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, pkt := range pkts {
		// 与 Send 同样的理由：EAGAIN/ENOBUFS 要**重试**而不是丢弃。
		// 这里是数据面，丢一个包在伪 TCP 上等于永久丢（QUIC 以为已发出，
		// lost 统计看不到），只能等 PTO 重传，直接抬高 RTT。
		var serr error
		for attempt := 0; attempt < 5; attempt++ {
			serr = syscall.Sendto(fd, pkt, 0, sa)
			if serr == nil {
				break
			}
			if !errors.Is(serr, syscall.EAGAIN) && !errors.Is(serr, syscall.EWOULDBLOCK) &&
				!errors.Is(serr, syscall.ENOBUFS) {
				break
			}
			time.Sleep(200 * time.Microsecond)
		}
		if serr != nil {
			if sent > 0 {
				// 已发出部分就直接返回成功计数，避免上层把已发的包再发一遍
				return sent, nil
			}
			return 0, os.NewSyscallError("sendto", serr)
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

// maxRecvBatch 是一次 recvmmsg 最多收多少个报文。
//
// 与 maxSendBatch 分开定义：收包侧的包数由网卡队列深度决定，
// 32 足以在一次 syscall 里排空 AF_PACKET 的接收队列（默认 rmem 8MB）。
const maxRecvBatch = 32

// erestartSys 是内核内部的「系统调用应当被重启」返回码。
//
// 它**不在**用户空间的 errno 表里（标准 errno 最大到 ~133），
// 所以 syscall 包的常量里没有它，但内核会把它返回给用户态：
// 当进程在系统调用中被信号打断、且该调用需要重启时使用。
//
// Go 运行时的**异步抢占**正是这种情形：GC/调度器向线程发送 SIGURG，
// 阻塞在 `recvmmsg` / `sendmmsg` 上的线程就会拿到 512。实测单测里
// 偶发 `RecvBatch 失败: recvmmsg: errno 512`，生产环境在 GC 繁忙时同理。
//
// 正确做法是**原样重试**：内核没有消费任何数据，重试是安全的。
// 若不重试，收包协程会空转一轮（包仍在内核队列，不丢），
// 但批次被打断会让延迟抖动；发送侧更严重——一次打断就丢一批报文。
const erestartSys = syscall.Errno(512)

// isInterrupted 判断一次 syscall 是否只是被信号打断（可安全重试）。
func isInterrupted(errno syscall.Errno) bool {
	return errno == syscall.EINTR || errno == erestartSys
}

// 全进程的 raw socket 存活计数，用于**泄漏自检**。
//
// 为什么要做这个：rawSocket 内含 3 个 fd，其中接收 fd 带 16MB SO_RCVBUF。
// 一旦某条路径忘记关闭，泄漏的接收 fd 仍会把整机所有 IPv4 包复制进
// 自己的队列——N 个 socket 就是 N 倍内存带宽与 CPU 开销。
// 实测（2026-11-14）客户端因 ownsRaw 缺省为 false，36 次重连后泄漏
// 36 个 socket（约 576MB 内核内存），RTT 从 72ms 恶化到 800ms~1.4s，
// 而链路本身完全正常。这种故障在应用层日志里看不到任何异常，
// 只能靠 `cat /proc/net/packet` 反推，代价极高。
//
// 有了这两个计数，`SendMode()` 里能直接显示 `raws=2/37`（存活/累计创建），
// 存活数持续增长即泄漏。
var (
	rawOpened atomic.Int64
	rawClosed atomic.Int64
)

// RawSocketStats 返回当前存活的 rawSocket 数与累计创建数。
//
// 存活数 = 已创建 - 已关闭。正常情况下客户端恒为 1（一条通道一个），
// 服务端恒为 1（Listener 独占）。持续增长说明有会话没关 socket。
func RawSocketStats() (live, total int64) {
	total = rawOpened.Load()
	return total - rawClosed.Load(), total
}

// recvBufSize 是每个接收缓冲的大小。
//
// **必须覆盖 GRO 聚合包，而且 GRO 可以超过 64KB。**
//
// 网卡开启 GRO（generic receive offload，默认开启）后，内核把同一 TCP 流的
// 多个段合并成一个 skb 再交给 AF_PACKET。IP 头的 total_len 是 16 位（最大
// 65535），但 **skb 本身可以是 GRO_MAX_SIZE（部分内核为 8×64KB）**。
// 缓冲小于实际包长时 `recvmmsg` 会截断并丢弃多余部分、**不返回错误**，
// 包就静默消失了——QUIC 以为已送达（`lost=` 恒为 0），只能靠 PTO 重传。
//
// 实测（2026-11-14，新加坡 ARM）：64KB 缓冲时服务端日志反复出现
// 「报文被截断」，对应现象是伪 TCP 握手 473~682ms、QUIC 握手 3.7s、
// 首包延迟 610ms，而链路 RTT 只有 73ms。
//
// 内存代价：maxRecvBatch(32) × 256KB = 8MB（每端一份）。
// 相比「静默丢包导致的 RTT 虚高」这个代价完全值得。
const recvBufSize = 256 * 1024

// SetPortFilter 在内核侧只保留「目的端口 == 本端端口」的 TCP 包。
//
// ### 为什么必须在核内过滤
//
// 服务端的 AF_PACKET 收包 fd 刻意不绑定网卡（要同时收 lo 与多网卡，
// 见 newRawSocket 的 bindRecv 注释）。代价是它收到**整机所有 IP 包**：
// 实测某台跑着 5 个 Docker 容器的服务器，3 秒内除隧道包外还有约 7000 个
// 无关包（veth / bridge / lo 上的容器流量），是隧道包的 10 倍以上。
//
// 这些包会全部被拷进用户态（现在是 32 × 64KB 的批量缓冲），
// 每个都要跑一遍 ParseFrame 再按端口丢弃。在 1 核 ARM 上，
// 收包协程因此长期处于「处理别人的包」状态，我们的 SYN 要排队几百毫秒
// 才被处理——实测抓包 SYN → SYN-ACK 356ms，而链路 RTT 只有 73ms。
//
// ### 过滤器内容（经典 BPF，13 条指令）
//
//	ethertype == IPv4        （否则丢弃）
//	ip.proto  == TCP         （否则丢弃）
//	ip.ihl    == 5           （无 IP 选项，否则丢弃）
//	无分片                    （否则丢弃）
//	tcp.dport == localPort   （否则丢弃）
//	VLAN 包保守放行           （交给用户态 ParseFrame，它支持 802.1Q）
//
// 附加失败不阻断启动：退化为「内核不过滤、用户态丢弃」的旧行为。
// 环境变量 FLOWTLS_NO_BPF=1 可显式关闭。
func (s *rawSocket) SetPortFilter(localPort uint16) {
	// **默认关闭。** 需要显式 `FLOWTLS_BPF=1` 才启用。
	//
	// 理由（2026-11-14 完整实测）：
	//   - 两次真链路部署都导致「隧道一个包都收不到」，而 setsockopt 返回成功；
	//   - 本机无法复现/验证：这台虚拟化机器上 AF_PACKET 看不到自己的出向包
	//     （基准测试 TestBPFBaselineNoFilter 收到 0 个），
	//     所以「过滤器写对了没」在本地根本测不出来。
	//
	// 这是一个纯优化（减少收包协程处理整机无关流量的开销），
	// 而关掉它时实测已达到目标指标（min_rtt 71ms、单流 14~24 MB/s），
	// 因此不值得为它承担「整条隧道不通」的风险。
	// 保留完整实现与 BPF 单测，待有真实环境能验证时再启用。
	if os.Getenv("FLOWTLS_BPF") != "1" {
		return
	}
	if os.Getenv("FLOWTLS_NO_BPF") == "1" || s.recvFD < 0 {
		return
	}
	// 布局见上面的注释；jt/jf 是相对下一条指令的偏移。
	prog := []syscall.SockFilter{
		{Code: syscall.BPF_LD | syscall.BPF_H | syscall.BPF_ABS, K: 12},                          // A = ethertype
		{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, Jt: 10, Jf: 0, K: 0x8100},        // VLAN → accept
		{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, Jt: 0, Jf: 8, K: 0x0800},         // 非 IPv4 → drop
		{Code: syscall.BPF_LD | syscall.BPF_B | syscall.BPF_ABS, K: 23},                            // A = ip.proto
		{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, Jt: 0, Jf: 6, K: 6},              // 非 TCP → drop
		{Code: syscall.BPF_LD | syscall.BPF_B | syscall.BPF_ABS, K: 14},                            // A = ihl/ver
		{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, Jt: 0, Jf: 4, K: 0x45},           // 有 IP 选项 → drop
		{Code: syscall.BPF_LD | syscall.BPF_H | syscall.BPF_ABS, K: 20},                            // A = frag_off
		{Code: syscall.BPF_JMP | syscall.BPF_JSET | syscall.BPF_K, Jt: 2, Jf: 0, K: 0x1FFF},        // 分片 → drop
		{Code: syscall.BPF_LD | syscall.BPF_H | syscall.BPF_ABS, K: 36},                            // A = tcp.dport
		{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, Jt: 1, Jf: 0, K: uint32(localPort)},
		{Code: syscall.BPF_RET | syscall.BPF_K, K: 0},          // drop
		{Code: syscall.BPF_RET | syscall.BPF_K, K: 0x00040000}, // accept
		// **accept 的返回值必须是正数且足够大，不能写 0xFFFFFFFF。**
		// 内核把 BPF 返回值当 `int` 用：0xFFFFFFFF 即 -1，
		// 会被判为「丢弃」——实测加上这条过滤器后 socket 一个包都收不到，
		// 而 setsockopt 返回成功，极难定位。tcpdump 生成的代码用的是
		// 0x00040000（262144），照抄它。
	}
	fprog := &syscall.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(s.recvFD),
		uintptr(syscall.SOL_SOCKET),
		uintptr(syscall.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(fprog)),
		unsafe.Sizeof(*fprog),
		0)
	if errno != 0 {
		// 不阻断启动：用户态仍会按端口丢弃，只是多花 CPU。
		log.Printf("flowtls: 附加 BPF 端口过滤器失败（%v），"+
			"收包侧将处理整机流量（高负载下会拉高延迟）", errno)
		return
	}
	s.portFilter = localPort
}

// sysRecvmmsg 返回当前架构上 recvmmsg 的 syscall 编号。
//
// 与 sendmmsg 同样的问题：标准库 amd64 的 SYS_* 表只到 303。
// recvmmsg 是 299（amd64）/ 243（arm64），取值来自各架构 unistd.h。
func sysRecvmmsg() uintptr {
	switch runtime.GOARCH {
	case "amd64":
		return 299
	case "arm64", "riscv64", "loong64":
		return 243
	case "arm":
		return 365
	case "386":
		return 337
	case "ppc64", "ppc64le":
		return 343
	case "s390x":
		return 367
	default:
		return 0
	}
}

// RecvBatch 一次系统调用接收多个报文，把每个包的长度写入 lens。
//
// ### 为什么收包侧也要批量
//
// 发送侧的 sendmmsg 只解决了「发」的一半成本。服务端 1 核实测
// 吞吐 87Mbps 时 `top` 显示 **47% 时间在内核态（sy）**，其中收包占大头：
// 下行 7700 pps 会换回约 3850 pps 的纯 ACK，每个 ACK 都要一次
// recvfrom + 一次协议栈处理。批量收包把 syscall 次数降到 1/32。
//
// ### 与 sendmmsg 的差异
//
// 收包不需要目的地址（AF_PACKET 的 recvfrom 也不返回有用的 msg_name），
// 所以 msg_name 填 0、namelen 填 0。每个包用独立缓冲——不能用同一个缓冲
// 循环收，因为上层要在处理完前一直持有它（ParseFrame 的切片直接指向缓冲）。
//
// 返回 0 且 err 为 nil 表示对端关闭（不会发生在 AF_PACKET 上，防御性处理）。
func (s *rawSocket) RecvBatch(bufs [][]byte, lens []int) (int, error) {
	trap := sysRecvmmsg()
	n := len(bufs)
	if n > maxRecvBatch {
		n = maxRecvBatch
	}
	if n == 0 {
		return 0, nil
	}
	if trap == 0 {
		// 未知架构：退化为逐包 recvfrom
		for i := 0; i < n; i++ {
			got, err := s.Recv(bufs[i])
			if err != nil {
				if i > 0 {
					return i, nil
				}
				return 0, err
			}
			lens[i] = got
		}
		return n, nil
	}

	var iovs [maxRecvBatch]iovec
	var msgs [maxRecvBatch]mmsgHdr
	for i := 0; i < n; i++ {
		if len(bufs[i]) > 0 {
			iovs[i].Base = uintptr(unsafe.Pointer(&bufs[i][0]))
		}
		iovs[i].Len = uint64(len(bufs[i]))
		msgs[i].Hdr.Name = 0
		msgs[i].Hdr.Namelen = 0
		msgs[i].Hdr.Iov = uintptr(unsafe.Pointer(&iovs[i]))
		msgs[i].Hdr.Iovlen = 1
		msgs[i].Hdr.Control = 0
		msgs[i].Hdr.Controllen = 0
		msgs[i].Hdr.Flags = 0
		msgs[i].MsgLen = 0
	}

	// flags=0：阻塞模式。内核收到至少一个包才返回，
	// 有多个时一次全部填满（这正是我们要的批量效果）。
	//
	// **必须对 EINTR / ERESTARTSYS 重试**：Go 的异步抢占会向线程发
	// SIGURG，阻塞中的 recvmmsg 会返回 ERESTARTSYS(512)。
	// 内核没有消费任何数据，重试完全安全；不重试会让收包协程白等一轮，
	// 表现为延迟抖动（单测里就是这样偶发失败的）。
	var (
		r0    uintptr
		errno syscall.Errno
	)
	for {
		r0, _, errno = syscall.Syscall6(trap,
			uintptr(s.recvFD),
			uintptr(unsafe.Pointer(&msgs[0])),
			uintptr(n),
			0, // flags
			0, 0)
		if errno == 0 || !isInterrupted(errno) {
			break
		}
	}
	if errno != 0 {
		return 0, os.NewSyscallError("recvmmsg", errno)
	}
	got := int(r0)
	for i := 0; i < got; i++ {
		// MSG_TRUNC 表示报文比 iov 缓冲长，**内核已把多余部分丢弃**。
		// 这类丢包在任何 QUIC 统计里都看不到（它死在收包缓冲里），
		// 所以必须在这里显式计数——否则「SYN-ACK 丢了、lost=0」
		// 这种矛盾现象又要靠抓包反推（2026-11-14 踩过两次）。
		if msgs[i].Hdr.Flags&syscall.MSG_TRUNC != 0 {
			if s.truncRecv.Add(1) == 1 {
				log.Printf("flowtls: 收包缓冲不足，报文被截断（GRO 聚合包超过 %d 字节）"+
					"——已丢弃，请检查 recvBufSize", len(bufs[0]))
			}
		}
		lens[i] = int(msgs[i].MsgLen)
	}
	return got, nil
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
	// /proc/net/arp 的 Flags 列是 "0x2" / "0x0" 形式（带前缀），
	// 而 /proc/net/route 的 Gateway 是无前缀的 8 位十六进制。
	// 必须兼容两种：早期版本没有剥离前缀，parseHexUint32("0x2") 遇到 'x' 报错，
	// 导致 arpLookup 永远失败 -> resolveNeighborMAC 拿不到网关 MAC ->
	// AF_PACKET 发送 fd 创建不出来 -> 所有发送静默退化到 IPPROTO_RAW。
	// 后果：回环测试全绿，跨境链路上源 IP 是公网地址时包被内核直接丢弃（
	// SYN-ACK 发不出去、握手超时），源 IP 是内网时吞吐大幅下降。
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return 0, fmt.Errorf("空十六进制值")
	}
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
