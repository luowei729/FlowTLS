//go:build linux

package flowtls

// 本文件是 legacy-rust:src/faketcp/socket.rs 的逐函数翻译。
//
// 对应关系：
//
//	RawSocket::new_with_local      → newRawSocket
//	RawSocket::dest_addr           → (内联在 send / sendBatch 里)
//	RawSocket::send                → (*rawSocket).Send
//	RawSocket::send_batch          → (*rawSocket).SendBatch
//	RawSocket::recv                → (*rawSocket).Recv
//	impl Drop for RawSocket        → (*rawSocket).Close
//	default_route                  → defaultRoute
//	resolve_neighbor_mac           → resolveNeighborMAC
//	arp_lookup                     → arpLookup
//	trigger_arp                    → triggerARP
//	local_ip_for                   → localIPFor
//
// 只用标准库 syscall：sing-box 锁定的 x/sys 版本里 Sendmmsg 等符号已变动，
// 且它的 go 指令会顶高整个模块的 Go 版本。标准库足够覆盖本层所需。
//
// ## 一个必须知道的既有行为：本实现（与 Rust 一致）实际走 IPPROTO_RAW
//
// Rust 的 `arp_lookup` 用 `u32::from_str_radix(flags, 16)` 解析
// `/proc/net/arp` 的 Flags 列，而该列的实际内容是 **"0x2"（带前缀）**，
// 解析必然失败 → `next_hop_mac` 恒为全零 → `ifindex > 0 && next_hop_mac != [0;6]`
// 不成立 → **AF_PACKET 发送 fd 从未被创建**，所有发送都走 IPPROTO_RAW。
//
// 这解释了为什么 NAT 云主机在配置里写公网 IP 也能工作：IPPROTO_RAW 走内核
// 路由，内核会用出接口地址回填 `iph->saddr`，把公网地址换成了内网地址。
//
// 本移植**保留这个行为**（arpLookup 同样不剥 "0x" 前缀），原因：
//   1. 这是唯一在真实链路上验证过的路径；
//   2. 若启用 AF_PACKET，包里的源地址会保持配置值，在 NAT 云主机上会被
//      网关反欺骗静默丢弃（需要同时做「源地址必须在本机网卡上」的纠正）。
// 详见 PROJECT_PLAN.md §7 的说明。

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
// 发送优先 AF_PACKET/SOCK_DGRAM（跳过 IP 层路由、netfilter、qdisc），
// 不可用时回退 IPPROTO_RAW（见文件头说明：目前实际总是走回退路径）。
type rawSocket struct {
	sendFD int
	// sendIsPacket 表示 sendFD 是否为 AF_PACKET 模式
	// （决定 sendto 用 sockaddr_ll 还是 sockaddr_in）
	sendIsPacket bool
	// ifindex 是出口网卡索引，AF_PACKET 发送必须指定
	ifindex int
	// nextHopMAC 是下一跳 MAC。
	//
	// AF_PACKET/SOCK_DGRAM 只让内核帮我们加以太网头，**但内核不会替我们做 ARP**：
	// 不给目的 MAC 就会发成全零地址，包在网关直接被丢。
	nextHopMAC [6]byte
	recvFD     int
	// localIP 是本机出口 IP，构造 IP 头时作为源地址
	localIP netip.Addr
	// closed 保证 Close 幂等（Go 没有析构函数，Close 可能被多条路径调用）。
	closed atomic.Bool
	// truncated 统计被截断的报文数（should be 0）。
	//
	// 网卡 GRO 会把多个 TCP 段聚合成一个 skb，报文可以超过收包缓冲；
	// `recvfrom` 默认**静默截断**，包就无声无息地消失——
	// 而伪 TCP 层没有重传，现象只是「吞吐偏低 + 周期性」。
	// 必须靠 MSG_TRUNC 把真实长度拿回来才能发现。
	truncated atomic.Uint64
	truncLog  atomic.Bool
}

// newRawSocket 创建收发 socket（对应 Rust `RawSocket::new_with_local`）。
//
// dst 用于探测出口 IP 与出口网卡；服务端可传任意外部地址。
// local 是配置里显式指定的源 IP（为空时按路由探测）。
func newRawSocket(dst netip.Addr, local netip.Addr) (*rawSocket, error) {
	if !dst.Is4() {
		return nil, ErrPlatformUnsupported
	}
	// 优先用配置指定的源 IP，未指定时回退到路由探测。
	//
	// 注意：这里**不校验**该地址是否真的配在本机网卡上——与 Rust 一致。
	// 走 IPPROTO_RAW 时内核会用出接口地址回填 saddr，所以配置公网地址也能
	// 正常工作（见文件头说明）。
	localIP := local
	if !localIP.IsValid() {
		probed, err := localIPFor(dst)
		if err != nil {
			return nil, err
		}
		localIP = probed
	}

	// AF_PACKET 发送必须知道出口网卡；取默认路由那一块
	ifindex := 0
	var nextHop [6]byte
	if route, err := defaultRoute(); err == nil {
		ifindex = route.ifindex
		if mac, ok := resolveNeighborMAC(route.gateway, dst, route.ifname); ok {
			nextHop = mac
		}
	}

	sendFD := -1
	sendIsPacket := false
	// 没有下一跳 MAC 时不能用 SOCK_DGRAM：内核补的以太网头目的地址会是全 0。
	//
	// （当前 ARP 解析必然失败，因此这个分支不会进入；保留以与 Rust 一致。）
	if ifindex > 0 && nextHop != ([6]byte{}) {
		fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM,
			int(htons(syscall.ETH_P_IP)))
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
				sendIsPacket = true
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
		// **不加 O_NONBLOCK**：与 Rust 一致。
		// 非阻塞 + EAGAIN 静默丢弃会让握手包随机丢失（实测握手 851ms，
		// 而链路 RTT 只有 73ms），因为伪 TCP 层没有任何重传。
		sendFD = fd
	}

	// ---- 接收 fd：AF_PACKET / SOCK_RAW / ETH_P_IP ----
	recvFD, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW,
		int(htons(syscall.ETH_P_IP)))
	if err != nil {
		_ = syscall.Close(sendFD)
		return nil, os.NewSyscallError("socket AF_PACKET", err)
	}
	// 不绑定特定网卡：服务端可能收多个网卡/回环，绑定 ifindex 会漏包。
	// 端口过滤交给上层逻辑，性能损失可忽略。
	// 接收缓冲调大，减少高速流量下的丢包。
	_ = syscall.SetsockoptInt(recvFD, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 8*1024*1024)

	return &rawSocket{
		sendFD:       sendFD,
		sendIsPacket: sendIsPacket,
		ifindex:      ifindex,
		nextHopMAC:   nextHop,
		recvFD:       recvFD,
		localIP:      localIP,
	}, nil
}

// LocalIP 返回构造 IP 头时使用的源地址。
func (s *rawSocket) LocalIP() netip.Addr { return s.localIP }

// SendMode 返回发送路径描述，供上层打进启动日志。
//
// 这一层的「af_packet 还是 ipproto_raw」「源地址用了谁」直接决定链路能不能通，
// 而两者失败时的现象完全一样（对端都收不到包），所以必须能看到。
func (s *rawSocket) SendMode() string {
	mode := "ipproto_raw"
	if s.sendIsPacket {
		mode = "af_packet"
	}
	return fmt.Sprintf("%s; 源 IP=%s", mode, s.localIP)
}

// Close 关闭收发 fd（对应 Rust 的 `impl Drop for RawSocket`）。
//
// 幂等：Go 没有析构函数，客户端会话关闭与连接重建都可能调用到这里。
func (s *rawSocket) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
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

// htons 把主机序的 16 位常量转成网络序（AF_PACKET 的 protocol 字段要求）。
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// errSocketClosed 在 raw socket 已关闭后返回。
//
// 必须与真实发送失败区分：Close 与「收包协程仍在发纯 ACK」天然存在竞态，
// 而这属于正常关闭路径，不应该被当成链路故障计数/告警。
var errSocketClosed = errors.New("flowtls: raw socket 已关闭")

// Send 发送一个完整的 IPv4 报文（不含以太网头）。
//
// 对应 Rust `RawSocket::send`：flags 恒为 0（阻塞语义），与 Rust 完全一致。
// 失败原样上报，绝不静默丢弃——伪 TCP 层没有重传，丢一个 SYN-ACK 就要等
// 对端重传定时器。
func (s *rawSocket) Send(pkt []byte, dst netip.Addr) error {
	if s.closed.Load() || s.sendFD < 0 {
		return errSocketClosed
	}
	if !dst.Is4() {
		return ErrPlatformUnsupported
	}
	err := syscall.Sendto(s.sendFD, pkt, 0, s.destSockaddr(dst))
	if err != nil {
		return os.NewSyscallError("sendto", err)
	}
	return nil
}

// destSockaddr 构造发送用的目的地址（对应 Rust `dest_addr`）。
func (s *rawSocket) destSockaddr(dst netip.Addr) syscall.Sockaddr {
	if s.sendIsPacket {
		// 目的 MAC 必须显式给出，否则内核补的是全零以太网头
		sa := &syscall.SockaddrLinklayer{
			Protocol: htons(syscall.ETH_P_IP),
			Ifindex:  s.ifindex,
			Halen:    6,
		}
		copy(sa.Addr[:6], s.nextHopMAC[:])
		return sa
	}
	return &syscall.SockaddrInet4{Addr: dst.As4()}
}

// maxSendBatch 是一次 sendmmsg 最多带多少个报文（对应 Rust `MAX_BATCH`）。
//
// 32 是折中：太小收益不明显，太大在突发时会一次性占满 qdisc 队列反而增加丢包。
const maxSendBatch = 32

// SendBatch 批量发送多个完整 IPv4 报文（同目的 IP），一次系统调用。
//
// 对应 Rust `send_batch`。返回成功递交的报文数；内核发送队列满（ENOBUFS）时
// 可能小于 len(pkts)——**与原实现一致，不在这里重试**，余下的由 QUIC 下一轮
// 重传覆盖。
func (s *rawSocket) SendBatch(pkts [][]byte, dst netip.Addr) (int, error) {
	if len(pkts) == 0 {
		return 0, nil
	}
	if s.closed.Load() || s.sendFD < 0 {
		return 0, errSocketClosed
	}
	if !dst.Is4() {
		return 0, ErrPlatformUnsupported
	}

	trap := sysSendmmsg()
	if trap == 0 {
		// 未知架构：退化为逐包 sendto
		return s.sendLoop(pkts, dst)
	}

	// 目的地址必须按内核布局重建，见 rawSockaddrIn 的注释。
	var (
		namePtr uintptr
		nameLen uint32
		sll     rawSockaddrLL
		sin     rawSockaddrIn
	)
	if s.sendIsPacket {
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
		sin = rawSockaddrIn{Family: syscall.AF_INET, Addr: dst.As4()}
		namePtr = uintptr(unsafe.Pointer(&sin))
		nameLen = uint32(unsafe.Sizeof(sin))
	}

	// iovec 与 mmsghdr 都放栈上：批量发送本身不能引入分配，
	// 否则省下的 syscall 开销又被 malloc 吃掉。
	var iovs [maxSendBatch]iovec
	var msgs [maxSendBatch]mmsgHdr

	total := 0
	for len(pkts) > 0 {
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

		var (
			r0    uintptr
			errno syscall.Errno
		)
		for {
			r0, _, errno = syscall.Syscall6(trap,
				uintptr(s.sendFD),
				uintptr(unsafe.Pointer(&msgs[0])),
				uintptr(n), 0, 0, 0)
			// Go 的异步抢占会用 SIGURG 打断阻塞 syscall，返回 ERESTARTSYS(512)。
			// 内核没有消费任何数据，重试安全；不重试会静默丢一批报文。
			if errno == 0 || !isInterrupted(errno) {
				break
			}
		}
		if errno != 0 {
			// 已经发出部分就直接返回成功计数，避免上层把已发的包再发一遍
			if total > 0 {
				return total, nil
			}
			return 0, os.NewSyscallError("sendmmsg", errno)
		}
		sent := int(r0)
		total += sent
		// 内核没全收下：qdisc 队列满，剩下的留给下一轮（QUIC 会重传）
		if sent < n {
			break
		}
		pkts = pkts[n:]
	}
	return total, nil
}

// sendLoop 是 sendmmsg 不可用时的退化路径：逐包 sendto（对应 Rust 在
// sendmmsg 不可用时的行为，Go 侧仅用于未知架构）。
func (s *rawSocket) sendLoop(pkts [][]byte, dst netip.Addr) (int, error) {
	sa := s.destSockaddr(dst)
	sent := 0
	for _, pkt := range pkts {
		if err := syscall.Sendto(s.sendFD, pkt, 0, sa); err != nil {
			if sent > 0 {
				return sent, nil
			}
			return 0, os.NewSyscallError("sendto", err)
		}
		sent++
	}
	return sent, nil
}

// recvOnce 是一次收包尝试，由 flags 决定阻塞还是非阻塞。
//
// 阻塞与非阻塞两条路径共用它，避免 MSG_TRUNC 截断检测被抄成两份后走样——
// 截断检测一旦漏掉，表现是「丢包但 lost 计数为 0」，极难定位。
//
// 返回 ok=false 有两种含义（都不算错误）：
//   - 非阻塞调用时队列为空（EAGAIN）；
//   - 报文超过缓冲被截断，已计数并丢弃。
func (s *rawSocket) recvOnce(buf []byte, flags int) (int, bool, error) {
	for {
		// MSG_TRUNC 让 recvfrom 返回**真实**报文长度（脏数据仍然只有 len(buf)）
		// 这是唯一能发现静默截断的办法：默认行为下返回值会封顶到 len(buf)。
		n, _, err := syscall.Recvfrom(s.recvFD, buf, flags)
		if err == nil {
			if n > len(buf) {
				// 报文比缓冲还大：数据已被截断，解析必然失败。
				// 计数并丢弃，不返回错误（否则上层会刷日志）。
				s.truncated.Add(1)
				if s.truncLog.CompareAndSwap(false, true) {
					log.Printf("flowtls: 收包缓冲不足（%d 字节），报文被截断；"+
						"请把 recvBufSize 调到 ≥ 256KB", len(buf))
				}
				return 0, false, nil
			}
			return n, true, nil
		}
		// 被信号打断：内核没有消费数据，直接重试。
		if errors.Is(err, syscall.EINTR) || errors.Is(err, erestartSys) {
			continue
		}
		// 只在调用方明确要求非阻塞时才把 EAGAIN 当「队列空」。
		// 阻塞 fd 上出现 EAGAIN 属于异常（fd 被改成非阻塞了），不能吞掉。
		if flags&syscall.MSG_DONTWAIT != 0 && (err == syscall.EAGAIN || err == syscall.EWOULDBLOCK) {
			return 0, false, nil
		}
		return 0, false, err
	}
}

// Recv 阻塞接收一个以太网帧，返回实际长度（对应 Rust `RawSocket::recv`）。
// 调用方负责解析并过滤非目标流量。
func (s *rawSocket) Recv(buf []byte) (int, error) {
	n, ok, err := s.recvOnce(buf, syscall.MSG_TRUNC)
	if err != nil {
		return 0, err
	}
	if !ok {
		// 截断（已计数并打日志）：交给调用方丢弃这一帧。
		return 0, nil
	}
	return n, nil
}

// recvAvailable 非阻塞收一个帧：队列里没有包时立即返回 ok=false。
//
// 为什么需要它：Rust 的事件循环是「阻塞 recv 一个 + try_recv 再凑最多 256 个」，
// 一轮收包结束才做一次延迟确认判定。Go 侧要做出同样语义，就必须能在
// 「阻塞等到第一帧之后」把已到达的帧一次性取干——而不是每帧都跑一遍
// 完整的一轮逻辑（那样 256 帧会发出 128 个纯 ACK，回程包数凭空翻倍）。
//
// 注意 MSG_DONTWAIT 是**单次调用**的语义，不会改变 fd 的阻塞属性，
// 因此不影响 Recv 的阻塞行为，也不违反「发送 fd 必须阻塞」那条约束
// （那是 sendFD，不是 recvFD）。
func (s *rawSocket) recvAvailable(buf []byte) (int, bool, error) {
	return s.recvOnce(buf, syscall.MSG_TRUNC|syscall.MSG_DONTWAIT)
}

// erestartSys 是内核内部的「系统调用应当被重启」返回码。
//
// 它**不在**用户空间的 errno 表里（标准 errno 最大约 133），所以 syscall
// 包的常量里没有它，但内核会把它返回给用户态。Go 运行时的异步抢占
// （GC/调度器发 SIGURG）正是这种情形：实测偶发 `recvfrom: errno 512`。
const erestartSys = syscall.Errno(512)

// isInterrupted 判断一次 syscall 是否只是被信号打断（可安全重试）。
func isInterrupted(errno syscall.Errno) bool {
	return errno == syscall.EINTR || errno == erestartSys
}

// sysSendmmsg 返回当前架构上 sendmmsg 的 syscall 编号。
//
// 标准库 syscall 包的 SYS_* 常量不能直接用：amd64 的 zsysnum 只生成到 303，
// 而 sendmmsg 是 307；arm64 上倒是有（269）。取值来自各架构 unistd.h。
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
// 不能直接用 syscall.Msghdr：它带 cgo padding 字段，且字段顺序按编译器对齐
// 规则排列，用它构造 sendmmsg 的数组容易踩到偏移错误。
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
// 实测后果：sendmmsg 每次返回错误；若调用方吞掉错误，报文就全部静默丢失
// ——表现是「TCP 握手成功但 QUIC 永远超时」。
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

// defaultRouteInfo 是默认路由信息（对应 Rust `DefaultRoute`）。
type defaultRouteInfo struct {
	ifindex int
	ifname  string
	gateway netip.Addr
}

// defaultRoute 取默认路由所在的网卡索引与网关。
//
// AF_PACKET 发送必须指定 ifindex，而服务端常处于 NAT 后面（本机地址 10.x、
// 出口是公网 IP），不能靠「接口地址等于 local_ip」去找。直接读内核路由表
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
		// 格式：Iface Destination Gateway Flags RefCnt Use Metric Mask ...
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

// parseHexUint32 解析 8 位十六进制（/proc/net/route 的 Gateway 列，
// 无 0x 前缀）。**故意不剥前缀**：这是 Rust 的原始实现，见文件头说明。
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

// resolveNeighborMAC 解析下一跳的 MAC 地址（对应 Rust `resolve_neighbor_mac`）。
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
	// 目的与网关的 /24 是否相同（Rust 用前 3 字节的简单启发式）
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

// arpLookup 从 /proc/net/arp 查指定 IP 的 MAC（对应 Rust `arp_lookup`）。
//
// **这里的十六进制解析不剥 "0x" 前缀，是刻意与 Rust 保持一致**：
// /proc/net/arp 的 Flags 列实际是 "0x2"，所以本函数在 Linux 上**必然返回
// false**，进而让 newRawSocket 走 IPPROTO_RAW 回退路径。
//
// 这不是笔误，而是唯一在真实链路上验证过的行为（见文件头的详细说明）。
// 要启用 AF_PACKET，必须同时做两件事：
//  1. 剥前缀修正解析；
//  2. 保证 IP 头里的源地址是本机网卡地址（NAT 云主机不能填公网地址）。
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
		// 与 Rust 等价：from_str_radix("0x2", 16) 失败 → 整体返回 None
		flags, err := parseHexUint32(f[2])
		if err != nil {
			return zero, false
		}
		if flags&0x2 == 0 {
			continue
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

// localIPFor 通过一个临时 UDP socket 让内核选路，拿到出口 IP
// （对应 Rust `local_ip_for`）。
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
