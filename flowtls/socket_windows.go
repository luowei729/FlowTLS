//go:build windows && (amd64 || 386)

package flowtls

// Windows 的 `rawSocket` 实现（基于 WinDivert）。
//
// # 与 Linux 版的根本差异
//
//	Linux  AF_PACKET 是**被动复制**：内核照常处理同一份包，我们只是旁听。
//	       所以「不是我的包 → 忽略」是安全的。
//	Windows WinDivert 是**扣留**：内核看不到这个包，直到我们放行或丢弃。
//	       所以「不是我的包 → 必须重新注入」，否则包被销毁，
//	       同端口上的真实网站（masquerade）会静默失效。
//
// 这条差异贯穿本文件与 listener.go 的 `Reinject` 路径。
//
// # 未验证警告
//
// 本文件**没有在任何 Windows 主机上运行过**（开发环境无 Windows）。
// 通过交叉编译与静态检查 ≠ 能用。首次部署请按 PROJECT_PLAN.md §W9 验证。

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// wdivRxQueue 是内部收包队列深度。
//
// 与 Linux 的 `rxQueueDepth`（8192）不同：这里的队列只是
// 「WinDivert 读取协程 → recvLoop」的交接点，**不是用来吸收积压的**。
// 队列满时阻塞而不是丢弃——丢包会让 QUIC 误判为链路丢包（quinn/quic-go 都
// 认为下层是 UDP，丢掉的包既不会重传也不会被记入 lost）。
const wdivRxQueue = 512

// wdivPacket 是收包队列里的一项。
//
// 必须连同 addr 一起排队：**注入入向包时驱动要求 IfIdx 有效**（见 wdivAddr
// 的注释），而 IfIdx 只有驱动在 Recv 时给出。丢了它，重新注入的包会落到
// 不存在的接口上，表现为「伪装网站时好时坏」。
type wdivPacket struct {
	data []byte
	addr wdivAddr
}

// rawSocket 是一条 WinDivert 通道。
//
// 每个 rawSocket **只对应一个 WinDivert 句柄**：驱动保证「同一优先级只扣留
// 一次」，所以本句柄注入的包不会被自己再次扣留；拆成两个句柄会形成注入自环。
type rawSocket struct {
	handle *wdivHandle
	// localIP 是构造 IP 头时使用的源地址。
	//
	// 注意上层直接读字段（`s.raw.localIP`），不是方法，所以必须叫这个名字。
	localIP netip.Addr

	// rx 是收包队列（由内部读取协程填充）。
	rx chan wdivPacket
	// txBuf 是 SendBatch 的拼接缓冲（驱动要求包首尾相接）。
	//
	// 单协程使用：`txLoop` 是唯一的发送者，所以不需要加锁。
	txBuf []byte
	// txLens 与 txBuf 配套（仅供诊断，不参与发送）。
	txLens []int

	// pool 复用收包缓冲：每包一次分配在高速率下会被 GC 拖垮。
	pool sync.Pool

	closed atomic.Bool
	// closeOnce 保证 rx 只关一次（Close 可能被多条路径调用）。
	closeOnce sync.Once
	// rxStop 通知内部读取协程退出。
	rxStop chan struct{}
	// rxDone 在读取协程退出后关闭。
	rxDone chan struct{}

	// reinjectUnmatched 表示「未消费的包必须还给内核」。
	// Windows 恒为 true；Linux 为 false（AF_PACKET 是被动复制）。
	reinjectUnmatched bool

	// lastAddr 是最近一次 Recv 收到的包的地址（WINDIVERT_ADDRESS）。
	//
	// **它不是长期可用的状态**：只保证「Recv 返回后、下一次 Recv 之前」有效。
	// 调用方必须用 TakeFrameHandle 立刻取走，随帧一起交给处理方
	// （见 frameHandle 的注释）。直接读这个字段是 bug。
	lastAddr wdivAddr

	truncated atomic.Uint64
	truncLog  atomic.Bool
	logger    Logger
}

// newRawSocket 创建一条 WinDivert 通道。
//
// 参数语义见 socket_linux.go 的同名函数；Windows 上
// `wantAFPacket` 无意义（永远走 WinDivert），保留只为签名一致。
func newRawSocket(dst netip.Addr, local netip.Addr, logger Logger, wantAFPacket bool, role socketRole) (*rawSocket, error) {
	if !dst.Is4() {
		return nil, ErrPlatformUnsupported
	}
	logger = loggerOr(logger)

	// 源 IP：配置优先，否则按「临时 UDP socket 让内核选路」探测。
	//
	// 与 Linux 不同，这里**不做「是否在本机网卡上」的校验**：WinDivert 在 IP
	// 层注入，驱动不校验源地址是否属于本机（这是它能做伪造的核心能力）。
	// 也正因如此，Windows 服务端部署在 NAT 后面时需要用户自己填对 `local_ip`。
	localIP := local
	if !localIP.IsValid() {
		probed, err := localIPForWindows(dst)
		if err != nil {
			return nil, err
		}
		localIP = probed
	}

	filter := wdivServerInboundFilter(role.listenPort)
	if !role.server {
		// 必须带上服务端端口：只按本机目的端口过滤会把本机其它连接的回包
		// 一并扣下（见 wdivClientInboundFilter 的函数注释）。
		filter = wdivClientInboundFilter(localIP, role.sourcePort, role.serverPort)
	}

	// 诊断开关：FLOWTLS_WDIV_ANY=1 时把过滤器放宽成「所有入向 IPv4 TCP 包」。
	//
	// 用途只有一个：**区分「过滤器匹配不到」和「驱动收包机制坏了」**。
	// 两者现象完全相同（Recv 永远阻塞、什么都不报），没有这个开关就只能靠猜。
	// 放宽后若开始收到包，问题一定在过滤器的字段/取值上；仍收不到则说明
	// 问题在 STARTUP/flags/方向声明，与过滤器条件无关。
	//
	// 只在排查时用：放宽后每一帧都要过一遍用户态解析，且会被动看到本机
	// 全部 TCP 流量（我们只处理自己的端口，但代价是白烧 CPU）。
	diagnosticAny := false
	if v := os.Getenv("FLOWTLS_WDIV_ANY"); v == "1" {
		filter = wdivAnyInboundTCPFilter()
		diagnosticAny = true
	}

	handle, err := wdivOpen(filter)
	if err != nil {
		return nil, err
	}
	if diagnosticAny {
		logger.Warn("诊断模式 FLOWTLS_WDIV_ANY=1：过滤器已放宽为所有入向 TCP 包")
	}

	s := &rawSocket{
		handle:  handle,
		localIP: localIP,
		rx:      make(chan wdivPacket, wdivRxQueue),
		txBuf:   make([]byte, 0, maxSendBatch*wdivMTUMax),
		rxStop:  make(chan struct{}),
		rxDone:  make(chan struct{}),
		// **只有服务端需要重新注入**：服务端要跟同端口的伪装站共存，
		// 伪装站的流量被驱动器扣留，不还回去就静默失效；客户端不 bind 任何
		// 本地端口，扣留的包都是自己的，丢弃才是正确动作
		// （还给内核会让内核回 RST，反而把 NAT 映射拆掉）。
		reinjectUnmatched: role.server,
		logger:            logger,
	}
	s.pool.New = func() any {
		b := make([]byte, wdivMTUMax)
		return &b
	}
	go s.readLoop()
	return s, nil
}

// localIPForWindows 让内核选路拿到出口 IP。
//
// 用 UDP connect 触发路由查询（不会真的发包），再读本地地址。
// 这是 Go 标准库能力，Windows/Linux 通用——Linux 版用 syscall 是为了
// 避免额外开销，这里没必要优化。
func localIPForWindows(dst netip.Addr) (netip.Addr, error) {
	conn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, 443)))
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()
	la, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, errors.New("flowtls: 无法确定出口 IP")
	}
	addr, ok := netip.AddrFromSlice(la.IP)
	if !ok {
		return netip.Addr{}, errors.New("flowtls: 出口 IP 非法")
	}
	return addr.Unmap(), nil
}

// readLoop 是唯一的 WinDivert 读取协程。
//
// 为什么不直接在 Recv 里读：`WinDivertRecv` 是阻塞的（本绑定没有非阻塞模式），
// 而 `drainAvailable` 需要「队列空了就立刻返回」的语义。
// 所以由本协程做阻塞读、把包连同地址塞进队列，上层用非阻塞 select 消费。
func (s *rawSocket) readLoop() {
	defer close(s.rxDone)
	for {
		bufPtr := s.pool.Get().(*[]byte)
		buf := *bufPtr
		n, addr, err := s.handle.Recv(buf)
		if err != nil {
			s.pool.Put(bufPtr)
			if s.closed.Load() {
				return
			}
			// 驱动错误不可恢复（句柄失效 / 驱动卸载）：退出而不是空转刷日志。
			s.logger.Error("windivert recv 失败: ", err)
			return
		}
		if n <= 0 {
			s.pool.Put(bufPtr)
			continue
		}
		pkt := wdivPacket{data: buf[:n], addr: addr}
		select {
		case s.rx <- pkt:
		case <-s.rxStop:
			s.pool.Put(bufPtr)
			return
		}
	}
}

// wdivEthPrefix 是补在裸 IP 包前面的 14 字节以太网头。
//
// Linux 的 AF_PACKET 收到的是以太网帧，ParseFrame 按「先读 EtherType
// 再找 IPv4」解析。WinDivert 的 NETWORK 层直接给出裸 IP 包，没有这 14 字节，
// 原样送进 ParseFrame 会被当成非法帧丢弃——表现为 SYN-ACK 到了驱动、
// 日志里也能看到，但握手永远等不到它。
// MAC 全 0 即可：ParseFrame 只看 EtherType（偏移 12 的 0x0800），不看地址。
var wdivEthPrefix = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00}

// stripFramePrefix 去掉 copyAsFrame 补上的以太网头，还原成裸 IP 包。
//
// 只在前缀确实是我们补的那 14 字节时才剥，避免误伤本来就是裸 IP 的缓冲。
func stripFramePrefix(frame []byte) []byte {
	if len(frame) >= len(wdivEthPrefix) && bytes.Equal(frame[:len(wdivEthPrefix)], wdivEthPrefix) {
		return frame[len(wdivEthPrefix):]
	}
	return frame
}

// copyAsFrame 把裸 IP 包拷进 buf，并在前面补上以太网头。
//
// 返回 (帧长度, 是否完整)。buf 装不下时返回 (0, false)，调用方按截断处理。
func copyAsFrame(buf, ip []byte) (int, bool) {
	if len(buf) < len(wdivEthPrefix)+len(ip) {
		return 0, false
	}
	copy(buf, wdivEthPrefix)
	copy(buf[len(wdivEthPrefix):], ip)
	return len(wdivEthPrefix) + len(ip), true
}

// Recv 阻塞取一个包（net.PacketConn 风格的语义由上层适配）。
func (s *rawSocket) Recv(buf []byte) (int, error) {
	for {
		select {
		case pkt := <-s.rx:
			n, ok := copyAsFrame(buf, pkt.data)
			s.lastAddr = pkt.addr
			// 归还池缓冲：copy 已经把数据搬走了。
			// 注意这里不能 put 一个被上层引用的切片——上层只拿到 buf 里的副本。
			s.releasePacket(pkt)
			if !ok {
				s.truncated.Add(1)
				continue
			}
			return n, nil
		case <-s.rxStop:
			return 0, net.ErrClosed
		}
	}
}

// recvAvailable 非阻塞取一个包：队列空时立即返回 ok=false。
func (s *rawSocket) recvAvailable(buf []byte) (int, bool, error) {
	select {
	case pkt := <-s.rx:
		n, ok := copyAsFrame(buf, pkt.data)
		s.lastAddr = pkt.addr
		s.releasePacket(pkt)
		if !ok {
			s.truncated.Add(1)
			return 0, false, nil
		}
		return n, true, nil
	default:
		return 0, false, nil
	}
}

// recvBatch 在 Windows 上不可用。
//
// 驱动有 `RecvBatch`（单次最多 255 个），但启用它需要把
// 「首尾相接的缓冲 + 地址数组」重新切分，而 Linux 侧的实测结论是
// 批量收包**没有可测收益**（DEVTIPS 129）。所以这里保持 false，
// 走上层统一的逐帧路径。
func (s *rawSocket) recvBatch(slots *recvSlots) (int, error) {
	return 0, nil
}

// recvBatchEnabled 返回是否启用批量收包（Windows 上恒为 false）。
func recvBatchEnabled() bool { return false }

// releasePacket 把包缓冲归还池。
func (s *rawSocket) releasePacket(pkt wdivPacket) {
	// 恢复到满容量再入池：recv 时被切成 buf[:n]。
	full := pkt.data[:cap(pkt.data)]
	ptr := &full
	s.pool.Put(ptr)
}

// WriteTo 的底层：发送一个已构好的完整 IP 报文。
func (s *rawSocket) Send(pkt []byte, dst netip.Addr) error {
	if s.closed.Load() {
		return errSocketClosed
	}
	if !dst.Is4() {
		return ErrPlatformUnsupported
	}
	addr := wdivAddr{}
	addr.Bits = wdivBitSet(addr.Bits, wdivBitOutbound, true)
	// 校验和位保持 0。WinDivert 2.2 的发送路径里，
	// IPChecksum/TCPChecksum == 0 才会重算（sys/windivert.c 的
	// WINDIVERT_HELPER_NO_*_CHECKSUM 分支）。置 1 表示「别动」，
	// 网卡校验和卸载会把 IP 头里的校验和清成 0 再发出去，
	// 中间设备直接丢，服务端一个 SYN 都看不到。
	if _, err := s.handle.Send(pkt, &addr); err != nil {
		return err
	}
	return nil
}

// SendBatch 批量发送（驱动要求包首尾相接）。
//
// 与 Linux 的 sendmmsg 语义一致：返回成功递交的包数。
// 拼接由 wdivPackBatch 完成（已单测），失败（容量不足）时降级为逐包发送。
func (s *rawSocket) SendBatch(pkts [][]byte, dst netip.Addr) (int, error) {
	if len(pkts) == 0 {
		return 0, nil
	}
	if s.closed.Load() {
		return 0, errSocketClosed
	}
	if !dst.Is4() {
		return 0, ErrPlatformUnsupported
	}
	buf, lens, ok := wdivPackBatch(s.txBuf, pkts)
	if !ok {
		// 缓冲不足（单批超大）：退化为逐包，正确性优先。
		sent := 0
		for _, p := range pkts {
			if err := s.Send(p, dst); err != nil {
				if sent > 0 {
					return sent, nil
				}
				return 0, err
			}
			sent++
		}
		return sent, nil
	}
	s.txBuf = buf
	s.txLens = lens
	n, err := s.handle.SendBatch(buf, len(pkts))
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Reinject 把「不是本协议的包」还给内核。
//
// **WinDivert 语义下这是必需的**：被扣留的包如果既不消费也不回注，
// 就等于丢弃。服务端的过滤器按端口匹配，同端口上的真实浏览器请求
// （伪装站）也会被扣留，必须原样还给内核，否则伪装站 100% 失效。
//
// 复用 `lastAddr` 是刻意的：注入入向包时驱动要求 IfIdx 有效，
// 而它只有 Recv 时给出。方向位强制为 inbound（我们的过滤器只收入向）。
//
// Linux 侧同名方法是 no-op（AF_PACKET 是被动复制，内核已经处理过）。
func (s *rawSocket) Reinject(pkt []byte, h frameHandle) error {
	if s.closed.Load() {
		return errSocketClosed
	}
	// 用调用方交回的句柄，**不要读 s.lastAddr**：收包与处理在不同协程，
	// lastAddr 早已被后续帧覆盖（见 frameHandle 的注释）。
	addr, ok := h.(wdivAddr)
	if !ok {
		// 句柄缺失就只能让驱动自己挑接口（IfIdx=0）；宁可慢一拍，
		// 也不要注入到错误的接口上（表现为伪装站偶发连不上）。
		addr = wdivAddr{}
	}
	// 明确置为入向：伪装站的包是发给本机的。
	addr.Bits = wdivBitSet(addr.Bits, wdivBitOutbound, false)
	// Recv 给上层的是补了以太网头的帧（见 copyAsFrame），驱动注入要裸 IP 包。
	ip := stripFramePrefix(pkt)
	// 校验和沿用驱动给出的判定（原包未修改，直接放行）。
	if _, err := s.handle.Send(ip, &addr); err != nil {
		return err
	}
	return nil
}

// TakeFrameHandle 返回最近一帧的注入句柄（WINDIVERT_ADDRESS 的副本）。
//
// **必须由调用方在 Recv 返回后立刻取走**，否则下一次 Recv 会覆盖它。
// 这是「帧与地址严格配对」的唯一保证，详见 frameHandle 的注释。
func (s *rawSocket) TakeFrameHandle() frameHandle { return s.lastAddr }

// LocalIP 返回构造 IP 头时使用的源地址。
func (s *rawSocket) LocalIP() netip.Addr { return s.localIP }

// SendMode 返回发送路径描述（上层会写进启动日志）。
//
// 刻意在同一行里写明「无需 iptables 规则」：Linux 的启动日志会打印实际写入的
// 两条规则，Windows 什么都不写会让运维怀疑规则没生效，跑去 raw 表里找。
// WinDivert 的扣留语义让内核看不到伪包，本来就不需要任何规则
// （原因见 rules_windows.go 文件头）。
func (s *rawSocket) SendMode() string {
	return "windivert; 源 IP=" + s.localIP.String() + "; 无需 iptables 规则"
}

// Close 关闭通道。
//
// 顺序：先标记 closed + 关 rxStop（让消费方立刻退出），再关句柄
// （让阻塞中的 Recv 返回），最后等读取协程退出。
func (s *rawSocket) Close() error {
	var firstErr error
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.rxStop)
		if err := s.handle.Close(); err != nil {
			firstErr = err
		}
		select {
		case <-s.rxDone:
		case <-time.After(2 * time.Second):
			// 读取协程卡在驱动调用里：不阻塞关闭流程（进程退出由 OS 兜底）。
		}
	})
	return firstErr
}
