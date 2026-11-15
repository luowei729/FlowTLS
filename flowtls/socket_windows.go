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
	"errors"
	"net"
	"net/netip"
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

	// lastAddr 是最近一次收到的包的地址，供 Reinject 复用。
	//
	// 只有 recvLoop 一个协程会在收到包之后立刻调用 Reinject，
	// 所以这里不需要加锁；竞态窗口由「先 Recv 再 Reinject」的时序保证。
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
		filter = wdivClientInboundFilter(role.serverPort, role.sourcePort)
	}
	handle, err := wdivOpen(filter)
	if err != nil {
		return nil, err
	}

	s := &rawSocket{
		handle:            handle,
		localIP:           localIP,
		rx:                make(chan wdivPacket, wdivRxQueue),
		txBuf:             make([]byte, 0, maxSendBatch*wdivMTUMax),
		rxStop:            make(chan struct{}),
		rxDone:            make(chan struct{}),
		reinjectUnmatched: true,
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

// Recv 阻塞取一个包（net.PacketConn 风格的语义由上层适配）。
func (s *rawSocket) Recv(buf []byte) (int, error) {
	for {
		select {
		case pkt := <-s.rx:
			n := copy(buf, pkt.data)
			s.lastAddr = pkt.addr
			// 归还池缓冲：copy 已经把数据搬走了。
			// 注意这里不能 put 一个被上层引用的切片——上层只拿到 buf 里的副本。
			s.releasePacket(pkt)
			if n < len(pkt.data) {
				s.truncated.Add(1)
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
		n := copy(buf, pkt.data)
		s.lastAddr = pkt.addr
		s.releasePacket(pkt)
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
	addr.SetChecksumsValid()
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
func (s *rawSocket) Reinject(pkt []byte) error {
	if s.closed.Load() {
		return errSocketClosed
	}
	addr := s.lastAddr
	// 明确置为入向：伪装站的包是发给本机的。
	addr.Bits = wdivBitSet(addr.Bits, wdivBitOutbound, false)
	// 校验和沿用驱动给出的判定（原包未修改，直接放行）。
	if _, err := s.handle.Send(pkt, &addr); err != nil {
		return err
	}
	return nil
}

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
