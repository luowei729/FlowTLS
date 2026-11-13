package flowtls

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Session 是一条伪造 TCP 连接，实现 net.PacketConn。
//
// 对上（quic-go / quic.Transport）它就是一个 UDP socket：ReadFrom 拿到一个
// QUIC 数据报，WriteTo 交出一个 QUIC 数据报。对下它把每个数据报封装成
// 「TLS 记录 + TCP 包」，走 raw socket。
//
// 为什么要实现 net.PacketConn 而不是直接暴露内部 API：
// quic.Transport{Conn: session} 就能工作，quic-go 一行都不用改。
// 这与 sing-quic 用 SalamanderConn 包装 net.PacketConn 是同一个套路。
type Session struct {
	raw *rawSocket
	// ownsRaw 表示本会话是否拥有 raw socket 的生命周期。
	//
	// 客户端独占（ownsRaw=true，Close 时关 fd）；
	// 服务端共享同一个 socket 管所有客户端（ownsRaw=false，绝不能关）。
	// 服务端若不共享，每客户端一个 AF_PACKET + 8MB 接收缓冲，
	// 100 个客户端就是 800MB 内核内存。
	ownsRaw bool
	codec   *Codec

	// peer 是对端地址（客户端模式是服务端，服务端模式是客户端）
	peer netip.AddrPort
	// localPort 是本端端口，remotePort 是对端端口
	localPort  uint16
	remotePort uint16

	// mu 保护下面所有 TCP 状态与写缓冲。
	//
	// **必须加锁**：写入方向由 quic-go 的写协程调用（WriteTo），
	// 读方向由接收协程调用（handleIncoming → sendPureACK），
	// 两者都会改 seq / ipid 并共用 wPkt 缓冲。
	// 之前只靠注释说「只由持有者访问」是不够的——P4 引入共享 socket 后
	// 两个方向真正并发，不加锁会产生「seq 跳变」这类抓包可见的异常。
	mu      sync.Mutex
	seq     uint32
	peerSeq uint32
	ipid    uint16
	mark    uint16
	clock   *TcpClock
	ackPend int
	lastAck time.Time

	rx      chan []byte
	closeCh chan struct{}
	closed  atomic.Bool
	// rules 是本次 Dial 落地的客户端规则结果，供上层记日志。
	//
	// 规则是部署级静态属性，不随会话关闭而删除（见 ApplyRules 的注释），
	// 所以这里只做「一次性上报」，不参与 Close。
	rules RuleReport
	// readDeadline 是读超时的绝对时刻（UnixNano），0 表示不超时。
	//
	// 用 atomic 而不是 sync.Mutex：这是每包都可能读一次的热路径值，
	// 而写入只发生在 quic-go 设置/清除 deadline 时（低频）。
	// 不必拆成「读锁 + 写锁」两套机制。
	readDeadline atomic.Uint64
	// once 保护「关闭动作」（sendFIN + close(closeCh)）
	once sync.Once
	// rxMu / rxClosed 把「向 rx 发送」与「关闭 rx」互斥起来。
	//
	// 为什么不是 rxOnce 就够了：Close 与接收协程退出都会关 rx，
	// sync.Once 只保证「只关一次」，**不能保证「关完之后没人再 send」**。
	// Go 对已关闭通道发送是直接 panic（`send on closed channel`），
	// 而不是返回错误，所以只要有一个投递方在 close 之后走到 send，
	// 整个进程就挂了。旧写法靠「单包接收 + 两侧都先看 closed」把窗口撑得很小，
	// 看起来没事；收包改成一批 32 包后窗口放大 32 倍，实测必然踩中（DEVTIPS 92）。
	rxMu     sync.RWMutex
	rxClosed bool

	// 收发缓冲复用。受 mu 保护。
	wRecord []byte
	// wPkt 是握手阶段的单包缓冲（SYN / ClientHello / ServerHello）。
	//
	// 握手包必须**立即**发出，不能进批量队列（队列会延迟到凑满一批），
	// 所以身份包保留一条独立的一次性缓冲。稳态数据面不再用它。
	wPkt []byte

	// ---- 批量发送队列 ----
	//
	// 为什么需要队列：实测新加坡 1 核 ARM 服务端在 100Mbps 量级时，
	// 每包一次 sendto 的 syscall 开销（单包约 40~50µs）让 CPU 饱和，
	// AF_PACKET 驱动队列满后大量丢包（QUIC 侧 lost>10%，吞吐崩到 0.7Mbps）。
	// Rust 版用 sendmmsg 一次 32 包，同样链路 lost 只有 0.57%。
	//
	// 顺序保证：入队发生在持有 s.mu 的临界区内（与 seq 推进同一把锁），
	// 因此队列顺序 == TCP 序号顺序；纯 ACK 与数据包共用同一队列，
	// 不会出现「ACK 的 seq 超过尚未发出的数据包」这种抓包可见的异常。
	txCh   chan []byte
	txWake chan struct{}
	txStop chan struct{}
	txWG   sync.WaitGroup
	// txDropped 统计队列满丢弃的报文数（UDP 语义，QUIC 会重传）。
	txDropped atomic.Uint64
	// txSendErr 统计 flushLoop 批量发送整批失败的次数。
	//
	// 为什么单独计：发送失败会把整批报文一起丢，而在「阻塞 fd」语义下它
	// 本不应该发生；一旦非零，说明链路/驱动在丢包，是吞吐下降的第一线索。
	txSendErr atomic.Uint64

	// 统计（供上层日志用）
	pktsSent atomic.Uint64
	pktsRecv atomic.Uint64
	// rxDropped 统计因队列满而丢弃的包数（应为 0；非 0 说明背压链路断了）
	rxDropped atomic.Uint64
	// rxBytes 是 rx 队列里**未读的总字节数**。
	//
	// 为什么要单独记字节数：`AdvertisedWindow` 的参数是字节，
	// 之前直接传 `len(s.rx)`（包数）——16384 个包实际是 21.8MB，
	// 但被当成 16384 字节，于是通告窗口永远接近满值（16MB）。
	// 后果：对端无限制地发 → rx 填满 → deliver 阻塞 → 收包协程停摆。
	//
	// deliver 时加、ReadFrom 时减，用原子操作是因为两者在不同协程。
	rxBytes atomic.Int64
	// lastSeenAt 是最后一次收到**任何属于本会话的包**的时刻（UnixNano）。
	//
	// 必须是「任何包」而不是「解密出数据的包」：QUIC 保活 PING 只换回
	// 一个纯 ACK（无载荷），若只在有数据的包上更新时间戳，
	// 健康连接空闲 10 秒后就会被误判为「已死」。
	// 探活也依赖这一点：探测包换回的同样是纯 ACK。
	lastSeenAt atomic.Int64
}

// net.PacketConn 接口断言。编译期即可发现签名不一致。
var _ net.PacketConn = (*Session)(nil)

// timeoutError 是 net.Error 的最小实现，Timeout() 返回 true。
//
// quic-go 靠 `err.(net.Error).Timeout()` 区分「读超时」和「真错误」：
// 前者是正常的 deadline 到期（握手期、空闲期都可能发生），
// 后者才需要上报。不实现这个接口会让它把超时当成致命错误。
type timeoutError struct{}

func (timeoutError) Error() string   { return "flowtls: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

var _ net.Error = timeoutError{}

// ReadFrom 读取一个 QUIC 数据报。
//
// 返回的 addr 恒为对端地址：伪造 TCP 是点对点的，不存在「一个 socket 收
// 多个对端」的场景，quic-go 也只是拿它做日志和连接标识。
//
// **必须实现 deadline**：quic-go 把握手超时、idle 超时都挂在
// SetReadDeadline 上。空实现会让 Dial 永远不超时——联调时表现为
// 「密码错误时客户端永久挂起」，只能被外部 timeout 杀掉。
func (s *Session) ReadFrom(p []byte) (int, net.Addr, error) {
	// 快路径：已经有数据就直接返回，避免每次读都创建一个 timer
	select {
	case data, ok := <-s.rx:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(p, data)
		s.rxBytes.Add(-int64(len(data)))
		// 归还缓冲到池（data 是 deliver 从池里取的切片）。
		// 这里只归还底层数组，不改长度：池里的元素仍可容纳同样大小的数据。
		putBack := data[:cap(data)]
		bufPool.Put(&putBack)
		return n, s.peerUDPAddr(), nil
	default:
	}

	// 慢路径：带 deadline 的等待
	if dl := s.readDeadline.Load(); dl != 0 {
		d := time.Unix(0, int64(dl))
		if !d.IsZero() {
			wait := time.Until(d)
			if wait <= 0 {
				return 0, nil, timeoutError{}
			}
			timer := time.NewTimer(wait)
			defer timer.Stop()
			select {
			case data, ok := <-s.rx:
				if !ok {
					return 0, nil, net.ErrClosed
				}
				n := copy(p, data)
				s.rxBytes.Add(-int64(len(data)))
				putBack := data[:cap(data)]
				bufPool.Put(&putBack)
				return n, s.peerUDPAddr(), nil
			case <-timer.C:
				return 0, nil, timeoutError{}
			case <-s.closeCh:
				return 0, nil, net.ErrClosed
			}
		}
	}

	select {
	case data, ok := <-s.rx:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(p, data)
		s.rxBytes.Add(-int64(len(data)))
		putBack := data[:cap(data)]
		bufPool.Put(&putBack)
		return n, s.peerUDPAddr(), nil
	case <-s.closeCh:
		return 0, nil, net.ErrClosed
	}
}

// WriteTo 发送一个 QUIC 数据报。
//
// 报文在持锁的临界区内构造并**入队**，由 flushLoop 用 sendmmsg 批量发出。
// 不能在这里直接 sendto：1 核 ARM 上每包一次 syscall 会在 100Mbps 量级饱和，
// 驱动队列满后大量丢包（实测服务端 QUIC lost>10%，吞吐 0.7Mbps）。
//
// 早前「攒批把吞吐打到 7KB/s」的教训与本实现不冲突，根因有两条：
//   - 当时用 `time.AfterFunc(200µs)` 兜底，Linux 定时器实际精度约 1ms，
//     而本实现用 channel 唤醒，没有定时器延迟；
//   - 当时纯 ACK 不进队列，seq 已推进的 ACK 先于数据包发出，对端判乱序。
//     本实现所有发包路径共用同一队列，顺序 == 序号顺序。
func (s *Session) WriteTo(p []byte, addr net.Addr) (int, error) {
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	s.mu.Lock()
	// 记录复用：稳态下除入队拷贝外零分配
	s.wRecord = s.codec.Seal(s.wRecord[:0], p)
	pkt := s.appendSegmentLocked(s.wPkt[:0], s.wRecord, TCPPSH|TCPACK)
	s.enqueueLocked(pkt)
	s.mu.Unlock()
	return len(p), nil
}

// enqueueLocked 把一个已构造好的报文放进发送队列（调用方必须持有 s.mu）。
//
// 必须持锁调用：入队顺序就是 TCP 序号顺序，这是纯 ACK 与数据包
// 共用队列后仍然「抓包看不出异常」的前提。
//
// 报文要拷贝：pkt 指向 s.wPkt 这条复用缓冲，下一包会覆盖它。
// 队列满时按 UDP 语义丢弃——这是最坏情况的兜底，quic-go 会重传。
func (s *Session) enqueueLocked(pkt []byte) {
	buf := txPool.Get().(*[]byte)
	if cap(*buf) < len(pkt) {
		*buf = make([]byte, len(pkt))
	} else {
		*buf = (*buf)[:len(pkt)]
	}
	copy(*buf, pkt)
	select {
	case s.txCh <- *buf:
		// 非阻塞唤醒 flush 协程：已有唤醒信号时不必重复发
		select {
		case s.txWake <- struct{}{}:
		default:
		}
	default:
		// 队列满：归还缓冲并丢弃
		txPool.Put(buf)
		s.txDropped.Add(1)
	}
}

// startSender 启动批量发送协程。
//
// 客户端在 StartReceiver 时启动（握手已完成）；服务端在会话建立时启动。
// 握手阶段的 SYN / SYN-ACK / ClientHello 仍走直接 Send，
// 因为它们必须在状态机推进前立刻上线。
func (s *Session) startSender() {
	s.txWG.Add(1)
	go s.flushLoop()
}

// txPool 复用发送队列里的报文缓冲。
//
// 尺寸与 MTU 对齐：1417 字节是最大报文（1332 载荷 + 33 记录封装 + 52 IP/TCP 头）。
var txPool = sync.Pool{New: func() any {
	b := make([]byte, 0, 1536)
	return &b
}}

// flushLoop 是唯一的发送协程：从队列取包，凑一批用 sendmmsg 发出。
//
// 批量大小的上限 32 与 Rust 版一致。每次被唤醒后**尽量排空**队列：
// quic-go 的 sendQueue 在一轮 Run 里会连续调用多次 WriteTo（受 pacing 限制），
// 这些包都能在同一个 sendmmsg 里发出。
func (s *Session) flushLoop() {
	defer s.txWG.Done()
	batch := make([][]byte, 0, maxSendBatch)
	for {
		select {
		case <-s.txStop:
			return
		case <-s.txWake:
		}
		for {
			batch = batch[:0]
			for len(batch) < maxSendBatch {
				select {
				case pkt := <-s.txCh:
					batch = append(batch, pkt)
				default:
					goto send
				}
			}
		send:
			if len(batch) == 0 {
				break
			}
			sent, err := s.raw.SendBatch(batch, s.peer.Addr())
			if err != nil {
				// 整批发送失败：计数并（开关下）记日志。以前这里是完全静默的，
				// 导致「吞吐不知为何上不去」时无从查起。
				s.txSendErr.Add(1)
				if os.Getenv("FLOWTLS_DEBUG_SEND") == "1" {
					log.Printf("flowtls: 批量发送失败 %d 包: %v", len(batch), err)
				}
			} else {
				s.pktsSent.Add(uint64(sent))
			}
			// 归还缓冲。SendBatch 返回后内核已拷贝走报文内容。
			for _, pkt := range batch {
				p := pkt[:cap(pkt)]
				txPool.Put(&p)
			}
			// 没凑满一批说明队列已空，回去等唤醒
			if len(batch) < maxSendBatch {
				break
			}
		}
	}
}

// stopSender 停止批量发送协程并丢弃队列中未发出的报文。
//
// FIN 由 Close 直接发送（绕过队列），所以这里不需要等待队列排空：
// 残留报文按 UDP 语义丢弃，对端 QUIC 会自行超时重连。
func (s *Session) stopSender() {
	select {
	case <-s.txStop:
		return // 已经停过
	default:
		close(s.txStop)
	}
	s.txWG.Wait()
}

// appendSegmentLocked 把 TLS 记录封装成一个 TCP 段（含 IP 头）。
// 调用方必须持有 s.mu。
func (s *Session) appendSegmentLocked(dst, payload []byte, flags uint8) []byte {
	seg := TcpSeg{
		Src:     s.raw.LocalIP,
		Dst:     s.peer.Addr(),
		SrcPort: s.localPort,
		DstPort: s.remotePort,
		Seq:     s.seq,
		Ack:     s.peerSeq,
		Flags:   flags,
		IPID:    s.ipid,
		// Window 是通告给对端的接收窗口（未缩放的原始值）。
		//
		// **必须传未读字节数，不能传 len(s.rx)**：后者是包数，
		// 16384 个包实际是 21.8MB，当成字节数后窗口永远接近满值（16MB），
		// 对端就会无限制地发，直到 rx 填满。实测后果是两台服务器吞吐
		// 同时崩到 63KB/s（详见 deliver 里 default 分支的注释）。
		Window:  AdvertisedWindow(int(s.rxBytes.Load())),
		TSVal:   s.clock.TSVal(),
		TSecr:   s.clock.PeerTS,
		Payload: payload,
	}
	dst = AppendPacket(dst, seg)
	// TCP 语义：序号按载荷推进，让中间盒看到的流是连续的
	s.seq += seqLen(flags, len(payload))
	s.ipid = NextIPID(s.mark, s.ipid)
	return dst
}

// sendPureACK 发一个纯 ACK（无载荷）。
//
// 真实 TCP 是双向确认的，下载方向必须有反向纯 ACK，否则一眼就是伪造。
// 纯 ACK 占包量的两成以上，必须走复用缓冲。
//
// **必须立即发送**：ACK 延迟会直接抬高对端的 RTT 估计。
// 实测把它放进 200µs 攒批队列（Linux 定时器实际约 1ms）后，
// RTT 从 76ms 虚高到 420ms，BBR 带宽估计崩塌，吞吐降到 7KB/s。
func (s *Session) sendPureACK() {
	if s.closed.Load() {
		return
	}
	s.mu.Lock()
	s.ackPend = 0
	s.lastAck = time.Now()
	pkt := s.appendSegmentLocked(s.wPkt[:0], nil, TCPACK)
	// 纯 ACK 不占序号：appendSegmentLocked 已按 seqLen 判断。
	// 与数据包共用队列，保证 seq 顺序与发出顺序一致。
	s.enqueueLocked(pkt)
	s.mu.Unlock()
}

// sendFIN 发 FIN 拆除连接，让拆除过程像真实 TCP。
func (s *Session) sendFIN() {
	if s.closed.Load() {
		return
	}
	s.mu.Lock()
	pkt := s.appendSegmentLocked(s.wPkt[:0], nil, TCPFIN|TCPACK)
	err := s.raw.Send(pkt, s.peer.Addr())
	s.mu.Unlock()
	_ = err
}

// Close 关闭会话。幂等。
//
// 关闭顺序有严格要求，否则会死锁：
// quic.Transport.Close 会等它内部的 reader goroutine 退出，
// 而那个 goroutine 正阻塞在本 Session 的 ReadFrom 上。
// ReadFrom 只有靠 close(closeCh) 才能返回 —— 而释放 closeCh 的只能是
// Session.Close 自己。因此**必须先闭 Session 再闭 Transport**。
// （反过来写时现象是：程序功能正常但进程永不退出，只能被 timeout 杀掉。）
func (s *Session) Close() error {
	s.once.Do(func() {
		s.sendFIN()
		s.closed.Store(true)
		// 停批量发送协程：之后不再有新的入队，残留报文按 UDP 语义丢弃
		s.stopSender()
		close(s.closeCh)
		// 关 rx 让上层仍阻塞在 ReadFrom 的调用同样被唤醒：
		// closeCh 只影响 select，而有数据分支可能先选中 rx。
		// 必须走 shutdownRx（与投递互斥），否则正在处理的那批包会向已关闭的通道发送而 panic。
		s.shutdownRx()
		// 只在自己拥有 socket 时才关闭。
		//
		// 客户端必须关：recvLoop 阻塞在 raw.Recv 上，只标 closed 不会唤醒它
		// （它不看标志，等的是 syscall 返回），不关会泄漏 goroutine + 2 个 fd。
		// 服务端绝不能关：所有会话共享同一个 socket，关掉会把整台服务器
		// 的所有客户端一起断掉。
		if s.ownsRaw {
			_ = s.raw.Close()
		}
	})
	return nil
}

// LocalAddr 返回本端地址。
func (s *Session) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(s.raw.LocalIP, s.localPort))
}

// peerUDPAddr 返回对端地址的 net.Addr 视图（每次分配一个，量很小）。
func (s *Session) peerUDPAddr() net.Addr {
	return net.UDPAddrFromAddrPort(s.peer)
}

// RemoteAddr 返回对端地址。quic.Transport 的 Dial 需要它作为目的地址。
func (s *Session) RemoteAddr() net.Addr {
	return net.UDPAddrFromAddrPort(s.peer)
}

// Rules 返回本次 Dial 落地的客户端规则结果。
//
// 上层（sing-box outbound / 联调工具）用它把规则文本记进日志：
// print 模式下这份文本就是运维需要手工安装的命令。
func (s *Session) Rules() RuleReport { return s.rules }

// SendMode 返回底层发送路径描述（见 Listener.SendMode）。
//
// 客户端用自己的 raw socket，服务端共用 Listener 的，两边语义一致：
// 这条信息只用于启动日志，帮运维一眼看出「实际走内核还是 AF_PACKET、
// 源地址到底用了谁」。
func (s *Session) SendMode() string {
	if s.raw == nil {
		return "none"
	}
	return s.raw.SendMode()
}

// SetDeadline 实现 net.PacketConn。quic-go 用它做握手与 idle 超时。
func (s *Session) SetDeadline(t time.Time) error {
	if err := s.SetReadDeadline(t); err != nil {
		return err
	}
	return s.SetWriteDeadline(t)
}

// SetReadDeadline 设置读超时。零值表示不超时。
func (s *Session) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		s.readDeadline.Store(0)
		return nil
	}
	s.readDeadline.Store(uint64(t.UnixNano()))
	return nil
}

// SetWriteDeadline 设置写超时。
//
// 写方向不需要真实现：底层 sendto 在 FIFO/raw socket 上是非阻塞语义的
// 尽力投递（队列满返回 ENOBUFS），不会无限阻塞。这里只接受值不做事,
// 避免 net.PacketConn 调用方因返回错误而中断。
func (s *Session) SetWriteDeadline(t time.Time) error { return nil }

// rxQueueDepth 是接收队列的深度（单位：包）。
//
// **这个值必须覆盖 QUIC 连接级接收窗口上限**，否则一定丢包。推导：
//
//	队列容量 = rxQueueDepth × ~1340 字节
//	quic-go 默认 MaxConnectionReceiveWindow = 15MB
//	队列容量 < 窗口上限 → 窗口允许的在途数据能填满队列 → 阻塞 →
//	recvLoop 停读 raw socket → 内核缓冲（8MB）满 → 内核丢包
//
// 而 FakeTCP 层**本身没有重传机制**（它只是外观像 TCP），
// 丢一个包就是永久丢；QUIC 靠 PTO 重传，重传又可能继续被丢，
// 形成「发→丢→重传→再丢」死循环，最终服务端报
// 「背压等待超过 30 秒，放弃该流」。
//
// 实测演进：
//
//	256 包（0.3MB）→ 单流 20MB 勉强，40MB 失败
//	8192 包（10.7MB）→ 单流 40MB 成功，2 流 16MB 成功，4 流 40MB 失败
//	16384 包（21.9MB）→ 覆盖 15MB 连接窗口，4 流稳定
//
// 内存代价：16384 × 1500B ≈ 24MB 上限，且只在真有流量时才占满
// （切片从 sync.Pool 取，空闲时会被 GC 回收）。
const rxQueueDepth = 16384

// LastSeenAt 返回最后一次收到属于本会话的包的时刻。
//
// 零值（会话从未收到包）返回 time.Time{}，调用方应视为「刚建立」。
func (s *Session) LastSeenAt() time.Time {
	v := s.lastSeenAt.Load()
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(0, v)
}

// IdleFor 返回距最后一次收到对端包已过去多久。
func (s *Session) IdleFor() time.Duration {
	t := s.LastSeenAt()
	if t.IsZero() {
		return 0
	}
	return time.Since(t)
}

// deliver 由接收协程调用：把解密后的数据报投进 rx。
//
// **必须阻塞，不能丢包。**这一点与普通 UDP 代理相反，原因是：
//
//	我们跑在「可靠」的伪造 TCP 之上，但 QUIC 认为下层是 UDP。
//	如果在这里静默丢包，quic-go 会以为包已投递成功——它既不会发 ACK，
//	也不会触发重传；而服务端的 QUIC 只能靠重传定时器盲猜，
//	重传的包进来又可能继续被丢，形成「发包→丢弃→重传→再丢」的死循环。
//	实测现象：单流 40MB 正常，但 2 流共 16MB 时服务端报
//	「背压等待超过 30 秒，放弃该流」——因为它一直在等客户端消费。
//
// 阻塞的代价是 recvLoop 会暂停读 raw socket，内核缓冲（8MB）填满后
// 由内核丢包。那比我们主动丢好：内核丢的是**整个加密 TCP 段**，
// 服务端的伪造 TCP/QUIC 两侧都会感知到并重传；而我们主动丢的是
// 一个已经解密、QUIC 已认定送达的数据报，永久丢失。
func (s *Session) deliver(payload []byte) {
	// 必须拷贝：payload 指向接收缓冲，下一轮会被覆盖。
	// 从池里取而不是每次 make：高吞吐下每包一次分配会带来明显 GC 压力。
	buf := bufPool.Get().(*[]byte)
	if cap(*buf) < len(payload) {
		*buf = make([]byte, len(payload))
	} else {
		*buf = (*buf)[:len(payload)]
	}
	copy(*buf, payload)
	s.deliverOwned(*buf)
}

// deliverOwned 同 deliver，但接管 owned 缓冲的所有权（不再拷贝）。
//
// 调用方必须保证 owned 来自 bufPool（ReadFrom 会用 data[:cap(data)] 归还），
// 否则池里会混入不同容量的缓冲，后续取用时会隐性扩容。
func (s *Session) deliverOwned(owned []byte) {
	// **必须持读锁**：shutdownRx() 拿写锁 close(s.rx)。
	// 不互斥就是「关完后仍然 send」的竞态，Go 会直接 panic。
	// 下面三个分支全部非阻塞（select 带 default），
	// 所以持读锁期间不会把写侧（关通道的人）卡住。
	s.rxMu.RLock()
	if s.rxClosed {
		s.rxMu.RUnlock()
		// 会话已结束：归还缓冲后退出
		putBack := owned[:cap(owned)]
		bufPool.Put(&putBack)
		return
	}
	select {
	case s.rx <- owned:
		s.rxMu.RUnlock()
		// 记账：AdvertisedWindow 要用真实未读字节数（见 rxBytes 的注释）
		s.rxBytes.Add(int64(len(owned)))
	case <-s.closeCh:
		s.rxMu.RUnlock()
		// 会话已关闭：归还缓冲后退出，不阻塞
		putBack := owned[:cap(owned)]
		bufPool.Put(&putBack)
	default:
		s.rxMu.RUnlock()
		// **队列满：丢弃这个包，绝不能阻塞。**
		//
		// 没有这个分支会造成全局死锁：服务端的 handleIncoming 是由
		// **唯一的** recvLoop 调用的（listener.go 里所有会话共享一个收包
		// 协程）。只要有一个会话的 rx 满了，deliver 就永久阻塞，
		// 整个 recvLoop 停摆 —— 所有会话同时收不到包、发不出 ACK，
		// 服务端随即判定大面积丢包、BBR 降速到几乎为零。
		//
		// 实测症状（两台服务器都复现）：
		//   - RTT 正常（78ms），但吞吐只有 63KB/s；
		//   - 服务端 sent 计数停滞、lost 占比 9.5%；
		//   - 客户端 sent 计数也停滞（它的 recvLoop 同样卡住）。
		//
		// 丢弃是正确的语义：这是 UDP，QUIC 会重传。
		// 计数用于诊断——非 0 说明上层读得太慢，rxQueueDepth 需要调大。
		putBack := owned[:cap(owned)]
		bufPool.Put(&putBack)
		s.rxDropped.Add(1)
	}
}

// bufPool 复用接收缓冲。
//
// 尺寸按常见 QUIC 数据报取整，避免频繁扩容；超出时 deliver 会重新分配
// 一块更大的（并归还旧块）。
var bufPool = sync.Pool{New: func() any {
	b := make([]byte, 1500)
	return &b
}}

// shutdownRx 关闭 rx，唤醒仍阻塞在 ReadFrom 的调用方。幂等。
//
// 与 deliverOwned 里的发送用同一把锁串行化：只要两者互斥，
// 「已关闭通道再 send」在语法上就不可能成立，不再依赖时序巧合。
func (s *Session) shutdownRx() {
	s.rxMu.Lock()
	if !s.rxClosed {
		s.rxClosed = true
		close(s.rx)
	}
	s.rxMu.Unlock()
}

// closeRx 标记会话结束并唤醒阻塞的读取方（接收协程退出时调用）。
func (s *Session) closeRx() {
	s.closed.Store(true)
	s.once.Do(func() { close(s.closeCh) })
	s.shutdownRx()
}

// ---- 客户端 ----

// handshakeTimeout 是 SYN-ACK 的默认等待时间。
const handshakeTimeout = 3 * time.Second

// Dial 建立一条伪造 TCP 连接，返回可直接交给 quic.Transport 的 net.PacketConn。
//
// 握手必须在这里**同步完成**，返回的 Session 已经是 ESTABLISHED 状态：
// quic-go 的 Dial 会立刻写 Initial，如果在 WriteTo 里才做三次握手，
// 就要在并发读循环里维护状态机，竞态极难排查。
// 先握手再交出去，语义与 Rust 版「握手完成前不 drain_transmits」一致。
func Dial(ctx context.Context, cfg ClientConfig) (*Session, error) {
	if !cfg.Server.Addr().Is4() {
		return nil, ErrPlatformUnsupported
	}
	if cfg.Password == "" {
		return nil, errors.New("flowtls: password 不能为空")
	}
	// bindRecv=true：客户端只跟一个对端，把接收 fd 绑到出口网卡，
	// 避开 lo / docker 上的无关流量把 AF_PACKET 接收队列淹没（见 newRawSocket）。
	raw, err := newRawSocket(cfg.Server.Addr(), netip.Addr{}, true)
	if err != nil {
		return nil, err
	}

	srcPort := cfg.SourcePort
	if srcPort == 0 {
		srcPort = 44300
	}

	// 客户端规则必须在**第一个包发出之前**就位。
	//
	// SYN-ACK 一回，内核就会发现没有对应 socket 并回 RST，
	// RST 是协议合法的终止信号，中间设备会立即拆掉 NAT 映射。
	// 所以这里不能在握手成功后再装规则。
	//
	// 规则是部署级静态属性，重复 Dial 只会命中 -C「已存在」，开销可忽略。
	rules, err := ApplyRules(cfg.IPTablesMode, ClientRules(srcPort, cfg.Server.Port(), cfg.IPIDMark))
	if err != nil {
		_ = raw.Close()
		return nil, err
	}

	codec, err := NewClientCodec(cfg.Password)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	mark := IPIDMarkOf(cfg.IPIDMark)
	if mark == 0 {
		mark = IPIDMark
	}
	s := &Session{
		raw:        raw,
		codec:      codec,
		peer:       cfg.Server,
		localPort:  srcPort,
		remotePort: cfg.Server.Port(),
		ipid:       RandomIPID(mark),
		mark:       mark,
		clock:      NewTcpClock(),
		rx:         make(chan []byte, rxQueueDepth),
		closeCh:    make(chan struct{}),
		lastAck:    time.Now(),
		rules:      rules,
	}
	// 初始化批量发送队列（flushLoop 在 StartReceiver 里启动）
	s.newTxQueues()
	// SYN 占 1 个序号
	isn := uint32(time.Now().UnixNano())
	s.seq = isn

	timeout := cfg.HandshakeTimeout
	if timeout <= 0 {
		timeout = handshakeTimeout
	}

	if cfg.Handshake {
		synAck, err := s.exchangeSyn(timeout)
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
		// SYN-ACK 之后客户端要回 ACK，并记录对端 ISN
		s.peerSeq = synAck.seq + 1
		s.clock.Observe(synAck.tsval, synAck.hasTS)
		ack := s.appendSegmentLocked(s.wPkt[:0], nil, TCPACK)
		if err := raw.Send(ack, s.peer.Addr()); err != nil {
			_ = raw.Close()
			return nil, err
		}
		s.pktsSent.Add(1)

		// ---- 发伪 ClientHello（与 Rust 版 client.rs:773 一致）----
		//
		// 顺序必须是「SYN → SYN-ACK → ACK → ClientHello → 数据」：
		// 严格 NAT 只放行握手完成后的包，把 ClientHello 提前会导致它被丢弃。
		//
		// 没有这一步，线上字节流就是「TCP 握手完立刻 17 03 03」——
		// 真实 TLS 永远先有 16 03 01/03 的 ClientHello，
		// 按「第一个应用层字节」分类的 DPI 一眼就能判定这不是 HTTPS。
		hello := BuildClientHello(cfg.SNI)
		helloPkt := s.appendSegmentLocked(s.wPkt[:0], hello, TCPPSH|TCPACK)
		if err := raw.Send(helloPkt, s.peer.Addr()); err != nil {
			_ = raw.Close()
			return nil, err
		}
		s.pktsSent.Add(1)
	} else {
		// 跳过握手（要求客户端有公网 IP，且服务端配置 handshake: none）
		s.peerSeq = 0
	}
	return s, nil
}

// synAckInfo 是服务端 SYN-ACK 里我们需要的信息。
type synAckInfo struct {
	seq   uint32
	tsval uint32
	hasTS bool
}

// exchangeSyn 发 SYN 并阻塞等待 SYN-ACK。
//
// 这里直接读 raw socket，不启动接收协程：握手阶段只有一个对端、一种包，
// 起一个协程再同步等它反而更绕。握手完成后才启动常驻接收协程。
func (s *Session) exchangeSyn(timeout time.Duration) (synAckInfo, error) {
	// 重传必须复用同一个 ISN：真实 TCP 重传 SYN 用同一序号，
	// 换新值会让服务端的 SYN 缓存对不上，也不会回我们的 ACK。
	isn := s.seq
	// 数组变量才能取切片：直接对返回值切片在 Go 里是不可寻址的
	opts := SynOptions(s.clock.TSVal(), 0)
	syn := AppendPacket(s.wPkt[:0], TcpSeg{
		Src:     s.raw.LocalIP,
		Dst:     s.peer.Addr(),
		SrcPort: s.localPort,
		DstPort: s.remotePort,
		Seq:     isn,
		Ack:     0,
		Flags:   TCPSYN,
		IPID:    s.ipid,
		Window:  65535, // SYN 阶段用未缩放的原始值
		TSVal:   s.clock.TSVal(),
		TSecr:   0,
		Options: opts[:],
	})
	// SYN 占 1 个序号，之后的 ACK 从这里开始
	s.seq = isn + 1
	// SYN 重传 3 次：丢一个 SYN 就完全建不起连接，成本极低但收益明显
	deadline := time.Now().Add(timeout)
	for attempt := 0; attempt < 3; attempt++ {
		if err := s.raw.Send(syn, s.peer.Addr()); err != nil {
			return synAckInfo{}, err
		}
		s.pktsSent.Add(1)
		buf := make([]byte, 65536)
		waitUntil := time.Now().Add(time.Second)
		if waitUntil.After(deadline) {
			waitUntil = deadline
		}
		for time.Now().Before(waitUntil) {
			n, err := s.raw.Recv(buf)
			if err != nil {
				continue
			}
			p, ok := ParseFrame(buf[:n])
			if !ok {
				// 排障开关：打印无法解析的帧（前 32 字节），
				// 用于判断「收包格式不对（如无以太头）」还是「解析逻辑不匹配」。
				if os.Getenv("FLOWTLS_DEBUG_HANDSHAKE") == "1" {
					head := buf[:n]
					if len(head) > 32 {
						head = head[:32]
					}
					log.Printf("flowtls handshake: 收到无法解析的帧 len=%d head=%x", n, head)
				}
				continue
			}
			if os.Getenv("FLOWTLS_DEBUG_HANDSHAKE") == "1" {
				log.Printf("flowtls handshake: recv %v:%d -> :%d flags=0x%02x seq=%d ack=%d (expect peer=%v:%d dstPort=%d ack=%d)",
					p.Src, p.SrcPort, p.DstPort, p.Flags, p.Seq, p.Ack,
					s.peer.Addr(), s.remotePort, s.localPort, isn+1)
			}
			// 只认「服务端 → 我们」的 SYN-ACK
			if p.Src != s.peer.Addr() || p.SrcPort != s.remotePort ||
				p.DstPort != s.localPort {
				continue
			}
			if p.Flags&TCPSYN == 0 || p.Flags&TCPACK == 0 {
				continue
			}
			if p.Ack != isn+1 {
				continue
			}
			return synAckInfo{
				seq:   p.Seq,
				tsval: p.TSVal,
				hasTS: p.HasTS,
			}, nil
		}
	}
	return synAckInfo{}, ErrHandshakeTimeout
}

// newTxQueues 初始化批量发送队列。
//
// 所有 Session 创建路径（客户端 Dial、服务端 Listener）都必须调用，
// 否则 enqueueLocked 会往 nil channel 发送（select 的 default 分支会兜住，
// 但报文会被全部丢弃）。
func (s *Session) newTxQueues() {
	s.txCh = make(chan []byte, txQueueDepth)
	s.txWake = make(chan struct{}, 1)
	s.txStop = make(chan struct{})
}

// txQueueDepth 是发送队列深度（单位：包）。
//
// 4096 × 1417B ≈ 5.8MB，覆盖连接级 BDP 的突发；
// 队列存在只为吸收「构造速度 > sendmmsg 速度」的瞬时差额，
// 持续过载时满即丢（UDP 语义）。
const txQueueDepth = 4096

// StartReceiver 启动常驻接收协程。
//
// 必须在握手完成后调用：握手阶段由 exchangeSyn 独占 raw socket。
// 单独暴露而不是在 Dial 里自动启动，是为了让调用方能在启动前完成
// quic.Transport 的装配，避免第一条包比 Transport 就绪还早到达。
//
// 同时启动批量发送协程：数据面从这一刻开始，握手包已经发完。
func (s *Session) StartReceiver() {
	s.startSender()
	go s.recvLoop()
}

func (s *Session) recvLoop() {
	defer s.closeRx()
	// **批量收包**：一次 recvmmsg 最多拿 maxRecvBatch 个报文。
	//
	// 为什么批量：公网下行 10MB/s 是 ~7700pps，逐包 recvfrom 就是每包一次
	// syscall（实测约 40µs）+ 一次协程调度。发送侧已经用 sendmmsg 把 syscall
	// 降了 32 倍，收包侧不对等就会让内核接收队列积压，而队列长度直接变成
	// 我们的 ACK 延迟、也就是对端算出来的 RTT。
	//
	// 曾经试过再拆一级（pump 只 syscall + 处理侧解密），实测吞吐无提升
	// （6.2 vs 6.1 MB/s）却多了一个「处理侧跟不上就丢帧」的风险点，
	// 所以回到单协程 + 批量。剩余差距见 DEVTIPS 88。
	//
	// 每个包必须用独立缓冲：同一批里多个包的密文要各自成立，
	// 而 ParseFrame 的切片直接指向它们。
	// 密文缓冲不会泄漏到下一轮：解密后的明文写进 bufPool 的另一块缓冲
	// （OpenTo 的目标），交给 quic-go 的是明文，所以下一轮覆写 bufs 安全。
	bufs := make([][]byte, maxRecvBatch)
	for i := range bufs {
		bufs[i] = make([]byte, 2048)
	}
	lens := make([]int, maxRecvBatch)
	for {
		if s.closed.Load() {
			return
		}
		n, err := s.raw.RecvBatch(bufs, lens)
		if err != nil {
			if s.closed.Load() {
				return
			}
			// recvmmsg 在 fd 被关闭/打断时返回错误：退避一下避免空转刷 CPU。
			time.Sleep(time.Millisecond)
			continue
		}
		// 逐个处理本轮收到的包。顺序保持内核给定顺序，
		// 与 handleIncoming 里的序号/时间戳推进语义一致。
		for i := 0; i < n; i++ {
			// 会话已关闭：剩下的一批直接丢掉（上面的循环窗口已缩小，
			// 真正的安全保证是 deliverOwned 里的 rxMu：这里只是少做无用功）。
			if s.closed.Load() {
				return
			}
			p, ok := ParseFrame(bufs[i][:lens[i]])
			if !ok {
				continue
			}
			if !s.matchPeer(p) {
				continue
			}
			s.handleIncoming(p)
		}
	}
}

// matchPeer 判断这个包是否属于本会话。
func (s *Session) matchPeer(p ParsedPacket) bool {
	return p.Src == s.peer.Addr() &&
		p.SrcPort == s.remotePort &&
		p.DstPort == s.localPort
}

// handleIncoming 处理一个属于本会话的包：更新 TCP 状态 + 解密交付。
//
// 客户端由自己的 recvLoop 调用；服务端由 Listener 的共享 recvLoop 调用。
// 两种模式下调用方都是单协程，但 WriteTo 可能在另一个协程里跑，
// 所以 TCP 状态更新必须持 s.mu。
func (s *Session) handleIncoming(p ParsedPacket) {
	// 记录收包时刻：只要收到对端的任何包（含纯 ACK），链路就是活的。
	// 更新时间放在最前面——连解密失败也要算「收到了包」，
	// 因为探活/保活关心的是链路可达性，不是业务数据。
	s.lastSeenAt.Store(time.Now().UnixNano())

	s.mu.Lock()
	// ack 只增不减：乱序时回退的 ack 会被中间设备当成非法包
	next := p.Seq + seqLen(p.Flags, len(p.Payload))
	if next-s.peerSeq < 0x8000_0000 {
		s.peerSeq = next
	}
	s.clock.Observe(p.TSVal, p.HasTS)
	if len(p.Payload) > 0 {
		s.ackPend++
	}
	// 延迟确认：累计 2 段立即确认，或已有积压且超 40ms 兜底。
	//
	// **第二个分支必须有 `ackPend > 0` 前提**，与 Rust 逐条对齐
	// （client.rs:808 / server.rs:501）。少了它，纯 ACK（无载荷）包也会
	// 每 40ms 触发一次额外 ACK：那些包对对端毫无意义，却会抢发送锁、
	// 挤满内核队列，把真正该及时发出的 ACK 拖慢。
	needACK := s.ackPend >= 2 ||
		(s.ackPend > 0 && time.Since(s.lastAck) >= 40*time.Millisecond)
	s.mu.Unlock()

	if len(p.Payload) == 0 {
		if needACK {
			s.sendPureACK()
		}
		return
	}
	s.pktsRecv.Add(1)
	// 解开每条 ApplicationData 记录。0x16 是表演握手，直接跳过。
	//
	// 用 ForEachRecord + OpenTo(池缓冲)：热路径零堆分配。
	// 实测 9000pps 量级下，旧写法（ParseRecords 切片 + AEAD 新分配）
	// 每秒产生 >20MB 垃圾，GC 停顿会直接拖慢收包。
	ForEachRecord(p.Payload, func(rec TlsRecord) bool {
		if rec.Type != RecAppData {
			return true
		}
		buf := bufPool.Get().(*[]byte)
		plain, ok := s.codec.OpenTo(*buf, rec.Payload)
		if !ok {
			bufPool.Put(buf)
			return true
		}
		// 能解开对端的包，说明对端已经用我们的 authID 找对密钥并鉴权通过。
		// 由此开始发送不再携带首包头（省 17 字节/包）。
		s.codec.MarkEstablished()
		// 明文已在池缓冲里，所有权转移给 deliverOwned，避免再拷贝一次。
		s.deliverOwned(plain)
		return true
	})
	// 延迟确认：累计 2 段立即确认，或超 40ms 兜底
	if needACK {
		s.sendPureACK()
	}
}
