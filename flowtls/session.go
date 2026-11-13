package flowtls

import (
	"context"
	"errors"
	"net"
	"net/netip"
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
	raw   *rawSocket
	codec *Codec

	// peer 是对端地址（客户端模式是服务端，服务端模式是客户端）
	peer netip.AddrPort
	// localPort 是本端端口，remotePort 是对端端口
	localPort  uint16
	remotePort uint16

	// TCP 状态。只由持有者（事件循环）访问，因此不需要原子操作：
	// raw socket 的读写分别在「接收协程」和「上层写」两个地方，
	// 但写方向只会有上层调用（quic-go 保证 WriteTo 串行），
	// 读方向的 TCP 状态更新全部在接收协程里做。
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
	// readDeadline 是读超时的绝对时刻（UnixNano），0 表示不超时。
	//
	// 用 atomic 而不是 sync.Mutex：这是每包都可能读一次的热路径值，
	// 而写入只发生在 quic-go 设置/清除 deadline 时（低频）。
	// 不必拆成「读锁 + 写锁」两套机制。
	readDeadline atomic.Uint64
	// once 保护「关闭动作」（sendFIN + close(closeCh)）
	once sync.Once
	// rxOnce 单独保护 close(rx)：Close 与接收协程退出都会走到这里，
	// 共用 once 会导致「先到者执行，后者再也无法关 rx」，
	// 让另一方永久阻塞在读通道上。
	rxOnce sync.Once

	// 收发缓冲复用。写侧由 quic-go 串行调用，读侧由接收协程独占。
	wRecord []byte
	wPkt    []byte

	// 统计（供上层日志用）
	pktsSent atomic.Uint64
	pktsRecv atomic.Uint64
	// rxDropped 统计因队列满而丢弃的包数（应为 0；非 0 说明背压链路断了）
	rxDropped atomic.Uint64
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
		putBack := data[:cap(data)]
		bufPool.Put(&putBack)
		return n, s.peerUDPAddr(), nil
	case <-s.closeCh:
		return 0, nil, net.ErrClosed
	}
}

// WriteTo 发送一个 QUIC 数据报。
func (s *Session) WriteTo(p []byte, addr net.Addr) (int, error) {
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	// 记录复用：稳态下零分配
	s.wRecord = s.codec.Seal(s.wRecord[:0], p)
	s.wPkt = s.appendSegment(s.wPkt[:0], s.wRecord, TCPPSH|TCPACK)
	if err := s.raw.Send(s.wPkt, s.peer.Addr()); err != nil {
		return 0, err
	}
	s.pktsSent.Add(1)
	return len(p), nil
}

// appendSegment 把 TLS 记录封装成一个 TCP 段（含 IP 头）。
func (s *Session) appendSegment(dst, payload []byte, flags uint8) []byte {
	seg := TcpSeg{
		Src:     s.raw.LocalIP,
		Dst:     s.peer.Addr(),
		SrcPort: s.localPort,
		DstPort: s.remotePort,
		Seq:     s.seq,
		Ack:     s.peerSeq,
		Flags:   flags,
		IPID:    s.ipid,
		Window:  AdvertisedWindow(len(s.rx)),
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
func (s *Session) sendPureACK() {
	if s.closed.Load() {
		return
	}
	s.ackPend = 0
	s.lastAck = time.Now()
	pkt := s.appendSegment(s.wPkt[:0], nil, TCPACK)
	// 纯 ACK 不占序号：appendSegment 已按 seqLen 判断，这里不用回退
	if err := s.raw.Send(pkt, s.peer.Addr()); err != nil {
		return
	}
	s.pktsSent.Add(1)
}

// sendFIN 发 FIN 拆除连接，让拆除过程像真实 TCP。
func (s *Session) sendFIN() {
	if s.closed.Load() {
		return
	}
	pkt := s.appendSegment(s.wPkt[:0], nil, TCPFIN|TCPACK)
	_ = s.raw.Send(pkt, s.peer.Addr())
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
		s.closed.Store(true)
		s.sendFIN()
		close(s.closeCh)
		// 关 rx 让上层仍阻塞在 ReadFrom 的调用同样被唤醒：
		// closeCh 只影响 select，而有数据分支可能先选中 rx。
		s.rxOnce.Do(func() { close(s.rx) })
		// 必须关 raw socket：recvLoop 阻塞在 raw.Recv 上，
		// 只标 closed 不会唤醒它（它不看标志，等的是 syscall 返回）。
		// 不关会泄漏一个 goroutine 和两个 fd。
		_ = s.raw.Close()
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
	select {
	case s.rx <- *buf:
	case <-s.closeCh:
		// 会话已关闭：归还缓冲后退出，不阻塞
		bufPool.Put(buf)
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

// closeRx 标记会话结束并唤醒阻塞的读取方（接收协程退出时调用）。
//
// 与 Close 共用 rxOnce，保证 rx 只被关一次。
func (s *Session) closeRx() {
	s.closed.Store(true)
	s.once.Do(func() { close(s.closeCh) })
	s.rxOnce.Do(func() { close(s.rx) })
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
	raw, err := newRawSocket(cfg.Server.Addr(), netip.Addr{})
	if err != nil {
		return nil, err
	}

	srcPort := cfg.SourcePort
	if srcPort == 0 {
		srcPort = 44300
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
	}
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
		ack := s.appendSegment(s.wPkt[:0], nil, TCPACK)
		if err := raw.Send(ack, s.peer.Addr()); err != nil {
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
				continue
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

// StartReceiver 启动常驻接收协程。
//
// 必须在握手完成后调用：握手阶段由 exchangeSyn 独占 raw socket。
// 单独暴露而不是在 Dial 里自动启动，是为了让调用方能在启动前完成
// quic.Transport 的装配，避免第一条包比 Transport 就绪还早到达。
func (s *Session) StartReceiver() {
	go s.recvLoop()
}

func (s *Session) recvLoop() {
	defer s.closeRx()
	buf := make([]byte, 65536)
	for {
		if s.closed.Load() {
			return
		}
		n, err := s.raw.Recv(buf)
		if err != nil {
			if s.closed.Load() {
				return
			}
			continue
		}
		p, ok := ParseFrame(buf[:n])
		if !ok {
			continue
		}
		if !s.matchPeer(p) {
			continue
		}
		s.handleIncoming(p)
	}
}

// matchPeer 判断这个包是否属于本会话。
func (s *Session) matchPeer(p ParsedPacket) bool {
	return p.Src == s.peer.Addr() &&
		p.SrcPort == s.remotePort &&
		p.DstPort == s.localPort
}

// handleIncoming 处理一个属于本会话的包：更新 TCP 状态 + 解密交付。
func (s *Session) handleIncoming(p ParsedPacket) {
	// ack 只增不减：乱序时回退的 ack 会被中间设备当成非法包
	next := p.Seq + seqLen(p.Flags, len(p.Payload))
	if next-s.peerSeq < 0x8000_0000 {
		s.peerSeq = next
	}
	s.clock.Observe(p.TSVal, p.HasTS)
	if len(p.Payload) > 0 {
		s.ackPend++
	}
	if len(p.Payload) == 0 {
		return
	}
	s.pktsRecv.Add(1)
	// 解开每条 ApplicationData 记录。0x16 是表演握手，直接跳过。
	for _, rec := range ParseRecords(p.Payload) {
		if rec.Type != RecAppData {
			continue
		}
		plain, ok := s.codec.Open(rec.Payload)
		if !ok {
			continue
		}
		// 能解开对端的包，说明对端已经用我们的 authID 找对密钥并鉴权通过。
		// 由此开始发送不再携带首包头（省 17 字节/包）。
		s.codec.MarkEstablished()
		s.deliver(plain)
	}
	// 延迟确认：累计 2 段立即确认，或超 40ms 兜底
	if s.ackPend >= 2 || time.Since(s.lastAck) >= 40*time.Millisecond {
		s.sendPureACK()
	}
}
