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
	once    sync.Once

	// 收发缓冲复用。写侧由 quic-go 串行调用，读侧由接收协程独占。
	wRecord []byte
	wPkt    []byte

	// 统计（供上层日志用）
	pktsSent atomic.Uint64
	pktsRecv atomic.Uint64
}

// net.PacketConn 接口断言。编译期即可发现签名不一致。
var _ net.PacketConn = (*Session)(nil)

// ReadFrom 读取一个 QUIC 数据报。
//
// 返回的 addr 恒为对端地址：伪造 TCP 是点对点的，不存在「一个 socket 收
// 多个对端」的场景，quic-go 也只是拿它做日志和连接标识。
func (s *Session) ReadFrom(p []byte) (int, net.Addr, error) {
	// 快路径：已经有数据就直接返回
	select {
	case data, ok := <-s.rx:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		return copy(p, data), s.peerUDPAddr(), nil
	default:
	}
	select {
	case data, ok := <-s.rx:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		return copy(p, data), s.peerUDPAddr(), nil
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
func (s *Session) Close() error {
	s.once.Do(func() {
		s.closed.Store(true)
		s.sendFIN()
		close(s.closeCh)
		// rx 由接收协程关闭：这里不能直接关，否则接收协程再发会 panic
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

// SetDeadline 实现 net.PacketConn。quic-go 用它做 idle timeout。
func (s *Session) SetDeadline(t time.Time) error      { return nil }
func (s *Session) SetReadDeadline(t time.Time) error  { return nil }
func (s *Session) SetWriteDeadline(t time.Time) error { return nil }

// deliver 由接收协程调用：把解密后的数据报投进 rx。
//
// 通道满就丢：这是 UDP 语义，QUIC 自己会重传关键帧。
// 若改成阻塞，接收协程会被上层拖死，整条连接的所有流一起卡住。
func (s *Session) deliver(payload []byte) {
	// 必须拷贝：payload 指向接收缓冲，下一轮会被覆盖
	buf := make([]byte, len(payload))
	copy(buf, payload)
	select {
	case s.rx <- buf:
	default:
		// 队列满：丢弃并记一次（UDP 语义，与 hysteria2 一致）
	}
}

// closeRx 关闭接收通道（只允许接收协程调用一次）。
func (s *Session) closeRx() {
	s.once.Do(func() {
		// 只有接收协程会走到这里时 Close 还没执行过
		s.closed.Store(true)
		close(s.closeCh)
		close(s.rx)
	})
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
		rx:         make(chan []byte, 256),
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
