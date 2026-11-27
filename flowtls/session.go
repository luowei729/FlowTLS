package flowtls

// 本文件对应 legacy-rust:src/client.rs 的 `SendCtx` 结构，以及
// `run_session` 里「收包线程 + 三层握手」的部分。
//
// 为什么单独一个文件：quic-go 要求一个 `net.PacketConn`，而 quinn-proto 是
// 同步状态机、Rust 直接驱动。这一层是**库边界所必需的适配**，
// 不是设计选择，所以要把它的职责压到最小：
//
//	ReadFrom   ← Rust 收包线程投递的 payload（带 deadline 支持）
//	WriteTo    ← Rust 的 build_datagram + send_batch(n=1)，同步发送
//	Close      ← Rust 的 Drop + send_fin
//
// 明确**不做**的事（Go v1/v2 都在这里走过弯路）：
//   - 不排发送队列、不起 flush 协程：quic-go 在调用 WriteTo 之前就记录了
//     发送时刻，本地排队会被它算成网络 RTT（实测 213ms vs 链路 73ms）。
//   - 不做存活判定：Rust 没有 lastSeenAt / Probe，只有 QUIC idle timeout。

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// rxQueueDepth 是收包通道深度。
//
// **必须装得下整个 QUIC 连接级接收窗口**（quic 包的 receiveWindow = 16MB），
// 即 rxQueueDepth × 最小包长 ≥ 16MB。否则是死锁而不是普通背压：
//
//	对端按窗口把 16MB 发满
//	→ 队列（8192 × 1332 ≈ 10.9MB）先满
//	→ deliver 阻塞（这里不能丢包，丢了 quic-go 会误判已交付）
//	→ recvLoop 停：不再读 socket，也不再发纯 ACK
//	→ 对端的发送窗口等不到 MAX_DATA，永远不释放
//	→ 这条连接上的新流全部打不开，只能重启进程
//
// 真机（2026-11-17，端口 2002，无限刷新测速页）：
// 日志里每条都是「connection download closed: stream N canceled by local
// with error code 0」，随后新请求全部超时，而套接字队列是空的——
// 数据堵在用户态队列里，内核侧看不出来。
//
// 16384 × 1332 ≈ 21.8MB，比 16MB 窗口多 36%。
// 客户端只有 1 条会话；服务端按会话计。
// **不要照抄 Rust 的 8192**：Rust 侧 quinn 的窗口与这里不同。
const rxQueueDepth = 16384

// minQUICPayload 是一个 QUIC 包的最小净载荷（保守值）。
//
// 真实载荷通常更大，所以按它算出的容量是上界，
// 拿去和接收窗口比不会把不够装误判成够装。
const minQUICPayload = 1332

// RxQueueCapacity 返回收包队列能缓存的最大字节数。
//
// 导出是为了让 quic 包的单测能断言「队列容量 ≥ 连接级接收窗口」。
// 两个值分属不同的包，只写在注释里的话，以后改窗口的人不会想起改队列。
func RxQueueCapacity() int { return rxQueueDepth * minQUICPayload }

// Session 是一条伪造 TCP 连接，实现 quic-go 需要的 net.PacketConn。
type Session struct {
	raw   *rawSocket
	codec *Codec
	// logger 是诊断日志出口，恒非 nil（构造时经 loggerOr 归一）。
	//
	// 它来自 ClientConfig/ServerConfig.Logger，也就是 sing-box 的 logger，
	// 因此这里的每一行日志都受 `log.level` 控制。
	logger Logger
	// ownsRaw 表示本会话是否拥有 raw socket 的生命周期。
	//
	// **客户端必须显式设为 true**：Go 的 bool 零值是 false，而 false 的语义
	// 是「共享 socket，绝不关闭」。漏设会让每次重连泄漏 3 个 fd，
	// 其中接收 fd 带 8MB SO_RCVBUF 且仍在复制整机流量——
	// 表现为「跑一段时间后 RTT 逐步恶化」，而应用日志里毫无异常。
	//
	// 服务端所有会话共享 Listener 的 socket，绝不能在这里关。
	ownsRaw bool

	// autoPort 表示 localPort 是自动分配的，Close 时要归还。
	//
	// 不能把「归还」放在 Dial 的 defer 里：defer 在 Dial 返回时就执行，
	// 而 Dial 返回成功正是隧道要开始工作的时候 —— 那样端口会立刻被
	// 释放，另一个实例就能抢到同一个端口，四元组又撞车了。
	autoPort bool
	peer     netip.AddrPort
	// localPort 是本端端口，remotePort 是对端端口
	localPort  uint16
	remotePort uint16
	// localIP 是回包使用的源地址。空（零值）表示用 raw socket 的探测值。
	//
	// 为什么需要它：多 IP 主机（云主机的公网 IP + 内网 IP 都在同一张网卡上）
	// 时，路由探测只能拿到「内核默认选的那个源 IP」，不一定是客户端发往的
	// 那个地址。回包源 IP 一旦不对，客户端会把包当作无关流量丢掉。
	//
	// 服务端在收包时就已经知道对端发往的是哪个地址（ParsedPacket.Dst），
	// 直接沿用它就是**零配置且永远正确**的源地址。
	localIP netip.Addr

	// mu 保护下面所有 TCP 状态与写缓冲。
	//
	// quic-go 的发送协程调 WriteTo（改 seq/ipid）与我们的收包协程
	// 发纯 ACK 会并发，必须加锁。
	mu      sync.Mutex
	seq     uint32
	peerSeq uint32
	// peerISN 是对端 SYN 的序号，**创建后永不改变**。
	//
	// 服务端用它识别「四元组复用」：客户端源端口固定，重启后 SYN 的 ISN
	// 一定和旧会话不同。这是 Rust `conns.retain(|_, c| c.client != client)`
	// 在本移植里的等价判据——Rust 由 quinn 报 NewConnection 时清理，
	// 我们的分流是按四元组做的，所以要在握手一开始就判断。
	peerISN uint32
	ipid    uint16
	mark    uint16
	clock   *TcpClock
	ackPend int
	lastAck time.Time

	// rx 是已解密的 QUIC 数据报队列（Rust `pkt_rx` 的下游）
	rx      chan []byte
	closeCh chan struct{}
	closed  atomic.Bool
	once    sync.Once

	// ---- 发送队列（Rust `drain_transmits` + `send_batch` 的对应物）----
	//
	// 为什么要队列：单个 `sendto` 在真实 ONX 上非常贵（实测 Oracle ARM
	// 单包 34µs，一万多包/秒就把 1 核吃满），而 `sendmmsg` 一次带
	// 32 个包能把每包降到 20.6µs。Rust 的做法正是把本轮所有要发的报文
	// 收集到 `PacketBatch`，一次 `send_batch` 发出。
	//
	// **深度刻意很小**：它只是 quic-go 发送协程与发送协程之间的交接点，
	// 不是缓冲队列。发出协程一被唤醒就会把能拿到的一起发掉。
	// v1 的 4096 深队列把 RTT 从 73ms 抬到 213ms，那是队列自身积压造成的，
	// 与这里的「立即排空」语义完全不同。
	txCh   chan []byte
	txStop chan struct{}
	txDone chan struct{}
	txOnce sync.Once
	// txPool 复用发送缓冲：稳态下除 syscall 外零分配。
	// 容量要能装下 MTU 1500 + 以太网头余量，构包时 BuildPacketInto 会自己扩。
	txPool sync.Pool

	// ---- 三次握手状态（仅客户端使用）----
	//
	// 与 Rust 事件循环里的 `awaiting_syn_ack` + `next_syn_at` 等价：
	// 收包协程是唯一读 socket 的地方，所以把判定放在那里。
	synISN uint32
	// awaitingSYNACK 表示还在等 SYN-ACK（Rust `awaiting_syn_ack`）。
	// 等待期间**不得发送任何 QUIC 数据**，否则严格 NAT 会当成非法包丢弃。
	awaitingSYNACK atomic.Bool
	// handshakeDone 在握手完成时关闭，唤醒 exchangeSYN。
	handshakeDone chan struct{}
	onceHandshake sync.Once
	// sni 是伪 ClientHello 携带的 SNI（不参与握手校验）。
	sni string
	// readDeadline 是读超时的绝对时刻（UnixNano），0 表示不超时。
	//
	// quic-go 靠 SetReadDeadline 驱动握手超时与 idle 超时，
	// 空实现会让它永远不超时（DEVTIPS 里记录过：密码错误时永久挂起）。
	readDeadline atomic.Uint64

	// 收发缓冲复用（受 mu 保护）
	wRecord []byte
	// wPkt 是握手阶段的单包缓冲（ClientHello / ServerHello 直接发送时复用）。
	//
	// 稳态数据面**不能**用它：数据包要交给发送协程批量发出，缓冲在
	// 发出去之前不能被下一包覆盖，所以走 txPool 每包一块。
	wPkt []byte

	// 统计（供上层日志）
	pktsSent atomic.Uint64
	pktsRecv atomic.Uint64
	txErr    atomic.Uint64
	// rxShort 统计「明文比调用方缓冲长」的次数。
	//
	// 正常为 0：quic-go 提供的缓冲 >= MTU。非 0 说明缓冲假设被破坏，
	// 必须能看见（静默截断会让 QUIC 收到半个包）。
	rxShort atomic.Uint64
	// lastSeenAt 只用于日志/诊断，**不参与任何存活判定**
	// （Rust 没有存活判定，见文件头）。
	lastSeenAt atomic.Int64
}

// net.PacketConn 接口断言。编译期即可发现签名不一致。
var _ net.PacketConn = (*Session)(nil)

// timeoutError 是 net.Error 的最小实现，Timeout() 返回 true。
//
// quic-go 靠 `err.(net.Error).Timeout()` 区分「读超时」与真错误：
// 前者是正常的 deadline 到期，后者才需要上报。
type timeoutError struct{}

func (timeoutError) Error() string   { return "flowtls: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

var _ net.Error = timeoutError{}

// ReadFrom 读取一个 QUIC 数据报。
//
// 返回的 addr 恒为对端地址：伪造 TCP 是点对点的。
// **必须实现 deadline**：quic-go 把握手超时、idle 超时都挂在
// SetReadDeadline 上。
func (s *Session) ReadFrom(p []byte) (int, net.Addr, error) {
	// 快路径：已有数据就直接返回，避免每次读都创建 timer
	select {
	case data := <-s.rx:
		return s.finishRead(p, data), s.peerUDPAddr(), nil
	default:
	}

	if dl := s.readDeadline.Load(); dl != 0 {
		wait := time.Until(time.Unix(0, int64(dl)))
		if wait <= 0 {
			return 0, nil, timeoutError{}
		}
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case data := <-s.rx:
			return s.finishRead(p, data), s.peerUDPAddr(), nil
		case <-timer.C:
			return 0, nil, timeoutError{}
		case <-s.closeCh:
			return 0, nil, net.ErrClosed
		}
	}

	select {
	case data := <-s.rx:
		return s.finishRead(p, data), s.peerUDPAddr(), nil
	case <-s.closeCh:
		return 0, nil, net.ErrClosed
	}
}

// finishRead 把数据拷进调用方缓冲并记账。
//
// 拷贝长度以 p 的长度为上限（Rust 侧由 quinn 提供足够大的缓冲；
// quic-go 也会给 MTU 大小的缓冲，不会截断）。
func (s *Session) finishRead(p, data []byte) int {
	n := copy(p, data)
	if n < len(data) {
		// 截断是异常：quic-go 的缓冲应该 >= MTU。计数而不是静默。
		s.rxShort.Add(1)
	}
	return n
}

// txQueueDepth 是发送队列深度。
//
// 它只用于衔接「quic-go 发送协程」与「发送协程」，不是用来吸收积压的：
// 发送协程每次醒来都会把能拿到的一次性发完（最多 maxSendBatch 个）。
const txQueueDepth = 64

// txBufCap 是一个发送缓冲的初始容量（MTU 上限 + 余量）。
const txBufCap = 2048

// WriteTo 发送一个 QUIC 数据报（对应 Rust `build_datagram` + `send_batch`）。
//
// 构包在锁内完成（要推进 seq/ipid，必须串行），实际发包交给发送协程
// 批量发出——对应 Rust 的 `drain_transmits` 把报文攒进 `PacketBatch` 再
// 一次 `send_batch`。
func (s *Session) WriteTo(p []byte, addr net.Addr) (int, error) {
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	buf := s.getTxBuf()
	s.mu.Lock()
	s.wRecord = s.codec.SealInto(s.wRecord[:0], p)
	pkt := s.appendSegmentLocked(buf, s.wRecord, TCPPSH|TCPACK)
	s.mu.Unlock()

	// 与 Rust `drain_transmits` 一致：发送失败只记日志，不打断连接。
	// 返回错误会让 quic-go 的 sendQueue.Run 退出（整条连接失效），
	// 而伪 TCP 层的一次 send 失败往往是瞬时的。
	if !s.enqueueTx(pkt) {
		s.putTxBuf(pkt)
		return len(p), nil
	}
	return len(p), nil
}

// getTxBuf / putTxBuf 复用发送缓冲。
func (s *Session) getTxBuf() []byte {
	if v := s.txPool.Get(); v != nil {
		return v.([]byte)[:0]
	}
	return make([]byte, 0, txBufCap)
}

func (s *Session) putTxBuf(b []byte) {
	// 只回收容量合适的，避免把异常大的缓冲一直留在池里
	if cap(b) == txBufCap || cap(b) < 2*txBufCap {
		s.txPool.Put(b[:0]) //nolint:staticcheck // 存 []byte 进 sync.Pool 是既定用法
	}
}

// startTx 启动发送协程（幂等）。
func (s *Session) startTx() {
	s.txOnce.Do(func() {
		s.txCh = make(chan []byte, txQueueDepth)
		s.txStop = make(chan struct{})
		s.txDone = make(chan struct{})
		go s.txLoop()
	})
}

// enqueueTx 把构好的报文交给发送协程。
//
// 返回 false 表示会话正在关闭，调用方负责回收缓冲。
// 队列满时**阻塞**而不是丢弃：丢弃会让 QUIC 误判为链路丢包。
func (s *Session) enqueueTx(pkt []byte) bool {
	s.startTx()
	select {
	case s.txCh <- pkt:
		return true
	case <-s.closeCh:
		return false
	}
}

// txLoop 是发送协程：醒来后把队列里已有的报文凑成一批，一次 sendmmsg 发出。
//
// 与 Rust `drain_transmits` 一致：每轮最多 maxSendBatch 个，凑不满立即发，
// 不做任何等待或定时排空——凑批不能引入额外延迟。
func (s *Session) txLoop() {
	defer close(s.txDone)
	dst := s.peer.Addr()
	batch := make([][]byte, 0, maxSendBatch)
	for {
		var first []byte
		select {
		case <-s.txStop:
			s.flushTx(dst)
			return
		case first = <-s.txCh:
		}
		batch = append(batch[:0], first)
		// 非阻塞地再凑一些：队列里有就一起发，没有就立刻发
	fill:
		for len(batch) < maxSendBatch {
			select {
			case p := <-s.txCh:
				batch = append(batch, p)
			default:
				break fill
			}
		}
		if _, err := s.raw.SendBatch(batch, dst); err != nil {
			s.noteSendError(err)
		} else {
			s.pktsSent.Add(uint64(len(batch)))
		}
		for _, p := range batch {
			s.putTxBuf(p)
		}
	}
}

// flushTx 在退出前排空队列（Close 时 FIN 必须真的发出去）。
func (s *Session) flushTx(dst netip.Addr) {
	batch := make([][]byte, 0, maxSendBatch)
	for {
		select {
		case p := <-s.txCh:
			batch = append(batch, p)
			if len(batch) < maxSendBatch {
				continue
			}
		default:
		}
		if len(batch) == 0 {
			return
		}
		if _, err := s.raw.SendBatch(batch, dst); err != nil {
			s.noteSendError(err)
		} else {
			s.pktsSent.Add(uint64(len(batch)))
		}
		for _, p := range batch {
			s.putTxBuf(p)
		}
		batch = batch[:0]
	}
}

// noteSendError 记录发送失败，最多每秒打一条日志（避免刷屏）。
func (s *Session) noteSendError(err error) {
	// 关闭后的发送失败是正常路径（Close 与收包协程发纯 ACK 存在竞态），
	// 不能计入链路故障。
	if errors.Is(err, errSocketClosed) || errors.Is(err, net.ErrClosed) {
		return
	}
	n := s.txErr.Add(1)
	if n == 1 || n%1000 == 0 {
		s.logger.Error("发送失败（累计 ", n, " 次）: ", err)
	}
}

// appendSegmentLocked 把 TLS 记录封装成一个 TCP 段（含 IP 头）。
// 调用方必须持有 s.mu。对应 Rust `SendCtx::build_datagram` 的报文部分。
func (s *Session) appendSegmentLocked(dst, payload []byte, flags uint8) []byte {
	seg := TcpSeg{
		Seq:   s.seq,
		Ack:   s.peerSeq,
		Flags: flags,
		IPID:  s.ipid,
		// 窗口随未读包数变化：恒为 65535 是明显的伪造特征。
		// unread 用「已投递但未被 ReadFrom 取走的包数 × 1400」估算，
		// 与 Rust 事件循环里 `streams.pending + pkt_rx.len()*1400` 同口径。
		Window:  AdvertisedWindow(len(s.rx) * 1400),
		TSVal:   s.clock.TSVal(),
		TSecr:   s.clock.PeerTS,
		Payload: payload,
	}
	// 源地址：会话若自带就用它（服务端从入包目的地址继承而来），
	// 否则回落到 raw socket 的路由探测值（客户端的正常路径）。
	src := s.localIP
	if !src.IsValid() {
		src = s.raw.localIP
	}
	dst = BuildPacketInto(dst, src, s.peer.Addr(),
		s.localPort, s.remotePort, seg)
	// TCP 语义：序号按载荷推进
	s.seq += seqLen(flags, len(payload))
	s.ipid = NextIPID(s.mark, s.ipid)
	return dst
}

// sendPureACK 发一个纯 ACK（无载荷）。
//
// 真实 TCP 是双向确认的：下载方向必须有反向纯 ACK，否则一眼就是伪造。
// ACK 与数据走**同一个队列**，否则 ACK 可能越过数据发出，
// 序号就倒挂了。
func (s *Session) sendPureACK() {
	if s.closed.Load() {
		return
	}
	buf := s.getTxBuf()
	s.mu.Lock()
	s.ackPend = 0
	s.lastAck = time.Now()
	pkt := s.appendSegmentLocked(buf, nil, TCPACK)
	s.mu.Unlock()
	if !s.enqueueTx(pkt) {
		s.putTxBuf(pkt)
	}
}

// sendFIN 发 FIN 拆除连接，让拆除过程像真实 TCP（对应 Rust `send_fin`）。
func (s *Session) sendFIN() {
	if s.closed.Load() {
		return
	}
	buf := s.getTxBuf()
	s.mu.Lock()
	pkt := s.appendSegmentLocked(buf, nil, TCPFIN|TCPACK)
	s.mu.Unlock()
	if !s.enqueueTx(pkt) {
		s.putTxBuf(pkt)
	}
}

// Close 关闭会话（对应 Rust 的 `Drop for SendCtx` + `send_fin`）。
//
// 顺序要求：先发 FIN（让线上像正常拆连），再置 closed、唤醒所有阻塞方、
// 最后关 raw socket（客户端独占）。
func (s *Session) Close() error {
	s.once.Do(func() {
		// 发送协程必须先起来：sendFIN 要靠它把 FIN 真的发出去，
		// 而从未发送过数据的会话还没启动过它。
		s.startTx()
		s.sendFIN()
		s.closed.Store(true)
		close(s.closeCh)
		// 通知发送协程排空后退出，并等它把 FIN 发完（有上限，不无限等）。
		close(s.txStop)
		select {
		case <-s.txDone:
		case <-time.After(200 * time.Millisecond):
		}
		// 只在自己拥有 socket 时才关。
		//
		// 客户端每个 Session 独占一个 rawSocket（3 个 fd），必须有归属方；
		// 服务端所有会话共享 Listener 的 socket，绝不能在这里关。
		if s.ownsRaw {
			_ = s.raw.Close()
		}
		// 归还自动分配的源端口。放在最后：先关 socket 再放端口，
		// 避免新会话拿到端口时旧 socket 还在往同一个四元组发包。
		if s.autoPort {
			ReleaseSourcePort(s.localPort)
		}
	})
	return nil
}

// LocalAddr 返回本端地址。
func (s *Session) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(s.raw.localIP, s.localPort))
}

// peerUDPAddr 返回对端地址的 net.Addr 视图（每次分配一个，量很小）。
func (s *Session) peerUDPAddr() net.Addr {
	return net.UDPAddrFromAddrPort(s.peer)
}

// RemoteAddr 返回对端地址。quic.Transport 的 Dial 需要它作为目的地址。
func (s *Session) RemoteAddr() net.Addr {
	return net.UDPAddrFromAddrPort(s.peer)
}

// SendMode 返回底层发送路径描述（供上层记启动日志）。
func (s *Session) SendMode() string {
	if s.raw == nil {
		return "none"
	}
	return s.raw.SendMode()
}

// idleFor 返回距最后一次收到对端包已过去多久（供服务端空闲回收使用）。
//
// 与 Rust 服务端一致：按「多久没收到任何包」判断死活
// （UDP 无连接，客户端可能直接消失）。零值视为刚建立。
func (s *Session) idleFor() time.Duration {
	v := s.lastSeenAt.Load()
	if v == 0 {
		return 0
	}
	return time.Since(time.Unix(0, v))
}

// SetDeadline 实现 net.PacketConn。
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
// 写方向不需要真实现：底层 sendto 在阻塞 fd 上是同步完成的
// （Rust 同样没有写超时），这里只接受值不做事，避免调用方因返回错误中断。
func (s *Session) SetWriteDeadline(t time.Time) error { return nil }

// StartReceiver 启动常驻收包协程（对应 Rust 的收包线程）。
//
// 必须在握手完成后调用：握手阶段由 Dial 独占 raw socket。
func (s *Session) StartReceiver() {
	go s.recvLoop()
}

// recvBufSize 是收包缓冲大小。
//
// Rust 用 `vec![0u8; 65536]`，但那正好是 GRO 聚合后的上限：一个 skb
// 带上 IP/TCP 头后可以超过 64KB，`recvfrom` 就会**静默截断**，包因此消失。
// 实测（Go×Go 真链路）表现为吞吐只有对端实现的 一半、且抓包可见周期
// 50~160ms 的停顿（截断 → QUIC 重传），而 `lost` 计数恒为 0。
//
// 取 256KB 并配 `MSG_TRUNC` 检测（见 socket_linux.go 的 Recv），
// 与 AGENTS.md 约束 15 一致。
const recvBufSize = 256 * 1024

// maxRecvBatch 是单轮最多消化的收包帧数（Rust `while batch.len() < 256`）。
//
// 为什么要批量：Rust 的事件循环是「阻塞收 1 帧 + 非阻塞再凑最多 256 帧」，
// 一轮结束才做一次延迟确认判定。逐帧独立处理时，256 个数据帧会触发
// 128 次纯 ACK 发送（每 2 帧一次），回程包数量凭空翻倍；Rust 里同样的
// 256 帧只发 1 个纯 ACK。这不是「优化」，而是对齐 Rust 的既有行为
// （见 `client.rs:754` / `server.rs:456` 的注释）。
const maxRecvBatch = 256

// recvSlotCount 是一次 recvmmsg 最多带多少个槽位。
//
// 与接收批量（maxRecvBatch=256）解耦：一轮排空会连续调几次 recvmmsg。
// 取 8 是把 syscall 数直接降到 1/8，而内存代价可控（见 recvSlotCap）。
const recvSlotCount = 8

// recvSlotCap 是单个槽位的缓冲容量。
//
// **不能等于 recvBufSize（256KB）**：8 × 256KB = 2MB/会话，服务端多会话时
// 内存会失控。取 128KB 是折中——网卡 GRO 的聚合上限通常是 64KB
// （`GRO_MAX_SIZE`），128KB 留了一倍余量，同时 8 槽位共 1MB/会话。
//
// 若某个极端聚合包真的超过 128KB，会被 MSG_TRUNC 检测到（计数 + 一次性
// Warn），由 QUIC 重传覆盖；看到那条告警就设置 FLOWTLS_RECVMMSG=0 关掉批量。
const recvSlotCap = 128 * 1024

// recvSlots 是批量收包用的槽位集合（调用方复用，稳态零分配）。
//
// 每个槽位独立缓冲而不是共用一块：recvmmsg 要把 8 个不同的 iovec 交给内核，
// 共用一块会让 8 个报文写进同一地址互相覆盖。
type recvSlots struct {
	bufs [recvSlotCount][]byte
	lens [recvSlotCount]int
}

// newRecvSlots 分配槽位。只在开启批量收包时调用（关闭时零内存开销）。
func newRecvSlots() *recvSlots {
	r := &recvSlots{}
	for i := range r.bufs {
		r.bufs[i] = make([]byte, recvSlotCap)
	}
	return r
}

// recvResult 是收包协程交给循环的一帧。frame 为 nil 表示这次读取失败。
//
// h 是这一帧的注入句柄（见 frameHandle），与 frame 严格配对：
// 收包协程在 Recv 之后**立刻**取快照，再由 channel 一起交出去。
//
// **Session 这条路径从不填 h，这是有意的**：只有服务端需要「把不是本协议的包
// 还给内核」（伪装站共存），而服务端的收包全部在 Listener 里完成（约束：
// Session 在服务端不启动 recvLoop）。客户端扣留下来的包都是自己的，丢弃才是
// 正确动作，也就不需要句柄。
type recvResult struct {
	frame []byte
	h     frameHandle
	err   error
}

// recvLoop 是收包协程：读原始帧 → 过滤 → 解密 → 投递（对应 Rust 收包线程）。
//
// Rust 侧顺序：`raw_recv.recv(&mut buf)` → `parse_frame` → 端口/IP 过滤 →
// `pkt_tx.blocking_send((seq, flags, tsval, payload))`，
// 而后由事件循环「一轮最多 256 帧」统一消化并做一次延迟确认。
// 这里因为要先解密再交给 quic-go，所以把「解密」也放在本协程完成，
// 但**收包的批量边界与延迟确认判定点严格照搬 Rust**。
func (s *Session) recvLoop() {
	buf := make([]byte, recvBufSize)
	// 批量收包的槽位：仅当 FLOWTLS_RECVMMSG=1 时分配（否则零内存开销）。
	var slots *recvSlots
	if recvBatchEnabled() {
		slots = newRecvSlots()
	}
	// 纯 ACK 不能只在「下一个包到达」时才判断。
	//
	// 下载时服务端一次发来一批数据，客户端要回 TCP ACK，QUIC 才算得到 RTT。
	// 原来 flushDelayedACK 只在 Recv 返回后调用。单个响应之后没有下一个包，
	// ACK 就一直攒着，直到保活或下一次请求。抓包量到这段是 221ms，
	// 而服务端自己从收到请求到发出响应只有 26ms（2026-11-14 两端对抓）。
	// 这里用 5ms 把阻塞的 Recv 截断一次：没有新包也把已经到期的 ACK 发出去。
	// fd 仍是阻塞的，超时由单独的计时器负责，不碰 socket 选项。
	frames := make(chan recvResult, recvHandoffDepth)
	go func() {
		scratch := make([]byte, recvBufSize)
		for {
			n, err := s.raw.Recv(scratch)
			var frame []byte
			if err == nil && n > 0 {
				frame = make([]byte, n)
				copy(frame, scratch[:n])
			}
			select {
			case frames <- recvResult{frame: frame, err: err}:
			case <-s.closeCh:
				return
			}
			if s.closed.Load() {
				return
			}
		}
	}()
	wake := time.NewTimer(5 * time.Millisecond)
	defer wake.Stop()
	for {
		if s.closed.Load() {
			return
		}
		var res recvResult
		got := false
		select {
		case res = <-frames:
			got = true
		case <-wake.C:
		case <-s.closeCh:
			return
		}
		if !wake.Stop() {
			select {
			case <-wake.C:
			default:
			}
		}
		wake.Reset(5 * time.Millisecond)
		if !got {
			s.flushDelayedACK()
			continue
		}
		n, err := len(res.frame), res.err
		if n > 0 {
			copy(buf[:n], res.frame)
		}
		if err != nil {
			if s.closed.Load() {
				return
			}
			// 与 Rust 一致：读失败告警后退避 10ms，避免空转刷 CPU。
			s.logger.Error("raw recv 失败: ", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		// 第一帧（阻塞取到的那一帧）
		s.recvFrame(buf[:n])
		// 把 socket 队列里已经到达的帧一起消化，最多再取 maxRecvBatch-1 帧
		s.drainAvailable(buf, slots)
		// 一轮收包结束才判定一次延迟确认（对应 Rust 批末的 `due` 判定）
		s.flushDelayedACK()
	}
}

// drainAvailable 非阻塞地把已到达的帧取干并处理（每轮最多 maxRecvBatch 帧）。
//
// 两条路径，由 FLOWTLS_RECVMMSG 选择（默认逐帧）：
//
//	逐帧   i 次 recvfrom
//	批量   ceil(i/8) 次 recvmmsg
//
// **主循环结构不变**：不论走哪条路，本函数都在处理完即返回，
// 5ms 心跳（延迟确认的唯一发送机会）不受影响。
// 这一点是上一轮把它误判成 RTT 恶化原因时没做对的地方——
// 当时的顾虑是「批量会让主循环长时间不回到 select」，
// 但真正的判据是「本函数有没有提前返回」，而不是「用了几个 syscall」。
//
// slots 为 nil（关闭批量）时走逐帧路径。
func (s *Session) drainAvailable(buf []byte, slots *recvSlots) {
	if slots != nil {
		s.drainBatch(slots)
		return
	}
	for i := 1; i < maxRecvBatch; i++ {
		if s.closed.Load() {
			return
		}
		n, ok, err := s.raw.recvAvailable(buf)
		if err != nil {
			if !s.closed.Load() {
				s.logger.Error("raw recv 失败: ", err)
			}
			return
		}
		if !ok {
			// 队列已空（或本帧被截断丢弃）：本轮结束
			return
		}
		s.recvFrame(buf[:n])
	}
}

// drainBatch 是批量版本的 drainAvailable。
func (s *Session) drainBatch(slots *recvSlots) {
	for done := 1; done < maxRecvBatch; {
		if s.closed.Load() {
			return
		}
		n, err := s.raw.recvBatch(slots)
		if err != nil {
			if !s.closed.Load() {
				s.logger.Error("raw recv 失败: ", err)
			}
			return
		}
		if n == 0 {
			return // 队列已空：本轮结束
		}
		for i := 0; i < n; i++ {
			if slots.lens[i] <= 0 {
				continue // -1 = 超过槽位被截断（已计数）
			}
			s.recvFrame(slots.bufs[i][:slots.lens[i]])
		}
		done += n
	}
}

// recvFrame 处理一帧原始报文：解析 → 过滤 → 握手判定或数据投递。
//
// 对应 Rust 收包线程里的 `parse_frame` + 两个过滤条件。
func (s *Session) recvFrame(raw []byte) {
	p, ok := ParseFrame(raw)
	if !ok {
		return
	}
	// 先做端口/IP 过滤，避免把无关流量送进解密路径
	if !s.matchPeer(p) {
		return
	}
	// 等待 SYN-ACK 阶段：先完成三次握手，这个包不再送进 QUIC。
	if s.awaitingSYNACK.Load() && s.isSYNACKFor(p) {
		s.handleSYNACK(p)
		return
	}
	s.handleIncoming(p)
}

// matchPeer 判断这个包是否属于本会话。
//
// 与 Rust 收包线程的三个条件一致：源端口 == 对端端口、目的端口 == 本端端口、
// 源 IP == 对端 IP。
func (s *Session) matchPeer(p ParsedPacket) bool {
	return p.Src == s.peer.Addr() &&
		p.SrcPort == s.remotePort &&
		p.DstPort == s.localPort
}

// handleIncoming 处理一个属于本会话的包：更新 TCP 状态 + 解密交付。
//
// 对应 Rust `handle_incoming`：只处理 ApplicationData 记录，
// 0x16 的握手表演包直接忽略。
//
// **本协议从不发 RST**（只有 SYN/SYN-ACK/ACK/PSH/FIN），所以载荷为空的包
// （例如对端内核回的 RST）自然在 `parse_records` 后得到零条记录而被丢弃，
// 不做任何「存活」推断——Rust 也没有。
func (s *Session) handleIncoming(p ParsedPacket) {
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
	s.mu.Unlock()

	// 纯 ACK 帧（无载荷）到此为止：延迟确认不在逐帧路径里判定，
	// 统一放到「一轮收包结束」的 flushDelayedACK，
	// 与 Rust 把 `due` 判定放在整批之后（`client.rs:815` / `server.rs:501`）一致。
	if len(p.Payload) == 0 {
		return
	}
	s.pktsRecv.Add(1)
	for _, rec := range ParseRecords(p.Payload) {
		if rec.Type != RecAppData {
			continue
		}
		// 首包（服务端方向不会带首包头，但客户端方向会）：
		// 先尝试 OpenFirst，失败再按后续包解——两个方向的会话共用本函数。
		plain, ok := s.codec.OpenFirst(rec.Payload)
		if !ok {
			plain, ok = s.codec.Open(rec.Payload)
		}
		if !ok {
			continue
		}
		// 能解开对端的包，说明对端已用我们的 authID 找对密钥并鉴权通过。
		// 由此开始发送不再携带首包头（省 17 字节/包）。
		s.codec.MarkEstablished()
		s.deliver(plain)
	}
}

// flushDelayedACK 在一轮收包结束时判定一次延迟确认（对应 Rust 批末的 `due`）。
//
// 规则与 Rust `client.rs:815` / `server.rs:501` 逐条一致：
// 累计 2 个数据段立即确认，或距上次确认超过 40ms（真实 Linux 的延迟确认上限）。
//
// 第二个分支必须有 `ackPend > 0` 前提：少了它，纯 ACK 帧也会每 40ms
// 触发一次额外 ACK，抢发送机会并挤占内核队列。
//
// 注意判定点：Rust 在「一整批（最多 256 帧）处理完」之后才判一次，
// 所以高包速率下一批只产生 1 个纯 ACK。逐帧判定会把这 1 个变成 128 个。
func (s *Session) flushDelayedACK() {
	s.mu.Lock()
	due := s.ackPend >= 2 ||
		(s.ackPend > 0 && time.Since(s.lastAck) >= 40*time.Millisecond)
	s.mu.Unlock()
	if due {
		s.sendPureACK()
	}
}

// deliver 把解密后的数据报投进 rx（对应 Rust `pkt_tx.blocking_send`）。
//
// **阻塞投递，不丢包**：伪造 TCP 之上跑 QUIC，如果在这里丢，quic-go 会以为
// 包已交付——既不发 ACK 也不重传，只能靠服务端 PTO 盲猜。
// 队列满时阻塞，背压由内核 socket 缓冲区承担（Rust 完全相同）。
func (s *Session) deliver(payload []byte) {
	// 必须拷贝：payload 指向接收缓冲，下一轮会被覆盖。
	buf := make([]byte, len(payload))
	copy(buf, payload)
	select {
	case s.rx <- buf:
	case <-s.closeCh:
		// 会话已关闭：直接丢弃，不阻塞退出
	}
}
