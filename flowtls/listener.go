package flowtls

// 本文件对应 legacy-rust:src/server.rs 的这几部分：
//
//	run() 里「raw socket + 收包线程 + 分流」
//	handle_packet()：纯 SYN / 已有连接 / 首包三条路径
//	syn_pending：SYN 与首包之间的临时握手状态
//
// 服务端的三个结构性决定（与 Rust 一致）：
//
//  1. **共享一个 raw socket**（不是每客户端一个）：每个 AF_PACKET socket
//     带 8MB 接收缓冲，100 个客户端就是 800MB 内核内存。
//  2. **一个收包协程**按四元组分发：收包路径只有一处，调试时看日志就知道
//     每个包去了哪。
//  3. **每客户端一个 Session**：QUIC 与伪造 TCP 都要求 seq/ack 是连续
//     字节流，多个客户端共用一个 Session 会让序号互相拉扯。

import (
	"context"
	"errors"
	"log"
	"net/netip"
	"sync"
	"time"
)

// synState 是收到 SYN 后、首包到达前的临时状态。
//
// 三样信息必须一起存：
//   - peerISN：回 SYN-ACK 时用的 ack；
//   - ourISN：SYN-ACK 的 seq（首包响应必须紧接着它，序号才连续）；
//   - ts：SYN-ACK 用的 TSval（后续包的 TSval 必须不小于它，
//     否则时间戳类 DPI 一眼看出回退）。
//
// 与 Rust `SynState` 逐字段一致。
type synState struct {
	peerISN uint32
	ourISN  uint32
	ts      uint32
	at      time.Time
}

// synStateTTL 是 pending 复用窗口（Rust `s.at.elapsed() < 10s`）。
const synStateTTL = 10 * time.Second

// ListenerOptions 是 NewListener 的参数。
type ListenerOptions struct {
	// IdleTimeout 是单条会话的空闲回收时间，默认 120s。
	IdleTimeout time.Duration
	// HandshakeTimeout 是 SYN 到首包的等待上限，默认 5s。
	HandshakeTimeout time.Duration
	// AcceptQueue 是待上层接管的会话队列长度，默认 64。
	AcceptQueue int
}

// Listener 是服务端入口：接收伪造 TCP 连接并交给上层（quic.Transport）。
type Listener struct {
	raw   *rawSocket
	users *userTable
	port  uint16
	mark  uint16

	idleTimeout      time.Duration
	handshakeTimeout time.Duration

	mu sync.RWMutex
	// byAddr 是四元组 → 会话。服务端所有包的查表依据。
	byAddr map[netip.AddrPort]*Session
	// pending 是「已回 SYN-ACK、还没收到首包」的中间状态。
	pending map[netip.AddrPort]*synState

	acceptCh    chan *Session
	sessionDone chan netip.AddrPort

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// NewListener 绑定端口并启动收包协程。
//
// 会立刻申请 raw socket（需要 root 或 CAP_NET_RAW），因此适配层必须在
// Start(StartStateStart) 里调用，绝不能在 NewInbound 里——否则
// `sing-box check` 也会要求 root。
func NewListener(cfg ServerConfig, opts ListenerOptions) (*Listener, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 120 * time.Second
	}
	if opts.HandshakeTimeout <= 0 {
		opts.HandshakeTimeout = 5 * time.Second
	}
	if opts.AcceptQueue <= 0 {
		opts.AcceptQueue = 64
	}

	users, err := newUserTable(mustEffectiveUsers(&cfg))
	if err != nil {
		return nil, err
	}

	// 探测用的目的地址**不能是监听地址**。
	//
	// 服务端 listen 通常是 0.0.0.0，拿它去查路由/网关 MAC 必然失败：
	// 0.0.0.0 没有下一跳。与 Rust 一致：固定用 8.8.8.8（必然走默认路由）。
	dst := netip.MustParseAddr("8.8.8.8")
	raw, err := newRawSocket(dst, cfg.LocalIP)
	if err != nil {
		return nil, err
	}

	// 规则的作用是「让内核别碰我们的伪包」。
	// 顺序理由：先有能收包的能力，再去改防火墙，失败时顺序可回退。
	if cfg.NetMode == ModeAuto {
		if err := EnsureServer(cfg.Listen.Port(), cfg.IPIDMark); err != nil {
			_ = raw.Close()
			return nil, err
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	l := &Listener{
		raw:              raw,
		users:            users,
		port:             cfg.Listen.Port(),
		mark:             IPIDMarkOf(cfg.IPIDMark),
		idleTimeout:      opts.IdleTimeout,
		handshakeTimeout: opts.HandshakeTimeout,
		byAddr:           make(map[netip.AddrPort]*Session),
		pending:          make(map[netip.AddrPort]*synState),
		acceptCh:         make(chan *Session, opts.AcceptQueue),
		sessionDone:      make(chan netip.AddrPort, opts.AcceptQueue),
		ctx:              ctx,
		cancel:           cancel,
	}
	if l.mark == 0 {
		l.mark = IPIDMark
	}

	l.wg.Add(2)
	go l.recvLoop()
	go l.maintainLoop()
	return l, nil
}

// mustEffectiveUsers 取实际生效的用户表（Validate 已保证非空）。
func mustEffectiveUsers(cfg *ServerConfig) []User {
	users, err := cfg.effectiveUsers()
	if err != nil || len(users) == 0 {
		// Validate 已校验过，这里只是防御。
		return nil
	}
	return users
}

// Addr 返回监听地址。
func (l *Listener) Addr() netip.AddrPort {
	return netip.AddrPortFrom(l.raw.localIP, l.port)
}

// LocalIP 返回对外使用的源 IP。
func (l *Listener) LocalIP() netip.Addr { return l.raw.localIP }

// SendMode 返回底层发送路径描述，供上层记启动日志。
func (l *Listener) SendMode() string { return l.raw.SendMode() }

// Users 返回用户表大小（供启动日志展示）。
func (l *Listener) Users() int { return l.users.len() }

// Accept 阻塞等待一条已鉴权的会话。
//
// 返回的 Session 已经解出过首包（用户身份已验证），可以直接交给
// quic.Transport 使用。调用方负责在结束时 Close 它。
func (l *Listener) Accept(ctx context.Context) (*Session, error) {
	select {
	case s := <-l.acceptCh:
		return s, nil
	case <-l.ctx.Done():
		return nil, ErrSessionClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close 关闭监听并释放所有会话。
func (l *Listener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		l.cancel()
		// 关 raw socket 会唤醒阻塞在 Recv 上的 recvLoop
		err = l.raw.Close()
	})
	l.wg.Wait()

	l.mu.Lock()
	sessions := make([]*Session, 0, len(l.byAddr))
	for _, s := range l.byAddr {
		sessions = append(sessions, s)
	}
	l.byAddr = make(map[netip.AddrPort]*Session)
	l.pending = make(map[netip.AddrPort]*synState)
	l.mu.Unlock()

	for _, s := range sessions {
		_ = s.Close()
	}
	return err
}

// recvLoop 是唯一的收包协程：读帧 → 解析 → 按四元组分发。
//
// 对应 Rust 的收包线程 + 事件循环里的批量消化：
// 阻塞收 1 帧，再把已到达的帧一起取干（每轮最多 maxRecvBatch 帧），
// **一轮结束才对本轮触达的会话各做一次延迟确认判定**——
// 与 Rust `server.rs:456` 的「批末统一 `due` 判定」逐条一致。
func (l *Listener) recvLoop() {
	defer l.wg.Done()
	buf := make([]byte, recvBufSize)
	// touched 是本轮收包触达的会话。用切片而不是集合：
	// 同一会话重复出现只是多调一次 flushDelayedACK（第二次 ackPend 已清零，
	// 天然幂等），换来的是热路径零 map 操作。
	touched := make([]*Session, 0, 16)
	// 与 Session.recvLoop 同一原因，方向相反：
	// 服务端收到客户端的一个请求后要回 TCP ACK。只在下一个包到达时判断的话，
	// 这个 ACK 会一直攒到保活包。两端对抓（2026-11-14）：
	// 客户端请求到达服务端后，服务端的 TCP ACK 是 221ms 后才离开本机网卡，
	// 而服务端自己的网卡上 0.08ms 就发出了。差额是客户端看到的时间，
	// 因为客户端同样把 ACK 压着；服务端这一侧用同一个 5ms 截断补上。
	frames := make(chan recvResult, 1)
	go func() {
		scratch := make([]byte, recvBufSize)
		for {
			n, err := l.raw.Recv(scratch)
			var frame []byte
			if err == nil && n > 0 {
				frame = make([]byte, n)
				copy(frame, scratch[:n])
			}
			select {
			case frames <- recvResult{frame, err}:
			case <-l.ctx.Done():
				return
			}
			if l.ctx.Err() != nil {
				return
			}
		}
	}()
	wake := time.NewTimer(5 * time.Millisecond)
	defer wake.Stop()
	for {
		if l.ctx.Err() != nil {
			return
		}
		var res recvResult
		got := false
		select {
		case res = <-frames:
			got = true
		case <-wake.C:
		case <-l.ctx.Done():
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
			for _, sess := range touched {
				sess.flushDelayedACK()
			}
			touched = touched[:0]
			continue
		}
		n, err := len(res.frame), res.err
		if n > 0 {
			copy(buf[:n], res.frame)
		}
		if err != nil {
			if l.ctx.Err() != nil {
				return
			}
			log.Printf("flowtls: raw recv 失败: %v", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if sess := l.recvFrame(buf[:n]); sess != nil {
			touched = append(touched, sess)
		}
		touched = l.drainAvailable(buf, touched)
		// 一轮收包结束：对本轮触达的会话各判定一次延迟确认
		for _, sess := range touched {
			sess.flushDelayedACK()
		}
		touched = touched[:0]
	}
}

// drainAvailable 非阻塞地把已到达的帧取干并处理（每轮最多 maxRecvBatch 帧）。
//
// 与 Session.drainAvailable 同构；服务端是共享 socket，
// 一轮里可能触达多个会话，所以把 session 收集在外层。
func (l *Listener) drainAvailable(buf []byte, touched []*Session) []*Session {
	for i := 1; i < maxRecvBatch; i++ {
		if l.ctx.Err() != nil {
			return touched
		}
		n, ok, err := l.raw.recvAvailable(buf)
		if err != nil {
			if l.ctx.Err() == nil {
				log.Printf("flowtls: raw recv 失败: %v", err)
			}
			return touched
		}
		if !ok {
			// 队列已空（或本帧被截断丢弃）：本轮结束
			return touched
		}
		if sess := l.recvFrame(buf[:n]); sess != nil {
			touched = append(touched, sess)
		}
	}
	return touched
}

// recvFrame 解析一帧并分发给 handlePacket。
//
// 返回被投递数据帧的会话（供批末做延迟确认）；SYN / 首包路径不需要确认，
// 返回 nil。
func (l *Listener) recvFrame(raw []byte) *Session {
	p, ok := ParseFrame(raw)
	if !ok {
		return nil
	}
	// 只处理发往本端口的包。绑定的是 AF_PACKET（收到整机所有 IP 包），
	// 不过滤会把 Docker/SSH/伪装站的流量都走进来。
	if p.DstPort != l.port {
		return nil
	}
	return l.handlePacket(p)
}

// handlePacket 是分流核心（对应 Rust `handle_packet`）。
//
// 三条路径，顺序很重要：
//  1. 纯 SYN（且带 IP ID 标记）→ 回 SYN-ACK 并登记 pending
//  2. 已有会话 → 直接投递（热路径）
//  3. 未知来源的数据包 → 尝试按「首包」鉴权并建会话
//
// 顺序不能反：「先试首包」会让已建立会话的每个包都多跑一次 authID 查表 +
// 首包解密（必然失败），高包速率下白烧 CPU。
//
// 返回值是「本帧被投递进去的会话」，供 recvLoop 在批末统一做延迟确认。
func (l *Listener) handlePacket(p ParsedPacket) *Session {
	client := netip.AddrPortFrom(p.Src, p.SrcPort)

	// 1) 纯 SYN：标准握手第一步，立即回 SYN-ACK。
	//
	// 判别依据是 IP ID 高字节（配置派生的标记），与 Rust 一致：
	// `(ip_id & mark) == mark && SYN && payload.is_empty()`。
	if p.IPID&l.mark == l.mark && p.Flags&TCPSYN != 0 && len(p.Payload) == 0 {
		l.handleSYN(client, p)
		return nil
	}

	// 2) 已有会话
	if sess := l.sessionFor(client); sess != nil {
		if sess.closed.Load() {
			l.dropSession(client)
			return nil
		}
		sess.handleIncoming(p)
		if sess.closed.Load() {
			l.dropSession(client)
			return nil
		}
		return sess
	}

	// 3) 未知来源的数据包：可能是首包
	if len(p.Payload) > 0 {
		l.handleFirstPacket(client, p)
	}
	return nil
}

// sessionFor 查已有会话。
func (l *Listener) sessionFor(client netip.AddrPort) *Session {
	l.mu.RLock()
	sess := l.byAddr[client]
	l.mu.RUnlock()
	return sess
}

// handleSYN 回应 SYN-ACK 并登记 pending（对应 Rust 的 SYN 分支）。
func (l *Listener) handleSYN(client netip.AddrPort, p ParsedPacket) {
	now := time.Now()
	l.mu.Lock()
	// 客户端重启后四元组会复用（源端口固定），旧会话必须先清掉。
	//
	// 不清的后果非常隐蔽：新连接的首包在 handlePacket 的第 2 分支被
	// 「已有会话」接走，交给旧会话的 ack 判定当乱序包丢弃，
	// 于是服务端永远走不到 handleFirstPacket，表现为
	// 「客户端显示通道已建立，但一个字都传不过去，直到 120 秒空闲回收」。
	//
	// 判据是 SYN 的 ISN：同一次握手的 SYN 重传复用同一个 ISN，
	// 客户端重启则一定是新随机值。
	// 对应 Rust `conns.retain(|_, c| c.client != client)`。
	var stale *Session
	if old, ok := l.byAddr[client]; ok && old.peerISN != p.Seq {
		delete(l.byAddr, client)
		stale = old
	}
	// 重复 SYN（客户端重传）：复用原 ISN 与 TSval。
	//
	// 真实 TCP 对重传的 SYN 回**一模一样**的 SYN-ACK（ISN 不变），
	// 客户端才能用同一个 ACK 完成握手。
	var isn, ts uint32
	if st, ok := l.pending[client]; ok && now.Sub(st.at) < synStateTTL {
		isn, ts = st.ourISN, st.ts
	} else {
		isn, ts = randomUint32(), randomUint32()
	}
	l.pending[client] = &synState{
		peerISN: p.Seq,
		ourISN:  isn,
		ts:      ts,
		at:      now,
	}
	l.mu.Unlock()

	// 关闭旧会话必须放在锁外：Close 会等待收包协程退出。
	if stale != nil {
		log.Printf("flowtls: 清理同一客户端的旧会话 %s（四元组复用）", client)
		_ = stale.Close()
	}

	// SYN-ACK 的 TSecr 回显客户端 SYN 的 TSval（RFC 7323 要求）
	tsecr := uint32(0)
	if p.HasTS {
		tsecr = p.TSVal
	}
	opts := SynOptions(ts, tsecr)
	pkt := BuildPacket(l.raw.localIP, client.Addr(), l.port, client.Port(), TcpSeg{
		Seq:   isn,
		Ack:   p.Seq + 1,
		Flags: TCPSYN | TCPACK,
		IPID:  RandomIPID(l.mark),
		// SYN 阶段用未缩放的原始窗口（缩放因子在 ESTABLISHED 后才生效）
		Window:  65535,
		TSVal:   ts,
		TSecr:   tsecr,
		Options: opts[:],
	})
	if err := l.raw.Send(pkt, client.Addr()); err != nil {
		log.Printf("flowtls: 发送 SYN-ACK 失败: %v", err)
	}
}

// handleFirstPacket 尝试把未知来源的数据包当作首包处理。
//
// 服务端在不知道用户是谁时必须先读明文头（ver + authID）查表选密钥，
// 解析本身不构成信任——真正的鉴权是随后的 AEAD 认证（OpenFirst）。
func (l *Listener) handleFirstPacket(client netip.AddrPort, p ParsedPacket) {
	var (
		plain   []byte
		entry   *userEntry
		firstOK bool
	)
	for _, rec := range ParseRecords(p.Payload) {
		if rec.Type != RecAppData {
			continue
		}
		ver, authID, ok := ParseFirstHeader(rec.Payload)
		if !ok || ver != ProtocolVersion {
			continue
		}
		e, found := l.users.lookup(authID)
		if !found {
			continue
		}
		out, ok := e.codec.OpenFirst(rec.Payload)
		if !ok {
			continue
		}
		plain, entry, firstOK = out, e, true
		break
	}
	if !firstOK {
		// 不是我们的客户端，或密钥不对：静默丢弃（公网端口每天大量探测）。
		return
	}

	l.mu.Lock()
	// 拿到 pending 里的握手状态（没走过标准握手也行，那就现取随机值）
	st, hasPending := l.pending[client]
	if hasPending {
		delete(l.pending, client)
	}
	// 同一地址的旧会话必须清掉：客户端重启后四元组会复用，
	// 两条会话共用 seq/ack 会互相干扰，抓包可见异常。
	// 与 Rust `conns.retain(|_, c| c.client != client)` 一致。
	if old, ok := l.byAddr[client]; ok {
		delete(l.byAddr, client)
		l.mu.Unlock()
		_ = old.Close()
		l.mu.Lock()
	}
	l.mu.Unlock()

	var peerISN, ourISN, ts uint32
	if hasPending {
		peerISN, ourISN, ts = st.peerISN, st.ourISN, st.ts
	} else {
		// 客户端跳过了握手：序号与时间戳现取随机值，
		// 但要满足「后续 TSval 不回退」，所以从一个随机基准起步。
		peerISN, ourISN, ts = 0, randomUint32(), randomUint32()
	}

	clock := NewTcpClockAt(ts + 2)
	clock.Observe(p.TSVal, p.HasTS)

	sess := newServerSession(l.raw, entry.codec, client, l.port, ourISN+1, peerISN+1, clock, l.mark)

	// ---- 发伪 ServerHello（与 Rust 一致）----
	//
	// 客户端握手完成后，服务端按真实 TLS 1.3 的顺序回三段：
	//   16 03 03 ServerHello（明文，含 key_share）
	//   14 03 03 00 01 01 ChangeCipherSpec
	//   17 03 03 <随机密文> 加密握手消息
	//
	// 用 appendSegmentLocked 发送因为它会推进 seq：ServerHello 占用的字节
	// 必须计入序号，否则后续 QUIC 数据的 seq 与对端看到的字节流对不上
	// （ack 与 seq+len 不衔接 = 可检测特征）。
	serverHello := BuildServerHello()
	sess.mu.Lock()
	helloPkt := sess.appendSegmentLocked(sess.wPkt[:0], serverHello, TCPPSH|TCPACK)
	err := sess.raw.Send(helloPkt, sess.peer.Addr())
	sess.mu.Unlock()
	if err != nil {
		log.Printf("flowtls: 发送 ServerHello 失败: %v", err)
	}

	l.mu.Lock()
	l.byAddr[client] = sess
	l.mu.Unlock()

	// 启动收包？**不能**：服务端所有会话共享 Listener 的收包协程，
	// 会话自己再起一个会把别家会话的包抢走（见 AGENTS.md 约束 3）。

	// 把首包投进队列，让上层的 quic.Transport 一启动就能读到。
	sess.lastSeenAt.Store(time.Now().UnixNano())
	sess.pktsRecv.Add(1)
	sess.deliver(plain)

	select {
	case l.acceptCh <- sess:
	case <-l.ctx.Done():
		_ = sess.Close()
	}
}

// newServerSession 构造服务端方向的会话。
func newServerSession(raw *rawSocket, codec *Codec, peer netip.AddrPort,
	localPort uint16, seq, peerSeq uint32, clock *TcpClock, mark uint16) *Session {
	s := &Session{
		raw:   raw,
		codec: codec,
		// 服务端所有会话共享 Listener 的 socket，绝不能在这里关。
		ownsRaw:    false,
		peer:       peer,
		localPort:  localPort,
		remotePort: peer.Port(),
		seq:        seq,
		peerSeq:    peerSeq,
		// peerSeq 入参始终是「对端 ISN + 1」（SYN 占一个序号），
		// 这里反推回 ISN 留给分流层判断四元组复用。
		peerISN: peerSeq - 1,
		ipid:    RandomIPID(mark),
		mark:    mark,
		clock:   clock,
		lastAck: time.Now(),
		rx:      make(chan []byte, rxQueueDepth),
		closeCh: make(chan struct{}),
	}
	// 首包已确认鉴权：服务端方向本来就不带首包头
	codec.MarkEstablished()
	return s
}

// dropSession 移除并关闭一条会话。
func (l *Listener) dropSession(client netip.AddrPort) {
	l.mu.Lock()
	s, ok := l.byAddr[client]
	if ok {
		delete(l.byAddr, client)
	}
	l.mu.Unlock()
	if ok && s != nil {
		_ = s.Close()
	}
	select {
	case l.sessionDone <- client:
	default:
	}
}

// maintainLoop 负责 pending 超时回收与会话空闲回收。
//
// 单独一个低频协程而不是在 recvLoop 里做：收包路径每包都要跑，
// 加进任何「遍历全表」的操作都会直接拖慢热路径。
//
// 与 Rust 一致：会话空闲超时按「多久没收到任何包」判断
// （UDP 无连接、客户端可能直接消失）。
func (l *Listener) maintainLoop() {
	defer l.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-ticker.C:
		}

		now := time.Now()

		// pending 超时：客户端发了 SYN 却不继续握手（扫描/半开连接）
		l.mu.Lock()
		for addr, st := range l.pending {
			if now.Sub(st.at) > l.handshakeTimeout*2 {
				delete(l.pending, addr)
			}
		}
		l.mu.Unlock()

		// 会话空闲超时
		var expired []*Session
		l.mu.Lock()
		for addr, s := range l.byAddr {
			if s.idleFor() > l.idleTimeout {
				delete(l.byAddr, addr)
				expired = append(expired, s)
			}
		}
		l.mu.Unlock()
		for _, s := range expired {
			_ = s.Close()
		}
	}
}

// userEntry 是一条用户记录（密码 + 该用户专属编解码器）。
type userEntry struct {
	name  string
	codec *Codec
}

// userTable 用 authID 做 O(1) 查表。
//
// 不能遍历试解：100 用户就是 100 倍 AEAD 开销，且试验次数可被计时。
type userTable struct {
	byAuthID map[[AuthIDLen]byte]*userEntry
}

// newUserTable 由用户列表构造查表结构。
func newUserTable(users []User) (*userTable, error) {
	if len(users) == 0 {
		return nil, errors.New("flowtls: 服务端必须配置 password 或 users")
	}
	t := &userTable{byAuthID: make(map[[AuthIDLen]byte]*userEntry, len(users))}
	for _, u := range users {
		c, err := NewServerCodec(u.Password)
		if err != nil {
			return nil, err
		}
		t.byAuthID[c.AuthID()] = &userEntry{name: u.Name, codec: c}
	}
	return t, nil
}

func (t *userTable) lookup(authID [AuthIDLen]byte) (*userEntry, bool) {
	e, ok := t.byAuthID[authID]
	return e, ok
}

func (t *userTable) len() int { return len(t.byAuthID) }
