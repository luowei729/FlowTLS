package flowtls

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Listener 是服务端入口：接收伪造 TCP 连接并交给上层（quic.Transport）。
//
// 结构上有三个关键决定，每个都对应一个具体问题：
//
//  1. **共享一个 raw socket**（不是每客户端一个）。
//     每个 AF_PACKET socket 要 8MB 接收缓冲；若每客户端一个，
//     100 个客户端就是 800MB 内核内存，且 100 个 recvLoop 抢 CPU。
//
//  2. **一个 recvLoop** 按四元组分发到各 Session。
//     收包路径只有这一处，调试时看日志就能知道每个包去了哪。
//
//  3. **每客户端一个 Session**（不可协商）。
//     QUIC 与伪造 TCP 都要求 seq/ack 是连续字节流；多个客户端共用
//     一个 Session 会让序号互相拉扯，中间盒直接判非法。
//     ——这一层是协议决定的，与 hy2 的「一个 UDP socket 管所有客户端」
//     看似相同、实则不同：hy2 的下层是无状态的 UDP，序号问题由 QUIC
//     connID 承担；我们的下层是有亲和性的伪造 TCP，必须按四元组分流。
type Listener struct {
	raw   *rawSocket
	users *userTable
	port  uint16
	mark  uint16
	// idleTimeout 是会话空闲回收时间。超时后 Session 被移出表并关闭。
	idleTimeout time.Duration
	// handshakeTimeout 是 SYN 之后等待首包的最长时间。
	handshakeTimeout time.Duration

	mu sync.RWMutex
	// byAddr 是四元组 → 会话。服务端所有包的查表依据。
	byAddr map[netip.AddrPort]*Session
	// pending 是「已回 SYN-ACK、还没收到首包」的中间状态。
	pending map[netip.AddrPort]*synState

	// acceptCh 把新建的 Session 交给上层（quic 包）。
	acceptCh chan *Session
	// sessionDone 用于把「会话结束」事件回传主循环，做集中清理。
	sessionDone chan netip.AddrPort

	// rules 是本次启动落地的 iptables 规则结果，供上层记日志。
	rules RuleReport

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	wg        sync.WaitGroup
	// 统计
	statAccepted atomic.Uint64
	statDropped  atomic.Uint64
}

// synState 是收到 SYN 后、首包到达前的临时状态。
//
// 三样信息必须一起存：
//   - peerISN：回 SYN-ACK 时用的 ack；
//   - ourISN：SYN-ACK 的 seq（首包响应必须紧接着它，序号才连续）；
//   - ts：SYN-ACK 用的 TSval（后续包的 TSval 必须不小于它，
//     否则时间戳类 DPI 一眼看出回退）。
type synState struct {
	peerISN uint32
	ourISN  uint32
	ts      uint32
	at      time.Time
}

// ListenerOptions 是 NewListener 的参数。
type ListenerOptions struct {
	// IdleTimeout 是单条连接的空闲回收时间，默认 120s。
	IdleTimeout time.Duration
	// HandshakeTimeout 是 SYN 到首包的等待上限，默认 5s。
	HandshakeTimeout time.Duration
	// AcceptQueue 是待上层接管的会话队列长度，默认 64。
	AcceptQueue int
	// IPTablesMode 决定 raw 表规则的落地方式，默认 print。
	//
	// 规则由 NewListener 在 raw socket 建好之后落地：
	// 先有能收包的能力，再去改防火墙，失败时顺序可回退。
	IPTablesMode IPTablesMode
}

// NewListener 绑定端口并启动收包协程。
//
// 会立刻申请 raw socket（需要 root 或 CAP_NET_RAW）。这与 sing-box 的
// `check` 冲突，所以适配层必须在 Start(StartStateStart) 里调用，
// 绝不能在 NewInbound 里。
func NewListener(cfg ServerConfig, opts ListenerOptions) (*Listener, error) {
	if !cfg.Listen.Addr().Is4() {
		return nil, ErrPlatformUnsupported
	}
	if len(cfg.Users) == 0 && cfg.Password == "" {
		return nil, errors.New("flowtls: 服务端必须配置 password 或 users")
	}
	users, err := newUserTable(cfg.effectiveUsers())
	if err != nil {
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

	// 探测用的目的地址**不能是监听地址**。
	//
	// 服务端 listen 通常是 0.0.0.0，拿它去查路由/网关 MAC 必然失败：
	// 0.0.0.0 没有下一跳，resolveNeighborMAC 返回空，
	// 发送时走 "自己拼以太网头" 分支，而目的 MAC 是全 0 —— 包发不出去。
	// 表现是客户端发了 SYN、服务端 flowtls 也解出来了，但 SYN-ACK 到不了，
	// 客户端只看到 handshake timeout。
	//
	// 与 Rust 版保持一致：固定用 8.8.8.8（一个必然走默认路由的外部地址）
	// 去探测出口网卡与网关 MAC。回包源地址取 cfg.LocalIP，
	// 但该值不在本机网卡上时（NAT 云主机写了公网地址）newRawSocket 会退回
	// 探测到的出口地址，并通过 SendMode() 把这件事暴露到启动日志。
	dst := netip.MustParseAddr("8.8.8.8")
	// bindRecv=false：服务端必须收所有网卡（含 lo）的包，绑到探测出的
	// 出口网卡会让回环联调的 SYN 永远收不到（newRawSocket 里有详细说明）。
	raw, err := newRawSocket(dst, cfg.LocalIP, false)
	if err != nil {
		return nil, err
	}
	mark := IPIDMarkOf(cfg.IPIDMark)
	if mark == 0 {
		mark = IPIDMark
	}

	// raw socket 就绪后再落地 iptables 规则。
	//
	// 顺序理由：规则的作用是「让内核别碰我们的伪包」。
	// 若反过来（先改防火墙再申请 socket），申请失败时会留下一堆
	// 指向一个根本不会运行的服务端的 DROP 规则，运维很难意识到要清理。
	//
	// 规则落地失败直接返回错误：没有规则的 auto 模式等于静默失效，
	// 比启动失败更难查。
	rules, err := ApplyRules(opts.IPTablesMode, ServerRules(cfg.Listen.Port(), cfg.IPIDMark))
	if err != nil {
		_ = raw.Close()
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	l := &Listener{
		raw:              raw,
		users:            users,
		port:             cfg.Listen.Port(),
		mark:             mark,
		idleTimeout:      opts.IdleTimeout,
		handshakeTimeout: opts.HandshakeTimeout,
		byAddr:           make(map[netip.AddrPort]*Session),
		pending:          make(map[netip.AddrPort]*synState),
		acceptCh:         make(chan *Session, opts.AcceptQueue),
		sessionDone:      make(chan netip.AddrPort, opts.AcceptQueue),
		rules:            rules,
		ctx:              ctx,
		cancel:           cancel,
	}

	l.wg.Add(2)
	go l.recvLoop()
	go l.maintainLoop()
	return l, nil
}

// Addr 返回监听地址。
func (l *Listener) Addr() netip.AddrPort {
	return netip.AddrPortFrom(l.raw.LocalIP, l.port)
}

// LocalIP 返回对外使用的源 IP。
func (l *Listener) LocalIP() netip.Addr { return l.raw.LocalIP }

// SendMode 返回底层发送路径描述（含源地址被纠正的说明），供上层记启动日志。
//
// 为什么一定要把这行打进日志：发送路径（内核 IP 层 vs AF_PACKET）与最终源地址
// 直接决定链路能不能通，而两者失败时的现象一模一样（对端一个包都收不到）。
// 之前只能靠 strace + 双端抓包反推，成本极高。
func (l *Listener) SendMode() string { return l.raw.SendMode() }

// Users 返回用户表大小（供启动日志展示）。
func (l *Listener) Users() int { return l.users.len() }

// Rules 返回本次启动落地的 iptables 规则结果。
//
// 上层（sing-box inbound / 联调工具）用它把规则文本记进日志：
// print 模式下这份文本就是运维需要手工安装的命令。
func (l *Listener) Rules() RuleReport { return l.rules }

// Accept 阻塞等待一条已鉴权的会话。
//
// 返回的 Session 已经解出过首包（即用户身份已验证），可以直接交给
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

// Stats 是监听器的运行统计。
type Stats struct {
	Sessions uint64
	Pending  uint64
	Accepted uint64
	Dropped  uint64
}

// Stats 返回当前统计。
func (l *Listener) Stats() Stats {
	l.mu.RLock()
	n := uint64(len(l.byAddr))
	p := uint64(len(l.pending))
	l.mu.RUnlock()
	return Stats{
		Sessions: n,
		Pending:  p,
		Accepted: l.statAccepted.Load(),
		Dropped:  l.statDropped.Load(),
	}
}

// recvLoop 是唯一的收包协程：解析 → 分流。
//
// **逐包 recvfrom，不用 recvmmsg**。曾试过 recvmmsg 批量收（一次 32 个），
// 结果吞吐从 87Mbps 崩到 7KB/s，且客户端 sent 计数完全停滞。
// 根因：`recvmmsg` 的 mmsghdr 布局在 AF_PACKET 上没有得到真实验证
// （本机回环测试被环境跳过），内核可能静默不填充 MsgLen，
// 表现为「收包协程空转、包全丢」——而 masquerade 走内核 TCP 栈
// 依然正常，极难定位。
//
// 教训：**任何 unsafe + syscall 的优化，没有能跑通的验证就不能上线**。
// 收包侧的真实验证需要一个独立的发包源（另一台机器或 tcpdump 回灌），
// 成本远高于收益，因此这里保持最简单的逐包实现。
func (l *Listener) recvLoop() {
	defer l.wg.Done()
	buf := make([]byte, 65536)
	for {
		if l.ctx.Err() != nil {
			return
		}
		n, err := l.raw.Recv(buf)
		if err != nil {
			if l.ctx.Err() != nil {
				return
			}
			continue
		}
		p, ok := ParseFrame(buf[:n])
		if !ok {
			continue
		}
		// 只处理发往本端口的包。绑定的是 AF_PACKET（收到所有 IP 包），
		// 不过滤会把整机流量都走进来。
		if p.DstPort != l.port {
			continue
		}
		l.handlePacket(p)
	}
}

// handlePacket 是分流核心。
//
// 三条路径，顺序很重要：
//  1. 已有会话 → 直接投递（热路径，99.9% 的包走这里）
//  2. 纯 SYN → 回 SYN-ACK 并登记 pending
//  3. 未知来源的数据包 → 尝试按「首包」鉴权并建会话
//
// 顺序不能反：「先试首包」会让已建立会话的每个包都多跑一次
// authID 查表 + 首包解密（必然失败），高包速率下白烧 CPU。
func (l *Listener) handlePacket(p ParsedPacket) {
	client := netip.AddrPortFrom(p.Src, p.SrcPort)

	// 1) 纯 SYN 最高优先：标准三次握手的第一步。
	//
	// **必须在「已有会话」判断之前**。客户端的源端口通常是固定的
	// （sing-box 配置里的 source_port），客户端重启后会用**完全相同的
	// 四元组**再发一次 SYN。若此时旧会话还没被回收，把它当普通数据包
	// 投进旧会话，新 SYN 就会被当作乱序包静默丢弃 —— 现象是客户端
	// 握手超时，而服务端日志里一条记录都没有。
	//
	// 真正的重传 SYN 走 handleSYN 内部的 pending 复用分支，
	// 仍然回一模一样的 SYN-ACK，不会打乱客户端状态。
	//
	// **必须按 wscale 校验是否为伪 SYN**，这是分流唯一可靠的特征。
	//
	// 少了这一条，任何真实浏览器的 SYN 都会拿到一个 flowtls 的 SYN-ACK，
	// 与内核（masquerade 网站）的 SYN-ACK 抢同一个四元组：
	//   - 实测双端抓包可见两个不同 ISN 的 SYN-ACK 并存；
	//   - 客户端取到内核那个 ISN 时，后续伪数据包的 ack 全部对不上；
	//   - 表现为「偶发约 3×RTT 的握手延迟、连接状态抖动」。
	//
	// 不用 IP ID 判断的原因见 packet.go 的 WScale 注释：掩码匹配有 1/16
	// 误命中率，且部分链路会改写 IP ID。
	//
	// 数据包不需要判断：靠四元组查表，只有已鉴权会话才存在表项。
	if p.Flags&TCPSYN != 0 && p.Flags&TCPACK == 0 && len(p.Payload) == 0 {
		if p.WScale != int(WScale) {
			// 不是我们的伪 SYN：交给内核（伪装网站）。服务端绝不能在
			// 这里回任何东西，否则真实 TLS 客户端会看到两个 SYN-ACK。
			return
		}
		if l.sessionFor(client) != nil {
			l.dropSession(client)
		}
		l.handleSYN(client, p)
		return
	}

	// 2) 已有会话
	if sess := l.sessionFor(client); sess != nil {
		if sess.closed.Load() {
			l.dropSession(client)
			return
		}
		sess.handleIncoming(p)
		if sess.closed.Load() {
			l.dropSession(client)
		}
		return
	}

	// 3) 未知来源的数据包：可能是首包
	if len(p.Payload) > 0 {
		l.handleFirstPacket(client, p)
	}
}

// sessionFor 查已有会话。
func (l *Listener) sessionFor(client netip.AddrPort) *Session {
	l.mu.RLock()
	sess := l.byAddr[client]
	l.mu.RUnlock()
	return sess
}

// handleSYN 回应 SYN-ACK 并登记 pending。
func (l *Listener) handleSYN(client netip.AddrPort, p ParsedPacket) {
	now := time.Now()
	l.mu.Lock()
	// 重复 SYN（客户端重传）：复用原 ISN 与 TSval。
	//
	// 真实 TCP 对重传的 SYN 回**一模一样**的 SYN-ACK（ISN 不变），
	// 客户端才能用同一个 ACK 完成握手。每次给新 ISN 会让客户端的
	// peer_seq 被两个值来回拉扯，抓包一看就是伪造。
	//
	// **但必须同时校验 ISN 相同**：真实 TCP 的重传 SYN 携带的是**同一个**
	// ISN（客户端自己记着），ISN 变了就是一条全新连接。
	// 只按时间判断会踩这个坑：客户端源端口固定（source_port 44311），
	// 重启后四元组完全相同，若上一个实例的 pending 还在 10 秒窗口内，
	// 服务端就会用**旧 ISN** 算 ack（ack = 旧 peerISN + 1），
	// 与客户端刚发的 ISN 对不上 —— 客户端丢弃该 SYN-ACK 并重传 SYN，
	// 实测要重试 3 次（约 2 秒）才建起来。
	//
	// 更严重的后果在链路上：这 2 个 ack 号错误的 SYN-ACK 会被沿途
	// DPI 判为「TCP 状态异常」，该流从此不做应用识别 ——
	// 表现为路由器连接表里隧道被标成通用 "SSL" 且提取不到域名，
	// 而同样的配置在 Rust 版（旧实现不复用 pending）是正常的。
	if st, ok := l.pending[client]; ok && now.Sub(st.at) < 10*time.Second && st.peerISN == p.Seq {
		l.mu.Unlock()
		l.sendSYNACK(client, st.peerISN, st.ourISN, st.ts, p.TSVal, p.HasTS)
		return
	}
	ourISN := randomUint32()
	ts := randomUint32()
	l.pending[client] = &synState{
		peerISN: p.Seq,
		ourISN:  ourISN,
		ts:      ts,
		at:      now,
	}
	l.mu.Unlock()

	// SYN-ACK 的 TSecr 回显客户端 SYN 的 TSval（RFC 7323 要求）
	l.sendSYNACK(client, p.Seq, ourISN, ts, p.TSVal, p.HasTS)
}

// sendSYNACK 发送一个 SYN-ACK。
func (l *Listener) sendSYNACK(client netip.AddrPort, peerISN, ourISN, ts, peerTS uint32, hasPeerTS bool) {
	tsecr := uint32(0)
	if hasPeerTS {
		tsecr = peerTS
	}
	opts := SynOptions(ts, tsecr)
	pkt := AppendPacket(nil, TcpSeg{
		Src:     l.raw.LocalIP,
		Dst:     client.Addr(),
		SrcPort: l.port,
		DstPort: client.Port(),
		Seq:     ourISN,
		Ack:     peerISN + 1,
		Flags:   TCPSYN | TCPACK,
		IPID:    RandomIPID(l.mark),
		// SYN 阶段用未缩放的原始窗口（缩放因子在 ESTABLISHED 后才生效）
		Window:  65535,
		TSVal:   ts,
		TSecr:   tsecr,
		Options: opts[:],
	})
	if err := l.raw.Send(pkt, client.Addr()); err != nil {
		l.statDropped.Add(1)
		return
	}
}

// handleFirstPacket 尝试把未知来源的数据包当作首包处理。
//
// 服务端在不知道用户是谁时必须先读明文头（ver + authID）查表选密钥，
// 解析本身不构成信任——真正的鉴权是随后的 AEAD 认证。
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
		out, ok := e.Codec.OpenFirst(rec.Payload)
		if !ok {
			continue
		}
		plain, entry, firstOK = out, e, true
		break
	}
	if !firstOK {
		// 不是我们的客户端，或密钥不对：静默丢弃。
		// 用计数而不是日志：公网端口每天会收到大量探测。
		l.statDropped.Add(1)
		return
	}

	l.mu.Lock()
	// 拿到 pending 里的握手状态（没走过标准握手也行，那就现取随机值）
	st, hasPending := l.pending[client]
	if hasPending {
		delete(l.pending, client)
	}
	// 同地址的旧会话必须清掉：客户端重启后四元组会复用，
	// 两条会话共用 seq/ack 会互相干扰，抓包可见异常。
	if old, ok := l.byAddr[client]; ok {
		delete(l.byAddr, client)
		_ = old.Close()
	}
	l.mu.Unlock()

	var peerISN, ourISN, ts uint32
	if hasPending {
		peerISN, ourISN, ts = st.peerISN, st.ourISN, st.ts
	} else {
		// 客户端跳过了握手（要求它有公网 IP）：序号与时间戳现取随机值，
		// 但要满足「后续 TSval 不回退」，所以从一个随机基准起步。
		peerISN, ourISN, ts = 0, randomUint32(), randomUint32()
	}

	clock := NewTcpClockAt(ts + 2)
	clock.Observe(p.TSVal, p.HasTS)

	codec, err := NewServerCodec(entry.Password)
	if err != nil {
		l.statDropped.Add(1)
		return
	}

	sess := &Session{
		raw:     l.raw,
		ownsRaw: false, // 共享 socket，绝不在这里关
		codec:   codec,
		peer:    client,
		// 服务端：本地端口是监听端口，对端端口是客户端源端口
		localPort:  l.port,
		remotePort: client.Port(),
		// SYN 占 1 个序号，之后的数据从 ourISN+1 开始
		seq:     ourISN + 1,
		peerSeq: peerISN + 1,
		ipid:    RandomIPID(l.mark),
		mark:    l.mark,
		clock:   clock,
		lastAck: time.Now(),
		rx:      make(chan []byte, rxQueueDepth),
		closeCh: make(chan struct{}),
	}
	// 首包已确认鉴权：服务端方向本来就不带首包头
	codec.MarkEstablished()
	// 初始化批量发送队列：服务端数据面也走 sendmmsg，
	// 逐包 sendto 在 1 核 ARM 上会让驱动队列满而丢包（见 Session 注释）。
	sess.newTxQueues()

	l.mu.Lock()
	l.byAddr[client] = sess
	l.mu.Unlock()
	l.statAccepted.Add(1)

	// ---- 发伪 ServerHello（与 Rust 版 server.rs:807 一致）----
	//
	// 客户端的 ClientHello 是它自己构造的表演，我们看不到也不用看；
	// 这里按真实 TLS 1.3 的顺序回三段：
	//   16 03 03 ServerHello（明文，含 key_share）
	//   14 03 03 00 01 01 ChangeCipherSpec
	//   17 03 03 <随机密文> 加密握手消息
	//
	// 早期版本在 CCS 之后发的是明文 0x16，那是**协议违规**，
	// DPI 一看就知道这不是真 TLS。
	//
	// 用 appendSegmentLocked 发送，因为它会推进 seq：
	// ServerHello 占用的字节必须计入序号，否则后续 QUIC 数据的 seq
	// 与对端看到的字节流对不上（ack 与 seq+len 不衔接 = 可检测特征）。
	serverHello := BuildServerHello()
	if pkt := sess.appendSegmentLocked(sess.wPkt[:0], serverHello, TCPPSH|TCPACK); len(pkt) > 0 {
		if err := l.raw.Send(pkt, client.Addr()); err == nil {
			sess.pktsSent.Add(1)
		}
	}
	// 握手表演包已直接发出，从这里开始启动批量发送协程：
	// 之后的 QUIC 数据面全部走「入队 + sendmmsg」。
	sess.startSender()

	// 把首包投进队列，让上层的 quic.Transport 一启动就能读到。
	// 必须在交给 Accept 之前完成，否则 quic-go 的握手会一直等这个包。
	sess.lastSeenAt.Store(time.Now().UnixNano())
	sess.pktsRecv.Add(1)
	sess.deliver(plain)
	if p.TSVal != 0 {
		sess.ackPend = 1
	}

	select {
	case l.acceptCh <- sess:
	case <-l.ctx.Done():
		_ = sess.Close()
	}
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
	// 通知 maintainLoop 不必再处理（容量 1 丢事件即可，它只是优化）
	select {
	case l.sessionDone <- client:
	default:
	}
}

// maintainLoop 负责两类回收：握手超时的 pending、空闲超时的会话。
//
// 单独一个低频协程而不是在 recvLoop 里做：收包路径每包都要跑，
// 加进任何「遍历全表」的操作都会直接拖慢热路径。
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
		var expiredPending []netip.AddrPort
		l.mu.Lock()
		for addr, st := range l.pending {
			if now.Sub(st.at) > l.handshakeTimeout*2 {
				expiredPending = append(expiredPending, addr)
			}
		}
		for _, addr := range expiredPending {
			delete(l.pending, addr)
		}
		l.mu.Unlock()

		// 会话空闲超时：UDP 无连接、客户端可能直接消失，
		// 只能靠「多久没收到包」判断死活。
		var expiredSessions []*Session
		l.mu.Lock()
		for addr, s := range l.byAddr {
			if s.IdleFor() > l.idleTimeout {
				delete(l.byAddr, addr)
				expiredSessions = append(expiredSessions, s)
			}
		}
		l.mu.Unlock()
		for _, s := range expiredSessions {
			_ = s.Close()
		}
	}
}
