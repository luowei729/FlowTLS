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
	// mark 是这条 SYN 命中的 ip_id_mark。
	//
	// 首包的 IP ID 低字节已经递增，多用户时 `markOf` 可能命中
	// 另一个用户的标记（匹配是 `ip_id & m == m`，不是高字节相等）。
	// 回包必须继续用握手时认下的那个，否则客户端内核规则对不上。
	mark uint16
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
	// marks 是本服务端接受的**全部** ip_id_mark（每个用户一个）。
	//
	// 为什么是一组：内核层要判断「这个包是不是我们的」时还没解密，
	// 不知道对端是哪个用户，所以只能把每个用户的派生标记都纳入范围
	// （见 ServerConfig.Marks）。这也是多用户部署下「mark 从 password
	// 派生」能成立的关键 —— 服务端不需要预先知道谁来连。
	marks []uint16
	// logger 是诊断日志出口，恒非 nil（构造时经 loggerOr 归一）。
	//
	// 服务端所有会话共享它：收包路径是单协程共享 socket，
	// 按会话注入只会让同一份日志被重复打出来。
	logger Logger

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
	// 日志出口先归一：后面 newRawSocket 与收包协程都要用。
	logger := loggerOr(cfg.Logger)

	// marks 是每个用户 password 派生出的 ip_id_mark（见 ServerConfig.Marks）。
	// 服务端在内核层判断「是不是我们的包」时还没解密，所以必须把所有
	// 用户的标记都纳入识别范围。
	marks := cfg.Marks()

	// 探测用的目的地址**不能是监听地址**。
	//
	// 服务端 listen 通常是 0.0.0.0，拿它去查路由/网关 MAC 必然失败：
	// 0.0.0.0 没有下一跳。与 Rust 一致：固定用 8.8.8.8（必然走默认路由）。
	dst := netip.MustParseAddr("8.8.8.8")
	// 服务端传 true：下载方向的服务端要发全部数据，
	// AF_PACKET 在 1 核 ARM 上比 IPPROTO_RAW 快 3~4 倍（见 socket_linux.go 文件头）。
	//
	// role 只有 Windows 用（WinDivert 过滤器在 Open() 时固定，需要监听端口）。
	raw, err := newRawSocket(dst, cfg.LocalIP, logger, true, socketRole{
		server:     true,
		listenPort: cfg.Listen.Port(),
	})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	// 规则的作用是「让内核别碰我们的伪包」。
	// 顺序理由：先有能收包的能力，再去改防火墙，失败时顺序可回退。
	//
	// **没有开关**（同客户端）：这些规则是协议能工作的前提，不是可选优化。
	// 少了它们内核会自己回 SYN-ACK / RST，把伪连接和同端口的真实网站都搞乱。
	// 写不进去就带着原因失败，比静默不通强。
	if err := EnsureServer(cfg.Listen.Port(), marks); err != nil {
		_ = raw.Close()
		cancel()
		return nil, err
	}
	// 同客户端：fw4 的 ct invalid DROP 会静默吞掉我们的伪包。
	for _, r := range NftRules(cfg.Listen.Port(), marks) {
		logger.Info("防火墙规则: ", r)
	}

	l := &Listener{
		raw:    raw,
		port:   cfg.Listen.Port(),
		users:  users,
		marks:  marks,
		logger: logger,
		// 这两个必须从 opts 抄过来。漏掉时字段是 0，
		// maintainLoop 里 `idleFor() > 0` 对任何刚收到包的会话都成立，
		// 下一秒就把会话关掉。客户端还以为隧道在，请求全部超时，
		// 服务端日志里看不到新连接。rev.6 有这两行，rev.8 重组字面量时丢了。
		idleTimeout:      opts.IdleTimeout,
		handshakeTimeout: opts.HandshakeTimeout,
		byAddr:           make(map[netip.AddrPort]*Session),
		pending:          make(map[netip.AddrPort]*synState),
		acceptCh:         make(chan *Session, opts.AcceptQueue),
		sessionDone:      make(chan netip.AddrPort, opts.AcceptQueue),
		ctx:              ctx,
		cancel:           cancel,
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
	// 批量收包的槽位：仅当 FLOWTLS_RECVMMSG=1 时分配。
	var slots *recvSlots
	if recvBatchEnabled() {
		slots = newRecvSlots()
	}
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
			// **必须在这里立刻取句柄**：Recv 一返回，下一次循环就可能把它覆盖。
			// 句柄要跟着 frame 一起走进 channel（见 frameHandle 的注释）。
			h := l.raw.TakeFrameHandle()
			select {
			case frames <- recvResult{frame: frame, h: h, err: err}:
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
			l.logger.Error("raw recv 失败: ", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if sess := l.recvFrame(buf[:n], res.h); sess != nil {
			touched = append(touched, sess)
		}
		touched = l.drainAvailable(buf, slots, touched)
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
// 批量路径同样“处理完即返回”，不影响 5ms 心跳。
func (l *Listener) drainAvailable(buf []byte, slots *recvSlots, touched []*Session) []*Session {
	if slots != nil {
		return l.drainBatch(slots, touched)
	}
	for i := 1; i < maxRecvBatch; i++ {
		if l.ctx.Err() != nil {
			return touched
		}
		n, ok, err := l.raw.recvAvailable(buf)
		if err != nil {
			if l.ctx.Err() == nil {
				l.logger.Error("raw recv 失败: ", err)
			}
			return touched
		}
		if !ok {
			// 队列已空（或本帧被截断丢弃）：本轮结束
			return touched
		}
		// 与主循环同理：Recv 一返回就取句柄，否则下一帧会覆盖它。
		h := l.raw.TakeFrameHandle()
		if sess := l.recvFrame(buf[:n], h); sess != nil {
			touched = append(touched, sess)
		}
	}
	return touched
}

// drainBatch 是批量版本的 drainAvailable（服务端共享 socket）。
func (l *Listener) drainBatch(slots *recvSlots, touched []*Session) []*Session {
	for done := 1; done < maxRecvBatch; {
		if l.ctx.Err() != nil {
			return touched
		}
		n, err := l.raw.recvBatch(slots)
		if err != nil {
			if l.ctx.Err() == nil {
				l.logger.Error("raw recv 失败: ", err)
			}
			return touched
		}
		if n == 0 {
			return touched
		}
		for i := 0; i < n; i++ {
			if slots.lens[i] <= 0 {
				continue // -1 = 超过槽位被截断（已计数）
			}
			// 批量路径只存在于 Linux（recvmmsg），句柄恒为 nil；
			// Windows 的 recvBatchEnabled() 返回 false，永远走不到这里。
			if sess := l.recvFrame(slots.bufs[i][:slots.lens[i]], nil); sess != nil {
				touched = append(touched, sess)
			}
		}
		done += n
	}
	return touched
}

// recvFrame 解析一帧并分发给 handlePacket。
//
// 返回被投递数据帧的会话（供批末做延迟确认）；SYN / 首包路径不需要确认，
// 返回 nil。
// h 是这一帧的注入句柄（Windows 需要，Linux 恒为 nil），与 raw 严格配对。
func (l *Listener) recvFrame(raw []byte, h frameHandle) *Session {
	p, ok := ParseFrame(raw)
	if !ok {
		return nil
	}
	// 只处理发往本端口的包。绑定的是 AF_PACKET（收到整机所有 IP 包），
	// 不过滤会把 Docker/SSH/伪装站的流量都走进来。
	if p.DstPort != l.port {
		return nil
	}
	sess, consumed := l.handlePacket(p)
	if !consumed && l.raw.reinjectUnmatched && !l.protocolOwned(p) {
		// 只有「不属于本协议族」的包才还给内核——典型情况就是同端口伪装站
		// 的真实浏览器流量。WinDivert 把这些包扣留了，不还回去内核永远看不到，
		// 伪装站会静默失效。
		//
		// **带标记但没被消费的包绝不能还**（认证失败、乱序、已关闭会话）：
		// 内核里没有对应 socket，会回一个 RST，而 RST 是协议合法的终止信号，
		// 中间设备看到就拆 NAT 映射，正在重建的同一四元组直接断掉。
		// 这与 Linux 侧 iptables 用 u32 匹配 IP ID 标记后 DROP 是同一条判据
		// （见 rules.go 的 serverRules）。
		//
		// Linux 上 reinjectUnmatched 恒为 false：AF_PACKET 只是内核处理的副本，
		// 忽略它不影响内核继续处理。
		if err := l.raw.Reinject(raw, h); err != nil {
			l.logger.Warn("重新注入未识别的包失败: ", err)
		}
	}
	return sess
}

// shouldReinject 报告「这个包必须还给内核」。
//
// 抽成独立函数是为了能单测：这是整个 Windows 移植里唯一一处
// 「判错就会造成真实故障」的决策，而它在 Linux 上恒为 false（跑不到），
// 不写成纯函数就没有任何测试能覆盖它。
//
// 真值表（服务端，reinjectUnmatched=true）：
//
//	包的类型                     consumed  带标记   还给内核
//	伪装站真实浏览器流量            false    false    **是**（否则伪装站死掉）
//	探测器/认证失败的首包           false    true     否（否则内核回 RST）
//	已关闭会话残留包                true     true     否（同上）
//	正常会话数据 / SYN              true     true     否
//
// 「带标记 + 未消费」绝不能还：内核里没有对应 socket，会回一个 RST，
// 中间设备看到 RST 就拆 NAT 映射，正在重建的同一四元组直接断掉。
func (l *Listener) shouldReinject(p ParsedPacket, consumed bool) bool {
	if !l.raw.reinjectUnmatched || consumed {
		return false
	}
	return !l.protocolOwned(p)
}

// protocolOwned 报告这个包是否属于本协议族。
//
// 判据就是 IP ID 高字节标记，与 Rust 版、与 Linux 的 iptables u32 规则
// （`0x4&0xff00ffff=0x<mark>4000`）逐位一致。
//
// 注意：带标记 ≠ 认证通过。标记只是「这个包被本协议占用」的声明，
// 真正的鉴权是握手首包的 AEAD 认证。两件事不能混。
//
// 多标记：任一用户的派生标记命中即算本协议（见 Listener.marks）。
func (l *Listener) protocolOwned(p ParsedPacket) bool {
	return l.markOf(p) != 0
}

// markOf 返回这个包的 IP ID 命中的标记；未命中返回 0。
//
// 只比高字节。配置里的 ip_id_mark 可以是 0xF107 这种带低字节的值，
// 低字节是按包递增的序号，不参与识别。若直接做 `ip_id & m == m`，
// m 的低字节非 0 时，IP ID 低字节一旦回绕到对不上就整包被丢掉。
// 返回值也收成 0xNN00：回包要拿它去填 IP ID 高字节。
func (l *Listener) markOf(p ParsedPacket) uint16 {
	hibyte := p.IPID & 0xFF00
	for _, m := range l.marks {
		m = m & 0xFF00
		if m != 0 && hibyte == m {
			return m
		}
	}
	return 0
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
// 返回值：
//   - sess：本帧被投递进去的会话，供 recvLoop 在批末统一做延迟确认。
//   - consumed：本帧是否已归属本协议。**Windows 上未消费的包必须重新注入**，
//     否则 WinDivert 扣留的包会被销毁（伪装站失效）。
//     Linux 上 AF_PACKET 是被动复制，未消费即"内核照常处理"，天然正确。
func (l *Listener) handlePacket(p ParsedPacket) (*Session, bool) {
	client := netip.AddrPortFrom(p.Src, p.SrcPort)

	// 1) 纯 SYN：标准握手第一步，立即回 SYN-ACK。
	//
	// 判别依据是 IP ID 高字节（配置派生的标记），与 Rust 一致：
	// `(ip_id & mark) == mark && SYN && payload.is_empty()`。
	if m := l.markOf(p); m != 0 && p.Flags&TCPSYN != 0 && len(p.Payload) == 0 {
		l.handleSYN(client, p, m)
		return nil, true
	}

	// 2) 已有会话
	if sess := l.sessionFor(client); sess != nil {
		if sess.closed.Load() {
			l.dropSession(client)
			// **必须返回 consumed=true**：这个四元组是我们的（只是会话刚关），
			// 还给内核会怎样？内核没有对应 socket，会回一个 RST 给对端。
			// 中间设备看到自己跟踪的连接被 RST 就拆 NAT 映射，
			// 而我们正在重建同一四元组（客户端源端口固定）。
			// 所以这里是「我们认识，主动丢弃」，不是「不是我的，还回去」。
			return nil, true
		}
		sess.handleIncoming(p)
		if sess.closed.Load() {
			l.dropSession(client)
			return nil, true // 同上：认识的四元组，消费掉
		}
		return sess, true
	}

	// 3) 未知来源的数据包：可能是首包
	if len(p.Payload) > 0 {
		if l.handleFirstPacket(client, p) {
			return nil, true
		}
	}
	// 不认识：不消费（Windows 会重新注入给内核）。
	return nil, false
}

// sessionFor 查已有会话。
func (l *Listener) sessionFor(client netip.AddrPort) *Session {
	l.mu.RLock()
	sess := l.byAddr[client]
	l.mu.RUnlock()
	return sess
}

// handleSYN 回应 SYN-ACK 并登记 pending（对应 Rust 的 SYN 分支）。
func (l *Listener) handleSYN(client netip.AddrPort, p ParsedPacket, mark uint16) {
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
		mark:    mark,
	}
	l.mu.Unlock()

	// 关闭旧会话必须放在锁外：Close 会等待收包协程退出。
	if stale != nil {
		l.logger.Info("清理同一客户端的旧会话 ", client, "（四元组复用）")
		_ = stale.Close()
	}

	// SYN-ACK 的 TSecr 回显客户端 SYN 的 TSval（RFC 7323 要求）
	tsecr := uint32(0)
	if p.HasTS {
		tsecr = p.TSVal
	}
	opts := SynOptions(ts, tsecr)
	// 回包源地址用入包的 Dst：客户端发往哪个地址，就从哪个地址回。
	// 这比路由探测更准（多 IP 主机上探测值未必是客户端访问的那个）。
	srcIP := p.Dst
	if !srcIP.IsValid() {
		srcIP = l.raw.localIP
	}
	pkt := BuildPacket(srcIP, client.Addr(), l.port, client.Port(), TcpSeg{
		Seq:   isn,
		Ack:   p.Seq + 1,
		Flags: TCPSYN | TCPACK,
		// 回包的标记必须与客户端发来的那个一致：客户端内核层规则
		// 按同一个值匹配，用别的标记会让它认不出来。
		IPID: RandomIPID(mark),
		// SYN 阶段用未缩放的原始窗口（缩放因子在 ESTABLISHED 后才生效）
		Window:  65535,
		TSVal:   ts,
		TSecr:   tsecr,
		Options: opts[:],
	})
	if err := l.raw.Send(pkt, client.Addr()); err != nil {
		l.logger.Error("发送 SYN-ACK 失败: ", err)
	}
}

// handleFirstPacket 尝试把未知来源的数据包当作首包处理。
//
// 服务端在不知道用户是谁时必须先读明文头（ver + authID）查表选密钥，
// 解析本身不构成信任——真正的鉴权是随后的 AEAD 认证（OpenFirst）。
// 返回值 consumed 表示「本帧已归属本协议」。
//
// **这个返回值在 Windows 上是必需的**：WinDivert 扣留的包若不归还内核就等于
// 丢弃，未消费的包必须重新注入（见 socket_windows.go 的 Reinject）。
// Linux 上它只用于日志/正确性表达，AF_PACKET 是内核的被动复制。
func (l *Listener) handleFirstPacket(client netip.AddrPort, p ParsedPacket) (consumed bool) {
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
		// 不是我们的客户端，或密钥不对：不消费本帧（Windows 会把它还给内核）。
		// 公网端口每天大量探测，Linux 上这里等于静默丢弃。
		return false
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
	// 有 pending 就用 SYN 认下的标记。首包再 markOf 一次会在多用户时
	// 命中别的标记，回包的 IP ID 高字节就和客户端规则不一致。
	mark := l.markOf(p)
	if hasPending {
		peerISN, ourISN, ts = st.peerISN, st.ourISN, st.ts
		if st.mark != 0 {
			mark = st.mark
		}
	} else {
		// 客户端跳过了握手：序号与时间戳现取随机值，
		// 但要满足「后续 TSval 不回退」，所以从一个随机基准起步。
		peerISN, ourISN, ts = 0, randomUint32(), randomUint32()
	}

	clock := NewTcpClockAt(ts + 2)
	clock.Observe(p.TSVal, p.HasTS)

	sess := newServerSession(l.raw, entry.codec, client, l.port, ourISN+1, peerISN+1, clock, mark, p.Dst, l.logger)

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
		l.logger.Error("发送 ServerHello 失败: ", err)
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
	return true
}

// newServerSession 构造服务端方向的会话。
//
// logger 由 Listener 传入而不是从 ServerConfig 重新取：
// 同一进程里可能有多个 inbound，从配置取会让日志打错 tag。
func newServerSession(raw *rawSocket, codec *Codec, peer netip.AddrPort,
	localPort uint16, seq, peerSeq uint32, clock *TcpClock, mark uint16,
	localIP netip.Addr, logger Logger) *Session {
	s := &Session{
		raw:   raw,
		codec: codec,
		// logger 恒非 nil：收包/发送路径的错误日志直接调，不需判空。
		logger: loggerOr(logger),
		// 服务端所有会话共享 Listener 的 socket，绝不能在这里关。
		ownsRaw: false,
		peer:    peer,
		// 回包源地址 = 客户端本次发往的地址（即入包的 Dst）。
		//
		// 这是「零配置且永远正确」的源地址：多 IP 主机（公网 + 内网同在
		// 一张网卡）时路由探测拿到的未必是客户端访问的那个 IP，用错
		// 源地址回包会被客户端当无关流量丢掉。
		localIP:    localIP,
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

		// pending 超时：客户端发了 SYN 却不继续握手（扫描/半开连接）。
		// 超时未配置（0）时不回收：0 比任何正的时间差都小，
		// 一到点就会把还没完成的握手状态删掉。
		l.mu.Lock()
		for addr, st := range l.pending {
			if l.handshakeTimeout > 0 && now.Sub(st.at) > l.handshakeTimeout*2 {
				delete(l.pending, addr)
			}
		}
		l.mu.Unlock()

		// 会话空闲超时。同样：未配置时不回收。
		// 否则刚收到包的会话 idleFor 只有几毫秒，照样大于 0，会被立刻关掉。
		var expired []*Session
		l.mu.Lock()
		for addr, s := range l.byAddr {
			if l.idleTimeout > 0 && s.idleFor() > l.idleTimeout {
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
