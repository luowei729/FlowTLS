package flowtls

// 本文件对应 legacy-rust:src/client.rs 中「建立伪 TCP 连接」的部分：
// `SendCtx` 的初始化、标准三次握手、SYN 退避重传。
//
// Rust 把这些放在 `run_session` 的事件循环里（`awaiting_syn_ack` 状态 +
// `next_syn_at` 定时器）。Go 侧没有用户级事件循环，所以把握手判定放进
// 收包协程（`recvLoop`）——那是唯一读 socket 的地方，与 Rust
// 「收包线程 → channel → 事件循环判定 SYN-ACK」结构等价。

import (
	"context"
	"log"
	"net/netip"
	"time"
)

// 握手参数（与 Rust client.rs 逐项一致）。
const (
	// handshakeTimeout 是「拿到 SYN-ACK」的总时长上限（Rust HANDSHAKE_TIMEOUT）。
	handshakeTimeout = 15 * time.Second
	// synInitialBackoff 是 SYN 首次重传间隔，之后按 1/2/4/8 秒退避。
	synInitialBackoff = 1 * time.Second
	// synMaxBackoff 是退避上限（Rust `syn_backoff = (syn_backoff*2).min(8)`）。
	synMaxBackoff = 8 * time.Second
)

// Dial 建立一条伪造 TCP 连接，返回可直接交给 quic.Transport 的 net.PacketConn。
//
// 握手必须在这里**同步完成**，返回的 Session 已经是 ESTABLISHED 状态：
// quic-go 的 Dial 会立刻写 Initial，如果握手还没完成，
// 服务端（严格 NAT 后的状态防火墙）会直接丢弃这些包。
func Dial(ctx context.Context, cfg ClientConfig) (*Session, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	raw, err := newRawSocket(cfg.Server.Addr(), netip.Addr{})
	if err != nil {
		return nil, err
	}
	// 与 Rust `tracing::info!(%server_ip, %server_port, %local_ip, ...)` 对位：
	// 这两行是排查「包发到哪去了」的第一现场证据。
	log.Printf("flowtls: FakeTCP 通道已就绪 server=%s local=%s 模式=%s",
		cfg.Server, raw.LocalIP(), raw.SendMode())

	// 客户端规则必须在**第一个包发出之前**就位。
	//
	// SYN-ACK 一回，内核就会发现没有对应 socket 并回 RST，
	// 而 RST 是协议合法的终止信号，中间设备会立即拆掉 NAT 映射。
	if cfg.NetMode == ModeAuto {
		if err := EnsureClient(cfg.SourcePort, cfg.Server.Port(), cfg.IPIDMark); err != nil {
			_ = raw.Close()
			return nil, err
		}
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

	// 随机初始序列号（Rust `rand::thread_rng().gen()`）。
	isn := randomUint32()
	s := &Session{
		raw:   raw,
		codec: codec,
		// **必须显式设为 true**：零值 false 表示「共享 socket，绝不关闭」，
		// 那是服务端的语义。漏设会让每次重连泄漏 3 个 fd。
		ownsRaw:    true,
		peer:       cfg.Server,
		localPort:  cfg.SourcePort,
		remotePort: cfg.Server.Port(),
		ipid:       RandomIPID(mark),
		mark:       mark,
		clock:      NewTcpClock(),
		// Rust 在 SYN 之前就把 seq 设为 isn+1（SYN 占 1 个序号）
		seq:     isn + 1,
		lastAck: time.Now(),
		rx:      make(chan []byte, rxQueueDepth),
		closeCh: make(chan struct{}),
		// 握手门闩与 SNI：漏了这两个会导致 exchangeSYN 永久阻塞
		// （handshakeDone 为 nil 时 close 会 panic / 接收会永远挂起）。
		handshakeDone: make(chan struct{}),
		sni:           cfg.SNI,
	}
	s.synISN = isn
	s.awaitingSYNACK.Store(cfg.Handshake != HandshakeNone)

	// 收包协程必须先起来：握手判定在它里面完成（见文件头说明）。
	s.StartReceiver()

	if cfg.Handshake == HandshakeNone {
		// 跳过握手（要求客户端有公网 IP，且链路无状态防火墙）。
		// Rust 同样把 peer_seq 留 0 后直接开始 drain_transmits。
		s.peerSeq = 0
		return s, nil
	}

	if err := s.exchangeSYN(ctx); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// exchangeSYN 发送 SYN 并等待收包协程完成三次握手（对应 Rust 的握手状态机）。
//
// 重传策略与 Rust 一致：1/2/4/8 秒退避，总时长 15 秒。
// 必须复用同一个 ISN——真实 TCP 重传 SYN 用同一序号，
// 换新值会让服务端的 SYN 缓存对不上，也不会回我们的 ACK。
func (s *Session) exchangeSYN(ctx context.Context) error {
	opts := SynOptions(s.clock.TSVal(), 0)
	syn := BuildPacket(s.raw.localIP, s.peer.Addr(), s.localPort, s.remotePort, TcpSeg{
		Seq:   s.synISN,
		Ack:   0,
		Flags: TCPSYN,
		IPID:  s.ipid,
		// SYN 阶段真实 Linux 通告的是 65535，缩放因子要到 ESTABLISHED 才生效
		Window:  65535,
		TSVal:   s.clock.TSVal(),
		TSecr:   0,
		Options: opts[:],
	})
	if err := s.raw.Send(syn, s.peer.Addr()); err != nil {
		return err
	}
	s.pktsSent.Add(1)

	deadline := time.NewTimer(handshakeTimeout)
	defer deadline.Stop()
	backoff := synInitialBackoff
	retry := time.NewTimer(backoff)
	defer retry.Stop()

	for {
		select {
		case <-s.handshakeDone:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-s.closeCh:
			return ErrSessionClosed
		case <-deadline.C:
			log.Printf("flowtls: 握手超时（SYN-ACK 未到达），放弃本次连接")
			return ErrHandshakeTimeout
		case <-retry.C:
			// 重传 SYN：序号不变、选项不变，只有 TSval 推进、IP ID 递增。
			opts := SynOptions(s.clock.TSVal(), 0)
			syn := BuildPacket(s.raw.localIP, s.peer.Addr(), s.localPort, s.remotePort, TcpSeg{
				Seq:     s.synISN,
				Flags:   TCPSYN,
				IPID:    s.ipid,
				Window:  65535,
				TSVal:   s.clock.TSVal(),
				Options: opts[:],
			})
			if err := s.raw.Send(syn, s.peer.Addr()); err == nil {
				s.pktsSent.Add(1)
			}
			s.mu.Lock()
			s.ipid = NextIPID(s.mark, s.ipid)
			s.mu.Unlock()
			backoff *= 2
			if backoff > synMaxBackoff {
				backoff = synMaxBackoff
			}
			retry.Reset(backoff)
		}
	}
}

// handleSYNACK 处理 SYN-ACK：完成三次握手并发出伪 ClientHello。
//
// 对应 Rust 事件循环里的 SYN-ACK 分支：
//
//	ctx.peer_seq = seq + 1;
//	ctx.send_pure_ack(advertised_window(0));
//	发送伪 ClientHello（payload = hello）;
//	awaiting_syn_ack = false;
func (s *Session) handleSYNACK(p ParsedPacket) {
	s.mu.Lock()
	s.peerSeq = p.Seq + 1
	s.clock.Observe(p.TSVal, p.HasTS)
	s.mu.Unlock()

	// 先回 ACK 完成三次握手（window = advertised_window(0) = 32768）
	s.sendPureACK()

	// 再发伪 ClientHello。
	//
	// 没有这一步，线上字节流就是「TCP 握手完立刻 17 03 03」——
	// 真实 TLS 永远先有 16 03 01/03 的 ClientHello，
	// 按「第一个应用层字节」分类的 DPI 一眼就能判定这不是 HTTPS。
	hello := BuildClientHello(s.sni)
	s.mu.Lock()
	pkt := s.appendSegmentLocked(s.wPkt[:0], hello, TCPPSH|TCPACK)
	err := s.raw.Send(pkt, s.peer.Addr())
	s.mu.Unlock()
	if err != nil {
		s.noteSendError(err)
	} else {
		s.pktsSent.Add(1)
	}

	// 握手完成：唤醒 exchangeSYN
	s.awaitingSYNACK.Store(false)
	s.onceHandshake.Do(func() { close(s.handshakeDone) })
}

// isSYNACKFor 判断这个包是否是我们正在等待的 SYN-ACK。
//
// 判定条件与 Rust `client.rs:767` 逐字对齐：
//
//	if flags & TCP_SYN != 0 && flags & TCP_ACK != 0 && awaiting_syn_ack
//
// **刻意不校验 `p.Ack == synISN+1`**。上一版多加了这一条，看起来更严格，
// 实际是多余的：四元组已经由 matchPeer 过滤过，源端口/IP 都对得上，
// 能走到这里的 SYN+ACK 只可能来自同一个对端。而多一条校验只会带来
// 一种后果——一旦 ACK 号因为任何原因（对端 pending 状态、中间设备改写）
// 对不上，有效的 SYN-ACK 被**静默丢弃**，客户端只能在 1/2/4/8 秒退避后
// 重传 SYN，很容易撞上 sing-box 那侧的建连超时（实测日志里
// `flowtls 握手失败: context deadline exceeded`）。
//
// 真正的鉴权是后续 AEAD，不靠这个字段，所以放宽不会降低安全性。
func (s *Session) isSYNACKFor(p ParsedPacket) bool {
	return p.Flags&TCPSYN != 0 && p.Flags&TCPACK != 0
}
