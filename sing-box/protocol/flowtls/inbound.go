package flowtls

// sing-box 入站适配层。
//
// 本文件**只做协议 ↔ sing-box 的翻译**，与 Rust 的对应关系：
//
//	Rust server.rs handle_packet「每客户端一条连接」
//	  → 这里 ftquic.Server.Accept 返回的 *quic.Conn
//	Rust server.rs read_stream + outbound
//	  → sing-box router（RouteConnectionEx 直接接管流）
//	Rust server.rs handle_udp_datagrams + udp_outbound
//	  → sing-box router（RoutePacketConnectionEx + canceler 管生命周期）
//
// Rust 自己实现 SOCKS5/HTTP 入口与出站拨号，Go 侧全部由 sing-box 提供，
// 所以这里的代码量比 Rust 小得多——但**协议行为完全一致**。

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"

	quicgo "github.com/sagernet/quic-go"

	ft "github.com/luowei729/flowtls"
	ftquic "github.com/luowei729/flowtls/quic"
)

// RegisterInbound 把 flowtls 入站注册进 registry。
func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.FlowTLSInboundOptions](registry, C.TypeFlowTLS, NewInbound)
}

var _ adapter.Inbound = (*Inbound)(nil)

// Inbound 是 flowtls 入站。
type Inbound struct {
	inbound.Adapter
	ctx    context.Context
	router adapter.Router
	logger log.ContextLogger
	opts   option.FlowTLSInboundOptions

	server *ftquic.Server
	masq   *masquerade

	// udpOn 对应 Rust `udp.enabled`；udpIdleTimeout / udpMaxSessions 对应
	// `udp.timeout_secs` / `udp.max_sessions`。
	udpOn          bool
	udpIdleTimeout time.Duration
	udpMaxSessions int

	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// NewInbound 只校验参数。真正的监听在 Start(StartStateStart)。
func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.FlowTLSInboundOptions) (adapter.Inbound, error) {
	// 凭据：password（单密码）/ passwords（多密码）/ users（旧写法）
	// **三者互斥**，且空值、重复项都要在这里拦住。
	//
	// 放在 NewInbound 而不只在 flowtls.ServerConfig.Validate 里，是因为
	// `sing-box check` 只走 NewInbound、不走 Start —— 而"配置校验不需要
	// root"是项目的硬要求，错误必须在 check 阶段就暴露。
	//
	// 同时填多个来源必须报错而不是"以某个为准"：被忽略的那个既不参与
	// 登录、也不参与 ISN 标记派生，留着只会让人以为它是兜底凭据，
	// 而 mark 不一致的症状是隧道完全不通（DEVTIPS 149）。
	//
	// 复用 ft.NormalizePasswords 而不是在这里重写一遍判断：
	// 互斥/空值/去重三套规则分散在两层各写一份，一旦走偏就会出现
	// 「check 通过但起不来」这种最难查的不一致。
	if _, err := ft.NormalizePasswords(options.Password, options.Passwords, legacyPasswords(options.Users)); err != nil {
		return nil, err
	}
	if options.ListenPort == 0 {
		return nil, E.New("flowtls: listen_port is required")
	}
	// ISNMark 保持 0（表示按每个用户的 password 各自派生）。
	//
	// 服务端是**多用户**的：它不能只算一个标记，而要把每个用户的都纳入
	// 识别范围（内核层判断「是不是我们的包」时还没解密）。这件事由
	// flowtls.ServerConfig.Marks() 统一处理，这里不预先填值。
	//
	// 握手参数在这里就校验，让 `sing-box check` 能拓出拼写错误
	// （Rust config 校验同样在建连前）。
	if _, err := ft.ParseHandshake(options.Handshake); err != nil {
		return nil, err
	}
	// 同客户端：没配带宽时明确告警（服务端 1 Gbps 兑底同样会让 loss_pct 虚高）。
	// 服务端这一侧尤其重要 —— 它上报的 loss_pct 被运维用来判断链路质量，
	// 而兑底超发造成的假丢包会把人引向错误的方向（排查过一整天）。
	warnIfNoBandwidth(logger, options.UpMbps, options.DownMbps)
	if options.Masquerade != nil {
		if options.Masquerade.CertificatePath == "" || options.Masquerade.KeyPath == "" {
			return nil, E.New("flowtls: masquerade 需要 certificate_path 与 key_path（必须是真证书）")
		}
	}

	udpIdle := time.Duration(options.UDPSessionTimeout) * time.Second
	if udpIdle <= 0 {
		udpIdle = 120 * time.Second // Rust default_udp_timeout
	}
	udpMax := options.UDPMaxSessions
	if udpMax <= 0 {
		udpMax = 256 // Rust default_udp_sessions
	}

	return &Inbound{
		Adapter:        inbound.NewAdapter(C.TypeFlowTLS, tag),
		ctx:            ctx,
		router:         router,
		logger:         logger,
		opts:           options,
		udpOn:          udpOn(options.UDPEnabled),
		udpIdleTimeout: udpIdle,
		udpMaxSessions: udpMax,
	}, nil
}

// legacyPasswords 把已废弃的 users[] 压成密码列表。
//
// name 被丢弃：服务端从 rev.12 起只有「凭据」概念，没有「用户」。
// 留在结构里只为让旧配置能被解析（删字段会触发 unknown field 拒绝启动）。
func legacyPasswords(users []option.FlowTLSUser) []string {
	if len(users) == 0 {
		return nil
	}
	out := make([]string, 0, len(users))
	for _, u := range users {
		out = append(out, u.Password)
	}
	return out
}

// Start 在 StartStateStart 阶段监听。
//
// 必须在 Start 里调用 NewServer：它会申请 raw socket（需要 root），
// 放在 NewInbound 里会让 `sing-box check` 也要求 root。
func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}

	listenAddr, err := h.listenAddrPort()
	if err != nil {
		return err
	}
	handshake, err := ft.ParseHandshake(h.opts.Handshake)
	if err != nil {
		return err
	}
	// 凭据归一（NewInbound 已校验过一次，这里拿到实际生效的列表）。
	// 两处都调同一个函数，所以不会出现「check 用一套规则、启动用另一套」。
	passwords, err := ft.NormalizePasswords(h.opts.Password, h.opts.Passwords, legacyPasswords(h.opts.Users))
	if err != nil {
		return err
	}

	cfg := ft.ServerConfig{
		Listen:         listenAddr,
		Passwords:      passwords,
		Handshake:      handshake,
		ISNMark:        h.opts.ISNMark,
		UDPEnabled:     &h.udpOn,
		UDPTimeoutSecs: int(h.udpIdleTimeout / time.Second),
		UDPMaxSessions: h.udpMaxSessions,
		// 直接注入 sing-box 的 logger：它的 Debug/Info/Warn/Error
		// 签名与 ft.Logger 逐字一致，因此不需要适配器。
		//
		// 注入之后，flowtls 传输层（握手上失败、收包失败、截断告警、
		// 清理旧会话等）全部受 `log.level` 控制；不注入则完全静默。
		Logger: h.logger,
	}
	if h.opts.LocalIP != "" {
		a, perr := netip.ParseAddr(h.opts.LocalIP)
		if perr != nil || !a.Unmap().Is4() {
			return E.New("flowtls: local_ip 不是合法 IPv4: ", h.opts.LocalIP)
		}
		cfg.LocalIP = a.Unmap()
	}

	onStats := func(s ftquic.PathStats) {
		h.logger.Debug("flowtls: QUIC 路径统计 peer=", s.Remote,
			" rtt=", s.RTT.Round(time.Millisecond),
			" srtt=", s.SmoothedRTT.Round(time.Millisecond),
			" cwnd=", s.Cwnd, " inflight=", s.InFlight,
			" sent=", s.SentPackets, " lost=", s.LostPackets,
			" loss_pct=", s.LossPct, " win_cap=", s.WinCap,
			" conns=", s.Conns)
	}

	srv, err := ftquic.NewServer(ftquic.ServerOptions{
		FlowTLS: cfg,
		// 与 hysteria2 同一对：up 限本端发送，down 回给客户端限它的发送。
		// 真正发出去的是 min(本端 up, 客户端报的 down)。
		SendBPS:    mbpsToBPS(h.opts.UpMbps),
		ReceiveBPS: mbpsToBPS(h.opts.DownMbps),
		OnStats:    onStats,
	})
	if err != nil {
		return E.Cause(err, "flowtls: start server on ", listenAddr)
	}
	h.server = srv
	h.logger.Info("flowtls 服务端已就绪 ", srv.Addr(),
		"（凭据 ", srv.Credentials(), " 条）; 发送路径: ", srv.SendMode())

	// 伪装网站：与 Rust 一样**真 bind 内核 TCP 端口**。
	// 伪包在 raw 表被 DROP，剩下的包才落到这个站点上。
	if h.opts.Masquerade != nil {
		m, merr := newMasquerade(h.masqueradeHost(), h.opts.ListenPort, h.opts.Masquerade, h.logger)
		if merr != nil {
			_ = srv.Close()
			return merr
		}
		h.masq = m
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			m.serve()
		}()
	}

	ctx, cancel := context.WithCancel(h.ctx)
	h.cancel = cancel
	h.wg.Add(1)
	go h.acceptLoop(ctx)

	scope.Add(h.Close)
	return nil
}

// listenAddrPort 把配置里的 listen / listen_port 归一成 netip.AddrPort。
//
// 空 listen 视为全部 IPv4 地址（0.0.0.0）：FakeTCP 目前只支持 IPv4，
// 显式落到 IPv4 上比交给内核双栈判断更可控。
func (h *Inbound) listenAddrPort() (netip.AddrPort, error) {
	addr, err := h.listenIPv4()
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(addr, h.opts.ListenPort), nil
}

// listenIPv4 只是 listenAddrPort 的拆解，mask/伪装站 也要用。
func (h *Inbound) listenIPv4() (netip.Addr, error) {
	// Rust 的 `[server] listen` 默认 0.0.0.0:8443；这里用同一个默认值。
	addr := h.opts.Listen.Build(netip.IPv4Unspecified()).Unmap()
	if !addr.Is4() {
		return netip.Addr{}, E.New("flowtls: listen 必须是 IPv4，得到 ", addr)
	}
	return addr, nil
}

// masqueradeHost 给出伪装站 bind 的 IP 文本。
func (h *Inbound) masqueradeHost() string {
	addr, err := h.listenIPv4()
	if err != nil || addr.IsUnspecified() {
		return "0.0.0.0"
	}
	return addr.String()
}

// Close 停止服务。
func (h *Inbound) Close() error {
	h.closeOnce.Do(func() {
		if h.cancel != nil {
			h.cancel()
		}
		if h.masq != nil {
			h.masq.close()
		}
		if h.server != nil {
			_ = h.server.Close()
		}
	})
	h.wg.Wait()
	return nil
}

// acceptLoop 不断接受新的 QUIC 连接。
//
// 一条 QUIC 连接 = 一个客户端（一个伪造 TCP 四元组会话），
// 里面的多流复用由 quic-go 负责。
func (h *Inbound) acceptLoop(ctx context.Context) {
	defer h.wg.Done()
	for {
		conn, err := h.server.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// 单条会话失败不影响监听（可能是对端异常断开）
			h.logger.DebugContext(ctx, "flowtls: accept: ", err)
			continue
		}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			h.serveConn(ctx, conn)
		}()
	}
}

// serveConn 在一条 QUIC 连接上同时处理 TCP 流与 UDP 数据报。
//
// 两条通路必须并行：TCP 走双向流，UDP 走 RFC 9221 DATAGRAM，
// 在 QUIC 层它们是不同机制，串行会互相阻塞。
func (h *Inbound) serveConn(ctx context.Context, conn *quicgo.Conn) {
	defer func() { _ = conn.CloseWithError(0, "") }()
	h.logger.DebugContext(ctx, "flowtls: connection from ", conn.RemoteAddr())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		h.serveStreams(ctx, conn)
	}()
	go func() {
		defer wg.Done()
		h.serveDatagrams(ctx, conn)
	}()
	wg.Wait()
}

// serveStreams 接受流并把每条流交给 router。
func (h *Inbound) serveStreams(ctx context.Context, conn *quicgo.Conn) {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go h.handleStream(ctx, conn, stream)
	}
}

// handleStream 解析目标地址帧，然后交给 router。
//
// 每条流的首帧是目标地址：[len u16][ATYP][ADDR][PORT]。
// **必须由本层读掉这一帧才能路由**——这是本协议与 vless/trojan 的关键差别：
// 那里目标地址在协议握手头里，这里它在流内的第一帧，
// router 不知道这个约定，所以不能把裸流直接丢过去。
func (h *Inbound) handleStream(ctx context.Context, conn *quicgo.Conn, stream *quicgo.Stream) {
	// 首帧长度是 u16，正常只有几十字节。
	// 给 8 秒上限：连地址帧都读不出来，说明对端不是本协议或链路已断。
	_ = stream.SetReadDeadline(time.Now().Add(8 * time.Second))
	destination, err := readAddressFrame(stream)
	_ = stream.SetReadDeadline(time.Time{})
	if err != nil {
		// **只关这条流，绝不关整条连接**：一条 QUIC 连接上同时有几十条流
		// （浏览器并发请求），关连接会把其他正在传输的流一起杀掉。
		h.logger.DebugContext(ctx, "flowtls: read address frame: ", err)
		stream.CancelRead(0)
		_ = stream.Close()
		return
	}

	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Source = M.SocksaddrFromNet(conn.RemoteAddr())
	metadata.Destination = destination

	h.logger.InfoContext(ctx, "inbound connection to ", destination)
	// quic-go 的 Stream 只有 Read/Write/Close/Deadline，
	// 缺 LocalAddr/RemoteAddr，不满足 net.Conn，补一层薄包装。
	h.router.RouteConnectionEx(ctx, &streamConn{Stream: stream, conn: conn}, metadata, nil)
}

// readAddressFrame 从流里读一帧目标地址。
func readAddressFrame(reader io.Reader) (M.Socksaddr, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(reader, lenBuf[:]); err != nil {
		return M.Socksaddr{}, err
	}
	frameLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if frameLen == 0 || frameLen > 300 {
		return M.Socksaddr{}, E.New("flowtls: invalid address frame length ", frameLen)
	}
	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(reader, frame); err != nil {
		return M.Socksaddr{}, err
	}
	host, port, err := ft.DecodeAddressFrame(frame)
	if err != nil {
		return M.Socksaddr{}, err
	}
	return M.ParseSocksaddrHostPort(host, port), nil
}

// serveDatagrams 接收 UDP 数据报并按 session 分发。
//
// quic-go 的 ReceiveDatagram 是**单消费者**语义：
// 多个协程同时读会互相抢包，所以这里只有一个循环，
// 收到后自己按 session 号分发到对应的 PacketConn。
//
// **UDP 会话必须有回收，否则会拖垮整机**：每个会话在服务端占一个出站
// UDP socket，而 Linux 临时端口只有约 28k 个。这里用 sing-box 标准的
// `canceler.NewPacketConn` 管生命周期（与 hysteria2 同款），
// 它靠 SetReadDeadline 驱动空闲回收——所以那个方法必须真生效。
func (h *Inbound) serveDatagrams(ctx context.Context, conn *quicgo.Conn) {
	var (
		mu      sync.Mutex
		session = make(map[uint32]*inboundPacketConn)
	)

	// 连接结束时统一关闭所有会话。
	defer func() {
		mu.Lock()
		sessions := make([]*inboundPacketConn, 0, len(session))
		for _, pc := range session {
			sessions = append(sessions, pc)
		}
		mu.Unlock()
		for _, pc := range sessions {
			_ = pc.Close()
		}
	}()

	for {
		data, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if !h.udpOn {
			// Rust 行为：关掉时不留在缓冲里（否则接收队列一直满），读出即丢。
			continue
		}
		id, targetFrame, payload, ok := ft.ParseClientDatagram(data)
		if !ok {
			continue
		}
		host, port, derr := ft.DecodeAddressFrame(targetFrame)
		if derr != nil {
			continue
		}
		target := M.ParseSocksaddrHostPort(host, port)

		mu.Lock()
		pc, exists := session[id]
		// 已超时/已关闭的会话不能复用：它可能正在被 router 拆除，
		// 复用会让新包投进一个死连接。
		if !exists || pc.ctx.Err() != nil {
			// 上限只拦**新建**，不驱逐已有会话（与 Rust 同样取舍）：
			// 驱逐正在传数据的会话会无故丢流，拒绝新会话只影响新发起的那一条。
			if len(session) >= h.udpMaxSessions {
				mu.Unlock()
				h.logger.DebugContext(ctx, "flowtls: UDP 会话数已达上限 ",
					h.udpMaxSessions, "，丢弃新会话 ", id)
				continue
			}
			pc = newInboundPacketConn(h.ctx, conn, id, target, func() {
				mu.Lock()
				delete(session, id)
				mu.Unlock()
			})
			session[id] = pc
			mu.Unlock()

			// 新会话：交给 router 决定出站。
			// target 取自客户端首帧，该会话后续包的地址与它相同。
			var metadata adapter.InboundContext
			metadata.Inbound = h.Tag()
			metadata.InboundType = h.Type()
			metadata.Source = M.SocksaddrFromNet(conn.RemoteAddr())
			metadata.Destination = target
			h.logger.DebugContext(ctx, "inbound UDP to ", target, " session=", id)

			sessCtx, sessConn := canceler.NewPacketConn(pc.ctx, pc, h.udpIdleTimeout)
			go h.router.RoutePacketConnectionEx(sessCtx, sessConn, metadata, nil)
		} else {
			mu.Unlock()
		}
		// 投递载荷。队列满说明应用侧消费不过来，按 UDP 语义直接丢。
		pc.push(payload)
	}
}

// inboundPacketConn 把一条 UDP session 包装成 network.PacketConn。
//
// 结构与生命周期照 hysteria2 的 udpPacketConn：
//
//	ctx + cancel  —— 管生命周期。Close / 超时 / 连接断开都走 cancel，
//	                 读方 select 到 ctx.Done() 就退出。
//	readDeadline  —— 管读超时。canceler.NewPacketConn 靠它实现空闲回收，
//	                 所以 SetReadDeadline **必须真的生效**。
//	onDestroy     —— 从会话表里删除自己，避免表无限增长。
//
// 为什么不用「关闭通道」：读方与写方是两个协程，关通道会让写方 panic。
// ctx 没有这个问题。
type inboundPacketConn struct {
	ctx    context.Context
	cancel context.CancelCauseFunc

	conn *quicgo.Conn
	id   uint32
	dest M.Socksaddr
	data chan []byte

	closeOnce sync.Once
	onDestroy func()
	// readDeadline 由 canceler 驱动。用 sing 的 pipe.Deadline，
	// 与 hy2 同一实现，不自己造定时器。
	readDeadline pipe.Deadline
}

func newInboundPacketConn(ctx context.Context, conn *quicgo.Conn, id uint32, dest M.Socksaddr, onDestroy func()) *inboundPacketConn {
	// 父 ctx 取 Inbound 的 ctx：入站关闭时所有会话一起作废。
	childCtx, cancel := context.WithCancelCause(ctx)
	return &inboundPacketConn{
		ctx:    childCtx,
		cancel: cancel,
		conn:   conn,
		id:     id,
		dest:   dest,
		// 队列深度按「一次往返可能堆多少包」估：
		// 64 × 1200B ≈ 77KB，与 hy2 取值一致。
		data:         make(chan []byte, 64),
		onDestroy:    onDestroy,
		readDeadline: pipe.MakeDeadline(),
	}
}

// push 投递一个上行载荷。满则丢。
//
// **不能返回错误也不能阻塞**：UDP 不重传，阻塞会让一条慢会话拖死
// 整条 QUIC 连接的 DATAGRAM 接收循环（所有会话一起受影响）。
func (p *inboundPacketConn) push(payload []byte) {
	select {
	case p.data <- append([]byte(nil), payload...):
	case <-p.ctx.Done():
		// 会话已回收：丢弃（UDP 语义）
	default:
		// 队列满：丢弃（UDP 语义）
	}
}

// ReadPacket 实现 network.PacketReader。
//
// 目标地址固定为会话建立时的 dest：同一 session 的所有包都发往同一个目标
// （由客户端首帧决定）。
func (p *inboundPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case payload := <-p.data:
		_, err := buffer.Write(payload)
		if err != nil {
			return M.Socksaddr{}, err
		}
		return p.dest, nil
	case <-p.ctx.Done():
		return M.Socksaddr{}, io.ErrClosedPipe
	case <-p.readDeadline.Wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

// WritePacket 把下行载荷封装成 DATAGRAM 发回客户端。
func (p *inboundPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	out := ft.EncodeServerDatagram(nil, p.id, buffer.Bytes())
	buffer.Release()
	// 超 MTU / 连接已断：按 UDP 语义直接丢，**不返回错误**。
	// 返回错误会让 router 的双向拷贝退出并关闭整个会话——
	// 一个过大的包不该杀掉一条健康的会话。
	_ = p.conn.SendDatagram(out)
	return nil
}

// Close 关闭会话。
func (p *inboundPacketConn) Close() error {
	p.closeOnce.Do(func() {
		p.cancel(os.ErrClosed)
		p.onDestroy()
	})
	return nil
}

func (p *inboundPacketConn) LocalAddr() net.Addr { return p.conn.LocalAddr() }

func (p *inboundPacketConn) SetDeadline(t time.Time) error      { return nil }
func (p *inboundPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// SetReadDeadline **必须真的生效**，不能空实现。
//
// sing-box 的 canceler.NewPacketConn 会先试 SetReadDeadline：
// 返回 nil 就走 deadline 分支（靠它判断空闲）。空实现返回 nil 会让那条分支
// 永不超时——会话不回收、出站 UDP socket 不释放，最终吃光整机临时端口。
func (p *inboundPacketConn) SetReadDeadline(t time.Time) error {
	p.readDeadline.Set(t)
	return nil
}

var _ N.PacketConn = (*inboundPacketConn)(nil)

// streamConn 把 quic-go 的 Stream 补成 net.Conn。
//
// quic-go 的 Stream 只有 Read/Write/Close/SetDeadline，
// 缺 LocalAddr/RemoteAddr——router 需要一个完整 net.Conn 来做日志与出站绑定。
type streamConn struct {
	*quicgo.Stream
	conn *quicgo.Conn
}

func (c *streamConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *streamConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// writeStallTimeout 与客户端的 openStreamTimeout 同值。
// 服务端是上传方向的写端，客户端不再读时同样会把整条连接的发送窗口占死。
const writeStallTimeout = 8 * time.Second

// targetWriteStallTimeout 是「写 dial 出去的目标连续零进展」的上限。
//
// 上传方向 relay 把 QUIC 流写进目标连接。目标停读时这一写堵在内核里，
// 本流的 Read 不会再被调用，客户端那 4MB 接收窗口就一直被占着。
// 判据与客户端写本地同一套：一次写入有字节出去就重新计时。
const targetWriteStallTimeout = 8 * time.Second

// Write 与客户端 StreamConn.Write 同一规则：零进展持续一个超时就放弃，
// 有进展就当成功返回。服务端没有「整条通道重建」这一层（连接是客户端拨进来的），
// 所以这里只放弃这一条流：CancelWrite 让对端停掉对应方向并释放窗口。
func (c *streamConn) Write(p []byte) (int, error) {
	_ = c.Stream.SetWriteDeadline(time.Now().Add(writeStallTimeout))
	n, err := c.Stream.Write(p)
	_ = c.Stream.SetWriteDeadline(time.Time{})
	if err == nil || n > 0 {
		return n, nil
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		c.Stream.CancelWrite(0)
		return 0, E.Cause(err, "flowtls: 写方向连续 ", writeStallTimeout, " 零进展，放弃该流")
	}
	return 0, err
}

// unblockStuckWrite 唤醒卡在流控窗口上的 Write。
//
// quic-go 的 Stream.Close() 不唤醒阻塞中的 Write，只有写超时会。
// 设一个已经过去的 deadline 只让那次 Write 返回错误，
// 已写入的数据和 FIN 不受影响。死锁链条见
// flowtls/quic/client.go 的 StreamConn.unblockStuckWrite。
func (c *streamConn) unblockStuckWrite() {
	_ = c.Stream.SetWriteDeadline(time.Now())
}

// CloseWrite 只关写方向。
//
// 必须显式实现：quic-go 的 Stream 有 Close() 但没有 CloseWrite()，
// 不实现的话 sing-box relay（route/conn.go）的类型断言失败，
// 一个方向结束就走 Close() 把整条流关掉。
func (c *streamConn) CloseWrite() error {
	err := c.Stream.Close()
	c.unblockStuckWrite()
	return err
}

// CloseRead 只关读方向，让对端停写这条流。
func (c *streamConn) CloseRead() error {
	c.Stream.CancelRead(0)
	return nil
}

// Close 关闭双向。
//
// 嵌入的 Stream.Close() 只关写方向，所以必须覆盖：先 CancelRead 让对端停发，
// 再 Close 发 FIN，最后唤醒卡在流控上的写协程。
func (c *streamConn) Close() error {
	c.Stream.CancelRead(0)
	err := c.Stream.Close()
	c.unblockStuckWrite()
	return err
}

// GuardLocalWrite 包住 relay 写入的另一端。
//
// 服务端的另一端是 dial 出去的目标。客户端上传、目标停读时，
// 这一写堵在目标连接的内核缓冲里，QUIC 流上的超时都不会被调用，
// 这条流占的接收窗口就还不回去。
//
// 连续 targetWriteStallTimeout 一个字节都写不进目标，就关闭本条流。
// CancelRead 归还窗口，同连接上的其它流继续。
func (c *streamConn) GuardLocalWrite(peer net.Conn) net.Conn {
	return &stalledPeerConn{Conn: peer, stream: c}
}

// stalledPeerConn 只改写的超时，读、关闭、地址都交给被包的连接。
type stalledPeerConn struct {
	net.Conn
	stream *streamConn
}

func (c *stalledPeerConn) Write(p []byte) (int, error) {
	// 每次写入重新计时：有字节出去就当这次成功，慢的目标不会被关。
	_ = c.Conn.SetWriteDeadline(time.Now().Add(targetWriteStallTimeout))
	n, err := c.Conn.Write(p)
	_ = c.Conn.SetWriteDeadline(time.Time{})
	if err == nil || n > 0 {
		return n, nil
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		_ = c.stream.Close()
		return 0, E.Cause(err, "flowtls: 写目标连接连续 ", targetWriteStallTimeout, " 零进展，放弃该流")
	}
	return 0, err
}

// CloseWrite 转给内层。包装不能盖住目标连接自己的半关闭，
// 否则 relay 在一个方向结束时会把整条连接关掉。
func (c *stalledPeerConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return c.Conn.Close()
}

func (c *stalledPeerConn) CloseRead() error {
	if r, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return r.CloseRead()
	}
	return nil
}

var (
	_ net.Conn = (*streamConn)(nil)
	// 半关闭能力：缺了 relay 就会整条关闭，详见 CloseWrite。
	_ interface{ CloseRead() error }  = (*streamConn)(nil)
	_ interface{ CloseWrite() error } = (*streamConn)(nil)
)

// 屏蔽未使用告警：N 包在本文件里只用于接口断言。
var _ = N.NetworkName
