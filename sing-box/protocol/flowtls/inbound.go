package flowtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	quicgo "github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/luowei729/flowtls"
	ftquic "github.com/luowei729/flowtls/quic"
)

// RegisterInbound 把 flowtls 入站注册进 registry。
// 与 anytls/hysteria2 完全同一形状，新增协议不需要改 registry 本体。
func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.FlowTLSInboundOptions](registry, C.TypeFlowTLS, NewInbound)
}

// Inbound 是 flowtls 服务端入站。
//
// 生命周期分两段，这个分界是**硬约束**：
//
//	NewInbound   —— 只做参数校验，绝不碰 raw socket
//	Start(Start) —— 才申请 raw socket（需要 root / CAP_NET_RAW）
//
// 原因：`sing-box check` 会把 box 完整构造一遍再关闭，
// 构造函数里开 raw socket 会让纯语法检查也要求 root。
type Inbound struct {
	inbound.Adapter
	ctx    context.Context
	router adapter.Router
	logger log.ContextLogger

	users   []flowtls.User
	conf    flowtls.ServerConfig
	lis     flowtls.ListenerOptions
	tlsConf *tls.Config

	server *ftquic.Server
	// masq 是同端口真证书网站，未配置时为 nil。
	masq       *Masquerade
	masqOpts   *option.FlowTLSMasqueradeOptions
	masqListen netip.AddrPort
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// NewInbound 只做参数校验，不申请任何特权资源。
func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.FlowTLSInboundOptions) (adapter.Inbound, error) {
	if len(options.Users) == 0 && options.Password == "" {
		return nil, C.ErrFlowTLSRequirePassword
	}
	if options.ListenPort == 0 {
		return nil, E.New("flowtls: missing listen_port")
	}
	// flowtls 不 bind 内核端口，listen/listen_port 只用于计算
	// 会话四元组与 iptables 规则，所以这里解析成 netip.AddrPort 即可。
	var listenAddr netip.Addr
	if options.Listen != nil {
		listenAddr = options.Listen.Build(netip.IPv4Unspecified())
	} else {
		listenAddr = netip.IPv4Unspecified()
	}

	// 用户表：显式 users 优先；否则单 password 等价于一个匿名用户。
	// 用户名只用于日志，鉴权完全由 authID（密码派生）完成。
	users := make([]flowtls.User, 0, len(options.Users)+1)
	for _, u := range options.Users {
		if u.Name == "" || u.Password == "" {
			return nil, E.New("flowtls: user name and password must not be empty")
		}
		users = append(users, flowtls.User{Name: u.Name, Password: u.Password})
	}
	if len(users) == 0 {
		users = append(users, flowtls.User{Name: "default", Password: options.Password})
	}

	idleTimeout := time.Duration(options.UDPSessionTimeout) * time.Second
	if idleTimeout <= 0 {
		idleTimeout = 120 * time.Second
	}

	// LocalIP 用于回包源地址：云主机在 NAT 后面时路由探测只能拿到内网 IP，
	// 必须由配置显式给出公网地址，否则回包会被对端丢弃。
	var localIP netip.Addr
	if options.LocalIP != "" {
		parsed, err := netip.ParseAddr(options.LocalIP)
		if err != nil {
			return nil, E.Cause(err, "flowtls: invalid local_ip")
		}
		localIP = parsed
	}

	// 内层 QUIC 证书：协议要求必须有 TLS，但安全性由外层 AEAD（密码）保证，
	// 所以每次启动现生成自签证书即可，不需要持久化，也不需要用户配置。
	tlsConf, err := selfSignedTLS()
	if err != nil {
		return nil, E.Cause(err, "flowtls: generate inner TLS certificate")
	}

	// 伪装站只校验必填字段，不读文件：
	// `sing-box check` 可能在证书还没挂载的机器上跑，
	// 真读文件会把它变成一条对环境有依赖的检查。
	// 缺少字段则一定能确定是配置笔误，可以在这里就拒掉。
	// 伪装站的校验分两层，这个分层是刻意的：
	//
	//	这里（构造函数）—— 纯字符串/结构校验。`sing-box check` 会走构造函数，
	//	                     所以这些错误在启动前就能被发现。
	//	newMasquerade（Start）—— 读文件、bind 端口。check 可能在证书还没
	//	                     挂载、也没有特权的机器上跑，这些动作会让 check
	//	                     变成一条对环境有依赖的检查，体验直接崩。
	//
	// 教训：曾经把「proxy_url 与 site_dir 互斥」只写在 Start 里，
	// 结果 check 完全静默通过，配置错了要到启动才知道。
	if options.Masquerade != nil {
		if err := validateMasqueradeOptions(options.Masquerade); err != nil {
			return nil, err
		}
	}

	// iptables 模式在这里解析并保存：拼错要报错，而不是拖到 Start 才
	// 变成一句看不懂的 iptables 报错。真正落地在 Start 阶段
	// （raw socket 之后），但模式值必须现在就确定下来——
	// 漏传会让 print 模式静默退化成 none，日志里看不到任何规则。
	iptablesMode, err := flowtls.ParseIPTablesMode(options.IPTablesMode)
	if err != nil {
		return nil, err
	}

	return &Inbound{
		Adapter: inbound.NewAdapter(C.TypeFlowTLS, tag),
		ctx:     ctx,
		router:  router,
		logger:  logger,
		users:   users,
		tlsConf: tlsConf,
		conf: flowtls.ServerConfig{
			Listen:   netip.AddrPortFrom(listenAddr, options.ListenPort),
			Users:    users,
			LocalIP:  localIP,
			IPIDMark: options.IPIDMark,
		},
		lis: flowtls.ListenerOptions{
			IdleTimeout:  idleTimeout,
			IPTablesMode: iptablesMode,
		},
		// 伪装站与协议用同一个端口：流量分流靠 iptables 规则，
		// 不靠端口差异。
		masqOpts:   options.Masquerade,
		masqListen: netip.AddrPortFrom(listenAddr, options.ListenPort),
	}, nil
}

// Start 在 StartStateStart 阶段才真正监听。
//
// 这里才申请 raw socket：此阶段 sing-box 已退出 check 模式，
// 用户也已经知道自己在跑特权程序。
func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}

	srv, err := ftquic.NewServer(ftquic.ServerOptions{
		FlowTLS:  h.conf,
		Listener: h.lis,
		TLS:      h.tlsConf,
	})
	if err != nil {
		return E.Cause(err, "flowtls: start server on ", h.conf.Listen)
	}
	h.server = srv

	// 规则文本含换行，必须拆开交给 logger，
	// 否则多行会挤在一条日志里、后续行没有时间戳。
	//
	// print 用 WARN：这是需要人动手的事，不能被 INFO 淡化。
	// auto 且本次无新增时用 Debug：重连/重启时规则早就存在，
	// 每次 INFO 一遍只会把有用的日志冲掉。
	if report := srv.ListenerRules(); !report.Empty() {
		for _, line := range strings.Split(report.Text(), "\n") {
			switch {
			case report.Mode == flowtls.IPTablesPrint:
				h.logger.Warn(line)
			case report.Mode == flowtls.IPTablesAuto && report.Added == 0:
				h.logger.Debug(line)
			default:
				h.logger.Info(line)
			}
		}
	}

	// 同端口真证书网站。
	//
	// 放在 raw socket 与 iptables 规则之后：先保证协议能用，
	// 再补伪装。站点启动失败直接返回错误——一个「以为开了但没开」
	// 的伪装站比没有更危险（以为探测已经处理好了）。
	if h.masqOpts != nil {
		masq, err := newMasquerade(h.ctx, netipAddr(h.masqListen), MasqueradeOptions{
			SiteDir:         h.masqOpts.SiteDir,
			CertificatePath: h.masqOpts.CertificatePath,
			KeyPath:         h.masqOpts.KeyPath,
			ProxyURL:        h.masqOpts.ProxyURL,
			RewriteHost:     h.masqOpts.RewriteHost,
		})
		if err != nil {
			_ = h.server.Close()
			return err
		}
		h.masq = masq
		h.logger.Info("flowtls masquerade site listening at ", masq.Addr(),
			" (", masqueradeMode(h.masqOpts), ")")
	}

	// 派生 ctx：入站关闭时能主动唤醒所有阻塞中的 Accept。
	ctx, cancel := context.WithCancel(h.ctx)
	h.cancel = cancel

	h.wg.Add(1)
	go h.acceptLoop(ctx)

	scope.Add(func() error { return h.Close() })
	h.logger.Info("flowtls inbound started at ", h.conf.Listen, " with ", len(h.users), " user(s)")
	return nil
}

// Close 关闭监听与所有在途连接。
func (h *Inbound) Close() error {
	if h.cancel != nil {
		h.cancel()
	}
	if h.masq != nil {
		_ = h.masq.Close()
	}
	if h.server != nil {
		_ = h.server.Close()
	}
	h.wg.Wait()
	return nil
}

// acceptLoop 不断接受新的 QUIC 连接。
//
// 一条 QUIC 连接 = 一个客户端（一个四元组会话），
// 里面的多流复用由 quinn/quic-go 负责。
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
	defer func() {
		_ = conn.CloseWithError(0, "")
	}()
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
//
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
		h.logger.DebugContext(ctx, "flowtls: read address frame: ", err)
		_ = stream.Close()
		_ = conn.CloseWithError(0, "")
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
	host, port, err := flowtls.DecodeAddress(frame)
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
func (h *Inbound) serveDatagrams(ctx context.Context, conn *quicgo.Conn) {
	var (
		mu      sync.Mutex
		session = make(map[uint32]*inboundPacketConn)
	)
	defer func() {
		mu.Lock()
		for _, pc := range session {
			pc.close()
		}
		mu.Unlock()
	}()

	for {
		data, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		id, targetFrame, payload, ok := flowtls.ParseClientDatagram(data)
		if !ok {
			continue
		}
		host, port, err := flowtls.DecodeAddress(targetFrame)
		if err != nil {
			continue
		}
		target := M.ParseSocksaddrHostPort(host, port)

		mu.Lock()
		pc, exists := session[id]
		if !exists {
			pc = newInboundPacketConn(conn, id, target)
			session[id] = pc
			mu.Unlock()

			// 新会话：立刻交给 router 决定出站。
			// target 取自客户端首帧，后续包的地址与它相同。
			var metadata adapter.InboundContext
			metadata.Inbound = h.Tag()
			metadata.InboundType = h.Type()
			metadata.Source = M.SocksaddrFromNet(conn.RemoteAddr())
			metadata.Destination = target
			h.logger.InfoContext(ctx, "inbound UDP to ", target, " session=", id)

			sessID := id
			h.router.RoutePacketConnectionEx(ctx, pc, metadata, func(error) {
				mu.Lock()
				delete(session, sessID)
				mu.Unlock()
			})
		} else {
			mu.Unlock()
		}
		// 投递载荷。队列满说明应用侧消费不过来，按 UDP 语义直接丢。
		pc.push(payload)
	}
}

// inboundPacketConn 把一条 UDP session 包装成 network.PacketConn。
//
// 上行（客户端 → 目标）由 serveDatagrams 调 push 投递；
// 下行（目标 → 客户端）由 WritePacket 封装成 DATAGRAM 发出。
type inboundPacketConn struct {
	conn *quicgo.Conn
	id   uint32
	dest M.Socksaddr

	rx     chan []byte
	closed chan struct{}
	once   sync.Once
}

func newInboundPacketConn(conn *quicgo.Conn, id uint32, dest M.Socksaddr) *inboundPacketConn {
	return &inboundPacketConn{
		conn: conn,
		id:   id,
		dest: dest,
		// 队列深度按「一次往返可能堆多少包」估：
		// 256 × 1200B ≈ 300KB，够吸收突发又不吃内存。
		rx:     make(chan []byte, 256),
		closed: make(chan struct{}),
	}
}

// push 投递一个上行载荷。满则丢。
func (p *inboundPacketConn) push(payload []byte) {
	select {
	case p.rx <- append([]byte(nil), payload...):
	default:
		// UDP 语义：不重传、不分片，队列满即丢。
	}
}

func (p *inboundPacketConn) close() {
	p.once.Do(func() { close(p.closed) })
}

// ReadPacket 实现 network.PacketReader。
//
// 目标地址固定为会话建立时的 target：
// 同一 session 的所有包都发往同一个目标（客户端首帧决定）。
func (p *inboundPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case payload := <-p.rx:
		_, err := buffer.Write(payload)
		if err != nil {
			return M.Socksaddr{}, err
		}
		return p.dest, nil
	case <-p.closed:
		return M.Socksaddr{}, io.EOF
	case <-p.conn.Context().Done():
		return M.Socksaddr{}, io.EOF
	}
}

// WritePacket 把下行载荷封装成 DATAGRAM 发回客户端。
func (p *inboundPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	// buffer 由调用方分配，读完必须归还池子。
	payload := buffer.Bytes()
	out := flowtls.EncodeServerDatagram(nil, p.id, payload)
	buffer.Release()
	// 超 MTU 时 quic-go 返回 DatagramTooLargeError，按 UDP 语义丢弃。
	_ = p.conn.SendDatagram(out)
	return nil
}

// Close 关闭会话。
func (p *inboundPacketConn) Close() error {
	p.close()
	return nil
}

// LocalAddr 返回 QUIC 连接的本地地址。
func (p *inboundPacketConn) LocalAddr() net.Addr {
	return p.conn.LocalAddr()
}

// 三个 deadline 都是空实现：会话生命周期由 QUIC 连接和 onClose 决定，
// 单条 UDP 会话没有独立的超时语义。
func (p *inboundPacketConn) SetDeadline(time.Time) error      { return nil }
func (p *inboundPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (p *inboundPacketConn) SetWriteDeadline(time.Time) error { return nil }

var _ N.PacketConn = (*inboundPacketConn)(nil)

// selfSignedTLS 生成内层 QUIC 用的自签证书。
//
// 内层 TLS 只满足 QUIC 的协议要求，安全由外层 AEAD 保证，
// 因此公钥/私钥都无需持久化，也没有可信度要求。
func selfSignedTLS() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "flowtls"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"flowtls"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		// ALPN 必须与客户端一致，否则 TLS 握手会直接失败。
		NextProtos: []string{"flowtls"},
		MinVersion: tls.VersionTLS13,
	}, nil
}

// streamConn 把 quic-go 的 Stream 补成 net.Conn。
//
// quic-go 的 Stream 只有 Read/Write/Close/SetDeadline，
// 缺 LocalAddr/RemoteAddr——router 需要一个完整 net.Conn
// 来做日志与出站绑定，所以补一层薄包装。
type streamConn struct {
	*quicgo.Stream
	conn *quicgo.Conn
}

func (c *streamConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *streamConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

var _ net.Conn = (*streamConn)(nil)
