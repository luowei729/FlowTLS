package quic

// 本文件对应 legacy-rust:src/server.rs 里 QUIC 侧的装配：
// `Endpoint::new(server_config)` + `endpoint.accept(...)` 创建服务端连接。
//
// 库边界差异（必须在文档里说清）：
//
//	quinn-proto：一个 Endpoint 管所有连接，accept 时把「首包数据报」喂进去
//	quic-go   ：Transport 绑一个 PacketConn，一条会话一个 Transport
//
// 这里选「每客户端一个 Transport」，原因是硬性的：
//   - deadline 语义不打架：每个 Transport 会对 PacketConn 调 SetReadDeadline
//     驱动自己的定时器。共用一个 PacketConn 时只能取最小 deadline，
//     一个客户端的超时会打断其他客户端的读取。
//   - 快客户端不会饿死慢客户端：聚合后只有一个 readLoop。
//   - 一条会话出错只影响自己。
//
// 真正该省的不是 Transport 而是 raw socket —— 那个已经由 flowtls.Listener 共享了。

import (
	"context"
	"crypto/tls"
	"net/netip"
	"sync"

	quicgo "github.com/sagernet/quic-go"

	"github.com/luowei729/flowtls"
)

// ServerOptions 是服务端参数。
type ServerOptions struct {
	// FlowTLS 是监听参数（端口、用户表、分流标记、空闲回收等）。
	FlowTLS flowtls.ServerConfig
	// Listener 是底层监听参数。
	Listener flowtls.ListenerOptions
	// TLS 是内层 QUIC 的证书配置；为 nil 时用 ServerTLSConfig() 生成自签证书。
	//
	// 注意：这不是外层伪装用的证书。外层安全由 AEAD（密码）保证，
	// 内层 TLS 只是 QUIC 的必备组件。
	TLS *tls.Config
	// QUIC 为 nil 时使用 ServerConfig()。
	QUIC *quicgo.Config
	// MaxCwnd 是窗口上限（字节），0 表示 8MB。
	// 服务端所有连接共享一份上限（同 Rust 的 Arc<AtomicU64>）。
	MaxCwnd uint64
	// OnStats 是每 2 秒一次的路径统计回调，可为 nil。
	OnStats func(PathStats)
}

// Server 是 flowtls 服务端。
type Server struct {
	opts     ServerOptions
	listener *flowtls.Listener
	acceptCh chan *quicgo.Conn

	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once

	mu    sync.Mutex
	conns map[*quicgo.Conn]struct{}

	winCtl *windowController
}

// NewServer 启动服务端。
//
// 会立刻申请 raw socket（需要 root 或 CAP_NET_RAW），因此只能在
// sing-box 的 Start(StartStateStart) 里调用。
func NewServer(opts ServerOptions) (*Server, error) {
	ln, err := flowtls.NewListener(opts.FlowTLS, opts.Listener)
	if err != nil {
		return nil, err
	}
	tlsConf := opts.TLS
	if tlsConf == nil {
		tlsConf, err = ServerTLSConfig()
		if err != nil {
			_ = ln.Close()
			return nil, err
		}
	}
	quicConf := opts.QUIC
	if quicConf == nil {
		quicConf = ServerConfig()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		opts:     opts,
		listener: ln,
		acceptCh: make(chan *quicgo.Conn, 64),
		ctx:      ctx,
		cancel:   cancel,
		conns:    make(map[*quicgo.Conn]struct{}),
		winCtl:   newWindowController(opts.MaxCwnd, opts.OnStats),
	}
	s.wg.Add(1)
	go s.acceptLoop(quicConf, tlsConf)
	return s, nil
}

// Accept 阻塞等待一条 QUIC 连接。
func (s *Server) Accept(ctx context.Context) (*quicgo.Conn, error) {
	select {
	case c := <-s.acceptCh:
		return c, nil
	case <-s.ctx.Done():
		return nil, flowtls.ErrSessionClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Addr 返回监听地址。
func (s *Server) Addr() string { return s.listener.Addr().String() }

// SendMode 返回底层发送路径描述。
func (s *Server) SendMode() string { return s.listener.SendMode() }

// LocalIP 返回回包实际使用的源 IP。
func (s *Server) LocalIP() netip.Addr { return s.listener.LocalIP() }

// Users 返回用户数（供启动日志）。
func (s *Server) Users() int { return s.listener.Users() }

// Close 停止服务并关闭所有连接。
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.cancel()
		err = s.listener.Close()
		// 停自适应循环：服务端退出后不该继续跑。
		s.winCtl.Close()
	})
	s.wg.Wait()

	s.mu.Lock()
	conns := make([]*quicgo.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.conns = make(map[*quicgo.Conn]struct{})
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.CloseWithError(0, "server closed")
	}
	return err
}

// acceptLoop 对每条已鉴权会话起一个独立的 Transport。
func (s *Server) acceptLoop(quicConf *quicgo.Config, tlsConf *tls.Config) {
	defer s.wg.Done()
	for {
		sess, err := s.listener.Accept(s.ctx)
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func(sess *flowtls.Session) {
			defer s.wg.Done()
			s.serveSession(sess, quicConf, tlsConf)
		}(sess)
	}
}

// serveSession 在一条会话上建 QUIC，握手完成后把连接交给 Accept。
//
// 关闭顺序严格：**先关 Session，再关 Transport**。
// Transport.Close 会等它内部的 reader 退出，而 reader 阻塞在
// Session.ReadFrom 上——只有 Session 关闭才会返回。
func (s *Server) serveSession(sess *flowtls.Session, quicConf *quicgo.Config, tlsConf *tls.Config) {
	// 服务端**不能**启动 Session 自己的收包协程：
	// 那条协程会直接读同一个共享 raw socket，把属于别家会话的包抢走。
	// 收包统一由 flowtls.Listener 的 recvLoop 完成，按四元组分发。

	transport := &quicgo.Transport{Conn: sess}
	// 服务端用 Listen 而不是 Dial：一条 Session 对应一条 QUIC 连接。
	listener, err := transport.Listen(tlsConf, quicConf)
	if err != nil {
		_ = sess.Close()
		_ = transport.Close()
		return
	}

	conn, err := listener.Accept(s.ctx)
	if err != nil {
		_ = listener.Close()
		_ = sess.Close()
		_ = transport.Close()
		return
	}
	// 两端都用 BBR + 窗口上限：只换一端等于「一端猛发、另一端丢包减半」。
	s.winCtl.Attach(conn)

	s.mu.Lock()
	s.conns[conn] = struct{}{}
	s.mu.Unlock()

	// 交给上层使用
	select {
	case s.acceptCh <- conn:
	case <-s.ctx.Done():
		_ = conn.CloseWithError(0, "server closed")
	}

	// 等连接结束（上层用完、或链路断了、或服务端退出）
	select {
	case <-conn.Context().Done():
	case <-s.ctx.Done():
		_ = conn.CloseWithError(0, "server closed")
	}

	// 先从统计里摘掉，再回收 socket：否则自适应循环会去读已销毁的连接，
	// 并且把死连接的丢包率算进窗口调整。
	s.winCtl.Detach(conn)

	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()

	_ = listener.Close()
	_ = sess.Close()
	_ = transport.Close()
}
