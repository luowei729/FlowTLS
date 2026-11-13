package quic

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	quicgo "github.com/sagernet/quic-go"

	"github.com/luowei729/flowtls"
)

// ServerOptions 是服务端参数。
type ServerOptions struct {
	// FlowTLS 是监听参数（端口、用户表、分流标记、空闲回收等）
	FlowTLS flowtls.ServerConfig
	// Listener 是底层监听参数
	Listener flowtls.ListenerOptions
	// TLS 是内层 QUIC 的证书配置。必须提供。
	//
	// 注意：这不是外层伪装用的证书。外层安全由 AEAD（密码）保证，
	// 内层 TLS 只是 QUIC 的必备组件。
	TLS *tls.Config
	// QUIC 为 nil 时使用 DefaultServerQUICConfig()
	QUIC *quicgo.Config
}

// DefaultServerQUICConfig 是服务端默认参数。
//
// 与客户端对称，但多了两条服务端特有的取舍：
//   - MaxIncomingStreams 必须足够大：每条本地连接一条流，
//     用户开几个标签页 + 几个后台请求就可能几十条；
//   - 关闭 MaxIncomingUniStreams：本协议不用单向流，
//     关掉能少一类攻击面。
func DefaultServerQUICConfig() *quicgo.Config {
	return &quicgo.Config{
		EnableDatagrams:            true,
		DisablePathMTUDiscovery:    true,
		InitialPacketSize:          1340,
		MaxIdleTimeout:             60 * time.Second,
		KeepAlivePeriod:            0, // 服务端不发保活，由客户端负责
		MaxIncomingStreams:         4096,
		MaxIncomingUniStreams:      -1,
		InitialStreamReceiveWindow: 4 * 1024 * 1024,
		MaxStreamReceiveWindow:     8 * 1024 * 1024,
	}
}

// Server 是 flowtls 服务端。
//
// **每客户端一个 quic.Transport**，而不是共用一个。
//
// 技术上完全可以聚合（实现一个按 addr 路由的 PacketConn，因为 QUIC 靠
// connID 而非四元组分流），但分开更划算：
//
//  1. deadline 语义不打架：每个 Transport 会对 PacketConn 调
//     SetReadDeadline 驱动自己的 timer。共用一个 PacketConn 时
//     只能取最小 deadline，一个客户端的超时会打断其他客户端的读取。
//  2. 快客户端不会饿死慢客户端：聚合后只有一个 readLoop，
//     拉满带宽的客户端会让 DNS 查询排在后面。
//  3. 一条会话出错只影响自己：聚合层必须把错误内部消化，
//     一旦抛给 ReadFrom，Transport 会认为 socket 坏了，把所有客户端一起断。
//
// 真正该省的不是 Transport，而是 raw socket —— 那个已经由
// flowtls.Listener 共享了（N+1 个协程，而不是 3N）。
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
}

// NewServer 启动服务端。
//
// 会立刻申请 raw socket（需要 root 或 CAP_NET_RAW），
// 因此只能在 sing-box 的 Start(StartStateStart) 里调用。
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.TLS == nil {
		return nil, fmt.Errorf("flowtls: 内层 TLS 配置不能为空")
	}
	ln, err := flowtls.NewListener(opts.FlowTLS, opts.Listener)
	if err != nil {
		return nil, err
	}
	quicConf := opts.QUIC
	if quicConf == nil {
		quicConf = DefaultServerQUICConfig()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		opts:     opts,
		listener: ln,
		acceptCh: make(chan *quicgo.Conn, 64),
		ctx:      ctx,
		cancel:   cancel,
		conns:    make(map[*quicgo.Conn]struct{}),
	}
	s.wg.Add(1)
	go s.acceptLoop(quicConf)
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

// ListenerStats 返回底层监听器统计。
func (s *Server) ListenerStats() flowtls.Stats { return s.listener.Stats() }

// ListenerRules 返回服务端本次启动落地的 iptables 规则结果。
//
// 由适配层取走记日志：print 模式下这份文本就是运维需要手工执行的命令。
func (s *Server) ListenerRules() flowtls.RuleReport { return s.listener.Rules() }

// Close 停止服务并关闭所有连接。
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.cancel()
		err = s.listener.Close()
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
func (s *Server) acceptLoop(quicConf *quicgo.Config) {
	defer s.wg.Done()
	for {
		sess, err := s.listener.Accept(s.ctx)
		if err != nil {
			return
		}
		s.wg.Add(1)
		// 每条会话一个协程：里面只做「建 Transport → Accept 一条连接」，
		// 接受成功后就只等关闭，成本很低。
		go func(sess *flowtls.Session) {
			defer s.wg.Done()
			s.serveSession(sess, quicConf)
		}(sess)
	}
}

// serveSession 在一条会话上建 QUIC，握手完成后把连接交给 Accept。
//
// 关闭顺序严格：**先关 Session，再关 Transport**。
// Transport.Close 会等它内部的 reader 退出，而 reader 阻塞在
// Session.ReadFrom 上——只有 Session 关闭才会返回。
// 反过来写时功能正常但协程永不退出（这一点在客户端侧已经踩过）。
func (s *Server) serveSession(sess *flowtls.Session, quicConf *quicgo.Config) {
	// 服务端**不能**启动 Session 自己的收包协程：
	// 那条协程会直接读同一个共享 raw socket，把属于别家会话的包抢走。
	// 收包统一由 flowtls.Listener 的 recvLoop 完成，按四元组分发。
	//
	// 会话的首包已经由 Listener 投进 rx 队列，
	// 所以 Transport 一启动就能读到 Initial，握手不会卡住。

	transport := &quicgo.Transport{Conn: sess}
	// 服务端用 Listen 而不是 Dial：一条 Session 对应一条 QUIC 连接。
	listener, err := transport.Listen(s.opts.TLS, quicConf)
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

	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()

	_ = listener.Close()
	_ = sess.Close()
	_ = transport.Close()
}
