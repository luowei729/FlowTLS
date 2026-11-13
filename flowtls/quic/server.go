package quic

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/netip"
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
	// MaxCwnd 是 QUIC 拥塞窗口上限（字节），对应 Rust 配置的
	// `net.max_cwnd`。0 表示用 DefaultMaxCwnd（8MB）。
	//
	// 服务端与客户端不同：这里是**所有连接共享一份上限**，
	// 自适应按全部连接的汇总丢包率调整（与 Rust `server.rs` 一致）。
	MaxCwnd uint64
	// OnStats 是每 2 秒一次的路径统计回调，可为 nil。
	OnStats func(PathStats)
	// BrutalBPS > 0 时启用 Brutal 拥塞控制（hy1 风格）：
	// **丢包不减窗，按这个带宽硬发**。单位字节/秒。
	//
	// **服务端这里填的是服务端自己的上行带宽**（= 客户端的下行）。
	// 跨境高丢包链路上，服务端下行（即客户端下载）往往是体验瓶颈，
	// 所以这个值要按服务器真实出口带宽填。0 表示走 BBR。
	BrutalBPS uint64
	// BrutalMultiplier 是 cwnd 相对 BDP 的倍数，默认 2.0（同 hy1）。
	BrutalMultiplier float64
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
		EnableDatagrams: true,
		// 与客户端、与 Rust 侧（quic/config.rs 的 mtu_discovery_config(None)）
		// 全部对齐，理由见 DefaultQUICConfig 的注释。
		DisablePathMTUDiscovery: true,
		// 1332 而不是 1340：外层 TCP 头多了 12 字节时间戳选项，
		// 1332 + 33 + 20 + 32 = 1417 < 链路 1428。
		InitialPacketSize: 1332,
		// 30s / 10s：与 Rust 侧 max_idle_timeout / keep_alive_interval 一致。
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
		// 服务端要给每个客户端开大量流（每条本地连接一条流），
		// 1024 与 Rust 侧 max_concurrent_bidi_streams 一致。
		MaxIncomingStreams: 1024,
		// 本协议不用单向流，但保持与 Rust 侧同值（Rust 也是 1024）。
		// 设 -1 会在传输参数里通告 0，虽不影响功能，但让两端参数不一致。
		MaxIncomingUniStreams: 1024,
		// 窗口与客户端/Rust 侧对齐：连接 16MB、流 4MB。
		InitialConnectionReceiveWindow: 16 * 1024 * 1024,
		MaxConnectionReceiveWindow:     16 * 1024 * 1024,
		InitialStreamReceiveWindow:     4 * 1024 * 1024,
		MaxStreamReceiveWindow:         4 * 1024 * 1024,
		// DATAGRAM 单帧上限与 MTU 对齐（UDP 不分片）
		MaxDatagramFrameSize: 1200,
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

	// winCtl 是 BBR + 自适应窗口上限控制器，所有连接共享。
	winCtl *windowController
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
		winCtl:   newWindowControllerEx(opts.MaxCwnd, opts.OnStats, opts.BrutalBPS, opts.BrutalMultiplier),
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

// SendMode 返回底层发送路径描述（含源地址被纠正的说明）。
//
// 为什么透传这一行：NAT 云主机上包里的源地址决定了链路通不通，
// 而配错时的现象（服务端发得出、对端收不到）与拥塞/丢包问题看起来一模一样。
// 适配层把它写进启动日志，运维一眼就能确认实际发送路径与生效的源地址。
func (s *Server) SendMode() string { return s.listener.SendMode() }

// LocalIP 返回回包实际使用的源 IP（可能与配置值不同，见 SendMode）。
func (s *Server) LocalIP() netip.Addr { return s.listener.LocalIP() }

// Close 停止服务并关闭所有连接。
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.cancel()
		err = s.listener.Close()
		// 停自适应循环：它会持续遍历连接读统计，
		// 服务端退出后不该继续跑。
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
	// 服务端也要 BBR + 窗口上限，理由与客户端一致（见 quic/client.go）。
	// 两端都用 BBR 才能避免「一端 BBR 猛发、另一端 Cubic 丢包减半」的错配。
	// 服务端所有连接共享同一个窗口上限（同 Rust 的 Arc<AtomicU64>）。
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

	// 先从统计里摘掉，再回收 socket：否则自适应循环会去读
	// 已经销毁的连接，并且把死连接的丢包率算进窗口调整。
	s.winCtl.Detach(conn)

	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()

	_ = listener.Close()
	_ = sess.Close()
	_ = transport.Close()
}
