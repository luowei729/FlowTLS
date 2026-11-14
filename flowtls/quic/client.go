package quic

// 本文件对应 legacy-rust:src/client.rs 里 QUIC 侧的装配：
// `Endpoint::connect`、`handle_incoming` 的事件投递、`drain_events` 的流处理。
//
// 结构映射：
//
//	Endpoint + Connection（quinn-proto 手动驱动）→ quic.Transport + quic.Conn
//	Event::Stream(Opened/Readable)              → conn.AcceptStream + 每流一个 goroutine
//	datagrams().send/recv                      → conn.SendDatagram/ReceiveDatagram
//	ProxyClient.tx（单一动作通道）               → 由 sing-box 直接调用 DialContext
//
// Rust 客户端自己监听 SOCKS5/HTTP 入口，Go 侧由 sing-box 提供入口，
// 所以 proxy/* 不移植（见 PROJECT_PLAN.md §2）。

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	quicgo "github.com/sagernet/quic-go"

	"github.com/luowei729/flowtls"
)

// openStreamTimeout 是开一条流的超时上限。
//
// 健康连接开流只需微秒级（等的是流控额度，不是网络往返）。
// 取 8 秒：超过它几乎必然是「连接已死但 quic-go 尚未检测到」，
// 此时应尽快报错让上层重建，而不是耗光调用方的全部预算。
const openStreamTimeout = 8 * time.Second

// ClientOptions 是客户端参数。
type ClientOptions struct {
	// FlowTLS 是底层伪造 TCP 参数。
	FlowTLS flowtls.ClientConfig
	// QUIC 为 nil 时使用 ClientConfig()。
	QUIC *quicgo.Config
	// DialTimeout 限制建连（含伪造 TCP 握手与 QUIC 握手）的总时长。
	DialTimeout time.Duration
	// MaxCwnd 是 QUIC 拥塞窗口上限（字节），对应 Rust 的 `net.max_cwnd`。
	// 0 表示 8MB。
	MaxCwnd uint64
	// OnStats 是每 2 秒一次的路径统计回调，可为 nil。
	OnStats func(PathStats)
}

// Client 是一条已建立的 flowtls + QUIC 通道。
//
// 语义与 Rust 一致：**一条 QUIC 连接承载所有本地连接**，
// 每个代理请求在它上面开一条新流，而不是重新握手。
type Client struct {
	session   *flowtls.Session
	transport *quicgo.Transport
	conn      *quicgo.Conn
	// winCtl 是 BBR + 自适应窗口上限控制器（2 秒周期），
	// 必须在 Close 时关闭，否则每条重连都会泄漏一个协程。
	winCtl *windowController

	// udpNext 是 UDP session id 分配器（随机起点，同 Rust）。
	udpNext atomic.Uint32
	// udpRoutes 是下行路由表：session → 该会话的投递对象。
	udpRoutes sync.Map // map[uint32]*udpSession
	// dispatcherOnce 保证下行分发协程只启动一次。
	dispatcherOnce sync.Once
}

// NewClient 建立 flowtls 通道并完成 QUIC 握手。
//
// 两个握手串行且必须串行：
//  1. flowtls.Dial 内部完成 TCP 三次握手（返回的 Session 已 ESTABLISHED）；
//  2. quic.Transport 在这个 Session 上做 QUIC 握手。
//
// 顺序反了会怎样：quic-go 会立刻写 Initial，而伪造 TCP 握手还没完成，
// 严格 NAT 下的状态防火墙会直接丢弃这些包。
func NewClient(ctx context.Context, opts ClientOptions) (*Client, error) {
	timeout := opts.DialTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	session, err := flowtls.Dial(dialCtx, opts.FlowTLS)
	if err != nil {
		return nil, fmt.Errorf("flowtls 握手失败: %w", err)
	}

	quicConf := opts.QUIC
	if quicConf == nil {
		quicConf = ClientConfig()
	}
	tlsConf := ClientTLSConfig()

	transport := &quicgo.Transport{Conn: session}
	conn, err := transport.Dial(dialCtx, session.RemoteAddr(), tlsConf, quicConf)
	if err != nil {
		// 关闭顺序：先 Session 再 Transport。
		// Transport 内部的 reader 阻塞在 Session.ReadFrom 上，
		// 只有 Session 关闭才会返回（顺序反了进程不退出）。
		_ = session.Close()
		_ = transport.Close()
		return nil, fmt.Errorf("QUIC 握手失败: %w", err)
	}

	winCtl := newWindowController(opts.MaxCwnd, opts.OnStats)
	winCtl.Attach(conn)

	return &Client{session: session, transport: transport, conn: conn, winCtl: winCtl}, nil
}

// Close 关闭通道。
//
// 顺序至关重要：**必须先关 Session，再关 Transport**。
// quic.Transport.Close 会等它内部的读 goroutine 退出，而那个 goroutine
// 正阻塞在 Session.ReadFrom 上；ReadFrom 只有在 Session 关闭后才返回。
func (c *Client) Close() error {
	var firstErr error
	if c.winCtl != nil {
		c.winCtl.Close()
	}
	if c.conn != nil {
		// CONNECTION_CLOSE 要能发出去，所以放在关 Session 之前
		if err := c.conn.CloseWithError(0, ""); err != nil {
			firstErr = err
		}
	}
	if c.session != nil {
		if err := c.session.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if c.transport != nil {
		if err := c.transport.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Done 返回连接关闭时关闭的 channel，用于上层做重连判断。
func (c *Client) Done() <-chan struct{} { return c.conn.Context().Done() }

// Err 返回连接关闭的原因（Done 触发后可读）。
func (c *Client) Err() error { return context.Cause(c.conn.Context()) }

// SendMode 返回传输层发送路径描述，供上层记建连日志。
func (c *Client) SendMode() string { return c.session.SendMode() }

// LocalAddr 返回本端地址。
func (c *Client) LocalAddr() net.Addr { return c.session.LocalAddr() }

// RemoteAddr 返回对端地址。
func (c *Client) RemoteAddr() net.Addr { return c.session.RemoteAddr() }

// DialConn 打开一条新流并连到 target。
//
// target 可以是 IP 也可以是域名：域名原样传给服务端，由服务端做远端解析
// （这样客户端的 DNS 不会泄漏，也能命中服务端的路由规则）。
//
// 线上格式：流的第一段载荷是地址帧 `[len u16][ATYP][ADDR][PORT]`，
// **之后没有任何响应头**，直接是双向数据。
func (c *Client) DialConn(ctx context.Context, target string, port uint16) (net.Conn, error) {
	frame, err := flowtls.EncodeTarget(target, port)
	if err != nil {
		return nil, err
	}
	tryCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		tryCtx, cancel = context.WithTimeout(ctx, openStreamTimeout)
		defer cancel()
	}
	stream, err := c.conn.OpenStreamSync(tryCtx)
	if err != nil {
		return nil, fmt.Errorf("打开 QUIC 流失败: %w", err)
	}
	// 写地址帧必须设 deadline：quic-go 的 Stream.Write 不看 ctx，
	// 连接「已死但未检测到」时会挂到 idle 超时（30 秒）。
	if dl, ok := ctx.Deadline(); ok {
		_ = stream.SetWriteDeadline(dl)
	}
	if _, err := stream.Write(frame); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("写地址帧失败: %w", err)
	}
	// 清掉写 deadline：后续数据由调用方的读写循环自己管理超时。
	_ = stream.SetWriteDeadline(time.Time{})
	return &StreamConn{
		stream: stream,
		local:  c.session.LocalAddr(),
		remote: addrForLog(target, port),
	}, nil
}

// StreamConn 把 quic.Stream 包装成 net.Conn。
//
// quic.Stream 只有 Read/Write/Close/SetDeadline，**没有 LocalAddr /
// RemoteAddr**，不满足 net.Conn，而上层（sing-box 的 router）需要它。
type StreamConn struct {
	stream *quicgo.Stream
	// local / remote 只用于日志与 metadata，不参与任何寻址逻辑
	local, remote net.Addr
	closeOnce     sync.Once
}

var _ net.Conn = (*StreamConn)(nil)

func (c *StreamConn) Read(p []byte) (int, error)  { return c.stream.Read(p) }
func (c *StreamConn) Write(p []byte) (int, error) { return c.stream.Write(p) }

// Close 关闭双向流。
//
// 必须先 CancelRead 再 Close：只 Close 只关写方向，服务端会以为我们还在读，
// 继续往这条流写数据，直到背压水位耗尽才放弃。
func (c *StreamConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.stream.CancelRead(0)
		err = c.stream.Close()
	})
	return err
}

func (c *StreamConn) LocalAddr() net.Addr  { return c.local }
func (c *StreamConn) RemoteAddr() net.Addr { return c.remote }

func (c *StreamConn) SetDeadline(t time.Time) error {
	if err := c.stream.SetReadDeadline(t); err != nil {
		return err
	}
	return c.stream.SetWriteDeadline(t)
}
func (c *StreamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *StreamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

// addrForLog 生成一个仅用于日志展示的地址。
func addrForLog(host string, port uint16) net.Addr {
	if a, err := netip.ParseAddr(host); err == nil {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(a, port))
	}
	return logAddr(fmt.Sprintf("%s:%d", host, port))
}

// logAddr 是 net.Addr 的最小实现，只承载一个字符串。
type logAddr string

func (a logAddr) Network() string { return "flowtls" }
func (a logAddr) String() string  { return string(a) }

// ErrNoSession 表示底层 Session 已关闭。
var ErrNoSession = errors.New("flowtls: 底层通道已关闭")
