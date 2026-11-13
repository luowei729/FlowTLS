// Package quic 把 flowtls 的伪造 TCP 连接接到 quic-go 上。
//
// 这是整个移植的**唯一依赖点**：module 主包只管 net.PacketConn，
// 本子包才引入 quic-go。好处是 sing-box 升级 quic-go 时，
// 可能编译不过的只有这个子包，其余部分（报文、AEAD、地址帧）不受影响。
//
// 与 sing-quic 的 SalamanderConn 是同一个套路：把自定义传输包装成
// net.PacketConn，quic-go 一行都不用改。
package quic

import (
	"context"
	"crypto/tls"
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

// ALPN 必须与 Rust 侧 src/quic/config.rs 的 ALPN 一致，否则握手直接失败。
const ALPN = "flowtls"

// DefaultQUICConfig 是客户端默认参数。
//
// 几个取值是对齐 Rust 版的（见 src/quic/config.rs）：
//   - MTU 用 1340 而不是 1200：外层加 37 字节后约 1377，仍在常见 1500 之内；
//   - 关闭 PMTU 探测：伪造 TCP 路径的 MTU 由我们自己定义，
//     探测包会被中间设备当异常流量；
//   - keep-alive 10s、idle 30s。
func DefaultQUICConfig() *quicgo.Config {
	return &quicgo.Config{
		EnableDatagrams: true,
		// 伪造 TCP 路径没有真实的 ICMP 反馈，PMTU 探测既探不准又像扫描
		DisablePathMTUDiscovery: true,
		InitialPacketSize:       1340,
		MaxIdleTimeout:          30 * time.Second,
		KeepAlivePeriod:         10 * time.Second,
		// HandshakeIdleTimeout 必须显式设置。
		//
		// 默认 5s 看似够用，但**它是「多久没收到任何包」而不是总时长**：
		// 密码错误时服务端会静默丢弃所有 Initial，客户端却仍在收
		// SYN-ACK/纯 ACK，握手期永远不会"空闲"到触发它。
		// 所以真正的超时兜底在 NewClient 里（见 dialWithTimeout）。
		HandshakeIdleTimeout: 10 * time.Second,

		// ---- 接收窗口：只调 stream，不动 connection ----
		//
		// Rust 侧（src/quic/config.rs）是 stream 4MB / connection 16MB。
		// 但**不要照抄 connection 值**：实测把
		// MaxConnectionReceiveWindow 设成 16MB 后，下载到 16.7MB 就永久卡住
		// （连接级窗口耗尽后没被回补，MAX_DATA 不再发出）。
		// 保持 quic-go 默认的连接级窗口（它会自适应增长）反而正常。
		//
		// stream 窗口需要显式调大：默认初始只有 512KB，
		// 爬升太慢会触发 Rust 服务端的背压判定
		// （`背压等待超过 30 秒，放弃该流`）。
		InitialStreamReceiveWindow: 4 * 1024 * 1024,
		MaxStreamReceiveWindow:     8 * 1024 * 1024,

		// Rust 侧单连接支持大量并发流（每条本地连接一条流）
		MaxIncomingStreams:    -1, // 不给对端开流（客户端不需要）
		MaxIncomingUniStreams: -1,
	}
}

// ClientOptions 是客户端参数。
type ClientOptions struct {
	// FlowTLS 是底层伪造 TCP 参数（服务端地址、密码、源端口、分流标记等）
	FlowTLS flowtls.ClientConfig
	// QUIC 为 nil 时使用 DefaultQUICConfig()
	QUIC *quicgo.Config
	// DialTimeout 限制建连（含伪造 TCP 握手与 QUIC 握手）的总时长
	DialTimeout time.Duration
}

// Client 是一条已建立的 flowtls + QUIC 通道。
//
// 语义与 Rust 版一致：**一条 QUIC 连接承载所有本地连接**，
// 每个代理请求在它上面开一条新流，而不是重新握手。
type Client struct {
	session   *flowtls.Session
	transport *quicgo.Transport
	conn      *quicgo.Conn

	// udpNext 是 UDP session id 分配器。
	//
	// 从随机值起步递增：session 只需在「一条 QUIC 连接内」唯一，
	// 随机起点能避免客户端重连后旧连接残留的包被误投到新会话上
	// （服务端重连后会话表本来就是空的，这属于防御性设计）。
	udpNext atomic.Uint32

	// udpRoutes 是下行路由表：session → 该会话的投递通道。
	//
	// 下行帧只有 [session][payload]，不带地址，客户端必须自己按 session
	// 找回是哪个本地 UDP socket 发的。表项由 ListenPacket 注册、
	// Close 注销。
	udpRoutes sync.Map // map[uint32]*udpSession

	// dispatcherOnce 保证下行分发协程只启动一次
	dispatcherOnce sync.Once
}

// udpSession 是一条本地 UDP 映射出来的会话。
type udpSession struct {
	id     uint32
	target netip.AddrPort
	// rx 是下行投递通道。容量小是有意的：UDP 不重传，堆太多只是延迟。
	rx chan []byte
	// 目标地址帧（不含长度前缀），每个上行包都要带
	targetFrame []byte
}

// ListenPacket 建立一条 UDP 会话，返回可直接当 net.PacketConn 使用的对象。
//
// 与 hysteria2 的差异：hy2 的 ListenPacket(ctx, destination) 是「一个会话一个
// 固定目标」，本协议上行**每包都带目标地址**，所以这里的目标只是默认值——
// 之后每次 WriteTo 都可以指定不同目标（多目标共享一个 session）。
//
// 为什么这样设计：服务端因此可以完全无状态，客户端重连后第一个包就能自愈。
func (c *Client) ListenPacket(ctx context.Context, target string, port uint16) (net.PacketConn, error) {
	_ = ctx
	if c.conn == nil {
		return nil, ErrNoSession
	}
	frame, err := encodeTargetFrame(target, port)
	if err != nil {
		return nil, err
	}
	id := c.udpNext.Add(1) - 1
	s := &udpSession{
		id:          id,
		rx:          make(chan []byte, 64),
		targetFrame: frame,
	}
	if a, err := netip.ParseAddr(target); err == nil {
		s.target = netip.AddrPortFrom(a, port)
	}
	c.udpRoutes.Store(id, s)

	// 第一次用到 UDP 时才启动分发协程：纯 TCP 用户不付这个成本。
	c.dispatcherOnce.Do(func() { go c.dispatchDatagrams() })

	return &udpConn{client: c, sess: s}, nil
}

// dispatchDatagrams 把 conn 收到的 DATAGRAM 按 session 分发到各自通道。
//
// 单独一个协程而不是让每个 udpConn 自己去 ReceiveDatagram：
// quic-go 的 ReceiveDatagram 是**单消费者**语义，多个协程同时读会互相抢包。
func (c *Client) dispatchDatagrams() {
	for {
		data, err := c.conn.ReceiveDatagram(c.conn.Context())
		if err != nil {
			// 连接关闭：通知所有会话退出
			c.udpRoutes.Range(func(_, v any) bool {
				close(v.(*udpSession).rx)
				return true
			})
			return
		}
		session, payload, ok := flowtls.ParseServerDatagram(data)
		if !ok {
			continue
		}
		v, loaded := c.udpRoutes.Load(session)
		if !loaded {
			// 会话已关闭或从未存在：丢弃（UDP 语义，不报错）
			continue
		}
		s := v.(*udpSession)
		// 拷贝：data 由 quic-go 复用，下一轮会被覆盖
		buf := make([]byte, len(payload))
		copy(buf, payload)
		select {
		case s.rx <- buf:
		default:
			// 通道满：丢弃（UDP 不重传，绝不阻塞分发协程，
			// 否则一条慢会话会拖死所有会话）
		}
	}
}

// udpConn 实现 net.PacketConn，对应一条 UDP 会话。
type udpConn struct {
	client *Client
	sess   *udpSession
	closed atomic.Bool
}

var _ net.PacketConn = (*udpConn)(nil)

func (u *udpConn) ReadFrom(p []byte) (int, net.Addr, error) {
	data, ok := <-u.sess.rx
	if !ok {
		return 0, nil, net.ErrClosed
	}
	n := copy(p, data)
	return n, net.UDPAddrFromAddrPort(u.sess.target), nil
}

// WriteTo 发送一个 UDP 数据报。
//
// addr 允许为 nil（沿用 ListenPacket 时给的目标），也允许指定不同目标——
// 协议上行每包带地址，因此天然支持多目标共享一个 session。
func (u *udpConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if u.closed.Load() {
		return 0, net.ErrClosed
	}
	frame := u.sess.targetFrame
	if addr != nil {
		if ap, ok := addrPortOf(addr); ok {
			var err error
			frame, err = flowtls.EncodeAddressFrame(ap)
			if err != nil {
				return 0, err
			}
		}
	}
	// 每包带 session + 地址帧
	pkt := flowtls.EncodeClientDatagram(nil, u.sess.id, frame, p)
	// SendDatagram 的语义：超出当前 MTU 会返回 DatagramTooLargeError。
	// 按 UDP 语义直接丢弃，不做应用层分片（与 Rust 侧一致）。
	if err := u.client.conn.SendDatagram(pkt); err != nil {
		if errors.As(err, new(*quicgo.DatagramTooLargeError)) {
			return 0, errDatagramTooLarge
		}
		return 0, err
	}
	return len(p), nil
}

// errDatagramTooLarge 表示载荷超出单包 MTU。
//
// 单独定义而不是直接透传：调用方（sing-box 的 UDP 转发层）需要区分
// 「这条会话坏了」和「这个包太大」——后者只该丢一个包，不该关会话。
var errDatagramTooLarge = errors.New("flowtls: UDP 载荷超出单包 MTU（不做分片，直接丢弃）")

func (u *udpConn) Close() error {
	if u.closed.Swap(true) {
		return nil
	}
	u.client.udpRoutes.Delete(u.sess.id)
	// 不关 rx：分发协程可能正在写入，关掉会 panic。
	// 注销路由表后不会再有新数据进来，残留的由 GC 回收。
	return nil
}

func (u *udpConn) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
}

func (u *udpConn) SetDeadline(t time.Time) error      { return nil }
func (u *udpConn) SetReadDeadline(t time.Time) error  { return nil }
func (u *udpConn) SetWriteDeadline(t time.Time) error { return nil }

// addrPortOf 从 net.Addr 提取 netip.AddrPort。
func addrPortOf(addr net.Addr) (netip.AddrPort, bool) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.AddrPort(), true
	case *net.TCPAddr:
		return netip.AddrPortFrom(a.AddrPort().Addr(), a.AddrPort().Port()), true
	}
	// 兜底：解析字符串
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	return ap, true
}

// encodeTargetFrame 生成不含长度前缀的地址帧。
func encodeTargetFrame(target string, port uint16) ([]byte, error) {
	full, err := encodeTarget(target, port)
	if err != nil {
		return nil, err
	}
	// encodeTarget 返回 [len u16][ATYP][ADDR][PORT]，去掉前 2 字节
	if len(full) < 3 {
		return nil, flowtls.ErrBadAddress
	}
	return full[2:], nil
}

// NewClient 建立 flowtls 通道并完成 QUIC 握手。
//
// 两个握手是串行且必须串行的：
//  1. flowtls.Dial 内部完成 TCP 三次握手（返回的 Session 已 ESTABLISHED）；
//  2. quic.Transport 在这个 Session 上做 QUIC 握手。
//
// 顺序反了会怎样：quic-go 会立刻写 Initial，而伪造 TCP 握手还没完成，
// 服务端（严格 NAT 后的状态防火墙）会直接丢弃这些包。Rust 版
// 「握手完成前不 drain_transmits」就是同一个约束。
func NewClient(ctx context.Context, opts ClientOptions) (*Client, error) {
	timeout := opts.DialTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	// 把超时同时施加在两步握手上，而不是各给一份：
	// 用户感知的是「建连总时长」，分开算会让最坏情况翻倍。
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	session, err := flowtls.Dial(dialCtx, opts.FlowTLS)
	if err != nil {
		return nil, fmt.Errorf("flowtls 握手失败: %w", err)
	}

	quicConf := opts.QUIC
	if quicConf == nil {
		quicConf = DefaultQUICConfig()
	}

	// 内层 QUIC 证书是服务端运行时自签的，无法预置信任链；
	// 安全性由外层 AEAD（密码）保证——这与 Rust 版设计一致。
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{ALPN},
		MinVersion:         tls.VersionTLS13,
	}

	transport := &quicgo.Transport{Conn: session}
	// 先启动接收协程再 Dial：quic-go 在握手期间就可能在写的同时读，
	// 若接收协程还没起来，服务端回的 Initial 会积在 socket 缓冲里，
	// 高 RTT 链路上会直接触发握手超时。
	session.StartReceiver()

	conn, err := dialWithTimeout(dialCtx, transport, session.RemoteAddr(), tlsConf, quicConf)
	if err != nil {
		_ = session.Close()
		_ = transport.Close()
		return nil, fmt.Errorf("QUIC 握手失败: %w", err)
	}
	return &Client{session: session, transport: transport, conn: conn}, nil
}

// dialWithTimeout 在做一次「带真实超时」的 QUIC 握手。
//
// 为什么不能直接 `transport.Dial(ctx, ...)`：
// quic-go 在 doDial 里调的是 `context.WithoutCancel(ctx)`——
// **故意剥离了 ctx 的取消信号**（它只用 ctx 传值）。所以传带超时的
// ctx 进去没有任何效果，握手会一直挂着。
//
// 这在密码错误时格外致命：服务端查不到用户会静默丢弃所有 Initial，
// 客户端却仍在正常收 SYN-ACK/纯 ACK，握手期永远不「空闲」，
// 连 HandshakeIdleTimeout 都不会触发。实测需要外部 timeout 杀掉进程。
//
// 因此这里自己起一个 goroutine 跑 Dial，用 select 抢超时；
// 超时后主动关 Session（会一并唤醒并结束 Dial 内部的所有等待）。
func dialWithTimeout(
	ctx context.Context,
	transport *quicgo.Transport,
	addr net.Addr,
	tlsConf *tls.Config,
	conf *quicgo.Config,
) (*quicgo.Conn, error) {
	type result struct {
		conn *quicgo.Conn
		err  error
	}
	// 容量 1：即使我们先超时返回，Dial goroutine 也能无阻塞写入并退出，
	// 不会泄漏。
	ch := make(chan result, 1)
	go func() {
		conn, err := transport.Dial(ctx, addr, tlsConf, conf)
		ch <- result{conn: conn, err: err}
	}()

	select {
	case r := <-ch:
		return r.conn, r.err
	case <-ctx.Done():
		// 超时/取消后主动关 Transport：它会结束内部的 handshake 等待，
		// 上面那个 goroutine 随之把错误写进 ch（容量 1，不会阻塞）。
		_ = transport.Close()
		return nil, fmt.Errorf("握手超时（%v 内未完成）: %w", ctx.Err(), ctx.Err())
	}
}

// Close 关闭通道。
//
// 顺序至关重要：**必须先关 Session，再关 Transport**。
// quic.Transport.Close 会等它内部的读 goroutine 退出，而那个 goroutine
// 正阻塞在 Session.ReadFrom 上；ReadFrom 只有在 Session 关闭后才返回。
// 反过来写不会报错、功能也正常，但进程永不退出（只能被 timeout 杀掉）——
// 这个坑在 P2 联调时真实踩到过。
func (c *Client) Close() error {
	var firstErr error
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

// Stats 是通道的核心统计，供日志/健康检查使用。
//
// 刻意不含拥塞窗口：sagernet/quic-go 这个版本的 ConnectionStats
// 只暴露 RTT 与字节/包计数（没有 CongestionWindow 字段），
// 想拿 cwnd 只能通过 qlog，成本远高于收益，故不做。
type Stats struct {
	SmoothedRTT time.Duration
	BytesSent   uint64
	BytesRecv   uint64
	PacketsSent uint64
	PacketsLost uint64
}

// Stats 返回当前连接统计。
func (c *Client) Stats() Stats {
	s := c.conn.ConnectionStats()
	return Stats{
		SmoothedRTT: s.SmoothedRTT,
		BytesSent:   s.BytesSent,
		BytesRecv:   s.BytesReceived,
		PacketsSent: s.PacketsSent,
		PacketsLost: s.PacketsLost,
	}
}

// StreamConn 把 quic.Stream 包装成 net.Conn。
//
// 为什么要包：quic.Stream 只有 Read/Write/Close/SetDeadline 和流 ID，
// **没有 LocalAddr / RemoteAddr**，不满足 net.Conn。上层（sing-box 的
// router、或任何 io.Copy 逻辑）需要它。
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
// 继续往这条流写数据，直到背压水位耗尽才放弃（Rust 版日志里那些
// 「背压等待超过 30 秒」就是漏掉这一步造成的）。
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

// DialConn 打开一条新流并连到 target。
//
// target 可以是 IP 也可以是域名：域名会原样传给服务端，
// 由服务端做远端解析（这样客户端的 DNS 不会泄漏，也能命中服务端的路由规则）。
//
// 线上格式：流的第一段载荷是地址帧 `[len u16][ATYP][ADDR][PORT]`，
// **之后没有任何响应头**，直接是双向数据。这一点和 hysteria2 相反
// （hy2 的 serverConn 首次 Write 会补一个 TCPResponse 头），照抄会让两端不通。
func (c *Client) DialConn(ctx context.Context, target string, port uint16) (net.Conn, error) {
	frame, err := encodeTarget(target, port)
	if err != nil {
		return nil, err
	}
	// OpenStreamSync 会在对端流数达到上限时阻塞，用调用方 ctx 控制
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("打开 QUIC 流失败: %w", err)
	}
	if _, err := stream.Write(frame); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("写地址帧失败: %w", err)
	}
	return &StreamConn{
		stream: stream,
		local:  c.session.LocalAddr(),
		remote: addrForLog(target, port),
	}, nil
}

// encodeTarget 根据 target 是否可解析为 IP，选择编码方式。
func encodeTarget(target string, port uint16) ([]byte, error) {
	if a, err := netip.ParseAddr(target); err == nil {
		return flowtls.EncodeAddress(netip.AddrPortFrom(a, port)), nil
	}
	return flowtls.EncodeDomainAddress(target, port)
}

// addrForLog 生成一个仅用于日志展示的地址。
func addrForLog(host string, port uint16) net.Addr {
	if a, err := netip.ParseAddr(host); err == nil {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(a, port))
	}
	return logAddr(host + ":" + itoa(int(port)))
}

// logAddr 是 net.Addr 的最小实现，只承载一个字符串。
type logAddr string

func (a logAddr) Network() string { return "flowtls" }
func (a logAddr) String() string  { return string(a) }

// itoa 是 strconv.Itoa 的极简替代。
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

// ErrNoSession 表示底层 Session 已关闭。
var ErrNoSession = errors.New("flowtls: 底层通道已关闭")
