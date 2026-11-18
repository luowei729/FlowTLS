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
	"os"
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

// localWriteStallTimeout 是「写本地连接连续零进展」的上限。
//
// 真机（2026-11-18 01:28，透明代理 1041）积压全在内核收队列，发队列为 0：
// 数据已经从 QUIC 读出来，卡在 relay 写本地 TCP。浏览器停读时这个 Write
// 堵在内核里，QUIC 流上的写超时根本不会触发，接收窗口也就还不回去。
//
// 与 QUIC 写超时同一标准：一次写入只要有字节出去就重新计时，
// 慢但一直在收的连接不会被关。8 秒只是「这一次完全没进展」的上限，
// 不是整条传输的寿命。hysteria 的 TCPStallTimeout 用的是同一判据（默认 10 秒）。
const localWriteStallTimeout = 8 * time.Second

// ClientOptions 是客户端参数。
type ClientOptions struct {
	// FlowTLS 是底层伪造 TCP 参数。
	FlowTLS flowtls.ClientConfig
	// QUIC 为 nil 时使用 ClientConfig()。
	QUIC *quicgo.Config
	// DialTimeout 限制建连（含伪造 TCP 握手与 QUIC 握手）的总时长。
	DialTimeout time.Duration
	// SendBPS 是本端上传速率（字节/秒），对应 hysteria2 的 up。
	// 0 表示用默认 1 Gbps。真正发出去的速率还要和对方报的 down 取较小值。
	SendBPS uint64
	// ReceiveBPS 是本端下载速率（字节/秒），对应 hysteria2 的 down。
	// 建连时告诉服务端，服务端用它限制发往本端的速率。0 同样是默认 1 Gbps。
	ReceiveBPS uint64
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
	// winCtl 是 Brutal 拥塞控制器和统计循环（2 秒周期），
	// 必须在 Close 时关闭，否则每条重连都会泄漏一个协程。
	winCtl *brutalController

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

	// 先按本端 up 装上。带宽帧谈完后换成 min(本端 up, 服务端 down)。
	// 谈不成就保持本端 up，和 hysteria2「对端回 0 就用自己的」同一退路。
	winCtl := newBrutalController(opts.SendBPS, opts.OnStats)
	winCtl.Attach(conn)

	c := &Client{session: session, transport: transport, conn: conn, winCtl: winCtl}
	if err := c.negotiateBandwidth(dialCtx, nonzeroBPS(opts.ReceiveBPS)); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// negotiateBandwidth 走 hysteria2 的带宽协商，只是承载换成一条 QUIC 流。
//
// 客户端把自己的 down 发给服务端，读回服务端的 down，
// 然后把自己的发送速率收成 min(本端 up, 服务端 down)。
// 服务端同时把自己的发送速率收成 min(服务端 up, 客户端 down)。
//
// 必须在 DialConn 之前做完：否则第一条代理流会按没谈过的速率发。
func (c *Client) negotiateBandwidth(ctx context.Context, receiveBPS uint64) error {
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("打开带宽协商流失败: %w", err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(openStreamTimeout))
	if err := writeBandwidth(stream, receiveBPS); err != nil {
		return fmt.Errorf("发送带宽失败: %w", err)
	}
	peerDown, err := readBandwidth(stream)
	if err != nil {
		return fmt.Errorf("读取对端带宽失败: %w", err)
	}
	c.winCtl.SetRate(c.conn, actualSendBPS(c.winCtl.bps, peerDown))
	return nil
}

// nonzeroBPS 把「没配」换成默认 1 Gbps。
//
// 配置里的 0 是「用默认」，不是 hysteria2 那个「请对端自己探测」。
// 探测需要 BBR 回退，而这里两端都固定用 Brutal。
func nonzeroBPS(bps uint64) uint64 {
	if bps == 0 {
		return defaultBrutalRate
	}
	return bps
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
	// 写地址帧必须有自己的上限，不能只看调用方的 ctx。
	//
	// quic-go 的 Stream.Write 不看 ctx，而测速页面这类请求的 ctx
	// 没有 deadline。连接的发送窗口一旦被占满（对端不再发 MAX_DATA），
	// 这一写就永远堵在 writeChan 上。更糟的是保活 ACK 还在流动，
	// QUIC 的 30 秒 idle 永不触发，Outbound.channel 就一直复用这条死连接，
	// 新请求全部超时，直到重启进程。
	//
	// 真机（2026-11-18 00:14，端口 2002）：
	// 39 个协程堵在 SendStream.write，38 个堵在 ReceiveStream.readImpl，
	// 发送队列是空的、recvLoop 没堵；对端服务端同一时刻完全空闲。
	// 也就是说包发出去了，窗口更新没回来，而客户端没有任何超时能发现这件事。
	//
	// 只限制地址帧（几十字节）。超时就关整条通道：closeCh 关闭后
	// ReadFrom 返回，Client.Done() 触发，下一次 channel() 会重建。
	// **不给后续的数据 Write 加超时**——那一版会在第 8 秒把正常的
	// 下载流 CancelWrite 掉，窗口反而更释放不了。
	_ = stream.SetWriteDeadline(time.Now().Add(openStreamTimeout))
	if _, err := stream.Write(frame); err != nil {
		_ = stream.Close()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			// 异步关：这里正用着 conn，同步 Close 要等传输层退出，会自锁。
			go func() { _ = c.Close() }()
		}
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

var (
	_ net.Conn = (*StreamConn)(nil)
	// sing-box 的 relay 用 N.WriteCloser / N.ReadCloser 判断能否半关闭
	// （route/conn.go）。Go 是结构化匹配，这里不导入 sing-common，
	// 只要方法集对上就满足那两个接口。缺了就是数据面 bug，见 CloseWrite。
	_ interface{ CloseRead() error }  = (*StreamConn)(nil)
	_ interface{ CloseWrite() error } = (*StreamConn)(nil)
)

func (c *StreamConn) Read(p []byte) (int, error) { return c.stream.Read(p) }

// Write 发送数据。「连续 8 秒零进展」只放弃这一条流，不拆整条通道。
//
// 流控有两级：每条流 4MB，整条连接 16MB。一条流的对端不读，
// 卡住的是它自己的 4MB，同连接上的其他流还能发。
//
// 上一版在这里关闭整条通道：一条上传卡住，所有正在进行的下载
// 一起中断，用户看到的是「卡一下然后全部重来」。
// 真机记录（2026-11-18 01:12，透明代理 1041）：积压从出现到清空用了
// 56 秒，期间 60 条连接全部受影响。
//
// 现在只 CancelWrite 这一条流：
//   - 发 RESET_STREAM，对端停掉对应方向并归还这条流占的窗口；
//   - relay 收到错误后关掉这一对连接（浏览器会重试这一个请求）；
//   - 同通道上的其他下载原样继续，不重建 QUIC 连接。
//
// n > 0 仍当成功返回。把有进展的超时当错误会掐断正常下载
// （2026-11-17 23:45：每条都正好死在第 8 秒）。
func (c *StreamConn) Write(p []byte) (int, error) {
	_ = c.stream.SetWriteDeadline(time.Now().Add(openStreamTimeout))
	n, err := c.stream.Write(p)
	_ = c.stream.SetWriteDeadline(time.Time{})
	if err == nil || n > 0 {
		return n, nil
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		// 放弃写方向。读方向不动：这条流可能还有没读完的响应，
		// 交给 relay 的另一个协程读完再收尾。
		c.stream.CancelWrite(0)
		return 0, fmt.Errorf("flowtls: 写方向连续 %v 零进展，放弃该流: %w", openStreamTimeout, err)
	}
	return 0, err
}

// unblockStuckWrite 唤醒卡在流控窗口上的 Write。
//
// quic-go 的 Stream.Close() 只把 finishedWriting 置位并安排发 FIN，
// **不唤醒**正堵在 `<-writeChan` 上等窗口的 Write；SetWriteDeadline 会
// （send_stream.go 原文："and any currently-blocked Write call"）。
//
// 窗口为 0 在并发下很容易成立：对端那条流的 4MB 接收窗口被没读走的数据占满。
// 于是 relay 的写协程不返回 → connectionCopy 走不到收尾 → 没人读 →
// 窗口永不恢复 → 写协程永远醒不过来。真机上就是端口 2002 的
// FIN_WAIT2 / CLOSE_WAIT 成对堆积、Recv-Q 数分钟不动、ESTABLISHED 归零。
//
// 设一个**已经过去**的 deadline 只让被堵住的那次 Write 返回错误。
// 已经拷进 STREAM 帧的数据和即将发出的 FIN 都不受影响：deadline 只在
// write() 的等待循环里检查，不碰发送队列。hysteria2 的
// clientConn.Close / serverConn.Close 用的是同一做法。
//
// **不动发送超时、不动队列深度**：上一版为了防挂死加了 SO_SNDTIMEO
// 并把 rxQueueDepth 从 8192 加到 16384，部署后下载速度明显变差，已撤回。
func (c *StreamConn) unblockStuckWrite() {
	_ = c.stream.SetWriteDeadline(time.Now())
}

// CloseWrite 只关写方向（对应 TCP 的 FIN，读方向继续）。
//
// sing-box 的 relay 在一个方向结束时这样收尾（route/conn.go）：
//
//	if isDuplex { duplexDst.CloseWrite() } else { destination.Close() }
//
// 没有 CloseWrite 时走 Close()：上传一结束整条流就被关掉，
// 下载方向还没读完的数据没人收，连接停在半关闭状态。
func (c *StreamConn) CloseWrite() error {
	err := c.stream.Close()
	// 必须在 Close 之后：被唤醒的 Write 看到 finishedWriting 才会返回，
	// 而不是继续阻塞。
	c.unblockStuckWrite()
	return err
}

// CloseRead 只关读方向：发 STOP_SENDING，让对端停写这条流。
func (c *StreamConn) CloseRead() error {
	c.stream.CancelRead(0)
	return nil
}

// Close 关闭双向流。
//
// 必须先 CancelRead 再 Close：只 Close 只关写方向，服务端会以为我们还在读，
// 继续往这条流写数据，直到背压水位耗尽才放弃。
// 最后唤醒可能卡在流控上的写协程，原因见 unblockStuckWrite。
func (c *StreamConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.stream.CancelRead(0)
		err = c.stream.Close()
		c.unblockStuckWrite()
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

// GuardLocalWrite 包住 relay 写入的本地入口连接。
//
// sing-box 的下载拷贝是 Copy(本地, 本连接)。本地（浏览器）停读时，
// 这一写堵在内核发送缓冲里，本连接的 Read/Write 都不会再被调用，
// 所以超时只能加在本地这一端。
//
// 连续 localWriteStallTimeout 一个字节都写不进本地，就关闭本条 QUIC 流：
// CancelRead 让对端停发并归还这条流占的接收窗口。其它流不动。
func (c *StreamConn) GuardLocalWrite(local net.Conn) net.Conn {
	return &stalledLocalConn{Conn: local, stream: c}
}

// stalledLocalConn 只改写的超时，其余全部交给内层连接。
type stalledLocalConn struct {
	net.Conn
	stream *StreamConn
}

func (c *stalledLocalConn) Write(p []byte) (int, error) {
	// 每次写入重新计时。上一次写出去了多少，不累加到这一次上，
	// 所以慢但一直在收的连接不会被关。
	_ = c.Conn.SetWriteDeadline(time.Now().Add(localWriteStallTimeout))
	n, err := c.Conn.Write(p)
	_ = c.Conn.SetWriteDeadline(time.Time{})
	if err == nil || n > 0 {
		return n, nil
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		_ = c.stream.Close()
		return 0, fmt.Errorf("flowtls: 写本地连接连续 %v 零进展，放弃该流: %w", localWriteStallTimeout, err)
	}
	return 0, err
}

// CloseWrite 转给内层。
//
// 不转的话这个包装盖住了本地连接自己的 CloseWrite，sing-box relay
// 的类型断言失败，一个方向结束就会把整条连接关掉。
func (c *stalledLocalConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return c.Conn.Close()
}

func (c *stalledLocalConn) CloseRead() error {
	if r, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return r.CloseRead()
	}
	return nil
}

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
