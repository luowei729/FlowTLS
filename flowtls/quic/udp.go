package quic

// 本文件是 UDP 中继在 Go 侧的适配，对应 Rust 的两块代码：
//
//   - legacy-rust:src/proxy/socks5.rs 的 `relay` / `UdpPeer`：
//     反向索引 `(peer, target) -> session`，同一个目标不必重复建会话；
//   - legacy-rust:src/client.rs 的 `ProxyClient.udp_routes` / `udp_next`：
//     session id 分配 + 下行按 session 路由。
//
// Rust 客户端自己就是 SOCKS5 服务端，所以它直接持有本地 UDP socket；
// Go 侧本地 socket 由 sing-box 提供，因此这里只负责「session 编号 + 路由」，
// 对外暴露 net.PacketConn 语义。**业务语义完全照搬**：
//   - 上行每包都带目标地址（服务端因此完全无状态）；
//   - 每个不同目标一条独立 session；
//   - 队列满即丢，绝不阻塞分发协程。

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	quicgo "github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/pipe"

	"github.com/luowei729/flowtls"
)

// udpSessionIdle 是客户端 UDP 会话的空闲回收时间。
//
// Rust `proxy/socks5.rs` 每 30 秒扫一次、空闲 `timeout_secs.max(10)` 回收；
// 客户端侧取 60 秒下限，避免 DNS 这类低频会话刚建就被回收。
const udpSessionIdle = 60 * time.Second

// udpRxQueueDepth 是下行合并队列深度（与旧实现同量级，够吸收突发）。
const udpRxQueueDepth = 256

// udpPacket 是合并下行队列里的一帧。
type udpPacket struct {
	from netip.AddrPort
	data []byte
}

// udpSession 是「本地 relay + 目标地址」映射出来的一条会话。
type udpSession struct {
	id uint32
	// from 是该会话的下行源地址（ReadFrom 回报给调用方）。
	from netip.AddrPort
	// targetFrame 是目标地址帧（不含长度前缀），每个上行包都要带。
	targetFrame []byte
	// sink 是本会话所属 udpConn 的合并下行队列。
	sink chan udpPacket
	// lastUsed 是最近一次收发包的 UnixNano，供空闲回收使用。
	lastUsed atomic.Int64

	ctx    context.Context
	cancel context.CancelCauseFunc
}

// udpConn 实现 net.PacketConn，对应一次 UDP 中继。
//
// 内部按目标地址维护多条 udpSession（对齐 Rust `(peer, target) -> session`），
// 但对外仍是单一 PacketConn：下行各会话的包合并进 rx，
// ReadFrom 带回各自的目标地址。
type udpConn struct {
	client *Client

	// defaultFrame / defaultFrom 来自 ListenPacket 的初始目标，
	// 供 addr 为 nil 的 WriteTo 使用。
	defaultFrame []byte
	defaultFrom  netip.AddrPort

	mu       sync.Mutex
	sessions map[string]*udpSession // key = 目标地址帧
	rx       chan udpPacket

	ctx          context.Context
	cancel       context.CancelCauseFunc
	readDeadline pipe.Deadline

	closed atomic.Bool
}

var _ net.PacketConn = (*udpConn)(nil)

// ListenPacket 建立一条 UDP 中继，返回可直接当 net.PacketConn 使用的对象。
//
// 与 hysteria2 的差异：hy2 的 ListenPacket 是「一个会话一个固定目标」，
// 本协议上行**每包都带目标地址**，所以这里的目标只是默认值——
// 之后每次 WriteTo 都可以指定不同目标，**每个不同目标自动分配一条独立会话**。
func (c *Client) ListenPacket(ctx context.Context, target string, port uint16) (net.PacketConn, error) {
	if c.conn == nil {
		return nil, ErrNoSession
	}
	frame, err := encodeTargetFrame(target, port)
	if err != nil {
		return nil, err
	}
	// 父 ctx 取 QUIC 连接：连接断了所有会话自动作废，不需要额外通知。
	parentCtx, parentCancel := context.WithCancelCause(c.conn.Context())
	u := &udpConn{
		client:       c,
		defaultFrame: frame,
		sessions:     make(map[string]*udpSession),
		rx:           make(chan udpPacket, udpRxQueueDepth),
		ctx:          parentCtx,
		cancel:       parentCancel,
	}
	if a, err := netip.ParseAddr(target); err == nil {
		u.defaultFrom = netip.AddrPortFrom(a, port)
	}

	// 第一次用到 UDP 时才启动分发协程与回收协程：纯 TCP 用户不付这个成本。
	c.dispatcherOnce.Do(func() { go c.dispatchDatagrams() })
	go u.reapLoop()

	return u, nil
}

// encodeTargetFrame 生成不含长度前缀的地址帧（UDP 上行用它）。
func encodeTargetFrame(target string, port uint16) ([]byte, error) {
	if a, err := netip.ParseAddr(target); err == nil {
		return flowtls.EncodeAddressFrame(netip.AddrPortFrom(a, port))
	}
	return flowtls.EncodeDomainFrame(target, port)
}

// sessionFor 取得（必要时创建）某个目标对应的会话。
func (u *udpConn) sessionFor(frame []byte, from netip.AddrPort) *udpSession {
	key := string(frame)

	u.mu.Lock()
	if s, ok := u.sessions[key]; ok {
		s.lastUsed.Store(time.Now().UnixNano())
		u.mu.Unlock()
		return s
	}
	if u.closed.Load() {
		u.mu.Unlock()
		return nil
	}
	id := u.client.udpNext.Add(1) - 1
	// 会话 ctx 挂在 udpConn 的 ctx 下：中继关闭时所有会话一起作废。
	sessCtx, sessCancel := context.WithCancelCause(u.ctx)
	s := &udpSession{
		id:          id,
		from:        from,
		targetFrame: frame,
		sink:        u.rx,
		ctx:         sessCtx,
		cancel:      sessCancel,
	}
	s.lastUsed.Store(time.Now().UnixNano())
	u.sessions[key] = s
	u.mu.Unlock()

	u.client.udpRoutes.Store(id, s)
	return s
}

// dropSession 注销一条会话（下发路由 + ctx）。
func (u *udpConn) dropSession(key string) {
	u.mu.Lock()
	s, ok := u.sessions[key]
	delete(u.sessions, key)
	u.mu.Unlock()
	if !ok {
		return
	}
	u.client.udpRoutes.Delete(s.id)
	s.cancel(net.ErrClosed)
}

// reapLoop 定期回收空闲会话（对齐 Rust 每 30 秒扫描一次的做法）。
//
// 必须有：一个 UDP 中继可能先后访问成百上千个目标（DNS、QUIC、P2P），
// 不回收会让客户端路由表无限增长，服务端也会为每个会话常驻一个 UDP socket。
func (u *udpConn) reapLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-ticker.C:
		}
		deadline := time.Now().Add(-udpSessionIdle).UnixNano()
		var stale []string
		u.mu.Lock()
		for key, s := range u.sessions {
			if s.lastUsed.Load() < deadline {
				stale = append(stale, key)
			}
		}
		u.mu.Unlock()
		for _, key := range stale {
			u.dropSession(key)
		}
	}
}

// dispatchDatagrams 把 conn 收到的 DATAGRAM 按 session 分发到各自中继。
//
// 单独一个协程而不是让每个 udpConn 自己去 ReceiveDatagram：
// quic-go 的 ReceiveDatagram 是**单消费者**语义，多个协程同时读会互相抢包。
func (c *Client) dispatchDatagrams() {
	for {
		data, err := c.conn.ReceiveDatagram(c.conn.Context())
		if err != nil {
			// 连接关闭：取消所有会话。
			// 不 close 通道——写方可能在 select 里等，关通道会 panic。
			c.udpRoutes.Range(func(_, v any) bool {
				v.(*udpSession).cancel(net.ErrClosed)
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
		s.lastUsed.Store(time.Now().UnixNano())
		select {
		case s.sink <- udpPacket{from: s.from, data: buf}:
		case <-s.ctx.Done():
			// 会话已关：丢弃（UDP 语义）
		default:
			// 队列满：丢弃（UDP 不重传，绝不阻塞分发协程，
			// 否则一条慢会话会拖死所有会话）
		}
	}
}

// ReadFrom 实现 net.PacketConn。
func (u *udpConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt := <-u.rx:
		n := copy(p, pkt.data)
		return n, net.UDPAddrFromAddrPort(pkt.from), nil
	case <-u.ctx.Done():
		return 0, nil, net.ErrClosed
	case <-u.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

// SetDeadline / SetReadDeadline 必须真正生效：上层靠它实现 UDP 空闲超时。
func (u *udpConn) SetDeadline(t time.Time) error {
	u.readDeadline.Set(t)
	return nil
}

func (u *udpConn) SetReadDeadline(t time.Time) error {
	u.readDeadline.Set(t)
	return nil
}

func (u *udpConn) SetWriteDeadline(t time.Time) error { return nil }

// LocalAddr 返回本端地址（伪造 TCP 的源地址）。
func (u *udpConn) LocalAddr() net.Addr {
	if u.client.session != nil {
		return u.client.session.LocalAddr()
	}
	return nil
}

// WriteTo 发送一个 UDP 数据报。
//
// addr 允许为 nil（沿用 ListenPacket 时给的目标），也允许指定不同目标：
// **每个不同目标对应一条独立会话**——服务端按 session id 只建一次出站
// socket，目标只在建会话时读一次。
func (u *udpConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if u.closed.Load() {
		return 0, net.ErrClosed
	}
	frame := u.defaultFrame
	from := u.defaultFrom
	if addr != nil {
		ap, ok := addrPortOf(addr)
		if !ok {
			// **不能静默回退到默认目标**：那会把包发到错误的地方，
			// 这类串流在代理场景下极难排查。
			return 0, errors.New("flowtls: 不支持的 UDP 地址类型")
		}
		f, err := flowtls.EncodeAddressFrame(ap)
		if err != nil {
			return 0, err
		}
		frame = f
		from = ap
	}
	s := u.sessionFor(frame, from)
	if s == nil {
		return 0, net.ErrClosed
	}
	// 每包带 session + 地址帧
	pkt := flowtls.EncodeClientDatagram(nil, s.id, frame, p)
	// SendDatagram 的语义：超出当前 MTU 会返回 DatagramTooLargeError。
	// 按 UDP 语义直接丢弃，不做应用层分片（与 Rust 一致）。
	if err := u.client.conn.SendDatagram(pkt); err != nil {
		var tooLarge *quicgo.DatagramTooLargeError
		if errors.As(err, &tooLarge) {
			return 0, errDatagramTooLarge
		}
		return 0, err
	}
	return len(p), nil
}

// errDatagramTooLarge 表示载荷超出单包 MTU。
//
// 单独定义而不是直接透传：调用方需要区分「这条会话坏了」和「这个包太大」
// ——后者只该丢一个包，不该关会话。
var errDatagramTooLarge = errors.New("flowtls: UDP 载荷超出单包 MTU（不做分片，直接丢弃）")

// Close 关闭中继。
func (u *udpConn) Close() error {
	if u.closed.Swap(true) {
		return nil
	}
	// 先注销所有会话的路由（后续下行包直接丢），再取消 ctx
	// （唤醒阻塞中的 ReadFrom，并让 reapLoop 退出）。
	u.mu.Lock()
	sessions := make([]*udpSession, 0, len(u.sessions))
	for _, s := range u.sessions {
		sessions = append(sessions, s)
	}
	u.sessions = make(map[string]*udpSession)
	u.mu.Unlock()
	for _, s := range sessions {
		u.client.udpRoutes.Delete(s.id)
	}
	u.cancel(net.ErrClosed)
	return nil
}

// addrPortOf 从 net.Addr 提取 netip.AddrPort。
func addrPortOf(addr net.Addr) (netip.AddrPort, bool) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.AddrPort(), true
	case *net.TCPAddr:
		return netip.AddrPortFrom(a.AddrPort().Addr(), a.AddrPort().Port()), true
	}
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	return ap, true
}
