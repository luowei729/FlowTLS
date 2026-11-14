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
	"log"
	"net"
	"net/netip"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	quicgo "github.com/sagernet/quic-go"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/pipe"

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
		// 伪造 TCP 路径没有真实的 ICMP 反馈，PMTU 探测既探不准又像扫描。
		//
		// Rust 侧关掉 PMTUD 还有个更硬的理由（见 quic/config.rs 注释）：
		// quinn 的 BlackHoleDetector 只要看到「连续 4 个可疑丢包突发」
		// 就把 MTU 打回 min_mtu（默认 1200）。跨境链路 20~50% 丢包是常态，
		// 这个启发式必然误判——实测 MTU 从 1340 塌到 1200 再没爬回来，
		// 此后每包少装 140 字节有效载荷（-10.4%），包数增加 11.7%，
		// 丢包概率随之上升，形成恶性循环。
		//
		// 我们的路径 MTU 是自己说了算的：外层封装固定、头部长度固定，
		// 1332 载荷对应 1417 字节报文，稳定小于链路 1428。
		DisablePathMTUDiscovery: true,
		// InitialPacketSize 必须与 Rust 侧 initial_mtu 逐字节对齐：1332。
		//
		// 为什么不是 1340（早期 Go 版的值）：伪装改造给每个数据包加了
		// TCP 时间戳选项，头部多 12 字节。若仍用 1340，总包会变成 1425，
		// 逼近服务端通告 MSS 1400 对应的 1440 上限，没有余量。
		//
		// 算一下：1332 + 33（5 记录头 + 12 nonce + 16 tag）
		//       + 20（IP）+ 32（TCP 含 12 字节 TS 选项）= 1417 < 1428 ✓
		InitialPacketSize: 1332,
		// MaxIdleTimeout 决定「隧道已死多久才被发现」。
		//
		// 取 30s 与 Rust 侧 max_idle_timeout 一致。
		// 它只适用于「完全收不到包」的场景，而健康连接每 KeepAlivePeriod
		// 就会收到一次 ACK，所以不会误触发。
		// 服务端重启后的快速恢复由 Probe + 上层重连负责，不靠缩短这个值。
		MaxIdleTimeout: 30 * time.Second,
		// 保活周期 10s：既是心跳也是死亡探测器，与 Rust 侧一致。
		// 必须明显小于 MaxIdleTimeout（3:1），否则一次丢包就可能被误判为掉线。
		KeepAlivePeriod: 10 * time.Second,
		// HandshakeIdleTimeout 必须显式设置。
		//
		// 默认 5s 看似够用，但**它是「多久没收到任何包」而不是总时长**：
		// 密码错误时服务端会静默丢弃所有 Initial，客户端却仍在收
		// SYN-ACK/纯 ACK，握手期永远不会"空闲"到触发它。
		// 所以真正的超时兜底在 NewClient 里（见 dialWithTimeout）。
		HandshakeIdleTimeout: 10 * time.Second,

		// ---- 接收窗口：与 Rust 侧逐项对齐 ----
		//
		// Rust: receive_window(16MB) / stream_receive_window(4MB)。
		//
		// 早期 Go 版把连接级窗口留默认，是因为把 MaxConnectionReceiveWindow
		// 设成 16MB 后下载到 16.7MB 就永久卡住（窗口耗尽后没被回补）。
		// 现在显式同时设置 Initial 与 Max 两个值：quic-go 只有在
		// Initial < Max 时才会增长并回补 MAX_DATA，只设 Max 不设 Initial
		// 会退化成「一次给满 16MB 却不再更新」。
		InitialConnectionReceiveWindow: 16 * 1024 * 1024,
		MaxConnectionReceiveWindow:     16 * 1024 * 1024,
		// 4MB 是 Rust 侧的安全值：受接收组装器乱序空洞数限制，
		// 8MB 在高丢包链路上会触发 too many gaps 断连。
		InitialStreamReceiveWindow: 4 * 1024 * 1024,
		MaxStreamReceiveWindow:     4 * 1024 * 1024,

		// DATAGRAM 单帧上限：Rust 侧 datagram_receive_buffer_size(1MB)。
		// quic-go 用「单帧最大字节数」表达，1200 与 MTU 对齐（UDP 不分片）。
		MaxDatagramFrameSize: 1200,

		// 客户端不需要对端开流，但**不能设 -1**：
		// Rust 侧是 max_concurrent_bidi_streams(1024)。
		// 设 -1 会让 QUIC 传输参数里 bidi 流上限为 0，
		// 万一将来需要服务端主动开流（如反向代理）就直接不可用。
		MaxIncomingStreams:    1024,
		MaxIncomingUniStreams: 1024,
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
	// MaxCwnd 是 QUIC 拥塞窗口上限（字节），对应 Rust 配置的
	// `net.max_cwnd`。0 表示用 DefaultMaxCwnd（8MB）。
	//
	// 它同时是 BBR 的硬上限和自适应算法的上界：
	// 小带宽跨境链路（如 20~50Mbps）设 1MB 左右能显著降低丢包。
	MaxCwnd uint64
	// OnStats 是每 2 秒一次的路径统计回调，可为 nil。
	//
	// 对应 Rust 版的「QUIC 路径统计」日志。排障时第一眼看它：
	// 丢包率、窗口上限、累计收发是否合理。
	OnStats func(PathStats)
	// BrutalBPS > 0 时启用 Brutal 拥塞控制（hy1 风格）：
	// **丢包不减窗，按这个带宽硬发**。单位字节/秒。
	//
	// 适用场景：跨境高丢包链路（随机丢包 20~50%）。BBR 会把这类
	// 随机丢包当成拥塞信号而降速，导致永远跑不满；Brutal 直接无视丢包，
	// 只靠 QUIC 重传兜底。
	//
	// **必须填本机真实上行带宽**（不是下行！）。填大了会把链路打爆、
	// 丢包更多；填小了跑不满。0 表示不用 Brutal，走 BBR。
	BrutalBPS uint64
	// BrutalMultiplier 是 cwnd 相对 BDP 的倍数，默认 2.0（同 hy1）。
	// 仅在 BrutalBPS > 0 时生效。
	BrutalMultiplier float64
}

// Client 是一条已建立的 flowtls + QUIC 通道。
//
// 语义与 Rust 版一致：**一条 QUIC 连接承载所有本地连接**，
// 每个代理请求在它上面开一条新流，而不是重新握手。
type Client struct {
	session   *flowtls.Session
	transport *quicgo.Transport
	conn      *quicgo.Conn

	// winCtl 是 BBR + 自适应窗口上限控制器。
	//
	// 必须在建连前创建（它启动一个 2 秒周期的丢包率采样协程），
	// 并在 Close 时关闭，否则每条重连都会泄漏一个协程。
	winCtl *windowController

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

// udpSession 是一条「本地 UDP socket + 目标地址」映射出来的会话。
//
// 生命周期模型照搬 hysteria2 的 udpPacketConn：
// ctx + cancel 管生命周期，readDeadline 管读超时，**不靠关闭通道**。
//
// 为什么不能用「Close 时 close(rx)」：分发协程是写方，
// 关通道会让写方 panic。用 ctx 就没有这个可逆问题——
// 发送方 select 时带上 <-ctx.Done() 就能安全退出。
//
// **一个目标一条会话**（对齐 Rust `proxy/socks5.rs` 的
// `index: HashMap<(peer, target), u32>`）：服务端按 session id 建一个出站
// socket，目标只在建会话时读一次；若同一 session 复用给不同目标，
// 包会被发到第一个目标上——这类串流在代理场景下极难排查。
type udpSession struct {
	id uint32
	// from 是该会话的下行源地址，ReadFrom 用它回报给调用方。
	from netip.AddrPort
	// targetFrame 是目标地址帧（不含长度前缀），每个上行包都要带。
	targetFrame []byte
	// sink 是本会话所属 udpConn 的合并下行队列。
	// 不设每会话独立队列：ReadFrom 只有一个消费者，
	// 多队列就得在 ReadFrom 里做动态 select，Go 做不到。
	sink chan udpPacket
	// lastUsed 是最近一次收发包的 UnixNano，供空闲回收使用。
	lastUsed atomic.Int64

	ctx    context.Context
	cancel context.CancelCauseFunc
}

// udpPacket 是合并下行队列里的一帧。
type udpPacket struct {
	from netip.AddrPort
	data []byte
}

// ListenPacket 建立一条 UDP 中继，返回可直接当 net.PacketConn 使用的对象。
//
// 与 hysteria2 的差异：hy2 的 ListenPacket(ctx, destination) 是「一个会话一个
// 固定目标」，本协议上行**每包都带目标地址**，所以这里的目标只是默认值——
// 之后每次 WriteTo 都可以指定不同目标，**每个不同目标自动分配一条独立会话**
// （对齐 Rust 的 `(peer, target) → session`）。
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
	// 父 ctx 取 QUIC 连接：连接断了所有会话自动作废，不需要额外通知。
	parentCtx, parentCancel := context.WithCancelCause(c.conn.Context())
	u := &udpConn{
		client:       c,
		defaultFrame: frame,
		sessions:     make(map[string]*udpSession),
		rx:           make(chan udpPacket, 256),
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

// sessionFor 取得（必要时创建）某个目标对应的会话。
//
// key 用地址帧的字符串形式：地址帧本身就是该目标的规范编码
// （IP 版本、地址、端口全在内），比拼字符串更不容易撞键。
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

// reapLoop 定期回收空闲会话。
//
// 对齐 Rust `proxy/socks5.rs` 的做法：每 30 秒扫一次，
// 空闲超过 idle 的会话注销。**必须有**：一个 SOCKS5 UDP 中继可能
// 先后访问成百上千个目标（DNS、QUIC、P2P），不回收会让
// 客户端路由表无限增长，服务端也会为每个会话常驻一个 UDP socket。
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

// udpSessionIdle 是客户端 UDP 会话的空闲回收时间。
//
// 下限取 60 秒而不是更短：DNS 这类低频会话若刚建就被回收，
// 每次查询都要重新分配 session id，服务端也要反复建 socket。
const udpSessionIdle = 60 * time.Second

// dispatchDatagrams 把 conn 收到的 DATAGRAM 按 session 分发到各自通道。
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

// udpConn 实现 net.PacketConn，对应一个本地 UDP 中继。
//
// 内部按目标地址维护多条 udpSession（对齐 Rust 的
// `(peer, target) → session` 反向索引），但对外仍是单一 PacketConn：
// 下行各会话的包合并进 rx，ReadFrom 带回各自的目标地址。
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

func (u *udpConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt := <-u.rx:
		n := copy(p, pkt.data)
		return n, net.UDPAddrFromAddrPort(pkt.from), nil
	case <-u.ctx.Done():
		// 中继已关闭（本地 Close 或 QUIC 连接断开）。
		// 必须返回错误：没有这个分支时 ReadFrom 会永久阻塞，
		// 调用方的读协程泄漏，且 sing-box 无法释放该会话。
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

func (u *udpConn) LocalAddr() net.Addr {
	if u.client.session != nil {
		return u.client.session.LocalAddr()
	}
	return nil
}

// WriteTo 发送一个 UDP 数据报。
//
// addr 允许为 nil（沿用 ListenPacket 时给的目标），也允许指定不同目标：
// **每个不同目标对应一条独立会话**——这是必须的，
// 服务端按 session id 只建一次出站 socket，目标只在建会话时读一次。
// 复用会话给不同目标会把包发到错误的主机。
func (u *udpConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if u.closed.Load() {
		return 0, net.ErrClosed
	}
	frame := u.defaultFrame
	from := u.defaultFrom
	if addr != nil {
		ap, ok := addrPortOf(addr)
		if !ok {
			// **不能静默回退到默认目标。**
			// 回退意味着把包发到错误的地方（比如把 DNS 包发给另一个 UDP 服务）。
			// 这类串流在代理场景下极难排查，必须直接报错。
			return 0, E.New("flowtls: unsupported UDP address type ", reflect.TypeOf(addr))
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

	tDial := time.Now()
	session, err := flowtls.Dial(dialCtx, opts.FlowTLS)
	if err != nil {
		return nil, fmt.Errorf("flowtls 握手失败: %w", err)
	}
	// 分阶段耗时必须可见：重建链路的耗时直接影响用户首个请求的等待，
	// 而「伪 TCP 握手」与「QUIC 握手」慢的原因完全不同
	// （前者通常是 SYN/SYN-ACK 重传，后者是 UDP 层的包丢失或 PTO）。
	//
	// 默认只在 debug 开关下输出：这是排障信息，不应该污染生产日志。
	if os.Getenv("FLOWTLS_DEBUG_HANDSHAKE") == "1" {
		log.Printf("flowtls: 伪 TCP 握手完成，耗时 %v",
			time.Since(tDial).Round(time.Millisecond))
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

	// 建连前就把拥塞控制准备好：自适应循环要贯穿连接整个生命周期。
	winCtl := newWindowControllerEx(opts.MaxCwnd, opts.OnStats,
		opts.BrutalBPS, opts.BrutalMultiplier)

	conn, err := dialWithTimeout(dialCtx, transport, session.RemoteAddr(), tlsConf, quicConf)
	if err != nil {
		winCtl.Close()
		_ = session.Close()
		_ = transport.Close()
		return nil, fmt.Errorf("QUIC 握手失败: %w", err)
	}
	if os.Getenv("FLOWTLS_DEBUG_HANDSHAKE") == "1" {
		log.Printf("flowtls: 建连总耗时 %v（含 QUIC 握手）",
			time.Since(tDial).Round(time.Millisecond))
	}
	// ---- 拥塞控制：原生 BBR + 自适应窗口上限 ----
	//
	// **这是跨境高丢包链路吞吐的关键**，不是可选优化。
	//
	// quic-go 默认用 Cubic（丢包即减半，把丢包当成拥塞信号）。
	// 跨境链路 20~50% 丢包是常态但不代表拥塞，Cubic 会反复把窗口
	// 砍到最小，实测吞吐只有 Rust 版的 1/5~1/10。
	//
	// `Attach` 做两件事：换上带窗口钳制的 BBR，并把这条连接
	// 纳入丢包率采样（每 2 秒按实测丢包率升降窗口上限，同 Rust）。
	// 传入 session 是为了把「本地发送队列深度/等待时间」带进统计日志。
	winCtl.Attach(conn, session)

	return &Client{session: session, transport: transport, conn: conn, winCtl: winCtl}, nil
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
	// 先停自适应循环：它每 2 秒会去读 conn 的统计，
	// 连接关掉后再读没意义，而且会持续占一个协程。
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

// IdleFor 返回距最后一次成功收到服务端包的时间。
//
// 这是判断「连接是否已死」的关键指标：QUIC 的保活 PING 每
// KeepAlivePeriod（10s）会收到一次 ACK，因此**健康连接的这个值
// 不会显著超过保活周期**。远大于它就意味着链路可能已断。
func (c *Client) IdleFor() time.Duration { return c.session.IdleFor() }

// Rules 返回客户端本次建连落地的 iptables 规则结果。
//
// 由适配层取走记日志：print 模式下这份文本就是运维需要手工执行的命令。
func (c *Client) Rules() flowtls.RuleReport { return c.session.Rules() }

// SendMode 返回传输层发送路径描述，供上层记建连日志（见 flowtls.Session.SendMode）。
func (c *Client) SendMode() string { return c.session.SendMode() }

// Probe 主动探测连接是否还活着。
//
// 为什么需要探活：QUIC 连接「已死但未检测到」是常态。服务端重启后，
// 客户端仍能在旧连接上瞬间开流并写入（这些操作只是本地缓冲，不等 ACK），
// 于是请求会卡在「等服务端响应」上，直到 MaxIdleTimeout（30 秒）。
// 实测：不探活时服务端重启后的首个请求固定耗时 30.0s。
//
// 探测手段：发一个对端会丢弃的 DATAGRAM。目的不是送达，而是让对端
// 回 ACK —— 只要收到任何包，Session.lastSeenAt 就会推进。
// 代价只有 1 个 RTT，远小于重建整个 QUIC 连接。
//
// 返回 true 表示链路确认存活。
func (c *Client) Probe(ctx context.Context, timeout time.Duration) bool {
	if c.session == nil {
		return false
	}
	before := c.session.LastSeenAt()
	// 载荷刻意是不合法的 UDP 帧（不足 6 字节），服务端解析失败后
	// 会按 UDP 语义静默丢弃——不会产生任何副作用，但 ACK 必须回。
	_ = c.conn.SendDatagram([]byte{0x00})
	// 轮询而不是等事件：Session 没有暴露「收到包」的通知通道，
	// 而探活是低频动作（仅在空闲超过阈值时触发），50ms 轮询成本可忽略。
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-deadline.C:
			return false
		case <-c.conn.Context().Done():
			return false
		case <-ticker.C:
			if c.session.LastSeenAt().After(before) {
				return true
			}
		}
	}
}

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
	// **写地址帧必须设 deadline**。
	//
	// quic-go 的 Stream.Write 只在两个条件下返回：写成功，或**连接关闭**。
	// 它不看 ctx —— 连接「已死但未检测到」时（服务端重启、链路中断），
	// 这里会一直挂到 MaxIdleTimeout（30 秒），表现为「一个请求卡 30 秒」。
	// 实测：不设 deadline 时，服务端重启后的首个请求耗时 30.0s。
	//
	// 设了 deadline 后，写超时会返回错误，上层据此重建通道并重试。
	if dl, ok := ctx.Deadline(); ok {
		_ = stream.SetWriteDeadline(dl)
	}
	if _, err := stream.Write(frame); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("写地址帧失败: %w", err)
	}
	// 清掉写 deadline：后续数据由调用方的读写循环自己管理超时，
	// 残留的 deadline 会让正常的大流量写被误杀。
	_ = stream.SetWriteDeadline(time.Time{})
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
