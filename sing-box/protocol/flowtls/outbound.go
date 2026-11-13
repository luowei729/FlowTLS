package flowtls

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	ft "github.com/luowei729/flowtls"
	ftquic "github.com/luowei729/flowtls/quic"
)

// RegisterOutbound 把 flowtls 出站注册进 registry。
func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.FlowTLSOutboundOptions](registry, C.TypeFlowTLS, NewOutbound)
}

var (
	_ adapter.Outbound                = (*Outbound)(nil)
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
)

// Outbound 是 flowtls 出站。
//
// 生命周期严格分三段（这是 sing-box 的硬约束）：
//
//	NewOutbound    只做参数校验，**绝不碰 raw socket**
//	Start(Start)   建连（需要 root/CAP_NET_RAW）
//	Close          释放
//
// 为什么构造函数不能申请权限：`sing-box check` 会完整走一遍
// box.New() → 各 NewXxx() → Close()。在构造函数里开 raw socket 会让
// check 也要求 root，而 check 是用户配错时的第一道防线，
// 必须能在普通用户下跑通。
type Outbound struct {
	outbound.Adapter
	ctx    context.Context
	logger log.ContextLogger
	opts   option.FlowTLSOutboundOptions

	// mu 保护 client 的懒加载与断线重建。
	//
	// 用 Mutex 而不是 atomic.Pointer：重建连接涉及「关旧、建新」两步，
	// 必须互斥，否则并发请求会同时建出两条通道（白白多一次 QUIC 握手）。
	mu     sync.Mutex
	client *ftquic.Client
	// dialing 在建连期间非 nil，用于让并发请求等待同一次握手，
	// 而不是各自触发一遍。
	dialing chan struct{}
}

// NewOutbound 只校验参数。真正的建连在 Start(StartStateStart)。
func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.FlowTLSOutboundOptions) (adapter.Outbound, error) {
	_ = router
	if options.Password == "" {
		return nil, C.ErrFlowTLSRequirePassword
	}
	if options.Server == "" {
		return nil, E.New("flowtls: server is required")
	}
	if options.SourcePort == 0 {
		options.SourcePort = 44300
	}
	if options.IPIDMark == 0 {
		options.IPIDMark = 0xF107
	}
	// iptables 模式在这里就解析：拼错时要报错，而不是拖到建连时
	// 才变成一句「握手超时」。
	//
	// 解析结果只是校验，实际值在建连时再解析一次（connect 会用到），
	// 好处是 `sing-box check` 也能拓出配置错误——它只走构造函数。
	if _, err := ft.ParseIPTablesMode(options.IPTablesMode); err != nil {
		return nil, err
	}

	networkList := options.Network.Build()
	if len(networkList) == 0 {
		networkList = []string{N.NetworkTCP, N.NetworkUDP}
	}
	// 只接受 TCP/UDP：明确拒绝而不是静默失败，
	// 否则用户只会看到「连接超时」这种毫无信息的现象。
	for _, network := range networkList {
		if network != N.NetworkTCP && network != N.NetworkUDP {
			return nil, E.New("flowtls: unsupported network: ", network)
		}
	}

	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(
			C.TypeFlowTLS, tag, networkList, options.DialerOptions),
		ctx:    ctx,
		logger: logger,
		opts:   options,
	}, nil
}

// Start 在 StartStateStart 阶段建立通道。
//
// 不在 Initialize 阶段建连：Initialize 要尽量轻量（校验、依赖排序），
// 真正申请系统资源的动作统一放在 Start。
func (o *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	// 建连失败不阻断 sing-box 启动：链路抖动、服务器临时不可达都很常见。
	// 让请求来时再重试，比整体启动失败更符合代理软件的预期
	// （否则一次网络抖动会让整个代理进程起不来）。
	if err := o.connect(); err != nil {
		o.logger.Error("flowtls 初始建连失败，将在首个请求时重试: ", err)
	} else {
		o.logger.Info("flowtls 通道已建立")
	}
	scope.Add(o.Close)
	return nil
}

// Close 释放通道。
func (o *Outbound) Close() error {
	o.mu.Lock()
	c := o.client
	o.client = nil
	o.mu.Unlock()
	if c != nil {
		return c.Close()
	}
	return nil
}

// resolveServer 解析服务端地址。
//
// 只取 IPv4：FakeTCP 目前只支持 IPv4（见 AGENTS.md 的已知限制）。
// 这里必须本地解析——服务端地址是固定基础设施，不像目标地址那样
// 可以交给服务端处理。
func (o *Outbound) resolveServer() (netip.AddrPort, error) {
	port := o.opts.ServerPort
	if port == 0 {
		port = 8443
	}
	if a, err := netip.ParseAddr(o.opts.Server); err == nil {
		if !a.Is4() {
			return netip.AddrPort{}, E.New("flowtls: server 必须是 IPv4 地址，得到 ", a)
		}
		return netip.AddrPortFrom(a, port), nil
	}
	// 域名：本地解析，只取 IPv4
	addrs, err := net.DefaultResolver.LookupNetIP(o.ctx, "ip4", o.opts.Server)
	if err != nil {
		return netip.AddrPort{}, E.Cause(err, "解析服务端域名 ", o.opts.Server)
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, E.New("flowtls: ", o.opts.Server, " 没有 IPv4 地址")
	}
	return netip.AddrPortFrom(addrs[0].Unmap(), port), nil
}

// connect 建立通道。调用方必须确保同一时刻只有一处在建连。
func (o *Outbound) connect() error {
	server, err := o.resolveServer()
	if err != nil {
		return err
	}
	sni := o.opts.SNI
	if sni == "" {
		sni = o.opts.Server
	}
	iptablesMode, err := ft.ParseIPTablesMode(o.opts.IPTablesMode)
	if err != nil {
		return err
	}
	c, err := ftquic.NewClient(o.ctx, ftquic.ClientOptions{
		FlowTLS: ft.ClientConfig{
			Server:     server,
			Password:   o.opts.Password,
			SNI:        sni,
			SourcePort: o.opts.SourcePort,
			IPIDMark:   o.opts.IPIDMark,
			// 客户端规则必须在第一个包发出前就位，
			// 所以模式随 ClientConfig 一起带进 Dial。
			IPTablesMode: iptablesMode,
			// 默认开启三次握手：严格 NAT/状态防火墙只放行握手完成的流量。
			// 字段是反向命名的 DisableHandshake，零值即「开启」。
			Handshake: !o.opts.DisableHandshake,
		},
		DialTimeout: 15 * time.Second,
		// 窗口上限：0 时由 quic 包退回默认 8MB。
		MaxCwnd: maxCwndOf(o.opts.MaxCwnd),
		// Brutal：up_mbps > 0 时丢包不减窗，按配置带宽硬发。
		BrutalBPS:        bpsOf(o.opts.UpMbps),
		BrutalMultiplier: o.opts.BrutalMultiplier,
		// 每 2 秒输出一次路径统计（对应 Rust 的「QUIC 路径统计」）。
		// 用 Debug 级别：正常运行时它只是背景噪声，
		// 但排查「连接活着却没速度」时它是第一现场证据。
		OnStats: func(s ftquic.PathStats) {
			o.logger.Debug("flowtls: QUIC 路径统计 ",
				"cc=", s.CC, " peer=", s.Remote,
				" rtt=", s.RTT, " srtt=", s.SmoothedRTT, " min_rtt=", s.MinRTT,
				" cwnd=", humanBytes(s.Cwnd), " inflight=", humanBytes(s.InFlight),
				" sent=", s.SentPackets, " lost=", s.LostPackets,
				" loss%=", s.LossPct,
				" win_cap=", humanBytes(s.WinCap),
				" tx_q=", s.TxQueueDepth, "/", s.TxMaxDepth,
				" tx_wait=", s.TxWait.Round(time.Millisecond),
				" tx_drop=", s.TxDropped, " tx_err=", s.TxSendErr)
		},
	})
	if err != nil {
		return err
	}
	// print 模式要把规则文本逐行写进日志：它有换行，
	// 必须拆开交给 logger，否则每行都会缺时间戳和级别。
	//
	// print 用 WARN：这是需要人动手的事。
	// auto 且本次无新增时用 Debug：outbound 会因空闲、链路抖动而重连，
	// 每次重连都把同一份规则 INFO 一遍只会刷掉有用的日志。
	if report := c.Rules(); !report.Empty() {
		for _, line := range strings.Split(report.Text(), "\n") {
			switch {
			case report.Mode == ft.IPTablesPrint:
				o.logger.Warn(line)
			case report.Mode == ft.IPTablesAuto && report.Added == 0:
				o.logger.Debug(line)
			default:
				o.logger.Info(line)
			}
		}
	}
	// 发送路径与源地址：与服务端同一理由，出向链路出问题时这行是第一个要看的信息
	// （源地址被替换成网卡地址意味着配置里写的是 NAT 公网地址）。
	o.logger.Debug("flowtls 发送路径: ", c.SendMode())
	o.mu.Lock()
	o.client = c
	o.mu.Unlock()
	return nil
}

// idleProbeThreshold 是触发探活的空闲阈值。
//
// 取值贴近保活周期（5s），因为**误判的代价只有一个 RTT**：探活只是发一个
// 对端会丢弃的 DATAGRAM 并等它的 ACK，成功就继续用原连接，不会重建。
// 反过来，判晚了代价极大：请求会卡在「等服务端响应」上直到
// MaxIdleTimeout（15s）。
//
// **已知局限**：如果隧道死亡时间短于保活周期，`IdleFor` 可能还很小，
// 探活不会触发——此时只能等 MaxIdleTimeout 兑底。
// 没有任何「基于空闲时长」的启发式能检测「刚刚死掉」的连接，
// 除非做应用层心跳应答。实测最差情况 14~15s，典型情况 0.7~2s。
const idleProbeThreshold = 5 * time.Second

// probeTimeout 是单次探活的等待上限。
//
// 1 个 RTT 就够（探测包 → ACK）。跨境 200ms 的链路留 1.5 秒已经很宽松；
// 拿不到的结论就是「连接已死」，直接重建（重建约 0.5~1s）。
const probeTimeout = 1500 * time.Millisecond

// getClient 取当前可用通道；不可用时建连。
//
// 并发模型：后来者等待同一个建连过程，而不是各自重试。
// 为什么不干脆全程持锁：建连可能耗时十几秒（跨境 + 丢包重传），
// 全程持有 mutex 会让其他请求全部阻塞在锁上，
// 而它们本可以在新通道建好后立刻使用。
func (o *Outbound) getClient(ctx context.Context) (*ftquic.Client, error) {
	for {
		o.mu.Lock()
		if c := o.client; c != nil {
			select {
			case <-c.Done():
				// 连接已关闭：丢弃并重建
				o.client = nil
				_ = c.Close()
			default:
				o.mu.Unlock()
				// 空闲较久时先探活。
				//
				// 不探活会怎样：服务端重启后旧连接「已死但未检测到」，
				// 开流与写入都瞬间返回（只是本地缓冲），
				// 请求实际卡在「等服务端响应」上直到 30 秒 idle timeout。
				// 实测不探活时恢复后首个请求固定 30.0s，探活后约 2s。
				if c.IdleFor() > idleProbeThreshold && !c.Probe(ctx, probeTimeout) {
					o.logger.Debug("flowtls 探活失败，重建通道")
					o.invalidate(c)
					continue
				}
				return c, nil
			}
		}
		if wait := o.dialing; wait != nil {
			o.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		done := make(chan struct{})
		o.dialing = done
		o.mu.Unlock()

		err := o.connect()

		o.mu.Lock()
		o.dialing = nil
		c := o.client
		o.mu.Unlock()
		// 关闭 done 唤醒所有等待者（它们在下一轮循环里读到新建的 client）
		close(done)

		if err != nil {
			return nil, err
		}
		if c == nil {
			return nil, E.New("flowtls: 建连后通道为空")
		}
		return c, nil
	}
}

// firstAttemptTimeout 是首次开流的超时上限。
//
// 健康的连接开一条流只需微秒级（等的是流控额度，不是网络往返）。
// 若 8 秒还没开出来，几乎必然是「连接已死但 quic-go 尚未检测到」——
// 此时不要耗光调用方的全部预算，留给重建后的第二次尝试。
const firstAttemptTimeout = 8 * time.Second

// attemptCtx 给第 n 次尝试包一层超时。
//
// 只对首次尝试加限制：第二次用的是刚建的新连接，
// 再限时反而可能误杀慢速链路。
func attemptCtx(ctx context.Context, attempt int) (context.Context, context.CancelFunc) {
	if attempt > 0 {
		return ctx, func() {}
	}
	if dl, ok := ctx.Deadline(); ok {
		if remain := time.Until(dl); remain < firstAttemptTimeout {
			return ctx, func() {}
		}
	}
	return context.WithTimeout(ctx, firstAttemptTimeout)
}

// invalidate 丢弃当前缓存的通道（如果它仍是 c）。
//
// 只丢弃「调用方正在用的那一条」：并发场景下其他请求可能已经重建了
// 新通道，无脑置空会把刚建好的好连接也一起关掉。
func (o *Outbound) invalidate(c *ftquic.Client) {
	o.mu.Lock()
	if o.client == c {
		o.client = nil
	}
	o.mu.Unlock()
	_ = c.Close()
}

// suspectConn 包装返回给 sing-box 的流，捕获「连接已死」的信号。
//
// 为什么需要它：隧道断开时，单条流的 Read 会一直阻塞到 QUIC 的
// MaxIdleTimeout，然后返回错误。这个错误发生在 sing-box 的拷贝循环里，
// 适配层看不到。若不据此让整条通道失效，**下一个请求仍会用同一条
// 死连接**，又要再等一个超时周期。
//
// **关键陷阱**：不能对所有错误都判定通道失效。正常结束一次请求时，
// sing-box 会 Close 这条流，随后 Read 返回「流已取消」——那是**本端**
// 主动关闭的结果，与通道健康无关。误判的后果极其明显：每个请求都会
// 重建一次 QUIC 连接（实测每次请求固定多 0.4s，服务端鉴权次数翻倍）。
// 因此只在「本端未主动关闭」时才算失效信号。
type suspectConn struct {
	net.Conn
	o      *Outbound
	client *ftquic.Client
	once   sync.Once
	// closed 标记本端已主动关闭该流。
	closed atomic.Bool
}

// note 在出错时让通道失效（只执行一次，且仅限本端未主动关闭时）。
func (c *suspectConn) note(err error) {
	if err == nil || c.closed.Load() {
		return
	}
	c.once.Do(func() {
		c.o.logger.Debug("flowtls 流出错，标记通道失效: ", err)
		c.o.invalidate(c.client)
	})
}

func (c *suspectConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil && err != io.EOF {
		c.note(err)
	}
	return n, err
}

func (c *suspectConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.note(err)
	return n, err
}

// Close 先标记再关闭，避免关闭引发的读错误被误判为通道故障。
func (c *suspectConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// DialContext 打开一条到 destination 的 TCP 流。
//
// destination 可以是域名：原样传给服务端，由服务端做远端解析。
// 这样客户端 DNS 不会泄漏，也能命中服务端的路由规则。
func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, E.New("flowtls: unsupported network: ", network)
	}
	var lastErr error
	// 重试两次：一次失败后换新通道再试。
	//
	// 为什么必须重试：QUIC 连接「已死但未检测到」是常态——服务端重启后
	// 客户端仍在旧连接上开流，OpenStreamSync 会一直阻塞到握手超时。
	// 首次失败即丢弃旧通道重建，用户只感知到一次稍慢的请求，
	// 而不是持续失败（实测不重试时服务端重启后一直 http=000）。
	for attempt := 0; attempt < 2; attempt++ {
		c, err := o.getClient(ctx)
		if err != nil {
			return nil, E.Cause(err, "flowtls 通道不可用")
		}
		if attempt == 0 {
			o.logger.InfoContext(ctx, "outbound connection to ", destination)
		}
		tryCtx, cancel := attemptCtx(ctx, attempt)
		conn, err := c.DialConn(tryCtx, destination.AddrString(), destination.Port)
		cancel()
		if err == nil {
			// 包一层：后续读写出错时让整条通道失效。
			// 不做这一步的话，隧道断开后下一个请求会继续用同一条死连接，
			// 又白等一个超时周期。
			return &suspectConn{Conn: conn, o: o, client: c}, nil
		}
		lastErr = err
		o.invalidate(c)
		if ctx.Err() != nil {
			break
		}
		o.logger.Debug("flowtls 开流失败，重建通道后重试: ", err)
	}
	return nil, E.Cause(lastErr, "flowtls 开流失败")
}

// ListenPacket 建立一条 UDP 会话。
func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		c, err := o.getClient(ctx)
		if err != nil {
			return nil, E.Cause(err, "flowtls 通道不可用")
		}
		if attempt == 0 {
			o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		}
		pc, err := c.ListenPacket(ctx, destination.AddrString(), destination.Port)
		if err == nil {
			return pc, nil
		}
		lastErr = err
		o.invalidate(c)
		if ctx.Err() != nil {
			break
		}
		o.logger.Debug("flowtls 开 UDP 会话失败，重建通道后重试: ", err)
	}
	return nil, E.Cause(lastErr, "flowtls 开 UDP 会话失败")
}

// MultiplexEnabled 恒为 true。
//
// flowtls 天然支持多路复用（一条 QUIC 连接承载所有流），
// 与 hysteria2 / anytls 一致。声明它让 sing-box 的连接管理
// 做出正确决策（复用连接而不是为每个请求重新建连）。
func (o *Outbound) MultiplexEnabled() bool { return true }

// InterfaceUpdated 在网络接口变化时关闭现有通道。
//
// 不重置会怎样：切换 Wi-Fi/有线、或公网 IP 变化后，旧的 QUIC 连接
// 仍在用旧的四元组与 seq 空间，服务端侧的伪造 TCP 状态对不上，
// 表现为「所有请求超时但进程正常」，且只能等 idle timeout（30 秒）自愈。
func (o *Outbound) InterfaceUpdated(ctx context.Context) {
	_ = ctx
	o.mu.Lock()
	c := o.client
	o.client = nil
	o.mu.Unlock()
	if c != nil {
		o.logger.Info("网络接口变化，重置 flowtls 通道")
		_ = c.Close()
	}
}

// SetKeepIdleConnections 保持空闲连接。
//
// flowtls 的通道是「建一次就一直用」的长连接，没有 per-request 建连的
// 概念，所以没有可切换的空闲池。空实现只为满足接口，
// 让 API 调用不会因缺少能力而报错。
func (o *Outbound) SetKeepIdleConnections(keep bool) { _ = keep }

// CloseIdleConnections 关闭空闲连接。
//
// 因为只有一条常驻通道，这里主动重建它——语义上等价于
// 「把当前连接标记为可弃用」，下次请求会重新握手。
// 比什么都不做更符合 API 使用者预期（例如 Clash API 的「断开所有连接」）。
func (o *Outbound) CloseIdleConnections() {
	o.mu.Lock()
	c := o.client
	o.client = nil
	o.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

// 保证 strconv 被使用（resolveServer 走 netip 解析，这里只是留一个
// 显式转换点，方便以后换成 strconv.Itoa 拼地址时不用改 import）
var _ = strconv.Itoa
