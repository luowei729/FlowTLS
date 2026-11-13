package flowtls

import (
	"context"
	"net"
	"net/netip"
	"sync"
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
// 结构刻意保持**单层**：只有一条常驻 QUIC 通道（`client`），
// 每个本地连接在它上面开一条流。没有连接池、没有 per-request 建连、
// 没有额外的错误包装层——与 Rust `client.rs` 的 `run_session` 一一对应。
//
// 生命周期遵循 sing-box 的三段式约束：
//
//	NewOutbound    只校验参数，绝不碰 raw socket
//	Start(Start)   建连（需要 root / CAP_NET_RAW）
//	Close          释放
//
// 构造函数不能申请权限：`sing-box check` 会完整走一遍
// box.New() → NewXxx() → Close()，在这里开 raw socket 会让纯语法检查
// 也要求 root，而 check 是用户配错时的第一道防线。
type Outbound struct {
	outbound.Adapter
	ctx    context.Context
	logger log.ContextLogger
	opts   option.FlowTLSOutboundOptions

	// mu 保护 client 与 dialing。
	mu     sync.Mutex
	client *ftquic.Client
	// dialing 在建连期间非 nil：并发请求等待同一次握手，
	// 而不是各自触发一遍（否则 N 个请求就是 N 次 QUIC 握手）。
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
	// 在这里解析一次是为了让 `sing-box check` 能拓出拼写错误，
	// 而不是拖到建连时变成一句「握手超时」。
	if _, err := ft.ParseIPTablesMode(options.IPTablesMode); err != nil {
		return nil, err
	}

	networkList := options.Network.Build()
	if len(networkList) == 0 {
		networkList = []string{N.NetworkTCP, N.NetworkUDP}
	}
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
func (o *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	// 建连失败不阻断 sing-box 启动：链路抖动、服务器临时不可达很常见。
	// 让请求来时再重试，比整体启动失败更符合代理软件的预期。
	if _, err := o.channel(o.ctx); err != nil {
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

// resolveServer 解析服务端地址，只取 IPv4（FakeTCP 的已知限制）。
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
	addrs, err := net.DefaultResolver.LookupNetIP(o.ctx, "ip4", o.opts.Server)
	if err != nil {
		return netip.AddrPort{}, E.Cause(err, "解析服务端域名 ", o.opts.Server)
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, E.New("flowtls: ", o.opts.Server, " 没有 IPv4 地址")
	}
	return netip.AddrPortFrom(addrs[0].Unmap(), port), nil
}

// connect 建立一条新通道。调用方必须保证同一时刻只有一处在建连。
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
			// 客户端规则必须在第一个包发出前就位：SYN-ACK 一回，内核就会
			// 发现没有对应 socket 并回 RST，中间设备会立即拆掉 NAT 映射。
			IPTablesMode: iptablesMode,
			// 默认开启三次握手（严格 NAT 只放行握手完成的流量）。
			// 字段是反向命名，零值即开启。
			Handshake: !o.opts.DisableHandshake,
		},
		DialTimeout: 15 * time.Second,
		MaxCwnd:     maxCwndOf(o.opts.MaxCwnd),
		BrutalBPS:   bpsOf(o.opts.UpMbps),
		BrutalMultiplier: o.opts.BrutalMultiplier,
		// 每 2 秒一条路径统计（对应 Rust 的「QUIC 路径统计」）。
		// 用 Debug：正常运行时是背景噪声，但排查「连接活着却没速度」
		// 时它是第一现场证据。
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
	// print 模式下规则文本要逐行写进日志（它有换行，必须拆开交给 logger）。
	// print 用 WARN：这是需要人动手的事；auto 且本次无新增时用 Debug。
	if report := c.Rules(); !report.Empty() {
		for _, line := range splitLines(report.Text()) {
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
	// 发送路径与源地址：出向链路出问题时这行是第一个要看的信息
	// （源地址被替换成网卡地址意味着配置里写的是 NAT 公网地址）。
	o.logger.Debug("flowtls 发送路径: ", c.SendMode())
	o.mu.Lock()
	o.client = c
	o.mu.Unlock()
	return nil
}

// idleProbeThreshold 是触发探活的空闲阈值。
//
// 取值贴近保活周期（5s）：误判的代价只有一个 RTT（多探一次），
// 漏判的代价是首个请求卡 15~30s。取舍偏向「多探」。
const idleProbeThreshold = 5 * time.Second

// probeTimeout 是单次探活的等待上限。1 个 RTT 就够，跨境 200ms 留 1.5s 很宽松。
const probeTimeout = 1500 * time.Millisecond

// openStreamTimeout 是开一条流的超时上限。
//
// 健康连接开流只需微秒级（等的是流控额度，不是网络往返）。
// 8 秒还没开出来，几乎必然是「连接已死但 quic-go 尚未检测到」——
// 此时不要耗光调用方的全部预算，留给重建后的第二次尝试。
const openStreamTimeout = 8 * time.Second

// channel 返回可用的 QUIC 通道，必要时建连。**这是唯一的获取入口。**
//
// 三种失效判定，都只在这里处理（v1 分散在 getClient / attemptCtx /
// invalidate / suspectConn 四处，结果是「本端 Close 引起的读错误」
// 被误判成通道故障，每个请求都重建一次连接）：
//
//  1. Done 已关闭 → 丢弃重建；
//  2. 空闲超过 5s 且探活失败 → 丢弃重建；
//  3. 开流失败 → 由调用方 drop 后重试一次。
//
// 不再提供「包装返回的 net.Conn 以捕获错误」的机制：正常关闭一条流时
// Read 必然返回错误，那与通道健康无关，包装层无法可靠区分。
func (o *Outbound) channel(ctx context.Context) (*ftquic.Client, error) {
	for {
		o.mu.Lock()
		c := o.client
		if c != nil {
			o.mu.Unlock()
			select {
			case <-c.Done():
				o.drop(c)
				continue
			default:
			}
			if c.IdleFor() > idleProbeThreshold && !c.Probe(ctx, probeTimeout) {
				o.logger.Debug("flowtls 探活失败，重建通道")
				o.drop(c)
				continue
			}
			return c, nil
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
		c = o.client
		o.mu.Unlock()
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

// drop 丢弃通道（只在它仍是当前通道时才关，避免关掉别人刚建好的新连接）。
func (o *Outbound) drop(c *ftquic.Client) {
	o.mu.Lock()
	if o.client == c {
		o.client = nil
	}
	o.mu.Unlock()
	_ = c.Close()
}

// DialContext 打开一条到 destination 的 TCP 流。
//
// destination 可以是域名：原样传给服务端，由服务端做远端解析。
// 这样客户端 DNS 不会泄漏，也能命中服务端的路由规则。
func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, E.New("flowtls: unsupported network: ", network)
	}
	o.logger.InfoContext(ctx, "outbound connection to ", destination)
	var lastErr error
	// 重试一次：QUIC 连接「已死但未检测到」是常态——服务端重启后
	// 客户端仍能在旧连接上开流并写入（只是本地缓冲），请求卡到 idle 超时。
	// 首次失败即丢弃旧通道重建，用户只感知到一次稍慢的请求。
	for attempt := 0; attempt < 2; attempt++ {
		c, err := o.channel(ctx)
		if err != nil {
			return nil, E.Cause(err, "flowtls 通道不可用")
		}
		tryCtx, cancel := context.WithTimeout(ctx, openStreamTimeout)
		conn, err := c.DialConn(tryCtx, destination.AddrString(), destination.Port)
		cancel()
		if err == nil {
			return conn, nil
		}
		lastErr = err
		o.drop(c)
		if ctx.Err() != nil {
			break
		}
		o.logger.Debug("flowtls 开流失败，重建通道后重试: ", err)
	}
	return nil, E.Cause(lastErr, "flowtls 开流失败")
}

// ListenPacket 建立一条 UDP 中继。
func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		c, err := o.channel(ctx)
		if err != nil {
			return nil, E.Cause(err, "flowtls 通道不可用")
		}
		pc, err := c.ListenPacket(ctx, destination.AddrString(), destination.Port)
		if err == nil {
			return pc, nil
		}
		lastErr = err
		o.drop(c)
		if ctx.Err() != nil {
			break
		}
		o.logger.Debug("flowtls 开 UDP 会话失败，重建通道后重试: ", err)
	}
	return nil, E.Cause(lastErr, "flowtls 开 UDP 会话失败")
}

// MultiplexEnabled 恒为 true：一条 QUIC 连接承载所有流，与 hy2/anytls 一致。
func (o *Outbound) MultiplexEnabled() bool { return true }

// InterfaceUpdated 在网络接口变化时重建通道。
//
// 不重置会怎样：切换 Wi-Fi/有线、或公网 IP 变化后，旧连接仍在用旧的四元组
// 与 seq 空间，服务端的伪造 TCP 状态对不上，表现为「所有请求超时但进程正常」，
// 且只能等 idle timeout 自愈。
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

// SetKeepIdleConnections 保持空闲连接：flowtls 只有一条常驻通道，
// 没有可切换的空闲池，空实现只为满足接口。
func (o *Outbound) SetKeepIdleConnections(keep bool) { _ = keep }

// CloseIdleConnections 关闭空闲连接：语义上等价于「下次请求重新握手」。
func (o *Outbound) CloseIdleConnections() {
	o.mu.Lock()
	c := o.client
	o.client = nil
	o.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}
