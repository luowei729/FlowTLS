package flowtls

// sing-box 出站适配层。
//
// 本文件**只做协议 ↔ sing-box 的翻译**，不含业务逻辑：
//
//	NewOutbound    参数校验（绝不碰 raw socket）
//	Start(Start)   建连（需要 root / CAP_NET_RAW）
//	DialContext    开一条流（对应 Rust `ProxyClient` 的一次 dial）
//	ListenPacket   开一条 UDP 中继
//	Close          释放
//
// 与 Rust 的对应关系：
//
//	Rust `ProxyClient`（单通道 + 每请求一次 dial） → 这里直接调用 ftquic.Client
//	Rust `client.rs::pipe_stream`（双向拷贝）      → sing-box router 负责
//	Rust `run()` 的指数退避重连                    → channel() 的懒重建
//
// **明确不做**（v1/v2 都在这里加过自造机制，全部被删除）：
//   - 不做探活（Probe）：Rust 没有，只有 QUIC idle timeout；
//   - 不做 suspectConn 式的错误包装：正常关闭流时 Read 必然报错，无法区分；
//   - 不做多层重试 / 不缓存失败：Rust 的重连在外层 run() 的退避里。

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
// 生命周期严格分三段（sing-box 的硬约束）：
//
//	NewOutbound    只做参数校验，**绝不碰 raw socket**
//	Start(Start)   建连（需要 root/CAP_NET_RAW）
//	Close          释放
//
// 构造函数不能申请权限：`sing-box check` 会完整走一遍
// box.New() → NewXxx() → Close()，在构造函数里开 raw socket 会让纯语法检查
// 也要求 root，而 check 是用户配错时的第一道防线。
type Outbound struct {
	outbound.Adapter
	ctx    context.Context
	logger log.ContextLogger
	opts   option.FlowTLSOutboundOptions

	// mu 保护 client 的懒加载与断线重建。
	mu     sync.Mutex
	client *ftquic.Client
	// dialing 在建连期间非 nil：并发请求等待同一次握手，
	// 而不是各自触发一遍（Rust 侧由单线程事件循环天然串行化）。
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
	if options.ServerPort == 0 {
		options.ServerPort = 8443
	}
	if options.SourcePort == 0 {
		options.SourcePort = 44300
	}
	if options.IPIDMark == 0 {
		options.IPIDMark = ft.IPIDMark | 0x07
	}
	// iptables 模式与握手参数在这里就解析：拼错时要报错，而不是拖到建连时
	// 才变成一句「握手超时」。Rust 的 config 校验同样在建连前。
	if _, err := ft.ParseMode(options.IPTablesMode); err != nil {
		return nil, err
	}
	if _, err := ft.ParseHandshake(options.Handshake); err != nil {
		return nil, err
	}

	networkList := options.Network.Build()
	if len(networkList) == 0 {
		networkList = []string{N.NetworkTCP}
		if udpOn(options.UDPEnabled) {
			networkList = append(networkList, N.NetworkUDP)
		}
	}
	// 只接受 TCP/UDP：明确拒绝而不是静默失败。
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

// udpOn 解释 udp_enabled 的三次态：nil(未填) 与 true 都是开启，只有显式
// false 才是关闭。与 Rust 的 `default_udp_enabled() -> true` 一致。
func udpOn(v *bool) bool {
	if v == nil {
		return true
	}
	return *v
}

// Start 在 StartStateStart 阶段建立通道。
func (o *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	scope.Add(o.Close)
	// 初始建连必须放到后台。
	//
	// sing-box 是串行启动：outbound 的 Start 返回之前，入口（mixed /
	// socks / tun）不会开始监听。而伪 TCP 握手最长要 15 秒才能判失败，
	// 在这期间客户端看起来「起来了但所有请求立刻失败」——
	// 实测 CI 的矩阵脚本就因此偶发 000。
	//
	// Rust 版没有这个问题：它的 socks5 入口与链路建立是并发的，
	// 链路没通时请求排队等待，而不是被立即拒绝。
	//
	// 建连失败不阻断启动：让请求来时重试，与 Rust 的退避重连等价。
	go func() {
		if _, err := o.channel(o.ctx); err != nil {
			o.logger.Error("flowtls 初始建连失败，将在首个请求时重试: ", err)
			return
		}
		// 极端时序：启动协程刚建好通道，Close 就先把 client 取走了。
		// 补一次清理，避免这条通道没人关（socket 泄漏）。
		if o.ctx.Err() != nil {
			_ = o.Close()
		}
	}()
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
	if a, err := netip.ParseAddr(o.opts.Server); err == nil {
		if !a.Unmap().Is4() {
			return netip.AddrPort{}, E.New("flowtls: server 必须是 IPv4 地址，得到 ", a)
		}
		return netip.AddrPortFrom(a.Unmap(), o.opts.ServerPort), nil
	}
	// 域名必须在这里解析成 IPv4：伪 TCP 层需要真实 IP 才能构造报文头。
	addrs, err := net.DefaultResolver.LookupNetIP(o.ctx, "ip4", o.opts.Server)
	if err != nil {
		return netip.AddrPort{}, E.Cause(err, "解析服务端域名 ", o.opts.Server)
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, E.New("flowtls: ", o.opts.Server, " 没有 IPv4 地址")
	}
	return netip.AddrPortFrom(addrs[0].Unmap(), o.opts.ServerPort), nil
}

// connect 建立一条新通道。调用方必须保证同一时刻只有一处在建连。
func (o *Outbound) connect() (*ftquic.Client, error) {
	server, err := o.resolveServer()
	if err != nil {
		return nil, err
	}
	sni := o.opts.SNI
	if sni == "" {
		sni = o.opts.Server
	}
	netMode, err := ft.ParseMode(o.opts.IPTablesMode)
	if err != nil {
		return nil, err
	}
	handshake, err := ft.ParseHandshake(o.opts.Handshake)
	if err != nil {
		return nil, err
	}

	onStats := func(s ftquic.PathStats) {
		o.logger.Debug("flowtls: QUIC 路径统计 peer=", s.Remote,
			" rtt=", s.RTT.Round(time.Millisecond),
			" srtt=", s.SmoothedRTT.Round(time.Millisecond),
			" cwnd=", s.Cwnd, " inflight=", s.InFlight,
			" sent=", s.SentPackets, " lost=", s.LostPackets,
			" loss_pct=", s.LossPct, " win_cap=", s.WinCap)
	}

	c, err := ftquic.NewClient(o.ctx, ftquic.ClientOptions{
		FlowTLS: ft.ClientConfig{
			Server:     server,
			Password:   o.opts.Password,
			SNI:        sni,
			SourcePort: o.opts.SourcePort,
			IPIDMark:   o.opts.IPIDMark,
			Handshake:  handshake,
			// 客户端规则必须在第一个包发出前就位：SYN-ACK 一回，内核就会
			// 发现没有对应 socket 并回 RST，中间设备会立即拆掉 NAT 映射。
			NetMode: netMode,
		},
		DialTimeout: 15 * time.Second,
		MaxCwnd:     maxCwndOf(o.opts.MaxCwnd),
		OnStats:     onStats,
	})
	if err != nil {
		return nil, err
	}
	// 发送路径与源地址：出向链路出问题时这行是第一个要看的信息。
	o.logger.Info("flowtls 通道已建立; 发送路径: ", c.SendMode())
	return c, nil
}

// channel 返回可用的 QUIC 通道，必要时建连。**这是唯一的获取入口。**
//
// 只做两件事（与 Rust 事件循环的等价物）：
//  1. 通道已关闭 → 丢弃重建（Rust 在 run() 里检测到会话结束就重连）；
//  2. 没有通道 → 建连，并发请求共享同一次握手。
func (o *Outbound) channel(ctx context.Context) (*ftquic.Client, error) {
	for {
		o.mu.Lock()
		c := o.client
		if c != nil {
			o.mu.Unlock()
			select {
			case <-c.Done():
				// 通道已死：丢弃后重来一轮。
				o.drop(c)
				continue
			default:
			}
			return c, nil
		}
		if wait := o.dialing; wait != nil {
			// 已有协程在建连：等它结束再判断结果，
			// 避免 N 个并发请求各握一次手（服务端会看到 N 个四元组）。
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

		newClient, err := o.connect()

		o.mu.Lock()
		o.dialing = nil
		if err == nil {
			o.client = newClient
		}
		o.mu.Unlock()
		close(done)

		if err != nil {
			return nil, err
		}
		return newClient, nil
	}
}

// drop 丢弃通道（只在它仍是当前通道时才关，避免误关别人刚建好的）。
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
	// 重试一次：QUIC 连接「已死但未检测到」是常态——服务端重启后，
	// 客户端仍能在旧连接上开流（只是写进本地缓冲），请求会卡到 idle 超时。
	// 首次失败即丢弃旧通道重建，用户只感知到一次稍慢的请求。
	for attempt := 0; attempt < 2; attempt++ {
		c, err := o.channel(ctx)
		if err != nil {
			return nil, E.Cause(err, "flowtls 通道不可用")
		}
		conn, err := c.DialConn(ctx, destination.AddrString(), destination.Port)
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
		pktConn, err := c.ListenPacket(ctx, destination.AddrString(), destination.Port)
		if err == nil {
			return pktConn, nil
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
// 与 seq 空间，服务端的伪造 TCP 状态对不上，表现为「所有请求超时但进程正常」。
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

// maxCwndOf 把配置里的 int64 窗口上限归一成 uint64。
//
// 为什么需要它：JSON 里的数字由用户手写，负数是完全可能的输入。
// Go 的 int64 → uint64 转换是位重解释，`uint64(-1)` 会变成 16EB，
// 等于彻底关掉窗口钳制，BBR 会把链路打爆，而日志里看不到任何异常。
func maxCwndOf(v int64) uint64 {
	if v <= 0 {
		return 0
	}
	return uint64(v)
}
