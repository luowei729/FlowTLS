package quic

// 本文件对应 legacy-rust:src/quic/capped.rs，以及 client.rs / server.rs
// 里每 2 秒一次的自适应窗口更新块。
//
// # 为什么需要「窗口上限」
//
// 跨境链路夜间高丢包时，BBR 会把 ACK 聚合误算成「一次送达大量字节」，
// 带宽估计被抬高，cwnd 一路涨到 17MB（68ms RTT 下 2Gbps 的 BDP），
// 而服务器只有 100M 端口。结果是自己把下行链路打爆、丢包率 50%+，
// QUIC 只能靠 PTO 单包重传——表现为「两端进程都在、连接也活着，但完全没速度」。
//
// # 为什么只钳窗口就够（以及为什么 Go 必须多钳 pacing）
//
// quinn 的 pacing 速率完全由 `Controller::window()` 和 RTT 推导
// （capacity = window / rtt * 1.25），因此钳住 window 上限等于同时限制了
// 突发容量和持续发送速率。
//
// quic-go **不是这样**：`GetCongestionWindow` 只决定在途上限，
// 发送时刻由 `TimeUntilSend` → 内层 pacer 决定，而 pacer 的带宽
// 来自 BBR 自己的估计，**不读窗口**。只钳窗口时，估计一旦被抬到数 Gbps，
// 会在一个 RTT 内把整窗数据突发打出去，然后干等 ACK——
// 这正是「两端进程都在、连接也活着，但完全没速度」的机制。
// 所以 Go 侧必须同时钳三条路径：GetCongestionWindow、CanSend、TimeUntilSend。
// 带宽估计本身不动，内层 BBR 的学习过程保持原样。
//
// # 为什么不能靠重装控制器
//
// `Conn.SetCongestionControl` 会把 `firstPacketNumber` 推到当前包号，
// 新实例看不到此前已在途的包，带宽估计从零开始。每 2 秒重装一次
// 等于让 BBR 永远停在 startup 阶段。因此控制器**只装一次**，
// 上限用共享原子值，自适应循环只 Store。

import (
	"log"
	"sync"
	"sync/atomic"
	"time"

	quicgo "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
)

// DefaultMaxWindow 是默认窗口上限：4MB（Rust `DEFAULT_MAX_WINDOW`）。
//
// 受接收组装器 MAX_CHUNKS=1024 硬限制约束：窗口 × 丢包率 ÷ 包大小 必须小于
// 1024，否则乱序空洞超限会直接断连。实测链路丢包 30~50%，4MB 对应 960 个
// 空洞，安全；同时仍为本链路 BDP（约 1.23MB）的 3 倍，能跑满 70Mbps。
const DefaultMaxWindow uint64 = 4 * 1024 * 1024

// 自适应算法的常量（与 Rust client.rs / server.rs 逐项一致）。
const (
	// 阈值放宽到 20%/5%、步长 0.9/1.2 的理由（Rust 注释原文）：
	// 之前 15%/0.85 太激进，正常链路抖动就会把窗口压到 1~2MB，
	// 测速时上下行都跑不满。崩了还有外层自动重连兜底。
	lossHighMark = 0.20
	lossLowMark  = 0.05
	windowShrink = 0.90
	windowGrow   = 1.20

	// 按丢包率反算组装器能容忍的安全上限：
	// 安全上限 = 1024 × 1308 ÷ 丢包率 × 0.7
	assembleSlots = 1024.0
	packetSize    = 1308.0
	safetyFactor  = 0.7
	lossFloor     = 0.01 // 丢包率下限，避免除零

	minWindow uint64 = 1536 * 1024
	maxWindow uint64 = 8 * 1024 * 1024

	// statsInterval 是自适应与统计的采样周期（Rust 也是 2 秒）。
	statsInterval = 2 * time.Second
)

// cappedBbr 给原生 BBR 加窗口上限（Rust `CappedBbr` 的翻译）。
//
// 所有方法原样委托给内部 BBR（保持带宽/RTT 估计不变），
// 只在读取窗口时截断。上限是共享原子值，自适应循环修改后立即生效。
type cappedBbr struct {
	congestion.CongestionControlEx
	// maxWindow 是允许的在途数据上限（字节），外层自适应算法实时调整。
	maxWindow *atomic.Uint64
	// lastCwnd / lastInFlight 记录对外可见的窗口与在途字节，
	// 供统计日志使用（quic-go 的 ConnectionStats 不暴露这两个值）。
	lastCwnd     atomic.Uint64
	lastInFlight atomic.Uint64
	// lostPackets / lostBytes 是本控制器**自己**统计的丢包计数。
	//
	// 为什么不能直接用 `ConnectionStats().PacketsLost`：
	// quic-go 里那个计数器**只在 cubic_sender.go 里累加**（BBR 路径根本不填），
	// 于是用 BBR 时它恒为 0。这不是显示问题——窗口自适应循环靠它算丢包率，
	// 恒为 0 会被判成「链路无丢包」，于是上限每 2 秒 ×1.2 一路涨到 8MB，
	// 从 Rust 移植的「高丢包时压窗口」机制变成死代码。
	// 实测（loopback + netem 突发丢包）表现为：Rust 上限稳定在 1.5MB、
	// 吞吐 3.3 MB/s；Go 上限停在 8MB、cwnd 在 6.6KB~43KB 剧烈震荡、
	// 吞吐塌到 86 KB/s。
	//
	// `PacketsSent` 是可靠的（在 sent_packet_handler.go 里累加，与控制器无关），
	// 因此只要自己数丢包，丢包率就能算对。
	lostPackets atomic.Uint64
	lostBytes   atomic.Uint64

	// nextSend 是「窗口掉到地板时」下一次允许发包的时刻。
	//
	// 只在窗口低于地板阈值时使用。正常窗口下不读它，
	// 所以不会改变健康连接的发送节奏。
	nextSend atomic.Int64

	// srtt 是本控制器自己算的平滑 RTT（微秒）。
	//
	// 不用内层 BBR 的 RTT：那个字段未导出，而且拥塞控制接口
	// 不提供读取方法。发送和确认时间都在 OnCongestionEventEx 里，
	// 自己算一份只为决定「包与包之间隔多久」。
	srtt atomic.Int64
}

// newCappedBbr 用给定初始包大小和共享上限构造控制器。
//
// initialPacketSize 必须是 `conn.InitialPacketSize()`：
// quic-go 的注释明确要求注入的控制器用连接的真实初始包大小播种。
func newCappedBbr(initialPacketSize congestion.ByteCount, maxWindow *atomic.Uint64) *cappedBbr {
	return &cappedBbr{
		CongestionControlEx: congestion_meta2.NewBbrSenderWithProfile(
			initialPacketSize, congestion_meta2.ProfileStandard),
		maxWindow: maxWindow,
	}
}

// limit 返回当前生效的窗口上限。
func (c *cappedBbr) limit() congestion.ByteCount {
	v := c.maxWindow.Load()
	if v == 0 {
		// 未初始化时退回默认值，避免窗口被钳成 0 把连接卡死。
		return congestion.ByteCount(DefaultMaxWindow)
	}
	return congestion.ByteCount(v)
}

// GetCongestionWindow 是核心改动：无论 BBR 算出多大，对外都不超过上限。
//
// quic-go 用这个值算「还能发几个包」（cwndPackets），
// 因此它直接决定在途字节上限，平均速率 ≈ 窗口 ÷ RTT。
func (c *cappedBbr) GetCongestionWindow() congestion.ByteCount {
	w := c.CongestionControlEx.GetCongestionWindow()
	if limit := c.limit(); w > limit {
		w = limit
	}
	c.lastCwnd.Store(uint64(w))
	return w
}

// CanSend 同样按上限判断。
//
// 为什么必须覆写：内层 BBR 的 CanSend 是 `bytesInFlight < GetCongestionWindow()`，
// 读的是**内层未钳制**的窗口；不覆写会让在途字节短暂突破上限
// （Rust 侧 quinn 只有 window() 一条判定路径，所以那边不需要）。
func (c *cappedBbr) CanSend(bytesInFlight congestion.ByteCount) bool {
	c.lastInFlight.Store(uint64(bytesInFlight))
	if bytesInFlight >= c.limit() {
		return false
	}
	return c.CongestionControlEx.CanSend(bytesInFlight)
}

// floorSpreadMinRate 是窗口掉到地板时铺开包的最低速率：1 Mbps。
//
// 为什么是 1 Mbps 而不是更大：
// 它只决定「这几个包之间隔多久」，不增加在途字节。
// 1 Mbps 在 80ms RTT 下约 10KB，比 BBR 的地板（4 个包，约 5KB）宽一倍，
// 足够把扎堆的丢包拆开，又不会在真拥塞时硬塞数据。
// 速率随 RTT 变化：RTT 更大时包之间隔得更开，不需要按线路手调。
const floorSpreadMinRate = 1_000_000 / 8 // 字节/秒

// TimeUntilSend 在窗口掉到 BBR 地板时，把仅有的几个包均匀铺开。
//
// 正常情况下原样交给内层 BBR：它的 pacing 按带宽估计发，
// 这一层不该改健康连接的节奏。
//
// 窗口一旦掉进 recovery（持续丢包时 recoveryWindow 每轮减掉丢失的字节，
// 减到比 4 个包还小就被钳回 4 个包），内层 pacing 仍按带宽估计把这 4 个包
// 堆在一个 RTT 的开头一次性打出，剩下几十毫秒空等。
// 丢包因此扎成一簇，recovery 更难爬出来。
//
// 2026-11-18 20:24 新加坡链路实测：cwnd 从 796KB 在 4 秒内掉到 38KB，
// 随后多次落到 5328 字节（正好 4×1332），客户端下载从 10 Mbps 掉到 1.3 Mbps，
// 持续约 30 秒。同一时刻 ICMP 丢包 10%、RTT 不抖，链路本身有余量。
//
// 这里不抬窗口下限。抬下限等于在真拥塞时硬塞数据，
// 而这次的丢包是随机的，补发只会让同一条链路丢更多。
func (c *cappedBbr) TimeUntilSend(bytesInFlight congestion.ByteCount) monotime.Time {
	inner := c.CongestionControlEx.TimeUntilSend(bytesInFlight)
	cwnd := c.GetCongestionWindow()
	if cwnd == 0 || cwnd > 8*initialMTU {
		// 窗口健康：连「铺开」的必要都没有，保持内层节奏。
		return inner
	}
	rtt := time.Duration(c.srtt.Load())
	if rtt <= 0 {
		// 还没有确认过任何包，没有 RTT 可用，保持内层节奏。
		return inner
	}
	// 间隔 = 包长 ÷ 速率，但速率至少要能在一个 RTT 内把当前窗口发完，
	// 否则人为拉开的间隔会比窗口允许的还慢。
	rate := congestion.ByteCount(float64(cwnd) / rtt.Seconds())
	if minRate := congestion.ByteCount(floorSpreadMinRate); rate < minRate {
		rate = minRate
	}
	gap := time.Duration(float64(time.Second) * float64(initialMTU) / float64(rate))
	now := monotime.Now()
	scheduled := monotime.Time(c.nextSend.Load())
	if scheduled < now {
		scheduled = now
	}
	// 只允许比内层更晚，不允许更早：内层若已经在限速，尊重它。
	if scheduled < inner {
		scheduled = inner
	}
	c.nextSend.Store(int64(scheduled.Add(gap)))
	return scheduled
}

// OnCongestionEventEx 在把丢包事件原样交给内层 BBR 之前，先自己记一笔。
//
// 这是**唯一**能拿到「本连接被判丢的包」的入口：quic-go 的
// `ConnectionStats().PacketsLost` 只在 cubic 路径累加，BBR 下恒为 0。
// 内层行为不做任何改动（全部委托），只做计数，因此不影响拥塞控制本身。
func (c *cappedBbr) OnCongestionEventEx(
	priorInFlight congestion.ByteCount,
	eventTime monotime.Time,
	ackedPackets []congestion.AckedPacketInfo,
	lostPackets []congestion.LostPacketInfo,
) {
	if len(lostPackets) > 0 {
		c.lostPackets.Add(uint64(len(lostPackets)))
		var bytes uint64
		for _, p := range lostPackets {
			bytes += uint64(p.BytesLost)
		}
		c.lostBytes.Add(bytes)
	}
	// 取这一批确认里最小的 RTT 当本次采样：同一批里偏大的值
	// 多半是延迟确认造成的，不代表链路。
	var sample time.Duration
	for _, p := range ackedPackets {
		if p.SentTime == 0 || p.ReceivedTime < p.SentTime {
			continue
		}
		rtt := time.Duration(p.ReceivedTime - p.SentTime)
		if rtt > 0 && (sample == 0 || rtt < sample) {
			sample = rtt
		}
	}
	if sample > 0 {
		c.updateSRTT(sample)
	}
	c.CongestionControlEx.OnCongestionEventEx(priorInFlight, eventTime, ackedPackets, lostPackets)
}

// updateSRTT 用 TCP 的标准权重更新平滑 RTT：srtt += (sample - srtt) / 8。
//
// 第一次采样直接采用。之后每次只动八分之一，
// 单个离群样本不会把发包间隔一下子拉得很开。
func (c *cappedBbr) updateSRTT(sample time.Duration) {
	prev := time.Duration(c.srtt.Load())
	if prev == 0 {
		c.srtt.Store(int64(sample))
		return
	}
	c.srtt.Store(int64(prev + (sample-prev)/8))
}

// windowController 管理一组连接的共享窗口上限与自适应循环。
//
// 对应 Rust 的 `Arc<AtomicU64> max_cwnd` + 每 2 秒的自适应块。
// 服务端所有连接共享一份上限（Rust server.rs 同一个 Arc 交给所有 CappedBbr）；
// 客户端只有一条连接，等价于单体。
type windowController struct {
	// cap 是当前窗口上限（字节），所有连接共享。
	cap atomic.Uint64
	// cfgMaxCwnd 是配置上限（net.max_cwnd）：自适应只能在它之下浮动。
	cfgMaxCwnd uint64

	mu     sync.Mutex
	conns  map[*quicgo.Conn]*connEntry
	closed bool
	stop   chan struct{}

	// onStats 是可选统计回调（nil 表示不输出）。
	onStats func(PathStats)
}

// connEntry 是一条被统计的连接及其附属信息。
type connEntry struct {
	conn *quicgo.Conn
	cc   *cappedBbr

	// prevSent / prevLost 是该连接上一次采样时的累计值。
	//
	// **必须按连接各自记录，不能共用一份全局基线**：
	// `loss_pct` 描述的是「这条连接在本采样周期的丢包率」，
	// 若用全部连接加总的 Δ 再打印到每一行，同一次采样的所有连接会显示
	// 同一个数字。真机上出现过 `sent=1368 lost=0 loss_pct=26` 这种荒谬
	// 结果 —— 那条连接一个包都没丢，26% 是别的连接丢的。
	//
	// 注意字段只由 loop 单协程读写（entries 快照后独占），不需要额外加锁。
	prevSent uint64
	prevLost uint64
}

// PathStats 是一次采样周期内的 QUIC 路径统计（对应 Rust 的「QUIC 路径统计」日志）。
type PathStats struct {
	// Remote 是本条连接的对端地址（多客户端时用于归属 RTT）。
	Remote string
	// RTT 是最近一次 RTT 采样；SmoothedRTT / MinRTT 是平滑值与最小值。
	RTT         time.Duration
	SmoothedRTT time.Duration
	MinRTT      time.Duration
	// SentPackets / LostPackets 是累计计数（不是本周期增量）。
	SentPackets uint64
	LostPackets uint64
	// LossPct 是本采样周期的丢包率百分数（0~100）。
	LossPct uint64
	// WinCap 是调整后的窗口上限（字节）。
	WinCap uint64
	// Cwnd / InFlight 是拥塞窗口与在途字节。
	Cwnd     uint64
	InFlight uint64
	// Conns 是参与统计的连接数。
	Conns int
}

// newWindowController 创建并启动自适应循环。
// cfgMaxCwnd 传 0 表示用默认 8MB；onStats 可为 nil。
func newWindowController(cfgMaxCwnd uint64, onStats func(PathStats)) *windowController {
	const defaultMaxCwnd = 8 * 1024 * 1024 // 与 Rust `default_max_cwnd` 一致
	if cfgMaxCwnd == 0 {
		cfgMaxCwnd = defaultMaxCwnd
	}
	w := &windowController{
		cfgMaxCwnd: cfgMaxCwnd,
		conns:      make(map[*quicgo.Conn]*connEntry),
		stop:       make(chan struct{}),
		onStats:    onStats,
	}
	// 初始窗口上限就是配置值（Rust `AtomicU64::new(cfg.net.max_cwnd)`）。
	w.cap.Store(cfgMaxCwnd)
	go w.loop()
	return w
}

// Window 返回当前窗口上限。
func (w *windowController) Window() uint64 { return w.cap.Load() }

// Attach 给新连接装上带当前上限的拥塞控制器，并纳入自适应统计。
func (w *windowController) Attach(conn *quicgo.Conn) {
	cc := newCappedBbr(conn.InitialPacketSize(), &w.cap)
	conn.SetCongestionControl(cc)

	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.conns[conn] = &connEntry{conn: conn, cc: cc}
	w.mu.Unlock()
}

// Detach 在连接关闭后移除，避免自适应循环统计已死连接。
func (w *windowController) Detach(conn *quicgo.Conn) {
	w.mu.Lock()
	delete(w.conns, conn)
	w.mu.Unlock()
}

// Close 停止自适应循环。
func (w *windowController) Close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	w.conns = nil
	close(w.stop)
	w.mu.Unlock()
}

// loop 每 2 秒按实测丢包率调整窗口上限。
//
// **逻辑逐行对应 Rust client.rs / server.rs 的自适应块**：
//
//	loss > 20% → 窗口 × 0.90
//	loss < 5%  → 窗口 × 1.20
//	其余保持不变
//
//	safe_cap = 1024 × 1308 ÷ loss × 0.7      （组装器硬限制反算）
//	upper    = clamp(safe_cap, 1.5MB, 8MB).min(cfg.max_cwnd.max(1.5MB))
//	next     = clamp(next, 1.5MB, upper)
//
// Rust 把这个块放在事件循环里；Go 没有用户级事件循环（quic-go 自己驱动），
// 因此用一个 2 秒 ticker 协程，语义相同。
func (w *windowController) loop() {
	ticker := time.NewTicker(statsInterval)
	defer ticker.Stop()

	var lastSent, lastLost uint64
	for {
		select {
		case <-w.stop:
			return
		case <-ticker.C:
		}

		w.mu.Lock()
		entries := make([]*connEntry, 0, len(w.conns))
		for _, e := range w.conns {
			entries = append(entries, e)
		}
		w.mu.Unlock()

		if len(entries) == 0 {
			// 没有活跃连接时重置基线：否则下次建连时会把「断开期间的 0」
			// 当成一次采样，算出 0% 丢包率把窗口放大。
			lastSent, lastLost = 0, 0
			continue
		}

		var totalSent, totalLost uint64
		for _, e := range entries {
			s := e.conn.ConnectionStats()
			totalSent += s.PacketsSent
			// 丢包数用 cappedBbr 自己的计数：quic-go 的 s.PacketsLost 只在
			// cubic 路径累加，BBR 下恒为 0（见 cappedBbr.lostPackets 的注释）。
			totalLost += e.cc.lostPackets.Load()
		}

		// PacketsLost 不单调递增（判丢的包可能后来又收到，会被减回去），
		// 所以差值必须「大减小、否则按 0」，
		// 否则 uint64 环绕会算出天文数字丢包率把窗口砸到下限。
		var dSent, dLost uint64
		if totalSent > lastSent {
			dSent = totalSent - lastSent
		}
		if totalLost > lastLost {
			dLost = totalLost - lastLost
		}
		lastSent, lastLost = totalSent, totalLost

		loss := 0.0
		if dSent > 0 {
			loss = float64(dLost) / float64(dSent)
		}

		cur := w.cap.Load()
		var next uint64
		switch {
		case loss > lossHighMark:
			next = uint64(float64(cur) * windowShrink)
		case loss < lossLowMark:
			next = uint64(float64(cur) * windowGrow)
		default:
			next = cur
		}

		// cfg_cap 语义与 Rust 严格一致：`cfg.net.max_cwnd.max(1536 * 1024)`。
		//
		// 为什么配置值也要抬到下限：用户可能填一个比安全下限还小的值（如 1MB），
		// 若直接用它收口，窗口会被压到 1MB 以下——在 78ms RTT 下只能跑 10Mbps。
		cfgCap := w.cfgMaxCwnd
		if cfgCap < minWindow {
			cfgCap = minWindow
		}
		// 按丢包率反算安全上限（loss 归一到下限，避免溢出成天文数字）
		effLoss := loss
		if effLoss < lossFloor {
			effLoss = lossFloor
		}
		safeCap := uint64(assembleSlots * packetSize / effLoss * safetyFactor)

		// upper = clamp(safe_cap, 1.5MB, 8MB).min(cfg_cap)
		upper := clampU64(safeCap, minWindow, maxWindow)
		if cfgCap < upper {
			upper = cfgCap
		}
		// next = clamp(next, 1.5MB, upper)
		next = clampU64(next, minWindow, upper)

		// 只改原子值，不动已装好的控制器：
		// cappedBbr 每次读窗口都会重新 load，因此立即生效，
		// 而 BBR 的带宽估计与 pacing 状态完整保留。
		w.cap.Store(next)

		if w.onStats != nil {
			// 每条连接单独上报：Rust 服务端也是每条连接一行，
			// 否则多客户端时 rtt= 属于谁无法判断。
			for _, e := range entries {
				s := e.conn.ConnectionStats()
				// 主动读一次窗口：quic-go 只在有数据要发时才调
				// GetCongestionWindow，空闲连接会一直停在旧值。
				_ = e.cc.GetCongestionWindow()

				// 本连接自己的周期增量。上面的 `loss` 是**全局聚合**的，
				// 只能用于窗口自适应（窗口本身就是全局的），
				// 打印时必须换成 per-conn 值，否则每条连接都显示同一个数。
				sent := s.PacketsSent
				lost := e.cc.lostPackets.Load()
				var connDSent, connDLost uint64
				if sent > e.prevSent {
					connDSent = sent - e.prevSent
				}
				if lost > e.prevLost {
					connDLost = lost - e.prevLost
				}
				e.prevSent, e.prevLost = sent, lost

				connLoss := 0.0
				if connDSent > 0 {
					connLoss = float64(connDLost) / float64(connDSent)
				}

				w.onStats(PathStats{
					Remote:      e.conn.RemoteAddr().String(),
					RTT:         s.LatestRTT,
					SmoothedRTT: s.SmoothedRTT,
					MinRTT:      s.MinRTT,
					SentPackets: sent,
					// 同上：必须用自建计数，否则日志里丢包率永远是 0。
					LostPackets: lost,
					LossPct:     uint64(connLoss * 100),
					WinCap:      next,
					Cwnd:        e.cc.lastCwnd.Load(),
					InFlight:    e.cc.lastInFlight.Load(),
					Conns:       len(entries),
				})
			}
		}
	}
}

// clampU64 把 v 限制在 [lo, hi]；hi < lo 时返回 lo。
func clampU64(v, lo, hi uint64) uint64 {
	if hi < lo {
		return lo
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// LogStats 是给**联调工具**用的默认统计输出（对应 Rust 的 INFO 日志行）。
//
// 它直接走标准库 log，因此**绕过宿主的 log.level**——只允许在
// `cmd/ftdial`、`cmd/ftserver` 这类不依赖 sing-box 的工具里使用。
// sing-box 适配层必须传自己的 OnStats（走 logger.Debug），
// 否则即使配置 `"level": "error"` 也会每 2 秒刷一行。
func LogStats(s PathStats) {
	log.Printf("flowtls: QUIC 路径统计 peer=%s rtt=%v cwnd=%dB inflight=%dB "+
		"sent=%d lost=%d loss_pct=%d win_cap=%d conns=%d",
		s.Remote, s.RTT.Round(time.Millisecond), s.Cwnd, s.InFlight,
		s.SentPackets, s.LostPackets, s.LossPct, s.WinCap, s.Conns)
}
