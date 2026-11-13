// Package quic 的拥塞控制层：BBR + 动态窗口上限。
//
// 这个文件是 Rust 版 `src/quic/capped.rs` 的**逐条对应移植**，
// 不是「参考重写」。Rust 版为什么这么写，注释里全部保留。
//
// ## 为什么需要「窗口上限」这一层
//
// 跨境链路夜间高丢包时，BBR 会把 ACK 聚合误算成「一次送达大量字节」，
// 带宽估计被抬高，cwnd 一路涨到 17MB（相当于 68ms RTT 下 2Gbps 的 BDP），
// 而香港服务器只有 100M 端口。结果是自己把下行链路打爆，丢包率 50%+，
// QUIC 只能靠 PTO 单包重传，表现为「两端进程都在、连接也活着，但完全没速度」。
//
// ## 为什么只钳 window 就够
//
// 发送端实际能压出去的字节数由「在途上限」决定，而在途上限就是 cwnd。
// 因此钳住 cwnd 就等于同时限制了突发容量和平均发送速率
// （平均速率 ≈ cwnd ÷ RTT）。这样不用改 quic-go 源码，
// 也保留 BBR 在正常链路上的自适应能力。
package quic

import (
	"sync"
	"sync/atomic"
	"time"

	quicgo "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
)

// PathStats 是一次采样周期内的 QUIC 路径统计。
//
// 对应 Rust 版每 2 秒那行「QUIC 路径统计」日志的字段。
// **字段必须能直接看出吞吐卡在哪**：
//   - LossPct 高 → 链路真的在丢，窗口会被调小；
//   - WinCap 卡在下限 1.5MB → 说明丢包率一直很高，链路本身有问题；
//   - WinCap 停在上限 → 说明 BBR 吃饱了，瓶颈在带宽而不是窗口；
//   - 完全没有日志 → 说明自适应循环没起来（或连接没 attach）。
type PathStats struct {
	// RTT 是最近一次 RTT 采样；SmoothedRTT 是平滑值。
	RTT         time.Duration
	SmoothedRTT time.Duration
	// SentPackets / LostPackets 是**累计**计数（不是本周期增量）。
	SentPackets uint64
	LostPackets uint64
	// LossPct 是本采样周期的丢包率百分数（0~100）。
	LossPct uint64
	// WinCap 是调整后的窗口上限（字节）。
	WinCap uint64
	// Conns 是参与统计的连接数。
	Conns int
	// CC 是当前拥塞控制算法名（"bbr" 或 "brutal"），仅用于日志。
	CC string
}

// 窗口参数常量，与 Rust 完全一致。
const (
	// DefaultMaxCwnd 是 `net.max_cwnd` 的默认值：8MB。
	//
	// Rust `config.rs::default_max_cwnd` 原文：
	// 与 hysteria2 默认流窗口（8MB）对齐，按 1000Mbps × 70ms 的 BDP 留足余量。
	// 小带宽跨境链路（实际 20~50Mbps）建议调到 1MB 左右，否则丢包会明显变多。
	DefaultMaxCwnd uint64 = 8 * 1024 * 1024

	// minWindow / maxWindow 是自适应算法的钳制边界，对应 Rust 的
	// `1536 * 1024` 与 `8 * 1024 * 1024`。
	minWindow uint64 = 1536 * 1024
	maxWindow uint64 = 8 * 1024 * 1024

	// bbrPacketSize / assembleSlots 用于按丢包率反算安全窗口：
	// 收包组装器能容忍的乱序空洞 = 窗口 ÷ 包大小 × 丢包率，
	// 反解出窗口上界，再乘 0.7 留余量。
	bbrPacketSize = 1308.0
	assembleSlots = 1024.0
	safetyFactor  = 0.7
	lossFloor     = 0.01 // 丢包率下限，避免除零

	// 自适应阈值与步长。
	// Rust 注释：之前 15%/0.85 太激进，正常链路抖动就会把窗口压到 1~2MB，
	// 测速时上下行都跑不满。崩了还有外层自动重连兜底。
	lossHighMark = 0.20
	lossLowMark  = 0.05
	windowShrink = 0.90
	windowGrow   = 1.20

	// statsInterval 是自适应与统计的采样周期（Rust 也是 2 秒）。
	statsInterval = 2 * time.Second
)

// cappedBbr 给原生 BBR 加窗口上限。
//
// 设计**与 Rust 的 `CappedBbr` 完全一致**：所有方法原样委托给内部 BBR
// （保持带宽/RTT 估计不变），只在「读取窗口」时截断。
// 窗口上限是共享原子值，自适应算法在连接运行中修改会立即生效，
// 不需要重建连接或重装控制器。
//
// 为什么不能靠 `Conn.SetCongestionControl` 重装：
// 重装会把 `firstPacketNumber` 推到当前包号，新实例拿不到此前的
// 发送/确认历史，带宽估计与 pacing 会从头再来——每 2 秒重装一次
// 等于让 BBR 永远停在 startup 阶段，吞吐反而更差。
//
// 这里嵌入 `CongestionControlEx`（不是基础接口），
// 保证包装后仍走 quic-go 的 Ex 快速路径，不降级成逐包回调。
type cappedBbr struct {
	congestion.CongestionControlEx
	// cap 是共享的窗口上限（字节），由 windowController 的自适应循环调整。
	cap *atomic.Uint64
}

// newCappedBbr 用给定初始包大小和共享上限构造控制器。
//
// initialPacketSize 必须是 `conn.InitialPacketSize()`：
// quic-go 的注释明确要求注入的控制器用连接的真实初始包大小播种，
// 用包默认值会在路径 MTU 发现报告中间值时错判。
func newCappedBbr(initialPacketSize congestion.ByteCount, cap *atomic.Uint64) *cappedBbr {
	return &cappedBbr{
		CongestionControlEx: congestion_meta2.NewBbrSenderWithProfile(
			initialPacketSize, congestion_meta2.ProfileStandard),
		cap: cap,
	}
}

// limit 返回当前生效的窗口上限。
func (c *cappedBbr) limit() congestion.ByteCount {
	v := c.cap.Load()
	if v == 0 {
		// 未初始化时退回默认值，避免窗口被钳成 0 把连接卡死。
		return congestion.ByteCount(DefaultMaxCwnd)
	}
	return congestion.ByteCount(v)
}

// GetCongestionWindow 是唯一真正改动的行为：
// 无论 BBR 算出多大的窗口，对外都不超过上限。
// quic-go 用这个值算「还能发几个包」（sent_packet_handler 的 cwndPackets），
// 因此它直接决定在途字节上限，平均速率 ≈ 窗口 ÷ RTT。
func (c *cappedBbr) GetCongestionWindow() congestion.ByteCount {
	w := c.CongestionControlEx.GetCongestionWindow()
	if limit := c.limit(); w > limit {
		return limit
	}
	return w
}

// CanSend 同样按上限判断，避免 BBR 内部认为「还能发」而绕开窗口限制。
func (c *cappedBbr) CanSend(bytesInFlight congestion.ByteCount) bool {
	if bytesInFlight >= c.limit() {
		return false
	}
	return c.CongestionControlEx.CanSend(bytesInFlight)
}

// windowController 管理一组连接的共享窗口上限与自适应循环。
//
// 为什么服务端要「共享一份上限」而不是每连接一份：
// Rust `server.rs` 里 `max_cwnd` 是单个 `Arc<AtomicU64>`，
// 被 `server_config(max_cwnd.clone())` 一次性交给所有连接的 `CappedBbr`，
// 自适应时按**全部连接的汇总丢包率**调整。
// 客户端只有一条连接，等价于单体。
type windowController struct {
	// cap 是当前窗口上限（字节），所有连接共享。
	cap atomic.Uint64
	// cfgMaxCwnd 是配置上限（`net.max_cwnd`）：自适应只能在它之下浮动。
	//
	// Rust 注释：之前只当初始值，丢包率低于 5% 时会被 1.2 倍一路放大到
	// 8MB，用户按小带宽链路设的值完全失效（窗口远超 BDP，丢包反而变多）。
	cfgMaxCwnd uint64

	mu     sync.Mutex
	conns  map[*quicgo.Conn]struct{}
	closed bool
	stop   chan struct{}
	// onStats 是可选统计回调（nil 表示不输出）。
	// 对应 Rust 每 2 秒那行「QUIC 路径统计」。
	onStats func(PathStats)

	// brutalBPS > 0 时用 Brutal（hy1 风格强制发包），否则用 BBR。
	//
	// Brutal 与 BBR 的取舍：
	//   - BBR：自动适应，但会把随机丢包当成拥塞信号而降速；
	//   - Brutal：按配置带宽硬发，丢包只靠重传兜底，高丢包链路吞吐高得多，
	//     但配错带宽（远大于真实带宽）会把链路打爆。
	brutalBPS        uint64
	brutalMultiplier float64
}

// newWindowController 创建并启动自适应循环。
// cfgMaxCwnd 传 0 表示用默认 8MB；onStats 可为 nil。
func newWindowController(cfgMaxCwnd uint64, onStats func(PathStats)) *windowController {
	return newWindowControllerEx(cfgMaxCwnd, onStats, 0, 0)
}

// newWindowControllerEx 带 Brutal 参数。
//
// brutalBPS > 0 时启用 Brutal（hy1 风格），brutalMultiplier <= 0 时取默认 2.0。
func newWindowControllerEx(cfgMaxCwnd uint64, onStats func(PathStats),
	brutalBPS uint64, brutalMultiplier float64) *windowController {
	if cfgMaxCwnd == 0 {
		cfgMaxCwnd = DefaultMaxCwnd
	}
	if brutalBPS > 0 && brutalMultiplier <= 0 {
		brutalMultiplier = DefaultBrutalMultiplier
	}
	w := &windowController{
		cfgMaxCwnd:       cfgMaxCwnd,
		conns:            make(map[*quicgo.Conn]struct{}),
		stop:             make(chan struct{}),
		onStats:          onStats,
		brutalBPS:        brutalBPS,
		brutalMultiplier: brutalMultiplier,
	}
	// 初始窗口上限就是配置值，与 Rust 的
	// `AtomicU64::new(cfg.net.max_cwnd)` 一致。
	w.cap.Store(cfgMaxCwnd)
	go w.loop()
	return w
}

// Window 返回当前窗口上限。
func (w *windowController) Window() uint64 { return w.cap.Load() }

// Attach 给新连接装上带当前上限的拥塞控制器，并纳入自适应统计。
//
// **两种模式都必须显式 SetCongestionControl**。
//
// 曾经只有 Brutal 分支设了控制器，BBR 分支什么都不做，后果是：
//   - quic-go 用自己的默认控制器，`w.cap` 与 cappedBbr 变成死代码；
//   - 自适应循环每 2 秒算出的窗口上限对真实发送**零影响**；
//   - 日志里 `cc=bbr` 只是根据 brutalBPS 推出来的字符串，与实际控制器无关，
//     直接误导排查（实测服务端 BBR 模式 254KB/s，Brutal 模式 10.7MB/s，
//     而 Rust 服务端同链路 BBR 能跑 14.5MB/s —— 差距根本不是算法选择问题，
//     而是我们压根没把自己那套控制器装上）。
func (w *windowController) Attach(conn *quicgo.Conn) {
	// Brutal 模式：丢包不减窗，按配置带宽硬发（hy1 风格）。
	// 这时窗口由 bps × rtt × multiplier 推导，不受 cap 影响。
	if w.brutalBPS > 0 {
		conn.SetCongestionControl(
			newBrutalSender(w.brutalBPS, w.brutalMultiplier, conn.InitialPacketSize()))
	} else {
		// BBR 模式：装上 capped BBR，让自适应窗口的上限真正生效。
		//
		// 注意传的是 &w.cap（共享原子值的地址），不是当前值快照：
		// 自适应循环之后改 w.cap 会立刻被这条连接读到，无需重建控制器
		// （重建会把 BBR 的带宽估计与 pacing 历史清零，见 cappedBbr 注释）。
		conn.SetCongestionControl(newCappedBbr(conn.InitialPacketSize(), &w.cap))
	}

	// **两种模式都要登记**：统计日志（RTT/丢包/批大小）是排障的唯一依据，
	// Brutal 模式尤其需要它——它不响应丢包，一旦配错带宽就会静默打爆链路，
	// 只有从日志里看到 loss% 才能发现。
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.conns[conn] = struct{}{}
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
// **逻辑逐行对应 Rust**（客户端 `client.rs`、服务端 `server.rs`
// 用的是完全同一套策略）：
//
//	loss > 20% → 窗口 × 0.90
//	loss < 5%  → 窗口 × 1.20
//	其余保持不变
//
//	safe_cap = 1024 × 1308 ÷ loss × 0.7      （组装器硬限制反算）
//	upper    = clamp(safe_cap, 1.5MB, 8MB).min(cfg.max_cwnd)
//	next     = clamp(next, 1.5MB, upper)
//
// 阈值放宽到 20%/5%、步长 0.9/1.2 的理由（Rust 注释原文）：
// 之前 15%/0.85 太激进，正常链路抖动就会把窗口压到 1~2MB，
// 测速时上下行都跑不满。崩了还有外层自动重连兜底。
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

		// 汇总全部连接的发送/丢包计数
		// （Rust 服务端也是汇总 total_sent / total_lost）。
		w.mu.Lock()
		conns := make([]*quicgo.Conn, 0, len(w.conns))
		for c := range w.conns {
			conns = append(conns, c)
		}
		w.mu.Unlock()

		if len(conns) == 0 {
			// 没有活跃连接时重置基线：否则下次建连时会把
			// 「断开期间的 0」当成一次采样，算出 0% 丢包率把窗口放大。
			lastSent, lastLost = 0, 0
			continue
		}

		// 拥塞控制算法名，只用于日志。Brutal 模式尤其要看它：
		// 它不响应丢包，配错带宽会静默打爆链路，只能靠日志发现。
		cc := "bbr"
		if w.brutalBPS > 0 {
			cc = "brutal"
		}

		var totalSent, totalLost uint64
		var rtt, srtt time.Duration
		for _, c := range conns {
			s := c.ConnectionStats()
			totalSent += s.PacketsSent
			totalLost += s.PacketsLost
			// 取最后一条连接的 RTT 作为代表（Rust 客户端只有一条，
			// 服务端日志里也只报汇总丢包率，不报每条连接的 RTT）。
			rtt, srtt = s.LatestRTT, s.SmoothedRTT
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

		// 按丢包率反算组装器能容忍的安全上限。
		// loss 归一到下限，避免低丢包率时 safe_cap 溢出成天文数字。
		effLoss := loss
		if effLoss < lossFloor {
			effLoss = lossFloor
		}
		safeCap := uint64(assembleSlots * bbrPacketSize / effLoss * safetyFactor)

		// cfg_cap 语义与 Rust 严格一致：`cfg.net.max_cwnd.max(1536 * 1024)`。
		//
		// 为什么配置值也要抬到下限：用户可能填一个比安全下限还小的值
		// （例如 1MB），若直接用它收口，窗口会被压到 1MB 以下——
		// 在 78ms RTT 下只能跑 10Mbps，等于把链路限死在低速。
		// Rust 用 `.max(1536*1024)` 保证下限，这里照抄。
		cfgCap := w.cfgMaxCwnd
		if cfgCap < minWindow {
			cfgCap = minWindow
		}

		// upper = clamp(safe_cap, 1.5MB, 8MB).min(cfg_cap)
		upper := clampU64(safeCap, minWindow, maxWindow)
		if cfgCap < upper {
			upper = cfgCap
		}
		// next = clamp(next, 1.5MB, upper)
		next = clampU64(next, minWindow, upper)

		// 只改原子值，不动已装好的控制器：
		// cappedBbr 每次读窗口都会重新 load，因此立即生效，
		// 而 BBR 的带宽估计与 pacing 状态完整保留（Rust 也是这个做法）。
		w.cap.Store(next)

		if w.onStats != nil {
			w.onStats(PathStats{
				RTT:         rtt,
				SmoothedRTT: srtt,
				SentPackets: totalSent,
				LostPackets: totalLost,
				LossPct:     uint64(loss * 100),
				WinCap:      next,
				Conns:       len(conns),
				CC:          cc,
			})
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
