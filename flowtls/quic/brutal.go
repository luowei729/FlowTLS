package quic

// 本文件把拥塞控制换成 hysteria2 同款的 Brutal。
//
// 为什么换：BBR 只要一轮里还有丢包就停在 recovery，窗口从在途字节
// 每丢一个包减一截，一直减到 4 个包。跨境链路丢包常年 15% 左右，
// recovery 几乎永远不结束，窗口掉到地板后吞吐只剩 1~3 Mbps，
// 直播就会卡。2026-11-18 20:46 的实测就是这样。
//
// Brutal 的做法相反（sing-quic/hysteria/congestion/brutal.go，
// 与 hysteria2 用的是同一份）：
//
//   - 丢包不进入 recovery，窗口不会被砍；
//   - 窗口 = 目标速率 × RTT × 2 ÷ 送达率；
//   - 送达率按最近 5 秒统计，低于 0.8 就按 0.8 算，
//     也就是丢包超过 20% 不再继续加码，最多补到 1.25 倍。
//
// 速率来自配置的 up_mbps（见 bandwidth.go 的协商），不是写死的常数。
// 按实际线路填：千兆线填 1000，300M 线填 300。填大了会按那个速率往外打，
// 链路撑不住时丢包全集中在瓶颈队列上。
//
// 不要用 max_cwnd ÷ RTT 来换算：8MB ÷ 80ms = 1.05e8 字节/秒 ≈ 839 Mbps，
// 比千兆少一截。之前把这个数误写成 100 Mbps，是把字节当成了比特。

import (
	"sync"
	"sync/atomic"
	"time"

	quicgo "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
	hycongestion "github.com/sagernet/sing-quic/hysteria/congestion"
)

// defaultBrutalRate 是没配带宽时的目标速率：1 Gbps，单位字节/秒。
//
// 1 Gbps = 125_000_000 字节/秒。窗口仍按实测 RTT 算
// （窗口 = 速率 × RTT × 2 ÷ 送达率），所以 RTT 变了不用改这个数。
const defaultBrutalRate uint64 = 1_000_000_000 / 8

// brutalSender 给 Brutal 补上统计用的计数。
//
// 内嵌的 BrutalSender 不暴露丢包数、在途字节和当前速率，
// 而路径统计日志需要它们。计数放在外层，不改依赖里的实现。
type brutalSender struct {
	*hycongestion.BrutalSender
	bps          uint64
	lostPackets  atomic.Uint64
	lastInFlight atomic.Uint64
}

// newBrutalSender 用目标速率（字节/秒）构造控制器。
func newBrutalSender(bps uint64, initialPacketSize congestion.ByteCount) *brutalSender {
	return &brutalSender{
		BrutalSender: hycongestion.NewBrutalSender(bps, initialPacketSize, false, nil),
		bps:          bps,
	}
}

// rate 返回这条连接当前的发送速率（字节/秒）。
func (b *brutalSender) rate() uint64 { return b.bps }

// OnCongestionEventEx 先记丢包，再交给 Brutal 更新送达率。
func (b *brutalSender) OnCongestionEventEx(
	priorInFlight congestion.ByteCount,
	eventTime monotime.Time,
	ackedPackets []congestion.AckedPacketInfo,
	lostPackets []congestion.LostPacketInfo,
) {
	if len(lostPackets) > 0 {
		b.lostPackets.Add(uint64(len(lostPackets)))
	}
	b.BrutalSender.OnCongestionEventEx(priorInFlight, eventTime, ackedPackets, lostPackets)
}

// CanSend 记录在途字节，供统计日志使用。判断本身交给 Brutal。
func (b *brutalSender) CanSend(bytesInFlight congestion.ByteCount) bool {
	b.lastInFlight.Store(uint64(bytesInFlight))
	return b.BrutalSender.CanSend(bytesInFlight)
}

// brutalController 管一组连接的 Brutal 控制器和统计日志。
//
// 它不做窗口自适应。Brutal 的窗口由速率和送达率决定，
// 再按丢包去缩窗口会把它变回 BBR 的行为。
type brutalController struct {
	// bps 是目标速率（字节/秒），由 max_cwnd 换算，运行中不变。
	bps uint64

	mu     sync.Mutex
	conns  map[*quicgo.Conn]*brutalEntry
	closed bool
	stop   chan struct{}

	onStats func(PathStats)
}

// brutalEntry 是一条连接和它的控制器。
type brutalEntry struct {
	conn *quicgo.Conn
	cc   *brutalSender

	// prevSent / prevLost 是该连接上一次采样时的累计值，
	// 用于算它**自己**在本周期的丢包率（理由见 connEntry 同名字段）。
	prevSent uint64
	prevLost uint64
}

// newBrutalController 创建并启动统计循环。
//
// bps 是目标速率（字节/秒）。0 用默认 1 Gbps。
func newBrutalController(bps uint64, onStats func(PathStats)) *brutalController {
	if bps == 0 {
		bps = defaultBrutalRate
	}
	c := &brutalController{
		bps:     bps,
		conns:   make(map[*quicgo.Conn]*brutalEntry),
		stop:    make(chan struct{}),
		onStats: onStats,
	}
	go c.loop()
	return c
}

// Attach 给新连接装上 Brutal，速率用本端 up。
//
// 协商完成前先按本端 up 发。QUIC 握手的那几包不走这条流控，
// 真正的数据要等带宽帧谈完、SetRate 把速率换成 min(本端 up, 对端 down)。
func (c *brutalController) Attach(conn *quicgo.Conn) {
	c.attachAt(conn, c.bps)
}

// SetRate 把一条连接的发送速率换成协商结果。
//
// BrutalSender 的速率是构造时写死的，没有修改入口
// （hysteria2 也是谈完之后才 NewBrutalSender 一次）。
// 这里重新装一个：QUIC 握手那几包已经发完，重装丢的只是还没开始的统计。
func (c *brutalController) SetRate(conn *quicgo.Conn, bps uint64) {
	if bps == 0 {
		bps = c.bps
	}
	c.mu.Lock()
	_, ok := c.conns[conn]
	closed := c.closed
	c.mu.Unlock()
	if closed || !ok {
		return
	}
	cc := newBrutalSender(bps, conn.InitialPacketSize())
	conn.SetCongestionControl(cc)
	c.mu.Lock()
	if e := c.conns[conn]; e != nil {
		e.cc = cc
	}
	c.mu.Unlock()
}

// attachAt 以指定速率装上 Brutal 并记入统计。
func (c *brutalController) attachAt(conn *quicgo.Conn, bps uint64) {
	if bps == 0 {
		bps = c.bps
	}
	cc := newBrutalSender(bps, conn.InitialPacketSize())
	conn.SetCongestionControl(cc)

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.conns[conn] = &brutalEntry{conn: conn, cc: cc}
	c.mu.Unlock()
}

// Detach 在连接关闭后移除，避免统计循环去读已销毁的连接。
func (c *brutalController) Detach(conn *quicgo.Conn) {
	c.mu.Lock()
	delete(c.conns, conn)
	c.mu.Unlock()
}

// Close 停止统计循环。
func (c *brutalController) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.conns = nil
	close(c.stop)
	c.mu.Unlock()
}

// loop 每 2 秒上报一次路径统计。
//
// 只上报，不调整任何东西。丢包率按「本周期新增丢包 ÷ 新增发送」算，
// 和原来的日志同一口径，方便和换 Brutal 之前的数字对比。
func (c *brutalController) loop() {
	ticker := time.NewTicker(statsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
		}

		c.mu.Lock()
		entries := make([]*brutalEntry, 0, len(c.conns))
		for _, e := range c.conns {
			entries = append(entries, e)
		}
		c.mu.Unlock()

		// 没有活跃连接就什么都不用做：每条连接各自记基线，
		// 不再需要维护全局基线（也就没有「断开期间当成一次采样」
		// 把窗口放大那个问题了）。
		if len(entries) == 0 || c.onStats == nil {
			continue
		}

		for _, e := range entries {
			s := e.conn.ConnectionStats()

			// 本连接自己的周期增量（不打印全局聚合值，否则同一次采样的
			// 所有连接会显示同一个丢包率，见 connEntry 的注释）。
			sent := s.PacketsSent
			lost := e.cc.lostPackets.Load()
			var dSent, dLost uint64
			if sent > e.prevSent {
				dSent = sent - e.prevSent
			}
			if lost > e.prevLost {
				dLost = lost - e.prevLost
			}
			e.prevSent, e.prevLost = sent, lost

			loss := 0.0
			if dSent > 0 {
				loss = float64(dLost) / float64(dSent)
			}

			c.onStats(PathStats{
				Remote:      e.conn.RemoteAddr().String(),
				RTT:         s.LatestRTT,
				SmoothedRTT: s.SmoothedRTT,
				MinRTT:      s.MinRTT,
				SentPackets: sent,
				LostPackets: lost,
				LossPct:     uint64(loss * 100),
				// WinCap 在 Brutal 下表示这条连接当前的发送速率（字节/秒）。
				// 协商之后它是 min(本端 up, 对端 down)，不再是配置原值。
				WinCap:   e.cc.rate(),
				Cwnd:     uint64(e.cc.GetCongestionWindow()),
				InFlight: e.cc.lastInFlight.Load(),
				Conns:    len(entries),
			})
		}
	}
}
