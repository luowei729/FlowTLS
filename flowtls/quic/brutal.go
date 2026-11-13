// Package quic 的 hy1 风格拥塞控制：Brutal。
//
// 这个文件是 hysteria1 `hysteria/congestion/brutal.go` + `pacer.go` 的
// **逐条对应移植**，注释保留原实现的理由。
//
// ## 为什么需要它
//
// BBR 和 Cubic 都是「拥塞响应式」算法：观测到丢包就降速。
// 但跨境链路的丢包有两类：
//
//  1. **拥塞丢包**：自己的发送速率超过链路容量，该降；
//  2. **随机丢包**：链路本身在丢（跨境常见 20~50%），与速率无关，降速没用。
//
// 算法无法区分这两类。BBR 已经比 Cubic 好很多（用带宽×RTT 建模，
// 不把丢包直接当拥塞信号），但它仍会在丢包时压低发送速率，
// 于是在「链路容量充足但随机丢包高」的场景下永远跑不满。
//
// Brutal 的做法是**放弃判断**：既然用户已经知道自己的带宽是多少，
// 就直接按这个值发，丢包只靠 QUIC 重传兜底，绝不降速。
// 这正是 hy1/hy2 在跨境高丢包链路上吞吐远高于 BBR 的原因。
//
// ## 与 hy1 的差异
//
// 无。参数与公式逐项照抄：
//
//	cwnd       = bps × srtt × multiplier ÷ ackRate
//	pacing 速率 = bps ÷ ackRate
//	ackRate    = 5 秒窗口内的 ack/(ack+loss)，钳在 [0.8, 1.0]
//	丢包回调    = 空实现（只看 ACK 比例，绝不减窗）
package quic

import (
	"time"

	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
)

// Brutal 的常量，与 hy1 完全一致。
const (
	// brutalSlotCount 是 ACK 率采样的槽数。槽索引按秒取模，
	// 所以 5 个槽 = 最近 5 秒的滑动窗口。
	brutalSlotCount = 5
	// brutalMinSampleCount 是启用 ackRate 调整所需的最小样本数。
	// 样本太少时用 1.0（等于「不修正」），避免刚开始就误判。
	brutalMinSampleCount = 50
	// brutalMinAckRate 是 ackRate 的下限。
	//
	// 为什么不允许更低：ackRate 越低，cwnd 和 pacing 速率被放大得越多。
	// 若链路真的丢了 80%，放大 5 倍只会把链路彻底打爆、丢得更多。
	// 0.8 意味着最多放大 1.25 倍。
	brutalMinAckRate = 0.8
	// brutalPacerBurstPackets / brutalPacerBurstDelay 控制令牌桶的突发上限。
	// 突发太大会瞬时打满中间设备队列（丢包），太小则无法跑满带宽。
	brutalPacerBurstPackets = 10
	brutalPacerBurstDelay   = 4
	brutalPacerMinDelay     = time.Millisecond
)

// DefaultBrutalMultiplier 是 cwnd 相对 BDP 的倍数。
//
// hy1 默认 2：cwnd = 2 × BDP，保证链路上始终有足够在途数据填满管道。
// 调大能更激进地抢带宽，但也会在真实拥塞时更容易把链路打爆。
const DefaultBrutalMultiplier = 2.0

// brutalPktInfo 是一个采样槽。
type brutalPktInfo struct {
	// ts 是槽对应的秒级时间戳（Unix 秒）。
	ts        int64
	ackCount  uint64
	lossCount uint64
}

// brutalSender 实现 hy1 的 Brutal 拥塞控制。
//
// 嵌入 `CongestionControlEx` 的全部方法（quic-go 的 Ex 接口），
// 因此可以经 `Conn.SetCongestionControl` 注入。
type brutalSender struct {
	rttStats        congestion.RTTStatsProvider
	bps             congestion.ByteCount
	maxDatagramSize congestion.ByteCount
	multiplier      float64
	pacer           *brutalPacer

	slots   [brutalSlotCount]brutalPktInfo
	ackRate float64
}

var _ congestion.CongestionControlEx = (*brutalSender)(nil)

// newBrutalSender 用给定发送带宽（字节/秒）构造控制器。
//
// initialMaxDatagramSize 必须是 `conn.InitialPacketSize()`：
// quic-go 的注释明确要求注入的控制器用连接的真实初始包大小播种。
func newBrutalSender(bps uint64, multiplier float64,
	initialMaxDatagramSize congestion.ByteCount) *brutalSender {
	if multiplier <= 0 {
		multiplier = DefaultBrutalMultiplier
	}
	b := &brutalSender{
		bps:             congestion.ByteCount(bps),
		maxDatagramSize: initialMaxDatagramSize,
		multiplier:      multiplier,
		ackRate:         1,
	}
	b.pacer = newBrutalPacer(initialMaxDatagramSize, func() congestion.ByteCount {
		// pacing 速率 = bps ÷ ackRate（hy1 原式）。
		// ackRate 是「实际收到的比例」，丢包越多它越小，
		// 于是发送速率被反向放大——这就是「Brutal」名字的来源。
		return congestion.ByteCount(float64(b.bps) / b.ackRate)
	})
	return b
}

func (b *brutalSender) SetRTTStatsProvider(p congestion.RTTStatsProvider) {
	b.rttStats = p
}

func (b *brutalSender) TimeUntilSend(bytesInFlight congestion.ByteCount) monotime.Time {
	return b.pacer.TimeUntilSend()
}

func (b *brutalSender) HasPacingBudget(now monotime.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

// CanSend 只看在途字节是否超过 cwnd，**完全不看丢包**。
func (b *brutalSender) CanSend(bytesInFlight congestion.ByteCount) bool {
	return bytesInFlight < b.GetCongestionWindow()
}

// GetCongestionWindow 返回 cwnd = bps × srtt × multiplier ÷ ackRate。
//
// 这是 Brutal 的核心：窗口完全由「配置带宽 × 实测 RTT」推导，
// 与丢包率无关（丢包只通过 ackRate 反向放大窗口）。
//
// RTT 未知时返回 10240（hy1 原值）：此时是连接刚建立，
// 任何小窗口都能起步，等第一个 RTT 样本到达就会切到正常公式。
func (b *brutalSender) GetCongestionWindow() congestion.ByteCount {
	if b.rttStats == nil {
		return 10240
	}
	rtt := b.rttStats.SmoothedRTT()
	if rtt <= 0 {
		return 10240
	}
	return congestion.ByteCount(float64(b.bps) * rtt.Seconds() * b.multiplier / b.ackRate)
}

func (b *brutalSender) OnPacketSent(sentTime monotime.Time, bytesInFlight congestion.ByteCount,
	packetNumber congestion.PacketNumber, bytes congestion.ByteCount, isRetransmittable bool) {
	b.pacer.SentPacket(sentTime, bytes)
}

// OnPacketAcked 是空实现：Brutal 不靠 ACK 调窗口。
func (b *brutalSender) OnPacketAcked(number congestion.PacketNumber, ackedBytes congestion.ByteCount,
	priorInFlight congestion.ByteCount, eventTime monotime.Time) {
}

// OnCongestionEvent 是空实现：**丢包绝不减窗**，这是 Brutal 与所有
// 拥塞响应式算法的根本区别。丢包交给 QUIC 重传兜底。
func (b *brutalSender) OnCongestionEvent(number congestion.PacketNumber, lostBytes congestion.ByteCount,
	priorInFlight congestion.ByteCount) {
}

// OnCongestionEventEx 只更新 ACK 率采样，不碰窗口。
//
// ackRate 的作用：如果链路真实丢包率很高，说明实际吞吐达不到配置值，
// 于是把 pacing 速率按比例放大（bps ÷ ackRate），补偿被丢掉的那部分，
// 让「到达对端的有效速率」尽量接近配置值。
func (b *brutalSender) OnCongestionEventEx(priorInFlight congestion.ByteCount,
	eventTime monotime.Time, ackedPackets []congestion.AckedPacketInfo,
	lostPackets []congestion.LostPacketInfo) {
	nowSec := int64(time.Duration(eventTime) / time.Second)
	slot := nowSec % brutalSlotCount
	if slot < 0 {
		slot += brutalSlotCount
	}
	if b.slots[slot].ts == nowSec {
		b.slots[slot].ackCount += uint64(len(ackedPackets))
		b.slots[slot].lossCount += uint64(len(lostPackets))
	} else {
		// 未初始化或已过期：重置该槽
		b.slots[slot].ts = nowSec
		b.slots[slot].ackCount = uint64(len(ackedPackets))
		b.slots[slot].lossCount = uint64(len(lostPackets))
	}
	b.updateAckRate(nowSec)
}

// updateAckRate 汇总最近 5 秒的 ACK 率并钳在 [0.8, 1.0]。
func (b *brutalSender) updateAckRate(nowSec int64) {
	minTS := nowSec - brutalSlotCount
	var ack, loss uint64
	for _, info := range b.slots {
		if info.ts < minTS {
			continue
		}
		ack += info.ackCount
		loss += info.lossCount
	}
	if ack+loss < brutalMinSampleCount {
		b.ackRate = 1
		return
	}
	rate := float64(ack) / float64(ack+loss)
	if rate < brutalMinAckRate {
		b.ackRate = brutalMinAckRate
		return
	}
	b.ackRate = rate
}

func (b *brutalSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	// 空实现：超时也不减窗（同 hy1）
}

func (b *brutalSender) SetMaxDatagramSize(size congestion.ByteCount) {
	b.maxDatagramSize = size
	b.pacer.SetMaxDatagramSize(size)
}

func (b *brutalSender) InSlowStart() bool   { return false }
func (b *brutalSender) InRecovery() bool    { return false }
func (b *brutalSender) MaybeExitSlowStart() {}

func (b *brutalSender) OnPacketNeutered(packetNumber congestion.PacketNumber) {}
func (b *brutalSender) OnPacketsLost(leastUnacked congestion.PacketNumber)    {}
func (b *brutalSender) OnAppLimited(bytesInFlight congestion.ByteCount)       {}

// brutalPacer 是令牌桶 pacing 器，与 hy1 的 pacer.go 逐行对应。
//
// 为什么必须有 pacing：Brutal 的 cwnd 可能很大（bps × rtt × 2），
// 若一次把 cwnd 全压出去，会瞬时打满中间设备队列造成大量丢包。
// pacing 把发送均匀摊到时间轴上，是 Brutal 能工作的前提。
type brutalPacer struct {
	budgetAtLastSent congestion.ByteCount
	maxDatagramSize  congestion.ByteCount
	lastSentTime     monotime.Time
	getBandwidth     func() congestion.ByteCount
}

func newBrutalPacer(initialMaxDatagramSize congestion.ByteCount,
	getBandwidth func() congestion.ByteCount) *brutalPacer {
	return &brutalPacer{
		budgetAtLastSent: brutalPacerBurstPackets * initialMaxDatagramSize,
		maxDatagramSize:  initialMaxDatagramSize,
		getBandwidth:     getBandwidth,
	}
}

func (p *brutalPacer) SentPacket(sendTime monotime.Time, size congestion.ByteCount) {
	budget := p.Budget(sendTime)
	if size > budget {
		p.budgetAtLastSent = 0
	} else {
		p.budgetAtLastSent = budget - size
	}
	p.lastSentTime = sendTime
}

// Budget 返回当前可发送的字节额度（令牌桶累积）。
func (p *brutalPacer) Budget(now monotime.Time) congestion.ByteCount {
	if p.lastSentTime.IsZero() {
		return p.maxBurstSize()
	}
	budget := p.budgetAtLastSent +
		(p.getBandwidth()*congestion.ByteCount(now.Sub(p.lastSentTime).Nanoseconds()))/1e9
	if budget < 0 {
		// 溢出保护
		budget = congestion.ByteCount(1<<62 - 1)
	}
	return minByteCount(p.maxBurstSize(), budget)
}

// maxBurstSize 是一次性最多能攒多少额度。
//
// 取「4ms 内的带宽量」与「10 个包」的较大者：
// 前者保证低速率时也能攒够一个包，后者保证高速率时不会攒出巨大突发。
func (p *brutalPacer) maxBurstSize() congestion.ByteCount {
	return maxByteCount(
		congestion.ByteCount((brutalPacerBurstDelay*brutalPacerMinDelay).Nanoseconds())*
			p.getBandwidth()/1e9,
		brutalPacerBurstPackets*p.maxDatagramSize,
	)
}

// TimeUntilSend 返回下次可发送的时刻（零值表示立即可发）。
func (p *brutalPacer) TimeUntilSend() monotime.Time {
	if p.budgetAtLastSent >= p.maxDatagramSize {
		return monotime.Time(0)
	}
	diff := 1e9 * uint64(p.maxDatagramSize-p.budgetAtLastSent)
	bw := uint64(p.getBandwidth())
	if bw == 0 {
		return monotime.Time(0)
	}
	// 向上取整：否则定时器到期时额度可能刚好差一个字节，白等一轮
	d := diff / bw
	if diff%bw > 0 {
		d++
	}
	return p.lastSentTime.Add(maxDuration(congestion.MinPacingDelay, time.Duration(d)*time.Nanosecond))
}

func (p *brutalPacer) SetMaxDatagramSize(s congestion.ByteCount) {
	p.maxDatagramSize = s
}

func maxByteCount(a, b congestion.ByteCount) congestion.ByteCount {
	if a < b {
		return b
	}
	return a
}

func minByteCount(a, b congestion.ByteCount) congestion.ByteCount {
	if a < b {
		return a
	}
	return b
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
