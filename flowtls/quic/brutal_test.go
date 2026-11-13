package quic

import (
	"testing"
	"time"

	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
)

// fakeRTT 是固定 RTT 的 RTTStatsProvider，用于确定性测试。
type fakeRTT struct{ srtt time.Duration }

func (f fakeRTT) MinRTT() time.Duration                  { return f.srtt }
func (f fakeRTT) LatestRTT() time.Duration               { return f.srtt }
func (f fakeRTT) SmoothedRTT() time.Duration             { return f.srtt }
func (f fakeRTT) MeanDeviation() time.Duration           { return 0 }
func (f fakeRTT) MaxAckDelay() time.Duration             { return 0 }
func (f fakeRTT) PTO(bool) time.Duration                 { return f.srtt }
func (f fakeRTT) UpdateRTT(time.Duration, time.Duration) {}
func (f fakeRTT) SetMaxAckDelay(time.Duration)           {}
func (f fakeRTT) SetInitialRTT(time.Duration)            {}

// TestBrutalPacingAllowsConfiguredRate 验证 Brutal 的 pacing 能放出配置的带宽。
//
// **这是本轮排查的关键测试**。现象：配 800Mbps，实际只有 25Mbps。
// 如果 pacing 逻辑有 bug（例如令牌桶算错、时间基准错），
// 它就会把发送速率压到远低于配置值，而**任何功能测试都发现不了**——
// 连接是通的、数据是对的，只是慢。
//
// 验证方式：模拟连续发送，统计「一秒内允许发出多少字节」，
// 断言它接近配置值（允许 20% 误差，因为令牌桶有突发上限）。
func TestBrutalPacingAllowsConfiguredRate(t *testing.T) {
	const mbps = 800
	bps := uint64(mbps) * 1_000_000 / 8 // 100 MB/s
	const pktSize = congestion.ByteCount(1332)

	b := newBrutalSender(bps, 2.0, pktSize)
	b.SetRTTStatsProvider(fakeRTT{srtt: 78 * time.Millisecond})

	// cwnd 应该 = bps × rtt × multiplier = 100e6 × 0.078 × 2 = 15.6MB
	cwnd := b.GetCongestionWindow()
	wantCwnd := congestion.ByteCount(float64(bps) * 0.078 * 2)
	if cwnd < wantCwnd*9/10 || cwnd > wantCwnd*11/10 {
		t.Fatalf("cwnd=%d，期望约 %d（bps×rtt×2）", cwnd, wantCwnd)
	}

	// 模拟 1 秒的发送：每步推进 100µs，检查 pacing 是否放行。
	//
	// 注意不能用 time.Now()：monotime 的基准与 wall clock 不同，
	// 必须用 monotime 自己的起点。
	start := monotime.Now()
	sentBytes := congestion.ByteCount(0)
	sentPackets := 0
	step := 100 * time.Microsecond

	for elapsed := time.Duration(0); elapsed < time.Second; elapsed += step {
		now := start.Add(elapsed)
		// 一次时间步内尽量多发（模拟 quic-go 的 sendPackets 循环）
		for i := 0; i < 64; i++ {
			if !b.HasPacingBudget(now) {
				break
			}
			// 模拟「在途字节不超 cwnd」
			if congestion.ByteCount(sentPackets%200)*pktSize >= cwnd {
				break
			}
			b.OnPacketSent(now, 0, congestion.PacketNumber(sentPackets), pktSize, true)
			sentBytes += pktSize
			sentPackets++
		}
	}

	gotMbps := float64(sentBytes) * 8 / 1e6
	t.Logf("1 秒内 pacing 放行 %d 字节 = %.1f Mbps（配置 %d Mbps，%d 包）",
		sentBytes, gotMbps, mbps, sentPackets)

	// 允许 30% 误差：令牌桶有突发上限，且我们的时间步是 100µs 粒度。
	if gotMbps < float64(mbps)*0.7 {
		t.Fatalf("pacing 只放出 %.1f Mbps，配置 %d Mbps——"+
			"令牌桶或时间基准有 bug，这会把吞吐锁死在低速",
			gotMbps, mbps)
	}
}

// TestBrutalNeverShrinksOnLoss 验证 Brutal 的核心语义：**丢包不减窗**。
func TestBrutalNeverShrinksOnLoss(t *testing.T) {
	bps := uint64(100) * 1_000_000 / 8
	const pktSize = congestion.ByteCount(1332)
	b := newBrutalSender(bps, 2.0, pktSize)
	b.SetRTTStatsProvider(fakeRTT{srtt: 78 * time.Millisecond})

	before := b.GetCongestionWindow()

	// 模拟大量丢包（50% 丢包，远超任何拥塞响应式算法的容忍度）
	now := monotime.Now()
	lost := make([]congestion.LostPacketInfo, 50)
	for i := 0; i < 20; i++ {
		b.OnCongestionEventEx(0, now.Add(time.Duration(i)*time.Second), nil, lost)
	}

	after := b.GetCongestionWindow()
	// ackRate 会被钳到 0.8，所以窗口最多放大 1.25 倍
	if after < before {
		t.Fatalf("丢包后窗口从 %d 缩到 %d——Brutal 不应减窗", before, after)
	}
	if after > before*2 {
		t.Fatalf("窗口放大到 %d（原 %d），ackRate 钳制失效", after, before)
	}
	t.Logf("丢包 50%% 后窗口 %d → %d（未缩减，符合 Brutal 语义）", before, after)
}

// TestBrutalCanSend 验证 CanSend 只看窗口、不看丢包。
func TestBrutalCanSend(t *testing.T) {
	bps := uint64(100) * 1_000_000 / 8
	b := newBrutalSender(bps, 2.0, 1332)
	b.SetRTTStatsProvider(fakeRTT{srtt: 78 * time.Millisecond})
	cwnd := b.GetCongestionWindow()

	if !b.CanSend(0) {
		t.Fatal("空管道应该能发")
	}
	if b.CanSend(cwnd) {
		t.Fatal("在途字节达到 cwnd 时不应能发")
	}
	if b.CanSend(cwnd/2) != true {
		t.Fatal("在途字节为 cwnd 一半时应该能发")
	}
}
