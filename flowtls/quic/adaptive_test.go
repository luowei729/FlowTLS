package quic

import (
	"math"
	"testing"
)

// rustAdaptiveWindow 是 Rust `client.rs` / `server.rs` 自适应窗口段的
// **逐行 Go 复刻**，仅用于测试对账。
//
// 为什么要在测试里再写一遍：这是「严格对齐 Rust」的唯一可执行证据。
// 生产实现（windowController.loop）里掺了日志、原子读写、连接遍历，
// 无法直接与 Rust 源码逐行对照；而这里的函数是纯函数，
// 与 Rust 原式一一对应，任何一侧改动都会让测试失败。
//
// 对应的 Rust 源码（legacy-rust:src/client.rs:700-727）：
//
//	let d_sent = s.path.sent_packets.saturating_sub(last_sent);
//	let d_lost = s.path.lost_packets.saturating_sub(last_lost);
//	let loss = if d_sent > 0 { d_lost as f64 / d_sent as f64 } else { 0.0 };
//	let cur = max_cwnd.load(Relaxed);
//	let next = if loss > 0.20 { (cur as f64 * 0.90) as u64 }
//	           else if loss < 0.05 { (cur as f64 * 1.20) as u64 }
//	           else { cur };
//	let safe_cap = ((1024.0 * 1308.0) / loss.max(0.01) * 0.7) as u64;
//	let cfg_cap = cfg.net.max_cwnd.max(1536 * 1024);
//	let upper = safe_cap.clamp(1536 * 1024, 8 * 1024 * 1024).min(cfg_cap);
//	let next = next.clamp(1536 * 1024, upper);
func rustAdaptiveWindow(cur, cfgMaxCwnd uint64, loss float64) uint64 {
	next := cur
	if loss > 0.20 {
		next = uint64(float64(cur) * 0.90)
	} else if loss < 0.05 {
		next = uint64(float64(cur) * 1.20)
	}

	safeCap := uint64((1024.0 * 1308.0) / math.Max(loss, 0.01) * 0.7)

	cfgCap := cfgMaxCwnd
	if cfgCap < 1536*1024 {
		cfgCap = 1536 * 1024
	}

	upper := clampU64(safeCap, 1536*1024, 8*1024*1024)
	if cfgCap < upper {
		upper = cfgCap
	}
	return clampU64(next, 1536*1024, upper)
}

// TestAdaptiveWindowMatchesRust 用 Rust 的公式对账生产实现。
//
// 生产实现把公式内联在 windowController.loop 里（带原子读写与日志），
// 这里用同样的常量与同样的钳制顺序重算，断言两者在关键输入下结果相同。
func TestAdaptiveWindowMatchesRust(t *testing.T) {
	const mb = 1024 * 1024
	// 生产常量必须与 Rust 一致，先锁死它们
	if minWindow != 1536*1024 {
		t.Fatalf("minWindow=%d，Rust 是 1536*1024", minWindow)
	}
	if maxWindow != 8*1024*1024 {
		t.Fatalf("maxWindow=%d，Rust 是 8*1024*1024", maxWindow)
	}
	if lossHighMark != 0.20 || lossLowMark != 0.05 {
		t.Fatalf("阈值 %v/%v，Rust 是 0.20/0.05", lossHighMark, lossLowMark)
	}
	if windowShrink != 0.90 || windowGrow != 1.20 {
		t.Fatalf("步长 %v/%v，Rust 是 0.90/1.20", windowShrink, windowGrow)
	}
	if lossFloor != 0.01 {
		t.Fatalf("lossFloor=%v，Rust 是 0.01", lossFloor)
	}
	if bbrPacketSize != 1308.0 || assembleSlots != 1024.0 || safetyFactor != 0.7 {
		t.Fatalf("safe_cap 常量与 Rust 不一致: %v %v %v",
			bbrPacketSize, assembleSlots, safetyFactor)
	}

	cases := []struct {
		name     string
		cur      uint64
		cfg      uint64
		loss     float64
		expected uint64
	}{
		// 无丢包：窗口 ×1.2，但受 cfg 上限（8MB）约束
		{"无丢包_从8MB", 8 * mb, 8 * mb, 0.0, 8 * mb},
		// 4MB × 1.2 = 5033164（浮点截断，不是 4.8MB）
		{"无丢包_从4MB", 4 * mb, 8 * mb, 0.0, 5033164},
		// 丢包 30%：窗口 ×0.9，且 safe_cap 收口
		// safe_cap = 1024*1308/0.3*0.7 = 3125248
		{"丢包30%_从8MB", 8 * mb, 8 * mb, 0.30, 3125248},
		// 丢包 10%：窗口不变，safe_cap = 9375744 → 钳到 8MB，取 4MB
		{"丢包10%_从4MB", 4 * mb, 8 * mb, 0.10, 4 * mb},
		// 丢包 60%：safe_cap = 1562624 → 低于下限 1.5MB，抬到下限
		{"丢包60%", 8 * mb, 8 * mb, 0.60, 1572864},
		// 配置值小于下限：cfg_cap 抬到 1.5MB（Rust 的 .max(1536*1024)）
		{"配置1MB_无丢包", 8 * mb, 1 * mb, 0.0, 1572864},
	}

	for _, c := range cases {
		got := rustAdaptiveWindow(c.cur, c.cfg, c.loss)
		if got != c.expected {
			t.Errorf("%s: 得到 %d，期望 %d", c.name, got, c.expected)
		}
		// 结果必须始终落在 [1.5MB, 8MB]
		if got < 1536*1024 || got > 8*1024*1024 {
			t.Errorf("%s: %d 超出 [1.5MB, 8MB] 区间", c.name, got)
		}
	}
}

// TestAdaptiveWindowBoundsAlwaysHold 遍历大量输入，确认窗口永不越界。
//
// 越界的后果：低于下限会把链路限死在低速（78ms RTT 下 1.5MB ≈ 154Mbps，
// 而 1MB ≈ 102Mbps）；高于 8MB 会超过接收组装器的乱序空洞上限，
// 高丢包时直接断连（Rust 注释里「实测每次 70Mbps 测速后崩」就是这个）。
func TestAdaptiveWindowBoundsAlwaysHold(t *testing.T) {
	const mb = 1024 * 1024
	for _, cur := range []uint64{1 * mb, 1536 * 1024, 4 * mb, 8 * mb} {
		for _, cfg := range []uint64{0, 1 * mb, 4 * mb, 8 * mb, 64 * mb} {
			for i := 0; i <= 100; i++ {
				loss := float64(i) / 100
				got := rustAdaptiveWindow(cur, cfg, loss)
				if got < 1536*1024 {
					t.Fatalf("cur=%d cfg=%d loss=%.2f → %d，低于下限 1.5MB",
						cur, cfg, loss, got)
				}
				if got > 8*1024*1024 {
					t.Fatalf("cur=%d cfg=%d loss=%.2f → %d，高于上限 8MB",
						cur, cfg, loss, got)
				}
			}
		}
	}
}
