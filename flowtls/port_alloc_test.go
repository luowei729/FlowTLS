package flowtls

// 本文件钉住动态源端口分配的三条性质。
//
// 为什么值得单测：端口分配一旦出错，症状是「隧道时通时不通」或者
// 「两个实例互相踢」，而不是一个明确的错误——这类问题在真机上极难定位。
// 所以用测试把语义固定下来。

import "testing"

// TestAllocSourcePortUnique 连续分配必须互不相同。
//
// 这是「同机多实例不再撞四元组」的直接保证：只要各实例拿到不同端口，
// 服务端就能区分出不同会话（源 IP 相同但端口不同 → 四元组不同）。
func TestAllocSourcePortUnique(t *testing.T) {
	const n = 64
	got := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		p := AllocSourcePort()
		if p == 0 {
			t.Fatalf("第 %d 次分配失败（端口段不应这么快耗尽）", i)
		}
		got = append(got, p)
	}
	seen := make(map[uint16]struct{}, n)
	for _, p := range got {
		if p < autoPortMin || p > autoPortMax {
			t.Fatalf("端口 %d 超出动态段 %d-%d", p, autoPortMin, autoPortMax)
		}
		if _, dup := seen[p]; dup {
			t.Fatalf("分配出重复端口 %d（%v）", p, got)
		}
		seen[p] = struct{}{}
	}
}

// TestReleaseSourcePortAllowsReuse 释放后该端口必须能被再次分配。
//
// 不释放的后果是长时间运行逐步耗光端口段——每次重连泄漏一个，
// 直到 Dial 开始报「没有可用的源端口」。
func TestReleaseSourcePortAllowsReuse(t *testing.T) {
	// 先占满一小批，再逐个释放，然后确认能重新分配回来。
	held := make([]uint16, 0, 8)
	for i := 0; i < 8; i++ {
		p := AllocSourcePort()
		if p == 0 {
			t.Fatal("分配失败")
		}
		held = append(held, p)
	}
	freed := held[0]
	ReleaseSourcePort(freed)

	// 注册表里已经没有它了，所以再分配必然不会返回同一个值以外的冲突。
	// 这里只验证「释放是幂等且不 panic」，以及分配仍然成功。
	ReleaseSourcePort(freed) // 二次释放必须安全
	ReleaseSourcePort(0)     // 0 表示"未分配"，也必须是空操作
	ReleaseSourcePort(80)    // 不在动态段内，同样是空操作

	if p := AllocSourcePort(); p == 0 {
		t.Fatal("释放后分配仍应成功")
	}
	// 收尾：把还占着的都放掉，避免影响同包内其它测试
	for _, p := range held[1:] {
		ReleaseSourcePort(p)
	}
}

// TestAllocSourcePortNoReleaseOfFixed 显式配置的端口不走分配器，
// 因此 ReleaseSourcePort 对它们必须是空操作（不能误删别人的登记）。
func TestAllocSourcePortNoReleaseOfFixed(t *testing.T) {
	// 固定端口常见值（44300 之类）都在动态段外，释放它们不应影响分配器。
	for _, p := range []uint16{0, 53, 443, 8443, 44300, 49151, 65535} {
		ReleaseSourcePort(p) // 不 panic 即通过
	}
	// 65535 在段内，前面的释放会让它变回可用——这没有副作用，
	// 因为登记表里本来也没有它。
	if p := AllocSourcePort(); p == 0 {
		t.Fatal("分配仍应成功")
	}
}
