package flowtls

import (
	"fmt"
	"strings"
)

// splitLines 把多行文本拆成非空行。
//
// 规则报告（print 模式）是多行文本，必须逐行交给 logger，
// 否则除第一行外都会丢掉时间戳与级别前缀。
func splitLines(s string) []string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// maxCwndOf 把配置里的 int64 窗口上限归一成 uint64。
//
// 为什么需要这个函数而不是直接 `uint64(x)`：
// JSON 里的数字由用户手写，负数是完全可能的输入（比如手滑写成 -1）。
// Go 的 int64 → uint64 转换是位重解释，`uint64(-1)` 会变成
// 18446744073709551615——窗口上限变成 16EB，等于彻底关掉窗口钳制，
// BBR 会把链路打爆，而日志里看不到任何异常。
//
// 语义：<= 0（含负数与「未配置」）一律视为 0，由 quic 包退回
// DefaultMaxCwnd（8MB）。
func maxCwndOf(v int64) uint64 {
	if v <= 0 {
		return 0
	}
	return uint64(v)
}

// bpsOf 把 Mbps 配置值换算成 Brutal 需要的字节/秒。
//
// 为什么用 Mbps 而不是直接写 BPS：
// 用户填的是「我的带宽是 100 兆」，写成 100 比 12500000 不容易错。
// 这里按 1 Mbps = 1e6 bit/s = 125000 字节/秒换算（十进制，与运营商标注一致）。
//
// 语义：<= 0 一律返回 0，表示不启用 Brutal（走 BBR）。
// 同样不能用裸 uint64 转换——负数会变成天文数字，让 Brutal 无限量发包，
// 几秒内就能把链路和自己的 socket 缓冲彻底打爆。
func bpsOf(mbps int64) uint64 {
	if mbps <= 0 {
		return 0
	}
	return uint64(mbps) * 1_000_000 / 8
}

// humanBytes 把字节数格式化成人类可读的形式，只用于日志。
//
// 为什么需要：窗口值在 1.5MB~8MB 之间浮动，日志里直接写
// 1572864 这种数字要靠心算才能比较，读日志的人看不出变化。
func humanBytes(v uint64) string {
	switch {
	case v >= 1024*1024:
		return fmt.Sprintf("%.2fMB", float64(v)/(1024*1024))
	case v >= 1024:
		return fmt.Sprintf("%.1fKB", float64(v)/1024)
	default:
		return fmt.Sprintf("%dB", v)
	}
}
