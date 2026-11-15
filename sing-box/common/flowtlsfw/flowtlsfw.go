//go:build with_flowtls

package flowtlsfw

import (
	"github.com/sagernet/sing-box/log"

	ftcore "github.com/luowei729/flowtls"
)

// Modified by FlowTLS: Windows 入站端口的防火墙放行（2026-11-15）。
//
// # 为什么单独一个包
//
// 逻辑本身属于 flowtls，但调用点在根包 box.go 的 start() 里。`include` 包看着
// 像自然的归属，实际不行——`include/registry.go` 反过来 import 了根包，从
// box.go 引 include 会构成 import cycle（编译器会直接拒绝）。
//
// 放到 common/ 下的独立小包就没有这个问题：它只依赖 flowtls core 和 log，
// 两边都不依赖根包。
//
// # 为什么需要放行
//
// `flowtls/rules_windows.go` 里「Windows 不需要任何防火墙规则」那句只对
// **伪包分流**成立——WinDivert 挂在 WFP 入站 IP 包层，子层权重最高，位于
// 防火墙过滤之前，所以伪 SYN / SYN-ACK 的收发完全不受防火墙影响。
//
// 但 **inbound 是真正的内核 TCP socket**（`0.0.0.0:1080`），防火墙对它一视同仁：
// 从局域网连进来会被静默丢弃。而手机、电视、另一台电脑共享代理正是最常见的
// 用法，所以必须放行。
//
// # 为什么能自动做而不用弹窗
//
// 加载 WinDivert 驱动本来就要求管理员权限，也就是说本程序一定以管理员在跑，
// 有权限直接写防火墙规则。只要规则在任何 listen() 之前就存在，Windows 连
// 「是否允许此应用访问网络」的弹窗都不会再弹——用户什么都不用点。
//
// # 覆盖范围
//
// 域 / 专用 / 公用全覆盖。覆盖「公用」是刻意取舍：用户换到酒店、咖啡馆这类被
// 判为公用网络的 Wi-Fi 时局域网共享仍然可用，不必重新配置。代价是代理端口在
// 不信任网络上也可达，防线是 inbound 的 `users` 口令，**部署不要留默认口令**。
//
// 失败不致命：伪包隧道不依赖这条规则，只打一条告警。
func EnsureWindowsInboundAllowed(logger log.ContextLogger) {
	if logger == nil {
		return
	}
	if err := ftcore.EnsureInboundFirewallRule(logger); err != nil {
		logger.Warn("Windows 防火墙放行失败（隧道本身不受影响，但局域网访问可能被拦）: ", err)
	}
}
