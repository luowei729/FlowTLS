//go:build windows && (amd64 || 386)

package flowtls

// Windows 上**不需要任何防火墙规则**，这是 WinDivert 与 AF_PACKET 的语义
// 差异带来的直接好处。本文件只做两件事：关掉 iptables 后端、提供日志文案。
//
// # Linux 为什么需要规则
//
// AF_PACKET 是内核对报文的**被动复制**：内核仍然会处理同一份伪包，
// 发现「没有对应 socket」就回 RST。RST 是协议合法的终止信号，
// 中间设备看到就拆 NAT 映射，隧道断掉。所以必须用 iptables：
//
//	服务端 raw/PREROUTING u32 DROP：让内核看不到伪包（AF_PACKET 照旧收到）
//	客户端 OUTPUT DROP RST：屏蔽内核对伪连接的回包
//
// # Windows 为什么不需要
//
// WinDivert 是**扣留**语义：匹配过滤器的包被驱动摘走，内核**从未看到**它们。
// 于是：
//
//	服务端：伪 SYN 被扣留 → 内核不会回 SYN-ACK/RST
//	客户端：服务端的 SYN-ACK 被扣留 → 内核不会回 RST
//	伪装站：真实浏览器的包不匹配过滤器 → 直接走内核 TCP 栈，完全不受干扰
//
// 换句话说，Linux 上需要「DROP 规则 + 旁路收包」两个机制配合才能做到的事，
// Windows 上一个过滤器就同时完成了。

// init 关掉 iptables 后端。
//
// 用 init 而不是在 Ensure* 里写 `runtime.GOOS == "windows"`，是因为后者会让
// 平台判断散落在业务代码里；放这里能一眼看出「Windows 关掉了什么、为什么」。
func init() {
	rulesBackendEnabled = false
}

// 说明：这里**不提供**规则文案函数。
//
// 适配层统一在启动日志里打 `SendMode()`（inbound.go / outbound.go），
// Windows 侧那句话已包含「无需 iptables 规则」的提示，再单独写一个
// 规则描述函数只会变成死代码。
