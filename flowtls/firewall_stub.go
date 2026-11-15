//go:build !windows || (!amd64 && !386)

package flowtls

// 非 Windows 平台上的空实现。
//
// Linux 的入站端口不受这套机制管辖（iptables 规则由 rules.go 处理，且只针对
// 伪包分流，不涉及放行代理端口）；macOS / FreeBSD 本来就跑不起来
// （见 socket_stub.go）。保留同名函数只为让调用点不必加 build tag。
//
// 参数与返回值必须与 firewall_windows.go 逐字对齐，否则跨平台编译会失败——
// `make platforms` 会拦住这类错误（DEVTIPS 第 135 条）。
func EnsureInboundFirewallRule(logger Logger) error { return nil }
