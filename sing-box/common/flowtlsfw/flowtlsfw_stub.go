//go:build !with_flowtls

package flowtlsfw

import "github.com/sagernet/sing-box/log"

// Modified by FlowTLS: 未编入 flowtls 时的空实现（2026-11-15）。
//
// 函数名与签名必须与 flowtlsfw.go（with_flowtls）逐字一致：根包 box.go 会
// 无条件调用它，缺了这个函数，不带 with_flowtls 的构建（纯上游 sing-box）
// 就会编译失败。
//
// 不编 flowtls 时没必要碰防火墙：没有 flowtls inbound，用户跑的是原版
// sing-box 的行为，不该被我们擅自改防火墙策略。
func EnsureWindowsInboundAllowed(logger log.ContextLogger) {}
