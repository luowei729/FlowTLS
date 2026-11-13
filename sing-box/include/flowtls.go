//go:build with_flowtls

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/flowtls"
)

// Modified by FlowTLS: with_flowtls 构建时注册真实协议（2026-11-13）。
//
// 与 include/quic.go 同一形状：把可选协议的注册收敛到一个函数，
// registry.go 里只留一行调用，上游改动这个文件时冲突范围可控。

func registerFlowTLSInbounds(registry *inbound.Registry) {
	flowtls.RegisterInbound(registry)
}

func registerFlowTLSOutbounds(registry *outbound.Registry) {
	flowtls.RegisterOutbound(registry)
}
