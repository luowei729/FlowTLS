//go:build !with_flowtls

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// Modified by FlowTLS: 未编入 flowtls 时注册 stub（2026-11-13）。
//
// 为什么不是「干脆不注册」：
// 不注册的话，配置里写 type=flowtls 会得到 "unknown inbound type"，
// 用户分不清是「构建没开 tag」还是「type 拼错了」。
// 注册 stub 后错误信息直接告诉你 rebuild with -tags with_flowtls。

func registerFlowTLSInbounds(registry *inbound.Registry) {
	inbound.Register[option.FlowTLSInboundOptions](registry, C.TypeFlowTLS, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.FlowTLSInboundOptions) (adapter.Inbound, error) {
		return nil, C.ErrFlowTLSNotIncluded
	})
}

func registerFlowTLSOutbounds(registry *outbound.Registry) {
	outbound.Register[option.FlowTLSOutboundOptions](registry, C.TypeFlowTLS, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.FlowTLSOutboundOptions) (adapter.Outbound, error) {
		return nil, C.ErrFlowTLSNotIncluded
	})
}
