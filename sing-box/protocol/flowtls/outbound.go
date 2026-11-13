package flowtls

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// RegisterOutbound 把 flowtls 出站注册进 registry。
func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.FlowTLSOutboundOptions](registry, C.TypeFlowTLS, NewOutbound)
}

// NewOutbound 在 P0 阶段只做参数校验，真正的 Session 建立留到 P2。
//
// 同样不在构造函数里开 raw socket：check 必须能在无权限环境下跑通。
func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.FlowTLSOutboundOptions) (adapter.Outbound, error) {
	_ = ctx
	_ = router
	_ = logger
	_ = tag
	_ = options
	if options.Password == "" {
		return nil, C.ErrFlowTLSRequirePassword
	}
	return nil, C.ErrFlowTLSNotImplemented
}
