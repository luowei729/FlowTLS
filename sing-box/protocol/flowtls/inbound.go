package flowtls

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// RegisterInbound 把 flowtls 入站注册进 registry。
// 与 anytls/hysteria2 完全同一形状，新增协议不需要改 registry 本体。
func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.FlowTLSInboundOptions](registry, C.TypeFlowTLS, NewInbound)
}

// NewInbound 在 P0 阶段只做参数校验，真正的监听留到 P4。
//
// 刻意**不在这里**创建 raw socket：
// `sing-box check` 会完整走一遍 box.New() 再 Close()，
// 构造函数里开 raw socket 会让 check 也要求 root，体验直接崩。
// 所有需要权限的动作必须放在 Start(StartStateStart) 里。
func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.FlowTLSInboundOptions) (adapter.Inbound, error) {
	_ = ctx
	_ = router
	_ = logger
	_ = tag
	_ = options
	if options.Password == "" && len(options.Users) == 0 {
		return nil, C.ErrFlowTLSRequirePassword
	}
	return nil, C.ErrFlowTLSNotImplemented
}
