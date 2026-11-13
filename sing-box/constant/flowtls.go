// Modified by FlowTLS (2026-11-13): 协议类型与错误常量。
//
// 刻意放在**独立新文件**而不是塞进 constant/proxy.go、constant/err.go：
// 新增文件在 `git subtree pull` 时永不冲突，
// 上游改动这两个文件也不会波及我们。
package constant

import E "github.com/sagernet/sing/common/exceptions"

// TypeFlowTLS 是 flowtls 协议的 type 字符串。
// 与 TypeAnyTLS / TypeHysteria2 同级，用于 inbound/outbound 的 "type" 字段。
const TypeFlowTLS = "flowtls"

// ErrFlowTLSNotIncluded 在未开 with_flowtls 构建时返回。
//
// 未编入时也必须注册 stub，否则配置里写 flowtls 只会得到
// "unknown inbound type"，看不出是「没开 build tag」还是「type 拼错了」。
var ErrFlowTLSNotIncluded = E.New(`flowtls is not included in this build, rebuild with -tags with_flowtls`)

// ErrFlowTLSNotImplemented 标记 P0 骨架阶段：已注册但传输层还没落地。
// P2/P4 完成后应删除。
var ErrFlowTLSNotImplemented = E.New(`flowtls is registered but the transport layer is not implemented yet`)

var ErrFlowTLSRequirePassword = E.New("flowtls: password is required")
