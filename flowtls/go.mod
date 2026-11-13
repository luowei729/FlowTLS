// FlowTLS 传输层独立模块。
//
// 设计边界（与 sagernet/sing-quic、sagernet/sing-anytls 完全一致）：
//   - 本模块**不 import sing-box**，只依赖 sagernet/sing 的通用网络类型；
//   - 因此它可以被任何 Go 项目复用，sing-box 只是其中一个消费者；
//   - 协议适配（adapter.Inbound / adapter.Outbound）放在 sing-box 侧，
//     本模块只提供 net.PacketConn 与连接管理。
module github.com/luowei729/flowtls

go 1.25.5

require github.com/sagernet/sing v0.9.7-0.20261023115459-5dc452e537bf

require golang.org/x/sys v0.47.0 // indirect
