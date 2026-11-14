// flowtls 是 FlowTLS 的 Go 实现：外观是 TCP + TLS、内部是 QUIC 数据报的代理传输层。
//
// 本模块是 sing-box 的独立协议库（与 hysteria2 / anytls 平级），
// 也可以由 cmd/ 下的联调工具单独驱动。
//
// ## 移植原则
//
// 本模块是 `legacy-rust` 分支 `src/` 的**逐函数翻译**，不是重新设计。
// 每个导出符号都应能在 Rust 源码里找到对应物；找不到的只允许是
// Go 语言/库边界所必需的适配（见 PROJECT_PLAN.md §3、§4）。
//
// 明确的禁区：不自造机制（Probe / suspectConn / 发送队列 / Brutal /
// BPF 过滤器 / conntrack 规则），不调参偏离 Rust 的常量。
//
// ## 依赖铁律
//
// go.mod 里的 `sagernet/sing`、`sagernet/quic-go`、`sagernet/sing-quic`
// 必须与 `sing-box/go.mod` **逐字节一致**，否则 `M.Socksaddr` 这类类型不兼容。
// 构建始终带 `GOTOOLCHAIN=local`。
package flowtls
