module github.com/luowei729/flowtls

// 依赖版本必须与 ../sing-box/go.mod **逐字节一致**（见 doc.go 的「依赖铁律」）。
//
// 这三个 pseudoversion 是从 sing-box/go.mod 复制的，不要手动"升级"：
// quic-go 的 fork 每次改动都可能调整内部接口，与 sing-box 用不同版本会在
// M.Socksaddr / congestion 接口处编译失败。
//
//   sing-box/go.mod:47  github.com/sagernet/quic-go v0.61.0-sing-box-mod.12
//   sing-box/go.mod:48  github.com/sagernet/sing v0.9.7-0.20261023115459-5dc452e537bf
//   sing-box/go.mod:54  github.com/sagernet/sing-quic v0.7.2-0.20261020082049-7e0a5869a5f4
//   sing-box/go.mod:72  golang.org/x/crypto v0.54.0
go 1.25.5

require (
	github.com/sagernet/quic-go v0.61.0-sing-box-mod.12
	github.com/sagernet/sing v0.9.7-0.20261023115459-5dc452e537bf
	github.com/sagernet/sing-quic v0.7.2-0.20261020082049-7e0a5869a5f4
	golang.org/x/crypto v0.54.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/metacubex/utls v1.8.7 // indirect
	golang.org/x/exp v0.0.0-20250911091902-df9299821621 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
