package flowtls

import "errors"

// 传输层的错误定义（对应 Rust 侧用 anyhow 直接抛出的几种情形）。
var (
	// ErrPlatformUnsupported 在非 Linux 平台或目的地址不是 IPv4 时返回。
	//
	// FakeTCP 只支持 IPv4：AF_PACKET 分支不经过内核路由，不会自己拒绝 IPv6，
	// 必须在构造报文之前显式拦住，否则上层会把「发往 IPv6 地址的 IPv4 报文」
	// 当成成功。
	ErrPlatformUnsupported = errors.New("flowtls: 仅支持 Linux + IPv4")

	// ErrHandshakeTimeout 表示 SYN-ACK 在总超时内没有到达。
	//
	// 对应 Rust `HANDSHAKE_TIMEOUT`（15 秒）耗尽的情形：链路不通或服务端没起。
	ErrHandshakeTimeout = errors.New("flowtls: 握手超时（SYN-ACK 未到达）")

	// ErrBadAddress 表示地址帧解析失败。
	ErrBadAddress = errors.New("flowtls: 地址帧格式错误")

	// ErrSessionClosed 表示底层会话已关闭。
	ErrSessionClosed = errors.New("flowtls: 会话已关闭")
)
