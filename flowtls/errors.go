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

	// ErrWindivertUnsupported 表示 Windows 上 WinDivert 不可用。
	//
	// 三种典型原因（都来自驱动交互，无法在编译期发现）：
	//   - 没有管理员权限（CreateFile \\.\WinDivert 返回 ACCESS_DENIED）
	//   - 驱动被安全软件拦截（ERROR_DRIVER_BLOCKED = 1275）
	//   - 运行在 Windows ARM64（官方没有 arm64 驱动资产）
	//
	// 单独给它一个错误，是为了让上层能打出一条「该怎么办」的日志，
	// 而不是把 ACCESS_DENIED 当成隧道故障。
	ErrWindivertUnsupported = errors.New("flowtls: Windows 需要管理员权限且允许加载 WinDivert 驱动")

	// errWindivertFilterTooLong 表示过滤器指令超过驱动上限（内部错误）。
	errWindivertFilterTooLong = errors.New("flowtls: windivert 过滤器过长")
)
