package flowtls

import E "github.com/sagernet/sing/common/exceptions"

var (
	// ErrNotImplemented 标记 P0 阶段的占位实现。
	// P1 起应逐项删除，不允许长期存在。
	ErrNotImplemented = E.New("flowtls: transport not implemented yet")

	// ErrPlatformUnsupported 由 socket_stub.go 返回，用于非 Linux 平台。
	ErrPlatformUnsupported = E.New("flowtls: only supported on linux with IPv4")

	// ErrHandshakeTimeout 表示 SYN-ACK 等待超时。
	ErrHandshakeTimeout = E.New("flowtls: handshake timeout")

	// ErrSessionClosed 表示 Session 已关闭，但仍被读写。
	ErrSessionClosed = E.New("flowtls: session closed")
)
