//go:build windows && (amd64 || 386)

package flowtls

// Windows 侧的测试辅助，与 socket_linux_test.go 里的 newTestRawSocket 对位。
//
// 两边的 rawSocket 字段完全不同（Linux 用 fd，Windows 用驱动句柄），
// 所以只能各写一份；而 listener_test.go 里的分流逻辑测试要在两个平台都跑。

import "net/netip"

// newTestRawSocket 返回一个「有源地址但发不出去」的 rawSocket。
//
// 与 Linux 侧的差异：这里没有 fd 可以把 Send 弄成静默失败，
// 而是直接把 closed 置 true —— Send 的第一行就是 `if s.closed.Load()`，
// 返回 errSocketClosed（同样被 noteSendError 忽略）。
// 绝不能让 handle 保持 nil：Send 里 s.handle.Send 会空指针 panic。
// localIP 必须有值，否则构包时 As4() 会 panic。
func newTestRawSocket() *rawSocket {
	s := &rawSocket{
		localIP: netip.MustParseAddr("10.0.0.10"),
		logger:  nopLogger{},
	}
	s.closed.Store(true)
	return s
}
