//go:build !linux

package flowtls

import "net/netip"

// 非 Linux 平台全部走这里。
//
// 为什么需要这个文件而不是「干脆不编译」：上游 sing-box 的 lint 会跑
// GOOS=windows/darwin/android 的 `go build ./...`，缺这个文件会让
// 整个模块在那些平台上编译失败，进而拖垮 sing-box 的多平台构建。
//
// 所有函数返回 ErrPlatformUnsupported，配置里写 flowtls 会得到明确报错，
// 而不是晦涩的编译错误。

type rawSocket struct {
	LocalIP netip.Addr
}

// maxSendBatch 与 Linux 侧保持同值。
//
// 为什么要在 stub 里定义：它是一次批量发送的报文上限，属于 socket 层常量，
// 但使用它的 session.go 是跨平台文件。放在带 linux tag 的文件里会让
// darwin/windows/android 编译直接失败（undefined: maxSendBatch），
// 从而拖垮 sing-box 的多平台构建。
const maxSendBatch = 32

// maxRecvBatch 同样要在非 Linux 对位：session.recvLoop 用它预分配
// recvmmsg 的缓冲数组，而 session.go 是跨平台文件。
const maxRecvBatch = 32

// bindRecv 与 Linux 侧保持同一签名：只有客户端需要把接收 fd 绑到出口网卡，
// 服务端必须保持不绑定（否则收不到 lo / 多网卡上的包）。
func newRawSocket(dst netip.Addr, local netip.Addr, bindRecv bool) (*rawSocket, error) {
	return nil, ErrPlatformUnsupported
}

func (s *rawSocket) Close() error { return nil }

func (s *rawSocket) Send(pkt []byte, dst netip.Addr) error { return ErrPlatformUnsupported }

func (s *rawSocket) SendBatch(pkts [][]byte, dst netip.Addr) (int, error) {
	return 0, ErrPlatformUnsupported
}

func (s *rawSocket) Recv(buf []byte) (int, error) { return 0, ErrPlatformUnsupported }

// RecvBatch 与非 Linux 对位：session.recvLoop 统一走批量收包，
// 缺这个方法会让 darwin/windows/android 编译失败。
func (s *rawSocket) RecvBatch(bufs [][]byte, lens []int) (int, error) {
	return 0, ErrPlatformUnsupported
}

// SendMode 与非 Linux 对位：这条平台根本不能发包，日志里直接写 unsupported，
// 避免上层（Listener.SendMode / Session.SendMode）出现平台缺失的编译错误。
func (s *rawSocket) SendMode() string { return "unsupported" }
