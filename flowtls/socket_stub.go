//go:build !linux && !windows

package flowtls

// 既非 Linux 也非 Windows 的平台上的空实现（macOS / FreeBSD / …）。
//
// flowtls 的传输层依赖 Linux 的 AF_PACKET / IPPROTO_RAW / iptables，
// 或 Windows 的 WinDivert 驱动；其余平台没有等价能力。
//
// 保留同一套签名只为让 sing-box 的多平台构建通过（`sing-box check` 在
// macOS 上也要能跑），构造必然失败，运行时不会出现「编译通过但行为诡异」。
//
// # 这个文件的字段为什么必须和真实实现对齐
//
// 上层代码直接读 `s.raw.localIP`（字段而不是方法），所以空实现也**必须有
// 同名同类型的字段**，否则 `GOOS=darwin go build` 直接失败。
// 历史上这里漏过字段，导致 macOS/FreeBSD 长期编译不过而没人发现
// （发行目标只有 Linux，CI 也没跑这些平台）。现在 CI 有全平台编译门禁。

import "net/netip"

type rawSocket struct {
	// localIP 必须存在：上层按字段访问（见文件头）。
	localIP netip.Addr
	// reinjectUnmatched 在无 WinDivert 的平台上恒为 false。
	reinjectUnmatched bool
}

// newRawSocket 与 Linux / Windows 侧保持同一签名。
func newRawSocket(dst netip.Addr, local netip.Addr, logger Logger, wantAFPacket bool, role socketRole) (*rawSocket, error) {
	return nil, ErrPlatformUnsupported
}

// recvBatchEnabled 在这些平台上恒为 false（构造先失败，走不到这里）。
func recvBatchEnabled() bool { return false }

// LocalIP 返回空地址（无出口 IP 概念）。
func (s *rawSocket) LocalIP() netip.Addr { return netip.Addr{} }

// SendMode 与真实实现对位：适配层会无条件读取它写启动日志。
func (s *rawSocket) SendMode() string { return "unsupported" }

func (s *rawSocket) Close() error { return nil }

func (s *rawSocket) Send(pkt []byte, dst netip.Addr) error { return ErrPlatformUnsupported }

func (s *rawSocket) SendBatch(pkts [][]byte, dst netip.Addr) (int, error) {
	return 0, ErrPlatformUnsupported
}

// Reinject 与真实实现对位（这些平台上永远不会被调用）。
func (s *rawSocket) Reinject(pkt []byte) error { return ErrPlatformUnsupported }

func (s *rawSocket) Recv(buf []byte) (int, error) { return 0, ErrPlatformUnsupported }

// recvAvailable 与真实实现对位：非阻塞取一帧。
func (s *rawSocket) recvAvailable(buf []byte) (int, bool, error) {
	return 0, false, ErrPlatformUnsupported
}

// recvBatch 与真实实现对位：批量收一帧集合。
func (s *rawSocket) recvBatch(slots *recvSlots) (int, error) {
	return 0, ErrPlatformUnsupported
}
