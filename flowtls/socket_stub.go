//go:build !linux

package flowtls

// 非 Linux 平台的空实现。
//
// flowtls 的传输层依赖 AF_PACKET / IPPROTO_RAW / iptables，这些是 Linux 专有
// 能力；其它平台保留同一套签名只为让 sing-box 的多平台构建通过
// （`sing-box check` 在 macOS/Windows 上也要能跑）。
//
// 所有方法都返回 ErrPlatformUnsupported，构造函数返回错误，
// 从而不会出现「编译通过但运行时行为诡异」的中间状态。

import "net/netip"

type rawSocket struct{}

// newRawSocket 与 Linux 侧保持同一签名。
func newRawSocket(dst netip.Addr, local netip.Addr) (*rawSocket, error) {
	return nil, ErrPlatformUnsupported
}

// LocalIP 返回空地址（非 Linux 无出口 IP 概念）。
func (s *rawSocket) LocalIP() netip.Addr { return netip.Addr{} }

// SendMode 与 Linux 对位：适配层会无条件读取它写启动日志。
func (s *rawSocket) SendMode() string { return "unsupported" }

func (s *rawSocket) Close() error { return nil }

func (s *rawSocket) Send(pkt []byte, dst netip.Addr) error { return ErrPlatformUnsupported }

func (s *rawSocket) SendBatch(pkts [][]byte, dst netip.Addr) (int, error) {
	return 0, ErrPlatformUnsupported
}

func (s *rawSocket) Recv(buf []byte) (int, error) { return 0, ErrPlatformUnsupported }

// recvAvailable 与 Linux 侧同一签名：非阻塞取一帧。
//
// 非 Linux 上永远不会被调用（构造函数就先失败了），保留只为对位编译。
func (s *rawSocket) recvAvailable(buf []byte) (int, bool, error) {
	return 0, false, ErrPlatformUnsupported
}
