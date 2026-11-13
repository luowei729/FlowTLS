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

func newRawSocket(dst netip.Addr, local netip.Addr) (*rawSocket, error) {
	return nil, ErrPlatformUnsupported
}

func (s *rawSocket) Close() error { return nil }

func (s *rawSocket) Send(pkt []byte, dst netip.Addr) error { return ErrPlatformUnsupported }

func (s *rawSocket) SendBatch(pkts [][]byte, dst netip.Addr) (int, error) {
	return 0, ErrPlatformUnsupported
}

func (s *rawSocket) Recv(buf []byte) (int, error) { return 0, ErrPlatformUnsupported }
