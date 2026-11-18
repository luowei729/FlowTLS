package quic

// 本文件是 hysteria2 带宽协商的翻译，只换了承载方式。
//
// hysteria2 把速率放在认证请求的 HTTP 头里（Hysteria-CC-RX）。
// flowtls 没有那次 HTTP 认证：QUIC 握手一完成，第一条流就是代理流。
// 所以改用一条专门的 QUIC 流，字节布局照它的头字段：
//
//	客户端 → 服务端：u8 版本 + u64 接收速率（字节/秒）
//	服务端 → 客户端：u8 版本 + u64 接收速率（字节/秒）
//
// 取较小值的公式与 hysteria2/client.go、service.go 逐行一致：
//
//	客户端发送速率 = min(自己的 up, 服务端回的 down)
//	服务端发送速率 = min(自己的 up, 客户端报的 down)
//	对端回 0，或者比自己的 up 还大，就用自己的 up。
//
// 0 在配置里表示「没填」，到这里之前已经被换成默认 1 Gbps，
// 所以线上的 0 只表示「对端没谈成 / 旧版本」，按 hysteria2 退回本端 up。

import (
	"encoding/binary"
	"fmt"
	"io"
)

// bwFrameVersion 是带宽帧的版本。
//
// 和地址帧一样先读一个字节再决定怎么解析，后面加字段不用改旧的读取方。
const bwFrameVersion byte = 1

// bwFrameSize 是一帧的字节数：1 字节版本 + 8 字节速率。
const bwFrameSize = 1 + 8

// writeBandwidth 写出一帧接收速率。
func writeBandwidth(w io.Writer, rxBPS uint64) error {
	var buf [bwFrameSize]byte
	buf[0] = bwFrameVersion
	binary.BigEndian.PutUint64(buf[1:], rxBPS)
	_, err := w.Write(buf[:])
	return err
}

// readBandwidth 读一帧接收速率。
//
// 版本不对直接报错：宁可这次协商失败退回本端 up，
// 也不要把不认识的字节当成一个速率。
func readBandwidth(r io.Reader) (uint64, error) {
	var buf [bwFrameSize]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	if buf[0] != bwFrameVersion {
		return 0, fmt.Errorf("flowtls: 不认识的带宽帧版本 %d", buf[0])
	}
	return binary.BigEndian.Uint64(buf[1:]), nil
}

// actualSendBPS 是 hysteria2 的取较小值。
//
// peerRx 是对端报的接收速率。0 或比本端 up 还大，都用本端 up。
// 对应 hysteria2：
//
//	actualTx := authResponse.Rx
//	if actualTx == 0 || actualTx > c.sendBPS { actualTx = c.sendBPS }
func actualSendBPS(localUp, peerRx uint64) uint64 {
	if peerRx == 0 || peerRx > localUp {
		return localUp
	}
	return peerRx
}
