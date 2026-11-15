package flowtls

// 构包路径基准：回答「每包自建 IP/TCP 头占多少 CPU」。
//
// # 为什么单独量它
//
// 线上每发一个数据报都要走 BuildPacketInto：写 20 字节 IP 头 + 32 字节 TCP 头
// （含 TS 选项）+ 两次一补校验和（IP 头一次、伪头+TCP+载荷一次）。
// 9400 pps（100Mbps 单向）时这一层每秒跑 9400 次。
//
// 要判断它值不值得优化，必须先知道单次成本。若只有几百 ns，
// 那 9400pps 也只有百分之几的单核——和当初误判「加密是瓶颈」是同一类错误
// （见 codec_bench_test.go 的说明）。真正的成本大头是 syscall 与驱动的
// 内核态拷贝，不是用户态的字节拼装。

import (
	"net/netip"
	"testing"
)

var (
	benchSrcIP = netip.MustParseAddr("203.0.113.10")
	benchDstIP = netip.MustParseAddr("198.51.100.20")
)

// BenchmarkBuildPacketInto 是最小构包：数据包（带 TS 选项）。
func BenchmarkBuildPacketInto(b *testing.B) {
	payload := make([]byte, benchPayloadSize)
	seg := TcpSeg{
		Seq:     0x12345678,
		Ack:     0x9abcdef0,
		Flags:   TCPPSH | TCPACK,
		IPID:    0xF107,
		Window:  32768,
		TSVal:   123456,
		TSecr:   654321,
		Payload: payload,
	}
	out := make([]byte, 0, 2048)
	b.SetBytes(benchPayloadSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 模拟热路径：seq 每包推进，其余不变
		seg.Seq += uint32(benchPayloadSize)
		out = BuildPacketInto(out[:0], benchSrcIP, benchDstIP, 44312, 8443, seg)
	}
	_ = out
}

// BenchmarkBuildPacketIntoSmall 是纯 ACK 构包（52 字节，无载荷）。
//
// 纯 ACK 占包量的 20% 左右，它的单次成本几乎全在固定开销里，
// 因此能看出「构包常量成本」的底。
func BenchmarkBuildPacketIntoSmall(b *testing.B) {
	seg := TcpSeg{
		Seq:    0x12345678,
		Ack:    0x9abcdef0,
		Flags:  TCPACK,
		IPID:   0xF107,
		Window: 32768,
		TSVal:  123456,
		TSecr:  654321,
	}
	out := make([]byte, 0, 2048)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = BuildPacketInto(out[:0], benchSrcIP, benchDstIP, 44312, 8443, seg)
	}
	_ = out
}

// BenchmarkSum16 单独量校验和扫描（1332 字节载荷）。
//
// 构包里有两次 sum16：IP 头 20 字节 + 伪头/TCP/载荷 1364 字节。
// 后者是唯一随载荷长度增长的部分。
func BenchmarkSum16(b *testing.B) {
	buf := make([]byte, IPHdrLen+TCPHdrWithTS+benchPayloadSize)
	for i := range buf {
		buf[i] = byte(i)
	}
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	var s uint32
	for i := 0; i < b.N; i++ {
		s = sum16(buf)
	}
	_ = s
}
