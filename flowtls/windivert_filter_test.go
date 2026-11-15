package flowtls

// WinDivert 用户态协议层的字节级断言。
//
// # 这些测试为什么存在
//
// Windows 支持的运行时部分（DeviceIoControl、驱动交互）**无法在本仓验证**
// ——没有 Windows 主机。但过滤器编码、批量包拼接、Address 位域这三样是纯字节
// 操作，写错时不会编译失败，只会表现为「驱动行为诡异」：
//
//	过滤器编码错 → 收不到任何包（与「链路不通」无法区分）
//	批量拼接错 → SendBatch 整批被驱动拒绝（它按 IP total length 校验）
//	Address 布局错 → 驱动按 80 字节步长遍历，读到垃圾
//
// 所以在 Linux 上钉住它们，是这套 Windows 支持里唯一能真正验证的部分。

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"unsafe"
)

// TestWindivertAddressLayout 钉住 WINDIVERT_ADDRESS 的 80 字节布局与位域。
func TestWindivertAddressLayout(t *testing.T) {
	var a wdivAddr
	if got := int(unsafe.Sizeof(a)); got != wdivAddressSize {
		t.Fatalf("Address 大小应为 %d 字节，实际 %d", wdivAddressSize, got)
	}
	// Bits 必须落在偏移 8（Timestamp 之后）。
	if off := int(unsafe.Offsetof(a.Bits)); off != 8 {
		t.Fatalf("Bits 偏移应为 8，实际 %d", off)
	}

	// Outbound = bit17，与 windivert.h 的位域顺序一致。
	a.Bits = 0
	if a.Outbound() {
		t.Fatal("零值不应是 outbound")
	}
	a.Bits = 1 << wdivBitOutbound
	if !a.Outbound() {
		t.Fatal("bit17 应表示 outbound")
	}
	// Impostor = bit19，不能被 outbound 误判。
	a.Bits = 1 << wdivBitImpostor
	if a.Outbound() {
		t.Fatal("impostor 位不应被读成 outbound")
	}
	if !a.Impostor() {
		t.Fatal("bit19 应表示 impostor")
	}
}

// TestWindivertFilterEncode 逐字节验证判定链编码。
//
// 布局（24 字节 packed，小端）：
//
//	word0 = field:11 | test:5<<11 | success:16<<16
//	word1 = failure:16
//	word2..5 = arg[4]
func TestWindivertFilterEncode(t *testing.T) {
	// 取值固定下来是为了让字节级断言可复现（本机地址 / 源端口 / 服务端端口）。
	// 8443 是服务端端口，过滤器必须限定源端口，否则会扣下别人的回包。
	f := wdivClientInboundFilter(netip.MustParseAddr("10.0.0.2"), 44311, 8443)
	bin, flags, err := f.encode()
	if err != nil {
		t.Fatal(err)
	}

	if want := wdivFilterFlagInbound | wdivFilterFlagIP; flags != want {
		t.Fatalf("flags 应为 %#x，实际 %#x", want, flags)
	}
	// 7 条指令：inbound / ip / ip.DstAddr / tcp / tcp.DstPort>= / tcp.DstPort<= / tcp.SrcPort
	const wantInsts = 7
	if len(bin) != wantInsts*wdivInstBytes {
		t.Fatalf("指令数应为 %d，实际 %d", wantInsts, len(bin)/wdivInstBytes)
	}

	// 逐条核对：field / test / success 链 / failure / arg
	type want struct {
		field uint16
		test  uint8
		succ  uint16
		arg   uint32
	}
	wants := []want{
		{wdivFieldInbound, wdivTestEQ, 1, 1},
		{wdivFieldIP, wdivTestEQ, 2, 1},
		{wdivFieldIPDstAddr, wdivTestEQ, 3, binary.BigEndian.Uint32(netip.MustParseAddr("10.0.0.2").AsSlice())},
		{wdivFieldTCP, wdivTestEQ, 4, 1},
		{wdivFieldTCPDstPort, wdivTestGEQ, 5, 44311},
		{wdivFieldTCPDstPort, wdivTestLEQ, 6, 44311},
		{wdivFieldTCPSrcPort, wdivTestEQ, wdivAccept, 8443},
	}
	for i, w := range wants {
		got := bin[i*wdivInstBytes : (i+1)*wdivInstBytes]
		word0 := binary.LittleEndian.Uint32(got[0:4])
		gotField := uint16(word0 & 0x7FF)
		gotTest := uint8(word0 >> 11 & 0x1F)
		gotSucc := uint16(word0 >> 16)
		gotFail := uint16(binary.LittleEndian.Uint32(got[4:8]) & 0xFFFF)
		gotArg := binary.LittleEndian.Uint32(got[8:12])

		if gotField != w.field || gotTest != w.test || gotSucc != w.succ ||
			gotFail != wdivReject || gotArg != w.arg {
			t.Fatalf("第 %d 条指令不符：field=%d test=%d succ=%#x fail=%#x arg=%d，期望 %+v",
				i, gotField, gotTest, gotSucc, gotFail, gotArg, w)
		}
		// ip.DstAddr 的 arg[1] 是 v4 标记 0x0000FFFF，其余指令后三个 arg 必须是 0。
		for k := 1; k < 4; k++ {
			v := binary.LittleEndian.Uint32(got[8+4*k : 12+4*k])
			want := uint32(0)
			if w.field == wdivFieldIPDstAddr && k == 1 {
				want = 0x0000FFFF
			}
			if v != want {
				t.Fatalf("第 %d 条指令 arg[%d] 应为 %#x，实际 %#x", i, k, want, v)
			}
		}
	}
}

// TestWindivertServerFilterShape 钉住服务端过滤器只含入向。
//
// 若把 outbound 也纳入，我们自己注入的包会被再扣留（即使驱动保证同优先级
// 不重复，也会多一次驱动往返），且 flags 会多出 outbound callout。
func TestWindivertServerFilterShape(t *testing.T) {
	f := wdivServerInboundFilter(8443)
	bin, flags, err := f.encode()
	if err != nil {
		t.Fatal(err)
	}
	if flags&wdivFilterFlagOutbound != 0 {
		t.Fatalf("服务端过滤器不应含 outbound flag，实际 %#x", flags)
	}
	if flags&wdivFilterFlagInbound == 0 {
		t.Fatalf("服务端过滤器必须含 inbound flag，实际 %#x", flags)
	}
	if len(bin) != 4*wdivInstBytes {
		t.Fatalf("指令数应为 4，实际 %d", len(bin)/wdivInstBytes)
	}
}

// TestWindivertEmptyFilterRejects 空过滤器必须「永不匹配」。
//
// 若编码成「总是匹配」，驱动会把整机流量都扣留，表现为断网。
func TestWindivertEmptyFilterRejects(t *testing.T) {
	f := &wdivFilter{}
	bin, flags, err := f.encode()
	if err != nil {
		t.Fatal(err)
	}
	if flags != 0 {
		t.Fatalf("空过滤器 flags 应为 0，实际 %#x", flags)
	}
	if len(bin) != wdivInstBytes {
		t.Fatalf("空过滤器应为 1 条指令，实际 %d", len(bin)/wdivInstBytes)
	}
	word0 := binary.LittleEndian.Uint32(bin[0:4])
	succ := uint16(word0 >> 16)
	fail := uint16(binary.LittleEndian.Uint32(bin[4:8]) & 0xFFFF)
	if succ != wdivReject || fail != wdivReject {
		t.Fatalf("空过滤器必须 success/failure 都是 REJECT，实际 %#x/%#x", succ, fail)
	}
}

// TestWindivertPackBatch 钉住 SendBatch 要求的「首尾相接」布局。
func TestWindivertPackBatch(t *testing.T) {
	p1 := []byte{0x45, 0x00, 0x00, 0x3C, 1, 2, 3}
	p2 := []byte{0x45, 0x00, 0x00, 0x28, 4, 5}
	pkts := [][]byte{p1, p2}

	dst := make([]byte, 0, 64)
	buf, lens, ok := wdivPackBatch(dst, pkts)
	if !ok {
		t.Fatal("容量足够却报告失败")
	}
	if !bytes.Equal(buf, []byte{0x45, 0, 0, 0x3C, 1, 2, 3, 0x45, 0, 0, 0x28, 4, 5}) {
		t.Fatalf("拼接结果不符：%v", buf)
	}
	if len(lens) != 2 || lens[0] != len(p1) || lens[1] != len(p2) {
		t.Fatalf("长度表不符：%v", lens)
	}

	// 容量不足必须整体失败，不能写半截（半截会让驱动的 total length 校验失败）
	small := make([]byte, 0, 5)
	if _, _, ok := wdivPackBatch(small, pkts); ok {
		t.Fatal("容量不足时应报告失败")
	}
}

// TestWindivertSplitBatch 钉住 RecvBatch 的切分（靠 IP total length）。
func TestWindivertSplitBatch(t *testing.T) {
	build := func(total uint16, marker byte) []byte {
		p := make([]byte, total)
		p[0] = 0x45
		binary.BigEndian.PutUint16(p[2:4], total)
		p[total-1] = marker
		return p
	}
	a := build(40, 0xAA)
	b := build(28, 0xBB)
	c := build(20, 0xCC)
	buf := append(append(append([]byte{}, a...), b...), c...)

	got := wdivSplitBatch(buf)
	if len(got) != 3 {
		t.Fatalf("应切出 3 个包，实际 %d", len(got))
	}
	for i, want := range [][]byte{a, b, c} {
		if !bytes.Equal(got[i], want) {
			t.Fatalf("第 %d 个包不符：len=%d（期望 %d）", i, len(got[i]), len(want))
		}
	}
}

// TestWindivertSplitBatchRejectsMalformed 畸形输入必须停止切分而不是 panic。
func TestWindivertSplitBatchRejectsMalformed(t *testing.T) {
	// total length = 0：驱动回填异常。
	bad := make([]byte, 40)
	bad[0] = 0x45
	if got := wdivSplitBatch(bad); len(got) != 0 {
		t.Fatalf("total=0 应切出 0 个包，实际 %d", len(got))
	}
	// total length 超过缓冲：半截包。
	trunc := make([]byte, 30)
	trunc[0] = 0x45
	binary.BigEndian.PutUint16(trunc[2:4], 100)
	if got := wdivSplitBatch(trunc); len(got) != 0 {
		t.Fatalf("越界应切出 0 个包，实际 %d", len(got))
	}
	// 不足一个 IP 头的残尾。
	if got := wdivSplitBatch(make([]byte, 10)); len(got) != 0 {
		t.Fatalf("残尾应切出 0 个包，实际 %d", len(got))
	}
	// 合法包 + 残尾：前面的合法包必须保留。
	good := make([]byte, 20)
	good[0] = 0x45
	binary.BigEndian.PutUint16(good[2:4], 20)
	tail := append(good, 1, 2, 3, 4, 5)
	if got := wdivSplitBatch(tail); len(got) != 1 {
		t.Fatalf("合法包+残尾应切出 1 个包，实际 %d", len(got))
	}
}

// TestWindivertFilterTooLong 指令数上限必须被拦住（驱动会直接拒绝）。
func TestWindivertFilterTooLong(t *testing.T) {
	f := &wdivFilter{}
	for i := 0; i < wdivMaxInsts; i++ {
		f.add(wdivFieldTCP, wdivTestEQ, 1)
	}
	if _, _, err := f.encode(); err == nil {
		t.Fatal("超过指令上限应返回错误")
	}
}

// TestWindivertIPIDRange 钉住 IP ID 标记的取值区间语义。
func TestWindivertIPIDRange(t *testing.T) {
	lo, hi := wdivIPIDMarkRange(0x1E07)
	if lo != 0x1E00 || hi != 0x1EFF {
		t.Fatalf("区间应为 [0x1E00,0x1EFF]，实际 [%#x,%#x]", lo, hi)
	}
	// 配置里低字节非零时同样只取高字节（与 IPIDMarkOf 一致）。
	lo2, hi2 := wdivIPIDMarkRange(0xF1FF)
	if lo2 != 0xF100 || hi2 != 0xF1FF {
		t.Fatalf("区间应为 [0xF100,0xF1FF]，实际 [%#x,%#x]", lo2, hi2)
	}
}
