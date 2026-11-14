package flowtls

// 本文件对应 legacy-rust:src/faketcp/packet.rs 末尾的 #[cfg(test)] 模块，
// 逐条翻译，并补一个「构造 → 解析」的往返测试（Rust 侧靠联调覆盖）。

import (
	"bytes"
	"net/netip"
	"testing"
)

// TestSynOptionsLayout 钉住 SYN 选项的 20 个字节。
//
// 这是伪装外观的核心：任何字段变化都会让「两个方向看起来是两个不同客户端」，
// 本身就是可疑信号。
func TestSynOptionsLayout(t *testing.T) {
	o := SynOptions(0xAABBCCDD, 0)
	if !bytes.Equal(o[0:4], []byte{0x02, 0x04, 0x05, 0xb4}) {
		t.Fatal("MSS 1460 错误")
	}
	if !bytes.Equal(o[4:6], []byte{0x04, 0x02}) {
		t.Fatal("SACK permitted 错误")
	}
	if !bytes.Equal(o[6:8], []byte{0x08, 0x0a}) {
		t.Fatal("时间戳 kind/len 错误")
	}
	if !bytes.Equal(o[8:12], []byte{0xAA, 0xBB, 0xCC, 0xDD}) {
		t.Fatal("TSval 错误")
	}
	if !bytes.Equal(o[12:16], []byte{0, 0, 0, 0}) {
		t.Fatal("SYN 的 TSecr 必须为 0")
	}
	if o[16] != 0x01 {
		t.Fatal("NOP 错误")
	}
	if !bytes.Equal(o[17:20], []byte{0x03, 0x03, WScale}) {
		t.Fatal("wscale 错误")
	}
	if WScale != 9 {
		t.Fatalf("wscale 必须与 Rust 一致（9），得到 %d", WScale)
	}
}

// TestIPIDProgression 验证 IP ID 在标记区间内递增，起点随机但仍在区间内。
func TestIPIDProgression(t *testing.T) {
	id := IPIDMarkOf(0xF107)
	for i := 0; i < 1000; i++ {
		id = NextIPID(IPIDMarkOf(0xF107), id)
		if id&0xFF00 != IPIDMark {
			t.Fatalf("高字节必须保持标记，得到 0x%04x", id)
		}
	}
	for i := 0; i < 50; i++ {
		if got := RandomIPID(IPIDMark); got&0xFF00 != IPIDMark {
			t.Fatalf("随机起点必须落在标记区间，得到 0x%04x", got)
		}
	}
}

// TestAdvertisedWindow 验证窗口随积压下降、且永不为 0。
func TestAdvertisedWindow(t *testing.T) {
	// 空载：16MB >> 9 = 32768
	if w := AdvertisedWindow(0); w != 32768 {
		t.Fatalf("空载窗口应为 32768，得到 %d", w)
	}
	// 满积压：不能声明零窗口（否则对端永久停发）
	if w := AdvertisedWindow(16 * 1024 * 1024); w != 1 {
		t.Fatalf("满积压窗口应为 1，得到 %d", w)
	}
	// 超过上限也按满处理
	if w := AdvertisedWindow(32 * 1024 * 1024); w != 1 {
		t.Fatalf("超上限窗口应为 1，得到 %d", w)
	}
	// 单调不增
	prev := AdvertisedWindow(0)
	for unread := 0; unread <= 16*1024*1024; unread += 512 * 1024 {
		w := AdvertisedWindow(unread)
		if w > prev {
			t.Fatalf("窗口随积压上升了：unread=%d w=%d prev=%d", unread, w, prev)
		}
		prev = w
	}
}

// TestSeqLen 验证 SYN/FIN 各占一个序号，纯 ACK 不占。
func TestSeqLen(t *testing.T) {
	cases := []struct {
		flags uint8
		plen  int
		want  uint32
	}{
		{TCPSYN, 0, 1},
		{TCPACK, 0, 0},
		{TCPPSH | TCPACK, 1382, 1382},
		{TCPFIN | TCPACK, 0, 1},
		{TCPFIN | TCPACK, 10, 11},
	}
	for _, c := range cases {
		if got := seqLen(c.flags, c.plen); got != c.want {
			t.Fatalf("seqLen(0x%02x, %d) = %d，期望 %d", c.flags, c.plen, got, c.want)
		}
	}
}

// wrapEthernet 给 IP 报文加上以太网头，模拟 AF_PACKET 收到的帧。
//
// BuildPacketInto 只产出 IP 报文（不含以太网头），与 Rust 一致：
// 发送走 AF_PACKET/SOCK_DGRAM 时内核补以太网头，接收侧的帧才带 14 字节头。
func wrapEthernet(ip []byte) []byte {
	frame := make([]byte, 14+len(ip))
	copy(frame[0:6], []byte{1, 2, 3, 4, 5, 6})
	copy(frame[6:12], []byte{7, 8, 9, 10, 11, 12})
	frame[12], frame[13] = 0x08, 0x00
	copy(frame[14:], ip)
	return frame
}

// TestBuildAndParseRoundTrip 验证「构造 → 解析」逐字段一致。
//
// 数据包自动追加 12 字节时间戳选项，因此 IP 总长 = 20 + 32 + 载荷。
func TestBuildAndParseRoundTrip(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("203.0.113.10")
	payload := make([]byte, 1365)
	for i := range payload {
		payload[i] = byte(i)
	}
	seg := TcpSeg{
		Seq:     1234567,
		Ack:     7654321,
		Flags:   TCPPSH | TCPACK,
		IPID:    0xF1AB,
		Window:  32768,
		TSVal:   1111,
		TSecr:   2222,
		Payload: payload,
	}
	ip := BuildPacket(src, dst, 44300, 8443, seg)

	if want := 20 + 32 + len(payload); len(ip) != want {
		t.Fatalf("IP 报文长度 %d，期望 %d", len(ip), want)
	}
	frame := wrapEthernet(ip)

	p, ok := ParseFrame(frame)
	if !ok {
		t.Fatal("ParseFrame 失败")
	}
	if p.Src != src || p.Dst != dst {
		t.Fatalf("地址不符: %v -> %v", p.Src, p.Dst)
	}
	if p.SrcPort != 44300 || p.DstPort != 8443 {
		t.Fatalf("端口不符: %d -> %d", p.SrcPort, p.DstPort)
	}
	if p.Seq != seg.Seq || p.Ack != seg.Ack {
		t.Fatalf("序号不符: seq=%d ack=%d", p.Seq, p.Ack)
	}
	if p.Flags != seg.Flags {
		t.Fatalf("标志不符: 0x%02x", p.Flags)
	}
	if p.IPID != seg.IPID {
		t.Fatalf("IP ID 不符: 0x%04x", p.IPID)
	}
	if p.Window != seg.Window {
		t.Fatalf("窗口不符: %d", p.Window)
	}
	if !p.HasTS || p.TSVal != seg.TSVal || p.TSecr != seg.TSecr {
		t.Fatalf("时间戳不符: hasTS=%v tsval=%d tsecr=%d", p.HasTS, p.TSVal, p.TSecr)
	}
	if p.WScale != -1 {
		t.Fatalf("数据包不应携带 wscale，得到 %d", p.WScale)
	}
	if !bytes.Equal(p.Payload, payload) {
		t.Fatal("载荷不一致")
	}
}

// TestParseFrameSYNOptions 验证 SYN 的 wscale 能被解析出来。
func TestParseFrameSYNOptions(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("203.0.113.10")
	opts := SynOptions(0x11223344, 0)
	ip := BuildPacket(src, dst, 44300, 8443, TcpSeg{
		Seq: 1, Flags: TCPSYN, IPID: 0xF101, Window: 65535,
		TSVal: 0x11223344, Options: opts[:],
	})
	if want := 20 + 20 + 20; len(ip) != want {
		t.Fatalf("SYN 报文长度 %d，期望 %d", len(ip), want)
	}
	p, ok := ParseFrame(wrapEthernet(ip))
	if !ok {
		t.Fatal("ParseFrame 失败")
	}
	if p.WScale != int(WScale) {
		t.Fatalf("SYN 的 wscale 应为 %d，得到 %d", WScale, p.WScale)
	}
	if !p.HasTS || p.TSVal != 0x11223344 {
		t.Fatalf("SYN 的 TSval 不符: %v %d", p.HasTS, p.TSVal)
	}
}

// TestParseFrameRejects 验证非目标流量被拒绝（分片 / 非 TCP / 截断）。
func TestParseFrameRejects(t *testing.T) {
	base := func() []byte {
		ip := BuildPacket(netip.MustParseAddr("1.1.1.1"),
			netip.MustParseAddr("2.2.2.2"), 1, 2, TcpSeg{Flags: TCPACK, Window: 1})
		return wrapEthernet(ip)
	}
	if _, ok := ParseFrame(base()); !ok {
		t.Fatal("基准帧应能解析")
	}
	// 截断
	if _, ok := ParseFrame(base()[:20]); ok {
		t.Fatal("截断帧不应解析成功")
	}
	// 非 IPv4
	f := base()
	f[12], f[13] = 0x86, 0xdd
	if _, ok := ParseFrame(f); ok {
		t.Fatal("IPv6 帧不应解析成功")
	}
	// 分片（MF 置位）
	f = base()
	f[14+6] |= 0x20
	if _, ok := ParseFrame(f); ok {
		t.Fatal("分片帧不应解析成功")
	}
	// 非 TCP
	f = base()
	f[14+9] = 17
	if _, ok := ParseFrame(f); ok {
		t.Fatal("UDP 帧不应解析成功")
	}
}

// TestTcpClockMonotonic 验证 TSval 单调不减、observe 回显。
func TestTcpClockMonotonic(t *testing.T) {
	c := NewTcpClockAt(1000)
	prev := c.TSVal()
	for i := 0; i < 100; i++ {
		v := c.TSVal()
		if v < prev {
			t.Fatalf("TSval 回退了：%d -> %d", prev, v)
		}
		prev = v
	}
	c.Observe(0xDEADBEEF, true)
	if c.PeerTS != 0xDEADBEEF {
		t.Fatalf("PeerTS 未记录: %d", c.PeerTS)
	}
	// HasTS=false 时不应覆盖
	c.Observe(0x1234, false)
	if c.PeerTS != 0xDEADBEEF {
		t.Fatal("无时间戳选项时不应覆盖 PeerTS")
	}
}
