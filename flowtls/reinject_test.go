package flowtls

// 本文件覆盖「未消费的包要不要还给内核」这个决策（Windows 移植的关键正确性）。
//
// 为什么单独测：这个问题（包被驱动扣留后销毁）在 Linux 上根本跑不到 ——
// AF_PACKET 是被动复制，reinjectUnmatched 恒为 false。
// 只有把这些判断写成纯函数，才能在 Linux 的 CI 上验证 Windows 的语义。
//
// rev.17 起判据从「IP ID 高字节」改成「纯 SYN + TCP ISN 低 16 位」，
// 因为 IP ID 会被中间设备随机化（见 packet.go 的长注释）。

import (
	"net/netip"
	"testing"
)

// reinjectTestListener 构造一个「Windows 服务端」形态的 Listener：
// reinjectUnmatched=true，其他字段够用即可。
func reinjectTestListener(mark uint16) *Listener {
	return &Listener{
		raw:      &rawSocket{reinjectUnmatched: true},
		port:     8443,
		isnMarks: []uint16{mark},
		byAddr:   make(map[netip.AddrPort]*Session),
		pending:  make(map[netip.AddrPort]*synState),
		logger:   nopLogger{},
	}
}

// TestShouldReinjectISONMarkedSYN 钉住核心分流决策。
//
// 判据 = 纯 SYN 且 ISN 低 16 位命中标记。**IP ID 完全不参与**。
func TestShouldReinjectISONMarkedSYN(t *testing.T) {
	const mark = 0xF107
	l := reinjectTestListener(mark)

	// 我们的 SYN：ISN 低 16 位是标记，IP ID 随便填（会被中间设备改写）。
	owned := ParsedPacket{
		IPID: 0x1234, SrcPort: 44300, DstPort: 8443,
		Flags: TCPSYN, Seq: 0xAAAAF107,
	}
	// 伪装站的真实浏览器 SYN：ISN 随机，不命中标记。
	foreign := ParsedPacket{
		IPID: 0xF107, SrcPort: 55000, DstPort: 8443,
		Flags: TCPSYN, Seq: 0xAAAA1234,
	}

	if !l.protocolOwned(owned) {
		t.Fatalf("纯 SYN 且 ISN 命中应判为本协议族: seq=%#x mark=%#x",
			owned.Seq, mark)
	}
	// 关键回归：**IP ID 恰好等于标记不能让它被误判**。
	// 改造前正是靠 IP ID 判定，改造后 IP ID 完全退出判据。
	if l.protocolOwned(foreign) {
		t.Fatal("ISN 不命中时，IP ID 恰好撞上标记也不能判为本协议族")
	}

	// 伪装站的真实浏览器流量：不带标记 + 未消费 → 必须还给内核，
	// 否则 WinDivert 把它销毁，同端口的真网站就静默失效了。
	if !l.shouldReinject(foreign, false) {
		t.Error("不带标记且未消费的包必须重新注入（伪装站靠这一条活着）")
	}

	// 带标记但认证失败/乱序：绝不能还。内核会回 RST，中间设备拆 NAT 映射。
	if l.shouldReinject(owned, false) {
		t.Error("带标记但未消费的包不能还给内核（会引出 RST 拆 NAT 映射）")
	}

	// 已消费的包永远不用还。
	if l.shouldReinject(foreign, true) {
		t.Error("已消费的包不应重新注入")
	}
	if l.shouldReinject(owned, true) {
		t.Error("已消费的包不应重新注入")
	}
}

// TestProtocolOwnedRequiresPureSYN 钉住「只有纯 SYN 才按标记判归属」。
//
// 数据包的序列号从 ISN+1 递增，低位早已打散；判归属必须靠四元组会话表
// （handlePacket 第 2 分支），不能靠标记。若这里放开，Windows 上会把
// 未归属的数据包错误扣留，伪装站与真实流量都会受影响。
func TestProtocolOwnedRequiresPureSYN(t *testing.T) {
	const mark = 0xF107
	l := reinjectTestListener(mark)

	// 带载荷的 SYN：不是纯 SYN，交给首包鉴权路径。
	withPayload := ParsedPacket{
		Flags: TCPSYN, Seq: 0xAAAAF107, Payload: []byte{1, 2, 3},
	}
	if l.protocolOwned(withPayload) {
		t.Error("带载荷的 SYN 不能按标记判归属")
	}
	// 纯 ACK / PSH：同样不按标记判。
	for _, f := range []uint8{TCPACK, TCPPSH | TCPACK, TCPFIN | TCPACK} {
		p := ParsedPacket{Flags: f, Seq: 0xAAAAF107}
		if l.protocolOwned(p) {
			t.Errorf("flags=%#x 不是纯 SYN，不能按标记判归属", f)
		}
	}
	// 纯 SYN 才认。
	if !l.protocolOwned(ParsedPacket{Flags: TCPSYN, Seq: 0xAAAAF107}) {
		t.Error("纯 SYN 且 ISN 命中应判为本协议族")
	}
}

func TestShouldReinjectDisabledOnLinux(t *testing.T) {
	// Linux 的 AF_PACKET 是被动复制：内核手里已经有这个包，
	// 未消费就是「内核照常处理」，不需要也不允许再注入一次。
	l := reinjectTestListener(0xF107)
	l.raw.reinjectUnmatched = false
	foreign := ParsedPacket{
		IPID: 0x1234, SrcPort: 55000, DstPort: 8443,
		Flags: TCPSYN, Seq: 0xAAAA1234,
	}
	if l.shouldReinject(foreign, false) {
		t.Error("Linux 上不应重新注入任何包")
	}
}

// TestProtocolOwnedMultiCredential 钉住多凭据：任一标记命中即认。
func TestProtocolOwnedMultiCredential(t *testing.T) {
	l := reinjectTestListener(0)
	l.isnMarks = []uint16{0x1111, 0x2222, 0x3333}

	for _, m := range l.isnMarks {
		p := ParsedPacket{Flags: TCPSYN, Seq: 0xABCD0000 | uint32(m)}
		if !l.protocolOwned(p) {
			t.Errorf("标记 %#x 应被认出", m)
		}
	}
	// 不在表里的标记（同一条密码换成别的部署派生值）必须不认。
	for _, m := range []uint16{0x4444, 0x0001, 0xFFFF} {
		p := ParsedPacket{Flags: TCPSYN, Seq: 0xABCD0000 | uint32(m)}
		if l.protocolOwned(p) {
			t.Errorf("标记 %#x 不在凭据表里，不能认", m)
		}
	}
	// ISN 低 16 位为 0 永远不认（0 在配置里表示「未配置」）。
	if l.protocolOwned(ParsedPacket{Flags: TCPSYN, Seq: 0xABCD0000}) {
		t.Error("ISN 低 16 位为 0 时不能判为本协议族")
	}
}

// TestISNMarkIndependentOfIPID 是本轮改造的核心回归。
//
// 背景：2026-11-28 实测发现 hk1 → tk3 路径会把 IP ID 随机化，
// 导致「IP ID 高字节 == 标记」的判据永远不成立，隧道彻底不通。
// 这个用例钉住：**IP ID 取任何值都不影响判定结果**。
func TestISNMarkIndependentOfIPID(t *testing.T) {
	const mark = 0xF107
	l := reinjectTestListener(mark)

	// 同一串 IP ID 值，分别配「ISN 命中」与「ISN 不命中」两种序列号。
	ipids := []uint16{0x0000, 0x0BE9, 0x2CA1, 0x4F3B, 0x6500, 0xBA46, 0xFFFF}
	for _, ipid := range ipids {
		hit := ParsedPacket{IPID: ipid, Flags: TCPSYN, Seq: 0x1234F107}
		if !l.protocolOwned(hit) {
			t.Errorf("ipid=%#04x 时 ISN 命中仍应认出（IP ID 不参与判定）", ipid)
		}
		miss := ParsedPacket{IPID: ipid, Flags: TCPSYN, Seq: 0x12349999}
		if l.protocolOwned(miss) {
			t.Errorf("ipid=%#04x 时 ISN 不命中就不能认出", ipid)
		}
	}
}
