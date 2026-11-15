package flowtls

// 本文件覆盖「未消费的包要不要还给内核」这个决策（Windows 移植的关键正确性）。
//
// 为什么单独测：Java 那侧的这个问题（包被驱动扣留后销毁）在 Linux 上根本
// 跑不到 —— AF_PACKET 是被动复制，reinjectUnmatched 恒为 false。
// 只有把这些判断写成纯函数，才能在 Linux 的 CI 上验证 Windows 的语义。

import (
	"net/netip"
	"testing"
)

// reinjectTestListener 构造一个「Windows 服务端」形态的 Listener：
// reinjectUnmatched=true，其他字段够用即可。
func reinjectTestListener(mark uint16) *Listener {
	return &Listener{
		raw:     &rawSocket{reinjectUnmatched: true},
		port:    8443,
		mark:    IPIDMarkOf(mark),
		byAddr:  make(map[netip.AddrPort]*Session),
		pending: make(map[netip.AddrPort]*synState),
		logger:  nopLogger{},
	}
}

func TestShouldReinjectMarksProtocolOwned(t *testing.T) {
	const mark = 0xF100
	l := reinjectTestListener(mark)
	owned := ParsedPacket{IPID: mark, SrcPort: 44300, DstPort: 8443}
	// 「不带标记」必须改高字节：低字节是每包递增的序号，本就不参与判定。
	// （第一次写这个用例时用了 mark+1，被测试当场拦住 —— 那正是判据的语义。）
	foreign := ParsedPacket{IPID: mark + 0x100, SrcPort: 55000, DstPort: 8443}

	if !l.protocolOwned(owned) {
		t.Fatalf("带标记的包应被判为本协议族: ipid=%#x mark=%#x", owned.IPID, l.mark)
	}
	if l.protocolOwned(foreign) {
		t.Fatalf("不带标记的包不应被判为本协议族: ipid=%#x mark=%#x", foreign.IPID, l.mark)
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

func TestShouldReinjectDisabledOnLinux(t *testing.T) {
	// Linux 的 AF_PACKET 是被动复制：内核手里已经有这个包，
	// 未消费就是「内核照常处理」，不需要也不允许再注入一次。
	l := reinjectTestListener(0xF100)
	l.raw.reinjectUnmatched = false
	foreign := ParsedPacket{IPID: 0x1234, SrcPort: 55000, DstPort: 8443}
	if l.shouldReinject(foreign, false) {
		t.Error("Linux 上不应重新注入任何包")
	}
}

func TestReinjectIgnoresIPIDLowByte(t *testing.T) {
	// 判据只用 IP ID 高字节（低字节是按包递增的序号），
	// 与 Rust 和 Linux 的 u32 掩码 `& 0xFF00` 逐位一致。
	const mark = 0xF100
	l := reinjectTestListener(mark)
	for _, low := range []uint16{0x00, 0x01, 0x7F, 0xFF} {
		p := ParsedPacket{IPID: mark | low}
		if !l.protocolOwned(p) {
			t.Errorf("低字节 %#04x 不应影响判定: ipid=%#x", low, p.IPID)
		}
	}
	// 高字节差一位就不算本协议族。
	if l.protocolOwned(ParsedPacket{IPID: 0xF200}) {
		t.Error("高字节不同不应判为本协议族")
	}
}
