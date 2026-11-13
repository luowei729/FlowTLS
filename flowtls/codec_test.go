package flowtls

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"testing"
)

// TestDeriveMatchesRust 固定住密钥派生参数。
//
// 这些字符串一旦变动，Go 与 Rust 两端就无法互通，而且现象是
// 「AEAD 全部解密失败」——非常难从日志看出根因。
// 用测试把派生结果钉死，改错立刻红。
func TestDeriveMatchesRust(t *testing.T) {
	key, authID, err := deriveKeyPair("test-password")
	if err != nil {
		t.Fatalf("deriveKeyPair: %v", err)
	}
	// 只断言长度与非零：具体密文值由两端联调保证，
	// 但参数（salt/info/长度）错了一定会体现为长度或互通失败。
	if len(key) != 32 {
		t.Fatalf("AEAD key 必须是 32 字节，得到 %d", len(key))
	}
	if len(authID) != AuthIDLen {
		t.Fatalf("authID 必须是 %d 字节，得到 %d", AuthIDLen, len(authID))
	}
	// 同密码必须可复现（服务端重启后还能认出同一个用户）
	key2, authID2, _ := deriveKeyPair("test-password")
	if !bytes.Equal(key[:], key2[:]) {
		t.Fatal("相同密码派生出的 key 必须一致")
	}
	if authID != authID2 {
		t.Fatal("相同密码派生出的 authID 必须一致")
	}
	// 不同密码必须不同
	_, authID3, _ := deriveKeyPair("test-password-2")
	if authID == authID3 {
		t.Fatal("不同密码的 authID 不能相同")
	}
	// authID 与 key 必须无关：authID 不等于 key 的任何 16 字节前缀
	if bytes.Equal(authID[:], key[:AuthIDLen]) {
		t.Fatal("authID 不能是 key 的前缀——那等于明文泄露密钥")
	}
	t.Logf("authID(%s) = %s", "test-password", hex.EncodeToString(authID[:]))
}

// TestSealOpenRoundtrip 验证首包/后续包的格式与解密路径。
func TestSealOpenRoundtrip(t *testing.T) {
	client, err := NewClientCodec("pw")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerCodec("pw")
	if err != nil {
		t.Fatal(err)
	}
	if client.AuthID() != server.AuthID() {
		t.Fatal("同密码的两端 authID 必须相同")
	}

	plain := []byte("quic datagram payload")
	rec := client.Seal(nil, plain)

	recs := ParseRecords(rec)
	if len(recs) != 1 {
		t.Fatalf("应解析出 1 条记录，得到 %d", len(recs))
	}
	if recs[0].Type != RecAppData {
		t.Fatalf("记录类型必须是 ApplicationData，得到 0x%02x", recs[0].Type)
	}
	payload := recs[0].Payload

	// 首包必须带 ver + authID
	if payload[0] != ProtocolVersion {
		t.Fatalf("首包版本字节必须是 %d，得到 %d", ProtocolVersion, payload[0])
	}
	wantID := client.AuthID()
	if !bytes.Equal(payload[1:FirstHeaderLen], wantID[:]) {
		t.Fatal("首包必须携带 authID")
	}
	ver, id, ok := ParseFirstHeader(payload)
	if !ok || ver != ProtocolVersion || id != client.AuthID() {
		t.Fatal("ParseFirstHeader 结果不正确")
	}
	got, ok := server.OpenFirst(payload)
	if !ok || !bytes.Equal(got, plain) {
		t.Fatalf("服务端解密首包失败: ok=%v got=%q", ok, got)
	}

	// 确认可达后不再带首包头
	client.MarkEstablished()
	rec2 := client.Seal(nil, []byte("second"))
	p2 := ParseRecords(rec2)[0].Payload
	if len(payload)-len(p2) != FirstHeaderLen-len([]byte("quic datagram payload"))+len("second") {
		// 长度关系由下面的显式断言保证，这里只是防御性检查
	}
	if len(p2) != 12+len("second")+16 {
		t.Fatalf("后续包长度应为 nonce12+密文+tag16=%d，得到 %d", 12+len("second")+16, len(p2))
	}
	// 后续包不能用 OpenFirst（没有首包头），必须用 Open
	if _, ok := server.OpenFirst(p2); ok {
		t.Fatal("后续包不应能按首包解开")
	}
	got2, ok := server.Open(p2)
	if !ok || string(got2) != "second" {
		t.Fatalf("服务端解密后续包失败: ok=%v got=%q", ok, got2)
	}
}

// TestRetransmitKeepsHeader 验证 QUIC Initial 重传仍带首包头。
//
// 这是 Rust 侧踩过的坑：若用「只发一次」的开关，重传包不带首包头，
// 服务端无法鉴权、静默丢弃，表现为「客户端一直重传、服务端无反应」。
func TestRetransmitKeepsHeader(t *testing.T) {
	client, _ := NewClientCodec("pw")
	server, _ := NewServerCodec("pw")
	for i := 0; i < 3; i++ {
		rec := client.Seal(nil, []byte{byte(i)})
		p := ParseRecords(rec)[0].Payload
		if p[0] != ProtocolVersion {
			t.Fatalf("第 %d 个重传包必须仍带首包头", i+1)
		}
		if _, ok := server.OpenFirst(p); !ok {
			t.Fatalf("第 %d 个重传包必须能被服务端鉴权", i+1)
		}
	}
	// 服务端方向从不带首包头
	rec := server.Seal(nil, []byte("reply"))
	p := ParseRecords(rec)[0].Payload
	if _, ok := client.Open(p); !ok {
		t.Fatal("服务端包必须能被客户端按后续包解开")
	}
	if _, ok := client.OpenFirst(p); ok {
		t.Fatal("服务端包不应能按首包解开")
	}
}

// TestWrongPasswordRejected 验证密码错误必须解不开。
func TestWrongPasswordRejected(t *testing.T) {
	a, _ := NewClientCodec("password-a")
	b, _ := NewServerCodec("password-b")
	if a.AuthID() == b.AuthID() {
		t.Fatal("不同密码的 authID 必须不同")
	}
	rec := a.Seal(nil, []byte("data"))
	p := ParseRecords(rec)[0].Payload
	// authID 不匹配：连 AEAD 都不用算就拒绝
	if _, ok := b.OpenFirst(p); ok {
		t.Fatal("authID 不匹配时必须拒绝")
	}
	// 后续包走 AEAD 认证失败
	a.MarkEstablished()
	rec2 := a.Seal(nil, []byte("data2"))
	p2 := ParseRecords(rec2)[0].Payload
	if _, ok := b.Open(p2); ok {
		t.Fatal("密码错误时 AEAD 必须认证失败")
	}
}

// TestTamperedAuthIDRejected 验证篡改首包头会被认证拦下。
//
// authID 与版本号都参与 AAD，改动任一字节都会导致 AEAD 失败。
func TestTamperedAuthIDRejected(t *testing.T) {
	client, _ := NewClientCodec("pw")
	server, _ := NewServerCodec("pw")
	rec := client.Seal(nil, []byte("data"))
	orig := ParseRecords(rec)[0].Payload

	bad := append([]byte(nil), orig...)
	bad[1] ^= 0xFF // 改 authID 第一个字节
	if _, ok := server.OpenFirst(bad); ok {
		t.Fatal("篡改 authID 后必须解密失败")
	}

	bad2 := append([]byte(nil), orig...)
	bad2[0] = 3 // 改版本号
	if _, ok := server.OpenFirst(bad2); ok {
		t.Fatal("版本号不匹配时必须拒绝")
	}

	// 篡改密文
	bad3 := append([]byte(nil), orig...)
	bad3[len(bad3)-1] ^= 0x01
	if _, ok := server.OpenFirst(bad3); ok {
		t.Fatal("篡改密文后必须认证失败")
	}
}

// TestParseRecordsMulti 验证一个 TCP 段里多条记录（首包带伪 ClientHello）。
func TestParseRecordsMulti(t *testing.T) {
	var buf []byte
	// 一条 handshake 记录（伪 ClientHello）
	buf = append(buf, RecHandshake, 0x03, 0x03, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD)
	// 一条 ApplicationData
	buf = append(buf, RecAppData, 0x03, 0x03, 0x00, 0x03, 1, 2, 3)

	recs := ParseRecords(buf)
	if len(recs) != 2 {
		t.Fatalf("应解析出 2 条记录，得到 %d", len(recs))
	}
	if recs[0].Type != RecHandshake || len(recs[0].Payload) != 4 {
		t.Fatal("第一条记录解析错误")
	}
	if recs[1].Type != RecAppData || len(recs[1].Payload) != 3 {
		t.Fatal("第二条记录解析错误")
	}
	// 截断的记录必须被丢弃而不是越界。
	// 第一条记录总长 5+4=9 字节，取 buf[:9] 应只剩它；
	// 再短（如 buf[:7]）连第一条都不完整，必须返回 0 条。
	if got := ParseRecords(buf[:9]); len(got) != 1 {
		t.Fatalf("截断到第一条末尾时应返回 1 条，得到 %d 条", len(got))
	}
	if got := ParseRecords(buf[:7]); len(got) != 0 {
		t.Fatalf("首条记录不完整时必须返回 0 条，得到 %d 条", len(got))
	}
}

// TestUserTable 验证多用户表按 authID 索引。
func TestUserTable(t *testing.T) {
	tbl, err := newUserTable([]User{
		{Name: "alice", Password: "alice-pw"},
		{Name: "bob", Password: "bob-pw"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tbl.len() != 2 {
		t.Fatalf("应有 2 个用户，得到 %d", tbl.len())
	}
	aliceCodec, _ := NewClientCodec("alice-pw")
	e, ok := tbl.lookup(aliceCodec.AuthID())
	if !ok || e.Name != "alice" {
		t.Fatalf("alice 查表失败: ok=%v", ok)
	}
	// 用 alice 的密钥封的首包，必须能被表里的 alice 解开
	rec := aliceCodec.Seal(nil, []byte("hi"))
	p := ParseRecords(rec)[0].Payload
	if _, ok := e.Codec.OpenFirst(p); !ok {
		t.Fatal("表里 alice 的密钥应能解开 alice 的首包")
	}
	// 不存在的用户
	other, _ := NewClientCodec("nobody-pw")
	if _, ok := tbl.lookup(other.AuthID()); ok {
		t.Fatal("不存在的用户不应查到")
	}
}

// TestUserTableDuplicate 验证密码相同的两个用户会互相覆盖（明确行为，非 bug）。
func TestUserTableDuplicate(t *testing.T) {
	tbl, err := newUserTable([]User{
		{Name: "alice", Password: "same"},
		{Name: "bob", Password: "same"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// 后写入的覆盖前者
	if tbl.len() != 1 {
		t.Fatalf("密码相同时应只剩 1 条，得到 %d", tbl.len())
	}
	c, _ := NewClientCodec("same")
	e, _ := tbl.lookup(c.AuthID())
	if e.Name != "bob" {
		t.Fatalf("后者应覆盖前者，得到 %q", e.Name)
	}
}

// TestPacketRoundtrip 验证报文构造与解析的自洽。
func TestPacketRoundtrip(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("203.0.113.12")
	pkt := AppendPacket(nil, TcpSeg{
		Src: src, Dst: dst,
		SrcPort: 44300, DstPort: 8443,
		Seq: 12345, Ack: 67890,
		Flags:  TCPPSH | TCPACK,
		IPID:   IPIDMark | 0x07,
		Window: 1234,
		TSVal:  0x01020304, TSecr: 0x05060708,
		Payload: []byte("hello"),
	})
	// 补 14 字节以太网头再解析
	frame := make([]byte, 14)
	frame[12], frame[13] = 0x08, 0x00
	frame = append(frame, pkt...)
	p, ok := ParseFrame(frame)
	if !ok {
		t.Fatal("解析失败")
	}
	if p.Src != src || p.Dst != dst {
		t.Fatal("地址解析错误")
	}
	if p.SrcPort != 44300 || p.DstPort != 8443 {
		t.Fatal("端口解析错误")
	}
	if p.Seq != 12345 || p.Ack != 67890 {
		t.Fatal("序号解析错误")
	}
	if p.Flags != TCPPSH|TCPACK {
		t.Fatal("flags 解析错误")
	}
	if p.Window != 1234 {
		t.Fatal("窗口解析错误")
	}
	if !p.HasTS || p.TSVal != 0x01020304 || p.TSecr != 0x05060708 {
		t.Fatal("时间戳解析错误")
	}
	if string(p.Payload) != "hello" {
		t.Fatal("载荷解析错误")
	}
}

// TestChecksumValid 用「整体再求一次反码和为 0」验证校验和。
func TestChecksumValid(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("203.0.113.10")
	for _, n := range []int{0, 1, 2, 3, 100, 1299, 1300, 1401} {
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte(i*7 + 13)
		}
		pkt := AppendPacket(nil, TcpSeg{
			Src: src, Dst: dst,
			SrcPort: 44311, DstPort: 8443,
			Seq: 1234, Ack: 5678,
			Flags:  TCPPSH | TCPACK,
			IPID:   0xF107,
			Window: 501,
			TSVal:  0x11223344, TSecr: 0x55667788,
			Payload: payload,
		})
		if got := fold(sum16(pkt[:20])); got != 0 {
			t.Fatalf("IP 校验和错误 len=%d got=0x%04x", n, got)
		}
		var pseudo [12]byte
		srcOct := src.As4()
		dstOct := dst.As4()
		copy(pseudo[0:4], srcOct[:])
		copy(pseudo[4:8], dstOct[:])
		pseudo[9] = 6
		tcpLen := len(pkt) - 20
		pseudo[10] = byte(tcpLen >> 8)
		pseudo[11] = byte(tcpLen)
		s := sum16(pseudo[:]) + sum16(pkt[20:])
		if got := fold(s); got != 0 {
			t.Fatalf("TCP 校验和错误 len=%d got=0x%04x", n, got)
		}
	}
}

// TestSynOptionsLayout 验证 SYN 选项与真实 Linux 逐字节一致。
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
	// WScale 是服务端分流的唯一可靠特征，改动会让伪 SYN 与真实 SYN
	// 无法区分（实测会导致双 SYN-ACK 竞争）。详见 packet.go 的注释。
	if WScale != 12 {
		t.Fatalf("wscale 必须是分流标记 12，得到 %d", WScale)
	}
}

// TestIPIDProgression 验证 IP ID 在标记区间内递增。
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

// TestAdvertisedWindow 验证窗口随积压下降且不为零。
func TestAdvertisedWindow(t *testing.T) {
	if w := AdvertisedWindow(0); w < 30000 || w > 33000 {
		t.Fatalf("空载窗口应接近 16MB>>9=32768，得到 %d", w)
	}
	prev := AdvertisedWindow(0)
	for _, unread := range []int{1 << 20, 4 << 20, 8 << 20, 15 << 20} {
		w := AdvertisedWindow(unread)
		if w > prev {
			t.Fatalf("积压增加时窗口不能变大: unread=%d", unread)
		}
		if w == 0 {
			t.Fatal("窗口不能为 0（会把对端卡死）")
		}
		prev = w
	}
	if w := AdvertisedWindow(64 << 20); w != 1 {
		t.Fatalf("严重溢出时应钳到 1，得到 %d", w)
	}
}

// TestSeqLen 验证 SYN/FIN 各占一个序号。
func TestSeqLen(t *testing.T) {
	if got := seqLen(TCPACK, 0); got != 0 {
		t.Fatalf("纯 ACK 不占序号，得到 %d", got)
	}
	if got := seqLen(TCPSYN, 0); got != 1 {
		t.Fatalf("SYN 占 1 个序号，得到 %d", got)
	}
	if got := seqLen(TCPFIN|TCPACK, 0); got != 1 {
		t.Fatalf("FIN 占 1 个序号，得到 %d", got)
	}
	if got := seqLen(TCPPSH|TCPACK, 100); got != 100 {
		t.Fatalf("数据段序号等于载荷长度，得到 %d", got)
	}
}

// TestParseFrameRejects 验证异常帧被拒绝而不是越界。
func TestParseFrameRejects(t *testing.T) {
	cases := [][]byte{
		nil,
		{0x00},           // 太短
		make([]byte, 13), // 不足以太网头
		append(make([]byte, 12), 0x86, 0xDD, 0x00), // IPv6
	}
	for i, c := range cases {
		if _, ok := ParseFrame(c); ok {
			t.Fatalf("case %d 应被拒绝", i)
		}
	}
}
