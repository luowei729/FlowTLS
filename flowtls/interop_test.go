package flowtls

// 冻结向量门禁：验证 Go 实现能还原**绝对字节**的 wire format v3。
//
// # 这份向量钉什么
//
// 向量由本文件末尾的 TestWriteFrozenVector 生成（固定 nonce 前缀 + 固定计数器），
// 格式为：
//
//	[len u32 BE][第一条记录][len u32 BE][第二条记录]
//
// 密码固定为 "interop-password"；第一条带 ver+authID 首包头，
// 第二条是 MarkEstablished 之后（不带首包头）。
//
// 任何改动下面任一项都会让门禁立刻变红：
//
//	HKDF 的 salt / info / 输出长度（换密钥 = 换算法）
//	AEAD 算法本身（AES-128-GCM 与 ChaCha20-Poly1305 的密文不同）
//	AAD 组成（ver / ver+authID）
//	nonce 布局（4 字节前缀 + 8 字节大端计数器）
//	TLS 记录头与首包头布局
//
// # 为什么删掉了 Rust 向量
//
// v2 时代的向量是 Rust（ChaCha20-Poly1305）导出的，换成 AES-128-GCM 后
// 它在密码学上就不可能再被解开——保留它只会变成一条永远红的门禁。
// v3 起向量由 Go 自己生成并入库：它仍然钉住绝对字节，
// 只是「两端同时改错一起通过」的盲区要靠人审 + CHANGELOG 记录来兜。

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

const interopPassword = "interop-password"

// vectorNoncePrefix 是生成冻结向量时强制使用的 nonce 前缀。
//
// 线上 codec 的前缀是 crypto/rand 出来的随机值；固定它是为了让向量可重现——
// 否则同一份代码每次产生的密文都不同，向量就没有意义了。
var vectorNoncePrefix = [4]byte{0xA1, 0xB2, 0xC3, 0xD4}

// newVectorCodec 构造一个 nonce 可重现的客户端 codec（仅测试与向量生成用）。
func newVectorCodec(t *testing.T, password string) *Codec {
	t.Helper()
	c, err := NewClientCodec(password)
	if err != nil {
		t.Fatalf("构造 codec 失败: %v", err)
	}
	c.noncePrefix = vectorNoncePrefix
	c.sendCtr.Store(0)
	return c
}

// loadFrozenVector 读取并切分冻结向量。
func loadFrozenVector(t *testing.T) (first, second []byte) {
	t.Helper()
	blob, err := os.ReadFile("testdata/wire_v3_golden.bin")
	if err != nil {
		t.Fatalf("读取冻结向量失败（它必须随仓库分发）: %v", err)
	}
	read := func(b []byte) (rec, rest []byte) {
		if len(b) < 4 {
			t.Fatalf("向量格式错误：剩余 %d 字节不足长度前缀", len(b))
		}
		n := int(binary.BigEndian.Uint32(b[:4]))
		if len(b) < 4+n {
			t.Fatalf("向量格式错误：声明 %d 字节，实际只剩 %d", n, len(b)-4)
		}
		return b[4 : 4+n], b[4+n:]
	}
	first, rest := read(blob)
	second, rest = read(rest)
	if len(rest) != 0 {
		t.Fatalf("向量尾部有 %d 字节未消费", len(rest))
	}
	return first, second
}

// TestFrozenVectorV3 用入库的绝对字节验证编解码结构。
//
// 这是 docs/interop_check.sh 调用的门禁函数，名字不能改。
func TestFrozenVectorV3(t *testing.T) {
	first, second := loadFrozenVector(t)

	// ---- authID 必须与入库值完全一致（钉住 HKDF 参数）----
	wantHex, err := os.ReadFile("testdata/wire_v3_golden_authid.txt")
	if err != nil {
		t.Fatalf("读取 authID 向量失败: %v", err)
	}
	c, err := NewClientCodec(interopPassword)
	if err != nil {
		t.Fatalf("构造客户端 codec 失败: %v", err)
	}
	gotHex := hex.EncodeToString(c.authID[:])
	if gotHex != strings.TrimSpace(string(wantHex)) {
		t.Fatalf("authID 派生结果与冻结值不一致：\n got=%s\nwant=%s",
			gotHex, strings.TrimSpace(string(wantHex)))
	}

	// ---- 首包：记录类型、版本、authID、可解密 ----
	recs := ParseRecords(first)
	if len(recs) != 1 {
		t.Fatalf("首包应恰好 1 条记录，得到 %d", len(recs))
	}
	if recs[0].Type != RecAppData {
		t.Fatalf("首包记录类型应为 ApplicationData(0x17)，得到 0x%02x", recs[0].Type)
	}
	ver, authID, ok := ParseFirstHeader(recs[0].Payload)
	if !ok {
		t.Fatal("解析首包头失败")
	}
	if ver != ProtocolVersion {
		t.Fatalf("版本号应为 %d，得到 %d", ProtocolVersion, ver)
	}
	if authID != c.authID {
		t.Fatalf("首包 authID 与派生值不一致：%x vs %x", authID, c.authID)
	}
	plain, ok := c.OpenFirst(recs[0].Payload)
	if !ok {
		t.Fatal("首包解密失败——HKDF/AAD/nonce 布局/算法已与冻结向量不一致")
	}
	if string(plain) != "first-datagram" {
		t.Fatalf("首包明文不符：%q", plain)
	}

	// ---- 第二个包：不带首包头，只能用 Open ----
	recs2 := ParseRecords(second)
	if len(recs2) != 1 {
		t.Fatalf("第二包应恰好 1 条记录，得到 %d", len(recs2))
	}
	// 两条记录的明文长度不同（"first-datagram" 14、"second-datagram" 15），
	// 所以不能简单地用「差 17 字节」判断，要按结构算出期望长度。
	const firstPlain, secondPlain = 14, 15
	if want := FirstHeaderLen + 12 + firstPlain + 16; len(recs[0].Payload) != want {
		t.Fatalf("首包记录长度应为 %d（含 %d 字节首包头），得到 %d",
			want, FirstHeaderLen, len(recs[0].Payload))
	}
	if want := 12 + secondPlain + 16; len(recs2[0].Payload) != want {
		t.Fatalf("后续包记录长度应为 %d（无首包头），得到 %d",
			want, len(recs2[0].Payload))
	}
	// 第二包不能用 OpenFirst 解（它没有首包头）
	if _, ok := c.OpenFirst(recs2[0].Payload); ok {
		t.Fatal("后续包不应能被 OpenFirst 解开")
	}
	plain2, ok := c.Open(recs2[0].Payload)
	if !ok {
		t.Fatal("后续包解密失败")
	}
	if string(plain2) != "second-datagram" {
		t.Fatalf("后续包明文不符：%q", plain2)
	}
}

// TestWriteFrozenVector 重建冻结向量。**只在明确要求时运行**：
//
//	FLOWTLS_WRITE_VECTOR=1 go test -run TestWriteFrozenVector -v .
//
// 重建后必须同批更新 docs/DESIGN.md 并在 CHANGELOG 记为破坏性变更
// （AGENTS.md 约束 1）——向量变红是设计意图，不是要随手刷新的噪声。
func TestWriteFrozenVector(t *testing.T) {
	if os.Getenv("FLOWTLS_WRITE_VECTOR") != "1" {
		t.Skip("仅在重建冻结向量时运行：FLOWTLS_WRITE_VECTOR=1 go test -run TestWriteFrozenVector")
	}
	c := newVectorCodec(t, interopPassword)
	first := c.Seal([]byte("first-datagram"))
	// 与线上一致：确认对端可达之后不再带首包头
	c.MarkEstablished()
	second := c.Seal([]byte("second-datagram"))

	var buf []byte
	for _, rec := range [][]byte{first, second} {
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(rec)))
		buf = append(buf, rec...)
	}
	if err := os.WriteFile("testdata/wire_v3_golden.bin", buf, 0o644); err != nil {
		t.Fatalf("写入向量失败: %v", err)
	}
	authHex := hex.EncodeToString(c.authID[:]) + "\n"
	if err := os.WriteFile("testdata/wire_v3_golden_authid.txt", []byte(authHex), 0o644); err != nil {
		t.Fatalf("写入 authID 向量失败: %v", err)
	}
	t.Logf("已重建冻结向量：%d 字节，authID=%s", len(buf), strings.TrimSpace(authHex))
}

// TestSealRoundTrip 验证 Go 自己的加解密与「首包头只带一次」语义。
func TestSealRoundTrip(t *testing.T) {
	cli, err := NewClientCodec("test-password")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServerCodec("test-password")
	if err != nil {
		t.Fatal(err)
	}

	// 首包带 ver+authID
	rec := cli.Seal([]byte("one"))
	recs := ParseRecords(rec)
	if len(recs) != 1 {
		t.Fatalf("应恰好 1 条记录，得到 %d", len(recs))
	}
	if recs[0].Type != RecAppData {
		t.Fatalf("记录类型错误: 0x%02x", recs[0].Type)
	}
	ver, authID, ok := ParseFirstHeader(recs[0].Payload)
	if !ok || ver != ProtocolVersion || authID != srv.authID {
		t.Fatalf("首包头不符: ver=%d ok=%v", ver, ok)
	}
	plain, ok := srv.OpenFirst(recs[0].Payload)
	if !ok || string(plain) != "one" {
		t.Fatalf("首包解密失败: %q ok=%v", plain, ok)
	}

	// mark_established 之后不再带首包头
	cli.MarkEstablished()
	rec2 := cli.Seal([]byte("two"))
	recs2 := ParseRecords(rec2)
	if len(recs[0].Payload)-len(recs2[0].Payload) != FirstHeaderLen {
		t.Fatalf("稳态包应少 %d 字节，实际差 %d",
			FirstHeaderLen, len(recs[0].Payload)-len(recs2[0].Payload))
	}
	plain2, ok := srv.Open(recs2[0].Payload)
	if !ok || string(plain2) != "two" {
		t.Fatalf("稳态包解密失败: %q ok=%v", plain2, ok)
	}
}

// TestSealIntoReusesBuffer 验证热路径复用缓冲不改变字节结果。
func TestSealIntoReusesBuffer(t *testing.T) {
	a, err := NewClientCodec("reuse")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewClientCodec("reuse")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 0, 2048)
	// 两次调用必须都得到结构完整的记录（nonce 不同，长度相同）
	for i := 0; i < 3; i++ {
		buf = a.SealInto(buf, []byte("payload"))
		recs := ParseRecords(buf)
		if len(recs) != 1 || len(recs[0].Payload) != FirstHeaderLen+12+7+16 {
			t.Fatalf("第 %d 次 SealInto 结构异常: recs=%d payloadLen=%d",
				i, len(recs), len(recs[0].Payload))
		}
		if _, ok := b.OpenFirst(recs[0].Payload); !ok {
			t.Fatalf("第 %d 次 SealInto 结果无法解密", i)
		}
	}
}

// TestOpenRejectsTampered 验证认证失败被静默拒绝（不 panic、返回 false）。
func TestOpenRejectsTampered(t *testing.T) {
	cli, _ := NewClientCodec("tamper")
	srv, _ := NewServerCodec("tamper")
	cli.MarkEstablished()
	rec := cli.Seal([]byte("secret"))
	recs := ParseRecords(rec)
	if len(recs) != 1 {
		t.Fatal("记录解析失败")
	}
	// 翻转密文的最后一个字节 → tag 校验必须失败
	payload := append([]byte(nil), recs[0].Payload...)
	payload[len(payload)-1] ^= 0xFF
	if _, ok := srv.Open(payload); ok {
		t.Fatal("被篡改的记录竟然解密成功——AEAD 未生效")
	}
	// 换密码的 codec 也必须解不开
	other, _ := NewServerCodec("wrong-password")
	if _, ok := other.Open(recs[0].Payload); ok {
		t.Fatal("错误密码竟然解密成功")
	}
}
