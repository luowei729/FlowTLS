package flowtls

// 冻结向量门禁：验证 Go 实现能解开 Rust 实现的绝对字节。
//
// 向量由 legacy-rust 的单测导出（src/faketcp/codec.rs 的
// `interop_vector::export_vector`），格式为：
//
//	[len u32 BE][第一条记录][len u32 BE][第二条记录]
//
// 密码固定为 "interop-password"；第一条是客户端 seal（带 ver+authID 首包头），
// 第二条是 mark_established 之后 seal（不带首包头）。
//
// 这份向量钉的是**绝对字节**：任何改动 HKDF 参数 / AAD 组成 / nonce 布局 /
// 记录头格式都会让它立刻变红，不存在「两端同时改错一起通过」的盲区。

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

const interopPassword = "interop-password"

// loadRustVector 读取并切分冻结向量。
func loadRustVector(t *testing.T) (first, second []byte) {
	t.Helper()
	blob, err := os.ReadFile("testdata/wire_v2_rust.bin")
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

// TestInteropRustToGo 用 Rust 导出的字节验证 Go 的解密路径。
//
// 这是 docs/interop_check.sh 调用的门禁函数，名字不能改。
func TestInteropRustToGo(t *testing.T) {
	first, second := loadRustVector(t)

	// ---- authID 必须与 Rust 导出的 hex 完全一致 ----
	wantHex, err := os.ReadFile("testdata/wire_v2_rust_authid.txt")
	if err != nil {
		t.Fatalf("读取 authID 向量失败: %v", err)
	}
	c, err := NewClientCodec(interopPassword)
	if err != nil {
		t.Fatalf("构造客户端 codec 失败: %v", err)
	}
	gotHex := hex.EncodeToString(c.authID[:])
	if gotHex != strings.TrimSpace(string(wantHex)) {
		t.Fatalf("authID 派生结果与 Rust 不一致：\n got=%s\nwant=%s",
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
		t.Fatal("首包解密失败——HKDF/AAD/nonce 布局与 Rust 已不一致")
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
