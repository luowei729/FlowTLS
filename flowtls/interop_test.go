package flowtls

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// 冻结向量门禁：与已归档的 Rust 参考实现对齐。
//
// 历史背景：本协议最早由 Rust 实现（现已冻结，见 docs/EVOLUTION.md）。
// 冻结前用它的单测导出了两份**黄金向量**并入库：
//
//	flowtls/testdata/wire_v2_rust.bin          —— 两条记录的字节流
//	flowtls/testdata/wire_v2_rust_authid.txt   —— 密码派生的 authID（hex）
//
// 这两个文件是 wire format v2 的**权威字节**。任何改动 HKDF 参数、
// AAD 组成、nonce 布局、记录头格式的行为都会让本测试立刻变红，
// 即使 Rust 代码已经不在主分支里。
//
// 如果向量文件不存在（比如在极简检出里），用 /tmp 的旧路径兼服。
const (
	frozenVectorPath = "testdata/wire_v2_rust.bin"
	frozenAuthIDPath = "testdata/wire_v2_rust_authid.txt"

	rustVectorPath = "/tmp/flowtls-rust-vector.bin"
	rustAuthIDPath = "/tmp/flowtls-rust-authid.txt"
	goVectorPath   = "/tmp/flowtls-go-vector.bin"
	interopPasswd  = "interop-password"
)

// readVector 优先读入库的冻结向量，其次读 /tmp 的临时文件。
func readVector(primary, fallback string) ([]byte, bool) {
	for _, path := range []string{primary, fallback} {
		if path == "" {
			continue
		}
		if blob, err := os.ReadFile(filepath.Clean(path)); err == nil {
			return blob, true
		}
	}
	return nil, false
}

// TestInteropRustToGo 用 Rust 加密的字节验证 Go 能解密。
//
// 覆盖的关键点：HKDF 参数（salt/info）、authID 派生、AAD 组成、
// nonce 布局、记录格式 —— 任何一项不一致都会解密失败。
func TestInteropRustToGo(t *testing.T) {
	blob, ok := readVector(frozenVectorPath, rustVectorPath)
	if !ok {
		t.Skipf("跳过：找不到冻结向量 %s（也不存在 %s）", frozenVectorPath, rustVectorPath)
	}
	codec, err := NewServerCodec(interopPasswd)
	if err != nil {
		t.Fatal(err)
	}
	// authID 必须与冻结参考实现完全一致
	if want, ok := readVector(frozenAuthIDPath, rustAuthIDPath); ok {
		wantID := string(want)
		id := codec.AuthID()
		if got := toHex(id[:]); got != wantID {
			t.Fatalf("authID 不一致：go=%s 冻结值=%s（HKDF 参数被改动了？）", got, wantID)
		}
	}

	want := []string{"first-datagram", "second-datagram"}
	off := 0
	for i, expect := range want {
		if off+4 > len(blob) {
			t.Fatalf("向量长度不足，缺第 %d 条", i+1)
		}
		n := int(binary.BigEndian.Uint32(blob[off:]))
		off += 4
		if off+n > len(blob) {
			t.Fatalf("向量长度不足，第 %d 条越界", i+1)
		}
		rec := blob[off : off+n]
		off += n

		recs := ParseRecords(rec)
		if len(recs) != 1 {
			t.Fatalf("第 %d 条应解析出 1 个记录，得到 %d", i+1, len(recs))
		}
		payload := recs[0].Payload

		var plain []byte
		var ok bool
		if i == 0 {
			plain, ok = codec.OpenFirst(payload)
		} else {
			plain, ok = codec.Open(payload)
		}
		if !ok {
			t.Fatalf("第 %d 条解密失败（Rust 与 Go 的格式不一致）", i+1)
		}
		if string(plain) != expect {
			t.Fatalf("第 %d 条明文不符：got=%q want=%q", i+1, plain, expect)
		}
	}
}

// TestInteropGoToRust 生成 Go 侧向量，并做自洽校验。
//
// Rust 侧的 `interop_consume::consume_go_vector` 会读取同一个文件。
// 这里的职责是「产出 + 自检」，真正的跨语言校验在 Rust 单测里完成。
func TestInteropGoToRust(t *testing.T) {
	codec, err := NewClientCodec(interopPasswd)
	if err != nil {
		t.Fatal(err)
	}
	first := codec.Seal(nil, []byte("go-first"))
	codec.MarkEstablished()
	second := codec.Seal(nil, []byte("go-second"))

	var blob []byte
	var l [4]byte
	for _, rec := range [][]byte{first, second} {
		binary.BigEndian.PutUint32(l[:], uint32(len(rec)))
		blob = append(blob, l[:]...)
		blob = append(blob, rec...)
	}
	if err := os.WriteFile(goVectorPath, blob, 0o644); err != nil {
		t.Skipf("跳过：无法写入 %s: %v", goVectorPath, err)
	}

	// 自洽校验：按 Rust 的消费顺序验证一次
	server, err := NewServerCodec(interopPasswd)
	if err != nil {
		t.Fatal(err)
	}
	off := 0
	for i, expect := range []string{"go-first", "go-second"} {
		n := int(binary.BigEndian.Uint32(blob[off:]))
		off += 4
		payload := ParseRecords(blob[off : off+n])[0].Payload
		off += n
		var plain []byte
		var ok bool
		if i == 0 {
			plain, ok = server.OpenFirst(payload)
		} else {
			plain, ok = server.Open(payload)
		}
		if !ok || string(plain) != expect {
			t.Fatalf("自洽校验失败 idx=%d ok=%v plain=%q", i, ok, plain)
		}
	}
	t.Logf("已写出 %s（%d 字节），可用 cargo test consume_go_vector 验证", goVectorPath, len(blob))
}

// toHex 把字节序列转成小写十六进制字符串。
func toHex(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexDigits[v>>4]
		out[i*2+1] = hexDigits[v&0x0F]
	}
	return string(out)
}
