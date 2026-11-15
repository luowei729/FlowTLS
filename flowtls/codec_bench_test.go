package flowtls

// 本文件是**加密开销基线**基准测试，不是功能单测。
//
// # 为什么要有它
//
// 现场反馈「CPU 开销大、带宽跑不高」，第一件要回答的是：
// **外层 AEAD 到底占多少 CPU**。猜测没有意义——
// 本机（amd64）与服务端（aarch64）的硬件加速能力完全不同：
//
//	amd64  : AES-NI + PCLMUL（AES-GCM 约 3~8 GB/s）、AVX2（ChaCha20 约 2 GB/s）
//	aarch64: ARMv8 Crypto（AES+PMULL，AES-GCM 约 2~4 GB/s）、NEON（ChaCha20 约 1 GB/s）
//
// 两者的相对排序一致（AES-GCM 更快），但**绝对耗时**必须各自实测，
// 所以这个文件要能在两端分别跑：
//
//	go test -run '^$' -bench . -benchtime 2s ./...              # amd64 本机
//	GOARCH=arm64 go test -c -o /tmp/flowtls-bench.test ./       # 交叉编译后拷到服务端跑
//
// # 读法
//
// 每个 op 是「一次 Seal + 一次 Open」（即一个数据报的完整收发加解密）。
// 1332 字节是 QUIC 载荷 MTU（见 quic/config.go 的 initialMTU），
// ns/op 除以 1332 即为单核可处理的字节速率上限。
//
// 100 Mbps 单向 = 约 9400 pps。若 ns/op 是 1000，那么单向加密占约 0.94% 单核；
// 若 ns/op 是 10000（10µs），则占约 9.4%——**这个量级才值得优化**。
//
// 因此本基准的用途是**排除法**：先确认外层 AEAD 不是瓶颈，
// 再去查 AF_PACKET syscall / quic-go 用户态路径。

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

// benchPayloadSize 与 quic/config.go 的 initialMTU 对齐。
const benchPayloadSize = 1332

// newBenchPayload 造一块伪随机明文（避免全零被某些实现特殊优化）。
func newBenchPayload() []byte {
	p := make([]byte, benchPayloadSize)
	for i := range p {
		p[i] = byte(i*31 + 7)
	}
	return p
}

// benchAEAD 跑「Seal + Open」一整轮，dst 复用（模拟热路径 SealInto/OpenTo）。
func benchAEAD(b *testing.B, aead cipher.AEAD) {
	b.Helper()
	plain := newBenchPayload()
	nonce := make([]byte, aead.NonceSize())
	sealed := make([]byte, 0, len(plain)+aead.Overhead())
	out := make([]byte, 0, len(plain))
	b.SetBytes(benchPayloadSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sealed = aead.Seal(sealed[:0], nonce, plain, nil)
		var err error
		out, err = aead.Open(out[:0], nonce, sealed, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
	_ = out
}

// BenchmarkAEADChaCha20Poly1305 是**当前线上算法**的基线。
func BenchmarkAEADChaCha20Poly1305(b *testing.B) {
	key := make([]byte, 32)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		b.Fatal(err)
	}
	benchAEAD(b, aead)
}

// BenchmarkAEADAES128GCM 是候选算法：ARMv8 与 amd64 都有硬件加速。
func BenchmarkAEADAES128GCM(b *testing.B) {
	key := make([]byte, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		b.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		b.Fatal(err)
	}
	benchAEAD(b, aead)
}

// BenchmarkAEADAES256GCM 是候选算法（密钥更长，硬件加速下差距很小）。
func BenchmarkAEADAES256GCM(b *testing.B) {
	key := make([]byte, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		b.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		b.Fatal(err)
	}
	benchAEAD(b, aead)
}

// BenchmarkChaCha20XOROnly 只跑 ChaCha20 流加密（不含认证）。
//
// 它给出「纯混淆」模式里 XOR 那部分的下限：
// 若这个值本身就和完整 AEAD 接近，说明「只混淆」省不下多少 CPU。
func BenchmarkChaCha20XOROnly(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, chacha20.NonceSize)
	plain := newBenchPayload()
	out := make([]byte, len(plain))
	// 循环外构造：NewUnauthenticatedCipher 每次要做一次 key setup，
	// 热路径是复用实例 + SetCounter，不能把它算进每包成本。
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(benchPayloadSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 不重置 counter：本来就是要测持续流加密的成本。
		// 1 秒基准只会消耗约 1~2 GB keystream，远低于 64GB 上限。
		c.XORKeyStream(out, plain)
	}
	_ = out
}

// BenchmarkPoly1305Tag 只算认证标签（不含加密）。
//
// 对应「obfs 模式」的认证开销：载荷明文 + Poly1305 tag。
// 与 ChaCha20 的 one-time key 派生合并后，就是一个完整的非加密认证路径。
func BenchmarkPoly1305Tag(b *testing.B) {
	var key [32]byte
	plain := newBenchPayload()
	var tag [16]byte
	b.SetBytes(benchPayloadSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		poly1305.Sum(&tag, plain, &key)
	}
	_ = tag
}

// BenchmarkCodecSealIntoOpenTo 走**真实热路径**：含 TLS 记录头、nonce 写入、
// 首包头判断（established 后不带）。它比裸 AEAD 更接近线上实测。
func BenchmarkCodecSealIntoOpenTo(b *testing.B) {
	c, err := NewClientCodec("bench-password")
	if err != nil {
		b.Fatal(err)
	}
	c.MarkEstablished()
	plain := newBenchPayload()
	buf := make([]byte, 0, 2048)
	out := make([]byte, 0, 2048)
	b.SetBytes(benchPayloadSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf = c.SealInto(buf[:0], plain)
		recs := ParseRecords(buf)
		if len(recs) == 0 {
			b.Fatal("no records")
		}
		var ok bool
		out, ok = c.OpenTo(out[:0], recs[0].Payload)
		if !ok {
			b.Fatal("open failed")
		}
	}
	_ = out
}

// BenchmarkCodecOpenAlloc 是**当前** handleIncoming 的路径：Open 内部 new。
//
// 保留它作为「改用 OpenTo 之后省了多少」的对照。
func BenchmarkCodecOpenAlloc(b *testing.B) {
	c, err := NewClientCodec("bench-password")
	if err != nil {
		b.Fatal(err)
	}
	c.MarkEstablished()
	plain := newBenchPayload()
	buf := c.Seal(plain)
	recs := ParseRecords(buf)
	b.SetBytes(benchPayloadSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := c.Open(recs[0].Payload); !ok {
			b.Fatal("open failed")
		}
	}
}
