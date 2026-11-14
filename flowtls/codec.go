package flowtls

// 本文件是 legacy-rust:src/faketcp/codec.rs（前 300 行）的逐函数翻译。
//
// 对应关系：
//
//	REC_HANDSHAKE / REC_CCS / REC_APPDATA   → RecHandshake / RecCCS / RecAppData
//	PROTOCOL_VERSION                        → ProtocolVersion
//	AUTH_ID_LEN / FIRST_HEADER_LEN          → AuthIDLen / FirstHeaderLen
//	TlsRecord                               → TlsRecord
//	Obfs::{new_client,new_server}           → NewClientCodec / NewServerCodec
//	Obfs::mark_established                  → MarkEstablished
//	Obfs::auth_id                           → AuthID
//	Obfs::{seal,seal_into}                  → Seal / SealInto
//	Obfs::{open,open_first}                 → Open / OpenFirst
//	parse_first_header                      → ParseFirstHeader
//	parse_records                           → ParseRecords
//
// ClientHello / ServerHello 的构造在 handshake.go（对应 codec.rs 后半）。

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

// TLS 记录类型常量
const (
	RecHandshake uint8 = 0x16
	RecCCS       uint8 = 0x14
	RecAppData   uint8 = 0x17
)

// ProtocolVersion 是线上协议版本。
//
// v1（无版本位、单密码、解密成功即鉴权）从未发布，直接废弃，不做兼容。
// v2 引入两个变化：
//  1. 每条连接的首包明文携带版本号与用户标识（支持多用户）；
//  2. 版本号参与 AAD，跨版本重放/混淆解不开。
const ProtocolVersion uint8 = 2

// AuthIDLen 是用户身份标识长度。
//
// 16 字节从密码独立派生，明文出现在首包。
// 选 16 而不是 32：多用户表里 2^128 空间足够避免碰撞，首包开销少 16 字节；
// 且与 AEAD 密钥无派生关系，泄露它也推不出密钥。
const AuthIDLen = 16

// FirstHeaderLen 是首包明文头长度：version(1) + authID(16)。
const FirstHeaderLen = 1 + AuthIDLen

// TLS 记录头的固定开销：type(1) + version(2) + length(2)。
const tlsRecordHeaderLen = 5

// AEAD 的附加开销：nonce(12) + tag(16)。
const aeadOverhead = 12 + 16

// TlsRecord 是一条解析出来的 TLS 记录视图。
type TlsRecord struct {
	Type    uint8
	Version uint16
	Payload []byte
}

// Codec 是外层伪装编解码器，持有密码派生出的 AEAD 密钥与用户身份标识。
//
// 与 Rust `Obfs` 一一对应。并发安全：只有 atomic 字段与只读密钥。
type Codec struct {
	aead aeadCipher

	// authID 是该用户的明文身份标识，服务端靠它查表选密钥。
	//
	// 与 AEAD 密钥用**不同的 HKDF info** 派生，两者在密码学上无关：
	// 即使抓包拿到 authID，也无法借此解开任何密文。
	authID [AuthIDLen]byte
	// noncePrefix 是发送侧 nonce 的 4 字节固定前缀，进程启动时随机生成。
	// 与下面的 64 位计数器拼成 12 字节 nonce：同一密钥下计数器严格单调，
	// nonce 永不重复；前缀只用来降低「不同会话重启后计数器从 0 开始」撞车的概率。
	noncePrefix [4]byte
	// sendCtr 是发送侧 nonce 计数器。
	//
	// 原实现每包取 12 字节随机数：在 11000 pps 下是纯粹的用户态浪费。
	// AEAD 的安全性只要求「同一密钥下 nonce 不重复」，递增计数器完全满足。
	sendCtr atomic.Uint64
	// sendFirstHeader 表示发送时是否需要携带首包头（版本 + authID）。
	//
	// 只有**客户端**需要：服务端总是先收后发，首包方向固定是客户端→服务端。
	sendFirstHeader bool
	// established 表示对端是否已证明能解我们的包。
	//
	// 初始 false：客户端在收到服务端第一个成功解密的包之前，**每个包都带**
	// 首包头。不能改成「只发一次」：QUIC Initial 丢包重传会产生新记录，
	// 如果只在第一份上带首包头，后续重传的包服务端就无法识别用户、
	// 全部静默丢弃，表现为「客户端一直在重传、服务端完全没反应」。
	established atomic.Bool
}

// aeadCipher 是 chacha20poly1305 的最小使用面（便于测试替换）。
type aeadCipher interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	Overhead() int
}

// NewClientCodec 构建客户端侧编解码器。
//
// 发送时会在「确认服务端可通」之前带上首包头（版本 + authID）。
func NewClientCodec(password string) (*Codec, error) {
	c := deriveCodec(password)
	c.sendFirstHeader = true
	return c, nil
}

// NewServerCodec 构建服务端侧编解码器。
//
// 服务端从不携带首包头：它总是先收到客户端的首包才知道对方是谁。
func NewServerCodec(password string) (*Codec, error) {
	c := deriveCodec(password)
	c.sendFirstHeader = false
	// 服务端不需要「等待确认」，直接置位避免多一次判断
	c.established.Store(true)
	return c, nil
}

// deriveCodec 由用户密码派生 AEAD 密钥与身份标识。
//
// 两个派生值用不同的 info 标签，保证互不可推导：
//   - aead key：真正的加密密钥
//   - auth id ：明文身份标识，只用于服务端查表
func deriveCodec(password string) *Codec {
	// HKDF-SHA256，salt = "flowtls-faketcp-v2"
	key, err := hkdf.Key(sha256.New, []byte(password), []byte("flowtls-faketcp-v2"),
		"flowtls faketcp aead key v2", 32)
	if err != nil {
		// hkdf.Key 只在参数非法时失败；长度固定 32，实际不可能触发。
		panic("flowtls: hkdf aead key: " + err.Error())
	}
	authID, err := hkdf.Key(sha256.New, []byte(password), []byte("flowtls-faketcp-v2"),
		"flowtls faketcp auth id v2", AuthIDLen)
	if err != nil {
		panic("flowtls: hkdf auth id: " + err.Error())
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic("flowtls: chacha20poly1305: " + err.Error())
	}
	c := &Codec{aead: aead}
	copy(c.authID[:], authID)
	// nonce 前缀只需一次随机，之后全部走计数器
	c.noncePrefix = newNoncePrefix()
	return c
}

// MarkEstablished 标记对端已证明能解开我们的包（客户端收到第一个服务端包时
// 调用）。之后发送不再携带首包头。
func (c *Codec) MarkEstablished() { c.established.Store(true) }

// AuthID 返回该用户的明文身份标识（服务端建表用）。
func (c *Codec) AuthID() [AuthIDLen]byte { return c.authID }

// nextNonce 取下一个发送 nonce：4 字节固定前缀 + 8 字节递增计数器（大端）。
func (c *Codec) nextNonce() [12]byte {
	ctr := c.sendCtr.Add(1) - 1
	var nonce [12]byte
	copy(nonce[:4], c.noncePrefix[:])
	binary.BigEndian.PutUint64(nonce[4:], ctr)
	return nonce
}

// Seal 把一个 QUIC 数据报封装为 TLS ApplicationData 记录。
//
// 首包带 version + authID，后续包只带 nonce。
// 返回新分配的切片（热路径请用 SealInto 复用缓冲）。
func (c *Codec) Seal(plaintext []byte) []byte {
	out := make([]byte, 0, tlsRecordHeaderLen+FirstHeaderLen+aeadOverhead+len(plaintext))
	return c.SealInto(out, plaintext)
}

// SealInto 封装并写入调用方提供的缓冲（可反复复用，不分配）。
//
// 首包：`17 03 03 len(2) | ver(1) | authID(16) | nonce(12) | 密文+tag(16)`
// 后续：`17 03 03 len(2) | nonce(12) | 密文+tag(16)`
//
// 语义与 Rust `seal_into` 一致：把 out 调整到所需长度并从偏移 0 覆写。
func (c *Codec) SealInto(out []byte, plaintext []byte) []byte {
	// 用 Load 而不是 swap：要的是「是否已经确认可达」这个持续状态，
	// 不是「是不是第一次调用」。首包丢了重传时仍然要带首包头。
	first := c.sendFirstHeader && !c.established.Load()
	return c.sealIntoWith(out, plaintext, first)
}

// SealFirstInto 显式按「首包」封装（测试与特殊场景用）。
func (c *Codec) SealFirstInto(out []byte, plaintext []byte) []byte {
	return c.sealIntoWith(out, plaintext, true)
}

// sealIntoWith 是 SealInto / SealFirstInto 的共同实现。
func (c *Codec) sealIntoWith(out []byte, plaintext []byte, first bool) []byte {
	nonce := c.nextNonce()
	headerLen := 0
	if first {
		headerLen = FirstHeaderLen
	}
	// body = [ver+authID] + nonce(12) + 密文(len) + tag(16)
	bodyLen := headerLen + 12 + len(plaintext) + 16
	need := tlsRecordHeaderLen + bodyLen
	if cap(out) < need {
		out = make([]byte, need)
	} else {
		out = out[:need]
	}
	out[0] = RecAppData
	out[1] = 0x03
	out[2] = 0x03
	binary.BigEndian.PutUint16(out[3:5], uint16(bodyLen))
	pos := tlsRecordHeaderLen
	if first {
		out[pos] = ProtocolVersion
		copy(out[pos+1:pos+1+AuthIDLen], c.authID[:])
		pos += FirstHeaderLen
	}
	copy(out[pos:pos+12], nonce[:])
	pos += 12

	// 明文填入载荷区，之后**原地**加密：密文覆盖明文，tag 追加在末尾。
	plainLen := len(plaintext)
	copy(out[pos:pos+plainLen], plaintext)
	aad := c.aad(first)
	aadLen := 1
	if first {
		aadLen = FirstHeaderLen
	}
	// Seal 会把 tag 追加到 dst 末尾，因此先切出"明文区"作为 dst，
	// 得到「密文 + tag」正好填满 out[pos:]。
	ct := c.aead.Seal(out[pos:pos], nonce[:], out[pos:pos+plainLen], aad[:aadLen])
	// ct 的底层数组是 out[pos:] 的剩余容量，长度 = plainLen + 16
	copy(out[pos:], ct)
	return out
}

// aad 返回 AAD：首包是 `ver|authID`，后续包只有 `ver`。
//
// 把版本号纳入认证有实际作用：将来出 v3 时，v2 的包在 v3 下一定解密失败，
// 不会出现「老包被新版本误当成自己的包解」。
// 把 authID 也纳入，是防止有人篡改首包里的用户标识去撞别的密钥。
func (c *Codec) aad(first bool) [FirstHeaderLen]byte {
	var aad [FirstHeaderLen]byte
	aad[0] = ProtocolVersion
	if first {
		copy(aad[1:], c.authID[:])
	}
	return aad
}

// Open 解开一条**后续** ApplicationData 记录（不含首包头）。
// 任何格式或认证失败都返回 ok=false，调用方应静默丢弃。
func (c *Codec) Open(recordPayload []byte) ([]byte, bool) {
	if len(recordPayload) < aeadOverhead {
		return nil, false
	}
	nonce := recordPayload[:12]
	ct := recordPayload[12:]
	aad := c.aad(false)
	plain, err := c.aead.Open(nil, nonce, ct, aad[:1])
	if err != nil {
		return nil, false
	}
	return plain, true
}

// OpenTo 解开后续记录，明文写入 dst 的剩余容量（复用缓冲，稳态零分配）。
//
// 与 Open 的关系类似 Rust 的 seal/seal_into：语义相同，只是不分配。
func (c *Codec) OpenTo(dst []byte, recordPayload []byte) ([]byte, bool) {
	if len(recordPayload) < aeadOverhead {
		return nil, false
	}
	nonce := recordPayload[:12]
	ct := recordPayload[12:]
	aad := c.aad(false)
	if cap(dst) < len(ct)-c.aead.Overhead() {
		dst = make([]byte, 0, len(ct)-c.aead.Overhead())
	}
	out, err := c.aead.Open(dst[:0], nonce, ct, aad[:1])
	if err != nil {
		return nil, false
	}
	return out, true
}

// OpenFirst 解开**首包**记录（整段 payload，含 ver + authID + nonce + 密文）。
//
// 会先校验版本号与 authID 是否等于自己的，不匹配直接返回 false：
// 服务端用错密钥时不该走到 AEAD 计算（那只是浪费 CPU）。
func (c *Codec) OpenFirst(recordPayload []byte) ([]byte, bool) {
	if len(recordPayload) < FirstHeaderLen+aeadOverhead {
		return nil, false
	}
	if recordPayload[0] != ProtocolVersion {
		return nil, false
	}
	if string(recordPayload[1:FirstHeaderLen]) != string(c.authID[:]) {
		return nil, false
	}
	rest := recordPayload[FirstHeaderLen:]
	nonce := rest[:12]
	ct := rest[12:]
	aad := c.aad(true)
	plain, err := c.aead.Open(nil, nonce, ct, aad[:])
	if err != nil {
		return nil, false
	}
	return plain, true
}

// ParseFirstHeader 从首包里读出 `(版本, authID)`，**不做任何认证**。
//
// 服务端在还不知道用户是谁的时候必须先读这两个字段才能查表选密钥，
// 所以这里只能解析明文。调用方拿到 authID 后必须用对应密钥
// OpenFirst 认证成功，才算真正通过鉴权——解析本身不构成信任。
func ParseFirstHeader(recordPayload []byte) (ver byte, authID [AuthIDLen]byte, ok bool) {
	if len(recordPayload) < FirstHeaderLen {
		return 0, authID, false
	}
	copy(authID[:], recordPayload[1:FirstHeaderLen])
	return recordPayload[0], authID, true
}

// ParseRecords 解析一个 TCP 段里可能串联的多条 TLS 记录。
//
// 首包会同时携带伪 ClientHello 和真实数据记录，因此必须支持多记录。
// 语义与 Rust 一致：末尾不完整的记录直接丢弃（不报错）。
func ParseRecords(buf []byte) []TlsRecord {
	// 上限保护：一条 1400 字节的段里最多也就几百条记录
	out := make([]TlsRecord, 0, 4)
	for len(buf) >= tlsRecordHeaderLen {
		typ := buf[0]
		version := binary.BigEndian.Uint16(buf[1:3])
		length := int(binary.BigEndian.Uint16(buf[3:5]))
		if len(buf) < tlsRecordHeaderLen+length {
			break
		}
		out = append(out, TlsRecord{
			Type:    typ,
			Version: version,
			Payload: buf[tlsRecordHeaderLen : tlsRecordHeaderLen+length],
		})
		buf = buf[tlsRecordHeaderLen+length:]
	}
	return out
}
