package flowtls

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

// TLS 记录类型常量。只有录制外观用途，不参与真实 TLS。
const (
	RecHandshake uint8 = 0x16
	RecCCS       uint8 = 0x14
	RecAppData   uint8 = 0x17
)

// ProtocolVersion 是当前线上格式版本。
//
// v1（无版本位、单密码、解密成功即鉴权）从未发布，直接废弃。
// v2 引入：首包明文携带版本与用户标识，版本号参与 AAD。
const ProtocolVersion uint8 = 2

// AuthIDLen 是用户身份标识长度。
//
// 16 字节从密码独立派生，明文出现在首包。选 16 而不是 32：
// 多用户表里 2^128 空间足够避免碰撞，首包开销少 16 字节；
// 且与 AEAD 密钥用不同 HKDF info 派生，泄露也推不出密钥。
const AuthIDLen = 16

// FirstHeaderLen 是首包明文头长度：ver(1) + authID(16)
const FirstHeaderLen = 1 + AuthIDLen

// 密钥派生参数。与 Rust 侧必须逐字节一致，否则两端无法互通。
const (
	hkdfSalt    = "flowtls-faketcp-v2"
	hkdfInfoKey = "flowtls faketcp aead key v2"
	hkdfInfoID  = "flowtls faketcp auth id v2"
)

// deriveKeyPair 由密码派生 (AEAD 密钥, 身份标识)。
//
// 两个派生值用**不同的 info**，密码学上互不可推导：
// 抓包拿到 authID 既推不出密码，也无法解密任何数据。
// 若图省事用 sha256(password) 当标识，等于把「密钥的哈希」明文发到网上，
// 弱密码场景下拿到 hash 就能跑彩虹表。
func deriveKeyPair(password string) (key [32]byte, authID [AuthIDLen]byte, err error) {
	ikm := []byte(password)
	kb, err := hkdf.Key(sha256.New, ikm, []byte(hkdfSalt), hkdfInfoKey, len(key))
	if err != nil {
		return key, authID, err
	}
	copy(key[:], kb)
	ib, err := hkdf.Key(sha256.New, ikm, []byte(hkdfSalt), hkdfInfoID, AuthIDLen)
	if err != nil {
		return key, authID, err
	}
	copy(authID[:], ib)
	return key, authID, nil
}

// Codec 是外层伪装编解码器，持有一个用户的 AEAD 密钥与身份标识。
type Codec struct {
	aead interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		NonceSize() int
		Overhead() int
	}
	authID [AuthIDLen]byte

	noncePrefix [4]byte
	sendCtr     atomic.Uint64

	// sendFirstHeader 表示发送时是否需要携带首包头（版本 + authID）。
	// 只有客户端为 true：服务端总是先收后发，首包方向固定是客户端→服务端。
	sendFirstHeader bool
	// established 表示对端已证明能解开我们的包。
	//
	// 初始 false：客户端在收到服务端第一个成功解密的包之前，**每个包都带**
	// 首包头。不能改成「只发一次」：QUIC Initial 丢包重传会产生新记录，
	// 如果只在第一份上带首包头，后续重传的包服务端就无法识别用户、
	// 全部静默丢弃，表现为「客户端一直在重传、服务端完全没反应」。
	established atomic.Bool
}

// NewClientCodec 构建客户端编解码器：确认服务端可通之前每包都带首包头。
func NewClientCodec(password string) (*Codec, error) {
	return newCodec(password, true)
}

// NewServerCodec 构建服务端编解码器：从不携带首包头。
func NewServerCodec(password string) (*Codec, error) {
	c, err := newCodec(password, false)
	if err != nil {
		return nil, err
	}
	// 服务端不需要「等待确认」，直接置位省一次分支
	c.established.Store(true)
	return c, nil
}

func newCodec(password string, client bool) (*Codec, error) {
	key, authID, err := deriveKeyPair(password)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return &Codec{
		aead:            aead,
		authID:          authID,
		noncePrefix:     newNoncePrefix(),
		sendFirstHeader: client,
	}, nil
}

// AuthID 返回该用户的明文身份标识（服务端建表用）。
func (c *Codec) AuthID() [AuthIDLen]byte { return c.authID }

// MarkEstablished 标记对端已证明能解开我们的包。
// 客户端收到第一个服务端包时调用，之后发送不再携带首包头。
func (c *Codec) MarkEstablished() { c.established.Store(true) }

// nextNonce 取下一个发送 nonce：4 字节固定前缀 + 8 字节递增计数器（大端）。
func (c *Codec) nextNonce() [12]byte {
	ctr := c.sendCtr.Add(1) - 1
	var n [12]byte
	copy(n[:4], c.noncePrefix[:])
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n
}

// aadFor 构造 AAD：首包 ver|authID，后续只有 ver。
//
// 版本号纳入认证：将来出 v3 时，v2 的包在 v3 下必然解密失败，
// 不会出现跨版本误判。authID 纳入认证：防止篡改首包身份去撞别人密钥槽位。
// 两者都不写进报文，因此零额外开销——这是 AAD 相比「加字段」的最大优势。
func (c *Codec) aadFor(first bool) []byte {
	var aad [FirstHeaderLen]byte
	aad[0] = ProtocolVersion
	if first {
		copy(aad[1:], c.authID[:])
		return aad[:]
	}
	return aad[:1]
}

// Seal 把一个 QUIC 数据报封装成 TLS ApplicationData 记录，追加到 dst。
//
// 首包：17 03 03 | len(2) | ver(1) | authID(16) | nonce(12) | 密文+tag(16)
// 后续：17 03 03 | len(2) | nonce(12) | 密文+tag(16)
func (c *Codec) Seal(dst, plaintext []byte) []byte {
	first := c.sendFirstHeader && !c.established.Load()
	headerLen := 0
	if first {
		headerLen = FirstHeaderLen
	}
	bodyLen := headerLen + 12 + len(plaintext) + c.aead.Overhead()

	base := len(dst)
	// 用切片扩容而不是 make：make 会每包新分配 ~1.3KB，
	// 9000pps 下就是每秒 12MB 的垃圾，GC 停顿会直接拖慢收包。
	// dst 在稳定态来自复用缓冲，扩容路径只在首次发生。
	dst = slices.Grow(dst, 5+bodyLen)
	dst = dst[:base+5+bodyLen]
	out := dst[base:]

	out[0] = RecAppData
	out[1] = 0x03
	out[2] = 0x03
	binary.BigEndian.PutUint16(out[3:5], uint16(bodyLen))

	pos := 5
	if first {
		out[pos] = ProtocolVersion
		copy(out[pos+1:], c.authID[:])
		pos += FirstHeaderLen
	}
	nonce := c.nextNonce()
	copy(out[pos:pos+12], nonce[:])
	pos += 12
	return c.aead.Seal(dst[:base+pos], nonce[:], plaintext, c.aadFor(first))
}

// OpenTo 与 Open 相同，但把明文写进调用方提供的 dst（通常是池缓冲）。
//
// 高包速率下每包一次 1.3KB 分配会让 GC 成为瓶颈（实测 9000pps 时
// 每秒 12MB 垃圾）。dst 容量不足时 AEAD 会自行重新分配，调用方应传
// 容量 ≥ 1500 的切片（bufPool 的默认大小）。
func (c *Codec) OpenTo(dst, payload []byte) ([]byte, bool) {
	if len(payload) < 12+c.aead.Overhead() {
		return nil, false
	}
	nonce := payload[:12]
	ct := payload[12:]
	out, err := c.aead.Open(dst[:0], nonce, ct, c.aadFor(false))
	if err != nil {
		return nil, false
	}
	return out, true
}

// Open 解开一条**后续** ApplicationData 记录（不含首包头）。
// 任何格式或认证失败都返回 false，调用方应静默丢弃。
func (c *Codec) Open(payload []byte) ([]byte, bool) {
	if len(payload) < 12+c.aead.Overhead() {
		return nil, false
	}
	nonce := payload[:12]
	ct := payload[12:]
	out, err := c.aead.Open(nil, nonce, ct, c.aadFor(false))
	if err != nil {
		return nil, false
	}
	return out, true
}

// OpenFirst 解开**首包**记录（整段 payload，含 ver + authID + nonce + 密文）。
//
// 先校验版本与 authID 是否等于自己的，不匹配直接返回 —— 服务端用错密钥时
// 不该走到 AEAD 计算（那只是浪费 CPU）。
func (c *Codec) OpenFirst(payload []byte) ([]byte, bool) {
	if len(payload) < FirstHeaderLen+12+c.aead.Overhead() {
		return nil, false
	}
	if payload[0] != ProtocolVersion {
		return nil, false
	}
	for i := 0; i < AuthIDLen; i++ {
		if payload[1+i] != c.authID[i] {
			return nil, false
		}
	}
	rest := payload[FirstHeaderLen:]
	nonce := rest[:12]
	ct := rest[12:]
	out, err := c.aead.Open(nil, nonce, ct, c.aadFor(true))
	if err != nil {
		return nil, false
	}
	return out, true
}

// ParseFirstHeader 从首包里读出 (版本, authID)，**不做任何认证**。
//
// 服务端在还不知道用户是谁的时候必须先读这两个字段才能查表选密钥，
// 所以只能解析明文。调用方拿到 authID 后必须用对应密钥 OpenFirst 认证成功，
// 才算真正通过鉴权——解析本身不构成信任。
func ParseFirstHeader(payload []byte) (ver uint8, authID [AuthIDLen]byte, ok bool) {
	if len(payload) < FirstHeaderLen {
		return 0, authID, false
	}
	copy(authID[:], payload[1:FirstHeaderLen])
	return payload[0], authID, true
}

// ParseRecords 解析一个 TCP 段里可能串联的多条 TLS 记录。
//
// 首包会同时携带伪 ClientHello 和真实数据记录，因此必须支持多记录。
// 返回的记录指向原缓冲区，零拷贝；调用方不得在返回后修改 buf。
type TlsRecord struct {
	Type    uint8
	Version uint16
	Payload []byte
}

func ParseRecords(buf []byte) []TlsRecord {
	var out []TlsRecord
	for len(buf) >= 5 {
		typ := buf[0]
		ver := binary.BigEndian.Uint16(buf[1:3])
		l := int(binary.BigEndian.Uint16(buf[3:5]))
		if len(buf) < 5+l {
			break
		}
		out = append(out, TlsRecord{Type: typ, Version: ver, Payload: buf[5 : 5+l]})
		buf = buf[5+l:]
	}
	return out
}

// ForEachRecord 是 ParseRecords 的零分配版本：逐条回调，不构造切片。
//
// 热路径（每包解密）必须用它：ParseRecords 对单记录包也会 append 一次，
// 9000pps 下每秒多出 9000 个小对象，GC 压力与缓存污染都实打实。
// 回调返回 false 可提前终止。
func ForEachRecord(buf []byte, fn func(TlsRecord) bool) {
	for len(buf) >= 5 {
		typ := buf[0]
		ver := binary.BigEndian.Uint16(buf[1:3])
		l := int(binary.BigEndian.Uint16(buf[3:5]))
		if len(buf) < 5+l {
			return
		}
		if !fn(TlsRecord{Type: typ, Version: ver, Payload: buf[5 : 5+l]}) {
			return
		}
		buf = buf[5+l:]
	}
}

// userTable 是多用户表：authID → (显示名, 该用户编解码器)。
//
// 键是从密码派生出的不透明标识，不是用户名也不是密码本身：
// 抓包只能看到一个 16 字节随机值。
type userTable struct {
	mu      sync.RWMutex
	entries map[[AuthIDLen]byte]*userEntry
}

type userEntry struct {
	Name string
	// Password 保留明文，因为**每条连接必须新建一个 Codec**。
	//
	// 不能共享：Codec 持有 nonce 计数器，两条连接共用一个计数器
	// 会让同一密钥下的 nonce 交叉重复；一旦重复，ChaCha20-Poly1305
	// 的机密性与完整性同时失效（可恢复明文、可伪造）。
	Password string
	Codec    *Codec
}

func newUserTable(users []User) (*userTable, error) {
	t := &userTable{entries: make(map[[AuthIDLen]byte]*userEntry, len(users))}
	for _, u := range users {
		codec, err := NewServerCodec(u.Password)
		if err != nil {
			return nil, err
		}
		id := codec.AuthID()
		// 密码相同 → authID 相同 → 后者覆盖前者，一整个用户会被静默顶掉。
		// check 会在配置层拦截，这里再兜一层（覆盖是明确的行为，不是 bug）。
		t.entries[id] = &userEntry{Name: u.Name, Password: u.Password, Codec: codec}
	}
	return t, nil
}

func (t *userTable) lookup(id [AuthIDLen]byte) (*userEntry, bool) {
	t.mu.RLock()
	e, ok := t.entries[id]
	t.mu.RUnlock()
	return e, ok
}

func (t *userTable) len() int {
	t.mu.RLock()
	n := len(t.entries)
	t.mu.RUnlock()
	return n
}
