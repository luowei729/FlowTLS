package flowtls

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
)

// 伪 TLS 握手表演。
//
// **这不是可选的装饰，是伪装的核心。**
//
// 没有它，线上的字节流是「TCP 三次握手 → 立刻 17 03 03 加密记录」。
// 真实 TLS 1.3 永远先有 ClientHello（16 03 01/03），任何按「TCP 连接的第一个
// 应用层字节」做分类的 DPI 都能一眼判定这不是 HTTPS。
//
// 与 Rust 版逐字节对齐：同样 512 字节量级、同样扩展集合、同样 GREASE、
// 同样以 pre_shared_key 结尾。改动这里必须同步 legacy-rust 的测试向量，
// 否则两端外观会不一致（虽然不影响互通，但会让「同一部署的两个方向看起来
// 是两个不同客户端」，本身就是可疑信号）。

// clientHelloTarget 是 ClientHello 的目标长度（含 5 字节记录头）。
//
// 实测真实 Chrome 的 ClientHello 是 1699 字节（带 X25519Kyber768 混合
// key_share），而我们早期版本只有 74 字节 —— 23 倍差距，
// 「ClientHello 小于 200 字节」就能直接命中。
//
// 这里取 512 附近的常见区间（不含 PQ 的传统浏览器量级），用 padding 扩展
// 补齐，大小每次略有随机，避免固定长度成为新特征。
const clientHelloTarget = 512

// greaseValues 是 RFC 8701 的 16 个 GREASE 值（形如 0x?a?a）。
//
// Chrome 会在 cipher suite 列表、extensions 列表、supported_groups、
// key_share 等处插入 GREASE，强制实现必须正确忽略未知值。
// 真实的 ClientHello 里几乎一定有它，没有反而显得可疑。
var greaseValues = [16]uint16{
	0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
	0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}

// grease 返回一个随机 GREASE 值。
func grease() uint16 {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return greaseValues[int(b[0])%len(greaseValues)]
}

// pushExt 追加一个 TLS 扩展：类型(2) + 长度(2) + 内容。
func pushExt(out []byte, typ uint16, body []byte) []byte {
	out = binary.BigEndian.AppendUint16(out, typ)
	out = binary.BigEndian.AppendUint16(out, uint16(len(body)))
	return append(out, body...)
}

// fillRandom 用密码学随机数填满 b。
//
// 用 crypto/rand 而不是 math/rand：这是发给 DPI 看的字节，
// 可预测的"随机"会让多次握手的 key_share/binder 之间出现关联，
// 而真实客户端每次都是密码学随机的。
func fillRandom(b []byte) {
	_, _ = rand.Read(b)
}

// BuildClientHello 构造一个结构完整的 TLS 1.3 ClientHello（Chrome 风格）。
//
// 早期版本只有 74 字节、2 个扩展（SNI + supported_versions），缺了：
//   - session_id（TLS 1.2 middlebox 兼容，Chrome/Firefox 都发 32 字节）
//   - key_share / supported_groups（**TLS 1.3 必需**，没有它根本握不了手）
//   - signature_algorithms（TLS 1.3 必需）
//   - ALPN、status_request、ec_point_formats 等常规扩展
//   - **early_data**：我们发完 ClientHello 立刻发 ApplicationData（QUIC 数据），
//     没有 early_data 这就是明文可见的协议违规
//     （ClientHello 后不可能有 0-RTT 数据）。
//     加上它之后「ClientHello → 立即 ApplicationData」就变成了合规的 0-RTT 流程。
//
// 另外补了 GREASE 和 padding：前者是真实浏览器的固定特征，
// 后者让长度落在真实区间内。
func BuildClientHello(sni string) []byte {
	// 用 IP 直连时真实浏览器/curl **不发送 SNI 扩展**（RFC 6066 要求
	// HostName 必须是域名，放 IP 属于协议违规）。
	//
	// 我们的默认部署正是 "server: 1.2.3.4:8443"，早期版本把 IP 当 SNI 发出去——
	// 「SNI 是裸 IP」是任何 DPI 都能一眼命中的特征。
	sniValid := sni != ""
	if sniValid {
		if _, err := netip.ParseAddr(sni); err == nil {
			sniValid = false
		}
	}

	exts := make([]byte, 0, 480)

	// GREASE 扩展必须放在第一个（Chrome 的习惯）
	exts = pushExt(exts, grease(), nil)

	// server_name (0x0000)，仅当 SNI 是合法域名时才发
	if sniValid {
		name := []byte(sni)
		sn := make([]byte, 0, 5+len(name))
		sn = binary.BigEndian.AppendUint16(sn, uint16(len(name)+3)) // server_name_list 长度
		sn = append(sn, 0)                                          // host_name
		sn = binary.BigEndian.AppendUint16(sn, uint16(len(name)))
		sn = append(sn, name...)
		exts = pushExt(exts, 0x0000, sn)
	}

	// extended_master_secret (0x0017)：空体，表示支持
	exts = pushExt(exts, 0x0017, nil)

	// renegotiation_info (0xff01)：长度 1 的 0（安全重协商）
	exts = pushExt(exts, 0xff01, []byte{0x00})

	// supported_groups (0x000a)：GREASE + x25519 + secp256r1 + secp384r1
	{
		g := make([]byte, 0, 10)
		g = binary.BigEndian.AppendUint16(g, grease())
		g = append(g, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18)
		body := binary.BigEndian.AppendUint16(nil, uint16(len(g)))
		body = append(body, g...)
		exts = pushExt(exts, 0x000a, body)
	}

	// ec_point_formats (0x000b)：只支持 uncompressed
	exts = pushExt(exts, 0x000b, []byte{0x01, 0x00})

	// session_ticket (0x0023)：空体表示支持
	exts = pushExt(exts, 0x0023, nil)

	// ALPN (0x0010)：h2 + http/1.1
	{
		body := make([]byte, 0, 12)
		body = binary.BigEndian.AppendUint16(body, 12)
		body = append(body, 0x02, 'h', '2')
		body = append(body, 0x08)
		body = append(body, "http/1.1"...)
		exts = pushExt(exts, 0x0010, body)
	}

	// status_request (0x0005)：OCSP stapling
	// 结构 = status_type(1) + responder_id_list(2) + request_extensions(2)
	exts = pushExt(exts, 0x0005, []byte{0x01, 0x00, 0x00, 0x00, 0x00})

	// signature_algorithms (0x000d)：TLS 1.3 必需
	{
		schemes := [8]uint16{
			0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
		}
		body := binary.BigEndian.AppendUint16(nil, uint16(len(schemes)*2))
		for _, s := range schemes {
			body = binary.BigEndian.AppendUint16(body, s)
		}
		exts = pushExt(exts, 0x000d, body)
	}

	// signed_certificate_timestamp (0x0012)：空体表示支持
	exts = pushExt(exts, 0x0012, nil)

	// key_share (0x0033)：GREASE 空 share + x25519 真实长度的随机 share。
	//
	// 没有这个扩展，TLS 1.3 服务端会直接拒绝，是「这不是真客户端」的铁证。
	{
		entries := make([]byte, 0, 41)
		// GREASE share（长度 1，内容 0）
		entries = binary.BigEndian.AppendUint16(entries, grease())
		entries = binary.BigEndian.AppendUint16(entries, 1)
		entries = append(entries, 0)
		// x25519 share：32 字节随机
		entries = append(entries, 0x00, 0x1d)
		entries = binary.BigEndian.AppendUint16(entries, 32)
		kx := make([]byte, 32)
		fillRandom(kx)
		entries = append(entries, kx...)

		body := binary.BigEndian.AppendUint16(nil, uint16(len(entries)))
		body = append(body, entries...)
		exts = pushExt(exts, 0x0033, body)
	}

	// psk_key_exchange_modes (0x002d)：psk_dhe_ke（与 early_data 配套必需）
	exts = pushExt(exts, 0x002d, []byte{0x01, 0x01})

	// supported_versions (0x002b)：TLS 1.3 + 1.2
	exts = pushExt(exts, 0x002b, []byte{0x04, 0x03, 0x04, 0x03, 0x03})

	// ---- 以下两个是为「ClientHello 后立刻发数据」服务的 ----

	// early_data (0x002a)：空体。声明愿意发 0-RTT 数据。
	exts = pushExt(exts, 0x002a, nil)

	// padding (0x0015)：先把长度补齐，再写必须位于最后的 pre_shared_key。
	// 目标总长 clientHelloTarget ± 小幅随机，避免固定长度本身成为特征。
	{
		const suitesLen = 16 // GREASE + 7 个真实套件，见下方
		// 5 记录头 + 4 握手头 + 2 legacy_version + 32 random + (1+32) session_id
		// + (2 + suites) + 2 compression + 2 extensions_len
		const fixed = 5 + 4 + 2 + 32 + 33 + 2 + suitesLen + 2 + 2
		var rb [1]byte
		_, _ = rand.Read(rb[:])
		target := clientHelloTarget + int(rb[0])%48
		// padding 扩展自身占 4 字节头；pre_shared_key 还在后面，先预留
		const pskLen = 4 + (2 + 2 + 96 + 4) + (2 + 1 + 32)
		avail := target - (fixed + len(exts) + pskLen + 4)
		if avail > 0 {
			exts = pushExt(exts, 0x0015, make([]byte, avail))
		}
	}

	// pre_shared_key (0x0029)：RFC 8446 要求它是**最后一个**扩展。
	//
	// 结构与 early_data 配套：identity 是伪造的 ticket，
	// binder 是随机字节（DPI 没有 PSK 无法验证 binder 真伪）。
	{
		const ticketLen = 96
		psk := make([]byte, 0, 4+ticketLen+4+2+33+4)
		// identities: 长度(2) + [ identity 长度(2) + ticket + age(4) ]
		psk = binary.BigEndian.AppendUint16(psk, uint16(2+ticketLen+4))
		psk = binary.BigEndian.AppendUint16(psk, ticketLen)
		ticket := make([]byte, ticketLen)
		fillRandom(ticket)
		psk = append(psk, ticket...)
		var age [4]byte
		fillRandom(age[:])
		psk = append(psk, age[:]...) // obfuscated_ticket_age
		// binders: 长度(2) + [ binder 长度(1) + 32 字节 ]
		psk = binary.BigEndian.AppendUint16(psk, 1+32)
		psk = append(psk, 32)
		binder := make([]byte, 32)
		fillRandom(binder)
		psk = append(psk, binder...)
		exts = pushExt(exts, 0x0029, psk)
	}

	// ---- 拼 ClientHello 主体 ----
	hs := make([]byte, 0, 64+len(exts))
	hs = append(hs, 0x03, 0x03) // legacy_version
	rnd := make([]byte, 32)
	fillRandom(rnd)
	hs = append(hs, rnd...)
	// legacy_session_id：Chrome/Firefox 都发 32 字节，用于 middlebox 兼容。
	// 早期版本这里是空的（0 长度），本身就是个不常见的做法。
	hs = append(hs, 32)
	sid := make([]byte, 32)
	fillRandom(sid)
	hs = append(hs, sid...)
	// cipher suites：GREASE + TLS 1.3 三个 + 常见 ECDHE 四个
	hs = binary.BigEndian.AppendUint16(hs, 16)
	for _, cs := range []uint16{
		grease(),
		0x1301, // TLS_AES_128_GCM_SHA256
		0x1302, // TLS_AES_256_GCM_SHA384
		0x1303, // TLS_CHACHA20_POLY1305_SHA256
		0xc02b, // ECDHE_ECDSA_AES_128_GCM
		0xc02f, // ECDHE_RSA_AES_128_GCM
		0xc02c, // ECDHE_ECDSA_AES_256_GCM
		0xc030, // ECDHE_RSA_AES_256_GCM
	} {
		hs = binary.BigEndian.AppendUint16(hs, cs)
	}
	hs = append(hs, 0x01, 0x00) // legacy_compression_methods: null
	hs = binary.BigEndian.AppendUint16(hs, uint16(len(exts)))
	hs = append(hs, exts...)

	// ---- 握手头 + 记录头 ----
	body := make([]byte, 0, 4+len(hs))
	body = append(body, 0x01) // handshake 类型：client_hello
	body = append(body, byte(len(hs)>>16), byte(len(hs)>>8), byte(len(hs)))
	body = append(body, hs...)

	out := make([]byte, 0, 5+len(body))
	out = append(out, RecHandshake)
	out = append(out, 0x03, 0x01) // ClientHello 的记录版本用 TLS1.0，与真实浏览器一致
	out = binary.BigEndian.AppendUint16(out, uint16(len(body)))
	out = append(out, body...)
	return out
}

// BuildServerHello 构造服务器侧的握手响应（ServerHello + CCS + 加密握手记录）。
//
// 早期版本在 CCS 之后发的是 **0x16 明文**的假 Finished 记录。
// 真实 TLS 1.3 里 ChangeCipherSpec 之后再出现明文握手记录是**协议违规**：
// ServerHello 之后的所有握手消息（EncryptedExtensions / Certificate /
// CertificateVerify / Finished）都必须包在 0x17 加密记录里，DPI 一看就知道。
//
// 现在按真实顺序构造：
//
//	16 03 03 <len>  02 ...            ServerHello（明文，含 key_share）
//	14 03 03 00 01 01                 ChangeCipherSpec（middlebox 兼容）
//	17 03 03 <len>  <随机密文>         加密的握手消息（长度取真实量级）
//
// 密文内容用随机字节：DPI 没有会话密钥无法验证，长度与真实证书链量级一致即可。
func BuildServerHello() []byte {
	out := make([]byte, 0, 900)

	// ---- ServerHello ----
	hs := make([]byte, 0, 90)
	hs = append(hs, 0x03, 0x03) // legacy_version
	rnd := make([]byte, 32)
	fillRandom(rnd)
	hs = append(hs, rnd...)
	// legacy_session_id_echo：必须回显客户端的 session_id。
	// 我们无法真的读到客户端的（ClientHello 是本地构造的、没保存），
	// 但真实客户端会发 32 字节，这里同样给 32 字节随机值保持长度一致。
	hs = append(hs, 32)
	sid := make([]byte, 32)
	fillRandom(sid)
	hs = append(hs, sid...)
	hs = append(hs, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	hs = append(hs, 0x00)       // legacy_compression_method

	// 扩展：supported_versions + key_share（都是 TLS 1.3 必需）
	exts := make([]byte, 0, 48)
	exts = pushExt(exts, 0x002b, []byte{0x03, 0x04}) // supported_versions = TLS1.3
	{
		// key_share：x25519 + 32 字节"公钥"
		ks := make([]byte, 0, 36)
		ks = append(ks, 0x00, 0x1d)
		ks = binary.BigEndian.AppendUint16(ks, 32)
		pk := make([]byte, 32)
		fillRandom(pk)
		ks = append(ks, pk...)
		exts = pushExt(exts, 0x0033, ks)
	}
	hs = binary.BigEndian.AppendUint16(hs, uint16(len(exts)))
	hs = append(hs, exts...)

	body := make([]byte, 0, 4+len(hs))
	body = append(body, 0x02) // handshake 类型：server_hello
	body = append(body, byte(len(hs)>>16), byte(len(hs)>>8), byte(len(hs)))
	body = append(body, hs...)

	out = append(out, RecHandshake)
	out = append(out, 0x03, 0x03)
	out = binary.BigEndian.AppendUint16(out, uint16(len(body)))
	out = append(out, body...)

	// ---- ChangeCipherSpec（TLS 1.3 为 middlebox 兼容保留）----
	out = append(out, RecCCS, 0x03, 0x03, 0x00, 0x01, 0x01)

	// ---- 加密的握手消息（EncryptedExtensions + Certificate + CertVerify + Finished）----
	// 用 0x17 记录类型 + 随机密文。长度取 512~703 的量级：
	// 一张 ECDSA 自签证书链 + 三个签名结构的实际大小就在这个范围。
	var rb [1]byte
	_, _ = rand.Read(rb[:])
	encLen := 512 + int(rb[0])%192
	enc := make([]byte, encLen)
	fillRandom(enc)
	out = append(out, RecAppData)
	out = append(out, 0x03, 0x03)
	out = binary.BigEndian.AppendUint16(out, uint16(encLen))
	out = append(out, enc...)

	return out
}
