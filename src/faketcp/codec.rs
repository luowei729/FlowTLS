//! 伪 TLS 记录编解码与外层 AEAD。
//!
//! 线上每个报文都是「TLS 记录头 + nonce + ChaCha20-Poly1305 密文」。
//! 记录头只是外观，真正的安全性来自 QUIC 自身的 TLS 1.3；
//! 外层 AEAD 的作用是让未授权方连 QUIC 状态机都进不来（解密失败即丢弃）。

use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand::{Rng, RngCore};
use sha2::Sha256;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// TLS 记录类型常量
pub const REC_HANDSHAKE: u8 = 0x16;
pub const REC_CCS: u8 = 0x14;
pub const REC_APPDATA: u8 = 0x17;

/// 线上协议版本。
///
/// v1（无版本位、单密码、解密成功即鉴权）从未发布，直接废弃，不做兼容。
/// v2 引入两个变化：
///   1. 每条连接的首包明文携带版本号与用户标识（支持多用户）；
///   2. 版本号参与 AAD，跨版本重放/混淆解不开。
pub const PROTOCOL_VERSION: u8 = 2;

/// 用户身份标识长度。
///
/// 16 字节从密码独立派生，明文出现在首包。
/// 选 16 而不是 32：多用户表里 2^128 空间足够避免碰撞，
/// 首包开销少 16 字节；且与 AEAD 密钥无派生关系，泄露它也推不出密钥。
pub const AUTH_ID_LEN: usize = 16;

/// 首包明文头长度：version(1) + authID(16)
pub const FIRST_HEADER_LEN: usize = 1 + AUTH_ID_LEN;

/// 一条解析出来的 TLS 记录视图
#[allow(dead_code)] // version 保留：核对记录头是否为 0x0303 时要看
pub struct TlsRecord<'a> {
    pub typ: u8,
    pub version: u16,
    pub payload: &'a [u8],
}

/// 外层伪装编解码器，持有密码派生出的 AEAD 密钥与用户身份标识。
pub struct Obfs {
    cipher: ChaCha20Poly1305,
    /// 该用户的明文身份标识，服务端靠它查表选密钥。
    ///
    /// 与 AEAD 密钥用**不同的 HKDF info** 派生，两者在密码学上无关：
    /// 即使抓包拿到 auth_id，也无法借此解开任何密文。
    auth_id: [u8; AUTH_ID_LEN],
    /// 发送侧 nonce 的固定前缀（4 字节），进程启动时随机生成。
    /// 与下面的 64 位计数器拼成 12 字节 nonce：
    /// 同一密钥下进程内计数器严格单调，nonce 永不重复，
    /// 前缀只用来降低「不同会话重启后计数器从 0 开始」撞车的概率。
    nonce_prefix: [u8; 4],
    /// 发送侧 nonce 计数器。
    /// 原实现每包调 `rand::thread_rng()` 取 12 字节随机数：
    /// thread_rng 要访问线程局部状态并跑 ChaCha12 CSPRNG，
    /// 在 11000 pps 下是纯粹的用户态浪费。AEAD 的安全性只要求
    /// 「同一密钥下 nonce 不重复」，递增计数器完全满足，且无锁无随机数生成。
    send_ctr: AtomicU64,
    /// 发送时是否需要携带首包头（版本 + authID）。
    ///
    /// 只有**客户端**需要：服务端总是先收后发，首包方向固定是客户端→服务端。
    send_first_header: bool,
    /// 对端是否已证明能解我们的包。
    ///
    /// 初始 false：客户端在收到服务端第一个成功解密的包之前，**每个包都带**
    /// 首包头。不能改成「只发一次」：QUIC Initial 丢包重传时会产生新记录，
    /// 如果只在第一份上带首包头，后续重传的包服务端就无法识别用户、
    /// 全部静默丢弃，表现为「客户端一直在重传、服务端完全没反应」。
    /// 确认可达后置 true，此后每包不再多带 17 字节。
    established: AtomicBool,
}

impl Obfs {
    /// 构建客户端侧编解码器。
    ///
    /// 发送时会在「确认服务端可通」之前带上首包头（版本 + authID）。
    pub fn new_client(password: &str) -> Self {
        let mut obfs = Self::derive(password);
        obfs.send_first_header = true;
        obfs
    }

    /// 构建服务端侧编解码器。
    ///
    /// 服务端从不携带首包头：它总是先收到客户端的首包才知道对方是谁。
    pub fn new_server(password: &str) -> Self {
        let mut obfs = Self::derive(password);
        obfs.send_first_header = false;
        // 服务端不需要「等待确认」，直接置位避免多一次判断
        obfs.established.store(true, Ordering::Relaxed);
        obfs
    }

    /// 标记对端已证明能解开我们的包（客户端收到第一个服务端包时调用）。
    /// 之后发送不再携带首包头。
    pub fn mark_established(&self) {
        self.established.store(true, Ordering::Relaxed);
    }

    /// 由用户密码派生 AEAD 密钥与身份标识。
    ///
    /// 两个派生值用不同的 info 标签，保证互不可推导：
    ///   - aead key：真正的加密密钥
    ///   - auth id ：明文身份标识，只用于服务端查表
    fn derive(password: &str) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"flowtls-faketcp-v2"), password.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(b"flowtls faketcp aead key v2", &mut key)
            .expect("hkdf expand");
        let mut auth_id = [0u8; AUTH_ID_LEN];
        hk.expand(b"flowtls faketcp auth id v2", &mut auth_id)
            .expect("hkdf expand");
        // nonce 前缀只需一次随机，之后全部走计数器
        let mut nonce_prefix = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut nonce_prefix);
        Self {
            cipher: ChaCha20Poly1305::new(&key.into()),
            auth_id,
            nonce_prefix,
            send_ctr: AtomicU64::new(0),
            send_first_header: false,
            established: AtomicBool::new(false),
        }
    }

    /// 该用户的明文身份标识（服务端建表用）。
    pub fn auth_id(&self) -> [u8; AUTH_ID_LEN] {
        self.auth_id
    }

    /// 取下一个发送 nonce：4 字节固定前缀 + 8 字节递增计数器（大端）。
    #[inline]
    fn next_nonce(&self) -> [u8; 12] {
        let ctr = self.send_ctr.fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.nonce_prefix);
        nonce[4..].copy_from_slice(&ctr.to_be_bytes());
        nonce
    }

    /// 封装一个 QUIC 数据报为 TLS ApplicationData 记录。
    /// 首包带 version + authID，后续包只带 nonce。
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        // 保留原 API：内部转调零分配版本
        let mut out = Vec::with_capacity(5 + FIRST_HEADER_LEN + 12 + plaintext.len() + 16);
        self.seal_into(&mut out, plaintext);
        out
    }

    /// 封装并写入调用方提供的缓冲区（可反复复用，不分配）。
    ///
    /// 首包：`17 03 03 len(2) | ver(1) | authID(16) | nonce(12) | 密文+tag(16)`
    /// 后续：`17 03 03 len(2) | nonce(12) | 密文+tag(16)`
    ///
    /// 加密用 detached 版本，密文直接覆盖在 `out` 的载荷区，
    /// 只有明文需要从入参拷进来一次（QUIC 明文缓冲 → 记录缓冲的必然搬运）。
    pub fn seal_into(&self, out: &mut Vec<u8>, plaintext: &[u8]) {
        // 用 load 而不是 swap：要的是「是否已经确认可达」这个持续状态，
        // 不是「是不是第一次调用」。首包丢了重传时仍然要带首包头。
        let first = self.send_first_header && !self.established.load(Ordering::Relaxed);
        self.seal_into_with(out, plaintext, first);
    }

    /// 显式指定是否按首包封装（测试与特殊场景用）。
    fn seal_into_with(&self, out: &mut Vec<u8>, plaintext: &[u8], first: bool) {
        let nonce = self.next_nonce();
        let header_len = if first { FIRST_HEADER_LEN } else { 0 };
        // body = [ver+authID] + nonce(12) + 密文(len) + tag(16)
        let body_len = header_len + 12 + plaintext.len() + 16;
        out.clear();
        out.resize(5 + body_len, 0);
        out[0] = REC_APPDATA;
        out[1] = 0x03;
        out[2] = 0x03;
        out[3..5].copy_from_slice(&(body_len as u16).to_be_bytes());
        let mut pos = 5;
        if first {
            out[pos] = PROTOCOL_VERSION;
            out[pos + 1..pos + 1 + AUTH_ID_LEN].copy_from_slice(&self.auth_id);
            pos += FIRST_HEADER_LEN;
        }
        out[pos..pos + 12].copy_from_slice(&nonce);
        pos += 12;
        // 明文填入载荷区，之后**原地**加密：密文覆盖明文，tag 追加在末尾。
        // aead 0.5 的 `Buffer` 只为 Vec<u8> 实现，所以用 detached 版本
        // 直接对 `&mut [u8]` 操作，避免多分配一个 Vec。
        let plain_len = plaintext.len();
        out[pos..pos + plain_len].copy_from_slice(plaintext);
        let aad = self.aad(first);
        let tag = self
            .cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                &aad[..if first { FIRST_HEADER_LEN } else { 1 }],
                &mut out[pos..pos + plain_len],
            )
            .expect("aead encrypt");
        out[pos + plain_len..].copy_from_slice(&tag);
    }

    /// AAD 缓冲：首包是 `ver|authID`，后续包只有 `ver`。
    ///
    /// 把版本号纳入认证有实际作用：将来出 v3 时，v2 的包在 v3 下
    /// 一定解密失败，不会出现「老包被新版本误当成自己的包解」。
    /// 把 authID 也纳入，是防止有人篡改首包里的用户标识去撞别的密钥。
    #[inline]
    fn aad(&self, first: bool) -> [u8; FIRST_HEADER_LEN] {
        let mut aad = [0u8; FIRST_HEADER_LEN];
        aad[0] = PROTOCOL_VERSION;
        if first {
            aad[1..].copy_from_slice(&self.auth_id);
        }
        aad
    }

    /// 解开一条**后续** ApplicationData 记录（不含首包头）。
    /// 任何格式或认证失败都返回 None，调用方应静默丢弃。
    pub fn open(&self, record_payload: &[u8]) -> Option<Vec<u8>> {
        if record_payload.len() < 12 + 16 {
            return None;
        }
        let (nonce, ct) = record_payload.split_at(12);
        let aad = self.aad(false);
        self.cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: &aad[..1],
                },
            )
            .ok()
    }

    /// 解开**首包**记录（整段 payload，含 ver + authID + nonce + 密文）。
    ///
    /// 会先校验版本号与 authID 是否等于自己的，不匹配直接返回 None：
    /// 服务端用错密钥时不该走到 AEAD 计算（那只是浪费 CPU）。
    pub fn open_first(&self, record_payload: &[u8]) -> Option<Vec<u8>> {
        if record_payload.len() < FIRST_HEADER_LEN + 12 + 16 {
            return None;
        }
        if record_payload[0] != PROTOCOL_VERSION {
            return None;
        }
        if record_payload[1..FIRST_HEADER_LEN] != self.auth_id {
            return None;
        }
        let rest = &record_payload[FIRST_HEADER_LEN..];
        let (nonce, ct) = rest.split_at(12);
        let aad = self.aad(true);
        self.cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: &aad,
                },
            )
            .ok()
    }
}

/// 从首包里读出 `(版本, authID)`，**不做任何认证**。
///
/// 服务端在还不知道用户是谁的时候必须先读这两个字段才能查表选密钥，
/// 所以这里只能解析明文。调用方拿到 auth_id 后必须用对应密钥
/// `open_first` 认证成功，才算真正通过鉴权——解析本身不构成信任。
pub fn parse_first_header(record_payload: &[u8]) -> Option<(u8, [u8; AUTH_ID_LEN])> {
    if record_payload.len() < FIRST_HEADER_LEN {
        return None;
    }
    let mut auth_id = [0u8; AUTH_ID_LEN];
    auth_id.copy_from_slice(&record_payload[1..FIRST_HEADER_LEN]);
    Some((record_payload[0], auth_id))
}

/// 解析一个 TCP 段里可能串联的多条 TLS 记录。
/// 首包会同时携带伪 ClientHello 和真实数据记录，因此必须支持多记录。
pub fn parse_records(mut buf: &[u8]) -> Vec<TlsRecord<'_>> {
    let mut out = Vec::new();
    while buf.len() >= 5 {
        let typ = buf[0];
        let version = u16::from_be_bytes([buf[1], buf[2]]);
        let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if buf.len() < 5 + len {
            break;
        }
        out.push(TlsRecord {
            typ,
            version,
            payload: &buf[5..5 + len],
        });
        buf = &buf[5 + len..];
    }
    out
}

/// 写一个 TLS 扩展：类型(2) + 长度(2) + 内容
fn push_ext(out: &mut Vec<u8>, typ: u16, body: &[u8]) {
    out.extend_from_slice(&typ.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

/// GREASE 值（RFC 8701）：形如 `0x?a?a`。
/// Chrome 会在 cipher suite 列表、extensions 列表、supported_groups、
/// key_share 等处插入 GREASE，用来强制实现必须正确忽略未知值。
/// 真实的 ClientHello 里几乎一定有它，没有反而显得可疑。
fn grease() -> u16 {
    const GREASE: [u16; 16] = [
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa,
        0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    ];
    GREASE[rand::thread_rng().gen_range(0..GREASE.len())]
}

/// ClientHello 的目标总长度（含 5 字节记录头）。
///
/// 实测真实 Chrome 的 ClientHello 是 1699 字节（带 X25519Kyber768 混合 key share），
/// 而改造前我们只有 74 字节——**23 倍差距**。任何「ClientHello 小于 200 字节」
/// 的规则都能直接命中。这里取 512 附近的常见区间（不含 PQ 的传统浏览器量级），
/// 用 padding 扩展补齐，大小每次略有随机避免固定长度成为新特征。
const CLIENT_HELLO_TARGET: usize = 512;

/// 构造一个结构完整的 TLS 1.3 ClientHello（Chrome 风格）。
///
/// 改造前只有 74 字节、2 个扩展（SNI + supported_versions），缺了：
/// - `session_id`（TLS 1.2 middlebox 兼容，Chrome/Firefox 都发 32 字节）
/// - `key_share` / `supported_groups`（**TLS 1.3 必需**，没有它根本握不了手）
/// - `signature_algorithms`（TLS 1.3 必需）
/// - `ALPN`、`status_request`、`ec_point_formats` 等常规扩展
/// - **`early_data`**：我们发完 ClientHello 立刻发 ApplicationData（QUIC 数据），
///   没有 early_data 这就是明文可见的协议违规（ClientHello 后不可能有 0-RTT 数据）。
///   加上它之后「ClientHello → 立即 ApplicationData」就变成了合规的 0-RTT 流程。
///
/// 另外补了 GREASE（RFC 8701）和 padding：前者是真实浏览器的固定特征，
/// 后者让长度落在真实区间内。
pub fn build_client_hello(sni: &str) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let name = sni.as_bytes();
    // 用 IP 直连时真实浏览器/curl **不发送 SNI 扩展**（RFC 6066 要求
    // HostName 必须是域名，放 IP 属于协议违规）。
    // 我们的默认部署正是 `server: 203.0.113.10:8443`，改造前就把
    // IP 当 SNI 发了出去——「SNI 是裸 IP」是任何 DPI 都能一眼命中的特征。
    let sni_valid = !sni.is_empty() && sni.parse::<std::net::IpAddr>().is_err();

    // ---- 扩展列表 ----
    let mut exts: Vec<u8> = Vec::with_capacity(480);

    // GREASE 扩展必须放在第一个（Chrome 的习惯）
    push_ext(&mut exts, grease(), &[]);

    // server_name (0x0000)，仅当 SNI 是合法域名时才发
    if sni_valid {
        let mut sn = Vec::with_capacity(5 + name.len());
        sn.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes()); // server_name_list 长度
        sn.push(0); // host_name
        sn.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sn.extend_from_slice(name);
        push_ext(&mut exts, 0x0000, &sn);
    }

    // extended_master_secret (0x0017)：空体，表示支持
    push_ext(&mut exts, 0x0017, &[]);

    // renegotiation_info (0xff01)：长度 1 的 0（安全重协商）
    push_ext(&mut exts, 0xff01, &[0x00]);

    // supported_groups (0x000a)：GREASE + x25519 + secp256r1 + secp384r1
    let mut groups = Vec::new();
    let g_body: Vec<u8> = {
        let mut v = Vec::new();
        v.extend_from_slice(&grease().to_be_bytes());
        v.extend_from_slice(&[0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]);
        v
    };
    groups.extend_from_slice(&(g_body.len() as u16).to_be_bytes());
    groups.extend_from_slice(&g_body);
    push_ext(&mut exts, 0x000a, &groups);

    // ec_point_formats (0x000b)：只支持 uncompressed
    push_ext(&mut exts, 0x000b, &[0x01, 0x00]);

    // session_ticket (0x0023)：空体表示支持
    push_ext(&mut exts, 0x0023, &[]);

    // ALPN (0x0010)：h2 + http/1.1
    let mut alpn = Vec::new();
    alpn.extend_from_slice(&12u16.to_be_bytes());
    alpn.extend_from_slice(&[0x02, b'h', b'2']);
    alpn.extend_from_slice(&[0x08]);
    alpn.extend_from_slice(b"http/1.1");
    push_ext(&mut exts, 0x0010, &alpn);

    // status_request (0x0005)：OCSP stapling，结构 = status_type(1) + responder_id_list(2) + request_extensions(2)
    push_ext(&mut exts, 0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00]);

    // signature_algorithms (0x000d)：TLS 1.3 必需
    let mut sigalgs = Vec::new();
    let schemes: [u16; 8] = [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    sigalgs.extend_from_slice(&((schemes.len() * 2) as u16).to_be_bytes());
    for s in schemes {
        sigalgs.extend_from_slice(&s.to_be_bytes());
    }
    push_ext(&mut exts, 0x000d, &sigalgs);

    // signed_certificate_timestamp (0x0012)：空体表示支持
    push_ext(&mut exts, 0x0012, &[]);

    // key_share (0x0033)：GREASE 空 share + x25519 真实长度的随机 share。
    // 没有这个扩展，TLS 1.3 服务端会直接拒绝，是「这不是真客户端」的铁证。
    let mut shares = Vec::new();
    {
        let mut entries = Vec::new();
        // GREASE share（长度 1，内容 0）
        let g = grease();
        entries.extend_from_slice(&g.to_be_bytes());
        entries.extend_from_slice(&1u16.to_be_bytes());
        entries.push(0);
        // x25519 share：32 字节随机
        entries.extend_from_slice(&[0x00, 0x1d]);
        entries.extend_from_slice(&32u16.to_be_bytes());
        let mut kx = [0u8; 32];
        rng.fill_bytes(&mut kx);
        entries.extend_from_slice(&kx);
        shares.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        shares.extend_from_slice(&entries);
    }
    push_ext(&mut exts, 0x0033, &shares);

    // psk_key_exchange_modes (0x002d)：psk_dhe_ke（与 early_data 配套必需）
    push_ext(&mut exts, 0x002d, &[0x01, 0x01]);

    // supported_versions (0x002b)：TLS 1.3 + 1.2
    push_ext(&mut exts, 0x002b, &[0x04, 0x03, 0x04, 0x03, 0x03]);

    // ---- 以下两个是为「ClientHello 后立刻发数据」服务的 ----

    // early_data (0x002a)：空体。声明愿意发 0-RTT 数据。
    push_ext(&mut exts, 0x002a, &[]);

    // padding (0x0015)：先把长度补齐，再写必须位于最后的 pre_shared_key。
    // 目标总长 CLIENT_HELLO_TARGET ± 小幅随机，避免固定长度本身成为特征。
    {
        // 已知固定部分的长度（不含 extensions 内容和 padding 自身）
        // 5 记录头 + 4 握手头 + 2 legacy_version + 32 random + (1+32) session_id
        // + (2 + suites) + 2 compression + 2 extensions_len
        let suites_len = 16usize; // GREASE + 7 个真实套件，见下方
        let fixed = 5 + 4 + 2 + 32 + 33 + 2 + suites_len + 2 + 2;
        let target = CLIENT_HELLO_TARGET + rng.gen_range(0..48);
        // padding 扩展自身占 4 字节头，pre_shared_key 还在后面，先预留
        let psk_len = 4 + (2 + 2 + 96 + 4) + (2 + 1 + 32); // 见下方构造
        let avail = target.saturating_sub(fixed + exts.len() + psk_len + 4);
        if avail > 0 {
            push_ext(&mut exts, 0x0015, &vec![0u8; avail]);
        }
    }

    // pre_shared_key (0x0029)：RFC 8446 要求它是**最后一个**扩展。
    // 结构与 early_data 配套：identity 是伪造的 ticket，
    // binder 是随机字节（DPI 没有 PSK 无法验证 binder 真伪）。
    {
        let ticket_len = 96usize;
        let mut psk = Vec::with_capacity(4 + ticket_len + 4 + 2 + 33 + 4);
        // identities: 长度(2) + [ identity 长度(2) + ticket + age(4) ]
        psk.extend_from_slice(&((2 + ticket_len + 4) as u16).to_be_bytes());
        psk.extend_from_slice(&(ticket_len as u16).to_be_bytes());
        let mut ticket = vec![0u8; ticket_len];
        rng.fill_bytes(&mut ticket);
        psk.extend_from_slice(&ticket);
        psk.extend_from_slice(&rng.gen::<u32>().to_be_bytes()); // obfuscated_ticket_age
        // binders: 长度(2) + [ binder 长度(1) + 32 字节 ]
        psk.extend_from_slice(&(1 + 32u16).to_be_bytes());
        psk.push(32);
        let mut binder = [0u8; 32];
        rng.fill_bytes(&mut binder);
        psk.extend_from_slice(&binder);
        push_ext(&mut exts, 0x0029, &psk);
    }

    // ---- 拼 ClientHello 主体 ----
    let mut hs = Vec::with_capacity(64 + exts.len());
    hs.extend_from_slice(&[0x03, 0x03]); // legacy_version
    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);
    hs.extend_from_slice(&random);
    // legacy_session_id：Chrome/Firefox 都发 32 字节，用于 middlebox 兼容。
    // 改造前这里是空的（0 长度），本身就是个不常见的做法。
    hs.push(32);
    let mut sid = [0u8; 32];
    rng.fill_bytes(&mut sid);
    hs.extend_from_slice(&sid);
    // cipher suites：GREASE + TLS 1.3 三个 + 常见 ECDHE 四个
    hs.extend_from_slice(&16u16.to_be_bytes());
    for cs in [
        grease(),
        0x1301, // TLS_AES_128_GCM_SHA256
        0x1302, // TLS_AES_256_GCM_SHA384
        0x1303, // TLS_CHACHA20_POLY1305_SHA256
        0xc02b, // ECDHE_ECDSA_AES_128_GCM
        0xc02f, // ECDHE_RSA_AES_128_GCM
        0xc02c, // ECDHE_ECDSA_AES_256_GCM
        0xc030, // ECDHE_RSA_AES_256_GCM
    ] {
        hs.extend_from_slice(&cs.to_be_bytes());
    }
    hs.extend_from_slice(&[0x01, 0x00]); // legacy_compression_methods: null
    hs.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hs.extend_from_slice(&exts);

    // ---- 握手头 + 记录头 ----
    let mut body = Vec::with_capacity(4 + hs.len());
    body.push(0x01); // handshake 类型：client_hello
    body.push(((hs.len() >> 16) & 0xff) as u8);
    body.push(((hs.len() >> 8) & 0xff) as u8);
    body.push((hs.len() & 0xff) as u8);
    body.extend_from_slice(&hs);

    let mut out = Vec::with_capacity(5 + body.len());
    out.push(REC_HANDSHAKE);
    out.push(0x03);
    out.push(0x01); // ClientHello 的记录版本用 TLS1.0，和真实浏览器一致
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// 构造服务器侧的握手响应（ServerHello + CCS + 加密握手记录）。
///
/// 改造前这里在 CCS 之后发的是 **0x16 明文** 的假 Finished 记录。
/// 真实 TLS 1.3 里 ChangeCipherSpec 之后再出现明文握手记录是**协议违规**：
/// ServerHello 之后的所有握手消息（EncryptedExtensions / Certificate /
/// CertificateVerify / Finished）都必须包在 0x17 加密记录里，DPI 一看就知道。
///
/// 现在按真实顺序构造：
/// ```text
/// 16 03 03 <len>  02 ...             ServerHello（明文，含 key_share）
/// 14 03 03 00 01 01                  ChangeCipherSpec（middlebox 兼容）
/// 17 03 03 <len>  <随机密文>          加密的握手消息（长度取真实量级）
/// ```
/// 密文内容用随机字节：DPI 没有会话密钥无法验证，长度与真实证书链量级一致即可。
pub fn build_server_hello() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut out = Vec::with_capacity(900);

    // ---- ServerHello ----
    let mut hs = Vec::with_capacity(90);
    hs.extend_from_slice(&[0x03, 0x03]); // legacy_version
    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);
    hs.extend_from_slice(&random);
    // legacy_session_id_echo：必须回显客户端的 session_id。
    // 我们无法真的读到客户端的（ClientHello 是本地构造的、没保存），
    // 但真实客户端会发 32 字节，这里同样给 32 字节随机值保持长度一致。
    hs.push(32);
    let mut sid = [0u8; 32];
    rng.fill_bytes(&mut sid);
    hs.extend_from_slice(&sid);
    hs.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    hs.push(0x00); // legacy_compression_method

    // 扩展：supported_versions + key_share（都是 TLS 1.3 必需）
    let mut exts = Vec::with_capacity(48);
    push_ext(&mut exts, 0x002b, &[0x03, 0x04]); // supported_versions = TLS1.3
    {
        // key_share：x25519 + 32 字节"公钥"
        let mut ks = Vec::with_capacity(36);
        ks.extend_from_slice(&[0x00, 0x1d]);
        ks.extend_from_slice(&32u16.to_be_bytes());
        let mut pk = [0u8; 32];
        rng.fill_bytes(&mut pk);
        ks.extend_from_slice(&pk);
        push_ext(&mut exts, 0x0033, &ks);
    }
    hs.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hs.extend_from_slice(&exts);

    let mut body = Vec::with_capacity(4 + hs.len());
    body.push(0x02); // handshake 类型：server_hello
    body.push(((hs.len() >> 16) & 0xff) as u8);
    body.push(((hs.len() >> 8) & 0xff) as u8);
    body.push((hs.len() & 0xff) as u8);
    body.extend_from_slice(&hs);

    out.push(REC_HANDSHAKE);
    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);

    // ---- ChangeCipherSpec（TLS 1.3 为 middlebox 兼容保留）----
    out.extend_from_slice(&[REC_CCS, 0x03, 0x03, 0x00, 0x01, 0x01]);

    // ---- 加密的握手消息（EncryptedExtensions + Certificate + CertVerify + Finished）----
    // 用 0x17 记录类型 + 随机密文。长度取 500~700 的量级：
    // 一张 ECDSA 自签证书链 + 三个签名结构的实际大小就在这个范围。
    let enc_len = 512 + rng.gen_range(0..192);
    let mut enc = vec![0u8; enc_len];
    rng.fill_bytes(&mut enc);
    out.push(REC_APPDATA);
    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(&(enc_len as u16).to_be_bytes());
    out.extend_from_slice(&enc);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_packet_carries_auth_id() {
        let obfs = Obfs::new_client("test-password");
        let plain = b"quic datagram payload";
        let rec = obfs.seal(plain);
        assert_eq!(rec[0], REC_APPDATA);
        let records = parse_records(&rec);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].typ, REC_APPDATA);
        let payload = records[0].payload;
        // 首包必须带 version + authID，且 authID 与派生值一致
        assert_eq!(payload[0], PROTOCOL_VERSION);
        assert_eq!(&payload[1..FIRST_HEADER_LEN], &obfs.auth_id());
        assert_eq!(
            parse_first_header(payload),
            Some((PROTOCOL_VERSION, obfs.auth_id()))
        );
        let out = obfs.open_first(payload).expect("decrypt first");
        assert_eq!(out, plain);
    }

    #[test]
    fn subsequent_packet_has_no_header() {
        // 确认服务端可达后，记录不再带首包头 —— 这是稳态零额外开销的前提
        let obfs = Obfs::new_client("test-password");
        let first = obfs.seal(b"one");
        obfs.mark_established();
        let second = obfs.seal(b"two");
        let f = parse_records(&first);
        let s = parse_records(&second);
        assert_eq!(
            f[0].payload.len() - s[0].payload.len(),
            FIRST_HEADER_LEN,
            "首包应比后续包多出 ver+authID 的开销"
        );
        // 第二包不能用 open_first 解（它没有首包头）
        assert!(obfs.open_first(s[0].payload).is_none());
        assert_eq!(obfs.open(s[0].payload).as_deref(), Some(&b"two"[..]));
        // 首包也不能用 open 解（open 认为开头就是 nonce）
        assert!(obfs.open(f[0].payload).is_none());
    }

    #[test]
    fn retransmit_still_carries_header() {
        // QUIC Initial 丢包重传必须仍然能被服务端鉴权：
        // 客户端在收到服务端回包之前，每个包都带首包头。
        let obfs = Obfs::new_client("test-password");
        let a = obfs.seal(b"initial-1");
        let b = obfs.seal(b"initial-2");
        for rec in [&a, &b] {
            let recs = parse_records(rec);
            assert_eq!(recs[0].payload[0], PROTOCOL_VERSION, "重传包也必须带首包头");
            assert!(obfs.open_first(recs[0].payload).is_some());
        }
        // 服务端侧永远不带首包头
        let server = Obfs::new_server("test-password");
        let s = server.seal(b"reply");
        let recs = parse_records(&s);
        assert!(server.open(recs[0].payload).is_some());
        assert!(server.open_first(recs[0].payload).is_none());
    }

    #[test]
    fn wrong_password_fails() {
        // 密码不同必须解密失败，这是外层鉴权的核心保证
        let a = Obfs::new_client("password-a");
        let b = Obfs::new_client("password-b");
        assert_ne!(a.auth_id(), b.auth_id(), "不同密码的 auth id 必须不同");
        let rec = a.seal(b"data");
        let records = parse_records(&rec);
        // auth id 不匹配：open_first 连 AEAD 都不用算就拒绝
        assert!(b.open_first(records[0].payload).is_none());
        // 换成后续包，AEAD 认证失败
        let rec2 = a.seal(b"data2");
        let records2 = parse_records(&rec2);
        assert!(b.open(records2[0].payload).is_none());
    }

    #[test]
    fn tampered_auth_id_rejected() {
        // 篡改首包里的 authID 必须解密失败：authID 参与了 AAD 认证，
        // 否则攻击者可以改掉它去撞别人的密钥槽位。
        let obfs = Obfs::new_client("test-password");
        let mut rec = obfs.seal(b"data");
        let records = parse_records(&rec);
        // 复制一份再改第 1 个字节（payload 里 authID 的起始位置）
        let mut payload = records[0].payload.to_vec();
        payload[1] ^= 0xFF;
        assert!(obfs.open_first(&payload).is_none());
        // 版本字节被改也必须失败
        let mut payload2 = records[0].payload.to_vec();
        payload2[0] = 3;
        assert!(obfs.open_first(&payload2).is_none());
        rec.clear();
    }

    /// `seal_into` 必须和 `seal` 产出同构的记录：
    /// 记录头一致、长度一致、都能被同一密钥解开。
    /// 这是零分配改造不破坏线上格式的关键回归用例。
    #[test]
    fn seal_into_matches_seal() {
        // 用两个独立实例，保证各自都从「首包」状态开始比较
        for plain in [&b""[..], b"a", b"hello world", &vec![7u8; 1400][..]] {
            let a = Obfs::new_client("test-password");
            let b = Obfs::new_client("test-password");
            let owned = a.seal(plain);
            let mut reused = Vec::new();
            b.seal_into(&mut reused, plain);
            assert_eq!(owned.len(), reused.len(), "记录总长必须一致");
            assert_eq!(owned[..5], reused[..5], "记录头必须一致");
            // 两次的 nonce 不同（前缀随机），但都必须能解回同样的明文
            let ra = parse_records(&owned);
            let rb = parse_records(&reused);
            assert_eq!(a.open_first(ra[0].payload).as_deref(), Some(plain));
            assert_eq!(a.open_first(rb[0].payload).as_deref(), Some(plain));
            // nonce 起点在 authID 之后
            let na = &ra[0].payload[FIRST_HEADER_LEN..FIRST_HEADER_LEN + 12];
            let nb = &rb[0].payload[FIRST_HEADER_LEN..FIRST_HEADER_LEN + 12];
            assert_ne!(na, nb, "独立实例的 nonce 前缀应随机不同");
        }
    }

    #[test]
    fn client_hello_parses() {
        // 伪 ClientHello 必须能被记录解析器识别为 handshake
        let ch = build_client_hello("test.example.com");
        let recs = parse_records(&ch);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].typ, REC_HANDSHAKE);
    }

    /// 遍历 ClientHello 的扩展，返回 (类型, 内容) 列表。
    fn hello_extensions(hs_body: &[u8]) -> Vec<(u16, Vec<u8>)> {
        // hs_body 是 ClientHello 的 handshake 消息体（不含 4 字节握手头）
        let mut i = 2 + 32; // legacy_version + random
        let sid_len = hs_body[i] as usize;
        i += 1 + sid_len;
        let cs_len = u16::from_be_bytes([hs_body[i], hs_body[i + 1]]) as usize;
        i += 2 + cs_len;
        i += 1 + hs_body[i] as usize; // compression methods
        let ext_total = u16::from_be_bytes([hs_body[i], hs_body[i + 1]]) as usize;
        i += 2;
        let end = i + ext_total;
        let mut out = Vec::new();
        while i + 4 <= end {
            let typ = u16::from_be_bytes([hs_body[i], hs_body[i + 1]]);
            let len = u16::from_be_bytes([hs_body[i + 2], hs_body[i + 3]]) as usize;
            i += 4;
            out.push((typ, hs_body[i..i + len].to_vec()));
            i += len;
        }
        assert_eq!(i, end, "扩展长度必须与声明一致");
        out
    }

    /// ClientHello 必须结构完整且像真实浏览器：
    /// 有 session_id、TLS 1.3 必需扩展，且 pre_shared_key 必须是最后一个。
    #[test]
    fn client_hello_looks_real() {
        let ch = build_client_hello("test.example.com");
        // 744 字节 = 记录头 5 + 握手头 4 + ClientHello 本体。
        // 改造前只有 79 字节，真实浏览器 300~1700，这里落在 512~600。
        assert!(
            ch.len() >= 512 && ch.len() < 620,
            "ClientHello 长度应在真实区间内，实际 {}",
            ch.len()
        );

        let hs = &ch[5..];
        assert_eq!(hs[0], 0x01, "必须是 ClientHello");
        let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
        assert_eq!(hs_len, hs.len() - 4, "握手长度必须自洽");
        let body = &hs[4..];

        // session_id 必须是 32 字节（Chrome/Firefox 都这样）
        assert_eq!(body[2 + 32], 32, "session_id 长度应为 32");

        let exts = hello_extensions(body);
        let types: Vec<u16> = exts.iter().map(|(t, _)| *t).collect();
        for need in [
            0x0000u16, // server_name
            0x000a,    // supported_groups
            0x000b,    // ec_point_formats
            0x000d,    // signature_algorithms
            0x0010,    // ALPN
            0x002b,    // supported_versions
            0x002d,    // psk_key_exchange_modes
            0x0033,    // key_share  ← 缺了它 TLS 1.3 根本握不了手
            0x002a,    // early_data ← 让「ClientHello 后立刻发数据」合规
        ] {
            assert!(types.contains(&need), "缺少扩展 0x{need:04x}: {types:?}");
        }
        // RFC 8446：pre_shared_key 必须是最后一个扩展
        assert_eq!(
            *types.last().unwrap(),
            0x0029,
            "pre_shared_key 必须是最后一个扩展"
        );

        // key_share 里必须有 x25519（0x001d）的 32 字节 share
        let ks = &exts.iter().find(|(t, _)| *t == 0x0033).unwrap().1;
        assert!(
            ks.windows(4).any(|w| w == [0x00, 0x1d, 0x00, 0x20]),
            "key_share 必须包含 x25519/32 字节"
        );
    }

    /// 服务器握手序列必须合规：CCS 之后不能再出现明文握手记录（0x16）。
    /// 真实 TLS 1.3 在 ServerHello 之后的所有握手消息都是 0x17 加密记录，
    /// 改造前这里发的是 0x16 明文 Finished，属于协议违规。
    #[test]
    fn server_hello_sequence_is_valid() {
        let sh = build_server_hello();
        let recs = parse_records(&sh);
        let types: Vec<u8> = recs.iter().map(|r| r.typ).collect();
        assert_eq!(
            types,
            vec![REC_HANDSHAKE, REC_CCS, REC_APPDATA],
            "服务器握手序列应为 ServerHello → CCS → 加密记录"
        );
        // 密文长度要落在真实证书链的量级（不能是几十字节的假数据）
        assert!(
            recs[2].payload.len() >= 500,
            "加密握手记录太短，实际 {}",
            recs[2].payload.len()
        );
    }
}


#[cfg(test)]
mod interop_vector {
    use super::*;

    /// 导出固定的互通向量供 Go 侧消费（Rust -> Go 方向）。
    ///
    /// 这不是常规单测，而是跨语言互通的可执行契约：
    /// Rust 加密的字节必须能被 Go 解开，反之亦然。
    /// 文件写失败时静默跳过，避免在没有 /tmp 的环境里失败。
    #[test]
    fn export_vector() {
        // 必须用客户端构造器：只有客户端会在首包上带 ver+authID。
        // 服务端方向从不携带首包头（它总是先收后发）。
        let obfs = Obfs::new_client("interop-password");
        let first = obfs.seal(b"first-datagram");
        // 模拟「已确认服务端可达」，后续包不再带首包头
        obfs.mark_established();
        let second = obfs.seal(b"second-datagram");
        let mut blob = Vec::new();
        blob.extend_from_slice(&(first.len() as u32).to_be_bytes());
        blob.extend_from_slice(&first);
        blob.extend_from_slice(&(second.len() as u32).to_be_bytes());
        blob.extend_from_slice(&second);
        let _ = std::fs::write("/tmp/flowtls-rust-vector.bin", &blob);

        // 同时导出 authID，便于 Go 侧核对派生参数
        let id: String = obfs.auth_id().iter().map(|b| format!("{:02x}", b)).collect();
        let _ = std::fs::write("/tmp/flowtls-rust-authid.txt", id);
    }
}

#[cfg(test)]
mod interop_consume {
    use super::*;

    /// 消费 Go 侧生成的向量（Go -> Rust 方向）。
    ///
    /// 与 export_vector 配对：两者合起来构成双向互通的回归门禁。
    /// 文件不存在时静默跳过，避免在没跑过 Go 侧的环境里失败。
    #[test]
    fn consume_go_vector() {
        let Ok(blob) = std::fs::read("/tmp/flowtls-go-vector.bin") else {
            eprintln!("跳过：没有 /tmp/flowtls-go-vector.bin");
            return;
        };
        let server = Obfs::new_server("interop-password");
        let mut off = 0usize;
        let mut idx = 0;
        while off + 4 <= blob.len() {
            let n = u32::from_be_bytes([blob[off], blob[off + 1], blob[off + 2], blob[off + 3]]) as usize;
            off += 4;
            let rec = &blob[off..off + n];
            off += n;
            let recs = parse_records(rec);
            assert_eq!(recs.len(), 1);
            let payload = recs[0].payload;
            if idx == 0 {
                let plain = server.open_first(payload).expect("Go 首包必须能解开");
                assert_eq!(plain, b"go-first");
            } else {
                let plain = server.open(payload).expect("Go 后续包必须能解开");
                assert_eq!(plain, b"go-second");
            }
            idx += 1;
        }
        assert_eq!(idx, 2, "应消费到 2 条记录");
    }
}
