//! 伪 TLS 记录编解码与外层 AEAD。
//!
//! 线上每个报文都是「TLS 记录头 + nonce + ChaCha20-Poly1305 密文」。
//! 记录头只是外观，真正的安全性来自 QUIC 自身的 TLS 1.3；
//! 外层 AEAD 的作用是让未授权方连 QUIC 状态机都进不来（解密失败即丢弃）。

use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering};

/// TLS 记录类型常量
pub const REC_HANDSHAKE: u8 = 0x16;
pub const REC_CCS: u8 = 0x14;
pub const REC_APPDATA: u8 = 0x17;

/// 一条解析出来的 TLS 记录视图
pub struct TlsRecord<'a> {
    pub typ: u8,
    pub version: u16,
    pub payload: &'a [u8],
}

/// 外层伪装编解码器，持有密码派生出的 AEAD 密钥。
pub struct Obfs {
    cipher: ChaCha20Poly1305,
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
}

impl Obfs {
    /// 由用户密码派生 AEAD 密钥。
    /// 用 HKDF 而不是直接用密码，避免弱密码直接暴露为密钥。
    pub fn new(password: &str) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"flowtls-faketcp-v1"), password.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(b"flowtls faketcp aead key", &mut key)
            .expect("hkdf expand");
        // nonce 前缀只需一次随机，之后全部走计数器
        let mut nonce_prefix = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut nonce_prefix);
        Self {
            cipher: ChaCha20Poly1305::new(&key.into()),
            nonce_prefix,
            send_ctr: AtomicU64::new(0),
        }
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
    /// 返回：17 03 03 len(2) + nonce(12) + 密文。
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        // 保留原 API：内部转调零分配版本
        let mut out = Vec::with_capacity(5 + 12 + plaintext.len() + 16);
        self.seal_into(&mut out, plaintext);
        out
    }

    /// 封装并写入调用方提供的缓冲区（可反复复用，不分配）。
    ///
    /// 结构：`17 03 03 len(2) | nonce(12) | 密文+tag(16)`
    /// 加密用 `encrypt_in_place`，密文直接覆盖在 `out` 的载荷区，
    /// 只有明文需要从入参拷进来一次（这是 QUIC 明文缓冲 → 记录缓冲的必然搬运）。
    pub fn seal_into(&self, out: &mut Vec<u8>, plaintext: &[u8]) {
        let nonce = self.next_nonce();
        // body = nonce(12) + 密文(len) + tag(16)
        let body_len = 12 + plaintext.len() + 16;
        out.clear();
        out.resize(5 + body_len, 0);
        out[0] = REC_APPDATA;
        out[1] = 0x03;
        out[2] = 0x03;
        out[3..5].copy_from_slice(&(body_len as u16).to_be_bytes());
        out[5..17].copy_from_slice(&nonce);
        // 明文填入载荷区，之后**原地**加密：密文覆盖明文，tag 追加在末尾。
        // aead 0.5 的 `Buffer` 只为 Vec<u8> 实现，所以用 detached 版本
        // 直接对 `&mut [u8]` 操作，避免多分配一个 Vec。
        let plain_len = plaintext.len();
        out[17..17 + plain_len].copy_from_slice(plaintext);
        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", &mut out[17..17 + plain_len])
            .expect("aead encrypt");
        out[17 + plain_len..].copy_from_slice(&tag);
    }

    /// 解开一条 ApplicationData 记录。
    /// 任何格式或认证失败都返回 None，调用方应静默丢弃。
    pub fn open(&self, record_payload: &[u8]) -> Option<Vec<u8>> {
        if record_payload.len() < 12 + 16 {
            return None;
        }
        let (nonce, ct) = record_payload.split_at(12);
        self.cipher
            .decrypt(Nonce::from_slice(nonce), ct)
            .ok()
    }
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

/// 构造一个结构合法的最小 TLS ClientHello（含 SNI）。
/// 只求 DPI 看起来合理，不参与真实握手，因此不追求完整扩展集。
pub fn build_client_hello(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    // SNI 扩展内容：server_name_list(2) + type(1) + name_len(2) + name
    let mut sni_body = Vec::with_capacity(5 + name.len());
    sni_body.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sni_body.push(0); // host_name
    sni_body.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni_body.extend_from_slice(name);

    let mut exts = Vec::new();
    // SNI 扩展
    exts.extend_from_slice(&[0x00, 0x00]);
    exts.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni_body);
    // supported_versions：声明支持 TLS 1.3 / 1.2
    exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]);

    let mut hs = Vec::new();
    hs.push(0x03); // ClientHello
    hs.push(0x03);
    let mut random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut random);
    hs.extend_from_slice(&random);
    hs.push(0); // session_id 长度 0
    hs.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]); // TLS1.3 套件
    hs.extend_from_slice(&[0x01, 0x00]); // 压缩方法 null
    hs.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hs.extend_from_slice(&exts);

    let mut body = Vec::with_capacity(4 + hs.len());
    body.push(0x01); // handshake 类型：client_hello
    body.push(((hs.len() >> 16) & 0xff) as u8);
    body.push(((hs.len() >> 8) & 0xff) as u8);
    body.push((hs.len() & 0xff) as u8);
    body.extend_from_slice(&hs);

    let mut out = Vec::with_capacity(5 + body.len());
    out.push(REC_HANDSHAKE);
    out.push(0x03);
    out.push(0x01); // ClientHello 用 TLS1.0 记录版本，和真实浏览器一致
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// 构造一段象征性的服务器握手响应。
/// 包含 ServerHello + ChangeCipherSpec + Finished，纯表演，不参与状态。
pub fn build_server_hello() -> Vec<u8> {
    let mut out = Vec::new();

    // ServerHello：TLS1.2 记录版本，随机 32 字节 + 套件 + 空扩展
    let mut hs = Vec::with_capacity(38);
    hs.extend_from_slice(&[0x03, 0x03]);
    let mut random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut random);
    hs.extend_from_slice(&random);
    hs.push(0); // session_id 长度
    hs.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    hs.push(0); // 压缩方法
    hs.extend_from_slice(&[0x00, 0x00]); // 扩展长度 0
    let mut body = vec![0x02];
    body.extend_from_slice(&((hs.len() >> 16) as u8).to_le_bytes());
    body.extend_from_slice(&((hs.len() >> 8) as u8).to_le_bytes());
    body.push((hs.len() & 0xff) as u8);
    body.extend_from_slice(&hs);
    out.push(REC_HANDSHAKE);
    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);

    // ChangeCipherSpec：TLS1.2 握手完成的典型信号
    out.extend_from_slice(&[REC_CCS, 0x03, 0x03, 0x00, 0x01, 0x01]);

    // Finished：随机的握手记录，让包序列看起来完整
    let mut fin = vec![0x14u8];
    let mut fin_body = [0u8; 36];
    rand::thread_rng().fill_bytes(&mut fin_body);
    fin.extend_from_slice(&((fin_body.len() >> 16) as u8).to_le_bytes());
    fin.extend_from_slice(&((fin_body.len() >> 8) as u8).to_le_bytes());
    fin.push((fin_body.len() & 0xff) as u8);
    fin.extend_from_slice(&fin_body);
    out.push(REC_HANDSHAKE);
    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(&(fin.len() as u16).to_be_bytes());
    out.extend_from_slice(&fin);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let obfs = Obfs::new("test-password");
        let plain = b"quic datagram payload";
        let rec = obfs.seal(plain);
        // 记录头必须是 ApplicationData
        assert_eq!(rec[0], REC_APPDATA);
        let records = parse_records(&rec);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].typ, REC_APPDATA);
        let out = obfs.open(records[0].payload).expect("decrypt");
        assert_eq!(out, plain);
    }

    #[test]
    fn wrong_password_fails() {
        // 密码不同必须解密失败，这是外层鉴权的核心保证
        let a = Obfs::new("password-a");
        let b = Obfs::new("password-b");
        let rec = a.seal(b"data");
        let records = parse_records(&rec);
        assert!(b.open(records[0].payload).is_none());
    }

    /// `seal_into` 必须和 `seal` 产出完全同构的记录：
    /// 记录头一致、长度一致、都能被同一密钥解开。
    /// 这是零分配改造不破坏线上兼容性的关键回归用例。
    #[test]
    fn seal_into_matches_seal() {
        let obfs = Obfs::new("test-password");
        for plain in [&b""[..], b"a", b"hello world", &vec![7u8; 1400][..]] {
            let owned = obfs.seal(plain);
            let mut reused = Vec::new();
            obfs.seal_into(&mut reused, plain);
            assert_eq!(owned.len(), reused.len(), "记录总长必须一致");
            assert_eq!(owned[..5], reused[..5], "记录头必须一致");
            // 两次的 nonce 不同（计数器递增），但都必须能解回同样的明文
            let a = parse_records(&owned);
            let b = parse_records(&reused);
            assert_eq!(obfs.open(a[0].payload).as_deref(), Some(plain));
            assert_eq!(obfs.open(b[0].payload).as_deref(), Some(plain));
            assert_ne!(a[0].payload[..12], b[0].payload[..12], "nonce 必须递增不重复");
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
}
