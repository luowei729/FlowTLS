//! QUIC 内核配置。
//!
//! 这里只负责生成 quinn-proto 需要的 TLS 与传输参数，
//! 真正的收发由 faketcp 层完成。内层 QUIC 的证书是运行时自签的，
//! 安全边界由外层 AEAD（密码派生密钥）保证，因此客户端跳过证书校验。

use std::sync::Arc;
use std::time::Duration;

use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn_proto::{ClientConfig, ServerConfig, TransportConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

/// 内层 QUIC 使用的 ALPN，和公网 HTTP/3 区分开
pub const ALPN: &[u8] = b"flowtls";

/// 生成内层 QUIC 的自签证书。
/// 每次进程启动重新生成即可：客户端本来就不校验，外层已经有真实鉴权。
fn self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["flowtls".to_string()])
        .expect("generate self-signed cert");
    let cert_der = cert.cert.der().clone();
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    (vec![cert_der], PrivateKeyDer::Pkcs8(key_der))
}

/// 构造传输参数。
/// `max_cwnd` 是共享的拥塞窗口上限原子值，由外层自适应算法实时调整；
/// 连接运行中修改会立即生效，不需要重建连接。
/// initial_mtu 固定 1200：外层还要加 TLS 记录头、nonce、AEAD tag 和 TCP/IP 头，
/// 总包控制在 1300 以内，避免 IP 分片（分片会破坏我们的按记录解析逻辑）。
fn transport_config(
    max_cwnd: std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    // 空闲 30 秒断开；保活 10 秒，防止 NAT 映射过期
    t.max_idle_timeout(Some(Duration::from_secs(30).try_into().expect("idle timeout")));
    t.keep_alive_interval(Some(Duration::from_secs(10)));
    // 跨境路径实测 MTU ≥ 1428，QUIC 载荷取 1332：
    // 外层 33 字节（5 记录头 + 12 nonce + 16 tag）+ IP 20 + TCP 32（含 12 字节
    // 时间戳选项）= 总包 1417 字节，与改造前（TCP 头 20 字节、载荷 1340）
    // 的 1413 基本一致，链路余量不变。
    // 之所以从 1340 降到 1332：伪装改造给每个数据包加了 TCP 时间戳选项，
    // 头部多 12 字节。若仍用 1340，总包会变成 1425，逼近服务端通告的 MSS 1400
    // 对应的 1440 上限，没有余量。
    t.initial_mtu(1332);
    // 必须关掉 PMTUD（路径 MTU 发现），并把 min_mtu 抬到同一值。
    //
    // 原因：quinn 的 BlackHoleDetector 只要观测到「连续 4 个可疑丢包突发」
    // （BLACK_HOLE_THRESHOLD = 3，突发里所有包都大于 min_mtu 且之后没有更大的包被 ACK），
    // 就判定路径 MTU 变小，把 current_mtu 直接打回 min_mtu（默认 1200）。
    // 国际线路 TCP/裸 IP 丢包本来就是常态（实测 20~50%），这个启发式必然误判：
    // 实测浏览器测速时 mtu 从 1340 塌到 1200 再也没爬回来，此后每包少装 140 字节
    // 有效载荷（-10.4%），包数增加 11.7%，丢包概率随之上升，形成恶性循环。
    //
    // 我们的路径 MTU 是「自己说了算」的：外层封装固定，头部长度固定，
    // 1332 载荷对应 1417 字节报文，稳定小于链路 1428。
    // 中间没有任何需要探测的变量，PMTUD 只会带来误判。
    t.mtu_discovery_config(None);
    // 双保险：即使将来重新开启 PMTUD，也不允许降到 1332 以下
    t.min_mtu(1332);
    // 窗口必须控制在 quinn 硬限制之内：接收组装器 MAX_CHUNKS=1024（代码写死），
    // 即单流最多容忍 1024 个乱序空洞。公式：窗口 × 丢包率 ÷ 包大小 < 1024。
    // 当前链路实测丢包 30~50%、包 1308 字节，
    // 8MB 窗口会产生 1900~3200 个空洞 → 必然触发
    // "too many gaps in stream buffer" 断开整条连接（实测每次 70Mbps 测速后崩）。
    // 4MB 对应 30% 丢包时约 960 个空洞，刚好在安全线内；
    // 同时 4MB 仍是本链路 BDP（70Mbps × 141ms ≈ 1.23MB）的 3 倍，够跑满。
    t.receive_window(quinn_proto::VarInt::from_u32(16 * 1024 * 1024));
    t.stream_receive_window(quinn_proto::VarInt::from_u32(4 * 1024 * 1024));
    // 发送侧内存上限（quinn 内部「已交给 QUIC 但还没被 ACK 释放」的字节，
    // 按整条连接算，应用层完全看不见）。
    // 之前固定 16MB，比 cwnd 上限（4MB）大 4 倍：目标是本地回环服务时
    // 读取速度几百 MB/s，会先无声地灌满这 16MB，再灌满我们自己的 pending，
    // 最后触发「pending 超过上限」保护把流 reset，下载断在 6~8MB。
    // 收到 max_cwnd 的 2 倍：既留足 BBR 爬升空间，又让缓冲在写爆之前
    // 就能通过 write() 返回 Blocked / 部分写入，把背压传回出站任务。
    let send_window = max_cwnd
        .load(std::sync::atomic::Ordering::Relaxed)
        .saturating_mul(2)
        .clamp(2 * 1024 * 1024, 16 * 1024 * 1024);
    t.send_window(send_window);
    // 让对端 5ms 内回 ACK：默认 25ms 会拉高 RTT，并使 PTO 误判丢包。
    // 通过 ACK Frequency 扩展协商，属于 QUIC 标准扩展。
    let mut ack = quinn_proto::AckFrequencyConfig::default();
    ack.max_ack_delay(Some(Duration::from_millis(5)));
    t.ack_frequency_config(Some(ack));
    // 拥塞控制：原生 BBR + 可自适应窗口上限。
    // 纯 BBR 在跨境高丢包链路上会把 ACK 聚合误判成高带宽，cwnd 一路膨胀；
    // CappedBbr 把窗口钳在 max_cwnd 内，外层根据实测丢包率每 2 秒调整。
    // 另外受 quinn 硬限制约束（MAX_CHUNKS=1024，窗口×丢包÷包大小 必须低于它）。
    t.congestion_controller_factory(Arc::new(
        crate::quic::capped::CappedBbrConfig::new(max_cwnd),
    ));
    // 单连接多流是核心优势，把并发流上限调高
    t.max_concurrent_bidi_streams(1024u32.into());
    t.max_concurrent_uni_streams(1024u32.into());
    Arc::new(t)
}

/// 客户端 QUIC 配置：跳过内层证书校验。
pub fn client_config(max_cwnd: std::sync::Arc<std::sync::atomic::AtomicU64>) -> ClientConfig {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerifier))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let quic = QuicClientConfig::try_from(crypto).expect("quic client config");
    let mut cfg = ClientConfig::new(Arc::new(quic));
    cfg.transport_config(transport_config(max_cwnd));
    cfg
}

/// 服务端 QUIC 配置：使用运行时自签证书。
pub fn server_config(max_cwnd: std::sync::Arc<std::sync::atomic::AtomicU64>) -> ServerConfig {
    let (chain, key) = self_signed();
    // quinn 0.11.19 的 QuicServerConfig::new 是私有的，走 rustls → TryFrom 路径
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("quic server cert");
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let quic = QuicServerConfig::try_from(crypto).expect("quic server crypto");
    let mut cfg = ServerConfig::with_crypto(Arc::new(quic));
    cfg.transport = transport_config(max_cwnd);
    cfg
}

/// 跳过内层证书校验。
/// 这是安全的：外层 FakeTLS + AEAD 已经完成了真实身份验证与加密，
/// 内层证书只用于让 QUIC 的 TLS 状态机正常走完。
#[derive(Debug)]
struct SkipVerifier;

impl ServerCertVerifier for SkipVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
