//! 代理协议公共类型。
//!
//! QUIC 流上传输的第一个载荷是「目标地址帧」，格式为：
//!   [总长 u16][ATYP u8][地址][端口 u16]
//! 服务端先读 2 字节总长，再读满整个地址帧，避免依赖流的分包边界。

use tokio::sync::{mpsc, oneshot};

pub mod http;
pub mod socks5;
pub mod udp;

/// 本地代理任务发往 QUIC 事件循环的动作。
///
/// **每个涉及 stream 的动作都带 `epoch`**：
/// stream id 是 quinn 按连接分配的，重连后会从 0 重新开始。
/// 而 `pipe_stream` 的收尾（`stop`）可能延后很久——它的 reader 一半卡在
/// 本地 socket 的 `read()` 上，只有本地对端关闭才会走到 `join!` 之后。
/// 这段时间里新连接可能已经开了同号的新流，一个陈旧的 `Stop(0)`
/// 就会把新流 RESET 掉（表现为重连后偶尔有请求莫名失败）。
/// 用 epoch 隔离后，陈旧动作一律被丢弃。
pub enum ProxyAction {
    /// 打开一条新流：携带目标地址帧；事件循环打开流后回传流 ID 和下行数据通道
    Open {
        epoch: u64,
        target: Vec<u8>,
        reply: oneshot::Sender<Option<(quinn_proto::StreamId, mpsc::UnboundedReceiver<Vec<u8>>)>>,
    },
    /// 本地 → 远端 的数据
    Data(u64, quinn_proto::StreamId, Vec<u8>),
    /// 本地方向结束（FIN）
    Fin(u64, quinn_proto::StreamId),
    /// 彻底放弃一条流：发 STOP_SENDING + RESET，告诉对端别再往这条流写。
    ///
    /// 本地连接被强制关闭时（浏览器取消下载、curl 超时退出）必须发这个：
    /// 否则服务端不知道客户端已经不再收数据，会把目标 socket 继续读下去，
    /// 一直堆到背压高水位，然后干等 30 秒兜底超时才放弃
    /// （日志里那些「背压等待超过 30 秒，放弃该流」就是漏发造成的）。
    Stop(u64, quinn_proto::StreamId),
    /// 本地 UDP relay 发来的一帧数据。
    ///
    /// 走 QUIC DATAGRAM 而不是 QUIC 流：不重传、不保序、队列满直接丢。
    /// 这是 UDP 本该有的语义，也是 hysteria2 的做法。
    /// 注意这条动作**永远不阻塞**：调用方用 `try_send` 投递，
    /// 通道满说明 QUIC 侧跟不上，按 UDP 语义丢弃即可——
    /// 绝不能让 UDP 反压把本地收包循环卡住（那会把整个 relay 拖死）。
    ///
    /// 这里不需要 epoch：session id 由客户端进程单调分配、跨重连不复用。
    Udp {
        /// 会话 ID：一条 QUIC 连接内唯一，由客户端本地 relay 分配
        session: u32,
        /// 目标地址帧 `[ATYP][ADDR][PORT]`，每个包都带
        target: Vec<u8>,
        /// UDP 载荷
        payload: Vec<u8>,
    },
}

/// SOCKS5 风格的地址编码。
pub fn encode_target(host: &str, port: u16) -> Vec<u8> {
    let mut inner = Vec::new();
    // 先尝试 IPv4，再尝试 IPv6，最后按域名处理
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        inner.push(1);
        inner.extend_from_slice(&v4.octets());
    } else if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        inner.push(4);
        inner.extend_from_slice(&v6.octets());
    } else {
        inner.push(3);
        let name = host.as_bytes();
        inner.push(name.len() as u8);
        inner.extend_from_slice(name);
    }
    inner.extend_from_slice(&port.to_be_bytes());

    // 外层加 2 字节长度前缀，服务端按长度精确读取
    let mut out = Vec::with_capacity(2 + inner.len());
    out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    out.extend_from_slice(&inner);
    out
}

/// 解析 SOCKS5 风格的地址帧（不含 2 字节长度前缀），返回主机和端口。
pub fn decode_target(buf: &[u8]) -> Option<(String, u16)> {
    let atyp = *buf.first()?;
    match atyp {
        1 => {
            // IPv4：1 + 4 + 2
            if buf.len() < 7 {
                return None;
            }
            let ip = std::net::Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Some((ip.to_string(), port))
        }
        4 => {
            // IPv6：1 + 16 + 2
            if buf.len() < 19 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Some((ip.to_string(), port))
        }
        3 => {
            // 域名：1 + 1 + n + 2
            if buf.len() < 4 {
                return None;
            }
            let n = buf[1] as usize;
            if buf.len() < 2 + n + 2 {
                return None;
            }
            let host = String::from_utf8(buf[2..2 + n].to_vec()).ok()?;
            let port = u16::from_be_bytes([buf[2 + n], buf[3 + n]]);
            Some((host, port))
        }
        _ => None,
    }
}

/// 解析 SOCKS5 UDP 请求（RFC 1928 §7），返回 `(地址帧, 载荷起始偏移)`。
///
/// 格式：`RSV(2) FRAG(1) ATYP(1) ADDR(n) PORT(2) DATA`
/// - `RSV` 必须全 0；
/// - `FRAG` 必须为 0：我们不实现分片（和 hysteria2、绝大多数实现一致），
///   收到分片包直接丢弃比假装支持更安全；
/// - 返回的地址帧是 `[ATYP][ADDR][PORT]`，可以直接喂给 `decode_target`
///   和 `udp::encode_client`，不需要再拷一次。
pub fn parse_socks5_udp(buf: &[u8]) -> Option<(&[u8], usize)> {
    // 最少要有 RSV(2) + FRAG(1) + ATYP(1)，之后按 ATYP 决定长度
    if buf.len() < 4 {
        return None;
    }
    if buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
        // RSV 非零或 FRAG != 0：不合法或分片包，丢弃
        return None;
    }
    // 地址帧从 ATYP 开始；总长度 = 1(ATYP) + 地址 + 2(端口)
    let frame_len = match buf[3] {
        1 => 1 + 4 + 2,
        4 => 1 + 16 + 2,
        3 => {
            // 域名：ATYP + 1 字节长度 + n
            if buf.len() < 5 {
                return None;
            }
            1 + 1 + buf[4] as usize + 2
        }
        _ => return None,
    };
    // 头总长 = RSV(2) + FRAG(1) + 地址帧
    let total = 3 + frame_len;
    if buf.len() < total {
        return None;
    }
    Some((&buf[3..total], total))
}

/// 组装 SOCKS5 UDP 响应：`RSV(2) FRAG(1)` + 地址帧 + 载荷。
///
/// 回程必须带上目标地址，否则本地应用分不清这个包是谁回的
/// （同一个 relay socket 可能同时和多个目标通信）。
pub fn build_socks5_udp(target: &[u8], payload: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.reserve(3 + target.len() + payload.len());
    // RSV 两个 0 + FRAG=0（不分片）
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(target);
    out.extend_from_slice(payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_roundtrip() {
        // 三种地址类型都要能正确编码解码
        for (host, port) in [
            ("1.2.3.4", 443u16),
            ("2001:db8::1", 8080),
            ("example.com", 80),
        ] {
            let encoded = encode_target(host, port);
            let len = u16::from_be_bytes([encoded[0], encoded[1]]) as usize;
            assert_eq!(len, encoded.len() - 2);
            let (h, p) = decode_target(&encoded[2..]).expect("decode");
            assert_eq!(p, port);
            assert_eq!(h, host);
        }
    }

    #[test]
    fn socks5_udp_header_roundtrip() {
        // 上行：RSV(2) FRAG(1) + 地址帧 + 载荷
        let target = encode_target("8.8.8.8", 53);
        let target_frame = &target[2..];
        let mut pkt = vec![0u8, 0, 0];
        pkt.extend_from_slice(target_frame);
        pkt.extend_from_slice(b"query");

        let (frame, off) = parse_socks5_udp(&pkt).expect("parse");
        assert_eq!(frame, target_frame);
        assert_eq!(&pkt[off..], b"query");
        assert_eq!(decode_target(frame), Some(("8.8.8.8".to_string(), 53)));

        // 下行：组出来的包必须能被同一套解析逻辑读回
        let mut out = Vec::new();
        build_socks5_udp(frame, b"answer", &mut out);
        let (f2, off2) = parse_socks5_udp(&out).expect("parse out");
        assert_eq!(f2, frame);
        assert_eq!(&out[off2..], b"answer");
    }

    #[test]
    fn socks5_udp_rejects_fragments() {
        // FRAG != 0 的分片包必须被拒绝（我们不实现重组）
        let pkt = [0u8, 0, 1, 1, 8, 8, 8, 8, 0, 53];
        assert!(parse_socks5_udp(&pkt).is_none());
        // 截断的包
        assert!(parse_socks5_udp(&[0, 0, 0, 1, 8]).is_none());
    }
}
