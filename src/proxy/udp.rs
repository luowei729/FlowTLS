//! UDP 会话帧编解码：用 QUIC DATAGRAM（RFC 9221）承载 UDP。
//!
//! 设计完全对齐 hysteria2 的 UDP 处理：
//! - **不重传、不重排、不重放**：QUIC DATAGRAM 本身就是不可靠帧，
//!   丢了就是丢了，绝不补发——这是 UDP 的语义，也是 hy2 的做法；
//! - **不做背压**：发送队列满就直接丢弃新包，绝不让 UDP 反压到本地应用；
//! - **超 MTU 直接丢**：不做应用层分片（分片会引入序号、重组超时和内存放大，
//!   而 DNS/游戏/QUIC 报文本来就基本在 1200 字节以内）。
//!
//! 线上格式（与 hysteria2 的 `ParseUDPPacket` 一致）：
//!
//! ```text
//! 客户端 → 服务端：[session u32 BE][addrLen u16 BE][ATYP][ADDR][PORT][payload]
//! 服务端 → 客户端：[session u32 BE][payload]
//! ```
//!
//! 上行每个包都带目标地址（不多占几字节，换来服务端完全无状态地重建会话：
//! 客户端重连后服务端是新连接、会话表是空的，第一个带地址的包就能自愈）；
//! 下行不带地址，客户端自己按 session 记着目标是哪。
//!
//! `session` 由客户端分配，作用域是「一条 QUIC 连接内的一个本地 UDP 五元组」。

/// 上行帧头长度：session(4) + addrLen(2)
pub const HEADER_LEN: usize = 6;

/// 编码一帧「客户端 → 服务端」的 UDP 数据报。
///
/// `target` 是地址帧 `[ATYP][ADDR][PORT]`（与 QUIC 流首帧同格式，
/// 可直接用 `decode_target` 解析），每个包都带。
/// 写入调用方提供的缓冲，稳态零分配。
pub fn encode_client(session: u32, target: &[u8], payload: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.reserve(HEADER_LEN + target.len() + payload.len());
    out.extend_from_slice(&session.to_be_bytes());
    out.extend_from_slice(&(target.len() as u16).to_be_bytes());
    out.extend_from_slice(target);
    out.extend_from_slice(payload);
}

/// 解析「客户端 → 服务端」帧，返回 `(session, 地址帧, 载荷)`。
/// 任何不合法的输入都返回 None，调用方应静默丢弃（UDP 语义）。
pub fn parse_client(buf: &[u8]) -> Option<(u32, &[u8], &[u8])> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    let session = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let addr_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    // addr_len 必须 > 0：上行每包都带地址，0 长度说明对端实现不匹配
    if addr_len == 0 || buf.len() < HEADER_LEN + addr_len {
        return None;
    }
    let target = &buf[HEADER_LEN..HEADER_LEN + addr_len];
    let payload = &buf[HEADER_LEN + addr_len..];
    Some((session, target, payload))
}

/// 编码一帧「服务端 → 客户端」的 UDP 数据报：只有 session + 载荷。
pub fn encode_server(session: u32, payload: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.reserve(4 + payload.len());
    out.extend_from_slice(&session.to_be_bytes());
    out.extend_from_slice(payload);
}

/// 解析「服务端 → 客户端」帧，返回 `(session, 载荷)`。
pub fn parse_server(buf: &[u8]) -> Option<(u32, &[u8])> {
    if buf.len() < 4 {
        return None;
    }
    let session = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    Some((session, &buf[4..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_frame_roundtrip() {
        // 目标地址用 IPv4 帧：[ATYP=1][4 字节 IP][2 字节端口]
        let target = [1u8, 8, 8, 8, 8, 0, 53];
        let payload = b"dns query bytes";
        let mut buf = Vec::new();
        encode_client(0xDEAD_BEEF, &target, payload, &mut buf);
        assert_eq!(buf.len(), HEADER_LEN + target.len() + payload.len());

        let (session, got_target, got_payload) = parse_client(&buf).expect("parse");
        assert_eq!(session, 0xDEAD_BEEF);
        assert_eq!(got_target, &target[..]);
        assert_eq!(got_payload, payload);
    }

    #[test]
    fn server_frame_roundtrip() {
        let payload = b"dns response";
        let mut buf = Vec::new();
        encode_server(7, payload, &mut buf);
        let (session, got) = parse_server(&buf).expect("parse");
        assert_eq!(session, 7);
        assert_eq!(got, payload);
    }

    #[test]
    fn rejects_malformed() {
        // 太短
        assert!(parse_client(&[0, 0, 0, 1, 0]).is_none());
        // addr_len = 0：上行必须带地址
        assert!(parse_client(&[0, 0, 0, 1, 0, 0, b'x']).is_none());
        // addr_len 越界
        assert!(parse_client(&[0, 0, 0, 1, 0, 99, 1, 2, 3]).is_none());
        assert!(parse_server(&[0, 0, 0]).is_none());
    }

    #[test]
    fn empty_payload_is_valid() {
        // 空载荷要能解析出来（某些 UDP 应用会发空包做探测）
        let target = [1u8, 1, 1, 1, 1, 0, 53];
        let mut buf = Vec::new();
        encode_client(1, &target, &[], &mut buf);
        let (session, _, payload) = parse_client(&buf).expect("parse");
        assert_eq!(session, 1);
        assert!(payload.is_empty());
    }
}
