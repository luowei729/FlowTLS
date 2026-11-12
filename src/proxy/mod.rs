//! 代理协议公共类型。
//!
//! QUIC 流上传输的第一个载荷是「目标地址帧」，格式为：
//!   [总长 u16][ATYP u8][地址][端口 u16]
//! 服务端先读 2 字节总长，再读满整个地址帧，避免依赖流的分包边界。

use tokio::sync::{mpsc, oneshot};

pub mod http;
pub mod socks5;

/// 本地代理任务发往 QUIC 事件循环的动作。
pub enum ProxyAction {
    /// 打开一条新流：携带目标地址帧；事件循环打开流后回传流 ID 和下行数据通道
    Open {
        target: Vec<u8>,
        reply: oneshot::Sender<Option<(quinn_proto::StreamId, mpsc::UnboundedReceiver<Vec<u8>>)>>,
    },
    /// 本地 → 远端 的数据
    Data(quinn_proto::StreamId, Vec<u8>),
    /// 本地方向结束（FIN）
    Fin(quinn_proto::StreamId),
    /// 彻底放弃一条流：发 STOP_SENDING + RESET，告诉对端别再往这条流写。
    ///
    /// 本地连接被强制关闭时（浏览器取消下载、curl 超时退出）必须发这个：
    /// 否则服务端不知道客户端已经不再收数据，会把目标 socket 继续读下去，
    /// 一直堆到背压高水位，然后干等 30 秒兜底超时才放弃
    /// （日志里那些「背压等待超过 30 秒，放弃该流」就是漏发造成的）。
    Stop(quinn_proto::StreamId),
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

/// 解析地址帧（不含 2 字节长度前缀），返回主机和端口。
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
}
