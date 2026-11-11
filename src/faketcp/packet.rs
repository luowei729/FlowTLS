//! FakeTCP 的 IP/TCP 报文构造与解析。
//!
//! 这里的所有报文都由本模块手工拼装，完全不经过内核 TCP 栈。
//! 之所以自己拼包：内核 TCP 会维护握手、序号、重传和拥塞窗口，
//! 我们需要的是「外观像 TCP、内部像 UDP」的无状态数据报语义。

use std::net::Ipv4Addr;

// TCP 标志位定义，构造和解析时共用，避免魔法数字散落各处
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

/// 解析后的 IPv4 + TCP 报文视图。
/// payload 直接借用接收缓冲区，零拷贝，避免每包一次内存分配。
pub struct ParsedPacket<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub ip_id: u16,
    /// TCP 选项里的窗口缩放因子（kind=3）。
    /// 用 wscale=12 作为伪包标识：NAT 会把 IP ID 改写成 0，但不动 TCP 选项。
    pub wscale: Option<u8>,
    pub payload: &'a [u8],
}

/// 16 位反码求和，IP 头和 TCP 伪头校验都复用这个函数。
fn sum16(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    // 奇数长度时最后一个字节要补到高 8 位
    if let Some(&b) = chunks.remainder().first() {
        sum += (b as u32) << 8;
    }
    sum
}

/// 把 32 位累加和折叠成 16 位反码，作为最终校验和。
fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// 解析 AF_PACKET 收到的以太网帧，提取 IPv4 + TCP 视图。
/// 只支持无分片的 IPv4 单播报文；分片、IPv6、非 TCP 一律返回 None。
pub fn parse_frame(frame: &[u8]) -> Option<ParsedPacket<'_>> {
    // 以太网头最短 14 字节，先做长度检查避免越界
    if frame.len() < 14 {
        return None;
    }
    // 跳过目的 MAC(6) + 源 MAC(6)，读 EtherType
    let mut off = 12usize;
    let mut ethertype = u16::from_be_bytes([frame[off], frame[off + 1]]);
    off += 2;
    // 处理单层 802.1Q VLAN 标签，部分云主机/虚拟化环境会带上
    if ethertype == 0x8100 {
        if frame.len() < off + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([frame[off + 2], frame[off + 3]]);
        off += 4;
    }
    // 只关心 IPv4
    if ethertype != 0x0800 || frame.len() < off + 20 {
        return None;
    }

    let ip = &frame[off..];
    let version_ihl = ip[0];
    if version_ihl >> 4 != 4 {
        return None;
    }
    // IHL 以 4 字节为单位，正常是 5（20 字节）
    let ihl = ((version_ihl & 0x0f) as usize) * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if total_len < ihl || total_len > ip.len() {
        return None;
    }
    // 分片报文直接丢弃：QUIC 数据报必须保持单包，否则无法按记录解析
    let frag = u16::from_be_bytes([ip[6], ip[7]]);
    if frag & 0x3fff != 0 {
        return None;
    }
    // 协议号必须为 6（TCP）
    if ip[9] != 6 {
        return None;
    }
    let ip_id = u16::from_be_bytes([ip[4], ip[5]]);
    let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);

    let tcp = &ip[ihl..total_len];
    if tcp.len() < 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let data_off = ((tcp[12] >> 4) as usize) * 4;
    if data_off < 20 || tcp.len() < data_off {
        return None;
    }
    let flags = tcp[13];
    // 解析 TCP 选项里的窗口缩放因子（kind=3）。
    // NAT 会改写 IP ID，但不会改 TCP 选项，所以伪包标识改用 wscale。
    let mut wscale = None;
    let mut i = 20usize;
    while i < data_off {
        let kind = tcp[i];
        if kind == 0 {
            break; // EOL
        }
        if kind == 1 {
            i += 1; // NOP
            continue;
        }
        if i + 1 >= data_off {
            break;
        }
        let len = tcp[i + 1] as usize;
        if len < 2 || i + len > data_off {
            break;
        }
        if kind == 3 && len == 3 {
            wscale = Some(tcp[i + 2]);
        }
        i += len;
    }
    let payload = &tcp[data_off..];

    Some(ParsedPacket {
        src,
        dst,
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        ip_id,
        wscale,
        payload,
    })
}

/// SYN / SYN-ACK 携带的 TCP 选项：
/// MSS=1460，SACK permitted，窗口缩放 shift=12（窗口 65535 × 4096 = 256MB）。
/// shift 7 只有 8MB，BBR 窗口会超过它，超窗的包仍会被中间设备丢弃；
/// 这里直接给到 256MB，确保任何拥塞窗口下在途数据都不会超窗。
/// 末尾用 NOP 补齐到 4 字节对齐。
pub const SYN_OPTIONS: &[u8] = &[
    0x02, 0x04, 0x05, 0xb4, // MSS 1460
    0x04, 0x02, // SACK permitted
    0x03, 0x03, 0x0c, // 窗口缩放 shift 12
    0x01, 0x01, 0x01, // NOP 对齐
];

/// 构造一个完整的 IPv4 + TCP 报文（不含以太网头），用于 IPPROTO_RAW 发送。
/// 内核在 IP_HDRINCL 模式下只负责路由和二层封装，报文内容完全由我们决定。
#[allow(clippy::too_many_arguments)]
pub fn build_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    ip_id: u16,
    payload: &[u8],
) -> Vec<u8> {
    build_packet_opts(
        src_ip, dst_ip, src_port, dst_port, seq, ack, flags, ip_id, &[], payload,
    )
}

/// 带 TCP 选项的版本：SYN / SYN-ACK 用它携带窗口缩放。
#[allow(clippy::too_many_arguments)]
pub fn build_packet_opts(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    ip_id: u16,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let header_len = 20 + options.len();
    let tcp_len = header_len + payload.len();
    let total_len = 20 + tcp_len;
    let mut buf = vec![0u8; total_len];

    // ---- IPv4 头 ----
    buf[0] = 0x45; // 版本 4，头长 5*4=20
    buf[1] = 0; // TOS 普通
    buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&ip_id.to_be_bytes());
    buf[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF 位，禁止分片
    buf[8] = 64; // TTL
    buf[9] = 6; // TCP
    buf[10..12].copy_from_slice(&[0, 0]); // 校验和先占位
    buf[12..16].copy_from_slice(&src_ip.octets());
    buf[16..20].copy_from_slice(&dst_ip.octets());
    let ip_sum = fold(sum16(&buf[..20]));
    buf[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    // ---- TCP 头 ----
    let t = &mut buf[20..20 + header_len];
    t[0..2].copy_from_slice(&src_port.to_be_bytes());
    t[2..4].copy_from_slice(&dst_port.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    // 数据偏移按 4 字节为单位，包含选项
    t[12] = ((header_len / 4) as u8) << 4;
    t[13] = flags;
    t[14..16].copy_from_slice(&65535u16.to_be_bytes()); // 窗口：配合 WS 选项实际为 8MB
    t[16..18].copy_from_slice(&[0, 0]); // 校验和占位
    t[18..20].copy_from_slice(&[0, 0]); // 紧急指针
    if !options.is_empty() {
        t[20..].copy_from_slice(options);
    }

    // 载荷拷贝到 TCP 头之后
    buf[20 + header_len..].copy_from_slice(payload);

    // ---- TCP 校验和（含伪头）----
    // 伪头：源 IP(4) + 目的 IP(4) + 0 + 协议(1) + TCP 长度(2)
    let mut pseudo = Vec::with_capacity(12 + tcp_len);
    pseudo.extend_from_slice(&src_ip.octets());
    pseudo.extend_from_slice(&dst_ip.octets());
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&buf[20..20 + header_len]);
    pseudo.extend_from_slice(payload);
    let tcp_sum = fold(sum16(&pseudo));
    buf[36..38].copy_from_slice(&tcp_sum.to_be_bytes());

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse_roundtrip() {
        // 构造一个带载荷的 PSH+ACK 包，再解析回来验证字段一致
        let src = Ipv4Addr::new(10, 0, 0, 253);
        let dst = Ipv4Addr::new(103, 244, 89, 78);
        let pkt = build_packet(
            src,
            dst,
            44300,
            8443,
            12345,
            67890,
            TCP_PSH | TCP_ACK,
            0xF107,
            b"hello",
        );
        // 构造时不含以太网头，这里手工补 14 字节以太网头再解析
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&pkt);
        let parsed = parse_frame(&frame).expect("parse");
        assert_eq!(parsed.src, src);
        assert_eq!(parsed.dst, dst);
        assert_eq!(parsed.src_port, 44300);
        assert_eq!(parsed.dst_port, 8443);
        assert_eq!(parsed.seq, 12345);
        assert_eq!(parsed.ack, 67890);
        assert_eq!(parsed.flags, TCP_PSH | TCP_ACK);
        assert_eq!(parsed.ip_id, 0xF107);
        assert_eq!(parsed.payload, b"hello");
    }
}
