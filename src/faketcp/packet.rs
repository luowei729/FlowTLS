//! FakeTCP 的 IP/TCP 报文构造与解析。
//!
//! 这里的所有报文都由本模块手工拼装，完全不经过内核 TCP 栈。
//! 之所以自己拼包：内核 TCP 会维护握手、序号、重传和拥塞窗口，
//! 我们需要的是「外观像 TCP、内部像 UDP」的无状态数据报语义。

use std::net::Ipv4Addr;

// TCP 标志位定义，构造和解析时共用，避免魔法数字散落各处
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
/// RST 标志：当前不主动发（连接拆除用 FIN），保留常量供解析侧比对
#[allow(dead_code)] // 解析侧保留：用于识别内核回的 RST
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

// ---- IP ID 分流标记 ----
//
// 我们必须在两端用 iptables 把伪造包挡在内核 TCP 栈之外（服务端防止内核回
// SYN-ACK/RST，客户端防止内核回 RST），而 iptables 需要一个「静态可匹配」的
// 特征。TCP 选项已经全部改回真实值（含时间戳、wscale=9），不能再当指纹，
// 因此静态标记只能留在 IP ID 上。
//
// **标记值必须来自配置（`faketcp.ip_id_magic`），不能写死在代码里。**
// 写死一个固定值意味着任何 DPI 只要加一条通用规则
// （「IP ID 高字节 == 0xF1」）就能一次性命中所有部署。
// 从配置派生后，每个部署的特征各不相同，检测方必须针对单条链路重新学习，
// 对抗成本从「一次编写」变成「逐个部署采集」。
//
// 关键权衡——标记范围不能随便放大：
// iptables 会把这些包直接 DROP，内核看不到就不会有任何响应。
// 若标记覆盖的 IP ID 范围过宽，普通端口探测只要 IP ID 恰好落进该范围，
// 就会得到「完全没有响应」，反而暴露这里有一层过滤。
//   高字节固定（256 个值）→ 0.4% 的探测无响应，与正常丢包率难以区分；
//   高四位固定（4096 个值）→ 6%，异常率高一倍以上，不能接受。
// 所以刻意保持「高字节固定」的窄范围：牺牲一点可见性，换取探测行为一致。
//
// 残留特征：单条连接的 IP ID 以 256 为周期锯齿递增。
// 要彻底消除必须换掉 iptables 的匹配依据（例如把口令派生的 12 bit 标签
// 放进 SYN 的 TSval 低位、TSecr 保持 0 以符合 RFC 7323），属于后续工作。
/// 默认标记高字节（等价于配置 `ip_id_magic: 0xF107` 的高字节）。
pub const IPID_MARK: u16 = 0xF100;
/// 可递增的低 8 位掩码
pub const IPID_LOW_MASK: u16 = 0x00FF;

/// 从配置的 `ip_id_magic` 取出标记高字节。
/// 只有高字节参与标记，低字节留给递增计数。
#[inline]
pub fn ipid_mark(magic: u16) -> u16 {
    magic & 0xFF00
}

/// 取下一个 IP ID：高字节保持标记，低字节 +1 回绕。
#[inline]
pub fn next_ipid(mark: u16, cur: u16) -> u16 {
    mark | (cur.wrapping_add(1) & IPID_LOW_MASK)
}

/// 随机起始 IP ID：让每条连接的起点不同，避免「所有连接都从同一值开始」。
#[inline]
pub fn random_ipid(mark: u16) -> u16 {
    use rand::Rng;
    mark | (rand::thread_rng().gen::<u16>() & IPID_LOW_MASK)
}

/// 解析后的 IPv4 + TCP 报文视图。
/// payload 直接借用接收缓冲区，零拷贝，避免每包一次内存分配。
// 部分字段当前没有读取（ack/window/tsecr），但保留它们是有意的：
// 排查伪装效果时要能直接从解析结果核对窗口值和时间戳回显，
// 删掉会让「抓包对不上」这类问题只能靠手工算字节偏移。
#[allow(dead_code)]
pub struct ParsedPacket<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub ip_id: u16,
    /// TCP 窗口字段（未经 wscale 放大）
    pub window: u16,
    /// TCP 选项里的窗口缩放因子（kind=3）。
    /// 当前分流仍靠这里：客户端的 NAT 会改写 IP ID，但不动 TCP 选项。
    pub wscale: Option<u8>,
    /// TCP 时间戳选项的 TSval（kind=8, len=10）。
    /// 必须回显到回包的 TSecr 里，否则对端/中间盒会认为时间戳不合法。
    pub tsval: Option<u32>,
    /// TCP 时间戳选项的 TSecr
    pub tsecr: Option<u32>,
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
    let window = u16::from_be_bytes([tcp[14], tcp[15]]);
    // 解析 TCP 选项里的窗口缩放因子（kind=3）与时间戳（kind=8）。
    // NAT 会改写 IP ID，但不会改 TCP 选项，所以伪包分流改用 wscale。
    let mut wscale = None;
    let mut tsval = None;
    let mut tsecr = None;
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
        // 时间戳：kind=8 len=10，后跟 TSval(4) + TSecr(4)
        if kind == 8 && len == 10 {
            tsval = Some(u32::from_be_bytes([
                tcp[i + 2],
                tcp[i + 3],
                tcp[i + 4],
                tcp[i + 5],
            ]));
            tsecr = Some(u32::from_be_bytes([
                tcp[i + 6],
                tcp[i + 7],
                tcp[i + 8],
                tcp[i + 9],
            ]));
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
        window,
        wscale,
        tsval,
        tsecr,
        payload,
    })
}

/// 数据段携带的 TCP 时间戳选项长度：`nop,nop,kind=8,len=10,TSval(4),TSecr(4)`。
/// 12 字节，正好 4 字节对齐，TCP 头从 20 变 32。
pub const TS_OPT_LEN: usize = 12;

/// 帧里数据段的最大 TCP 头长度（20 基础 + 12 时间戳）。
pub const TCP_HDR_WITH_TS: usize = 20 + TS_OPT_LEN;

/// 交换端口的 TCP 窗口缩放因子。
/// 真实 Linux 在这台机器的实测值是 9（见 DEVTIPS 31 的抓包对照），
/// 原来用 12 是个明显异常值——256MB 的窗口真实操作系统基本不会声明。
pub const WSCALE: u8 = 9;

/// 写一个 TCP 时间戳选项到 `dst`（必须正好 12 字节）。
/// 开头两个 NOP 是为了对齐，和 Linux 的 `nop,nop,TS val .. ecr ..` 逐字节一致。
#[inline]
pub fn write_ts_option(dst: &mut [u8], tsval: u32, tsecr: u32) {
    dst[0] = 0x01; // NOP
    dst[1] = 0x01; // NOP
    dst[2] = 0x08; // kind = 时间戳
    dst[3] = 0x0a; // len = 10
    dst[4..8].copy_from_slice(&tsval.to_be_bytes());
    dst[8..12].copy_from_slice(&tsecr.to_be_bytes());
}

/// 构造 SYN / SYN-ACK 的 TCP 选项（20 字节，与真实 Linux 开启时间戳后完全一致）：
/// `MSS 1460` + `SACK permitted` + `TS val <tsval> ecr <tsecr>` + `NOP` + `wscale 9`。
///
/// 字节布局（相对选项起点）：
/// ```text
///  0..4   02 04 05 b4   MSS 1460
///  4..6   04 02         SACK permitted
///  6..16  08 0a <tsval> <tsecr>   TCP 时间戳
/// 16..17  01            NOP
/// 17..20  03 03 09      window scale = 9
/// ```
///
/// 之前这里是 `MSS + SACK + wscale 12 + 3×NOP`，有两个可识别特征：
/// 1. **完全缺时间戳**——现代 Linux/Windows/macOS/Android 默认都开，
///    一条双向传几万个包的连接一个 TS 都没有，任何 DPI 都能一眼判定为伪造；
/// 2. wscale=12 是罕见值（Windows 8、Linux 7~9），256MB 窗口真实系统不会声明。
/// 现在两者都改成真实值，分流改由 IP ID 高 4 位承担（见 `IPID_MARK`）。
pub fn syn_options(tsval: u32, tsecr: u32) -> [u8; 20] {
    let mut o = [0u8; 20];
    o[0..4].copy_from_slice(&[0x02, 0x04, 0x05, 0xb4]); //  0..4  MSS 1460
    o[4..6].copy_from_slice(&[0x04, 0x02]); //             4..6  SACK permitted
    o[6] = 0x08; //                                        6     TS kind
    o[7] = 0x0a; //                                        7     TS len = 10
    o[8..12].copy_from_slice(&tsval.to_be_bytes()); //     8..12 TSval
    o[12..16].copy_from_slice(&tsecr.to_be_bytes()); //   12..16 TSecr
    o[16] = 0x01; //                                      16     NOP 对齐
    o[17] = 0x03; //                                      17     wscale kind
    o[18] = 0x03; //                                      18     wscale len = 3
    o[19] = WSCALE; //                                    19     shift = 9
    o
}

/// 构造一个 TCP 段所需的全部可变字段。
/// 用结构体而不是十几个参数，避免调用点错位（之前 `build_packet` 已有 9 个参数）。
pub struct TcpSeg<'a> {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub ip_id: u16,
    /// 通告窗口（未经 wscale 放大）
    pub window: u16,
    pub tsval: u32,
    pub tsecr: u32,
    /// SYN / SYN-ACK 的完整选项表；数据包与纯 ACK 传空，
    /// 由构造函数自动追加 12 字节时间戳选项。传空数组时长度必须为 0。
    pub options: &'a [u8],
    pub payload: &'a [u8],
}

/// 一条伪造 TCP 连接的时间戳时钟。
///
/// 真实 TCP 的 TSval 是「内核启动以来的毫秒数 + 随机偏移」，单调递增；
/// TSecr 回显对端最近一次的 TSval。中间盒和时间戳校验类 DPI 会检查：
/// 1. TSval 单调不回退；2. TSecr 必须等于自己最近发出的 TSval。
/// 两者都对不上就会被判定为「非 TCP 实现」。
pub struct TcpClock {
    /// 连接建立时刻，用于计算已过去的毫秒数
    t0: std::time::Instant,
    /// 随机基准值，让每条连接的 TSval 起点不同（真实栈也是随机偏移）
    base: u32,
    /// 对端最近一次的 TSval，回包时填进 TSecr
    pub peer_ts: u32,
}

impl TcpClock {
    pub fn new() -> Self {
        use rand::Rng;
        Self {
            t0: std::time::Instant::now(),
            base: rand::thread_rng().gen(),
            peer_ts: 0,
        }
    }

    /// 用指定的 TSval 基准构造。
    ///
    /// 为什么需要它：同一条连接里所有报文的 TSval 必须**单调不减**
    /// （RFC 7323 的 PAWS 就靠这个丢弃旧包）。握手阶段的 SYN-ACK 和
    /// ServerHello 由 `handle_packet` 直接发、不走 TcpClock，
    /// 如果连接建立后再 `TcpClock::new()` 取一个随机基准，
    /// 第一个数据包的 TSval 就可能小于前面握手包的 TSval，出现「时间戳回退」，
    /// 这是时间戳类 DPI 最容易抓的伪造特征。
    /// 传进来握手包用的 TSval（再 +2 留出空隙），后续就天然单调。
    pub fn new_at(base: u32) -> Self {
        Self {
            t0: std::time::Instant::now(),
            base,
            peer_ts: 0,
        }
    }

    /// 当前应发送的 TSval。
    /// 步长就是真实毫秒数，和 Linux 的 `tcp_time_stamp` 一致（不回退）。
    #[inline]
    pub fn tsval(&self) -> u32 {
        self.base
            .wrapping_add(self.t0.elapsed().as_millis() as u32)
    }

    /// 记录对端的时间戳，供后续回包回显。
    #[inline]
    pub fn observe(&mut self, tsval: Option<u32>) {
        if let Some(v) = tsval {
            self.peer_ts = v;
        }
    }
}

impl Default for TcpClock {
    fn default() -> Self {
        Self::new()
    }
}

/// 根据「已收下但还没被上层消费的字节数」计算要通告的窗口（未缩放值）。
///
/// 恒为 65535 是明显的伪造特征：真实 TCP 的窗口会随接收缓冲占用持续变化，
/// 而且 65535 换算后是 33.5MB 这种「整数上限」，真实栈用的
/// `tcp_rmem` 上限换算回来一般不会正好是这个值。
///
/// 这里按真实语义计算：接收缓冲总量（与 QUIC 的 receive_window 保持一致，
/// 16MB）减去未消费字节，再换算回未缩放值。
/// 空载时正好是 16MB >> 9 = 32768，与真实 Linux 在 16MB rmem 下的通告值一致；
/// 有积压时平滑下降，和真实下载时的窗口变化趋势相同。
#[inline]
pub fn advertised_window(unread: usize) -> u16 {
    /// 接收缓冲总量，与 `quic::config` 里的 receive_window 对齐
    const RCV_TOTAL: usize = 16 * 1024 * 1024;
    let free = RCV_TOTAL.saturating_sub(unread);
    // 换算回未缩放值；至少保留 1，避免声明零窗口把对端卡死
    ((free >> WSCALE).clamp(1, 65535)) as u16
}

/// 计算一个 TCP 段占用的序号长度（SYN 与 FIN 各占 1）。
#[inline]
pub fn seq_len(flags: u8, payload_len: usize) -> u32 {
    payload_len as u32 + u32::from(flags & (TCP_SYN | TCP_FIN) != 0)
}

/// 构造一个完整的 IPv4 + TCP 报文（不含以太网头）。
#[allow(clippy::too_many_arguments)]
pub fn build_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seg: &TcpSeg<'_>,
) -> Vec<u8> {
    let opts_len = if seg.options.is_empty() {
        TS_OPT_LEN
    } else {
        seg.options.len()
    };
    let mut out = Vec::with_capacity(40 + opts_len + seg.payload.len());
    build_packet_into(
        &mut out, src_ip, dst_ip, src_port, dst_port, seg,
    );
    out
}

/// 构造 IPv4 + TCP 报文，直接写入调用方提供的缓冲区（可反复复用）。
///
/// 与逐包分配版本的区别，都是为了高速率下的 CPU 开销：
/// 1. 复用 `out` 已分配的内存，不再每包 `vec![0u8; total_len]`；
/// 2. TCP 校验和直接在 `out` 上分段累加，不再拼一个 `pseudo` 临时 Vec。
///    原实现每包要把「伪头 + TCP 头 + 载荷」整段 memcpy 一遍，
///    等于载荷被遍历两次（一次拷贝、一次求和），这里只剩一次。
#[allow(clippy::too_many_arguments)]
pub fn build_packet_into(
    out: &mut Vec<u8>,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seg: &TcpSeg<'_>,
) {
    // 选项为空 = 数据包/纯 ACK，统一带 12 字节时间戳；
    // 否则用调用方给的完整选项表（SYN / SYN-ACK）。
    let auto_ts = seg.options.is_empty();
    let header_len = if auto_ts { TCP_HDR_WITH_TS } else { 20 + seg.options.len() };
    let tcp_len = header_len + seg.payload.len();
    let total_len = 20 + tcp_len;

    // 复用容量：resize 只改长度，已分配的堆内存保留；下面每个字节都会被覆盖，
    // 因此不需要先 clear（少一次 memset）
    out.resize(total_len, 0);

    // ---- IPv4 头 ----
    out[0] = 0x45; // 版本 4，头长 5*4=20
    out[1] = 0; // TOS 普通（真实服务器方向会是 0x4，由网络侧标记，我们照原样）
    out[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    out[4..6].copy_from_slice(&seg.ip_id.to_be_bytes());
    out[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF 位，禁止分片
    out[8] = 64; // TTL
    out[9] = 6; // TCP
    out[10..12].copy_from_slice(&[0, 0]); // 校验和先占位
    out[12..16].copy_from_slice(&src_ip.octets());
    out[16..20].copy_from_slice(&dst_ip.octets());
    let ip_sum = fold(sum16(&out[..20]));
    out[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    // ---- TCP 头 ----
    let t = &mut out[20..20 + header_len];
    t[0..2].copy_from_slice(&src_port.to_be_bytes());
    t[2..4].copy_from_slice(&dst_port.to_be_bytes());
    t[4..8].copy_from_slice(&seg.seq.to_be_bytes());
    t[8..12].copy_from_slice(&seg.ack.to_be_bytes());
    // 数据偏移按 4 字节为单位，包含选项
    t[12] = ((header_len / 4) as u8) << 4;
    t[13] = seg.flags;
    // 窗口必须随接收缓冲变化，恒为 65535 是明显的伪造特征。
    t[14..16].copy_from_slice(&seg.window.to_be_bytes());
    t[16..18].copy_from_slice(&[0, 0]); // 校验和占位
    t[18..20].copy_from_slice(&[0, 0]); // 紧急指针
    if auto_ts {
        write_ts_option(&mut t[20..32], seg.tsval, seg.tsecr);
    } else {
        t[20..].copy_from_slice(seg.options);
    }

    // 载荷拷贝到 TCP 头之后
    out[20 + header_len..].copy_from_slice(seg.payload);

    // ---- TCP 校验和（伪头 + TCP 头 + 载荷，全程零额外拷贝）----
    // 伪头 12 字节是固定格式，放栈上即可，不必再分配 Vec：
    // 源 IP(4) + 目的 IP(4) + 0 + 协议(1) + TCP 长度(2)
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip.octets());
    pseudo[4..8].copy_from_slice(&dst_ip.octets());
    pseudo[9] = 6;
    pseudo[10..12].copy_from_slice(&(tcp_len as u16).to_be_bytes());
    // TCP 头里的校验和字段此刻是 0，正好符合反码求和规则；
    // TCP 头与载荷在 out 中是连续的，一次遍历覆盖两段
    let mut sum = sum16(&pseudo);
    sum += sum16(&out[20..total_len]);
    let tcp_sum = fold(sum);
    out[36..38].copy_from_slice(&tcp_sum.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 校验和自验证：正确的报文整体再求一次反码和，结果必须为 0。
    /// 这是检验「去掉 pseudo 临时 Vec、改为在 out 上分段累加」是否正确的关键用例，
    /// 覆盖奇数/偶数载荷长度，确保首尾拼接的字节对齐规则没写错。
    #[test]
    fn checksum_valid() {
        let src = Ipv4Addr::new(10, 0, 0, 253);
        let dst = Ipv4Addr::new(129, 150, 44, 117);
        for len in [0usize, 1, 2, 3, 100, 1299, 1300, 1401] {
            let payload: Vec<u8> = (0..len).map(|i| (i * 7 + 13) as u8).collect();
            let mut pkt = Vec::new();
            build_packet_into(
                &mut pkt,
                src,
                dst,
                44311,
                8443,
                &TcpSeg {
                    seq: 1234,
                    ack: 5678,
                    flags: TCP_PSH | TCP_ACK,
                    ip_id: 0xF107,
                    window: 501,
                    tsval: 0x1122_3344,
                    tsecr: 0x5566_7788,
                    options: &[],
                    payload: &payload,
                },
            );
            // IP 头：整头求和后折叠应为 0
            assert_eq!(fold(sum16(&pkt[..20])), 0, "IP 校验和错误 len={len}");
            // TCP：伪头 + TCP 段求和后折叠应为 0
            let tcp_len = pkt.len() - 20;
            let mut pseudo = [0u8; 12];
            pseudo[0..4].copy_from_slice(&src.octets());
            pseudo[4..8].copy_from_slice(&dst.octets());
            pseudo[9] = 6;
            pseudo[10..12].copy_from_slice(&(tcp_len as u16).to_be_bytes());
            let s = sum16(&pseudo) + sum16(&pkt[20..]);
            assert_eq!(fold(s), 0, "TCP 校验和错误 len={len}");
        }
    }

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
            &TcpSeg {
                seq: 12345,
                ack: 67890,
                flags: TCP_PSH | TCP_ACK,
                ip_id: 0xF107,
                window: 1234,
                tsval: 0x0102_0304,
                tsecr: 0x0506_0708,
                options: &[],
                payload: b"hello",
            },
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
        assert_eq!(parsed.window, 1234);
        assert_eq!(parsed.payload, b"hello");
        // 数据包必须带时间戳选项，且能被解析回来：
        // 这是整个伪装改造的核心断言——缺时间戳是最好认的伪造特征
        assert_eq!(parsed.tsval, Some(0x0102_0304));
        assert_eq!(parsed.tsecr, Some(0x0506_0708));
    }

    /// SYN 选项必须与真实 Linux 逐字节一致（MSS/SACK/TS/NOP/wscale 9），
    /// 且能被解析器正确取出时间戳与窗口缩放。
    #[test]
    fn syn_options_layout() {
        let o = syn_options(0xAABB_CCDD, 0);
        assert_eq!(o.len(), 20);
        assert_eq!(&o[0..4], &[0x02, 0x04, 0x05, 0xb4], "MSS 1460");
        assert_eq!(&o[4..6], &[0x04, 0x02], "SACK permitted");
        assert_eq!(&o[6..8], &[0x08, 0x0a], "TS kind/len");
        assert_eq!(&o[8..12], &0xAABB_CCDDu32.to_be_bytes(), "TSval");
        assert_eq!(&o[12..16], &[0u8; 4], "SYN 的 TSecr 必须为 0");
        assert_eq!(o[16], 0x01, "NOP");
        assert_eq!(&o[17..20], &[0x03, 0x03, WSCALE], "wscale 9");
        assert_eq!(WSCALE, 9, "wscale 必须是真实 Linux 的取值");
    }

    /// IP ID 必须在标记区间内 +1 递增（高字节保持，低字节回绕）。
    #[test]
    fn ipid_progression() {
        let mut id = IPID_MARK;
        for _ in 0..1000 {
            id = next_ipid(IPID_MARK, id);
            assert_eq!(id & 0xFF00, IPID_MARK, "高字节必须保持标记");
        }
        // 起点随机，但仍在标记区间内
        for _ in 0..50 {
            assert_eq!(random_ipid(IPID_MARK) & 0xFF00, IPID_MARK);
        }
    }
}
