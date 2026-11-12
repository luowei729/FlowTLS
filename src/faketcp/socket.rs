//! 裸 socket 收发封装。
//!
//! 接收用 AF_PACKET：它在 netfilter 之前拿到报文，因此即使 iptables 把
//! 这些包 DROP 掉（不让内核协议栈处理），我们依然能收到。
//!
//! 发送优先用 AF_PACKET / SOCK_DGRAM：内核只按包里的 IP 头做 ARP，
//! 直接把帧交给驱动，跳过 IP 层路由、netfilter OUTPUT/POST_ROUTING、
//! MTU 分片检查和 qdisc 排队。
//! 原先用 IPPROTO_RAW + IP_HDRINCL，实测在 1 核 ARM 上约 35µs/包
//! （15260 pps 时内核态吃掉 54% CPU），是高速率下的第一瓶颈。
//! AF_PACKET 不可用时自动回退 IPPROTO_RAW。

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::RawFd;

/// Linux SOL_PACKET 选项：把发送直接交给驱动的 `ndo_start_xmit`，绕过 qdisc。
/// libc crate 未导出该常量，按内核头文件取值 20。
/// 队列满时直接丢包而不是排队——QUIC 会重传，排队反而把延迟和内存拖坏。
const PACKET_QDISC_BYPASS: libc::c_int = 20;

/// 裸 socket 句柄，持有收发 fd。
pub struct RawSocket {
    /// 发送 fd：AF_PACKET/SOCK_DGRAM 为主，回退时是 IPPROTO_RAW
    send_fd: RawFd,
    /// 发送 fd 是否为 AF_PACKET 模式（决定 sendto 用 sockaddr_ll 还是 sockaddr_in）
    send_is_packet: bool,
    /// 出口网卡索引，AF_PACKET 发送必须指定
    ifindex: libc::c_int,
    /// 下一跳 MAC。
    /// AF_PACKET/SOCK_DGRAM 只让内核帮我们加以太网头，
    /// **但内核不会替我们做 ARP**——不给目的 MAC 就会发成全零地址，
    /// 包在网关直接被丢（实测表现为客户端一直停在「等待 SYN-ACK」）。
    /// 所以启动时从内核邻居表里取一次网关 MAC，之后固定复用：
    /// 我们所有包都发给同一个下一跳（默认网关），中途不会变。
    next_hop_mac: [u8; 6],
    recv_fd: RawFd,
    /// 本机出口 IP，构造 IP 头时作为源地址
    pub local_ip: Ipv4Addr,
}

impl RawSocket {
    /// 创建收发 socket。
    /// `dst_ip` 用于探测本机出口 IP 和出口网卡，服务端可传任意外部地址。
    pub fn new(dst_ip: Ipv4Addr) -> io::Result<Self> {
        Self::new_with_local(dst_ip, None)
    }

    /// 显式指定本地源 IP。
    /// 服务端在 NAT/内网后面时（如云厂商内网地址 10.x），
    /// 路由探测只能拿到内网地址，但发给客户端的包源 IP 必须是公网 IP，
    /// 否则客户端会因源地址不匹配而丢弃。
    pub fn new_with_local(dst_ip: Ipv4Addr, local: Option<Ipv4Addr>) -> io::Result<Self> {
        // 优先用配置指定的公网 IP，未指定时回退到路由探测
        let local_ip = match local {
            Some(ip) => ip,
            None => local_ip_for(dst_ip)?,
        };
        // AF_PACKET 发送必须知道出口网卡；取默认路由那一块
        let route = default_route().ok();
        let ifindex = route.as_ref().map(|r| r.ifindex).unwrap_or(0);
        // AF_PACKET 还需要下一跳 MAC，从内核邻居表取（拿不到就回退 IPPROTO_RAW）
        let next_hop_mac = route
            .as_ref()
            .and_then(|r| resolve_neighbor_mac(r.gateway, dst_ip, &r.ifname))
            .unwrap_or([0u8; 6]);

        unsafe {
            // ---- 发送 fd：优先 AF_PACKET / SOCK_DGRAM / ETH_P_IP ----
            // SOCK_DGRAM 模式下内核自己补以太网头并按 IP 头做 ARP，
            // 我们只管交出完整 IPv4 报文，比自己拼 14 字节以太网头更省事也更稳。
            let mut send_fd = -1;
            let mut send_is_packet = false;
            // 没有下一跳 MAC 时不能用 SOCK_DGRAM：内核补的以太网头目的地址会是全 0
            if ifindex > 0 && next_hop_mac != [0u8; 6] {
                let fd = libc::socket(
                    libc::AF_PACKET,
                    libc::SOCK_DGRAM,
                    (libc::ETH_P_IP as u16).to_be() as libc::c_int,
                );
                if fd >= 0 {
                    let mut sll: libc::sockaddr_ll = std::mem::zeroed();
                    sll.sll_family = libc::AF_PACKET as u16;
                    sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
                    sll.sll_ifindex = ifindex;
                    let rc = libc::bind(
                        fd,
                        &sll as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                    );
                    if rc == 0 {
                        // 绕过 qdisc：少一次入队/出队和软中断唤醒
                        let on: libc::c_int = 1;
                        libc::setsockopt(
                            fd,
                            libc::SOL_PACKET,
                            PACKET_QDISC_BYPASS,
                            &on as *const _ as *const libc::c_void,
                            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                        );
                        // 发送缓冲调大，减少突发时的 ENOBUFS
                        let sndbuf: libc::c_int = 8 * 1024 * 1024;
                        libc::setsockopt(
                            fd,
                            libc::SOL_SOCKET,
                            libc::SO_SNDBUF,
                            &sndbuf as *const _ as *const libc::c_void,
                            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                        );
                        send_fd = fd;
                        send_is_packet = true;
                    } else {
                        libc::close(fd);
                    }
                }
            }

            // ---- 回退：AF_INET / SOCK_RAW / IPPROTO_RAW ----
            if send_fd < 0 {
                let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW);
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                // 开启 IP_HDRINCL，告诉内核「IP 头我自己写」
                let on: libc::c_int = 1;
                if libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_HDRINCL,
                    &on as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                ) != 0
                {
                    let e = io::Error::last_os_error();
                    libc::close(fd);
                    return Err(e);
                }
                let sndbuf: libc::c_int = 4 * 1024 * 1024;
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &sndbuf as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
                send_fd = fd;
            }

            // ---- 接收 fd：AF_PACKET / SOCK_RAW / ETH_P_IP ----
            let recv_fd = libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_IP as u16).to_be() as libc::c_int,
            );
            if recv_fd < 0 {
                let e = io::Error::last_os_error();
                libc::close(send_fd);
                return Err(e);
            }
            // 不绑定特定网卡：服务端可能收多个网卡/回环，绑定 ifindex 会漏包。
            // 端口过滤交给上层逻辑，性能损失可忽略。
            // 接收缓冲调大，减少高速流量下的丢包
            let rcvbuf: libc::c_int = 8 * 1024 * 1024;
            libc::setsockopt(
                recv_fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcvbuf as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );

            Ok(Self {
                send_fd,
                send_is_packet,
                ifindex,
                next_hop_mac,
                recv_fd,
                local_ip,
            })
        }
    }

    /// 发送时使用的目的地址（两种 fd 各有一套构造规则）。
    #[inline]
    fn dest_addr(&self, dst_ip: Ipv4Addr) -> (libc::sockaddr_ll, libc::sockaddr_in) {
        unsafe {
            let mut sll: libc::sockaddr_ll = std::mem::zeroed();
            let mut sin: libc::sockaddr_in = std::mem::zeroed();
            if self.send_is_packet {
                sll.sll_family = libc::AF_PACKET as u16;
                sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
                sll.sll_ifindex = self.ifindex;
                // 目的 MAC 必须显式给出，否则内核补的是全零以太网头
                sll.sll_halen = 6;
                sll.sll_addr[..6].copy_from_slice(&self.next_hop_mac);
            } else {
                sin.sin_family = libc::AF_INET as u16;
                // octets() 本身是大端排列，from_ne_bytes 保持字节序不变
                sin.sin_addr.s_addr = u32::from_ne_bytes(dst_ip.octets());
            }
            (sll, sin)
        }
    }

    /// 发送一个完整的 IPv4 报文（不含以太网头）。
    pub fn send(&self, pkt: &[u8], dst_ip: Ipv4Addr) -> io::Result<usize> {
        let (mut sll, sin) = self.dest_addr(dst_ip);
        unsafe {
            let (addr, addr_len) = if self.send_is_packet {
                (
                    &mut sll as *mut _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            } else {
                (
                    &sin as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            let n = libc::sendto(
                self.send_fd,
                pkt.as_ptr() as *const libc::c_void,
                pkt.len(),
                0,
                addr,
                addr_len,
            );
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(n as usize)
        }
    }

    /// 批量发送多个完整 IPv4 报文（同目的 IP），一次系统调用。
    ///
    /// 这是本层最关键的优化：实测单包 sendto 在 1 核 ARM 上约 40~50µs/包
    /// （进程 76% CPU 落在内核态），11197 pps 就把 CPU 打满。
    /// sendmmsg 一次最多发 32 个包，系统调用次数按 32 倍下降，
    /// 直接对应内核态时间的 32 倍缩减。
    ///
    /// 返回成功递交的报文数；内核发送队列满（ENOBUFS）时可能小于 `pkts.len()`，
    /// 调用方应把余下的留到下一轮。
    pub fn send_batch(&self, pkts: &[Vec<u8>], dst_ip: Ipv4Addr) -> io::Result<usize> {
        // 一次系统调用最多带多少个报文。32 是折中：
        // 太小收益不明显，太大在突发时会一次性占满 qdisc 队列反而增加丢包。
        const MAX_BATCH: usize = 32;
        if pkts.is_empty() {
            return Ok(0);
        }

        // msghdr / iovec 全部放栈上，避免批量发送本身引入分配
        let mut iovs: [libc::iovec; MAX_BATCH] = unsafe { std::mem::zeroed() };
        let mut msgs: [libc::mmsghdr; MAX_BATCH] = unsafe { std::mem::zeroed() };
        let (mut sll, sin) = self.dest_addr(dst_ip);
        let (name, name_len) = if self.send_is_packet {
            (
                &mut sll as *mut _ as *mut libc::c_void,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        } else {
            (
                &sin as *const _ as *mut libc::c_void,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };

        let mut total = 0usize;
        for chunk in pkts.chunks(MAX_BATCH) {
            let n = chunk.len();
            for (i, pkt) in chunk.iter().enumerate() {
                iovs[i].iov_base = pkt.as_ptr() as *mut libc::c_void;
                iovs[i].iov_len = pkt.len();
                msgs[i].msg_hdr.msg_name = name;
                msgs[i].msg_hdr.msg_namelen = name_len;
                msgs[i].msg_hdr.msg_iov = &mut iovs[i] as *mut libc::iovec;
                msgs[i].msg_hdr.msg_iovlen = 1;
                msgs[i].msg_len = 0;
            }
            let sent = unsafe {
                libc::sendmmsg(self.send_fd, msgs.as_mut_ptr(), n as _, 0)
            };
            if sent < 0 {
                let e = io::Error::last_os_error();
                // 已经发出部分就直接返回成功计数，避免上层把已发的包再发一遍
                if total > 0 {
                    return Ok(total);
                }
                return Err(e);
            }
            total += sent as usize;
            // 内核没全收下：qdisc 队列满，剩下的留给下一轮（QUIC 会重传，不会丢数据）
            if (sent as usize) < n {
                break;
            }
        }
        Ok(total)
    }

    /// 阻塞接收一个以太网帧，返回实际长度。
    /// 调用方负责解析并过滤非目标流量。
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let n = libc::recvfrom(
                self.recv_fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(n as usize)
        }
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        // 句柄必须显式关闭，否则重启进程会残留 fd
        unsafe {
            libc::close(self.send_fd);
            libc::close(self.recv_fd);
        }
    }
}

/// 批量发送缓冲池。
///
/// 一次发送要经过「QUIC 明文 → TLS 记录 → IP 报文」三步，
/// 原实现每步各分配一个 Vec，加上 `pseudo` 临时 Vec 和收包侧的 `to_vec()`，
/// 每包 3~5 次 malloc/free。在 11000 pps 下就是 3~5 万次/秒，
/// 这些内存抖动会抬高用户态时间并带来 cache 压力。
/// 这里把三类缓冲全部预分配并复用：每轮只 `reset()` 一个计数器，零分配。
pub struct PacketBatch {
    /// QUIC 明文缓冲（`poll_transmit` 的写入目标）
    pub plain: Vec<u8>,
    /// 外层 TLS 记录缓冲（`Obfs::seal_into` 的输出）
    pub record: Vec<u8>,
    /// 完整的 IP 报文缓冲，按下标复用；一次 `sendmmsg` 发送前 `count` 个
    pub bufs: Vec<Vec<u8>>,
}

impl PacketBatch {
    /// 单轮最多攒多少个报文再一次性发出。
    /// 与 `send_batch` 的上限保持一致，避免多余的 chunks 拆分。
    pub const MAX: usize = 32;

    pub fn new() -> Self {
        Self {
            plain: Vec::with_capacity(2048),
            record: Vec::with_capacity(2048),
            // 预分配 32 个报文缓冲，稳态下不再需要扩容
            bufs: (0..Self::MAX).map(|_| Vec::with_capacity(2048)).collect(),
        }
    }

    /// 确保至少有 `n` 个可复用缓冲。
    #[inline]
    pub fn ensure(&mut self, n: usize) {
        while self.bufs.len() < n {
            self.bufs.push(Vec::with_capacity(2048));
        }
    }
}

impl Default for PacketBatch {
    fn default() -> Self {
        Self::new()
    }
}

/// 默认路由信息。
struct DefaultRoute {
    ifindex: libc::c_int,
    ifname: String,
    /// 网关地址（大端序 IPv4）
    gateway: Ipv4Addr,
}

/// 取默认路由所在的网卡索引与网关。
///
/// AF_PACKET 发送必须指定 ifindex，而服务端常处于 NAT 后面
/// （本机地址 10.x、出口是公网 IP），不能靠「接口地址等于 local_ip」去找。
/// 直接读内核路由表取默认路由那一块最可靠。
fn default_route() -> io::Result<DefaultRoute> {
    let content = std::fs::read_to_string("/proc/net/route")?;
    // 格式：Iface Destination Gateway Flags RefCnt Use Metric Mask ...
    // Destination 为 00000000 表示默认路由；Gateway 是十六进制小端序
    let mut best: Option<(u32, DefaultRoute)> = None;
    for line in content.lines().skip(1) {
        let mut it = line.split_whitespace();
        let (Some(ifname), Some(dest), Some(gateway)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if dest != "00000000" {
            continue;
        }
        // 第 7 个字段是 Metric，越小优先级越高
        let metric = it.nth(3).and_then(|m| m.parse::<u32>().ok()).unwrap_or(0);
        // 网关字段是 8 位十六进制、主机字节序（小端），例如 0100000A → 10.0.0.1
        let Ok(raw) = u32::from_str_radix(gateway, 16) else {
            continue;
        };
        let g = raw.to_le_bytes();
        let gateway_ip = Ipv4Addr::new(g[0], g[1], g[2], g[3]);
        let cstr = std::ffi::CString::new(ifname)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let idx = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
        if idx == 0 {
            continue;
        }
        let route = DefaultRoute {
            ifindex: idx as libc::c_int,
            ifname: ifname.to_string(),
            gateway: gateway_ip,
        };
        if best.as_ref().map(|(m, _)| metric < *m).unwrap_or(true) {
            best = Some((metric, route));
        }
    }
    best.map(|(_, r)| r)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "无默认路由"))
}

/// 解析下一跳的 MAC 地址（供 AF_PACKET/SOCK_DGRAM 填写目的以太网地址）。
///
/// 下一跳的判定：目的 IP 与默认网关同网段直接用目的本身，否则走网关。
/// 实际场景（国内家庭宽带 ↔ 云主机）几乎总是走网关。
/// 邻居表里没有条目时先发一个 UDP 包触发内核 ARP，再轮询一会儿。
fn resolve_neighbor_mac(gateway: Ipv4Addr, dst: Ipv4Addr, ifname: &str) -> Option<[u8; 6]> {
    // 目的与网关的 /24 是否相同（用简单启发式：前 3 字节）
    let g = gateway.octets();
    let d = dst.octets();
    let next_hop = if g[..3] == d[..3] { dst } else { gateway };

    if let Some(mac) = arp_lookup(next_hop, ifname) {
        return Some(mac);
    }
    // 触发内核 ARP：UDP connect + 发一个字节，内核会解析网关邻居
    trigger_arp(next_hop);
    // 最多等 500ms；ARP 通常 10ms 内回来
    for _ in 0..25 {
        std::thread::sleep(std::time::Duration::from_millis(20));
        if let Some(mac) = arp_lookup(next_hop, ifname) {
            return Some(mac);
        }
    }
    None
}

/// 从 /proc/net/arp 查指定 IP 的 MAC。
fn arp_lookup(ip: Ipv4Addr, ifname: &str) -> Option<[u8; 6]> {
    let content = std::fs::read_to_string("/proc/net/arp").ok()?;
    // 格式：IP address  HW type  Flags  HW address  Mask  Device
    // Flags 0x2 表示 ATF_COM（已完成），0x0 是未完成
    for line in content.lines().skip(1) {
        let mut it = line.split_whitespace();
        let (Some(addr), Some(_hwtype), Some(flags)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let (Some(mac_str), Some(_mask), Some(dev)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if addr.parse::<Ipv4Addr>().ok() != Some(ip) || dev != ifname {
            continue;
        }
        if u32::from_str_radix(flags, 16).ok()? & 0x2 == 0 {
            continue;
        }
        let parts: Vec<u8> = mac_str
            .split(':')
            .filter_map(|p| u8::from_str_radix(p, 16).ok())
            .collect();
        if parts.len() == 6 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&parts);
            return Some(mac);
        }
    }
    None
}

/// 用 UDP 包触发内核做一次 ARP 解析（不关心是否送达）。
fn trigger_arp(target: Ipv4Addr) {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return;
        }
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        sa.sin_family = libc::AF_INET as u16;
        sa.sin_port = 9u16.to_be(); // discard 端口，发了也没人理
        sa.sin_addr.s_addr = u32::from_ne_bytes(target.octets());
        libc::sendto(
            fd,
            b"x".as_ptr() as *const libc::c_void,
            1,
            0,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        libc::close(fd);
    }
}

/// 通过一个临时 UDP socket 让内核选路，拿到出口 IP。
pub fn local_ip_for(dst_ip: Ipv4Addr) -> io::Result<Ipv4Addr> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // UDP connect 不会真的发包，只触发路由查询
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        sa.sin_family = libc::AF_INET as u16;
        sa.sin_port = 443u16.to_be();
        sa.sin_addr.s_addr = u32::from_ne_bytes(dst_ip.octets());
        if libc::connect(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) != 0
        {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        let mut local: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let r = libc::getsockname(
            fd,
            &mut local as *mut _ as *mut libc::sockaddr,
            &mut len,
        );
        libc::close(fd);
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Ipv4Addr::from(u32::from_be(local.sin_addr.s_addr)))
    }
}

/// 根据本机 IP 找到对应网卡的 ifindex，供调试/后续扩展使用。
#[allow(dead_code)]
fn ifindex_for_ip(ip: Ipv4Addr) -> Option<i32> {
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return None;
        }
        let mut cur = ifap;
        let mut found = None;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() {
                let sa = &*ifa.ifa_addr;
                // 只看 IPv4 地址
                if sa.sa_family == libc::AF_INET as u16 {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    if Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)) == ip {
                        found = Some(libc::if_nametoindex(ifa.ifa_name) as i32);
                        break;
                    }
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
        found
    }
}
