//! 裸 socket 收发封装。
//!
//! 接收用 AF_PACKET：它在 netfilter 之前拿到报文，因此即使 iptables 把
//! 这些包 DROP 掉（不让内核协议栈处理），我们依然能收到。
//! 发送用 IPPROTO_RAW + IP_HDRINCL：内核只做路由和二层封装，
//! IP/TCP 头完全由我们自己构造。

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::RawFd;

/// 裸 socket 句柄，持有收发两个 fd。
pub struct RawSocket {
    send_fd: RawFd,
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

        unsafe {
            // ---- 发送 fd：AF_INET / SOCK_RAW / IPPROTO_RAW ----
            let send_fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW);
            if send_fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // 开启 IP_HDRINCL，告诉内核「IP 头我自己写」
            let on: libc::c_int = 1;
            if libc::setsockopt(
                send_fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                let e = io::Error::last_os_error();
                libc::close(send_fd);
                return Err(e);
            }
            // 发送缓冲调大，避免突发时 sendto 阻塞
            let sndbuf: libc::c_int = 4 * 1024 * 1024;
            libc::setsockopt(
                send_fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &sndbuf as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );

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
                recv_fd,
                local_ip,
            })
        }
    }

    /// 发送一个完整的 IPv4 报文（不含以太网头）。
    pub fn send(&self, pkt: &[u8], dst_ip: Ipv4Addr) -> io::Result<usize> {
        unsafe {
            let mut sa: libc::sockaddr_in = std::mem::zeroed();
            sa.sin_family = libc::AF_INET as u16;
            sa.sin_addr.s_addr = u32::from_ne_bytes(dst_ip.octets());
            let n = libc::sendto(
                self.send_fd,
                pkt.as_ptr() as *const libc::c_void,
                pkt.len(),
                0,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(n as usize)
        }
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
