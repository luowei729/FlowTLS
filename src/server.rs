//! 服务端主流程：FakeTCP 收包 → 外层 AEAD 验签 → QUIC → 出站连接。
//!
//! 同端口还有内核 TCP 网站（site 模块），普通探测走内核，代理流量走 raw。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::BytesMut;
use quinn_proto::{
    Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig, Event, ReadError,
    ReadableError, ServerConfig, StreamEvent, StreamId, WriteError,
};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::config::{parse_listen, ServerFile};
use crate::faketcp::codec::{
    build_server_hello, parse_first_header, parse_records, Obfs, AUTH_ID_LEN,
    PROTOCOL_VERSION, REC_APPDATA,
};
use crate::faketcp::packet::{
    advertised_window, build_packet, build_packet_into, next_ipid, parse_frame, random_ipid,
    seq_len, syn_options, TcpClock, TcpSeg, TCP_ACK, TCP_FIN, TCP_PSH, TCP_SYN,
};
use crate::faketcp::socket::{PacketBatch, RawSocket};
use crate::proxy::{decode_target, udp};

/// 出站任务发回事件循环的动作
enum ServerAction {
    Data(ConnectionHandle, StreamId, Vec<u8>),
    Fin(ConnectionHandle, StreamId),
    /// UDP 回程：出站 UDP 任务收到目标回的包，已按 `[session][payload]` 编好，
    /// 主循环拿到后直接丢给 `conn.datagrams().send()`。
    ///
    /// 走主循环而不是在任务里直接发，是因为 `datagrams()` 需要 `&mut Connection`，
    /// 而 Connection 由主循环独占（quinn-proto 是单线程状态机）。
    Datagram(ConnectionHandle, Vec<u8>),
}

/// 服务端一个 UDP 会话。
///
/// 与 TCP 流的本质区别：**完全没有背压，也没有重传**。
/// 上行通道满就丢、下行 datagram 发不出去也丢——这正是 UDP 的语义，
/// 也是 hysteria2 对 UDP 的处理方式。所以这里没有任何 pending / 水位 /
/// 唤醒机制，只有一个容量很小的通道当安全网。
struct UdpSession {
    /// 上行：主循环 → 出站任务。容量小是有意的：
    /// 它就是「允许积压多少个包」的上限，满了直接丢。
    to_target: mpsc::Sender<Vec<u8>>,
    /// 目标地址 `host:port`（仅用于日志）。
    /// 实际解析出来的 IP 在出站任务里，主循环不需要知道。
    target: String,
    /// 最后一次收到上行包的时间，用于空闲回收。
    ///
    /// UDP 是无连接的，客户端可能直接消失、永远不发结束信号，
    /// 只能靠「多久没收到这个 session 的包」来决定何时关 socket。
    last_active: Instant,
}

/// 服务端单条流的状态
struct ServerStream {
    /// 发往出站 TCP 任务的通道。
    /// 用有界通道：speedtest 多线并发时目标写入跟不上，
    /// 无限缓冲会把整台机器的内存吃光（实测 RSS 到 70MB+）。
    to_tcp: Option<mpsc::Sender<Vec<u8>>>,
    /// 因流控阻塞暂存的待写数据
    pending: Vec<u8>,
    /// pending 的字节数，与出站任务共享。
    /// 出站任务靠它感知下游堵塞，从而停止读目标 socket——这就是背压。
    /// quic-go 里由阻塞式 Write 完成，quinn-proto 的同步 write 需要自己做。
    pending_bytes: Arc<std::sync::atomic::AtomicUsize>,
    /// pending 被消化时通知出站任务。
    /// 之前出站任务用「每 5ms 醒来读 16KB」轮询水位，拥塞时吞吐被锁在
    /// 16KB ÷ 5ms ≈ 3MB/s，BBR 看到流量受限就永远爬不出低速区（实测单流 20Mbps）。
    /// 改成事件通知：pending 一降下去立刻唤醒，等待只有微秒级。
    drain_notify: Arc<tokio::sync::Notify>,
    /// QUIC 发送缓冲是否已满（write 返回 Blocked / 只写了部分）。
    /// 这是真正的背压信号：pending_bytes 只统计「我们自己暂存」的字节，
    /// 而 quinn 内部还有一个 send_window（默认十几 MB、按连接算）的发送缓冲，
    /// 那部分背压完全看不见。所以出站任务必须同时看这个标志，
    /// 否则会以本地回环速度（几百 MB/s）把数据吸进来，直到 quinn 缓冲写满、
    /// 我们自己的 pending 涨过安全阈值，整条流被当作僵尸流 reset——
    /// 实测表现就是单流下到 6~8MB 后 curl 报
    /// "transfer closed with ... bytes remaining to read"。
    write_blocked: Arc<std::sync::atomic::AtomicBool>,
    /// 该流已被放弃（对端 STOP_SENDING / 我们主动 reset）。
    /// 出站任务的读取协程必须能看到它并立即退出：
    /// 只把 `to_tcp` 置 None 不够，那个协程等的是原子计数、不看 channel，
    /// 会一直等到 30 秒兜底超时才放弃
    /// （日志里「背压等待超过 30 秒，放弃该流」就是漏了这个信号）。
    abandon: Arc<std::sync::atomic::AtomicBool>,
    /// 目标地址帧累积缓冲
    target_buf: Vec<u8>,
    /// 目标地址是否已经解析完毕
    target_ready: bool,
    /// 出站方向是否结束
    local_finished: bool,
    /// 远端方向是否结束
    remote_finished: bool,
    /// 已因读取错误被 stop。置位后忽略该流的后续 Readable 事件，
    /// 否则 quinn 会持续投递 Readable，每次都重新 read/失败/stop 空转。
    stopped: bool,
    /// 上游（目标 socket）已 EOF，等 pending 写完才能发 FIN。
    /// 直接 finish() 会在 pending 之前就把 FIN 发出去，
    /// 客户端会提前看到流结束——实测就是 200MB 下载最后少掉约 1MB
    /// （刚好是一个背压高水位），curl 报 exit 18。
    fin_pending: bool,
    /// 最后一次读写时间，用于 5 分钟空闲超时清理僵尸流。
    last_active: Instant,
}

impl Default for ServerStream {
    fn default() -> Self {
        Self {
            to_tcp: None,
            pending: Vec::new(),
            pending_bytes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            drain_notify: Arc::new(tokio::sync::Notify::new()),
            write_blocked: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            abandon: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            target_buf: Vec::new(),
            target_ready: false,
            local_finished: false,
            remote_finished: false,
            stopped: false,
            fin_pending: false,
            last_active: Instant::now(),
        }
    }
}

/// 收到 SYN 之后的临时状态，等 QUIC 首包到达时才用得上。
///
/// 三样信息必须一起存：
/// - `peer_isn`：回 SYN-ACK 的 ack 号；
/// - `our_isn`：SYN-ACK 的 seq，ServerHello 必须紧接着它；
/// - `ts`：SYN-ACK 用的 TSval。后续 ServerHello 和数据包的 TSval
///   都必须 **大于等于** 它，否则时间戳类 DPI 一眼就能看出回退
///   （真实 TCP 的 TSval 基于全局时钟，永不回退）。
///
/// 之前这三样散在两个 map 里，且握手包的 TSval 是各发一次随机数，
/// 连接建的 TcpClock 又取另一个随机基准——于是「SYN-ACK 的 TSval 可能是
/// 0x8f3a...，第一个数据包的 TSval 是 0x1c2b...」，回退概率约 50%。
struct SynState {
    peer_isn: u32,
    our_isn: u32,
    ts: u32,
    /// 收到 SYN 的时刻，用于超时清理
    at: Instant,
}

/// 多用户表：auth id → (显示名, 该用户的密钥)。
///
/// 键是从密码派生出的不透明标识，不是用户名也不是密码本身：
/// 抓包只能看到一个 16 字节随机值，推不出密码。
type UserMap = HashMap<[u8; AUTH_ID_LEN], (String, Arc<Obfs>)>;

/// 服务端单条 QUIC 连接
struct ServerConn {
    conn: Connection,
    ch: ConnectionHandle,
    /// 客户端的真实地址（NAT 后的）
    client: SocketAddr,
    /// 该连接所属用户的密钥。
    ///
    /// 多用户下每条连接的用户可能不同，所以**必须按连接持有**，
    /// 不能像单用户时代那样用进程级全局 Obfs。
    /// 放在 Option 里是因为从「收到 SYN」到「首包解密成功」之间还不知谁是用户。
    obfs: Option<Arc<Obfs>>,
    /// 该连接的用户显示名（仅日志/统计用）
    user: String,
    /// 本机接收该连接时使用的目标 IP，回包时作为源 IP
    local_ip: std::net::Ipv4Addr,
    /// 发往客户端时的序列号
    seq: u32,
    /// 最近一次收到客户端的序列号
    peer_seq: u32,
    /// IP ID 当前值：高字节是配置派生的分流标记，低字节递增
    ip_id: u16,
    /// 分流标记高字节（来自 `faketcp.ip_id_magic`），每个部署不同
    mark: u16,
    /// TCP 时间戳时钟：数据包必须带 TS，且 TSecr 要回显客户端最近一次的 TSval
    clock: TcpClock,
    /// 待确认的数据段数（延迟确认用）
    ack_pending: u32,
    /// 上次发送纯 ACK 的时刻（40ms 兜底）
    last_ack: Instant,
    /// 纯 ACK / FIN 的复用发送缓冲（热路径数据包走 PacketBatch，不用这个）
    ctrl_buf: Vec<u8>,
    streams: HashMap<StreamId, ServerStream>,
    /// UDP 会话表：session id → 出站 socket 任务。
    /// 键由客户端分配，作用域是这条连接；重连后客户端会重建，服务端表清空即可。
    udp: HashMap<u32, UdpSession>,
}

/// 服务端入口。
pub async fn run(cfg: ServerFile) -> Result<()> {
    let listen: SocketAddr = parse_listen(&cfg.listen)?;
    let port = listen.port();

    // ---- 1. 同端口真网站：走内核 TCP，处理所有正常 SYN ----
    {
        let listen_str = cfg.listen.clone();
        let cert = cfg.tls.cert.clone();
        let key = cfg.tls.key.clone();
        let dir = cfg.site.dir.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::site::run(&listen_str, cert, key, dir).await {
                tracing::error!(error = %e, "伪装网站启动失败");
            }
        });
    }

    // ---- 2. 防火墙规则：让内核不要插手我们的伪造包 ----
    if cfg.net.mode == "auto" {
        if let Err(e) = crate::rules::ensure_server(port, cfg.faketcp.ip_id_magic) {
            tracing::warn!(error = %e, "iptables 规则写入失败，NAT 场景下连接可能被内核 RST 干扰");
        } else {
            tracing::info!(port, "iptables 规则已就绪");
        }
    } else {
        tracing::info!("net.mode=none，跳过 iptables 规则");
    }

    // ---- 3. raw socket 与收包线程 ----
    // 用一个外部地址探测出口 IP；服务端出口 IP 就是本机公网/内网地址
    // 云主机常处于 NAT 后面（内网地址 10.x），路由探测只能拿到内网 IP，
    // 而发给客户端的包源 IP 必须是公网 IP，所以优先用配置里的 faketcp.local_ip。
    let local_override = match &cfg.faketcp.local_ip {
        Some(s) => Some(
            s.parse::<std::net::Ipv4Addr>()
                .with_context(|| format!("faketcp.local_ip 不是合法 IPv4: {s}"))?,
        ),
        None => None,
    };
    let raw = Arc::new(RawSocket::new_with_local(
        "8.8.8.8".parse().unwrap(),
        local_override,
    )?);
    let local_ip = raw.local_ip;
    tracing::info!(%local_ip, port, "FakeTCP 服务端已就绪");

    // 有界 channel：突发流量（测速/直播）时最多积压 8192 个包，
    // 超过后收包线程阻塞，由内核 socket 缓冲区兜底丢包（QUIC 会重传）。
    // 之前用 unbounded，高包速率下内存会无限上涨，且主循环每轮只处理一个包，
    // 队列越积越长，ACK 延迟拖到几秒，表现为「上传为 0、整条连接卡死」。
    let (pkt_tx, mut pkt_rx) = mpsc::channel::<(
        u32,
        SocketAddr,
        std::net::Ipv4Addr,
        u16,
        u8,
        Option<u8>,
        Option<u32>,
        Vec<u8>,
    )>(8192);
    let raw_recv = raw.clone();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        loop {
            match raw_recv.recv(&mut buf) {
                Ok(n) => {
                    if let Some(p) = parse_frame(&buf[..n]) {
                        // 只处理发往监听端口的包；syn 由 raw 层回，避免给内核看到
                        if p.dst_port != port {
                            continue;
                        }
                        let client = SocketAddr::new(p.src.into(), p.src_port);
                        // 连同目标 IP、TCP flags 一起送出：多网卡/回环环境下回包必须用对的源 IP，
                        // flags 用于区分真正的 SYN 和内核回的空 RST/ACK
                        if pkt_tx
                            .blocking_send((
                                p.seq,
                                client,
                                p.dst,
                                p.ip_id,
                                p.flags,
                                p.wscale,
                                p.tsval,
                                p.payload.to_vec(),
                            ))
                            .is_err()
                        {
                            break;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "raw recv 失败");
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    });

    // ---- 4. QUIC 状态机 ----
    // 拥塞窗口上限：共享原子值，主循环每 2 秒根据实测丢包率自适应调整。
    let max_cwnd = Arc::new(std::sync::atomic::AtomicU64::new(cfg.net.max_cwnd));
    let mut last_sent = 0u64;
    let mut last_lost = 0u64;
    let server_quic: Arc<ServerConfig> =
        Arc::new(crate::quic::config::server_config(max_cwnd.clone()));
    // 背压高水位：决定「每条流最多能在内存里堆多少待发数据」。
    // 之前取窗口上限的 2 倍（千兆 8MB → 每流 16MB），实测这是最严重的问题：
    // 12 条并发流能堆到 214MB，目标 TCP 被读得飞快，QUIC 却发不出去，
    // 于是 cwnd 允许时就会把几百 MB 一次性灌进链路 → 瓶颈队列溢出 →
    // 大量丢包 → BBR 窗口从 8MB 崩到 1.2MB，吞吐被锁在 100Mbps 上下，
    // 而且 RTT 抖动剧烈。这就是典型的自造 bufferbloat。
    // 正确做法是把它绑到「链路 BDP」而不是「窗口上限」：
    // 按 100ms RTT 估算，每流 1MB 已经足够填满 80Mbps 的在途数据，
    // 再多只是排队。多条流合计仍在可控范围（12 流约 12MB）。
    let pending_high_water = ((cfg.net.max_cwnd as usize) / 4).clamp(512 * 1024, 1024 * 1024);
    let mut endpoint = Endpoint::new(
        Arc::new(EndpointConfig::default()),
        Some(server_quic.clone()),
        false,
        None,
    );
    // ---- 多用户鉴权表 ----
    // 每个用户一份独立的 AEAD 密钥，用密码派生出的 16 字节 auth id 做索引。
    //
    // 为什么不用「遍历所有密钥试解」：ChaCha20-Poly1305 每次尝试都要跑一遍
    // poly1305 校验，100 用户就是 100 倍 CPU；而且试验次数多了本身也是
    // 一个可被计时的侧信道。用明文 auth id 查表是 O(1)。
    //
    // 为什么明文 auth id 是安全的：它由 HKDF 独立派生（info 与密钥不同），
    // 与密钥在密码学上无关；抓包只能看到 16 字节随机值，既推不出密码，
    // 也无法借此解密——真正的鉴权仍然靠 open_first 的 AEAD 校验。
    let user_map: UserMap = {
        let mut m: UserMap = HashMap::new();
        for (name, password) in cfg.effective_users() {
            let obfs = Arc::new(Obfs::new_server(&password));
            let id = obfs.auth_id();
            // 密码相同 → auth id 相同 → 后者覆盖前者，一整个用户会被静默顶掉。
            // check 会拦这种情况，这里再兜一层日志，避免线上莫名少一个用户。
            if m.insert(id, (name.clone(), obfs)).is_some() {
                tracing::warn!(user = %name, "用户密码与前面的重复，已覆盖；请检查配置");
            }
        }
        m
    };
    tracing::info!(users = user_map.len(), "外层鉴权表已就绪");
    // 客户端地址 → (连接句柄, 密钥, 显示名)。
    //
    // 每个入向包都要靠它选密钥。不能用 find_by_client 那种 O(n) 遍历：
    // 高包速率下（1 万 pps、几十条连接）会把 CPU 烧在无意义的地址比较上。
    // 与 conns 同步维护：accept 时插入，连接回收时删除。
    let mut by_client: HashMap<SocketAddr, (ConnectionHandle, Arc<Obfs>, String)> = HashMap::new();
    let magic = cfg.faketcp.ip_id_magic;
    let mut conns: HashMap<ConnectionHandle, ServerConn> = HashMap::new();
    // 记录每个客户端 SYN 的状态（ISN / TSval），等 QUIC 首包到达时复用。
    // 没有超时清理的版本会永久残留（掉线、探测、攻击都会留下条目），
    // 因此主循环里按 60 秒回收。
    let mut syn_pending: HashMap<SocketAddr, SynState> = HashMap::new();
    // 有界动作队列：按 quic-go 的「阻塞写」模型做背压。
    // 目标读到数据后要等队列有空位才能继续读，队列满 → 目标 TCP 接收缓冲满
    // → 目标发送变慢。这样下行数据不会在 pending 里无限堆积。
    // 1024 项 ≈ 16MB（200Mbps 下约 0.65 秒）：既能吸收主循环抖动，
    // 又不会在 cwnd 收缩时攒出几百 MB 的 backlog（之前 2048 项 + 每流 16MB
    // 背压上限实测堆到过 214MB，直接把链路打成 bufferbloat）。
    let (action_tx, mut action_rx) = mpsc::channel::<ServerAction>(1024);
    let mut last_stats = Instant::now();

    // 批量发送缓冲池：全部报文缓冲只分配一次，之后每轮复用。
    // 这是把 11000 pps 的「每包 3~5 次 malloc + 每包一次 sendto」
    // 压成「每 32 包一次 sendmmsg」的关键。
    let mut send_batch = PacketBatch::new();
    // `poll_transmit` 的备用缓冲（保留签名完整性，实际不再使用）
    let mut scratch: Vec<u8> = Vec::new();

    loop {
        // 每 2 秒打印一次每条连接的路径统计，定位吞吐瓶颈
        if last_stats.elapsed() >= Duration::from_secs(2) {
            let mut total_sent = 0u64;
            let mut total_lost = 0u64;
            for c in conns.values() {
                let s = c.conn.stats();
                total_sent += s.path.sent_packets;
                total_lost += s.path.lost_packets;
                // streams/pending 是排查「内存暴涨 / 流卡死」的关键：
                // pending 是 QUIC 流控阻塞后暂存的下行数据，一直不降就说明对端不读。
                let pending: usize = c.streams.values().map(|x| x.pending.len()).sum();
                tracing::info!(
                    client = %c.client,
                    rtt_ms = s.path.rtt.as_millis() as u64,
                    cwnd = s.path.cwnd,
                    sent = s.path.sent_packets,
                    lost = s.path.lost_packets,
                    mtu = s.path.current_mtu,
                    streams = c.streams.len(),
                    udp_sessions = c.udp.len(),
                    pending,
                    "服务端 QUIC 路径统计"
                );
            }
            // ---- 自适应窗口 ----
            // 与客户端同一套策略：阈值 20%/5%、步长 0.9/1.2，下限 1.5MB。
            // 之前 15%/0.85 太激进，正常链路抖动就会把窗口压到 1~2MB，测速跑不满。
            let d_sent = total_sent.saturating_sub(last_sent);
            let d_lost = total_lost.saturating_sub(last_lost);
            let loss = if d_sent > 0 {
                d_lost as f64 / d_sent as f64
            } else {
                0.0
            };
            last_sent = total_sent;
            last_lost = total_lost;
            let cur = max_cwnd.load(std::sync::atomic::Ordering::Relaxed);
            let next = if loss > 0.20 {
                (cur as f64 * 0.90) as u64
            } else if loss < 0.05 {
                (cur as f64 * 1.20) as u64
            } else {
                cur
            };
            // quinn 接收组装器硬限制 MAX_CHUNKS=1024：
            // 窗口(字节) ÷ 1308 × 丢包率 必须小于 1024，否则直接断连。
            // 按当前丢包率反算安全上限，再乘 0.7 留余量，然后限制在 1.5MB~8MB。
            let safe_cap = ((1024.0 * 1308.0) / loss.max(0.01) * 0.7) as u64;
            // 配置里的 net.max_cwnd 是「上限」语义：自适应只能在它之下浮动。
            // 之前只当初始值，丢包率低于 5% 时会被 1.2 倍一路放大到 8MB，
            // 用户按小带宽链路设的值完全失效（窗口远超 BDP，丢包反而变多）。
            let cfg_cap = cfg.net.max_cwnd.max(1536 * 1024);
            let upper = safe_cap
                .clamp(1536 * 1024, 8 * 1024 * 1024)
                .min(cfg_cap);
            let next = next.clamp(1536 * 1024, upper);
            max_cwnd.store(next, std::sync::atomic::Ordering::Relaxed);
            // 收包队列积压：持续不归零说明主循环处理不过来（或批量上限太小）
            tracing::info!(
                rx_queue = pkt_rx.len(),
                conns = conns.len(),
                loss_pct = (loss * 100.0) as u64,
                win_cap = next,
                "服务端队列统计"
            );
            last_stats = Instant::now();
        }
        // 所有连接里最近的定时器
        let deadline = conns
            .values_mut()
            .filter_map(|c| c.conn.poll_timeout())
            .min()
            .map(tokio::time::Instant::from_std);

        tokio::select! {
            // 1. 收到客户端的 raw 数据包
            maybe = pkt_rx.recv() => {
                let Some(first) = maybe else { break };
                // 批量处理：除刚取到的包外，把队列里已到达的一起消化，
                // 每轮最多 256 个。单包一轮在测速上传时会产生严重积压。
                let mut batch: Vec<(
                    u32,
                    SocketAddr,
                    std::net::Ipv4Addr,
                    u16,
                    u8,
                    Option<u8>,
                    Option<u32>,
                    Vec<u8>,
                )> = Vec::with_capacity(256);
                batch.push(first);
                while batch.len() < 256 {
                    match pkt_rx.try_recv() {
                        Ok(p) => batch.push(p),
                        Err(_) => break,
                    }
                }
                for (seq, client, dst_ip, ip_id, flags, wscale, tsval_in, payload) in batch {
                    handle_packet(
                        &mut endpoint,
                        &server_quic,
                        &mut conns,
                        &mut syn_pending,
                        &raw,
                        dst_ip,
                        port,
                        magic,
                        &user_map,
                        &mut by_client,
                        seq,
                        client,
                        ip_id,
                        flags,
                        wscale,
                        tsval_in,
                        &payload,
                        &action_tx,
                    );
                }
                // 反向纯 ACK：上传方向也要让中间盒看到正常的 TCP 确认流。
                // 与客户端同一套延迟确认规则：累计 2 段立即确认，或超 40ms 兜底。
                let ack_list: Vec<ConnectionHandle> = conns
                    .iter()
                    .filter(|(_, c)| {
                        c.ack_pending >= 2
                            || (c.ack_pending > 0
                                && c.last_ack.elapsed() >= Duration::from_millis(40))
                    })
                    .map(|(h, _)| *h)
                    .collect();
                for h in ack_list {
                    if let Some(c) = conns.get_mut(&h) {
                        let unread: usize = c.streams.values().map(|s| s.pending.len()).sum();
                        c.send_pure_ack(&raw, port, advertised_window(unread));
                    }
                }
            }
            // 2. QUIC 定时器
            _ = tick(deadline) => {
                let now = Instant::now();
                for c in conns.values_mut() {
                    c.conn.handle_timeout(now);
                }
            }
            // 3. 出站任务回传的数据
            maybe = action_rx.recv() => {
                let Some(first) = maybe else { break };
                // 同样批量消化：上传大流量时目标回写动作会集中爆发。
                // 每轮上限 64 项（约 1MB）而不是 256 项（4MB）：
                // 这个上限直接决定了单轮能往某条流的 pending 里推进多少，
                // 必须明显小于背压溢出的判断阈值，否则会误杀正常流。
                let mut actions: Vec<ServerAction> = Vec::with_capacity(64);
                actions.push(first);
                while actions.len() < 64 {
                    match action_rx.try_recv() {
                        Ok(a) => actions.push(a),
                        Err(_) => break,
                    }
                }
                for action in actions {
                    handle_action(&mut conns, action, pending_high_water);
                }
            }
        }

        // 每条连接都要把 QUIC 待发包排空，并处理事件
        for c in conns.values_mut() {
            // 通告窗口按「待发字节数」动态计算，恒为 65535 是明显的伪造特征
            let unread: usize = c.streams.values().map(|s| s.pending.len()).sum();
            let window = advertised_window(unread);
            drain_transmits(c, &raw, port, &mut send_batch, &mut scratch, window);
            drain_events(c, &action_tx, pending_high_water, &cfg.udp);
        }
        // 清理已双向结束的流：之前从不删除，长时间跑高并发（直播/测速）会一直累积，
        // 每条流的 pending / target_buf 都占用内存，最终拖慢整个事件循环。
        for c in conns.values_mut() {
            c.streams
                .retain(|_, s| {
                    // 双向已完成，或已空闲超过 5 分钟（双方都没发 FIN 的僵尸流）
                    let done = s.local_finished && s.remote_finished;
                    let idle =
                        Instant::now().duration_since(s.last_active) > Duration::from_secs(300);
                    !(done || idle)
                });
            // UDP 会话回收：UDP 无连接，只能靠「多久没收到包」判断死活。
            // 移除后 `to_target` 被 drop，出站任务的 `rx.recv()` 立刻返回 None
            // 并退出，socket 随之关闭——不需要额外的取消信号。
            let udp_idle = Duration::from_secs(cfg.udp.timeout_secs.max(10));
            let now = Instant::now();
            // 先收集再删除：日志里要带上目标地址，方便排查「为什么这个会话被回收了」
            let expired: Vec<(u32, String)> = c
                .udp
                .iter()
                .filter(|(_, s)| now.duration_since(s.last_active) >= udp_idle)
                .map(|(id, s)| (*id, s.target.clone()))
                .collect();
            for (id, target) in expired {
                c.udp.remove(&id);
                tracing::debug!(
                    client = %c.client,
                    session = id,
                    %target,
                    idle_secs = cfg.udp.timeout_secs,
                    "UDP 会话空闲超时回收"
                );
            }
        }
        // SYN 表超时清理：客户端发了 SYN 但 QUIC 首包始终没到达
        //（掉线、扫描器也带魔数、或客户端进程被杀），条目会永久残留。
        // 60 秒足够覆盖正常握手（1 个 RTT），超时后按普通丢包处理。
        {
            let now_syn = Instant::now();
            let before = syn_pending.len();
            syn_pending.retain(|_, s| {
                now_syn.duration_since(s.at) < Duration::from_secs(60)
            });
            if syn_pending.len() != before {
                tracing::debug!(
                    expired = before - syn_pending.len(),
                    alive = syn_pending.len(),
                    "SYN 表超时清理"
                );
            }
        }
        // 连接完全关闭后清理。先补一个 FIN，让拆除过程像真实 TCP。
        for c in conns.values_mut() {
            if c.conn.is_drained() {
                let unread: usize = c.streams.values().map(|s| s.pending.len()).sum();
                // 带上用户，多用户下排查「谁断了」不用去对时间戳
                tracing::info!(client = %c.client, user = %c.user, "QUIC 连接结束");
                c.send_fin(&raw, port, advertised_window(unread));
            }
        }
        // 地址索引必须跟着一起摘，否则它会指向已删除的句柄：
        // 下一个包会先用一条不存在的连接的密钥试解，白白跑一次 AEAD。
        let drained_addrs: Vec<SocketAddr> = conns
            .values()
            .filter(|c| c.conn.is_drained())
            .map(|c| c.client)
            .collect();
        conns.retain(|_, c| !c.conn.is_drained());
        for addr in drained_addrs {
            by_client.remove(&addr);
        }
    }

    tracing::info!("服务端退出");
    Ok(())
}

/// 处理一个收到的客户端数据包。
#[allow(clippy::too_many_arguments)]
fn handle_packet(
    endpoint: &mut Endpoint,
    server_cfg: &Arc<ServerConfig>,
    conns: &mut HashMap<ConnectionHandle, ServerConn>,
    syn_pending: &mut HashMap<SocketAddr, SynState>,
    raw: &Arc<RawSocket>,
    local_ip: std::net::Ipv4Addr,
    port: u16,
    magic: u16,
    user_map: &UserMap,
    by_client: &mut HashMap<SocketAddr, (ConnectionHandle, Arc<Obfs>, String)>,
    seq: u32,
    client: SocketAddr,
    ip_id: u16,
    flags: u8,
    _wscale: Option<u8>,
    tsval_in: Option<u32>,
    payload: &[u8],
    action_tx: &mpsc::Sender<ServerAction>,
) {
    // 分流标记高字节：来自配置，与客户端一致
    let mark = crate::faketcp::packet::ipid_mark(magic);

    // 纯 SYN：标准握手第一步，立即回 SYN-ACK。
    // 严格 NAT/状态防火墙只放行 SYN-ACK 之后的数据包，不回 SYN-ACK 的话
    // 客户端后续的 ClientHello 和 QUIC Initial 会被直接丢弃。
    //
    // 判别依据是 IP ID 高字节（配置派生的标记）。
    // 之前用 wscale=12，但伪装改造后 wscale 必须改成真实的 9，
    // 那时 wscale 就无法再区分伪包和真实 TLS 客户端了（真实 Linux 也是 9）。
    if (ip_id & mark) == mark && flags & TCP_SYN != 0 && payload.is_empty() {
        // 重复 SYN（客户端重传）：复用原来的 ISN 和 TSval。
        //
        // 真实 TCP 栈对重传的 SYN 回**一模一样**的 SYN-ACK（ISN 不变），
        // 客户端才能用同一个 ACK 完成握手。
        // 如果每次都给新 ISN，客户端先收到旧 SYN-ACK、再收到新 SYN-ACK 时，
        // peer_seq 会被两个不同的 seq 来回拉扯，ServerHello 的序号
        // 与握手包不连续，抓包一看就是伪造。
        // 10 秒内视为同一次握手尝试，超过就当新连接。
        let (isn, tsval) = match syn_pending.get(&client) {
            Some(s) if s.at.elapsed() < Duration::from_secs(10) => {
                tracing::debug!(%client, "收到重复 SYN，复用原 ISN 回 SYN-ACK");
                (s.our_isn, s.ts)
            }
            _ => {
                let isn: u32 = rand::thread_rng().gen();
                // TSval 只生成一次，握手后续的 ServerHello 和数据包都以它为基准，
                // 保证同一条连接内 TSval 单调不减（真实 TCP 的 PAWS 依赖这一点）。
                (isn, rand::thread_rng().gen::<u32>())
            }
        };
        syn_pending.insert(
            client,
            SynState {
                peer_isn: seq,
                our_isn: isn,
                ts: tsval,
                at: Instant::now(),
            },
        );
        if let std::net::IpAddr::V4(dst_ip) = client.ip() {
            // SYN-ACK 的选项与真实 Linux 逐字节一致（MSS/SACK/TS/NOP/wscale 9）。
            // TSecr 回显客户端 SYN 里的 TSval（RFC 7323 要求）。
            let opts = syn_options(tsval, tsval_in.unwrap_or(0));
            let seg = TcpSeg {
                seq: isn,
                ack: seq.wrapping_add(1),
                flags: TCP_SYN | TCP_ACK,
                ip_id: random_ipid(mark),
                // SYN-ACK 阶段同样用 65535（缩放因子在 ESTABLISHED 后才生效）
                window: 65535,
                tsval,
                tsecr: tsval_in.unwrap_or(0),
                options: &opts,
                payload: &[],
            };
            let synack = build_packet(local_ip, dst_ip, port, client.port(), &seg);
            let _ = raw.send(&synack, dst_ip);
        }
        tracing::info!(%client, "标准握手：已回 SYN-ACK");
        return;
    }
    let _ = action_tx;
    // 诊断：确认 raw 包是否到达、魔数与 flags 是否正确（排查 NAT/TUN 劫持时用）
    tracing::debug!(
        %client,
        ip_id = format!("0x{ip_id:04X}"),
        flags = format!("0x{flags:02X}"),
        payload = payload.len(),
        "收到 raw 包"
    );
    // 本包解出的用户身份，等 accept 时塞进 ServerConn。
    // 只有首包解密成功才会被赋值；后续包的身份已经在连接里了。
    let mut pending_user: Option<(Arc<Obfs>, String)> = None;

    // 遍历 TLS 记录：0x16 是表演握手，0x17 才是真实数据
    for rec in parse_records(payload) {
        if rec.typ != REC_APPDATA {
            continue;
        }
        let Some((plain, obfs_used, user_name, is_first)) =
            decrypt_record(conns, by_client, client, user_map, rec.payload)
        else {
            // 解密失败：不是我们的客户端（或密码不对），静默丢弃。
            // 用 debug 而不是 warn：公网端口每天会收到大量探测包，
            // warn 会把日志刷满，反而掩盖真正的异常。
            tracing::debug!(%client, len = rec.payload.len(), "外层 AEAD 解密失败");
            continue;
        };
        if is_first {
            tracing::info!(%client, user = %user_name, "首包鉴权通过");
            pending_user = Some((obfs_used, user_name));
        }
        let now = Instant::now();
        let mut buf = Vec::with_capacity(2048);
        let event = endpoint.handle(
            now,
            client,
            None,
            None,
            BytesMut::from(&plain[..]),
            &mut buf,
        );
        match event {
            Some(DatagramEvent::NewConnection(incoming)) => {
                // 客户端重启/重连后五元组会复用，旧连接会和新连接共用同一套 seq/ack
                // 并持续重传，互相干扰（日志里 conns=2、旧连接 streams=56 就是这个）。
                // 建新连接时直接丢弃同一客户端地址的旧连接。
                let before = conns.len();
                conns.retain(|_, c| c.client != client);
                if conns.len() != before {
                    tracing::info!(%client, "清理同一客户端的旧连接");
                    // 地址索引同步作废：否则它会指向已删除的句柄，
                    // 后续包就先按旧密钥试解，白白跑一次 AEAD
                    by_client.remove(&client);
                }
                match endpoint.accept(incoming, now, &mut buf, Some(server_cfg.clone())) {
                    Ok((ch, conn)) => {
                        // 用客户端 SYN 的 ISN 回 SYN-ACK，再把伪 ServerHello 按连续 seq 发出。
                        // 标准握手模式下 SYN-ACK 已经在收到 SYN 时发过，这里只补 ServerHello，
                        // 复用当时的 ISN 与 TSval，保证客户端看到的序列号和时间戳都连续。
                        let (peer_isn, isn, ts0, synack_sent) = match syn_pending.remove(&client) {
                            Some(s) => (s.peer_isn, s.our_isn, s.ts, true),
                            // 没走过标准握手（handshake=none 或旧客户端）：全部现取随机值
                            None => (
                                0,
                                rand::thread_rng().gen(),
                                rand::thread_rng().gen(),
                                false,
                            ),
                        };
                        // ServerHello 实际发出去的长度，决定后续数据的起始 seq。
                        // **必须用实际缓冲的长度**：`build_server_hello()` 的
                        // 加密段落是 512~703 的随机长度，再调一次拿到的长度和
                        // 刚才发出去的不一样，`data_seq` 就会偏掉 0~191 字节。
                        // 后果是对端/中间盒看到的 TCP 序号与字节流对不上
                        // （ack 与上一包的 seq+len 不衔接），是明确可检测的特征。
                        let mut hello_len = 0u32;
                        if let std::net::IpAddr::V4(dst_ip) = client.ip() {
                            // 兼容没走标准握手的客户端：没记录过 ISN 就补发 SYN-ACK。
                            // 选项同样使用真实 Linux 形态（含时间戳、wscale 9）。
                            if !synack_sent {
                                let opts = syn_options(ts0, tsval_in.unwrap_or(0));
                                let seg = TcpSeg {
                                    seq: isn,
                                    ack: peer_isn.wrapping_add(1),
                                    flags: TCP_SYN | TCP_ACK,
                                    ip_id: random_ipid(mark),
                                    window: 65535,
                                    tsval: ts0,
                                    tsecr: tsval_in.unwrap_or(0),
                                    options: &opts,
                                    payload: &[],
                                };
                                let synack =
                                    build_packet(local_ip, dst_ip, port, client.port(), &seg);
                                let _ = raw.send(&synack, dst_ip);
                            }
                            let hello = build_server_hello();
                            let seg = TcpSeg {
                                seq: isn.wrapping_add(1),
                                ack: peer_isn.wrapping_add(1),
                                flags: TCP_PSH | TCP_ACK,
                                ip_id: random_ipid(mark),
                                window: advertised_window(0),
                                // 比 SYN-ACK 大 1，单调
                                tsval: ts0.wrapping_add(1),
                                tsecr: tsval_in.unwrap_or(0),
                                options: &[],
                                payload: &hello,
                            };
                            let hello_pkt =
                                build_packet(local_ip, dst_ip, port, client.port(), &seg);
                            let _ = raw.send(&hello_pkt, dst_ip);
                            hello_len = hello.len() as u32;
                            tracing::debug!(%client, %peer_isn, hello_len, "已发送 ServerHello");
                        }
                        let data_seq = isn.wrapping_add(1).wrapping_add(hello_len);
                        // 起始序号之后，数据包的 TSval 从 ts0+2 起算（比 ServerHello 大 1），
                        // 并立即记下客户端最近的 TSval，避免首个数据包回显 TSecr=0。
                        let mut clock = TcpClock::new_at(ts0.wrapping_add(2));
                        clock.observe(tsval_in);
                        // 用户身份来自本包的首包解密结果。理论上走到这里
                        // 一定有值（端 handle 之前必须先解密成功），
                        // 拿不到就不建立连接——没有密钥的连接发不出任何包。
                        let auth = pending_user.clone();
                        conns.insert(
                            ch,
                            ServerConn {
                                conn,
                                ch,
                                client,
                                obfs: auth.as_ref().map(|(o, _)| o.clone()),
                                user: auth
                                    .as_ref()
                                    .map(|(_, n)| n.clone())
                                    .unwrap_or_default(),
                                local_ip,
                                seq: data_seq,
                                peer_seq: peer_isn.wrapping_add(1),
                                // 服务端自己的 IP ID 序列，与客户端的独立
                                ip_id: random_ipid(mark),
                                mark,
                                clock,
                                ack_pending: 0,
                                last_ack: Instant::now(),
                                ctrl_buf: Vec::with_capacity(256),
                                streams: HashMap::new(),
                                udp: HashMap::new(),
                            },
                        );
                        // 地址索引只对已鉴权的连接建立：
                        // 没有密钥的连接解不开任何后续包，建索引也没用。
                        if let Some((obfs_ready, user)) = auth {
                            by_client.insert(client, (ch, obfs_ready, user));
                        }
                        tracing::info!(%client, "新的 QUIC 连接");
                    }
                    Err(e) => tracing::debug!(%client, ?e, "accept 失败"),
                }
            }
            Some(DatagramEvent::ConnectionEvent(ch, ev)) => {
                if let Some(c) = conns.get_mut(&ch) {
                    // 记录客户端时间戳：所有回包的 TSecr 都要回显它
                    c.clock.observe(tsval_in);
                    // ack 只增不减：乱序时回退的 ack 会被中间设备当成非法包。
                    // seq_len 会把 SYN/FIN 各算 1 个序号，与真实 TCP 一致。
                    let next = seq.wrapping_add(seq_len(flags, payload.len()));
                    if next.wrapping_sub(c.peer_seq) < 0x8000_0000 {
                        c.peer_seq = next;
                    }
                    if !payload.is_empty() {
                        c.ack_pending += 1;
                    }
                    c.conn.handle_event(ev);
                }
            }
            Some(DatagramEvent::Response(t)) => {
                // endpoint 直接产生响应（如 Retry / stateless reset）
                if let Some(found) = find_by_client(conns, client) {
                    if let Some(c) = conns.get_mut(&found) {
                        c.send_datagram_one(raw, port, &buf[..t.size]);
                    }
                }
            }
            None => {}
        }
        // 消化 endpoint 事件，避免内部队列堆积
        let handles: Vec<ConnectionHandle> = conns.keys().copied().collect();
        for ch in handles {
            if let Some(c) = conns.get_mut(&ch) {
                while let Some(ee) = c.conn.poll_endpoint_events() {
                    if let Some(ce) = endpoint.handle_event(ch, ee) {
                        c.conn.handle_event(ce);
                    }
                }
            }
        }
    }
    let _ = action_tx; // 目前不需要在这里用，保留参数便于后续扩展
}

/// 找到指定客户端地址对应的连接句柄。
///
/// **故意不做「找不到就退回第一个连接」的容错**：
/// 那样会把一个 stateless reset / Retry 用错误的 seq 发给无关的客户端，
/// 既无意义，又会在抓包里制造看不懂的包。找不到就不发。
fn find_by_client(
    conns: &HashMap<ConnectionHandle, ServerConn>,
    client: SocketAddr,
) -> Option<ConnectionHandle> {
    conns
        .iter()
        .find(|(_, c)| c.client == client)
        .map(|(ch, _)| *ch)
}

/// 尝试解密一条 ApplicationData 记录。
///
/// 返回 `(明文, 该用户密钥, 显示名, 是否首包)`。
///
/// 顺序刻意是「先按已有连接的密钥解，再按首包解」：
/// 客户端重连时三元组地址会复用，旧连接还在 conns 里，
/// 若先按首包处理，就会拿旧连接的密钥去解新连接的首包（含 17 字节首包头），
/// 必然失败，然后白白多跑一次查表 + AEAD。
///
/// 反过来先试连接密钥也安全：后续包开头是 4 字节随机 nonce 前缀，
/// 恰好等于某个用户的 auth id 且版本字节对得上的概率可以忽略，
/// 即使撞上也过不了 AEAD 认证。
fn decrypt_record(
    conns: &HashMap<ConnectionHandle, ServerConn>,
    by_client: &HashMap<SocketAddr, (ConnectionHandle, Arc<Obfs>, String)>,
    client: SocketAddr,
    user_map: &UserMap,
    payload: &[u8],
) -> Option<(Vec<u8>, Arc<Obfs>, String, bool)> {
    // 1) 已建立连接：用该连接自己的密钥（共 99.9% 的包走这条）
    if let Some((ch, obfs, user)) = by_client.get(&client) {
        if conns.contains_key(ch) {
            if let Some(plain) = obfs.open(payload) {
                return Some((plain, obfs.clone(), user.clone(), false));
            }
        }
    }
    // 2) 首包：明文头里读版本 + auth id，查表拿密钥
    let (ver, auth_id) = parse_first_header(payload)?;
    if ver != PROTOCOL_VERSION {
        return None;
    }
    let (user, obfs) = user_map.get(&auth_id)?;
    let plain = obfs.open_first(payload)?;
    Some((plain, obfs.clone(), user.clone(), true))
}

impl ServerConn {
    /// 把一个 QUIC 数据报封装成 TLS 记录 + TCP 包，写入 `out` 后由调用方批量发送。
    ///
    /// 与旧实现（每包内部 `raw.send`）的区别：这里不碰 socket，
    /// 只负责「明文 → 记录 → IP 报文」的纯内存构造，
    /// 让上层可以把 32 个包攒起来用一次 `sendmmsg` 发出去。
    ///
    /// 返回目的 IPv4，供批量发送复用；非 IPv4 客户端返回 None。
    fn build_datagram(
        &mut self,
        port: u16,
        record: &mut Vec<u8>,
        out: &mut Vec<u8>,
        payload: &[u8],
        window: u16,
    ) -> Option<std::net::Ipv4Addr> {
        // 每条连接用自己所属用户的密钥加密（多用户），
        // 所以密钥必须从 self 取，不能再走参数传入的全局 Obfs。
        //
        // clone 一个 Arc 而不是长期借用 self.obfs：
        // 函数后段要用 &mut self 改 seq / ip_id，借用会冲突；
        // Arc 克隆只是一次原子自增，比重新组织借用关系便宜得多。
        let obfs = self.obfs.clone()?;
        // 外层 AEAD：写进复用缓冲，不分配
        obfs.seal_into(record, payload);
        let std::net::IpAddr::V4(dst_ip) = self.client.ip() else {
            return None;
        };
        let seg = TcpSeg {
            seq: self.seq,
            ack: self.peer_seq,
            flags: TCP_PSH | TCP_ACK,
            ip_id: self.ip_id,
            window,
            tsval: self.clock.tsval(),
            tsecr: self.clock.peer_ts,
            options: &[],
            payload: record,
        };
        build_packet_into(out, self.local_ip, dst_ip, port, self.client.port(), &seg);
        // TCP 语义：序列号按载荷推进，让中间盒看到的流是连续的
        self.seq = self.seq.wrapping_add(seq_len(TCP_PSH | TCP_ACK, record.len()));
        self.ip_id = next_ipid(self.mark, self.ip_id);
        Some(dst_ip)
    }

    /// 发一个纯 ACK（无载荷）。
    /// 真实 TCP 是双向确认的，下载方向必须有反向纯 ACK，否则一眼就是伪造。
    ///
    /// 用 `ctrl_buf` 复用缓冲：纯 ACK 占全部包量的 22.5%，
    /// 163Mbps 时每秒约 3400 个，每包一次 `build_packet` 就是每秒 3400 次
    /// malloc/free——在 1 核机器上是可观的用户态开销。
    fn send_pure_ack(&mut self, raw: &Arc<RawSocket>, port: u16, window: u16) {
        self.ack_pending = 0;
        self.last_ack = Instant::now();
        let std::net::IpAddr::V4(dst_ip) = self.client.ip() else {
            return;
        };
        let seg = TcpSeg {
            seq: self.seq,
            ack: self.peer_seq,
            flags: TCP_ACK,
            ip_id: self.ip_id,
            window,
            tsval: self.clock.tsval(),
            tsecr: self.clock.peer_ts,
            options: &[],
            payload: &[],
        };
        // take 出来避免同时借用 self 和 self.ctrl_buf
        let mut buf = std::mem::take(&mut self.ctrl_buf);
        build_packet_into(
            &mut buf,
            self.local_ip,
            dst_ip,
            port,
            self.client.port(),
            &seg,
        );
        let _ = raw.send(&buf, dst_ip);
        self.ctrl_buf = buf;
        // 纯 ACK 不占序号，只推进 IP ID
        self.ip_id = next_ipid(self.mark, self.ip_id);
    }

    /// 发 FIN 拆除连接。真实 TCP 断开一定有 FIN（或 RST），
    /// 旧实现是静默消失，抓包里「连接凭空蒸发」也是明显特征。
    fn send_fin(&mut self, raw: &Arc<RawSocket>, port: u16, window: u16) {
        let std::net::IpAddr::V4(dst_ip) = self.client.ip() else {
            return;
        };
        let seg = TcpSeg {
            seq: self.seq,
            ack: self.peer_seq,
            flags: TCP_FIN | TCP_ACK,
            ip_id: self.ip_id,
            window,
            tsval: self.clock.tsval(),
            tsecr: self.clock.peer_ts,
            options: &[],
            payload: &[],
        };
        let mut buf = std::mem::take(&mut self.ctrl_buf);
        build_packet_into(
            &mut buf,
            self.local_ip,
            dst_ip,
            port,
            self.client.port(),
            &seg,
        );
        let _ = raw.send(&buf, dst_ip);
        self.ctrl_buf = buf;
        self.seq = self.seq.wrapping_add(1);
        self.ip_id = next_ipid(self.mark, self.ip_id);
    }

    /// 单包发送：只用于 Retry / stateless reset 这类低频冷路径。
    /// 热路径（正常数据包）不走这里，否则又会退化成「一包一次 sendto」。
    fn send_datagram_one(
        &mut self,
        raw: &Arc<RawSocket>,
        port: u16,
        payload: &[u8],
    ) {
        let mut record = Vec::with_capacity(2048);
        let mut pkt = Vec::with_capacity(2048);
        if let Some(dst_ip) = self.build_datagram(
            port,
            &mut record,
            &mut pkt,
            payload,
            advertised_window(0),
        ) {
            if let Err(e) = raw.send(&pkt, dst_ip) {
                tracing::warn!(error = %e, "发送失败");
            }
        }
    }
}

/// 排空一条连接的待发 QUIC 包。
///
/// 核心优化：不再「一包一次 sendto」，而是攒满 `PacketBatch::MAX` 个
/// 或队列取空后，用一次 `sendmmsg` 发出。对应地，明文/记录/IP 报文
/// 三个缓冲全部复用，稳态零分配。
fn drain_transmits(
    c: &mut ServerConn,
    raw: &Arc<RawSocket>,
    port: u16,
    batch: &mut PacketBatch,
    buf: &mut Vec<u8>,
    window: u16,
) {
    let std::net::IpAddr::V4(dst_ip) = c.client.ip() else {
        return;
    };
    let mut n = 0usize;
    // 一次 poll_transmit 最多要多少个 QUIC 数据报。
    // 传 1 时每个数据报都要走一遍完整状态机 + pacing 检查，高速率下
    // 每次唤醒只发一个包，事件循环被迫按包数空转（1.2 万 pps 就是 1.2 万次）。
    // 传 32 后 quinn 在一次调用里封好整批（等长、按 segment_size 对齐），
    // 我们按 segment_size 切开逐包加外层 TLS 记录，再一次性 sendmmsg 发出。
    const DATAGRAMS_PER_POLL: usize = PacketBatch::MAX;
    loop {
        // Instant::now() 提到循环外，避免每包一次时钟读取
        let now = Instant::now();
        // poll_transmit 是追加写入，必须先清空，否则缓冲区无限膨胀
        batch.plain.clear();
        let Some(t) = c.conn.poll_transmit(now, DATAGRAMS_PER_POLL, &mut batch.plain) else {
            break;
        };
        // 多数据报时 segment_size 给出单个数据报长度；单数据报为 None。
        // quinn 已保证批内每个数据报等长并按 segment 对齐（末包补齐）。
        let seg = t.segment_size.unwrap_or(t.size);
        if t.size == 0 || seg == 0 {
            break;
        }
        let mut off = 0usize;
        while off < t.size && n < PacketBatch::MAX {
            let end = (off + seg).min(t.size);
            batch.ensure(n + 1);
            // 明文 → 记录 → IP 报文，三步都写在复用缓冲上
            if c.build_datagram(
                port,
                &mut batch.record,
                &mut batch.bufs[n],
                &batch.plain[off..end],
                window,
            )
            .is_none()
            {
                break;
            }
            n += 1;
            off = end;
        }
        // 每轮最多 32 个包：既对齐 sendmmsg 上限，又避免长时间占住事件循环
        // 导致入向 ACK 在 channel 里积压、RTT 虚高、PTO 误判。
        if n >= PacketBatch::MAX {
            break;
        }
    }
    let _ = buf;
    if n > 0 {
        if let Err(e) = raw.send_batch(&batch.bufs[..n], dst_ip) {
            tracing::warn!(error = %e, "批量发送失败");
        }
    }
}

/// 处理一条 QUIC 连接上的事件。
fn drain_events(
    c: &mut ServerConn,
    action_tx: &mpsc::Sender<ServerAction>,
    pending_high_water: usize,
    udp_cfg: &crate::config::UdpFile,
) {
    // 先把 QUIC DATAGRAM 队列排空（UDP 上行）。
    // 必须每轮都读：quinn 的接收缓冲有限，不读就一直是满的，
    // 后面的 datagram 会被静默丢弃。空闲时 `recv()` 立刻返回 None，开销可忽略。
    handle_udp_datagrams(c, action_tx, udp_cfg);
    // 先无条件 accept 所有新流：Readable 可能先于 Opened 事件到达，
    // 不先建表会丢掉第一个数据包（也就是目标地址帧）
    while let Some(id) = c.conn.streams().accept(Dir::Bi) {
        tracing::debug!(stream = ?id, "接受新流");
        c.streams.entry(id).or_insert_with(ServerStream::default);
    }
    while let Some(ev) = c.conn.poll() {
        match ev {
            Event::Connected => {
                tracing::debug!(client = %c.client, "QUIC 握手完成");
            }
            Event::ConnectionLost { reason } => {
                tracing::debug!(client = %c.client, ?reason, "QUIC 连接断开");
            }
            Event::Stream(StreamEvent::Opened { dir: Dir::Bi }) => {
                // 上面已经统一 accept，这里不再重复处理
            }
            Event::Stream(StreamEvent::Readable { id }) => {
                read_stream(c, id, action_tx, pending_high_water);
            }
            Event::Stream(StreamEvent::Writable { id }) => {
                // QUIC 发送缓冲腾出空间：这是端到端背压的「放行」信号。
                // 清掉标志并唤醒出站任务，它可以继续读目标 socket 了。
                if let Some(s) = c.streams.get_mut(&id) {
                    s.write_blocked
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                    s.drain_notify.notify_waiters();
                }
                flush_pending(c, id);
            }
            Event::Stream(StreamEvent::Finished { id }) => {
                // 本地发送方向完成（我们发的 FIN 被 ACK），与接收方向无关。
                // 不能标 remote_finished，否则会把还在收数据的流误删。
                if let Some(s) = c.streams.get_mut(&id) {
                    s.local_finished = true;
                }
            }
            Event::Stream(StreamEvent::Stopped { id, .. }) => {
                // 对端要求停止发送（STOP_SENDING）：清 pending、停出站，并释放发送缓冲。
                // 这是「客户端已不读、服务端还在写」的唯一正确退出路径。
                if let Some(s) = c.streams.get_mut(&id) {
                    s.local_finished = true;
                    s.to_tcp = None;
                    s.pending.clear();
                    // 唤醒可能正卡在背压水位上的出站读取协程，让它立即退出。
                    // 只把 to_tcp 置 None 不够：那个协程等的是原子计数，不会看 channel。
                    s.pending_bytes.store(0, std::sync::atomic::Ordering::Relaxed);
                    s.write_blocked.store(false, std::sync::atomic::Ordering::Relaxed);
                    s.abandon.store(true, std::sync::atomic::Ordering::Relaxed);
                    s.drain_notify.notify_waiters();
                }
                let _ = c.conn.send_stream(id).reset(0u32.into());
            }
            _ => {}
        }
    }
}

/// 读一条流上的数据：先解析目标地址帧，之后转给出站任务。
fn read_stream(
    c: &mut ServerConn,
    id: StreamId,
    action_tx: &mpsc::Sender<ServerAction>,
    pending_high_water: usize,
) {
    let Some(st) = c.streams.get_mut(&id) else { return };
    if st.stopped {
        // 已经 stop 过的流：quinn 可能仍投递 Readable，忽略即可。
        return;
    }
    st.last_active = Instant::now();
    let mut out = Vec::new();
    let mut finished = false;
    // 出站缓冲打满时必须停流：标记后再动 conn，避免借用冲突
    let mut need_stop = false;
    {
        let mut recv = c.conn.recv_stream(id);
        match recv.read(true) {
            Ok(mut chunks) => {
                loop {
                    match chunks.next(65536) {
                        Ok(Some(chunk)) => out.extend_from_slice(&chunk.bytes),
                        Ok(None) => {
                            finished = true;
                            break;
                        }
                        Err(ReadError::Blocked) => break,
                        Err(_) => {
                            finished = true;
                            break;
                        }
                    }
                }
                let _ = chunks.finalize();
            }
            // “流已不在接收表 / 已读空 / 已停止”是正常状态：
            // Readable 事件会重复投递，上一轮已经把数据读完，这一轮再读就拿到
            // ReadableError::ClosedStream。
            // 旧代码把任何 Err 都当成「流卡死」，执行 stop() 并把 st.to_tcp 置 None，
            // 而 to_tcp 一断，出站任务立刻退出、目标 TCP 连接被关闭，
            // 正在下载的这条流直接被截断——实测 curl 报
            // "transfer closed with ... bytes remaining to read"，
            // 200MB 单流只能下到 6~7MB 就断。
            // 这里什么都不做，等下一个 Readable 事件即可。
            Err(ReadableError::ClosedStream) => {}
            // 有序读写在无序读之后：编程错误，只记日志不杀流
            Err(ReadableError::IllegalOrderedRead) => {
                tracing::warn!(stream = ?id, "有序读写在无序读之后，忽略本轮");
            }
        };
    }

    if !st.target_ready {
        st.target_buf.extend_from_slice(&out);
        tracing::debug!(stream = ?id, bytes = out.len(), buf = st.target_buf.len(), "首帧数据");
        // 地址帧：2 字节长度 + SOCKS5 格式地址
        if st.target_buf.len() >= 2 {
            let len = u16::from_be_bytes([st.target_buf[0], st.target_buf[1]]) as usize;
            if st.target_buf.len() >= 2 + len {
                let addr = st.target_buf[2..2 + len].to_vec();
                let rest = st.target_buf[2 + len..].to_vec();
                st.target_buf.clear();
                st.target_ready = true;
                if let Some((host, port)) = decode_target(&addr) {
                    // 有界通道 4096 项（约 64MB 上限）：上传大流量时目标写入会短暂落后，
                    // 小容量会把正常流误杀；背压由 pending_bytes 负责，这里只做安全网。
                    let (tx, rx) = mpsc::channel(4096);
                    st.to_tcp = Some(tx);
                    let action_tx = action_tx.clone();
                    let ch = c.ch;
                    tracing::debug!(%host, port, "打开出站连接");
                    tokio::spawn(outbound(
                        ch,
                        id,
                        host,
                        port,
                        rest,
                        rx,
                        action_tx,
                        st.pending_bytes.clone(),
                        st.drain_notify.clone(),
                        st.write_blocked.clone(),
                        st.abandon.clone(),
                        pending_high_water,
                    ));
                }
            }
        }
    } else if !out.is_empty() {
        tracing::debug!(stream = ?id, bytes = out.len(), "转发到出站 TCP");
        if let Some(tx) = &st.to_tcp {
            // 有界通道 + try_send：目标写得慢时直接停掉这条流，
            // 不把数据无下限地堆在内存里。客户端会收到 RESET，
            // speedtest/播放器这类会自己重试，不会拖死其它流。
            match tx.try_send(out) {
                Ok(_) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::warn!(stream = ?id, "出站缓冲已满，停止该流");
                    st.to_tcp = None;
                    st.remote_finished = true;
                    need_stop = true;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    // 出站任务已退出（目标关闭），后续数据不再转
                    st.to_tcp = None;
                    st.remote_finished = true;
                }
            }
        }
    }

    if finished && !st.remote_finished {
        st.remote_finished = true;
        // 发送空 Vec 通知出站任务关闭写端
        if let Some(tx) = &st.to_tcp {
            let _ = tx.try_send(Vec::new());
        }
    }

    // 必须在 st 的可变借用结束后再动 conn，否则借用冲突
    if need_stop {
        let _ = c.conn.recv_stream(id).stop(0u32.into());
    }
}

/// 背压高水位由配置文件 net.max_cwnd 推导（见 run 里的 pending_high_water）。

/// 处理 QUIC DATAGRAM（UDP 上行）。
///
/// 线上格式与 hysteria2 一致：
/// `[session u32][addrLen u16][ATYP][ADDR][PORT][payload]`
/// 每个包都带目标地址，所以服务端**不需要**任何跨连接的会话恢复逻辑：
/// 客户端重连后服务端是新连接、会话表是空的，第一个带地址的包就能重建会话。
///
/// 全程不做背压：`try_send` 失败就丢包，符合 UDP 语义。
fn handle_udp_datagrams(
    c: &mut ServerConn,
    action_tx: &mpsc::Sender<ServerAction>,
    udp_cfg: &crate::config::UdpFile,
) {
    if !udp_cfg.enabled {
        // 关闭时也必须读空队列，否则 quinn 的接收缓冲一直是满的
        while c.conn.datagrams().recv().is_some() {}
        return;
    }
    loop {
        let Some(pkt) = c.conn.datagrams().recv() else {
            break;
        };
        let Some((session, target, payload)) = udp::parse_client(&pkt) else {
            continue;
        };

        // 已有会话：直接投给出站任务
        if let Some(st) = c.udp.get_mut(&session) {
            let send_result = st.to_target.try_send(payload.to_vec());
            // 只有真正投递成功才刷新活跃时间。
            // 之前在 try_send 之前就刷新，导致「出站任务已退出」的死会话
            // 被源源不断的上行包一直续命，永远不会被空闲超时回收——
            // 实测向一个不可达目标持续发包时 udp_sessions 永远停在 1，
            // 客户端那条 (peer, target) 就成了永久黑洞。
            if send_result.is_ok() {
                st.last_active = Instant::now();
            }
            // 借用到这里结束，下面可能要删条目
            match send_result {
                Ok(()) => tracing::debug!(
                    client = %c.client,
                    session,
                    bytes = payload.len(),
                    "UDP 上行 → 已有会话"
                ),
                // 通道关闭 = 出站任务已退出（目标解析失败 / ICMP 不可达 /
                // socket 绑定失败）。必须删掉条目，让下一个包重新建会话，
                // 否则这条会话永远发不出去。
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    c.udp.remove(&session);
                    tracing::debug!(
                        client = %c.client,
                        session,
                        "UDP 出站任务已退出，删除会话（下个包重建）"
                    );
                }
                // 通道满 = 目标侧发得太慢或主循环跟不上，按 UDP 语义丢这个包，
                // 但会话本身是健康的，保留。
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::debug!(session, "UDP 上行队列满，丢弃")
                }
            }
            continue;
        }

        // 新会话：受 max_sessions 限制，防止单个客户端耗尽文件描述符
        if c.udp.len() >= udp_cfg.max_sessions {
            tracing::trace!(
                client = %c.client,
                session,
                limit = udp_cfg.max_sessions,
                "UDP 会话数已达上限，丢弃新会话"
            );
            continue;
        }
        let Some((host, port)) = decode_target(target) else {
            continue;
        };

        // 容量 64：约 64 个包（~80KB）的抖动余量。
        // 它就是「服务端允许为一个会话积压多少」，满了直接丢。
        let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
        // 第一个包不能丢：先塞进通道再 spawn，保证建会话的第一个请求能到目标
        let first = payload.to_vec();
        if tx.try_send(first).is_err() {
            continue;
        }
        tracing::debug!(client = %c.client, session, %host, port, "新建 UDP 会话");
        tokio::spawn(udp_outbound(
            c.ch,
            session,
            host.clone(),
            port,
            rx,
            action_tx.clone(),
        ));
        c.udp.insert(
            session,
            UdpSession {
                to_target: tx,
                target: format!("{host}:{port}"),
                last_active: Instant::now(),
            },
        );
    }
}

/// 一个 UDP 会话的收发任务。
///
/// 一个任务同时管两个方向：`select!` 让上行和下行都及时，
/// 会话结束时（主循环 drop 掉 `to_target`）`rx.recv()` 返回 None 立刻退出。
///
/// 与 TCP 出站任务的差别：
/// - 没有 `pending` / 水位 / 背压，读写都是「尽力而为」；
/// - 任何失败（目标不可达、发送缓冲满）都只是丢包，不结束整条连接。
async fn udp_outbound(
    ch: ConnectionHandle,
    session: u32,
    host: String,
    port: u16,
    mut rx: mpsc::Receiver<Vec<u8>>,
    action_tx: mpsc::Sender<ServerAction>,
) {
    // 解析目标：域名走系统解析器。失败就直接返回，主循环那边
    // 会在下一次超时回收时把这个 session 清掉（后续包也会因为通道关闭被丢）。
    let Ok(mut addrs) = tokio::net::lookup_host((host.as_str(), port)).await else {
        tracing::debug!(%host, port, "UDP 目标解析失败");
        return;
    };
    let Some(dst) = addrs.next() else {
        tracing::debug!(%host, port, "UDP 目标无可用地址");
        return;
    };

    let sock = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, "UDP socket 绑定失败");
            return;
        }
    };
    // connect 之后内核只会把该目标发来的包交给我们，
    // 天然防住「任意源地址注入」；send 也不需要每次指定地址。
    if let Err(e) = sock.connect(dst).await {
        tracing::debug!(%dst, error = %e, "UDP connect 失败");
        return;
    }
    tracing::debug!(session, %dst, "UDP 会话已建立");

    let mut buf = vec![0u8; 65536];
    // 回程帧缓冲复用，稳态零分配
    let mut out = Vec::with_capacity(2048);
    loop {
        tokio::select! {
            // 上行：主循环 → 目标
            maybe = rx.recv() => {
                match maybe {
                    // 主循环已经把这个会话回收/丢弃
                    None => break,
                    Some(d) => {
                        // 这里必须用 `send().await`，不能用 `try_send`。
                        // tokio 的 `UdpSocket::try_send` 依赖 socket 的可写就绪状态，
                        // 刚创建/刚 connect 的 socket 在 reactor 里还没被 poll 过，
                        // 会直接返回 WouldBlock —— 结果就是「会话建好了，第一个包
                        // （也就是 DNS 查询本身）被静默丢掉」，表现为 UDP 100% 收不到回程。
                        // UDP 的 sendto 在正常情况下不会阻塞，真要阻塞时短暂等一下
                        // 也比丢包好；失败就直接丢（UDP 不重传）。
                        match sock.send(&d).await {
                            Ok(_) => {}
                            Err(e) => {
                                tracing::debug!(session, error = %e, "UDP 发往目标失败，丢弃");
                            }
                        }
                    }
                }
            }
            // 下行：目标 → 主循环
            r = sock.recv(&mut buf) => {
                match r {
                    Ok(n) => {
                        udp::encode_server(session, &buf[..n], &mut out);
                        // try_send：主循环跟不上就丢包，绝不阻塞这个任务
                        match action_tx.try_send(ServerAction::Datagram(ch, out.clone())) {
                            Ok(()) => tracing::debug!(
                                session,
                                bytes = n,
                                "UDP 下行 → 主循环"
                            ),
                            Err(_) => tracing::debug!(session, "UDP 回程队列满，丢弃"),
                        }
                    }
                    // ICMP 不可达之类的错误：会话已经没有意义，退出
                    Err(e) => {
                        tracing::debug!(session, error = %e, "UDP 接收失败，会话结束");
                        break;
                    }
                }
            }
        }
    }
    tracing::debug!(session, "UDP 会话任务退出");
}

/// 彻底抛弃一条流：清空 pending、断开与出站任务的联系、给对端发 RESET。
/// 必须在不使用 streams 借用的作用域里调用。
fn reset_stream(c: &mut ServerConn, id: StreamId, why: &str) {
    if let Some(st) = c.streams.get_mut(&id) {
        st.pending.clear();
        st.pending_bytes.store(0, std::sync::atomic::Ordering::Relaxed);
        // 配额被强制清零也要唤醒出站任务，否则它会一直卡在等待里直到 50ms 兜底
        st.write_blocked
            .store(false, std::sync::atomic::Ordering::Relaxed);
        // 标记放弃：出站读取协程看到它才不会再从目标 socket 读数据
        st.abandon.store(true, std::sync::atomic::Ordering::Relaxed);
        st.drain_notify.notify_waiters();
        st.target_buf.clear();
        st.to_tcp = None;
        st.local_finished = true;
        st.remote_finished = true;
    }
    // reset 会告诉对端不要再等这条流，从而释放它占用的连接级接收窗口。
    // 这是防止「已结束的流一直占满 20MB 窗口、拖死所有新请求」的关键。
    let _ = c.conn.send_stream(id).reset(0u32.into());
    let _ = c.conn.recv_stream(id).stop(0u32.into());
    tracing::warn!(stream = ?id, reason = why, "重置该流");
}

/// 把暂存数据写回 QUIC 流。
fn flush_pending(c: &mut ServerConn, id: StreamId) {
    let Some(st) = c.streams.get_mut(&id) else { return };
    let mut freed = false;
    while !st.pending.is_empty() {
        match c.conn.send_stream(id).write(&st.pending) {
            Ok(n) if n > 0 => {
                st.pending.drain(..n);
                // 已写出，归还背压配额，通知出站任务可以继续读目标
                st.pending_bytes
                    .fetch_sub(n, std::sync::atomic::Ordering::Relaxed);
                freed = true;
            }
            Ok(_) => break,
            Err(WriteError::Blocked) => break,
            Err(WriteError::Stopped(code)) => {
                // 对端已经丢弃这条流（发了 STOP_SENDING / RESET）：
                // 剩下的数据永远送不出去，必须丢掉，但要留日志。
                // 这是**正常路径**（浏览器取消下载、客户端请求超时退出），
                // 不是故障，所以用 debug 而不是 warn——否则正常使用就会刷屏，
                // 把真正的异常淹没掉。
                tracing::debug!(
                    stream = ?id,
                    code = %code,
                    dropped = st.pending.len(),
                    "对端已停止该流，丢弃待发数据"
                );
                st.pending.clear();
                st.pending_bytes.store(0, std::sync::atomic::Ordering::Relaxed);
                freed = true;
                break;
            }
            Err(WriteError::ClosedStream) => {
                // 流已经被关闭（reset/finish）：剩下的数据不可能再送出
                st.pending.clear();
                st.pending_bytes.store(0, std::sync::atomic::Ordering::Relaxed);
                freed = true;
                break;
            }
        }
    }
    // 归还了配额就唤醒出站任务：它可能正卡在 pending 水位上，
    // 事件驱动唤醒比 5ms 轮询快两个数量级，直接决定了拥塞时的吞吐。
    if freed {
        // pending 已经全部交给 quinn，说明发送缓冲的压力缓解了，
        // 清掉阻塞标志（否则出站任务会一直等到下一个 Writable 事件）。
        if st.pending.is_empty() {
            st.write_blocked
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }
        st.drain_notify.notify_waiters();
    }
    // 上游已 EOF 且这一次终于把残留数据全部写进 QUIC，才能发 FIN。
    // 否则 FIN 会越过还没写出的数据，客户端提前收到流结束
    // （实测 200MB 下载最后少掉约 1MB，正好是一个背压高水位）。
    // 先算好标志再结束借用，避免与 c.conn 同时可变借用。
    let ready_to_finish = st.fin_pending && st.pending.is_empty();
    if ready_to_finish {
        st.fin_pending = false;
    }
    if ready_to_finish {
        let _ = c.conn.send_stream(id).finish();
    }
}

/// 处理出站任务回传的动作。
fn handle_action(
    conns: &mut HashMap<ConnectionHandle, ServerConn>,
    action: ServerAction,
    pending_high_water: usize,
) {
    match action {
        ServerAction::Data(ch, id, data) => {
            let Some(c) = conns.get_mut(&ch) else { return };
            let overflow;
            {
                let Some(st) = c.streams.get_mut(&id) else { return };
                // 这批数据已经到达主循环，先从「在途」计数里剪掉。
                // pending_bytes 现在的语义是「从目标 socket 读出来、但还没交给 QUIC 的
                // 全部字节」，包含两段：还在 action 通道里排队的 + 已经落到 st.pending 的。
                // 少算前一段是背压失效的根因：通道容量 1024 × 16KB ≈ 16MB，
                // 出站任务可以比主循环领先 16MB，目标是本地回环服务（几百 MB/s）时
                // 很快就把 st.pending 顶过安全阈值，整条流被 reset。
                // 用 saturating 减法：reset_stream 会把计数器清零，
                // 此时队列里可能还有在途数据，直接 fetch_sub 会下溢成 usize::MAX，
                // 导致这条流的背压判断彻底失效。
                let _ = st
                    .pending_bytes
                    .fetch_update(
                        std::sync::atomic::Ordering::Relaxed,
                        std::sync::atomic::Ordering::Relaxed,
                        |v| Some(v.saturating_sub(data.len())),
                    );
                if st.local_finished {
                    return;
                }
                st.last_active = Instant::now();
                tracing::debug!(stream = ?id, bytes = data.len(), "目标数据写回 QUIC");
                if st.pending.is_empty() {
                    match c.conn.send_stream(id).write(&data) {
                        Ok(n) if n == data.len() => {
                            // 全部交给 quinn，未触顶，背压标志保持原样
                            st.write_blocked
                                .store(false, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                        Ok(n) => {
                            // 只写进去一部分：quinn 的发送缓冲快满了，
                            // 从此刻起必须让出站任务停下来，别再读目标 socket。
                            st.pending.extend_from_slice(&data[n..]);
                            st.pending_bytes.fetch_add(
                                data.len() - n,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            st.write_blocked
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                        Err(WriteError::Blocked) => {
                            st.pending.extend_from_slice(&data);
                            st.pending_bytes.fetch_add(
                                data.len(),
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            st.write_blocked
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                        Err(WriteError::Stopped(code)) => {
                            // 流已被对端丢弃：这批数据送不出去了
                            // 同上：对端主动放弃属于正常路径，用 debug
                            tracing::debug!(
                                stream = ?id,
                                code = %code,
                                dropped = data.len(),
                                "对端已停止该流，丢弃数据"
                            );
                            return;
                        }
                        Err(WriteError::ClosedStream) => return,
                    }
                } else {
                    st.pending.extend_from_slice(&data);
                    st.pending_bytes
                        .fetch_add(data.len(), std::sync::atomic::Ordering::Relaxed);
                }
                // 超过高水位的 8 倍才认为对端已彻底不读，继续堆只会在内存里越积越多。
                // 不能取 2 倍：一批动作最冬 64 × 16KB = 1MB 会一次性推进 pending，
                // 阈值太低会把正在正常下载的流误判成僵尸流。
                overflow = st.pending.len() > pending_high_water.saturating_mul(8);
            }
            if overflow {
                reset_stream(c, id, "pending 超过上限");
                return;
            }
            flush_pending(c, id);
        }
        ServerAction::Fin(ch, id) => {
            let Some(c) = conns.get_mut(&ch) else { return };
            {
                let Some(st) = c.streams.get_mut(&id) else { return };
                if st.local_finished {
                    return;
                }
                st.local_finished = true;
                // 只登记「待发 FIN」：上游 EOF 不代表数据已经写完，
                // 真正 finish() 由 flush_pending 在 pending 清空时执行。
                // 直接在这里 finish() 会让 FIN 越过残留数据，
                // 客户端提前看到流结束（末尾少约 1MB 的元凶）。
                st.fin_pending = true;
            }
            flush_pending(c, id);
        }
        ServerAction::Datagram(ch, pkt) => {
            let Some(c) = conns.get_mut(&ch) else {
                tracing::debug!("UDP 回程连接已失效，丢弃");
                return;
            };
            // drop=true：发送缓冲满就丢最旧的排队包。
            // UDP 没有重传，保住新包比留住旧包有意义（实时流的共识）。
            match c.conn.datagrams().send(pkt.into(), true) {
                Ok(()) => tracing::debug!(
                    client = %c.client,
                    "UDP 回程已交给 QUIC"
                ),
                // TooLarge 是常态：目标的 UDP 响应可能远大于 MTU，
                // 按 UDP 语义直接丢弃，不做应用层分片（与 hysteria2 一致）。
                Err(e) => tracing::debug!(
                    client = %c.client,
                    error = %e,
                    "服务端 datagram 发送失败，丢弃"
                ),
            }
        }
    }
}

/// 连接目标 TCP。
///
/// **不缓存任何东西**：每次请求都现解析，和改造前的语义完全一致。
///
/// 唯一的变化是「多个地址怎么试」。tokio 的 `TcpStream::connect(&addr)` 对解析出
/// 多个地址的域名是**顺序重试**的：头一个地址不可达就要等它自己超时
/// （内核 SYN 重传 3~21 秒）才会试下一个。
/// `www.gstatic.com` / `www.youtube.com` 实测解析出 16 个地址，
/// 只要头一个当时不通，这条请求就会卡几百毫秒到几秒。
/// 这里是改成**并发连所有地址、取最先成功的那个**（Happy Eyeballs 的思路），
/// 不涉及任何缓存或复用，只是不再排队等超时。
async fn connect_target(host: &str, port: u16) -> std::io::Result<(TcpStream, usize)> {
    /// 并发尝试的地址上限：再多只是白占 fd，对降低延迟没有帮助
    const MAX_PARALLEL: usize = 4;
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    // 已经是 IP 就直接连，跳过解析
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let t = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((ip, port)))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "连接目标超时")
            })??;
        return Ok((t, 1));
    }

    // 域名：现解析（不缓存），拿到全部地址
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| std::io::Error::new(e.kind(), format!("解析 {host} 失败: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{host} 没有可用地址"),
        ));
    }
    let n = addrs.len();

    // 单个地址：直接连，省掉 spawn 的开销
    if n == 1 {
        let t = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addrs[0]))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "连接目标超时")
            })??;
        return Ok((t, n));
    }

    // 多地址：并发连，谁先成功用谁。
    // JoinSet 在 drop 时会 abort 掉其余任务，所以没成功的连接会被立刻取消，
    // 不会泄漏 fd，也不会在后台继续做无用的 SYN 重传。
    let mut set = tokio::task::JoinSet::new();
    for a in addrs.iter().take(MAX_PARALLEL) {
        let a = *a;
        set.spawn(async move {
            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(a)).await
        });
    }
    let mut last_err: Option<std::io::Error> = None;
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Ok(Ok(t))) => return Ok((t, n)),
            Ok(Ok(Err(e))) => last_err = Some(e),
            Ok(Err(_)) => {
                last_err = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "连接目标超时",
                ))
            }
            Err(e) => {
                last_err = Some(std::io::Error::other(format!("连接任务失败: {e}")))
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::other("所有目标地址都连接失败")
    }))
}

/// 出站任务：连接目标，双向搬运数据。
async fn outbound(
    ch: ConnectionHandle,
    id: StreamId,
    host: String,
    port: u16,
    initial: Vec<u8>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    action_tx: mpsc::Sender<ServerAction>,
    pending_bytes: Arc<std::sync::atomic::AtomicUsize>,
    drain_notify: Arc<tokio::sync::Notify>,
    write_blocked: Arc<std::sync::atomic::AtomicBool>,
    abandon: Arc<std::sync::atomic::AtomicBool>,
    high_water: usize,
) {
    let addr = format!("{host}:{port}");
    let t_conn = Instant::now();
    let tcp = match connect_target(&host, port).await {
        Ok((t, naddr)) => {
            // 出站连接耗时是延迟抖动的主要来源之一，记在 debug 里方便排查。
            // 「隧道本身很快但某些站点慢」这类问题，第一件事就是看这里：
            // 域名解析（服务端做）+ 目标 TCP 握手都在这一段。
            tracing::debug!(
                %addr,
                connect_ms = t_conn.elapsed().as_millis() as u64,
                addrs = naddr,
                "出站连接完成"
            );
            t
        }
        Err(e) => {
            tracing::debug!(
                %addr,
                error = %e,
                connect_ms = t_conn.elapsed().as_millis() as u64,
                "出站连接失败"
            );
            let _ = action_tx.send(ServerAction::Fin(ch, id)).await;
            return;
        }
    };
    let _ = tcp.set_nodelay(true);
    let (mut r, mut w) = tcp.into_split();

    // 目标地址帧之后可能已经粘了请求数据，先写出去
    if !initial.is_empty() && w.write_all(&initial).await.is_err() {
        let _ = action_tx.send(ServerAction::Fin(ch, id)).await;
        return;
    }

    let at1 = action_tx.clone();
    let addr_reader = addr.clone();
    let notify = drain_notify.clone();
    let blocked = write_blocked.clone();
    let abandoned = abandon.clone();
    let reader = async move {
        let mut buf = [0u8; 16384];
        // 连续背压等待的轮数（最多 50ms 一轮），用于 30 秒超时
        let mut stalled = 0u32;
        loop {
            // 流已被放弃（客户端发了 STOP_SENDING / 我们主动 reset）：
            // 立即退出，不再从目标 socket 读任何数据。
            if abandoned.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            // 端到端背压，两个条件任一成立就停下：
            // 1) 我们自己暂存的 pending 超水位；
            // 2) quinn 的发送缓冲满了（write 返回 Blocked 或只写进一部分）。
            //    这一条之前没有，于是目标是本地回环时（几百 MB/s）会一口气
            //    把几 MB 数据吸进 quinn 的内部缓冲 + 我们的 pending，
            //    最后被「pending 超过上限」的保护当成僵尸流 reset，
            //    正在下载的连接直接断在 6~8MB。
            while pending_bytes.load(std::sync::atomic::Ordering::Relaxed) > high_water
                || blocked.load(std::sync::atomic::Ordering::Relaxed)
            {
                // 已被放弃：不必再等水位，直接退出
                if abandoned.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                // 先拿 notified() 再做一次检查，避免「检查后、await 前」
                // 刚好被写空导致丢失通知而白等 50ms。
                let wait = notify.notified();
                if pending_bytes.load(std::sync::atomic::Ordering::Relaxed) <= high_water
                    && !blocked.load(std::sync::atomic::Ordering::Relaxed)
                {
                    break;
                }
                // 50ms 只是兜底（对端彻底不 ACK 时不会有 Writable 事件）
                let _ = tokio::time::timeout(Duration::from_millis(50), wait).await;
                stalled += 1;
                if stalled > 600 {
                    tracing::warn!(addr = %addr_reader, "背压等待超过 30 秒，放弃该流");
                    let _ = at1.send(ServerAction::Fin(ch, id)).await;
                    return;
                }
            }
            stalled = 0;
            match r.read(&mut buf).await {
                Ok(0) => {
                    // 目标发完了：发 Fin，再等队列空位（下面 send 会阻塞）
                    let _ = at1.send(ServerAction::Fin(ch, id)).await;
                    break;
                }
                Ok(n) => {
                    tracing::debug!(addr = %addr_reader, bytes = n, "目标返回数据");
                    // 送进队列之前先计入背压水位（含通道在途部分），
                    // 主循环 handle_action 会把这笔账转录成 st.pending 的占用。
                    pending_bytes.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                    // 阻塞发送：QUIC 写得慢时在这里挂住，不再读目标 socket，
                    // 于是目标 TCP 窗口收缩、发送降速——这就是背压。
                    if at1
                        .send(ServerAction::Data(ch, id, buf[..n].to_vec()))
                        .await
                        .is_err()
                    {
                        // 主循环已不在（连接/流结束）：把刚计入的在途量退回，
                        // 避免它残留在计数器里影响后续判断
                        pending_bytes.fetch_sub(n, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                }
                Err(_) => {
                    let _ = at1.send(ServerAction::Fin(ch, id)).await;
                    break;
                }
            }
        }
    };
    let writer = async move {
        while let Some(d) = rx.recv().await {
            if d.is_empty() {
                let _ = w.shutdown().await;
                break;
            }
            tracing::debug!(%addr, bytes = d.len(), "写入目标 TCP");
            if w.write_all(&d).await.is_err() {
                break;
            }
        }
    };
    // 两个方向必须各跑各的：用 select! 会在任一方向结束时把另一方向直接 drop，
    // 导致「客户端半关闭后目标数据没读完」就发 FIN，下载表现为几十 KB 就断。
    // hysteria/quic-go 用两个独立 io.Copy，任一方真正 EOF 才结束，这里用 join! 对齐。
    tokio::join!(reader, writer);
}

/// QUIC 定时器驱动。
/// deadline 在未来时精确睡到该时刻；已过期或为 None 时按最小 5ms 间隔重试。
async fn tick(deadline: Option<tokio::time::Instant>) {
    let now = tokio::time::Instant::now();
    match deadline {
        Some(d) if d > now => tokio::time::sleep_until(d).await,
        _ => tokio::time::sleep(Duration::from_millis(5)).await,
    }
}
