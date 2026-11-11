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
    ServerConfig, StreamEvent, StreamId, WriteError,
};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::config::{parse_listen, ServerFile};
use crate::faketcp::codec::{build_server_hello, parse_records, Obfs, REC_APPDATA};
use crate::faketcp::packet::{build_packet, build_packet_opts, parse_frame, SYN_OPTIONS, TCP_ACK, TCP_PSH, TCP_SYN};
use crate::faketcp::socket::RawSocket;
use crate::proxy::decode_target;

/// 出站任务发回事件循环的动作
enum ServerAction {
    Data(ConnectionHandle, StreamId, Vec<u8>),
    Fin(ConnectionHandle, StreamId),
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
    /// 最后一次读写时间，用于 5 分钟空闲超时清理僵尸流。
    last_active: Instant,
}

impl Default for ServerStream {
    fn default() -> Self {
        Self {
            to_tcp: None,
            pending: Vec::new(),
            pending_bytes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            target_buf: Vec::new(),
            target_ready: false,
            local_finished: false,
            remote_finished: false,
            stopped: false,
            last_active: Instant::now(),
        }
    }
}

/// 服务端单条 QUIC 连接
struct ServerConn {
    conn: Connection,
    ch: ConnectionHandle,
    /// 客户端的真实地址（NAT 后的）
    client: SocketAddr,
    /// 本机接收该连接时使用的目标 IP，回包时作为源 IP
    local_ip: std::net::Ipv4Addr,
    /// 发往客户端时的序列号
    seq: u32,
    /// 最近一次收到客户端的序列号
    peer_seq: u32,
    /// 当前 IP ID：真实流量递增，固定值容易被 DPI 标记
    ip_id: u16,
    streams: HashMap<StreamId, ServerStream>,
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
    let (pkt_tx, mut pkt_rx) = mpsc::channel::<(u32, SocketAddr, std::net::Ipv4Addr, u16, u8, Option<u8>, Vec<u8>)>(8192);
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
    // 背压高水位：默认为窗口上限的 2 倍。
    // 千兆（8MB）→ 16MB；30Mbps 链路（1MB）→ 2MB。
    // 出站任务看到 pending 超过这个值就暂停读目标 socket，让目标 TCP 窗口收缩。
    let pending_high_water = ((cfg.net.max_cwnd as usize).saturating_mul(2)).max(512 * 1024);
    let mut endpoint = Endpoint::new(
        Arc::new(EndpointConfig::default()),
        Some(server_quic.clone()),
        false,
        None,
    );
    let obfs = Obfs::new(&cfg.password);
    let magic = cfg.faketcp.ip_id_magic;
    let mut conns: HashMap<ConnectionHandle, ServerConn> = HashMap::new();
    // 记录每个客户端 SYN 的 ISN，以及我们回复的 SYN-ACK ISN。
    // 标准握手要求：收到 SYN 就立即回 SYN-ACK，客户端回 ACK 后才会发数据。
    let mut syn_seqs: HashMap<SocketAddr, u32> = HashMap::new();
    let mut syn_isns: HashMap<SocketAddr, u32> = HashMap::new();
    // 有界动作队列：按 quic-go 的「阻塞写」模型做背压。
    // 目标读到数据后要等队列有空位才能继续读，队列满 → 目标 TCP 接收缓冲满
    // → 目标发送变慢。这样下行数据不会在 pending 里无限堆积。
    // 2048 项 ≈ 32MB：70Mbps 下约 3.7 秒缓冲，
    // 256 项（4MB）只有 0.46 秒，主循环稍一抖动就会误触发背压降速。
    let (action_tx, mut action_rx) = mpsc::channel::<ServerAction>(2048);
    let mut last_stats = Instant::now();

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
            let upper = safe_cap.clamp(1536 * 1024, 8 * 1024 * 1024);
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
                let mut batch: Vec<(u32, SocketAddr, std::net::Ipv4Addr, u16, u8, Option<u8>, Vec<u8>)> =
                    Vec::with_capacity(256);
                batch.push(first);
                while batch.len() < 256 {
                    match pkt_rx.try_recv() {
                        Ok(p) => batch.push(p),
                        Err(_) => break,
                    }
                }
                for (seq, client, dst_ip, ip_id, flags, wscale, payload) in batch {
                    handle_packet(
                        &mut endpoint,
                        &server_quic,
                        &mut conns,
                        &mut syn_seqs,
                        &mut syn_isns,
                        &raw,
                        dst_ip,
                        port,
                        magic,
                        &obfs,
                        seq,
                        client,
                        ip_id,
                        flags,
                        wscale,
                        &payload,
                        &action_tx,
                    );
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
                // 同样批量消化：上传大流量时目标回写动作会集中爆发
                let mut actions: Vec<ServerAction> = Vec::with_capacity(256);
                actions.push(first);
                while actions.len() < 256 {
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
            drain_transmits(c, &raw, port, magic, &obfs);
            drain_events(c, &action_tx, pending_high_water);
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
        }
        // 连接完全关闭后清理
        conns.retain(|_, c| !c.conn.is_drained());
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
    syn_seqs: &mut HashMap<SocketAddr, u32>,
    syn_isns: &mut HashMap<SocketAddr, u32>,
    raw: &Arc<RawSocket>,
    local_ip: std::net::Ipv4Addr,
    port: u16,
    magic: u16,
    obfs: &Obfs,
    seq: u32,
    client: SocketAddr,
    ip_id: u16,
    flags: u8,
    wscale: Option<u8>,
    payload: &[u8],
    action_tx: &mpsc::Sender<ServerAction>,
) {
    // 纯 SYN：标准握手第一步，立即回 SYN-ACK。
    // 严格 NAT/状态防火墙只放行 SYN-ACK 之后的数据包，不回 SYN-ACK 的话
    // 客户端后续的 ClientHello 和 QUIC Initial 会被直接丢弃。
    // 识别用 TCP 选项里的 wscale=12，不再用 IP ID：
    // 实测客户端的 NAT 会把 IP ID 改写成 0x0000，魔数判断完全失效。
    // 正常浏览器/扫描器的 SYN 的 wscale 是 8~9，不会误伤。
    if wscale == Some(12) && flags & TCP_SYN != 0 && payload.is_empty() {
        let isn: u32 = rand::thread_rng().gen();
        syn_seqs.insert(client, seq);
        syn_isns.insert(client, isn);
        if let std::net::IpAddr::V4(dst_ip) = client.ip() {
            let synack = build_packet_opts(
                local_ip,
                dst_ip,
                port,
                client.port(),
                isn,
                seq.wrapping_add(1),
                TCP_SYN | TCP_ACK,
                magic & 0xFF00,
                SYN_OPTIONS,
                &[],
            );
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
    // 遍历 TLS 记录：0x16 是表演握手，0x17 才是真实数据
    for rec in parse_records(payload) {
        if rec.typ != REC_APPDATA {
            continue;
        }
        let Some(plain) = obfs.open(rec.payload) else {
            // 解密失败：不是我们的客户端，静默丢弃
            tracing::warn!(%client, len = rec.payload.len(), "外层 AEAD 解密失败");
            continue;
        };
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
                }
                match endpoint.accept(incoming, now, &mut buf, Some(server_cfg.clone())) {
                    Ok((ch, conn)) => {
                        // 用客户端 SYN 的 ISN 回 SYN-ACK，再把伪 ServerHello 按连续 seq 发出。
                        // 标准握手模式下 SYN-ACK 已经在收到 SYN 时发过，这里只补 ServerHello，
                        // 复用当时的 ISN，保证客户端看到的序列号完全连续。
                        let peer_isn = syn_seqs.get(&client).copied().unwrap_or(0);
                        let (isn, synack_sent) = match syn_isns.get(&client).copied() {
                            Some(v) => (v, true),
                            None => (rand::thread_rng().gen(), false),
                        };
                        if let std::net::IpAddr::V4(dst_ip) = client.ip() {
                            // 兼容没走标准握手的旧客户端：没记录过 ISN 就补发 SYN-ACK
                            if !synack_sent {
                                let synack = build_packet_opts(
                                    local_ip, dst_ip, port, client.port(), isn,
                                    peer_isn.wrapping_add(1), TCP_SYN | TCP_ACK,
                                    magic & 0xFF00, SYN_OPTIONS, &[],
                                );
                                let _ = raw.send(&synack, dst_ip);
                            }
                            let hello = build_server_hello();
                            let hello_pkt = build_packet(
                                local_ip, dst_ip, port, client.port(), isn.wrapping_add(1),
                                peer_isn.wrapping_add(1), TCP_PSH | TCP_ACK,
                                (magic & 0xFF00) | 1, &hello,
                            );
                            let _ = raw.send(&hello_pkt, dst_ip);
                            tracing::debug!(%client, %peer_isn, "已发送 ServerHello");
                        }
                        // 握手状态只用于建连，清理掉避免泄漏
                        syn_seqs.remove(&client);
                        syn_isns.remove(&client);
                        let data_seq = isn
                            .wrapping_add(1)
                            .wrapping_add(build_server_hello().len() as u32);
                        conns.insert(
                            ch,
                            ServerConn {
                                conn,
                                ch,
                                client,
                                local_ip,
                                seq: data_seq,
                                peer_seq: peer_isn.wrapping_add(1),
                                ip_id: (magic & 0xFF00) | 2,
                                streams: HashMap::new(),
                            },
                        );
                        tracing::info!(%client, "新的 QUIC 连接");
                    }
                    Err(e) => tracing::debug!(%client, ?e, "accept 失败"),
                }
            }
            Some(DatagramEvent::ConnectionEvent(ch, ev)) => {
                if let Some(c) = conns.get_mut(&ch) {
                    // ack 只增不减：乱序时回退的 ack 会被中间设备当成非法包
                    let next = seq.wrapping_add(payload.len() as u32);
                    if next.wrapping_sub(c.peer_seq) < 0x8000_0000 {
                        c.peer_seq = next;
                    }
                    c.conn.handle_event(ev);
                }
            }
            Some(DatagramEvent::Response(t)) => {
                // endpoint 直接产生响应（如 Retry / stateless reset）
                if let Some(found) = find_by_client(conns, client) {
                    if let Some(c) = conns.get_mut(&found) {
                        c.send_datagram(raw, port, magic, obfs, &buf[..t.size]);
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
fn find_by_client(
    conns: &HashMap<ConnectionHandle, ServerConn>,
    client: SocketAddr,
) -> Option<ConnectionHandle> {
    conns
        .iter()
        .find(|(_, c)| c.client == client)
        .map(|(ch, _)| *ch)
        .or_else(|| conns.keys().next().copied())
}

/// 处理表演性质的 SYN：回 SYN-ACK + 伪 ServerHello。
/// 返回值仅用于日志。
fn handle_perfunctory_syn(
    raw: &Arc<RawSocket>,
    local_ip: std::net::Ipv4Addr,
    port: u16,
    magic: u16,
    peer_seq: u32,
    client: SocketAddr,
    ip_id: u16,
    flags: u8,
    payload: &[u8],
) -> Option<u32> {
    // 三重条件：IP ID 必须是我们约定的魔数、flags 含 SYN、零载荷。
    // 缺一不可，否则会干扰正常的 TCP 网站连接。
    if ip_id != magic || flags & TCP_SYN == 0 || !payload.is_empty() {
        return None;
    }
    let isn: u32 = rand::thread_rng().gen();
    // SYN-ACK：ack = 对端 seq + 1
    let synack = build_packet(
        local_ip,
        match client.ip() {
            std::net::IpAddr::V4(v4) => v4,
            _ => return None,
        },
        port,
        client.port(),
        isn,
        peer_seq.wrapping_add(1),
        TCP_SYN | TCP_ACK,
        magic,
        &[],
    );
    let _ = raw.send(&synack, match client.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => return None,
    });

    // 紧跟一个伪 ServerHello，完成「表演握手」的观感
    let hello = build_server_hello();
    let pkt = build_packet(
        local_ip,
        match client.ip() {
            std::net::IpAddr::V4(v4) => v4,
            _ => return None,
        },
        port,
        client.port(),
        isn.wrapping_add(1),
        peer_seq.wrapping_add(1),
        TCP_PSH | TCP_ACK,
        magic,
        &hello,
    );
    let _ = raw.send(&pkt, match client.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => return None,
    });
    Some(peer_seq)
}

impl ServerConn {
    /// 把一个 QUIC 数据报封装成 TLS 记录 + TCP 包发给客户端。
    fn send_datagram(
        &mut self,
        raw: &Arc<RawSocket>,
        port: u16,
        magic: u16,
        obfs: &Obfs,
        payload: &[u8],
    ) {
        let record = obfs.seal(payload);
        let dst_ip = match self.client.ip() {
            std::net::IpAddr::V4(v4) => v4,
            _ => return,
        };
        let pkt = build_packet(
            self.local_ip,
            dst_ip,
            port,
            self.client.port(),
            self.seq,
            self.peer_seq,
            TCP_PSH | TCP_ACK,
            self.ip_id,
            &record,
        );
        if let Err(e) = raw.send(&pkt, dst_ip) {
            tracing::warn!(error = %e, "发送失败");
        }
        self.seq = self.seq.wrapping_add(record.len() as u32);
        // IP ID 在 magic 高字节内递增
        let base = self.ip_id & 0xFF00;
        self.ip_id = base | ((self.ip_id.wrapping_add(1)) & 0x00FF);
    }
}

/// 排空一条连接的待发 QUIC 包。
fn drain_transmits(
    c: &mut ServerConn,
    raw: &Arc<RawSocket>,
    port: u16,
    magic: u16,
    obfs: &Obfs,
) {
    let mut buf = Vec::with_capacity(2048);
    let mut sent = 0;
    loop {
        // poll_transmit 是追加写入，必须先清空，否则缓冲区无限膨胀
        buf.clear();
        let Some(t) = c.conn.poll_transmit(Instant::now(), 1, &mut buf) else {
            break;
        };
        c.send_datagram(raw, port, magic, obfs, &buf[..t.size]);
        sent += 1;
        // 每轮最多 64 个包，避免长时间占住事件循环导致 ACK 积压
        if sent >= 64 {
            break;
        }
    }
}

/// 处理一条 QUIC 连接上的事件。
fn drain_events(
    c: &mut ServerConn,
    action_tx: &mpsc::Sender<ServerAction>,
    pending_high_water: usize,
) {
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
    // 出站缓冲打满 / 接收流已卡死时必须停流：标记后再动 conn，避免借用冲突
    let mut need_stop = false;
    let mut stop_recv = false;
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
            Err(_) => {
                // 流已进入不可恢复状态（组装器被锁定）。
                // 继续跳过只会让这条流的接收窗口永不释放，上行数据堆成几十 MB pending。
                // 直接 stop 释放流控额度，让客户端该请求失败重试。
                stop_recv = true;
            }
        };
    }
    if stop_recv {
        st.stopped = true;
        st.remote_finished = true;
        st.to_tcp = None;
        let _ = c.conn.recv_stream(id).stop(0u32.into());
        tracing::warn!(stream = ?id, "接收流已卡死，停止并释放窗口");
        return;
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

/// 彻底抛弃一条流：清空 pending、断开与出站任务的联系、给对端发 RESET。
/// 必须在不使用 streams 借用的作用域里调用。
fn reset_stream(c: &mut ServerConn, id: StreamId, why: &str) {
    if let Some(st) = c.streams.get_mut(&id) {
        st.pending.clear();
        st.pending_bytes.store(0, std::sync::atomic::Ordering::Relaxed);
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
    while !st.pending.is_empty() {
        match c.conn.send_stream(id).write(&st.pending) {
            Ok(n) if n > 0 => {
                st.pending.drain(..n);
                // 已写出，归还背压配额，通知出站任务可以继续读目标
                st.pending_bytes
                    .fetch_sub(n, std::sync::atomic::Ordering::Relaxed);
            }
            Ok(_) => break,
            Err(WriteError::Blocked) => break,
            Err(_) => {
                st.pending.clear();
                st.pending_bytes.store(0, std::sync::atomic::Ordering::Relaxed);
                break;
            }
        }
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
                if st.local_finished {
                    return;
                }
                st.last_active = Instant::now();
                tracing::debug!(stream = ?id, bytes = data.len(), "目标数据写回 QUIC");
                if st.pending.is_empty() {
                    match c.conn.send_stream(id).write(&data) {
                        Ok(n) if n == data.len() => return,
                        Ok(n) => {
                            st.pending.extend_from_slice(&data[n..]);
                            st.pending_bytes.fetch_add(
                                data.len() - n,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                        }
                        Err(WriteError::Blocked) => {
                            st.pending.extend_from_slice(&data);
                            st.pending_bytes.fetch_add(
                                data.len(),
                                std::sync::atomic::Ordering::Relaxed,
                            );
                        }
                        Err(_) => return,
                    }
                } else {
                    st.pending.extend_from_slice(&data);
                    st.pending_bytes
                        .fetch_add(data.len(), std::sync::atomic::Ordering::Relaxed);
                }
                // 超过高水位 2 倍说明对端已经彻底不读，继续堆只会在内存里越积越多
                overflow = st.pending.len() > pending_high_water.saturating_mul(2);
            }
            if overflow {
                reset_stream(c, id, "pending 超过上限");
                return;
            }
            flush_pending(c, id);
        }
        ServerAction::Fin(ch, id) => {
            let Some(c) = conns.get_mut(&ch) else { return };
            let Some(st) = c.streams.get_mut(&id) else { return };
            if st.local_finished {
                return;
            }
            st.local_finished = true;
            flush_pending(c, id);
            let _ = c.conn.send_stream(id).finish();
        }
    }
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
    high_water: usize,
) {
    let addr = format!("{host}:{port}");
    let tcp = match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            tracing::debug!(%addr, error = %e, "出站连接失败");
            let _ = action_tx.send(ServerAction::Fin(ch, id)).await;
            return;
        }
        Err(_) => {
            tracing::debug!(%addr, "出站连接超时");
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
    let reader = async move {
        let mut buf = [0u8; 16384];
        // 连续背压等待的轮数（5ms 一轮），用于 30 秒超时
        let mut stalled = 0u32;
        loop {
            // 端到端背压：pending 超过高水位就暂停读目标 socket。
            // 目标 TCP 接收缓冲随之堆满，发送方降速，于是 QUIC 发不出去的速度
            // 会反向传导给目标，而不是全部堆在服务端内存里。
            // quic-go 靠阻塞式 Stream.Write 自动实现，quinn-proto 的同步 write
            // 必须显式做，这是两者最关键的区别。
            while pending_bytes.load(std::sync::atomic::Ordering::Relaxed) > high_water {
                tokio::time::sleep(Duration::from_millis(5)).await;
                stalled += 1;
                if stalled > 6000 {
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
                    // 阻塞发送：QUIC 写得慢时在这里挂住，不再读目标 socket，
                    // 于是目标 TCP 窗口收缩、发送降速——这就是背压。
                    if at1
                        .send(ServerAction::Data(ch, id, buf[..n].to_vec()))
                        .await
                        .is_err()
                    {
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
