//! 客户端主流程：本地代理入口 → QUIC → FakeTCP → 服务端。
//!
//! 事件循环是单线程的：quinn-proto 是同步状态机，所有连接/流操作都在
//! 同一个循环里完成，避免跨线程共享 Connection 带来的锁竞争。

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use bytes::BytesMut;
use quinn_proto::{
    ConnectionHandle, Dir, Endpoint, EndpointConfig, Event, ReadError, StreamEvent, StreamId,
    WriteError,
};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

use crate::config::{parse_host_port, ClientFile};
use crate::faketcp::codec::{build_client_hello, parse_records, Obfs, REC_APPDATA};
use crate::faketcp::packet::{build_packet, build_packet_opts, parse_frame, SYN_OPTIONS, TCP_ACK, TCP_PSH, TCP_SYN};
use crate::faketcp::socket::RawSocket;
use crate::proxy::{self, ProxyAction};

/// 本地代理任务持有的句柄，用来向事件循环发动作。
#[derive(Clone)]
pub struct ProxyClient {
    /// 内部动作通道。用 Mutex<Option<..>> 而不是直接持有 Sender，
    /// 是因为断线重连时主循环会重建通道，而本地代理入口只启动一次。
    tx: Arc<std::sync::Mutex<Option<mpsc::UnboundedSender<ProxyAction>>>>,
}

impl ProxyClient {
    /// 新建一个未绑定的客户端（重连后由主循环调用 set_tx 绑定）。
    fn new() -> Self {
        Self {
            tx: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// 绑定本次连接的动作通道。旧通道被丢弃，旧连接上的请求随之失效。
    fn set_tx(&self, tx: mpsc::UnboundedSender<ProxyAction>) {
        if let Ok(mut guard) = self.tx.lock() {
            *guard = Some(tx);
        }
    }

    /// 取出当前通道的克隆；未绑定（重连间隙）时返回 None。
    fn sender(&self) -> Option<mpsc::UnboundedSender<ProxyAction>> {
        self.tx.lock().ok().and_then(|g| g.clone())
    }

    /// 打开一条 QUIC 流，返回流 ID 和下行数据通道。
    pub async fn open(
        &self,
        target: Vec<u8>,
    ) -> Option<(StreamId, mpsc::UnboundedReceiver<Vec<u8>>)> {
        // 先克隆出 Sender，避免 std Mutex 的 guard 跨 await
        let tx = self.sender()?;
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(ProxyAction::Open { target, reply: reply_tx }).ok()?;
        reply_rx.await.ok().flatten()
    }

    /// 本地 → 远端
    pub fn send(&self, id: StreamId, data: Vec<u8>) {
        if let Some(tx) = self.sender() {
            let _ = tx.send(ProxyAction::Data(id, data));
        }
    }

    /// 本地方向结束
    pub fn fin(&self, id: StreamId) {
        if let Some(tx) = self.sender() {
            let _ = tx.send(ProxyAction::Fin(id));
        }
    }
}

/// 单条流的状态
struct StreamState {
    /// 发往本地任务的数据通道；发送空 Vec 表示远端已关闭
    to_local: mpsc::UnboundedSender<Vec<u8>>,
    /// 因为流控窗口阻塞而暂存的待发数据
    pending: Vec<u8>,
    /// 本地是否已经发过 FIN
    local_finished: bool,
    /// 远端是否已经关闭
    remote_finished: bool,
    /// 已因读取错误被 stop。置位后忽略该流的后续 Readable 事件，
    /// 否则 quinn 会持续投递 Readable，每次都重新 read/失败/stop 空转。
    stopped: bool,
    /// 最后一次读写时间。用于清理「双方都没发 FIN、但已经长时间无数据」的僵尸流。
    last_active: Instant,
}

/// 发送上下文：FakeTCP 需要的所有参数
struct SendCtx {
    raw: Arc<RawSocket>,
    server_ip: Ipv4Addr,
    server_port: u16,
    source_port: u16,
    magic: u16,
    local_ip: Ipv4Addr,
    obfs: Obfs,
    /// 当前发送序列号
    seq: u32,
    /// 最近一次收到的对端序列号
    peer_seq: u32,
    /// 当前 IP ID：真实流量 IP ID 递增，固定值容易被 DPI 标记。
    /// 高 8 位固定为 magic 的高字节（供 iptables 分流），低 8 位递增。
    ip_id: u16,
}

impl SendCtx {
    /// 把一个 QUIC 数据报封装成 TLS 记录 + TCP 包并发出。
    fn send_datagram(&mut self, payload: &[u8]) {
        let record = self.obfs.seal(payload);
        let pkt = build_packet(
            self.local_ip,
            self.server_ip,
            self.source_port,
            self.server_port,
            self.seq,
            self.peer_seq,
            TCP_PSH | TCP_ACK,
            self.ip_id,
            &record,
        );
        if let Err(e) = self.raw.send(&pkt, self.server_ip) {
            tracing::warn!(error = %e, "发送失败");
        } else {
            tracing::debug!(src_port = self.source_port, dst_port = self.server_port, len = pkt.len(), "raw 包已发出");
        }
        // TCP 语义上序列号要按载荷长度推进，让中间盒看起来正常
        self.seq = self.seq.wrapping_add(record.len() as u32);
        // IP ID 在 magic 高字节内递增，避免固定值被识别
        let base = self.ip_id & 0xFF00;
        self.ip_id = base | ((self.ip_id.wrapping_add(1)) & 0x00FF);
    }
}

/// 客户端入口。
pub async fn run(cfg: ClientFile) -> Result<()> {
    let (host, server_port) = parse_host_port(&cfg.server)?;
    // 解析服务端 IP：只取第一个 IPv4，FakeTCP 目前只支持 IPv4
    let server_ip = resolve_ipv4(&host).await?;
    let sni = cfg.effective_sni();

    let raw = Arc::new(RawSocket::new(server_ip)?);
    let local_ip = raw.local_ip;
    tracing::info!(%server_ip, %server_port, %local_ip, "FakeTCP 通道已就绪");

    // 客户端规则：屏蔽内核对伪造连接回包产生的 RST。
    // 不装也不会影响 raw 收发，但避免 NAT/内核噪音。
    if cfg.net.mode == "auto" {
        if let Err(e) = crate::rules::ensure_client(
            cfg.faketcp.source_port,
            server_port,
            cfg.faketcp.ip_id_magic,
        ) {
            tracing::warn!(error = %e, "客户端 iptables 规则写入失败，不影响 raw 收发但可能有内核 RST 噪音");
        } else {
            tracing::info!(port = cfg.faketcp.source_port, "客户端 iptables 规则已就绪");
        }
    }

    // 收包线程：AF_PACKET 是阻塞接口，放到独立线程，通过 channel 送进异步循环。
    // 用有界 channel：下行大流量时最多积压 8192 个包，超过后收包线程阻塞，
    // 由内核 socket 缓冲区兜底丢包（QUIC 会重传），避免 unbounded 把内存吃光。
    let (pkt_tx, mut pkt_rx) = mpsc::channel::<(u32, u8, Vec<u8>)>(8192);
    let raw_recv = raw.clone();
    let expect_src_port = server_port;
    let expect_dst_port = cfg.faketcp.source_port;
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        loop {
            match raw_recv.recv(&mut buf) {
                Ok(n) => {
                    // 先做端口过滤，避免把无关流量送进异步循环
                    if let Some(p) = parse_frame(&buf[..n]) {
                        if p.src_port == expect_src_port
                            && p.dst_port == expect_dst_port
                            && p.src == server_ip
                        {
                            // 连同 seq 和 flags 一起送出：SYN-ACK 需要单独回 ACK 完成三次握手
                            if pkt_tx.blocking_send((p.seq, p.flags, p.payload.to_vec())).is_err() {
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "raw recv 失败");
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
    });

    // ---- 本地代理入口（只启动一次，重连不重建）----
    let proxy_client = ProxyClient::new();
    spawn_inbounds(&cfg, proxy_client.clone()).await?;

    // ---- 连接循环：断线后指数退避自动恢复 ----
    // 用户不需要手动重启：服务端重启、链路中断、QUIC 内部错误（如空洞超限）都能自愈。
    let mut backoff = 5u64;
    loop {
        // 清掉上个连接残留的包，避免旧序列号干扰新握手
        while pkt_rx.try_recv().is_ok() {}

        match run_session(
            &cfg,
            &raw,
            local_ip,
            server_ip,
            server_port,
            &sni,
            &mut pkt_rx,
            &proxy_client,
        )
        .await
        {
            Ok(()) => tracing::info!("连接结束，准备重连"),
            Err(e) => tracing::warn!(error = %e, "连接异常，准备重连"),
        }

        // 指数退避：5s → 10s → 20s → 40s → 60s 封顶，避免频繁发包触发链路风控
        tracing::warn!(backoff_secs = backoff, "等待后重连");
        tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(60);
    }
}

/// 单次连接会话：建 QUIC 连接、走标准握手、跑事件循环，直到断开。
/// 断线返回 Ok(())，由外层退避重连。
async fn run_session(
    cfg: &ClientFile,
    raw: &Arc<RawSocket>,
    local_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    server_port: u16,
    sni: &str,
    pkt_rx: &mut mpsc::Receiver<(u32, u8, Vec<u8>)>,
    proxy_client: &ProxyClient,
) -> Result<()> {
    let mut endpoint = Endpoint::new(Arc::new(EndpointConfig::default()), None, false, None);
    let server_addr = SocketAddr::new(server_ip.into(), server_port);
    // 拥塞窗口上限：共享原子值，主循环每 2 秒根据实测丢包率自适应调整。
    // 用户不需要填带宽：丢包高自动收敛，链路变好自动探高。
    let max_cwnd = Arc::new(std::sync::atomic::AtomicU64::new(cfg.net.max_cwnd));
    let mut last_sent = 0u64;
    let mut last_lost = 0u64;
    let (ch, mut conn) = endpoint
        .connect(
            Instant::now(),
            crate::quic::config::client_config(max_cwnd.clone()),
            server_addr,
            "flowtls",
        )
        .context("QUIC connect 失败")?;

    let mut ctx = SendCtx {
        raw: raw.clone(),
        server_ip,
        server_port,
        source_port: cfg.faketcp.source_port,
        magic: cfg.faketcp.ip_id_magic,
        local_ip,
        obfs: Obfs::new(&cfg.password),
        seq: 0,
        peer_seq: 0,
        ip_id: cfg.faketcp.ip_id_magic & 0xFF00,
    };

    // 随机初始序列号，SYN 占 1 个序号
    let isn: u32 = rand::thread_rng().gen();
    ctx.seq = isn.wrapping_add(1);

    // ---- 标准三次握手：先只发 SYN ----
    // 严格 NAT/状态防火墙只放行「SYN → SYN-ACK → ACK」之后的数据包，
    // 旧版「SYN + 数据同批发」会被直接丢弃（实测江苏移动新网关）。
    // 代价是多 1 个 RTT（约 70ms），但兼容性从「看网关脸色」变成通用。
    let hello = build_client_hello(sni);
    let mut pending_hello = Some(hello);
    if cfg.faketcp.handshake != "none" {
        // 裸 SYN，带 MSS/SACK/窗口缩放选项（12 字节），外观和真实握手一致。
        // 窗口缩放让中间设备按 8MB 而不是 64KB 校验在途数据。
        let syn = build_packet_opts(
            local_ip,
            server_ip,
            cfg.faketcp.source_port,
            server_port,
            isn,
            0,
            TCP_SYN,
            cfg.faketcp.ip_id_magic & 0xFF00,
            SYN_OPTIONS,
            &[],
        );
        let _ = raw.send(&syn, server_ip);
        tracing::info!("已发送 SYN，等待 SYN-ACK");
    } else {
        // handshake=none（客户端有公网 IP）时不需要表演握手，直接发数据
        pending_hello = None;
    }

    // 本次连接的本地动作通道，绑定给常驻的代理入口
    let (action_tx, mut action_rx) = mpsc::unbounded_channel::<ProxyAction>();
    proxy_client.set_tx(action_tx);

    // ---- 流表 ----
    let mut streams: HashMap<StreamId, StreamState> = HashMap::new();
    let mut connected_logged = false;
    // 是否还在等 SYN-ACK。等待期间不发送任何 QUIC 数据，
    // 否则严格 NAT 会把「握手完成前的数据包」当成非法丢弃。
    let mut awaiting_syn_ack = cfg.faketcp.handshake != "none";
    let mut last_stats = Instant::now();

    loop {
        // 每 2 秒打印一次 QUIC 路径统计，方便定位吞吐问题
        if last_stats.elapsed() >= std::time::Duration::from_secs(2) {
            let s = conn.stats();
            // streams/pending/rx_queue 是排查卡顿的三大关键：
            // pending 不降说明 QUIC 发不出去，rx_queue 不降说明事件循环处理不过来。
            let pending: usize = streams.values().map(|x| x.pending.len()).sum();
            // ---- 自适应窗口 ----
            // 用本采样周期的丢包率决定窗口升降。
            // 阈值放宽到 20%/5%、步长 0.9/1.2：之前 15%/0.85 太激进，
            // 正常链路抖动就会把窗口压到 1~2MB，测速时上下行都跑不满。
            // 崩了还有外层自动重连兜底。
            let d_sent = s.path.sent_packets.saturating_sub(last_sent);
            let d_lost = s.path.lost_packets.saturating_sub(last_lost);
            let loss = if d_sent > 0 {
                d_lost as f64 / d_sent as f64
            } else {
                0.0
            };
            last_sent = s.path.sent_packets;
            last_lost = s.path.lost_packets;
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
            tracing::info!(
                rtt_ms = s.path.rtt.as_millis() as u64,
                cwnd = s.path.cwnd,
                sent = s.path.sent_packets,
                lost = s.path.lost_packets,
                mtu = s.path.current_mtu,
                streams = streams.len(),
                pending,
                rx_queue = pkt_rx.len(),
                loss_pct = (loss * 100.0) as u64,
                win_cap = next,
                "QUIC 路径统计"
            );
            last_stats = Instant::now();
        }
        // 用固定 5ms tick 驱动 QUIC 定时器：quinn 的 poll_timeout 在
        // 某些状态下会返回已经过去的时刻，直接 sleep_until 会变成忙循环。
        // 5ms 对 RTT 级别定时器足够，后续可改成"下次到期时间 + 最小间隔"。
        let deadline = conn.poll_timeout().map(tokio::time::Instant::from_std);
        tokio::select! {
            // 1. 收到服务端的数据包
            maybe = pkt_rx.recv() => {
                let Some(first) = maybe else { break };
                // 批量处理：把队列里已经到达的包一起消化，每轮最多 256 个。
                // 单包一轮在高包速率下会造成 ACK 积压，拖垮整条连接。
                let mut batch: Vec<(u32, u8, Vec<u8>)> = Vec::with_capacity(256);
                batch.push(first);
                while batch.len() < 256 {
                    match pkt_rx.try_recv() {
                        Ok(p) => batch.push(p),
                        Err(_) => break,
                    }
                }
                for (seq, flags, payload) in batch {
                    if flags & TCP_SYN != 0 && flags & TCP_ACK != 0 && awaiting_syn_ack {
                        // 标准握手第二步：收到 SYN-ACK。
                        // 先回 ACK 完成三次握手，再发伪 ClientHello，最后才放行 QUIC 数据。
                        ctx.peer_seq = seq.wrapping_add(1);
                        let ack = build_packet(
                            local_ip,
                            server_ip,
                            cfg.faketcp.source_port,
                            server_port,
                            ctx.seq,
                            ctx.peer_seq,
                            TCP_ACK,
                            cfg.faketcp.ip_id_magic & 0xFF00,
                            &[],
                        );
                        let _ = raw.send(&ack, server_ip);
                        // 伪 ClientHello 在 ACK 之后发出，线上顺序就像正常 TLS 握手
                        if let Some(hello) = pending_hello.take() {
                            let hello_pkt = build_packet(
                                local_ip,
                                server_ip,
                                cfg.faketcp.source_port,
                                server_port,
                                ctx.seq,
                                ctx.peer_seq,
                                TCP_PSH | TCP_ACK,
                                cfg.faketcp.ip_id_magic & 0xFF00,
                                &hello,
                            );
                            let _ = raw.send(&hello_pkt, server_ip);
                            ctx.seq = ctx.seq.wrapping_add(hello.len() as u32);
                        }
                        awaiting_syn_ack = false;
                        tracing::info!(%seq, "三次握手完成，开始发送数据");
                    } else {
                        // 记录对端序列号，回包时填 ack。
                        // 跨境链路会乱序，如果 ack 跟着回退，中间设备可能认为非法并丢包，
                        // 所以 ack 只增不减。
                        let next = seq.wrapping_add(payload.len() as u32);
                        if next.wrapping_sub(ctx.peer_seq) < 0x8000_0000 {
                            ctx.peer_seq = next;
                        }
                    }
                    handle_incoming(&mut endpoint, &mut conn, ch, server_addr, &payload, &mut ctx);
                }
            }
            // 2. QUIC 定时器（PTO、空闲超时、保活）
            _ = tick(deadline) => {
                conn.handle_timeout(Instant::now());
            }
            // 3. 本地代理动作
            maybe = action_rx.recv() => {
                let Some(first) = maybe else { break };
                // 批量消化本地写入动作：直播/测速时一次性写入会有很多小包
                let mut actions: Vec<ProxyAction> = Vec::with_capacity(256);
                actions.push(first);
                while actions.len() < 256 {
                    match action_rx.try_recv() {
                        Ok(a) => actions.push(a),
                        Err(_) => break,
                    }
                }
                for action in actions {
                    handle_action(&mut conn, &mut streams, action);
                }
            }
        }

        // 每次状态变化后都要把 QUIC 想发的包全部排空。
        // 握手未完成时不能发：严格 NAT 会丢掉 SYN-ACK 之前的数据包。
        if !awaiting_syn_ack {
            drain_transmits(&mut conn, &mut ctx);
        }
        // 处理事件（连接建立、流可读、流可写）
        let disconnected = drain_events(&mut conn, &mut streams, &mut connected_logged);

        // 流被关闭后清理。
        // 除了双向已完成，还加一个 5 分钟空闲超时：
        // 测速/浏览结束后有些流双方都没发 FIN，会一直留在表里（实测残留 40+ 条），
        // 占用内存和遍历开销。
        let now_clean = Instant::now();
        streams.retain(|_, s| {
            let done = s.remote_finished && s.local_finished;
            let idle = now_clean.duration_since(s.last_active) > std::time::Duration::from_secs(300);
            !(done || idle)
        });

        // 连接已断开：跳出会话，外层退避重连
        if disconnected {
            break;
        }
    }

    Ok(())
}

/// 把收到的 TLS 记录解密后交给 QUIC 状态机。
fn handle_incoming(
    endpoint: &mut Endpoint,
    conn: &mut quinn_proto::Connection,
    ch: ConnectionHandle,
    server_addr: SocketAddr,
    payload: &[u8],
    ctx: &mut SendCtx,
) {
    for rec in parse_records(payload) {
        if rec.typ != REC_APPDATA {
            // 伪 ServerHello / CCS 等握手表演包，直接忽略
            continue;
        }
        let Some(plain) = ctx.obfs.open(rec.payload) else {
            // 解密失败：不是我们的服务端，或链路被篡改，静默丢弃
            continue;
        };
        let now = Instant::now();
        let mut buf = Vec::with_capacity(2048);
        if let Some(event) = endpoint.handle(
            now,
            server_addr,
            None,
            None,
            BytesMut::from(&plain[..]),
            &mut buf,
        ) {
            match event {
                quinn_proto::DatagramEvent::ConnectionEvent(_, ev) => conn.handle_event(ev),
                quinn_proto::DatagramEvent::Response(t) => {
                    // endpoint 直接产生的响应（如 stateless reset），原样发出
                    ctx.send_datagram(&buf[..t.size]);
                }
                quinn_proto::DatagramEvent::NewConnection(_) => {}
            }
        }
        // 保证 endpoint 事件被消化，避免内存堆积
        while let Some(ee) = conn.poll_endpoint_events() {
            if let Some(ce) = endpoint.handle_event(ch, ee) {
                conn.handle_event(ce);
            }
        }
    }
}

/// 把所有待发的 QUIC 包排空。
/// 注意：poll_transmit 会向 buf 追加写入，每次循环必须先 clear，
/// 否则 buf 无限增长，seal 会越来越慢，看起来像死循环。
fn drain_transmits(conn: &mut quinn_proto::Connection, ctx: &mut SendCtx) {
    let mut buf = Vec::with_capacity(2048);
    let mut sent = 0;
    loop {
        buf.clear();
        let Some(t) = conn.poll_transmit(Instant::now(), 1, &mut buf) else {
            break;
        };
        tracing::debug!(size = t.size, dst_port = ctx.server_port, "发出 QUIC 数据报");
        ctx.send_datagram(&buf[..t.size]);
        sent += 1;
        // 每轮最多 64 个包：一次发上千包会长时间占住事件循环，
        // 导致入向 ACK 在 channel 里积压，RTT 虚高、PTO 误判。
        if sent >= 64 {
            break;
        }
    }
}

/// 处理 QUIC 事件：连接建立、流可读、流可写。
fn drain_events(
    conn: &mut quinn_proto::Connection,
    streams: &mut HashMap<StreamId, StreamState>,
    connected_logged: &mut bool,
) -> bool {
    let mut disconnected = false;
    while let Some(ev) = conn.poll() {
        match ev {
            Event::Connected => {
                if !*connected_logged {
                    tracing::info!("QUIC 连接已建立");
                    *connected_logged = true;
                }
            }
            Event::ConnectionLost { reason } => {
                // 不再只打日志：置位后主循环退出，外层按退避策略重连。
                tracing::warn!(?reason, "QUIC 连接断开，准备重连");
                disconnected = true;
            }
            Event::Stream(StreamEvent::Readable { id }) => {
                read_stream(conn, streams, id);
            }
            Event::Stream(StreamEvent::Writable { id }) => {
                flush_pending(conn, streams, id);
            }
            Event::Stream(StreamEvent::Finished { id }) => {
                // Finished 只表示「本地发送方向已完全确认」（我们发的 FIN 被 ACK），
                // 与接收方向无关。之前把它当成对端接收结束，导致还在下载的流被误删，
                // 紧接着被 stop，表现为下载几秒就断。
                if let Some(s) = streams.get_mut(&id) {
                    s.local_finished = true;
                }
            }
            Event::Stream(StreamEvent::Stopped { id, .. }) => {
                // 对端要求我们停止发送：清掉待发数据，标记本地方向结束
                if let Some(s) = streams.get_mut(&id) {
                    s.local_finished = true;
                    s.pending.clear();
                }
            }
            _ => {}
        }
    }
    // 返回是否已断开，供主循环跳出会话
    disconnected
}

/// 读一条流上的所有可用数据，转给本地任务。
fn read_stream(
    conn: &mut quinn_proto::Connection,
    streams: &mut HashMap<StreamId, StreamState>,
    id: StreamId,
) {
    let Some(st) = streams.get_mut(&id) else {
        // 本地已经不再跟踪这条流（应用层结束/已清理），但服务端可能还在写。
        // 必须主动 stop 并读掉残留数据，否则它会一直占用 QUIC 的连接级接收窗口，
        // 把其它所有流一起拖死（实测服务端 pending 因此涨到 58MB）。
        tracing::warn!(stream = ?id, "流已不在本地表，stop 并丢弃残留数据");
        let mut recv = conn.recv_stream(id);
        if let Ok(mut chunks) = recv.read(true) {
            while let Ok(Some(_)) = chunks.next(65536) {}
            let _ = chunks.finalize();
        }
        let _ = conn.recv_stream(id).stop(0u32.into());
        return;
    };
    if st.stopped {
        // 已经 stop 过的流：quinn 可能仍投递 Readable，忽略即可，
        // 不再重复 read/stop，避免 CPU 空转和日志刷屏。
        return;
    }
    st.last_active = Instant::now();
    let mut out = Vec::new();
    let mut finished = false;
    let mut read_err = false;
    {
        let mut recv = conn.recv_stream(id);
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
            Err(_) => read_err = true,
        };
    }
    if read_err {
        // 流已进入不可恢复状态（组装器被锁定）。
        // 继续跳过只会让这条流的窗口永不释放，最终堆成几十 MB pending，
        // 所以直接 stop：释放流控额度，让请求失败重试，不拖累整条连接。
        st.stopped = true;
        st.remote_finished = true;
        let _ = conn.recv_stream(id).stop(0u32.into());
        tracing::warn!(stream = ?id, "recv.read 失败，停止该流释放窗口");
        return;
    }
    if !out.is_empty() {
        tracing::info!(stream = ?id, bytes = out.len(), "收到 QUIC 数据");
        let _ = st.to_local.send(out);
    }
    if finished {
        tracing::info!(stream = ?id, "远端流结束");
    }
    if finished && !st.remote_finished {
        st.remote_finished = true;
        // 发送空 Vec 作为 EOF 标记，本地任务收到后关闭写端
        let _ = st.to_local.send(Vec::new());
    }
}

/// 把暂存的数据继续写入流。
fn flush_pending(
    conn: &mut quinn_proto::Connection,
    streams: &mut HashMap<StreamId, StreamState>,
    id: StreamId,
) {
    let Some(st) = streams.get_mut(&id) else { return };
    while !st.pending.is_empty() {
        match conn.send_stream(id).write(&st.pending) {
            Ok(n) if n > 0 => {
                st.pending.drain(..n);
            }
            Ok(_) => break,
            Err(WriteError::Blocked) => break,
            Err(_) => {
                st.pending.clear();
                break;
            }
        }
    }
}

/// 处理本地代理任务发来的动作。
fn handle_action(
    conn: &mut quinn_proto::Connection,
    streams: &mut HashMap<StreamId, StreamState>,
    action: ProxyAction,
) {
    match action {
        ProxyAction::Open { target, reply } => {
            let Some(id) = conn.streams().open(Dir::Bi) else {
                let _ = reply.send(None);
                return;
            };
            // 先把地址帧写进去，写不完的部分挂到 pending
            let target_len = target.len();
            let mut pending = target;
            if let Ok(n) = conn.send_stream(id).write(&pending) {
                pending.drain(..n);
            }
            let (tx, rx) = mpsc::unbounded_channel();
            streams.insert(
                id,
                StreamState {
                    to_local: tx,
                    pending,
                    local_finished: false,
                    remote_finished: false,
                    stopped: false,
                    last_active: Instant::now(),
                },
            );
            tracing::debug!(stream = ?id, target_len, "打开 QUIC 流");
            let _ = reply.send(Some((id, rx)));
        }
        ProxyAction::Data(id, data) => {
            let Some(st) = streams.get_mut(&id) else { return };
            if st.local_finished {
                return;
            }
            st.last_active = Instant::now();
            tracing::debug!(stream = ?id, bytes = data.len(), "本地数据写入 QUIC");
            // 先尝试直接写入，阻塞的部分排到 pending
            if st.pending.is_empty() {
                match conn.send_stream(id).write(&data) {
                    Ok(n) if n == data.len() => return,
                    Ok(n) => st.pending.extend_from_slice(&data[n..]),
                    Err(WriteError::Blocked) => st.pending.extend_from_slice(&data),
                    Err(_) => return,
                }
            } else {
                st.pending.extend_from_slice(&data);
            }
            flush_pending(conn, streams, id);
        }
        ProxyAction::Fin(id) => {
            let Some(st) = streams.get_mut(&id) else { return };
            if st.local_finished {
                return;
            }
            st.local_finished = true;
            // 先清空 pending，再 FIN；写不完时依靠后续 Writable 事件继续
            flush_pending(conn, streams, id);
            let _ = conn.send_stream(id).finish();
        }
    }
}

/// 启动配置里指定的本地代理入口。
async fn spawn_inbounds(cfg: &ClientFile, client: ProxyClient) -> Result<()> {
    if let Some(inb) = &cfg.socks5 {
        let addr = crate::config::parse_listen(&inb.listen)?;
        let client = client.clone();
        let auth = (inb.username.clone(), inb.password.clone());
        tokio::spawn(async move {
            if let Err(e) = proxy::socks5::run(addr, auth, client).await {
                tracing::error!(error = %e, "SOCKS5 入口退出");
            }
        });
        tracing::info!(%addr, "SOCKS5 入口已启动");
    }
    if let Some(inb) = &cfg.http {
        let addr = crate::config::parse_listen(&inb.listen)?;
        let client = client.clone();
        let auth = (inb.username.clone(), inb.password.clone());
        tokio::spawn(async move {
            if let Err(e) = proxy::http::run(addr, auth, client).await {
                tracing::error!(error = %e, "HTTP 入口退出");
            }
        });
        tracing::info!(%addr, "HTTP 入口已启动");
    }
    if let Some(inb) = &cfg.https {
        let addr = crate::config::parse_listen(&inb.listen)?;
        let client = client.clone();
        let auth = (inb.username.clone(), inb.password.clone());
        tokio::spawn(async move {
            if let Err(e) = proxy::http::run_tls(addr, auth, client).await {
                tracing::error!(error = %e, "HTTPS 入口退出");
            }
        });
        tracing::info!(%addr, "HTTPS 入口已启动");
    }
    Ok(())
}

/// DNS 解析，只保留 IPv4 地址。
async fn resolve_ipv4(host: &str) -> Result<Ipv4Addr> {
    // 如果本身就是 IP，直接返回
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    let addrs = tokio::net::lookup_host(format!("{host}:0"))
        .await
        .with_context(|| format!("解析 {host} 失败"))?;
    for a in addrs {
        if let SocketAddr::V4(v4) = a {
            return Ok(*v4.ip());
        }
    }
    anyhow::bail!("{host} 没有可用的 IPv4 地址")
}

/// QUIC 定时器驱动。
/// deadline 在未来时精确睡到该时刻；已过期或为 None 时按最小 5ms 间隔重试，
/// 避免 poll_timeout 返回过去时刻导致 CPU 100%。
async fn tick(deadline: Option<tokio::time::Instant>) {
    let now = tokio::time::Instant::now();
    match deadline {
        Some(d) if d > now => tokio::time::sleep_until(d).await,
        _ => tokio::time::sleep(std::time::Duration::from_millis(5)).await,
    }
}

/// 把一条本地连接（明文 TCP 或本地 TLS）和一条 QUIC 流对接起来。
pub async fn pipe_stream<S>(
    local: S,
    id: StreamId,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
    client: ProxyClient,
)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    // 用 tokio::io::split 而不是 TcpStream::into_split，兼容 TLS 流
    let (mut r, mut w) = tokio::io::split(local);
    let c1 = client.clone();
    // 本地 → QUIC
    let reader = async move {
        let mut buf = [0u8; 16384];
        loop {
            match r.read(&mut buf).await {
                Ok(0) => {
                    c1.fin(id);
                    break;
                }
                Ok(n) => c1.send(id, buf[..n].to_vec()),
                Err(_) => {
                    c1.fin(id);
                    break;
                }
            }
        }
    };
    // QUIC → 本地
    let writer = async move {
        while let Some(data) = rx.recv().await {
            if data.is_empty() {
                let _ = w.shutdown().await;
                break;
            }
            if w.write_all(&data).await.is_err() {
                break;
            }
        }
    };
    // 两个方向独立跑完，不能用 select!：任一方结束时 drop 另一方向，
    // 会导致剩余数据没搬完连接就被关（下载几十 KB 就报 transfer closed）。
    tokio::join!(reader, writer);
}
