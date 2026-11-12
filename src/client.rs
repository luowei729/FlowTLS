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
    ConnectionHandle, Dir, Endpoint, EndpointConfig, Event, ReadError, ReadableError, StreamEvent,
    StreamId, WriteError,
};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use crate::config::{parse_host_port, ClientFile};
use crate::faketcp::codec::{build_client_hello, parse_records, Obfs, REC_APPDATA};
use crate::faketcp::packet::{
    advertised_window, build_packet, build_packet_into, next_ipid, parse_frame, random_ipid,
    seq_len, syn_options, TcpClock, TcpSeg, TCP_ACK, TCP_FIN, TCP_PSH, TCP_SYN,
};
use crate::faketcp::socket::{PacketBatch, RawSocket};
use crate::proxy::{self, ProxyAction};

/// 本地代理任务持有的句柄，用来向事件循环发动作。
#[derive(Clone)]
pub struct ProxyClient {
    /// 内部动作通道。用 Mutex<Option<..>> 而不是直接持有 Sender，
    /// 是因为断线重连时主循环会重建通道，而本地代理入口只启动一次。
    ///
    /// 必须是有界通道：QUIC 写不下去时（跨境链路丢包高、窗口收缩），
    /// 无界通道会让本地 socket 读到的数据无限堆在内存里（实测 8 小时峰值 125MB）。
    /// 有界之后 send().await 会挂住，本地 socket 停止读取，TCP 窗口收缩，
    /// 浏览器/测速端自然降速——这就是端到端背压，和 hysteria2 的阻塞式 Write 一致。
    tx: Arc<std::sync::Mutex<Option<mpsc::Sender<ProxyAction>>>>,
    /// 已从本地 socket 读出、但还没交给 QUIC 的全部字节数。
    ///
    /// 必须同时覆盖两段，否则背压是假的：
    /// 1. 还在动作通道里排队的（1024 × 16KB ≈ 16MB）；
    /// 2. 已经落到 `StreamState.pending` 的（原来完全没有上限）。
    /// 之前只靠「通道满」这一层兜底，quinn 自己的 `send_window`（8MB）
    /// 和 pending 都看不见，实测上传时 pending 峰值冲到 78MB。
    /// 现在按 BDP 定价：1MB 已足够填满 80Mbps 在途数据，再多只是排队。
    inflight: Arc<std::sync::atomic::AtomicUsize>,
    /// quinn 发送缓冲是否已满（`write` 返回 Blocked 或只写进一部分）。
    /// 与 `inflight` 一起构成真实的发送侧背压信号。
    blocked: Arc<std::sync::atomic::AtomicBool>,
    /// 发送缓冲腾出空间时唤醒读取任务。
    /// 用事件通知而不是 sleep 轮询：轮询会把吞吐死锁在「一次读量 ÷ 轮询间隔」。
    notify: Arc<tokio::sync::Notify>,
}

impl ProxyClient {
    /// 新建一个未绑定的客户端（重连后由主循环调用 set_tx 绑定）。
    fn new() -> Self {
        Self {
            tx: Arc::new(std::sync::Mutex::new(None)),
            inflight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            blocked: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// 上传方向的背压水位：超过它就暂停读本地 socket。
    /// 与服务端 `pending_high_water` 同一口径（max_cwnd/4，封顶 1MB）：
    /// 100ms RTT 下 1MB 足够跑满 80Mbps，再多只是把数据堆在内存里排队。
    pub const HIGH_WATER: usize = 1024 * 1024;

    /// 当前在途字节数（供统计日志使用）。
    pub fn inflight(&self) -> usize {
        self.inflight.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 是否应该暂停读取本地 socket。
    #[inline]
    fn should_pause(&self) -> bool {
        self.inflight.load(std::sync::atomic::Ordering::Relaxed) > Self::HIGH_WATER
            || self.blocked.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 等待背压缓解。
    /// 先拿 `notified()` 再做一次检查，避免「检查后、await 前」刚好被写空而白等；
    /// 50ms 的 timeout 只作兜底（对端彻底不 ACK 时不会有通知）。
    async fn wait_drain(&self) {
        loop {
            if !self.should_pause() {
                return;
            }
            let wait = self.notify.notified();
            if !self.should_pause() {
                return;
            }
            let _ = tokio::time::timeout(std::time::Duration::from_millis(50), wait).await;
        }
    }

    /// 绑定本次连接的动作通道。旧通道被丢弃，旧连接上的请求随之失效。
    fn set_tx(&self, tx: mpsc::Sender<ProxyAction>) {
        if let Ok(mut guard) = self.tx.lock() {
            *guard = Some(tx);
        }
        // 新连接开始：旧连接的流全部作废，在途计数必须归零，
        // 否则上一轮残留的数值会立刻把新连接卡在背压等待里。
        self.inflight.store(0, std::sync::atomic::Ordering::Relaxed);
        self.blocked.store(false, std::sync::atomic::Ordering::Relaxed);
        self.notify.notify_waiters();
    }

    /// 取出当前通道的克隆；未绑定（重连间隙）时返回 None。
    fn sender(&self) -> Option<mpsc::Sender<ProxyAction>> {
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
        // 有界通道满时在这里等待：新连接也会被背压，不会绕过水位
        tx.send(ProxyAction::Open { target, reply: reply_tx }).await.ok()?;
        reply_rx.await.ok().flatten()
    }

    /// 本地 → 远端。
    /// 用 async + 有界通道实现背压：通道满时调用方（pipe_stream 的读取任务）
    /// 会挂在这里，于是不再读本地 socket，浏览器发送端被 TCP 窗口反向限速。
    ///
    /// 这里同时维护 `inflight`：在把数据交给通道**之前**就记账，
    /// 这样「还在通道里排队」和「已落到 st.pending」两段都被算进背压，
    /// 不会出现「通道还没满、pending 已经堆了几十 MB」的情况。
    pub async fn send(&self, id: StreamId, data: Vec<u8>) {
        let n = data.len();
        self.inflight
            .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
        let Some(tx) = self.sender() else {
            // 未绑定（重连间隙）：直接丢弃并退回记账
            self.inflight
                .fetch_sub(n, std::sync::atomic::Ordering::Relaxed);
            return;
        };
        if tx.send(ProxyAction::Data(id, data)).await.is_err() {
            // 通道已关闭：这笔数据不会有人处理，退回记账
            self.inflight
                .fetch_sub(n, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// 本地方向结束。同样走有界通道，保证 FIN 不会插到未写完的数据前面。
    pub async fn fin(&self, id: StreamId) {
        if let Some(tx) = self.sender() {
            let _ = tx.send(ProxyAction::Fin(id)).await;
        }
    }

    /// 彻底放弃一条流：通知对端别再写了。
    /// 本地连接异常关闭时必须调用，否则对端会一直往这条流里堆数据。
    pub async fn stop(&self, id: StreamId) {
        if let Some(tx) = self.sender() {
            let _ = tx.send(ProxyAction::Stop(id)).await;
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
    /// 本地已 EOF，等 pending 写完才能发 FIN。
    /// 直接 finish() 会让 FIN 越过尚未写出的数据，对端提前看到流结束。
    fin_pending: bool,
    /// 最后一次读写时间。用于清理「双方都没发 FIN、但已经长时间无数据」的僵尸流。
    last_active: Instant,
}

/// 发送上下文：FakeTCP 需要的所有参数
struct SendCtx {
    raw: Arc<RawSocket>,
    server_ip: Ipv4Addr,
    server_port: u16,
    source_port: u16,
    local_ip: Ipv4Addr,
    obfs: Obfs,
    /// 当前发送序列号
    seq: u32,
    /// 最近一次收到的对端序列号
    peer_seq: u32,
    /// IP ID 当前值：高字节是配置派生的分流标记，低字节单调递增
    ip_id: u16,
    /// 分流标记高字节（来自 `faketcp.ip_id_magic`）。
    /// 从配置派生而不是写死，这样每个部署的特征不同，
    /// DPI 无法用一条通用规则命中所有实例。
    mark: u16,
    /// TCP 时间戳时钟：数据包带回显的 TS，缺失是最好认的伪造特征
    clock: TcpClock,
    /// 待确认的数据段数（延迟确认用）
    ack_pending: u32,
    /// 上次发送纯 ACK 的时刻（延迟确认的 40ms 兜底）
    last_ack: std::time::Instant,
    /// 纯 ACK / FIN 的复用发送缓冲。
    /// 数据面已经走 PacketBatch 批量池，但控制包还是每包一次 build_packet →
    /// 一次 Vec 分配。实测纯 ACK 占总包数的 22.5%，14 万包就是 3 万次 malloc，
    /// 在 1 核机器上是可观的用户态开销。这里复用同一个缓冲，稳态零分配。
    ctrl_buf: Vec<u8>,
}

impl SendCtx {
    /// 组装一个 TCP 段（数据包自动带时间戳选项）。
    /// `window` 由调用方按接收积压算出，不再恒为 65535。
    #[inline]
    fn seg<'a>(&self, flags: u8, window: u16, options: &'a [u8], payload: &'a [u8]) -> TcpSeg<'a> {
        TcpSeg {
            seq: self.seq,
            ack: self.peer_seq,
            flags,
            ip_id: self.ip_id,
            window,
            tsval: self.clock.tsval(),
            tsecr: self.clock.peer_ts,
            options,
            payload,
        }
    }

    /// 推进序号与 IP ID（发出一个段之后调用）。
    #[inline]
    fn advance(&mut self, flags: u8, payload_len: usize) {
        self.seq = self.seq.wrapping_add(seq_len(flags, payload_len));
        self.ip_id = next_ipid(self.mark, self.ip_id);
    }

    /// 把一个 QUIC 数据报封装成 TLS 记录 + TCP 包并发出。
    /// 只用于零星包（stateless reset 等），热路径走 `build_datagram` + 批量发送。
    fn send_datagram(&mut self, payload: &[u8], window: u16) {
        let record = self.obfs.seal(payload);
        let seg = self.seg(TCP_PSH | TCP_ACK, window, &[], &record);
        let pkt = build_packet(
            self.local_ip,
            self.server_ip,
            self.source_port,
            self.server_port,
            &seg,
        );
        if let Err(e) = self.raw.send(&pkt, self.server_ip) {
            tracing::warn!(error = %e, "发送失败");
        } else {
            tracing::debug!(src_port = self.source_port, dst_port = self.server_port, len = pkt.len(), "raw 包已发出");
        }
        self.advance(TCP_PSH | TCP_ACK, record.len());
    }

    /// 只做「明文 → 记录 → IP 报文」的纯内存构造，不碰 socket。
    /// 三个缓冲都由调用方复用，稳态零分配；构造完由上层批量 `sendmmsg` 发出。
    fn build_datagram(
        &mut self,
        record: &mut Vec<u8>,
        out: &mut Vec<u8>,
        payload: &[u8],
        window: u16,
    ) {
        self.obfs.seal_into(record, payload);
        let seg = self.seg(TCP_PSH | TCP_ACK, window, &[], record);
        build_packet_into(
            out,
            self.local_ip,
            self.server_ip,
            self.source_port,
            self.server_port,
            &seg,
        );
        self.advance(TCP_PSH | TCP_ACK, record.len());
    }

    /// 发一个纯 ACK（无载荷）。
    ///
    /// 真实 TCP 是双向确认的：接收方必须回纯 ACK。
    /// 旧实现只在握手时发过一个 ACK，数据阶段一个都没有，
    /// 抓包时「下载方向有几万个包，反向零个纯 ACK」是极其显眼的伪造特征。
    fn send_pure_ack(&mut self, window: u16) {
        self.ack_pending = 0;
        self.last_ack = std::time::Instant::now();
        // 内联构造 TcpSeg（不调 self.seg）的原因：下面要把 ctrl_buf 从 self 里
        // take 出来做 &mut 借用，若 seg 还借着 &self 就会冲突。
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
        // 复用缓冲：take 出来 → 用完放回，稳态不再分配
        let mut buf = std::mem::take(&mut self.ctrl_buf);
        build_packet_into(
            &mut buf,
            self.local_ip,
            self.server_ip,
            self.source_port,
            self.server_port,
            &seg,
        );
        let _ = self.raw.send(&buf, self.server_ip);
        self.ctrl_buf = buf;
        // 纯 ACK 不占序号，只需推进 IP ID
        self.ip_id = next_ipid(self.mark, self.ip_id);
    }

    /// 发 FIN 拆除连接（真实 TCP 至少有 FIN 握手，旧实现是静默消失）。
    fn send_fin(&mut self, window: u16) {
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
            self.server_ip,
            self.source_port,
            self.server_port,
            &seg,
        );
        let _ = self.raw.send(&buf, self.server_ip);
        self.ctrl_buf = buf;
        self.advance(TCP_FIN | TCP_ACK, 0);
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
    let (pkt_tx, mut pkt_rx) = mpsc::channel::<(u32, u8, Option<u32>, Vec<u8>)>(8192);
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
                            // 连同 seq / flags / 对端 TSval 一起送出：
                            // SYN-ACK 需要回 ACK 完成握手，TSval 要回显到 TSecr
                            if pkt_tx
                                .blocking_send((p.seq, p.flags, p.tsval, p.payload.to_vec()))
                                .is_err()
                            {
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
    pkt_rx: &mut mpsc::Receiver<(u32, u8, Option<u32>, Vec<u8>)>,
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

    // 分流标记高字节：来自配置的 ip_id_magic。
    // 让每个部署的 IP ID 特征各不相同，DPI 无法用一条通用规则命中。
    let mark = crate::faketcp::packet::ipid_mark(cfg.faketcp.ip_id_magic);
    let mut ctx = SendCtx {
        raw: raw.clone(),
        server_ip,
        server_port,
        source_port: cfg.faketcp.source_port,
        local_ip,
        obfs: Obfs::new(&cfg.password),
        seq: 0,
        peer_seq: 0,
        // 起始 IP ID 随机，避免所有连接都从同一值开始
        ip_id: random_ipid(mark),
        mark,
        clock: TcpClock::new(),
        ack_pending: 0,
        last_ack: std::time::Instant::now(),
        // 预分配一个 MTU 大小的控制包缓冲，稳态复用
        ctrl_buf: Vec::with_capacity(256),
    };

    // 随机初始序列号，SYN 占 1 个序号
    let isn: u32 = rand::thread_rng().gen();
    ctx.seq = isn.wrapping_add(1);

    // 批量发送缓冲池：跨重连复用，报文缓冲只分配一次
    let mut send_batch = PacketBatch::new();

    // ---- 标准三次握手：先只发 SYN ----
    // 严格 NAT/状态防火墙只放行「SYN → SYN-ACK → ACK」之后的数据包，
    // 旧版「SYN + 数据同批发」会被直接丢弃（实测江苏移动新网关）。
    // 代价是多 1 个 RTT（约 70ms），但兼容性从「看网关脸色」变成通用。
    let hello = build_client_hello(sni);
    let mut pending_hello = Some(hello);
    if cfg.faketcp.handshake != "none" {
        // 裸 SYN，选项与真实 Linux 逐字节一致：MSS/SACK/TS/NOP/wscale 9。
        // 之前这里缺 TCP 时间戳、且用 wscale 12，两个特征都能一眼认出是伪造。
        let opts = syn_options(ctx.clock.tsval(), 0);
        let seg = TcpSeg {
            seq: isn,
            ack: 0,
            flags: TCP_SYN,
            ip_id: ctx.ip_id,
            // SYN 阶段真实 Linux 通告的是 65535，缩放因子要到 ESTABLISHED 才生效
            window: 65535,
            tsval: ctx.clock.tsval(),
            tsecr: 0,
            options: &opts,
            payload: &[],
        };
        let syn = build_packet(
            local_ip,
            server_ip,
            cfg.faketcp.source_port,
            server_port,
            &seg,
        );
        let _ = raw.send(&syn, server_ip);
        // SYN 占 1 个序号，IP ID 也要推进
        ctx.ip_id = next_ipid(ctx.mark, ctx.ip_id);
        tracing::info!("已发送 SYN，等待 SYN-ACK");
    } else {
        // handshake=none（客户端有公网 IP）时不需要表演握手，直接发数据
        pending_hello = None;
    }

    // 本次连接的本地动作通道，绑定给常驻的代理入口
    // 有界动作队列：1024 × 16KB ≈ 16MB 上限，与 max_cwnd(4MB) 的 4 倍对齐。
    // 满了之后本地读取任务阻塞在 send().await，形成端到端背压。
    let (action_tx, mut action_rx) = mpsc::channel::<ProxyAction>(1024);
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
            // 配置里的 net.max_cwnd 是「上限」语义：自适应只能在它之下浮动。
            // 之前只把它当初始值，丢包率低于 5% 时会被 1.2 倍一路放大到 8MB，
            // 用户按小带宽链路设的 4MB 完全失效（表现为窗口远超 BDP、丢包变多）。
            let cfg_cap = cfg.net.max_cwnd.max(1536 * 1024);
            let upper = safe_cap
                .clamp(1536 * 1024, 8 * 1024 * 1024)
                .min(cfg_cap);
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
                // 已读出但还没交给 QUIC 的全部字节（含动作通道在途 + pending）。
                // 上传卡住时这个值不降，就是背压失效的第一现场。
                inflight = proxy_client.inflight(),
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
                let mut batch: Vec<(u32, u8, Option<u32>, Vec<u8>)> = Vec::with_capacity(256);
                batch.push(first);
                while batch.len() < 256 {
                    match pkt_rx.try_recv() {
                        Ok(p) => batch.push(p),
                        Err(_) => break,
                    }
                }
                for (seq, flags, tsval, payload) in batch {
                    // 记录对端时间戳，后续所有回包都要原样回显到 TSecr
                    ctx.clock.observe(tsval);
                    if flags & TCP_SYN != 0 && flags & TCP_ACK != 0 && awaiting_syn_ack {
                        // 标准握手第二步：收到 SYN-ACK。
                        // 先回 ACK 完成三次握手，再发伪 ClientHello，最后才放行 QUIC 数据。
                        ctx.peer_seq = seq.wrapping_add(1);
                        ctx.send_pure_ack(advertised_window(0));
                        // 伪 ClientHello 在 ACK 之后发出，线上顺序就像正常 TLS 握手
                        if let Some(hello) = pending_hello.take() {
                            let seg = ctx.seg(TCP_PSH | TCP_ACK, advertised_window(0), &[], &hello);
                            let hello_pkt = build_packet(
                                local_ip,
                                server_ip,
                                cfg.faketcp.source_port,
                                server_port,
                                &seg,
                            );
                            let _ = raw.send(&hello_pkt, server_ip);
                            ctx.advance(TCP_PSH | TCP_ACK, hello.len());
                        }
                        awaiting_syn_ack = false;
                        tracing::info!(%seq, "三次握手完成，开始发送数据");
                    } else {
                        // 记录对端序列号，回包时填 ack。
                        // 跨境链路会乱序，如果 ack 跟着回退，中间设备可能认为非法并丢包，
                        // 所以 ack 只增不减。
                        let next = seq.wrapping_add(seq_len(flags, payload.len()));
                        if next.wrapping_sub(ctx.peer_seq) < 0x8000_0000 {
                            ctx.peer_seq = next;
                        }
                        // 带载荷的段必须被确认（纯 ACK 不需要再确认）。
                        // 按 RFC 1122 的延迟确认：每收到 2 个数据段回 1 个纯 ACK，
                        // 而不是每批都回——实测「每批一个」会让纯 ACK 占到总包数 42%，
                        // 既不像真实 TCP，也把 CPU 抬了 3 倍（每包一次 alloc + sendto）。
                        if !payload.is_empty() {
                            ctx.ack_pending += 1;
                        }
                    }
                    handle_incoming(&mut endpoint, &mut conn, ch, server_addr, &payload, &mut ctx);
                }
                // 反转方向告：下载方向必须有纯 ACK 回程，否则抓包一眼就是伪造。
                // 触发条件与真实 Linux 一致：累计 2 个数据段立即确认，
                // 或距上次确认超过 40ms（延迟确认上限）。
                let due = ctx.ack_pending >= 2
                    || (ctx.ack_pending > 0
                        && ctx.last_ack.elapsed() >= std::time::Duration::from_millis(40));
                if due && !awaiting_syn_ack {
                    let unread: usize = streams.values().map(|s| s.pending.len()).sum();
                    ctx.send_pure_ack(advertised_window(unread));
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
                    handle_action(&mut conn, &mut streams, action, &proxy_client);
                }
            }
        }

        // 每次状态变化后都要把 QUIC 想发的包全部排空。
        // 握手未完成时不能发：严格 NAT 会丢掉 SYN-ACK 之前的数据包。
        if !awaiting_syn_ack {
            // 通告窗口按「待发+待消费」字节数动态计算。
            // 恒为 65535 是真实 TCP 不会出现的：窗口必须随接收缓冲占用变化。
            let unread: usize = streams
                .values()
                .map(|s| s.pending.len())
                .sum::<usize>()
                + pkt_rx.len() * 1400;
            let window = advertised_window(unread);
            drain_transmits(&mut conn, &mut ctx, &mut send_batch, window);
        }
        // 处理事件（连接建立、流可读、流可写）
        let disconnected = drain_events(&mut conn, &mut streams, &mut connected_logged, &proxy_client);

        // 流被关闭后清理。
        // 除了双向已完成，还加一个 5 分钟空闲超时：
        // 测速/浏览结束后有些流双方都没发 FIN，会一直留在表里（实测残留 40+ 条），
        // 占用内存和遍历开销。
        let now_clean = Instant::now();
        streams.retain(|_, s| {
            let done = s.remote_finished && s.local_finished;
            let idle = now_clean.duration_since(s.last_active) > std::time::Duration::from_secs(300);
            let keep = !(done || idle);
            if !keep && !s.pending.is_empty() {
                // 被清理的流如果还挂着待发数据，那些字节永远不会交给 QUIC，
                // 必须从在途计数里退掉，否则会永久占着背压配额。
                subtract_inflight(&proxy_client, s.pending.len());
            }
            keep
        });

        // 连接已断开：跳出会话，外层退避重连
        if disconnected {
            break;
        }
    }

    // 会话结束前补一个 FIN：真实 TCP 拆除连接一定有 FIN（或 RST），
    // 旧实现是直接静默消失，抓包时「连接凭空蒸发」也是明显特征。
    ctx.send_fin(advertised_window(0));

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
                    ctx.send_datagram(&buf[..t.size], 65535);
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
///
/// 优化要点：明文/记录/IP 报文全部用复用缓冲，且攒满 32 个包后
/// 一次性 `sendmmsg` 发出——单包 `sendto` 在 1 核机器上约 40~50µs/包，
/// 是高速率下 CPU 打满的主因。
/// 注意：poll_transmit 会向 buf 追加写入，每次循环必须先 clear，
/// 否则 buf 无限增长，seal 会越来越慢，看起来像死循环。
fn drain_transmits(
    conn: &mut quinn_proto::Connection,
    ctx: &mut SendCtx,
    batch: &mut PacketBatch,
    window: u16,
) {
    let mut n = 0usize;
    // 一次 poll_transmit 最多要多少个 QUIC 数据报。
    // 之前固定传 1，等于「每个数据报走一遍完整状态机」：pacing 在高速率下
    // 每包都会拦一次，于是每次唤醒只能发一个包，事件循环被 1 个包/次拖着空转。
    // 传 32 后 quinn 会在一次调用里连续封好整批（segment_size 等长对齐），
    // 我们按 segment_size 切开逐包加外层 TLS 记录，再一次性 sendmmsg 发出。
    // 线上格式完全不变，只是少了几十倍的调度与状态机开销。
    const DATAGRAMS_PER_POLL: usize = PacketBatch::MAX;
    loop {
        // Instant::now() 提到循环外：每包取一次时钟在 1.2 万 pps 下也是可观开销
        let now = Instant::now();
        batch.plain.clear();
        let Some(t) = conn.poll_transmit(now, DATAGRAMS_PER_POLL, &mut batch.plain) else {
            break;
        };
        // 单数据报时 segment_size 为 None；多数据报时每个数据报都等长且按 segment 对齐，
        // 因此直接按 segment_size 切片即可（quinn 已保证末包补齐）。
        let seg = t.segment_size.unwrap_or(t.size);
        if t.size == 0 || seg == 0 {
            break;
        }
        let mut off = 0usize;
        while off < t.size && n < PacketBatch::MAX {
            let end = (off + seg).min(t.size);
            batch.ensure(n + 1);
            ctx.build_datagram(
                &mut batch.record,
                &mut batch.bufs[n],
                &batch.plain[off..end],
                window,
            );
            n += 1;
            off = end;
        }
        // 每轮最多 32 个包：一次发上千包会长时间占住事件循环，
        // 导致入向 ACK 在 channel 里积压，RTT 虚高、PTO 误判。
        if n >= PacketBatch::MAX {
            break;
        }
    }
    if n > 0 {
        if let Err(e) = ctx.raw.send_batch(&batch.bufs[..n], ctx.server_ip) {
            tracing::warn!(error = %e, "批量发送失败");
        }
    }
}

/// 处理 QUIC 事件：连接建立、流可读、流可写。
fn drain_events(
    conn: &mut quinn_proto::Connection,
    streams: &mut HashMap<StreamId, StreamState>,
    connected_logged: &mut bool,
    client: &ProxyClient,
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
                // quinn 发送缓冲腾出空间：这是上传方向背压的「放行」信号。
                // 先清阻塞标志并唤醒读取任务，再继续写 pending。
                client
                    .blocked
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                client.notify.notify_waiters();
                flush_pending(conn, streams, id, client);
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
                // 对端要求我们停止发送：清掉待发数据，标记本地方向结束。
                // 被清掉的数据永远不会交给 QUIC，在途计数也要同步退掉，
                // 否则残留的数值会永久占着背压配额，把之后的流卡死。
                if let Some(s) = streams.get_mut(&id) {
                    s.local_finished = true;
                    let dropped = s.pending.len();
                    s.pending.clear();
                    subtract_inflight(client, dropped);
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
            // “流已不在接收表 / 已读空 / 已停止”是正常状态：
            // Readable 事件会重复投递，上一轮已把数据读空，这一轮自然拿不到东西。
            // 旧代码把任何 Err 都判成「流卡死」直接 stop()，会让还在传输的流被提前
            // 中断，日志里大量 "recv.read 失败，停止该流释放窗口" 都是误报。
            Err(ReadableError::ClosedStream) => {}
            Err(ReadableError::IllegalOrderedRead) => {
                tracing::warn!(stream = ?id, "有序读写在无序读之后，忽略本轮");
            }
        };
    }
    if !out.is_empty() {
        // 每条数据都打 INFO 会写出几十万行、几十 MB 日志（实测 8 小时 62MB），
        // 格式化 + 写 stdout 的开销在高速传输时不可忽略，降到 trace 只在排查时打开。
        tracing::trace!(stream = ?id, bytes = out.len(), "收到 QUIC 数据");
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
    client: &ProxyClient,
) {
    let Some(st) = streams.get_mut(&id) else { return };
    let mut freed = false;
    let mut hit_blocked = false;
    // 这一轮真正被 quinn 接收的字节数，写完统一扣在途
    let mut accepted = 0usize;
    // 流已不可写时丢弃的量，也要从在途里退掉
    let mut dropped = 0usize;
    while !st.pending.is_empty() {
        match conn.send_stream(id).write(&st.pending) {
            Ok(n) if n > 0 => {
                st.pending.drain(..n);
                accepted += n;
                freed = true;
            }
            Ok(_) => break,
            Err(WriteError::Blocked) => {
                hit_blocked = true;
                break;
            }
            Err(_) => {
                dropped = st.pending.len();
                st.pending.clear();
                freed = true;
                break;
            }
        }
    }
    // 本地 EOF 后必须等 pending 真正写空再 finish()，
    // 否则 FIN 会越过尚未写出的数据，服务端提前认为请求结束。
    let ready = st.fin_pending && st.pending.is_empty();
    if ready {
        st.fin_pending = false;
    }
    // pending 清空 = quinn 发送缓冲的压力缓解了，清掉阻塞标志，
    // 否则读取任务会一直等到下一个 Writable 事件。
    if st.pending.is_empty() && !hit_blocked {
        client
            .blocked
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }
    if ready {
        let _ = conn.send_stream(id).finish();
    }
    // 只有真正被 quinn 接收（或确定丢弃）的字节才退出在途计数
    subtract_inflight(client, accepted + dropped);
    // 归还了配额就唤醒读取任务：事件驱动比 sleep 轮询快两个数量级，
    // 直接决定了拥塞时的上传吞吐。
    if freed {
        client.notify.notify_waiters();
    }
}

/// 从在途计数里扣减（saturating，避免重连清零后下溢成 usize::MAX）。
#[inline]
fn subtract_inflight(client: &ProxyClient, n: usize) {
    if n == 0 {
        return;
    }
    let _ = client.inflight.fetch_update(
        std::sync::atomic::Ordering::Relaxed,
        std::sync::atomic::Ordering::Relaxed,
        |v| Some(v.saturating_sub(n)),
    );
}

/// 处理本地代理任务发来的动作。
fn handle_action(
    conn: &mut quinn_proto::Connection,
    streams: &mut HashMap<StreamId, StreamState>,
    action: ProxyAction,
    client: &ProxyClient,
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
                    fin_pending: false,
                    last_active: Instant::now(),
                },
            );
            tracing::debug!(stream = ?id, target_len, "打开 QUIC 流");
            let _ = reply.send(Some((id, rx)));
        }
        ProxyAction::Data(id, data) => {
            let n = data.len();
            // 注意：这里**不能**在开头就把 n 扣掉。
            // inflight 的语义是「已读出但还没交给 QUIC 的字节」，
            // 数据从通道取出来之后如果只是转存到 st.pending，它仍然没交给 QUIC，
            // 必须继续计入水位。只在 write() 真正被 quinn 接收了多少才扣多少。
            // 之前在开头扣整笔，结果 pending 堆到 36MB 时 inflight 仍显示 1MB，
            // 背压完全失效。
            let Some(st) = streams.get_mut(&id) else {
                // 流已不在表里：这笔数据不会有人处理，整笔退回
                subtract_inflight(client, n);
                return;
            };
            if st.local_finished {
                subtract_inflight(client, n);
                return;
            }
            st.last_active = Instant::now();
            tracing::debug!(stream = ?id, bytes = data.len(), "本地数据写入 QUIC");
            // 先尝试直接写入，阻塞的部分排到 pending
            if st.pending.is_empty() {
                match conn.send_stream(id).write(&data) {
                    Ok(m) if m == data.len() => {
                        // 全部写进 quinn：扣掉这部分，未触顶
                        subtract_inflight(client, m);
                        client
                            .blocked
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                        return;
                    }
                    Ok(m) => {
                        // 只写进一部分：扣掉已收的，余下的进 pending（仍在 inflight 里），
                        // 并让读取任务停下来等 quinn 腾空间
                        subtract_inflight(client, m);
                        st.pending.extend_from_slice(&data[m..]);
                        client
                            .blocked
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(WriteError::Blocked) => {
                        st.pending.extend_from_slice(&data);
                        client
                            .blocked
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(_) => {
                        // 流已不可写（对端 reset / 已关闭）：这批数据丢弃，退回记账
                        subtract_inflight(client, n);
                        return;
                    }
                }
            } else {
                st.pending.extend_from_slice(&data);
            }
            flush_pending(conn, streams, id, client);
        }
        ProxyAction::Fin(id) => {
            {
                let Some(st) = streams.get_mut(&id) else { return };
                if st.local_finished {
                    return;
                }
                st.local_finished = true;
                // 只登记「待发 FIN」，真正 finish() 交给 flush_pending
                // 在 pending 清空时执行；否则 FIN 会越过残留数据。
                st.fin_pending = true;
            }
            flush_pending(conn, streams, id, client);
        }
        ProxyAction::Stop(id) => {
            // 本地连接已经彻底关闭（浏览器取消 / curl 超时退出）：
            // 通知服务端别再往这条流写，并释放它占用的流控额度。
            // 不发的话服务端会继续读目标 socket，堆到背压高水位后
            // 干等 30 秒兜底超时才放弃（实测每次中断都刷 3 条这样的 WARN）。
            let dropped = streams
                .remove(&id)
                .map(|s| s.pending.len())
                .unwrap_or(0);
            subtract_inflight(client, dropped);
            let _ = conn.recv_stream(id).stop(0u32.into());
            let _ = conn.send_stream(id).reset(0u32.into());
            client.notify.notify_waiters();
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
    // HTTPS 入口默认开启：未配置时监听 127.0.0.1:8443（仅本机，安全），
    // 鉴权沿用 SOCKS5 配置；需要局域网访问或换证书时在配置里显式写 https。
    let https_cfg = cfg.https.clone().unwrap_or_else(|| {
        let (u, p) = cfg
            .socks5
            .as_ref()
            .map(|s| (s.username.clone(), s.password.clone()))
            .unwrap_or_default();
        crate::config::InboundFile {
            listen: "127.0.0.1:8443".to_string(),
            username: u,
            password: p,
            cert: None,
            key: None,
        }
    });
    {
        let inb = &https_cfg;
        let addr = crate::config::parse_listen(&inb.listen)?;
        let client = client.clone();
        let auth = (inb.username.clone(), inb.password.clone());
        let cert = inb.cert.clone();
        let key = inb.key.clone();
        tokio::spawn(async move {
            if let Err(e) = proxy::http::run_tls(addr, auth, client, cert, key).await {
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
            // 端到端背压：在读出下一块数据之前先看水位。
            //
            // 不能只依赖「动作通道满」这一层：通道容量 1024 × 16KB ≈ 16MB，
            // 加上 quinn 自己的 send_window（8MB）和完全没有上限的 st.pending，
            // 实测上传时 pending 峰值冲到 78MB。
            // 这里按「已读出但还没交给 QUIC 的字节数」判断（含通道在途 + pending），
            // 超过 HIGH_WATER 就停在这里不读，本地 socket 的接收窗口随之收缩，
            // 浏览器/测速端自然降速——这才是真正的端到端背压。
            c1.wait_drain().await;
            match r.read(&mut buf).await {
                Ok(0) => {
                    c1.fin(id).await;
                    break;
                }
                Ok(n) => c1.send(id, buf[..n].to_vec()).await,
                Err(_) => {
                    c1.fin(id).await;
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
    // 本地连接已经彻底结束：主动告诉服务端别再往这条流写。
    // 正常收完时这只是个无害的空操作，但连接被强制中断时（取消下载、
    // curl 超时、浏览器切页）它是唯一能让服务端立刻停止读目标的信号。
    client.stop(id).await;
}
