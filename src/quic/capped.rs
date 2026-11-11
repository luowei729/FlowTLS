//! 给原生 BBR 加窗口上限的拥塞控制器。
//!
//! 为什么需要：
//! 跨境链路夜间高丢包时，quinn 的 BBR 会把 ACK 聚合误算成「一次送达大量字节」，
//! 带宽估计被抬高，cwnd 一路涨到 17MB（相当于 68ms RTT 下 2Gbps 的 BDP），
//! 而香港服务器只有 100M 端口。结果是自己把下行链路打爆，丢包率 50%+，
//! QUIC 只能靠 PTO 单包重传，表现为「两端进程都在、连接也活着，但完全没速度」。
//!
//! 为什么只钳 window 就够：
//! quinn-proto 的 pacing 速率完全由 `Controller::window()` 和 RTT 推导
//! （connection/pacing.rs 中 capacity = window / rtt * 1.25），
//! 因此钳住 window 上限就等于同时限制了突发容量和持续发送速率。
//! 这样不用改 quinn 源码，也保留 BBR 在正常链路上的自适应能力。

use std::any::Any;
use std::sync::Arc;
use std::time::Instant;

use quinn_proto::congestion::{Bbr, BbrConfig, Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;

/// 默认窗口上限：4MB。
/// 受 quinn 接收组装器 MAX_CHUNKS=1024 硬限制约束：
/// 窗口 × 丢包率 ÷ 包大小 必须小于 1024，否则乱序空洞超限会直接断连。
/// 实测链路丢包 30~50%，4MB 对应 960 个空洞，安全；
/// 同时仍为本链路 BDP（约 1.23MB）的 3 倍，能跑满 70Mbps。
pub const DEFAULT_MAX_WINDOW: u64 = 4 * 1024 * 1024;

/// BBR 包装器：所有逻辑委托给原生 BBR，只在读取窗口时截断。
#[derive(Debug, Clone)]
pub struct CappedBbr {
    inner: Bbr,
    /// 允许的在途数据上限（字节）。
    /// 用原子值而不是普通 u64：外层自适应算法会每 2 秒根据实测丢包率调整，
    /// 同一条连接内立即生效，不需要重建连接。
    max_window: Arc<std::sync::atomic::AtomicU64>,
}

impl CappedBbr {
    /// 用给定配置和 MTU 构造；max_window 是对外可见窗口的硬上限。
    pub fn new(
        config: Arc<BbrConfig>,
        current_mtu: u16,
        max_window: Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        Self {
            inner: Bbr::new(config, current_mtu),
            max_window,
        }
    }
}

impl Controller for CappedBbr {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        // 发送记账交给原生 BBR，带宽估计依赖这部分数据
        self.inner.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        // ACK 记账同样委托，保持 BBR 的带宽/RTT 估计逻辑不变
        self.inner.on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        // 每批 ACK 结束时 BBR 会重算 pacing 和 cwnd，这里不做干预
        self.inner
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        // 丢包事件必须完整传给 BBR，否则它会误判链路状态
        self.inner
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        // MTU 变化会影响最小窗口，交给 BBR 自己处理
        self.inner.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        // 核心改动：无论 BBR 算出多大的窗口，对外都不超过 max_window。
        // quinn 的 pacing 也读这个值，所以发送速率会一起被压住。
        // 读原子值：自适应算法可在连接运行中实时调窗口，立即生效。
        let cap = self
            .max_window
            .load(std::sync::atomic::Ordering::Relaxed);
        self.inner.window().min(cap)
    }

    fn metrics(&self) -> ControllerMetrics {
        // 统计日志里显示的 cwnd 也要反映真实生效值，方便排查
        let cap = self
            .max_window
            .load(std::sync::atomic::Ordering::Relaxed);
        let mut m = self.inner.metrics();
        m.congestion_window = m.congestion_window.min(cap);
        m
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        // 初始窗口同样不能超过上限，避免起步阶段就突发过大
        let cap = self
            .max_window
            .load(std::sync::atomic::Ordering::Relaxed);
        self.inner.initial_window().min(cap)
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// 控制器工厂：每条 QUIC 连接建立时调用一次。
#[derive(Debug, Clone)]
pub struct CappedBbrConfig {
    inner: BbrConfig,
    max_window: Arc<std::sync::atomic::AtomicU64>,
}

impl CappedBbrConfig {
    /// 构造配置。
    /// 初始窗口固定 64KB：起步慢一点，避免一上来就把跨境链路打爆。
    pub fn new(max_window: Arc<std::sync::atomic::AtomicU64>) -> Self {
        let mut inner = BbrConfig::default();
        inner.initial_window(64 * 1024);
        Self { inner, max_window }
    }
}

impl Default for CappedBbrConfig {
    fn default() -> Self {
        Self::new(Arc::new(std::sync::atomic::AtomicU64::new(
            DEFAULT_MAX_WINDOW,
        )))
    }
}

impl ControllerFactory for CappedBbrConfig {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        // BbrConfig 需要 Arc 持有，这里克隆一份交给连接；
        // max_window 是共享原子值，克隆 Arc 后外层仍可实时调整
        Box::new(CappedBbr::new(
            Arc::new(self.inner.clone()),
            current_mtu,
            self.max_window.clone(),
        ))
    }
}
