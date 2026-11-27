package flowtls

import "errors"

// 本文件是**跨平台**的 socket 层常量，两个实现（Linux / Windows）共用。
//
// 之所以单独一个文件：这些常量原来住在 `socket_linux.go` 里，Windows 版
// 因为 build tag 看不到它们，编译时会报一串 `undefined: maxSendBatch`。
// 放在无 tag 的文件里比在每个平台各写一份更安全（两份必然会漂移）。

// maxSendBatch 是一次批量发送最多带多少个报文（对应 Rust `MAX_BATCH`）。
//
// Linux 上它是 `sendmmsg` 的批大小；Windows 上它是 WinDivert `SendBatch`
// 的包数（驱动的硬上限是 255，这里取 64 保持两端语义一致）。
//
// 从 32 提到 64 的依据（Linux 实测）：单次 sendto 在 1 核 ARM 上约 34µs，
// 64 个报文 = 一次 syscall 交 90KB 载荷。不取更大值是因为发送队列深度
// 只有 64（`txQueueDepth`），一次排空就够。
const maxSendBatch = 64

// recvHandoffDepth 是「收包协程 → 主循环」交接队列的深度。
//
// **这是 Rust 原版的值，Go 移植时被误改成了 1**。
// `legacy-rust:src/client.rs:485` 的原文：
//
//	// 用有界 channel：下行大流量时最多积压 8192 个包，超过后收包线程阻塞，
//	// 由内核 socket 缓冲区兜底丢包（QUIC 会重传），避免 unbounded 把内存吃光。
//	let (pkt_tx, mut pkt_rx) = mpsc::channel::<...>(8192);
//
// 容量为 1 时的后果：主循环一旦卡在 deliver（rx 满时阻塞），读协程最多
// 再塞 1 个包就阻塞在 `frames <-`，socket 不再被读，内核 AF_PACKET 队列
// 积压后被丢弃；同时主循环回不到 select，5ms 心跳失效，延迟确认也跟着停摆。
// Rust 的抗抖动能力是 Go 的 8192 倍。
//
// 恢复该值属于**对齐参考实现**，不引入任何新语义（队列满时仍是阻塞，不丢包）。
// 内存代价：8192 个切片头（约 200KB）+ 引用指向的帧数据（受内核队列背压限制）。
const recvHandoffDepth = 8192

// socketRole 是建 socket 时需要的角色信息。
//
// **只有 Windows 用得到**：WinDivert 的过滤器在 Open() 时固定，必须知道
// 自己是服务端（按监听端口过滤）还是客户端（按 4 元组端口过滤）。
// Linux 的 AF_PACKET 不需要角色信息（它收整机流量，由上层按四元组分流），
// 那份实现忽略这个参数——保留它只是为了让两个平台共用同一个构造入口。
type socketRole struct {
	// server 表示本端是服务端。
	server bool
	// listenPort 是服务端监听端口（server=true 时使用）。
	listenPort uint16
	// serverPort / sourcePort 是客户端用的两个端口（server=false 时使用）。
	serverPort uint16
	sourcePort uint16
}

// errSocketClosed 在 raw socket 已关闭后返回。
//
// 必须与真实发送失败区分：Close 与「收包协程仍在发纯 ACK」天然存在竞态，
// 而这属于正常关闭路径，不应该被当成链路故障计数/告警。
//
// 放在共享文件里是因为两个平台的实现都要用它（session.go 的错误分类也读它）。
var errSocketClosed = errors.New("flowtls: raw socket 已关闭")

// frameHandle 是收包时由平台实现附加的不透明元数据，**必须与那一帧配对使用**。
//
// 为什么需要它：WinDivert 要求「重新注入」时带上原始 WINDIVERT_ADDRESS
// （里面含有 IfIdx，缺了它包会落到不存在的接口上）。而收包与处理不在同一个
// 协程里（recvLoop 用 channel 交接），如果把这个地址存在 rawSocket 的字段上，
// 下一帧的读取就会把它覆盖 —— 表现为「伪装站偶发连不上」，是那种查一天都
// 查不出来的问题。
//
// Linux 的 AF_PACKET 用不到它（被动复制，不需要注入），恒为 nil。
type frameHandle any
