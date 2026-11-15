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
