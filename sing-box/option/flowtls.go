package option

// Modified by FlowTLS (2026-11-15): 字段清单以 legacy-rust:src/config.rs 为唯一权威。
//
// 每条都对应 Rust 的一个字段（ServerFile / SiteFile / TlsFile /
// FakeTcpFile / NetFile / UdpFile / UserFile / ClientFile / FakeTcpClientFile）。
//
// **v1/v2 自造的字段已全部删除**，因为它们没有 Rust 对应物：
//
//	up_mbps / brutal_multiplier          —— Rust 没有 Brutal（只有 BBR + 自适应窗口）
//	masquerade.proxy_url / rewrite_host  —— Rust 只 serve 静态目录
//	masquerade.enabled                   —— Rust 配了 site 就是开，没配就是关
//	iptables_mode = "print"              —— Rust 只有 auto / none
//
// 保留它们比删除更危险：用户配上去以后没有任何效果，
// 只能靠读源码才知道「这个字段是假的」。

// FlowTLSInboundOptions 是 flowtls 入站配置。
//
// 结构对齐 Rust `ServerFile`：先内嵌通用字段，再只保留协议特有的项，
// 这样 detour / bind_interface / routing_mark / netns 等能力自动继承。
//
// 注意 flowtls 不用内核 TCP/UDP 端口承载隧道，它自己开 AF_PACKET：
// listen / listen_port 用于计算 iptables 规则与伪装网站，隧道本身不占用。
type FlowTLSInboundOptions struct {
	ListenOptions
	// Password 同时是外层 AEAD 的密钥来源（HKDF 输入）。对应 Rust `password`。
	Password string `json:"password,omitempty"`
	// Users 对应 Rust `users`；为空时只用 Password 做单用户认证。
	Users []FlowTLSUser `json:"users,omitempty"`
	// LocalIP 对应 Rust `faketcp.local_ip`，是回包时使用的源 IP。
	//
	// NAT 云主机上路由探测只能拿到内网地址（如 10.0.0.10），
	// 而对外源 IP 是网关 SNAT 后的公网地址。此时必须显式填**内网地址**，
	// 让网关做 1:1 SNAT；填公网地址会被网关反欺骗静默丢弃。
	LocalIP string `json:"local_ip,omitempty"`
	// IPIDMark 对应 Rust `faketcp.ip_id_magic`，是 IP ID 高字节分流标记。
	// 每个部署应不同；默认 0xF100 | 0x07。
	IPIDMark uint16 `json:"ip_id_mark,omitempty"`
	// IPTablesMode 对应 Rust `net.mode`，只有两个合法值：
	//   none  — 不生成也不执行，部署方自行维护规则；
	//   auto  — 启动时幂等写入 iptables（写后不清理，见 AGENTS 约束 13）。
	IPTablesMode string `json:"iptables_mode,omitempty"`
	// Handshake 对应 Rust `faketcp.handshake`：symbolic（默认）/ none。
	Handshake string `json:"handshake,omitempty"`
	// MaxCwnd 对应 Rust `net.max_cwnd`，QUIC 拥塞窗口硬上限（字节，默认 8MB）。
	//
	// 它同时是自适应算子的上界：服务端按**全部连接**的汇总丢包率每 2 秒
	// 在此值之下浮动（>20% 缩 10%，<5% 涨 20%）。
	MaxCwnd int64 `json:"max_cwnd,omitempty"`
	// UDPEnabled 对应 Rust `udp.enabled`（默认 true）。
	//
	// 服务端关掉后所有 datagram 被读出丢弃，避免误开成公网 UDP 反射器。
	//
	// 用 *bool 而不是 bool：Rust 的 serde 默认值是 true，而 Go 的 bool 零值是
	// false。若用 bool，省略字段就等于关闭 UDP，与 Rust 行为相反。
	// 指针的 nil 才能表达「没填」，由 UDPOn() 统一解释。
	UDPEnabled *bool `json:"udp_enabled,omitempty"`
	// UDPMaxSessions 对应 Rust `udp.max_sessions`（默认 256）。
	//
	// 每个 UDP 会话在服务端占一个出站 UDP socket，
	// 而整机临时端口只有约 28k 个。
	UDPMaxSessions int `json:"udp_max_sessions,omitempty"`
	// UDPSessionTimeout 对应 Rust `udp.timeout_secs`（默认 120）。
	//
	// 这与 fake-TCP 会话的空闲回收是两件事：
	// 前者是一次 UDP 会话（可能只查一次 DNS），
	// 后者是一条 QUIC 连接，用户在线就一直有流量。
	UDPSessionTimeout int `json:"udp_session_timeout,omitempty"`
	// Masquerade 对应 Rust `site` + `tls`：同端口真证书网站。
	//
	// 不配时 inbound 只做隧道，端口由其它进程（nginx/caddy）负责，
	// 与 Rust 版不配 site 时的行为一致。
	Masquerade *FlowTLSMasqueradeOptions `json:"masquerade,omitempty"`
}

// FlowTLSMasqueradeOptions 对应 Rust `SiteFile` + `TlsFile`。
//
// 行为完全照 `legacy-rust:src/site/mod.rs`：
//
//	TLS 1.3，ALPN 只宣告 http/1.1（真实世界大量站点如此，不成为指纹）
//	GET/HEAD      → 静态文件 → 目录 index.html → 内置占位页
//	/robots.txt   → Allow: /
//	/favicon.ico  → 204（比 404 更像正常站点）
//	其它方法      → 405
//	keep-alive 由 Connection 头决定；单请求头上限 16KB；连接上限 30s
//
// **没有 proxy_url**：Rust 没那么做。
type FlowTLSMasqueradeOptions struct {
	// SiteDir 对应 Rust `site.dir`，静态站点根目录。
	// 留空返回内置占位页——**生产环境必须填真实内容**，占位页本身就是指纹。
	SiteDir string `json:"site_dir,omitempty"`
	// CertificatePath / KeyPath 对应 Rust `tls.cert` / `tls.key`。
	// **必须是真证书**（Let's Encrypt / CloudFlare Origin CA 等）：
	// 探测者能看到证书链，自签证书等于自报家门。
	CertificatePath string `json:"certificate_path,omitempty"`
	KeyPath         string `json:"key_path,omitempty"`
}

// FlowTLSUser 对应 Rust `UserFile`。
type FlowTLSUser struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}

// FlowTLSOutboundOptions 是 flowtls 出站配置。
//
// 结构对齐 Rust `ClientFile` + `FakeTcpClientFile`。
type FlowTLSOutboundOptions struct {
	DialerOptions
	ServerOptions
	// Password 对应 Rust `password`。
	Password string `json:"password,omitempty"`
	// SourcePort 对应 Rust `faketcp.source_port`，固定源端口。
	//
	// 为什么要固定：客户端 iptables 规则按源端口精确匹配内核发回的 RST。
	// 端口随机的话规则写不出来，只能整段 DROP。
	// 重启后四元组完全相同——这正是「纯 SYN 判断必须优先于已有会话」
	// 那条约束的来源。
	SourcePort uint16 `json:"source_port,omitempty"`
	// IPIDMark 对应 Rust `faketcp.ip_id_magic`，与客户端 iptables 规则一致。
	IPIDMark uint16 `json:"ip_id_mark,omitempty"`
	// Handshake 对应 Rust `faketcp.handshake`：symbolic（默认）/ none。
	//
	// 用字符串而不是 Go 惯用的反向 bool：
	// bool 零值是 false，若写成 `Handshake bool`，默认行为就变成「关闭握手」，
	// 而正确默认是**开启**——严格 NAT/状态防火墙只放行握手完成的流量。
	Handshake string `json:"handshake,omitempty"`
	// SNI 对应 Rust `sni`，只影响伪 ClientHello 的外观，不参与握手校验。
	SNI string `json:"sni,omitempty"`
	// IPTablesMode 对应 Rust `net.mode`，与服务端同名、同语义。
	//
	// 客户端规则的作用是屏蔽内核对伪连接回的 RST：
	// Session 走 raw socket，内核里没有对应 socket，收到 SYN-ACK 就会回 RST，
	// 而 RST 是协议合法的终止信号，会让中间设备立刻拆掉 NAT 映射。
	IPTablesMode string `json:"iptables_mode,omitempty"`
	// MaxCwnd 对应 Rust `net.max_cwnd`。
	// **客户端与服务端应保持一致**：两端各算各的窗口，取小值生效。
	MaxCwnd int64 `json:"max_cwnd,omitempty"`
	// UDPEnabled 对应 Rust `udp.enabled`（默认 true）。指针含义见入站同名注释。
	UDPEnabled *bool `json:"udp_enabled,omitempty"`
	// Network 声明支持的承载网络，默认 TCP+UDP。
	Network NetworkList `json:"network,omitempty"`
}
