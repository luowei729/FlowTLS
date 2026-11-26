package option

// Modified by FlowTLS (2026-11-15): 字段清单以 legacy-rust:src/config.rs 为唯一权威。
//
// 每条都对应 Rust 的一个字段（ServerFile / SiteFile / TlsFile /
// FakeTcpFile / NetFile / UdpFile / UserFile / ClientFile / FakeTcpClientFile）。
//
// **v1/v2 自造的字段已全部删除**，因为它们没有 Rust 对应物：
//
//	brutal_multiplier                    —— 当时 Rust 没有 Brutal
//	masquerade.proxy_url / rewrite_host  —— Rust 只 serve 静态目录
//
// up_mbps / down_mbps 在 2026-11-18 加回来了：拥塞控制换成 hysteria2
// 同款 Brutal，速率按本端配置，不再用 max_cwnd。max_cwnd 仍能解析，
// 只为兼容旧配置，Brutal 不读它。
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
	// Password 是**单密码**凭据（与 passwords / users 互斥）。
	//
	// 同时是外层 AEAD 的密钥来源（HKDF 输入），对应 Rust `password`。
	//
	// **多个客户端可以共用同一个密码**：凭据只有一份，谁拿到都能连。
	// 这是「一台服务端 + 多台设备」最省事的形态，也是推荐形态。
	Password string `json:"password,omitempty"`
	// Passwords 是**多密码**凭据表（与 password / users 互斥）。
	//
	// 每个元素是一条独立凭据，各自派生自己的 authID 与 ip_id_mark
	// （见 flowtls/mark.go）。多个客户端也可以共用其中一条（"默认密码"），
	// 所以下面这种配置同时表达了「朋友共用一个」与「自己的设备可单独吊销」：
	//
	//	"passwords": ["family-default", "my-phone", "my-laptop"]
	//
	// **不要重复填同一个密码**：一条密码本来就支持任意多个客户端，
	// 重复项会派生出同一个 authID 而被直接拒绝（静默去重会让日志里的
	// 凭据数少于配置项，那种故障极难查）。
	//
	// 没有用户名字段：线上只传 password 派生出的 authID，
	// 日志里的 uXXXXXXXX 同样从 authID 派生，无法反推密码。
	Passwords []string `json:"passwords,omitempty"`
	// Users 已废弃（rev.11 及更早的旧写法），仅为让旧配置继续启动：
	// 等价于 Passwords，其中 name 被**忽略**。
	//
	// 保留而不是删除，是因为 sing-box 会以 unknown field 拒绝启动，
	// 直接删字段会让所有旧 server.json 起不来。新配置请用 passwords。
	Users []FlowTLSUser `json:"users,omitempty"`
	// LocalIP 是回包时使用的源 IP。**留空即可，不需要配**。
	//
	// 服务端优先用「客户端本次发往的地址」（即入包的 IP 头目的地址）
	// 作为回包源地址——这是零配置且永远正确的做法：
	//   - NAT 云主机（Oracle Cloud 等）网卡上只有内网地址，
	//     包里的源 IP 就填那个内网地址，让网关做 1:1 SNAT；
	//   - 多 IP 主机（公网 + 内网同在一张网卡）时，客户端访问的是哪个
	//     地址就从哪个地址回，不依赖路由探测猜；
	//   - 单 IP 主机自然也对。
	//
	// 只有在特殊拓扑（例如要显式绑某块网卡的内网地址）时才需要填。
	LocalIP string `json:"local_ip,omitempty"`
	// IPIDMark 对应 Rust `faketcp.ip_id_magic`，是 IP ID 高字节分流标记。
	// **留空即从 password 派生**，两端自动一致；填了就用你填的值。
	IPIDMark uint16 `json:"ip_id_mark,omitempty"`
	// Handshake 对应 Rust `faketcp.handshake`：symbolic（默认）/ none。
	Handshake string `json:"handshake,omitempty"`
	// UpMbps / DownMbps 是 Brutal 的目标速率，单位 Mbps，与 hysteria2 的
	// `up_mbps` / `down_mbps` 同一含义。
	//
	// 方向按本端看，含义与 hysteria2 相同，建连时互相协商：
	//   本端发出去的速率 = min(本端 UpMbps, 对端 DownMbps)
	//   对端发过来的速率 = min(对端 UpMbps, 本端 DownMbps)
	// 0 表示用默认 1000（千兆）。协商走一条专门的 QUIC 流，
	// 不改外层伪 TCP 的报文格式。
	UpMbps   int `json:"up_mbps,omitempty"`
	DownMbps int `json:"down_mbps,omitempty"`
	// MaxCwnd 已废弃：Brutal 不读它。
	//
	// 保留这个字段只为兼容旧配置。rev.10 之前的 server.json 都写了
	// max_cwnd，删掉会导致 sing-box 以 unknown field 拒绝启动。
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

// FlowTLSUser 是已废弃的旧写法（rev.11 及更早），用 `passwords: ["..."]` 代替。
//
// 保留这个结构只为让旧配置不因 unknown field 而启动失败。
type FlowTLSUser struct {
	// Name 已废弃且**被忽略**。
	//
	// 服务端从 rev.12 起没有「用户」概念，只有「凭据」：一条密码就是一个
	// 凭据，多个客户端可以共用同一条。日志里的 uXXXXXXXX 由 authID 派生，
	// 不需要也不应该由配置提供——这样共用密码的设备天然不可区分。
	Name string `json:"name,omitempty"`
	// Password 是这条凭据的密码，等价于 passwords 数组里的一个元素。
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
	// SourcePort 是客户端源端口。**留空（0）即自动分配，这也是推荐值**。
	//
	// 一条 FlowTLS 隧道就是一个固定四元组（客户端 IP:源端口 →
	// 服务端 IP:端口），服务端靠它定位会话。固定源端口等于「一条隧道
	// 占一个端口」，而两台机器经同一个 NAT 去同一台服务端时，源端口
	// 相同就会四元组撞车——服务端只看得到一个会话，新 SYN 把旧会话
	// 踢掉，两边反复互踢。
	//
	// 旧版（≤ rev.6）之所以必须固定，是因为客户端防火墙规则按源端口
	// 匹配内核回的 RST。现在规则改为按**服务端地址**匹配（同一服务端
	// 的多个实例共享一组规则），与源端口无关，这个限制已消失。
	//
	// 所以这里不再提供固定端口选项：动态分配是默认且唯一推荐做法。
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
	// UpMbps / DownMbps 与入站同名，含义见入站注释。
	// 客户端的 UpMbps 是上传速率，DownMbps 是下载速率。
	UpMbps   int `json:"up_mbps,omitempty"`
	DownMbps int `json:"down_mbps,omitempty"`
	// MaxCwnd 已废弃，保留只为兼容旧的客户端配置，Brutal 不读它。
	MaxCwnd int64 `json:"max_cwnd,omitempty"`
	// UDPEnabled 对应 Rust `udp.enabled`（默认 true）。指针含义见入站同名注释。
	UDPEnabled *bool `json:"udp_enabled,omitempty"`
	// Network 声明支持的承载网络，默认 TCP+UDP。
	Network NetworkList `json:"network,omitempty"`
}
