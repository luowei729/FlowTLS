package option

// FlowTLSInboundOptions 是 flowtls 入站配置。
//
// 结构刻意对齐 anytls/hysteria2：先内嵌通用字段，再只保留协议特有的项，
// 这样 detour / bind_interface / routing_mark / netns 等能力自动继承。
//
// 注意 flowtls 不绑定内核 TCP/UDP 端口，它自己开 AF_PACKET：
// listen / listen_port 用于计算 iptables 规则和伪装网站，不会被 bind。
type FlowTLSInboundOptions struct {
	ListenOptions
	// Password 同时是外层 AEAD 的密钥来源（HKDF 输入）。
	Password string `json:"password,omitempty"`
	// Users 预留多用户；为空时只用 Password 做单用户认证。
	Users []FlowTLSUser `json:"users,omitempty"`
	// LocalIP 是回包时使用的源 IP。
	// 云主机在 NAT 后面时路由探测只能拿到内网地址，必须显式指定公网 IP。
	LocalIP string `json:"local_ip,omitempty"`
	// IPIDMark 是 IP ID 高字节分流标记，每个部署应不同。
	IPIDMark uint16 `json:"ip_id_mark,omitempty"`
	// IPTablesMode 控制 raw 表规则的落地方式：
	//   none  — 不生成也不执行，部署方自行维护；
	//   print — 只打印规则文本（默认，最安全）；
	//   auto  — 启动时执行 iptables，需要额外确认。
	IPTablesMode string `json:"iptables_mode,omitempty"`
	// UDPSessionTimeout 是 UDP 会话空闲回收时间（秒），默认 60。
	//
	// 注意这与 fake-TCP 会话的空闲回收是两件事：
	// 前者是一次 SOCKS5 UDP ASSOCIATE，可能只查一次 DNS；
	// 后者是一条 QUIC 连接，用户在线就一直有流量。
	UDPSessionTimeout int `json:"udp_session_timeout,omitempty"`
	// UDPMaxSessions 是每条 QUIC 连接上同时存在的 UDP 会话上限，默认 8192。
	//
	// 超出后淘汰最久未活动的会话。这是兜底：即使 udp_session_timeout
	// 配得偏大，也不会无限增长。每个会话在服务端占一个出站 UDP socket，
	// 而整机临时端口只有约 28k 个——泄漏会拖垮整台机器而不只是隧道。
	UDPMaxSessions int `json:"udp_max_sessions,omitempty"`
	// Masquerade 是同端口真证书网站（应对主动端口探测）。
	//
	// 不配时 inbound 只做隧道，端口由其它进程（nginx/caddy）负责。
	// 配了就会****真 bind 内核 TCP 端口**：
	// flowtls 的伪造包在 raw 表被 DROP，剩下的包才落到这个站点上。
	Masquerade *FlowTLSMasqueradeOptions `json:"masquerade,omitempty"`
	// MaxCwnd 是 QUIC 拥塞窗口上限（字节），默认 8MB。
	//
	// 对齐 Rust 版 `net.max_cwnd`：与 hysteria2 默认流窗口（8MB）一致，
	// 按 1000Mbps × 70ms 的 BDP 留足余量。
	// 小带宽跨境链路（实际 20~50Mbps）建议调到 1MB 左右，否则丢包会明显变多。
	//
	// 它同时是硬上限和自适应算子的上界：服务端会按**全部连接**的
	// 汇总丢包率每 2 秒在此值之下浮动（>20% 缩 10%，<5% 涨 20%）。
	MaxCwnd int64 `json:"max_cwnd,omitempty"`
	// UpMbps 是**服务端自己的上行带宽**（Mbps），对应客户端的下行。
	//
	// 非 0 时启用 Brutal 拥塞控制（hy1 风格）：丢包不减窗，
	// 按这个带宽硬发。跨境高丢包链路（随机丢包 20~50%）下，
	// BBR 会把随机丢包当拥塞信号而反复降速，Brutal 直接无视丢包，
	// 只靠 QUIC 重传兜底，吞吐能高数倍。
	//
	// **必须按真实出口带宽填**：填大了把链路打爆（丢包更多），
	// 填小了跑不满。0（默认）表示用 BBR。
	UpMbps int64 `json:"up_mbps,omitempty"`
	// BrutalMultiplier 是 Brutal 的 cwnd 倍数（相对 BDP），默认 2.0（同 hy1）。
	BrutalMultiplier float64 `json:"brutal_multiplier,omitempty"`
}

// FlowTLSMasqueradeOptions 是同端口伪装站点的配置。
//
// 属性优先级：proxy_url > site_dir > 内置占位页。
// 前两者互斥，同时填会报错——静默二选一会让运维以为自己配的那个生效了。
type FlowTLSMasqueradeOptions struct {
	// SiteDir 是静态站点根目录。
	// 留空返回占位页——**生产环境必须填真实内容**，占位页本身就是指纹。
	SiteDir string `json:"site_dir,omitempty"`
	// CertificatePath / KeyPath 是**真证书**（Let's Encrypt / CloudFlare
	// Origin CA 等）。探测者能看到证书链，自签证书等于自报家门。
	CertificatePath string `json:"certificate_path,omitempty"`
	KeyPath         string `json:"key_path,omitempty"`
	// ProxyURL 开启反向代理模式：把请求转发到一个真实站点。
	//
	// 比静态文件更不容易被识破：静态站点的目录结构、响应头、404 页
	// 都是可枚举的；而反代拿到的就是一个真实在跑的站点，
	// 探测者看到的一切都与直接访问那个站点一致。
	//
	// 必须带 scheme（https:// 或 http://）。
	ProxyURL string `json:"proxy_url,omitempty"`
	// RewriteHost 决定转发时 Host 头用哪个：
	//   false（默认）—— 沿用客户端请求的 Host，目标站点按自己的虚拟主机规则处理；
	//   true          —— 改用 ProxyURL 里的 Host，适合目标站点对 Host 校验严的情形。
	//
	// **实战经验**：如果回源指向第三方站点（如 example.com），必须设 true，
	// 否则目标站点收到 Host=你的域名 会直接返回 403。
	// 回源指向自己的站点时保持 false 更自然。
	RewriteHost bool `json:"rewrite_host,omitempty"`
}

// FlowTLSUser 是多用户条目。
type FlowTLSUser struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}

// FlowTLSOutboundOptions 是 flowtls 出站配置。
type FlowTLSOutboundOptions struct {
	DialerOptions
	ServerOptions
	// Password 与服务端一致。
	Password string `json:"password,omitempty"`
	// SourcePort 固定源端口，供客户端 iptables 精确匹配内核 RST。
	SourcePort uint16 `json:"source_port,omitempty"`
	// IPIDMark 与客户端 iptables 规则里的标记保持一致。
	IPIDMark uint16 `json:"ip_id_mark,omitempty"`
	// SNI 只影响伪 ClientHello 的外观，不参与握手校验。
	SNI string `json:"sni,omitempty"`
	// IPTablesMode 控制客户端规则的落地方式，与服务端同名。
	//
	// 客户端规则的作用是屏蔽内核对伪连接回的 RST：
	// Session 走 raw socket，内核里没有对应 socket，收到 SYN-ACK 就会回 RST，
	// RST 是协议合法的终止信号，会让中间设备立刻拆掉 NAT 映射。
	//
	//   none  — 不生成也不执行，部署方自行维护；
	//   print — 只把规则文本写进日志（默认，最安全）；
	//   auto  — 启动时执行 iptables。
	IPTablesMode string `json:"iptables_mode,omitempty"`
	// DisableHandshake 关闭三次握手表演。
	//
	// **字段名故意是反向的**：Go 的 bool 零值是 false，若写成
	// `Handshake bool`，默认行为就变成「关闭握手」——而正确默认是
	// **开启**（严格 NAT/状态防火墙只放行握手完成的流量，不握手会直接被丢）。
	// 用反向字段才能让零值等于「安全默认」。
	//
	// 仅在客户端有公网 IP、且链路没有状态防火墙时才可关闭
	// （省一个 RTT）。
	DisableHandshake bool `json:"disable_handshake,omitempty"`
	// Network 声明支持的承载网络，默认 TCP+UDP。
	Network NetworkList `json:"network,omitempty"`
	// MaxCwnd 是 QUIC 拥塞窗口上限（字节），默认 8MB。
	//
	// 对齐 Rust 版 `net.max_cwnd`。**客户端与服务端应保持一致**：
	// 两端各算各的窗口，一边大一边小会让有效吞吐取小值。
	MaxCwnd int64 `json:"max_cwnd,omitempty"`
	// UpMbps 是**客户端自己的上行带宽**（Mbps）。
	//
	// 非 0 时启用 Brutal 拥塞控制（hy1 风格）：丢包不减窗，按这个带宽硬发。
	// **必须按真实上行带宽填**，填大了会自己把链路打爆。
	// 0（默认）表示用 BBR。
	UpMbps int64 `json:"up_mbps,omitempty"`
	// BrutalMultiplier 是 Brutal 的 cwnd 倍数（相对 BDP），默认 2.0（同 hy1）。
	BrutalMultiplier float64 `json:"brutal_multiplier,omitempty"`
}
