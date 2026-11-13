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
	// UDPSessionTimeout 是 UDP 会话空闲回收时间（秒）。
	UDPSessionTimeout int `json:"udp_session_timeout,omitempty"`
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
}
