package flowtls

// 本文件对应 legacy-rust:src/config.rs 里传输层关心的字段，以及
// legacy-rust:src/check.rs 里的取值校验。
//
// 只保留协议本身需要的项；TLS 证书、伪装站点等属于 sing-box 适配层
// （option/flowtls.go）的职责，不在这里重复定义。

import (
	"errors"
	"fmt"
	"net/netip"
)

// 握手模式。取值与 Rust `faketcp.handshake` 一致。
const (
	// HandshakeSymbolic 执行标准三次握手（默认）。
	//
	// 严格 NAT/状态防火墙只放行「SYN → SYN-ACK → ACK」之后的流量，
	// 不握手会被直接丢弃。代价是建连多 1 个 RTT。
	HandshakeSymbolic = "symbolic"
	// HandshakeNone 跳过握手（要求客户端有公网 IP，且链路无状态防火墙）。
	HandshakeNone = "none"
)

// ParseHandshake 校验 faketcp.handshake 取值（Rust check.rs:497）。
func ParseHandshake(mode string) (string, error) {
	switch mode {
	case "":
		return HandshakeSymbolic, nil
	case HandshakeSymbolic, HandshakeNone:
		return mode, nil
	default:
		return "", fmt.Errorf("flowtls: 未知 handshake %q（可选 symbolic / none）", mode)
	}
}

// validatePortRange 已不需要：SourcePort 是 uint16，不可能超出上界，
// 而 0 现在有明确语义（自动分配）。保留这条注释是为了不让后来的人
// 以为漏了校验。

// ClientConfig 是客户端的传输层参数。
type ClientConfig struct {
	// Server 是服务端地址（只支持 IPv4）。
	Server netip.AddrPort
	// Password 是外层 AEAD 的密钥来源。
	Password string
	// SNI 只影响伪 ClientHello 的外观，不参与握手校验。
	SNI string
	// SourcePort 是客户端源端口。**0 表示自动分配**（推荐）。
	//
	// 自动分配的必要性：一条 FlowTLS 隧道就是一个固定四元组
	// （客户端 IP:源端口 → 服务端 IP:端口），服务端靠它定位会话。
	// 固定源端口等于「一条隧道占一个端口」，当两台机器经同一个 NAT
	// 去同一台服务端时，源端口相同就会四元组撞车，服务端只能看到一个
	// 会话，新 SYN 会把旧会话踢掉（真机踩过：haproxy 反复把后端标 DOWN）。
	//
	// 旧版必须固定，是因为防火墙规则按源端口匹配内核回的 RST。
	// 现在规则改成按服务端地址匹配（见 rules.go 的 clientRules），
	// 与源端口无关，这个限制已消失。
	//
	// 显式填一个非 0 值仍然有效：部署方需要可预测的四元组时（例如
	// 对端防火墙按源端口放行）可以钉死，此时行为与旧版完全一致。
	SourcePort uint16
	// IPIDMark 是 IP ID 分流标记（用高字节）。
	IPIDMark uint16
	// Handshake 是握手模式（HandshakeSymbolic / HandshakeNone）。
	Handshake string
	// Logger 是诊断日志出口；nil 表示静默（见 log.go 的说明）。
	//
	// 适配层直接传 sing-box 的 logger，日志级别因此完全由 `log.level` 控制，
	// flowtls 不需要自己的开关。**不要在 Validate 里给它赋默认值**：
	// 静默是刻意的默认行为，回退到标准库会让「不注入」等于「照样吵」。
	Logger Logger
}

// Validate 校验客户端配置（对应 Rust check.rs 的客户端分支）。
func (c *ClientConfig) Validate() error {
	if !c.Server.IsValid() {
		return errors.New("flowtls: server 不能为空")
	}
	if !c.Server.Addr().Is4() {
		return fmt.Errorf("flowtls: server 必须是 IPv4 地址，得到 %s", c.Server.Addr())
	}
	if c.Server.Port() == 0 {
		return errors.New("flowtls: server_port 不能为 0")
	}
	if c.Password == "" {
		return errors.New("flowtls: password 不能为空")
	}
	// SourcePort == 0 是合法的：表示让 Dial 自动分配一个未在用的端口。
	// 参数是 uint16，不存在超出 65535 的可能，所以无需额外范围校验。
	//
	// IPIDMark == 0 表示**从 password 派生**，这是推荐值也是默认值。
	//
	// 为什么可以派生而 source_port 不行：source_port 是本机资源，只需本地
	// 唯一；而 ip_id_mark 是两端共享的标识，必须两端算出同一个值。
	// password 本来就两端共享且每个部署不同，所以它是最合适的派生源
	// （见 mark.go 的完整论证）。
	if c.IPIDMark == 0 {
		c.IPIDMark = DeriveIPIDMark(c.Password)
	}
	if _, err := ParseHandshake(c.Handshake); err != nil {
		return err
	}
	if c.Handshake == "" {
		c.Handshake = HandshakeSymbolic
	}
	return nil
}

// User 是一个用户条目。线上只传 password 派生出的 authID，name 仅用于日志。
type User struct {
	Name     string
	Password string
}

// ServerConfig 是服务端的传输层参数。
type ServerConfig struct {
	// Listen 是监听地址（只用于计算规则与端口，不会 bind 内核端口）。
	Listen netip.AddrPort
	// Password 是单用户模式的密码（Users 为空时使用）。
	Password string
	// Users 是多用户表（非空时优先于 Password）。
	Users []User
	// LocalIP 是回包时使用的源 IP；为空时按路由探测。
	//
	// 与 Rust 一致：**不做「是否真的配在本机网卡上」的校验**。
	// 走 IPPROTO_RAW 时内核会用出接口地址回填 saddr，
	// 所以 NAT 云主机填公网地址也能正常工作。
	LocalIP netip.Addr
	// IPIDMark 是 IP ID 分流标记（用高字节）。
	IPIDMark uint16
	// Handshake 对应 Rust `faketcp.handshake`（两端共用同一个配置结构）。
	//
	// 服务端本身不使用它（服务端总是被动的），但 Rust 的 `FakeTcpFile`
	// 两端共用，`check.rs:497` 对两端都做取值校验，因此这里保留以保持
	// 配置语义一致（写错值会在两端都报错，而不是只在客户端报）。
	Handshake string
	// UDPEnabled 对应 Rust `udp.enabled`（默认 true）。
	//
	// 默认值在 Rust 里是 true，而 Go 的 bool 零值是 false，所以这里用指针
	// 让调用方显式表达「没填」，由 UDPOn() 统一解释。
	UDPEnabled *bool
	// UDPMaxSessions 是每条连接上同时存在的 UDP 会话上限。
	UDPMaxSessions int
	// UDPTimeoutSecs 是 UDP 会话空闲回收秒数。
	UDPTimeoutSecs int
	// Logger 是诊断日志出口；nil 表示静默（语义与 ClientConfig.Logger 相同）。
	//
	// 服务端所有会话共享 Listener 的 logger：伪造 TCP 的收包路径是
	// 单协程共享 socket，按会话注入只会让同一份日志被重复打出来。
	Logger Logger
}

// UDPOn 返回 UDP 是否启用（默认 true，与 Rust `default_udp_enabled` 一致）。
func (s *ServerConfig) UDPOn() bool {
	return s.UDPEnabled == nil || *s.UDPEnabled
}

// Validate 校验服务端配置（对应 Rust check.rs 的服务端分支）。
func (s *ServerConfig) Validate() error {
	if !s.Listen.IsValid() || s.Listen.Port() == 0 {
		return errors.New("flowtls: listen/listen_port 不合法")
	}
	users, err := s.effectiveUsers()
	if err != nil {
		return err
	}
	if len(users) == 0 {
		return errors.New("flowtls: 服务端必须配置 password 或 users")
	}
	// IPIDMark 参见 Marks()：0 表示按每个用户的 password 各自派生。
	// 服务端**不再**在这里填一个全局值，因为它要为每个用户维护各自的标记。
	if s.IPIDMark != 0 {
		// 显式配置时所有用户共用一个标记（兼容旧配置与特殊部署）。
		s.IPIDMark &= 0xFF00
		if s.IPIDMark == 0 {
			return errors.New("flowtls: ip_id_mark 的高字节不能为 0")
		}
	}
	if _, err := ParseHandshake(s.Handshake); err != nil {
		return err
	}
	if s.Handshake == "" {
		s.Handshake = HandshakeSymbolic
	}
	if s.UDPMaxSessions <= 0 {
		s.UDPMaxSessions = 256
	}
	if s.UDPTimeoutSecs <= 0 {
		s.UDPTimeoutSecs = 120
	}
	return nil
}

// effectiveUsers 归一出实际生效的用户表（与 Rust `ClientFile::effective_users`
// / `ServerFile::users` 的取舍一致）：Users 非空则优先，否则退回单用户模式。
func (s *ServerConfig) effectiveUsers() ([]User, error) {
	if len(s.Users) > 0 {
		// 同时填 password 与 users 是**错误**，不是"以 users 为准"。
		//
		// 静默忽略顶层 password 会形成一个很难发现的陷阱：
		//   - 它既不能用来登录（authID 只在 users 里）；
		//   - 它也不参与 ip_id_mark 派生（mark 只从 users 派生）；
		//   - 但配置文件里它明明白白写着，运维会以为它是兜底凭据。
		// 而 ip_id_mark 不一致的症状是"隧道完全不通"，排查成本极高，
		// 所以这里直接拒绝，逼配置只表达一件事。
		if s.Password != "" {
			return nil, errors.New(
				"flowtls: password 与 users 不能同时配置 —— " +
					"只配 password 表示单用户；配 users 表示多用户，" +
					"此时 password 会被完全忽略（既不能登录、也不参与 ip_id_mark 派生）")
		}
		out := make([]User, 0, len(s.Users))
		for _, u := range s.Users {
			if u.Password == "" {
				return nil, fmt.Errorf("flowtls: 用户 %q 的 password 不能为空", u.Name)
			}
			out = append(out, u)
		}
		return out, nil
	}
	if s.Password != "" {
		return []User{{Name: "", Password: s.Password}}, nil
	}
	return nil, nil
}

// Marks 返回本服务端会接受的全部 ip_id_mark。
//
// 为什么是**一组**而不是一个：服务端在内核层就要判断「这个包是不是我们的」
// （rules.go 写 drop 规则）和「这个 SYN 要不要回 SYN-ACK」
// （listener.go 的 protocolOwned），而这两件事都发生在**解密之前** ——
// 那时还不知道是哪个用户。
//
// 所以只能把每个用户的 password 都派生一遍，全部纳入识别范围：
//
//	用户 A → password_A → mark_A
//	用户 B → password_B → mark_B
//	服务端接受 mark_A 与 mark_B
//
// 包数很少（用户数十个量级），所以 nft 规则数与 map 大小都可以忽略。
//
// 显式配置了 ip_id_mark 时只返回那一个值（兼容旧配置：
// 旧部署可能已经和客户端约定了一个手工值）。
func (s *ServerConfig) Marks() []uint16 {
	if s.IPIDMark != 0 {
		return []uint16{s.IPIDMark & 0xFF00}
	}
	users, err := s.effectiveUsers()
	if err != nil || len(users) == 0 {
		// Validate 已校验过，这里只是防御：退回默认值，
		// 保证不会返回空集（空集会让服务端一个包都认不出来）。
		return []uint16{IPIDMark}
	}
	out := make([]uint16, 0, len(users))
	seen := make(map[uint16]struct{}, len(users))
	for _, u := range users {
		m := DeriveIPIDMark(u.Password)
		// 去重：不同部署/不同用户理论上有极小概率派生出同一个标记，
		// 那样规则会重复写两遍（无害但脏），去重更干净。
		if _, dup := seen[m]; dup {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	return out
}
