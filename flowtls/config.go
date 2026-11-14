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

// ClientConfig 是客户端的传输层参数。
type ClientConfig struct {
	// Server 是服务端地址（只支持 IPv4）。
	Server netip.AddrPort
	// Password 是外层 AEAD 的密钥来源。
	Password string
	// SNI 只影响伪 ClientHello 的外观，不参与握手校验。
	SNI string
	// SourcePort 是固定源端口，供客户端 iptables 精确匹配内核 RST。
	SourcePort uint16
	// IPIDMark 是 IP ID 分流标记（用高字节）。
	IPIDMark uint16
	// Handshake 是握手模式（HandshakeSymbolic / HandshakeNone）。
	Handshake string
	// NetMode 是 iptables 规则模式（ModeAuto / ModeNone）。
	NetMode string
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
	if c.SourcePort == 0 {
		return errors.New("flowtls: source_port 不能为 0")
	}
	if c.IPIDMark == 0 {
		c.IPIDMark = IPIDMark | 0x07
	}
	if _, err := ParseHandshake(c.Handshake); err != nil {
		return err
	}
	if c.Handshake == "" {
		c.Handshake = HandshakeSymbolic
	}
	mode, err := ParseMode(c.NetMode)
	if err != nil {
		return err
	}
	c.NetMode = mode
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
	// NetMode 是 iptables 规则模式。
	NetMode string
	// UDPEnabled 对应 Rust `udp.enabled`（默认 true）。
	//
	// 默认值在 Rust 里是 true，而 Go 的 bool 零值是 false，所以这里用指针
	// 让调用方显式表达「没填」，由 UDPOn() 统一解释。
	UDPEnabled *bool
	// UDPMaxSessions 是每条连接上同时存在的 UDP 会话上限。
	UDPMaxSessions int
	// UDPTimeoutSecs 是 UDP 会话空闲回收秒数。
	UDPTimeoutSecs int
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
	if s.IPIDMark == 0 {
		s.IPIDMark = IPIDMark | 0x07
	}
	if _, err := ParseHandshake(s.Handshake); err != nil {
		return err
	}
	if s.Handshake == "" {
		s.Handshake = HandshakeSymbolic
	}
	mode, err := ParseMode(s.NetMode)
	if err != nil {
		return err
	}
	s.NetMode = mode
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
