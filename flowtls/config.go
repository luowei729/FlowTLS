package flowtls

import (
	"net/netip"
	"time"
)

// ClientConfig 是客户端建立 Session 所需的参数。
type ClientConfig struct {
	// Server 是服务端的 IPv4 地址与端口。
	Server netip.AddrPort
	// Password 同时是外层 AEAD 的密钥来源（HKDF 输入）。
	Password string
	// SNI 只影响伪 ClientHello 的外观，不参与握手校验。
	// 传 IP 时不会生成 server_name 扩展（真实浏览器同样不发）。
	SNI string
	// SourcePort 固定源端口，供客户端 iptables 精确匹配内核 RST。
	SourcePort uint16
	// IPIDMark 是 IP ID 高字节分流标记，每个部署应不同。
	IPIDMark uint16
	// Handshake 为 false 时跳过三次握手（要求客户端有公网 IP）。
	Handshake bool
	// HandshakeTimeout 限制 SYN-ACK 的等待时间。
	HandshakeTimeout time.Duration
}

// User 是一个用户条目。
//
// 结构与 sing-box 的 hysteria2 / anytls / shadowsocks 完全一致：
// Name 只用于日志和统计，可留空；真正的凭证是 Password。
// 线上不会传 Name，也不会传 Password 本身——客户端发的是
// Password 派生出的 16 字节不透明 authID。
type User struct {
	Name     string
	Password string
}

// ServerConfig 是服务端监听所需的参数。
type ServerConfig struct {
	// Listen 是本地监听地址与端口。
	Listen netip.AddrPort
	// Password 是单用户模式下的唯一凭证。
	// Users 非空时忽略，仅为兼容只配一个密码的场景。
	Password string
	// Users 是多用户列表，非空时优先于 Password。
	Users []User
	// LocalIP 是发给客户端时使用的源 IP。
	// 云主机在 NAT 后面时路由探测只能拿到内网地址，必须显式指定公网 IP。
	LocalIP netip.Addr
	// IPIDMark 与服务端 iptables 规则中的标记保持一致。
	IPIDMark uint16
	// SessionTimeout 是单条连接的空闲回收时间。
	SessionTimeout time.Duration
}

// effectiveUsers 展开成用户列表：Users 非空优先，否则退回单密码模式。
//
// 空名字统一补成 user[N]，这样日志里绝不会出现「空字符串用户」这种
// 看不出是谁的记录。
func (c *ServerConfig) effectiveUsers() []User {
	if len(c.Users) > 0 {
		out := make([]User, len(c.Users))
		for i, u := range c.Users {
			if u.Name == "" {
				u.Name = "user[" + itoa(i) + "]"
			}
			out[i] = u
		}
		return out
	}
	return []User{{Name: "", Password: c.Password}}
}

// itoa 是 strconv.Itoa 的极简替代，避免为一行格式化引入依赖。
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}
