package flowtls

import (
	"net/netip"
	"time"
)

// ProtocolVersion 是线上格式版本。
//
// Rust 版当前没有任何版本位，Go 版新增字段时无法协商；
// 这里预留一个常量，P1 落地时会写进 AEAD 的 AD（附加认证数据），
// 老版本解密失败即静默丢弃，行为与「密码错误」一致，不会暴露探测面。
const ProtocolVersion = 1

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

// ServerConfig 是服务端监听所需的参数。
type ServerConfig struct {
	// Listen 是本地监听地址与端口。
	Listen netip.AddrPort
	// Password 与客户端一致。
	Password string
	// LocalIP 是发给客户端时使用的源 IP。
	// 云主机在 NAT 后面时路由探测只能拿到内网地址，必须显式指定公网 IP。
	LocalIP netip.Addr
	// IPIDMark 与服务端 iptables 规则中的标记保持一致。
	IPIDMark uint16
	// SessionTimeout 是单条连接的空闲回收时间。
	SessionTimeout time.Duration
}
