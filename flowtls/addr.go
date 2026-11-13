package flowtls

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// SOCKS5 风格的地址类型。
//
// 与 Rust 侧 proxy::decode_target 保持一致，**不能换成 sing 的
// M.SocksaddrSerializer**：那个序列化没有 u16 长度前缀，而 Rust 服务端
// 会先读 2 字节长度再读满整个地址帧。换了就两端不通。
const (
	AddrTypeIPv4   uint8 = 1
	AddrTypeDomain uint8 = 3
	AddrTypeIPv6   uint8 = 4
)

// ErrBadAddress 表示地址帧格式非法。
var ErrBadAddress = errors.New("flowtls: 地址帧格式非法")

// EncodeAddress 把目标地址编码成「带 u16 长度前缀」的地址帧。
//
// 线上格式（流的第一段载荷）：
//
//	[总长 u16][ATYP u8][地址][端口 u16]
//
// 长度前缀是 Rust 服务端按「先读 2 字节再读满」逻辑解析的前提。
func EncodeAddress(addr netip.AddrPort) []byte {
	var inner []byte
	if addr.Addr().Is4() {
		o := addr.Addr().As4()
		inner = make([]byte, 0, 1+4+2)
		inner = append(inner, AddrTypeIPv4)
		inner = append(inner, o[:]...)
	} else {
		o := addr.Addr().As16()
		inner = make([]byte, 0, 1+16+2)
		inner = append(inner, AddrTypeIPv6)
		inner = append(inner, o[:]...)
	}
	inner = binary.BigEndian.AppendUint16(inner, addr.Port())
	return prefixLen(inner)
}

// EncodeDomainAddress 把域名目标编码成地址帧。
//
// 域名必须原样传下去，不能先在本地解析：服务端按域名做路由/规则/远端解析
// 是它存在的意义之一；本地解析还会让 DNS 泄漏到客户端侧。
func EncodeDomainAddress(host string, port uint16) ([]byte, error) {
	if len(host) == 0 || len(host) > 255 {
		return nil, fmt.Errorf("%w: 域名长度 %d 超出 1..255", ErrBadAddress, len(host))
	}
	inner := make([]byte, 0, 1+1+len(host)+2)
	inner = append(inner, AddrTypeDomain, byte(len(host)))
	inner = append(inner, host...)
	inner = binary.BigEndian.AppendUint16(inner, port)
	return prefixLen(inner), nil
}

// prefixLen 在地址帧前补上 2 字节总长。
func prefixLen(inner []byte) []byte {
	out := make([]byte, 0, 2+len(inner))
	out = binary.BigEndian.AppendUint16(out, uint16(len(inner)))
	return append(out, inner...)
}

// DecodeAddress 解析「不含长度前缀」的地址帧，返回目标。
// ipv6 为 true 时返回 IPv6 地址，域名返回 Addr 无效但 Host 有值。
func DecodeAddress(frame []byte) (host string, port uint16, err error) {
	if len(frame) < 1 {
		return "", 0, ErrBadAddress
	}
	switch frame[0] {
	case AddrTypeIPv4:
		if len(frame) < 1+4+2 {
			return "", 0, ErrBadAddress
		}
		var o [4]byte
		copy(o[:], frame[1:5])
		port = binary.BigEndian.Uint16(frame[5:7])
		return netip.AddrFrom4(o).String(), port, nil
	case AddrTypeIPv6:
		if len(frame) < 1+16+2 {
			return "", 0, ErrBadAddress
		}
		var o [16]byte
		copy(o[:], frame[1:17])
		port = binary.BigEndian.Uint16(frame[17:19])
		return netip.AddrFrom16(o).String(), port, nil
	case AddrTypeDomain:
		if len(frame) < 2 {
			return "", 0, ErrBadAddress
		}
		n := int(frame[1])
		if len(frame) < 2+n+2 {
			return "", 0, ErrBadAddress
		}
		port = binary.BigEndian.Uint16(frame[2+n : 4+n])
		return string(frame[2 : 2+n]), port, nil
	default:
		return "", 0, fmt.Errorf("%w: 未知 ATYP %d", ErrBadAddress, frame[0])
	}
}
