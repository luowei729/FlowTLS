package flowtls

// 本文件是 legacy-rust:src/proxy/mod.rs 里 `encode_target` / `decode_target`
// 的逐函数翻译。
//
// 地址帧是 QUIC 流的首帧，也是 UDP DATAGRAM 上行每包携带的目标地址。

import (
	"encoding/binary"
	"net/netip"
)

// 地址类型（与 SOCKS5 一致）。
const (
	// ATYPIPv4 是 IPv4 地址
	ATYPIPv4 byte = 1
	// ATYPDomain 是域名
	ATYPDomain byte = 3
	// ATYPIPv6 是 IPv6 地址
	ATYPIPv6 byte = 4
)

// EncodeAddressFrame 编码 `[ATYP][ADDR][PORT]`（**不含** 2 字节长度前缀）。
//
// 用于 UDP DATAGRAM 上行：外层已有 addrLen 字段，不能再套一层长度。
func EncodeAddressFrame(ap netip.AddrPort) ([]byte, error) {
	addr := ap.Addr()
	switch {
	case addr.Is4():
		out := make([]byte, 0, 1+4+2)
		out = append(out, ATYPIPv4)
		a4 := addr.As4()
		out = append(out, a4[:]...)
		return binary.BigEndian.AppendUint16(out, ap.Port()), nil
	case addr.Is6():
		out := make([]byte, 0, 1+16+2)
		out = append(out, ATYPIPv6)
		a16 := addr.As16()
		out = append(out, a16[:]...)
		return binary.BigEndian.AppendUint16(out, ap.Port()), nil
	default:
		return nil, ErrBadAddress
	}
}

// EncodeDomainFrame 编码域名形式的 `[ATYP=3][len][name][PORT]`（不含前缀）。
func EncodeDomainFrame(host string, port uint16) ([]byte, error) {
	name := []byte(host)
	if len(name) == 0 || len(name) > 255 {
		return nil, ErrBadAddress
	}
	out := make([]byte, 0, 1+1+len(name)+2)
	out = append(out, ATYPDomain, byte(len(name)))
	out = append(out, name...)
	return binary.BigEndian.AppendUint16(out, port), nil
}

// EncodeTarget 编码带 2 字节长度前缀的地址帧：
// `[len u16][ATYP][ADDR][PORT]`。
//
// 这是 QUIC 流首帧的格式——服务端先读 2 字节长度，再按长度读满。
// host 可以是 IP 也可以是域名（域名原样传给服务端解析，避免客户端 DNS 泄漏）。
func EncodeTarget(host string, port uint16) ([]byte, error) {
	var inner []byte
	var err error
	if a, perr := netip.ParseAddr(host); perr == nil {
		inner, err = EncodeAddressFrame(netip.AddrPortFrom(a, port))
	} else {
		inner, err = EncodeDomainFrame(host, port)
	}
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 2+len(inner))
	out = binary.BigEndian.AppendUint16(out, uint16(len(inner)))
	return append(out, inner...), nil
}

// DecodeAddressFrame 解析 `[ATYP][ADDR][PORT]`（不含长度前缀）。
//
// 返回 (host, port)。域名原样返回，由调用方决定是否本地解析。
func DecodeAddressFrame(buf []byte) (string, uint16, error) {
	if len(buf) < 1 {
		return "", 0, ErrBadAddress
	}
	switch buf[0] {
	case ATYPIPv4:
		if len(buf) < 1+4+2 {
			return "", 0, ErrBadAddress
		}
		var oct [4]byte
		copy(oct[:], buf[1:5])
		return netip.AddrFrom4(oct).String(),
			binary.BigEndian.Uint16(buf[5:7]), nil
	case ATYPIPv6:
		if len(buf) < 1+16+2 {
			return "", 0, ErrBadAddress
		}
		var oct [16]byte
		copy(oct[:], buf[1:17])
		return netip.AddrFrom16(oct).String(),
			binary.BigEndian.Uint16(buf[17:19]), nil
	case ATYPDomain:
		if len(buf) < 2 {
			return "", 0, ErrBadAddress
		}
		n := int(buf[1])
		if len(buf) < 2+n+2 {
			return "", 0, ErrBadAddress
		}
		host := string(buf[2 : 2+n])
		return host, binary.BigEndian.Uint16(buf[2+n : 2+n+2]), nil
	default:
		return "", 0, ErrBadAddress
	}
}
