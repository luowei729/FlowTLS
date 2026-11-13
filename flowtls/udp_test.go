package flowtls

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// TestUDPClientFrameRoundtrip 验证上行帧格式（与 Rust proxy::udp 逐字节一致）。
func TestUDPClientFrameRoundtrip(t *testing.T) {
	// 目标：8.8.8.8:53 → [ATYP=1][8,8,8,8][0,53]
	target := []byte{1, 8, 8, 8, 8, 0, 53}
	payload := []byte("dns query bytes")

	buf := EncodeClientDatagram(nil, 0xDEADBEEF, target, payload)
	if len(buf) != UDPHeaderLen+len(target)+len(payload) {
		t.Fatalf("长度错误: got %d want %d", len(buf),
			UDPHeaderLen+len(target)+len(payload))
	}
	// 手工核对前 6 字节
	if got := binary.BigEndian.Uint32(buf[0:4]); got != 0xDEADBEEF {
		t.Fatalf("session 错误: 0x%08x", got)
	}
	if got := binary.BigEndian.Uint16(buf[4:6]); got != uint16(len(target)) {
		t.Fatalf("addrLen 错误: %d", got)
	}

	session, gotTarget, gotPayload, ok := ParseClientDatagram(buf)
	if !ok {
		t.Fatal("解析失败")
	}
	if session != 0xDEADBEEF {
		t.Fatalf("session 不匹配: 0x%08x", session)
	}
	if !bytes.Equal(gotTarget, target) {
		t.Fatalf("目标帧不匹配: %v", gotTarget)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("载荷不匹配: %q", gotPayload)
	}
}

// TestUDPServerFrameRoundtrip 验证下行帧格式（只有 session + 载荷）。
func TestUDPServerFrameRoundtrip(t *testing.T) {
	payload := []byte("dns response")
	buf := EncodeServerDatagram(nil, 7, payload)
	session, got, ok := ParseServerDatagram(buf)
	if !ok || session != 7 || !bytes.Equal(got, payload) {
		t.Fatalf("下行帧往返失败: ok=%v session=%d payload=%q", ok, session, got)
	}
}

// TestUDPRejectsMalformed 验证畸形帧被拒绝而不是越界。
func TestUDPRejectsMalformed(t *testing.T) {
	cases := [][]byte{
		nil,
		{0, 0, 0, 1, 0},              // 太短
		{0, 0, 0, 1, 0, 0, 'x'},      // addrLen = 0（上行必须带地址）
		{0, 0, 0, 1, 0, 99, 1, 2, 3}, // addrLen 越界
	}
	for i, c := range cases {
		if _, _, _, ok := ParseClientDatagram(c); ok {
			t.Fatalf("case %d 应被拒绝", i)
		}
	}
	if _, _, ok := ParseServerDatagram([]byte{0, 0, 0}); ok {
		t.Fatal("下行帧过短应被拒绝")
	}
}

// TestUDPEmptyPayload 空载荷必须合法（部分 UDP 应用会发空包探测）。
func TestUDPEmptyPayload(t *testing.T) {
	target := []byte{1, 1, 1, 1, 1, 0, 53}
	buf := EncodeClientDatagram(nil, 1, target, nil)
	session, _, payload, ok := ParseClientDatagram(buf)
	if !ok || session != 1 || len(payload) != 0 {
		t.Fatalf("空载荷处理错误: ok=%v session=%d len=%d", ok, session, len(payload))
	}
}

// TestAddressFrameMatchesRust 地址帧必须与 Rust 的 encode_target 去掉长度前缀后一致。
func TestAddressFrameMatchesRust(t *testing.T) {
	// IPv4
	ap := netip.MustParseAddrPort("8.8.8.8:53")
	frame, err := EncodeAddressFrame(ap)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{1, 8, 8, 8, 8, 0, 53}
	if !bytes.Equal(frame, want) {
		t.Fatalf("IPv4 地址帧不匹配: %v want %v", frame, want)
	}
	// 能被同一套解析逻辑读回
	host, port, err := DecodeAddress(frame)
	if err != nil || host != "8.8.8.8" || port != 53 {
		t.Fatalf("解码失败: %s:%d %v", host, port, err)
	}

	// 域名
	dframe, err := EncodeDomainFrame("example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	if dframe[0] != AddrTypeDomain || int(dframe[1]) != len("example.com") {
		t.Fatalf("域名帧头错误: %v", dframe[:2])
	}
	h2, p2, err := DecodeAddress(dframe)
	if err != nil || h2 != "example.com" || p2 != 443 {
		t.Fatalf("域名解码失败: %s:%d %v", h2, p2, err)
	}

	// EncodeAddressFrame 必须等于 EncodeAddress 去掉 2 字节前缀
	full := EncodeAddress(ap)
	if !bytes.Equal(full[2:], frame) {
		t.Fatal("EncodeAddressFrame 必须等于 EncodeAddress 去掉长度前缀")
	}
}

// TestEncodeAddressRoundtrip 带长度前缀的版本往返。
func TestEncodeAddressRoundtrip(t *testing.T) {
	// 注意 IPv6 必须带方括号，否则 netip 解析会把它当成 host:port 的一部分
	for _, s := range []string{"1.2.3.4:443", "[2001:db8::1]:8080", "8.8.8.8:53"} {
		ap := netip.MustParseAddrPort(s)
		buf := EncodeAddress(ap)
		n := int(binary.BigEndian.Uint16(buf[0:2]))
		if n != len(buf)-2 {
			t.Fatalf("%s: 长度前缀 %d 与实际 %d 不符", s, n, len(buf)-2)
		}
		host, port, err := DecodeAddress(buf[2:])
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if port != ap.Port() {
			t.Fatalf("%s: 端口 %d != %d", s, port, ap.Port())
		}
		if host != ap.Addr().String() {
			t.Fatalf("%s: 地址 %s != %s", s, host, ap.Addr())
		}
	}
}

// TestDomainLengthBoundary 域名长度边界必须被正确处理。
func TestDomainLengthBoundary(t *testing.T) {
	if _, err := EncodeDomainFrame("", 80); err == nil {
		t.Fatal("空域名必须报错")
	}
	long := make([]byte, 256)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := EncodeDomainFrame(string(long), 80); err == nil {
		t.Fatal("超长域名必须报错")
	}
	// 255 字节是合法上限
	if _, err := EncodeDomainFrame(string(long[:255]), 80); err != nil {
		t.Fatalf("255 字节域名应合法: %v", err)
	}
}
