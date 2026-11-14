// Package quic 把 flowtls 的伪造 TCP 连接接到 quic-go 上。
//
// 本子包是模块里唯一引入 quic-go 的地方：主包只管 net.PacketConn，
// 好处是 sing-box 升级 quic-go 时可能编译不过的只有这里。
//
// 本文件对应 legacy-rust:src/quic/config.rs。
package quic

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	quicgo "github.com/sagernet/quic-go"
)

// ALPN 必须与 Rust 侧一致，否则内层 TLS 握手直接失败。
const ALPN = "flowtls"

// 传输参数常量（与 Rust `quic/config.rs` 逐项对应）。
const (
	// initialMTU 是 QUIC 载荷 MTU。
	//
	// 跨境路径实测 MTU ≥ 1428，QUIC 载荷取 1332：
	// 外层 33 字节（5 记录头 + 12 nonce + 16 tag）+ IP 20 + TCP 32
	// （含 12 字节时间戳选项）= 总包 1417 字节，留有余量。
	initialMTU = 1332

	// maxIdleTimeout：空闲 30 秒断开。与 Rust `max_idle_timeout(30s)` 一致。
	maxIdleTimeout = 30 * time.Second

	// keepAlivePeriod：保活 10 秒，防止 NAT 映射过期。
	// 必须明显小于 maxIdleTimeout（3:1），否则一次丢包就可能被误判为掉线。
	keepAlivePeriod = 10 * time.Second

	// receiveWindow / streamReceiveWindow 与 Rust 一致。
	//
	// 窗口受 quinn 接收组装器 MAX_CHUNKS=1024 的硬限制：
	// 窗口 × 丢包率 ÷ 包大小 必须小于 1024，否则乱序空洞超限会直接断连。
	// 4MB 对应 30% 丢包时约 960 个空洞，刚好在安全线内；
	// 同时 4MB 仍是本链路 BDP（70Mbps × 141ms ≈ 1.23MB）的 3 倍，够跑满。
	receiveWindow       = 16 * 1024 * 1024
	streamReceiveWindow = 4 * 1024 * 1024

	// maxConcurrentStreams 与 Rust `max_concurrent_bidi_streams(1024)` 一致。
	// 单连接多流是核心优势：每条本地连接一条流，浏览器开几十个标签页也不够用
	// 更小的值。
	maxConcurrentStreams = 1024

	// maxDatagramFrameSize 与 Rust 的 datagram buffer 语义对齐：
	// UDP 不做应用层分片，单帧上限由 MTU 决定（约 1200 字节）。
	maxDatagramFrameSize = 1200
)

// ClientConfig 构造客户端 QUIC 配置（对应 Rust `client_config`）。
//
// 内层证书是服务端运行时自签的，无法预置信任链；安全性由外层 AEAD（密码）
// 保证，因此跳过证书校验——与 Rust 版设计一致。
//
// 注意：quic-go 的 TLS 配置是 Dial/Listen 的参数，不在 Config 里
// （quinn 把两者合在 ClientConfig/ServerConfig 里，这是库边界差异）。
func ClientConfig() *quicgo.Config {
	return baseConfig()
}

// ServerConfig 构造服务端 QUIC 配置（对应 Rust `server_config`）。
//
// 证书在 ServerTLSConfig() 里生成，由 Listen 传入。
func ServerConfig() *quicgo.Config {
	return baseConfig()
}

// ClientTLSConfig 返回客户端的内层 TLS 配置（跳过校验 + ALPN）。
func ClientTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{ALPN},
		MinVersion:         tls.VersionTLS13,
	}
}

// ServerTLSConfig 生成服务端内层 TLS 配置（自签证书 + ALPN）。
//
// 证书是运行时自签的：客户端本来就不校验，外层已有真实鉴权。
func ServerTLSConfig() (*tls.Config, error) {
	return selfSignedTLS()
}

// baseConfig 是两端共用的传输参数（对应 Rust `transport_config`）。
//
// 无法对齐的项（quic-go 没有对应配置）：
//   - `send_window = max_cwnd*2 clamp(2MB,16MB)`：quic-go 内部自行管理；
//   - `ack_frequency(max_ack_delay=5ms)`：quic-go 用对端协商的默认值。
// 这两项记录在此而不"绕过"——绕过需要改 quic-go 源码，不属于移植范围。
func baseConfig() *quicgo.Config {
	return &quicgo.Config{
		EnableDatagrams: true,
		// 必须关掉 PMTUD（路径 MTU 发现）。
		//
		// quinn 的 BlackHoleDetector 只要观测到「连续 4 个可疑丢包突发」
		// 就把 current_mtu 打回 min_mtu（默认 1200）。跨境链路 20~50% 丢包
		// 是常态，这个启发式必然误判——实测 MTU 从 1340 塌到 1200 再没爬回来，
		// 此后每包少装 140 字节有效载荷（-10.4%），包数增加 11.7%，
		// 丢包概率随之上升，形成恶性循环。
		//
		// 我们的路径 MTU 是自己说了算的：外层封装固定、头部长度固定。
		DisablePathMTUDiscovery: true,
		// InitialPacketSize 与 Rust 的 initial_mtu(1332) 逐字节对齐。
		InitialPacketSize: initialMTU,
		// MaxIdleTimeout / KeepAlivePeriod 与 Rust 一致。
		MaxIdleTimeout:  maxIdleTimeout,
		KeepAlivePeriod: keepAlivePeriod,
		// 握手空闲超时：Rust 由调用方自己控制（HANDSHAKE_TIMEOUT=15s），
		// quic-go 需要一个值兜底。取 10s（小于 15s，先由库报告）。
		HandshakeIdleTimeout: 10 * time.Second,

		// 接收窗口：同时设置 Initial 与 Max。
		// 只在 Initial < Max 时 quic-go 才会增长并回补 MAX_DATA；
		// 只设 Max 会退化成「一次给满却不再更新」。
		InitialConnectionReceiveWindow: receiveWindow,
		MaxConnectionReceiveWindow:     receiveWindow,
		InitialStreamReceiveWindow:     streamReceiveWindow,
		MaxStreamReceiveWindow:         streamReceiveWindow,

		// DATAGRAM 单帧上限（UDP 不分片）
		MaxDatagramFrameSize: maxDatagramFrameSize,

		// 流上限与 Rust 一致（1024）。
		MaxIncomingStreams:    maxConcurrentStreams,
		MaxIncomingUniStreams: maxConcurrentStreams,
	}
}

// selfSignedTLS 生成内层 QUIC 用的自签证书。
//
// 内层 TLS 只满足 QUIC 的协议要求，安全由外层 AEAD 保证，
// 因此公钥/私钥都无需持久化，也没有可信度要求。
func selfSignedTLS() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "flowtls"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"flowtls"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		// ALPN 必须与客户端一致，否则 TLS 握手会直接失败。
		NextProtos: []string{ALPN},
		MinVersion: tls.VersionTLS13,
	}, nil
}
