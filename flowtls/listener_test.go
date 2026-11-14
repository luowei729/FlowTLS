package flowtls

// 本文件覆盖 listener.go 的四元组复用清理（对应 Rust
// `conns.retain(|_, c| c.client != client)`）。

import (
	"net/netip"
	"testing"
)

// newTestListener 构造一个只用于分流逻辑的最小 Listener。
//
// raw 用一个不可发送的 rawSocket（sendFD = -1）：Send 会返回
// errSocketClosed，被 noteSendError 忽略，不需要 root 也不会真的发包。
// localIP 必须有值，否则构包时 As4() 会 panic。
func newTestListener() *Listener {
	return &Listener{
		raw:     newTestRawSocket(),
		port:    8443,
		mark:    IPIDMarkOf(0xF107),
		byAddr:  make(map[netip.AddrPort]*Session),
		pending: make(map[netip.AddrPort]*synState),
	}
}

// newTestRawSocket 返回一个「有源地址但发不出去」的 rawSocket。
func newTestRawSocket() *rawSocket {
	return &rawSocket{
		sendFD:  -1,
		recvFD:  -1,
		localIP: netip.MustParseAddr("10.0.0.10"),
	}
}

// newTestSession 构造一个可安全关闭的最小会话。
func newTestSession(peer netip.AddrPort, peerISN uint32) *Session {
	return &Session{
		raw:       newTestRawSocket(),
		peer:      peer,
		localPort: 8443,
		remotePort: peer.Port(),
		peerISN:   peerISN,
		mark:      IPIDMarkOf(0xF107),
		clock:     NewTcpClock(),
		rx:        make(chan []byte, 1),
		closeCh:   make(chan struct{}),
	}
}

// TestSYNWithNewISNDropsStaleSession 钉住「四元组复用时清掉旧会话」。
//
// 现场症状：客户端源端口固定，重启后四元组与旧会话完全相同。若不清理，
// 新连接的首包会被 handlePacket 的第 2 分支交给旧会话，按乱序包丢弃，
// 服务端永远走不到 handleFirstPacket。表现为客户端日志「通道已建立」
// 但所有请求超时，直到 120 秒空闲回收才恢复。
func TestSYNWithNewISNDropsStaleSession(t *testing.T) {
	l := newTestListener()
	addr := netip.MustParseAddrPort("203.0.113.7:44300")

	stale := newTestSession(addr, 111)
	l.byAddr[addr] = stale

	// 客户端重启：新 SYN 带新的 ISN
	l.handleSYN(addr, ParsedPacket{Src: addr.Addr(), SrcPort: addr.Port(), Seq: 222})

	if got := l.sessionFor(addr); got != nil {
		t.Fatal("新 SYNC 到达后旧会话必须被清掉，否则新连接的数据会被旧会话吞掉")
	}
	if !stale.closed.Load() {
		t.Fatal("旧会话必须被关闭（Close 会发 FIN 释放对端资源）")
	}
	if st, ok := l.pending[addr]; !ok || st.peerISN != 222 {
		t.Fatalf("pending 应记录新 SYN 的 ISN 222，实际 %+v", st)
	}
}

// TestSYNRetransmitKeepsSession 钉住「同一 ISN 的重传 SYN 不能误杀会话」。
//
// 客户端的 SYN 重传可能晚于服务端建会话到达；它的 ISN 与建连时一致，
// 必须识别为同一次握手，而不是当成新连接把已建好的会话关掉。
func TestSYNRetransmitKeepsSession(t *testing.T) {
	l := newTestListener()
	addr := netip.MustParseAddrPort("203.0.113.7:44300")

	sess := newTestSession(addr, 222)
	l.byAddr[addr] = sess

	// 握手完成后迟到的 SYN 重传：ISN 与建连时相同
	l.handleSYN(addr, ParsedPacket{Src: addr.Addr(), SrcPort: addr.Port(), Seq: 222})

	if got := l.sessionFor(addr); got != sess {
		t.Fatal("ISN 相同的 SYN 是重传，绝不能关掉已建立的会话")
	}
	if sess.closed.Load() {
		t.Fatal("重传 SYN 不应关闭会话")
	}
}
