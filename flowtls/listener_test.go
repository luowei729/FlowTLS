package flowtls

// 本文件覆盖 listener.go 的四元组复用清理（对应 Rust
// `conns.retain(|_, c| c.client != client)`）。

import (
	"net/netip"
	"testing"
	"time"
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
		marks:   []uint16{IPIDMarkOf(0xF107)},
		byAddr:  make(map[netip.AddrPort]*Session),
		pending: make(map[netip.AddrPort]*synState),
		// 手工构造会绕过 NewListener 的 loggerOr 归一，
		// 必须显式给个实现：nil 接口调方法会 panic。
		logger: nopLogger{},
	}
}

// newTestRawSocket 由平台测试文件提供（socket_linux_test.go / socket_windows_test.go）：
// 两边的 rawSocket 字段完全不同，无法共用一份构造。

// newTestSession 构造一个可安全关闭的最小会话。
func newTestSession(peer netip.AddrPort, peerISN uint32) *Session {
	return &Session{
		raw:        newTestRawSocket(),
		peer:       peer,
		localPort:  8443,
		remotePort: peer.Port(),
		peerISN:    peerISN,
		mark:       IPIDMarkOf(0xF107),
		clock:      NewTcpClock(),
		rx:         make(chan []byte, 1),
		closeCh:    make(chan struct{}),
		// 同上：手工构造必须显式填，否则错误路径会 panic。
		logger: nopLogger{},
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
	l.handleSYN(addr, ParsedPacket{Src: addr.Addr(), SrcPort: addr.Port(), Seq: 222}, IPIDMarkOf(0xF107))

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
	l.handleSYN(addr, ParsedPacket{Src: addr.Addr(), SrcPort: addr.Port(), Seq: 222}, IPIDMarkOf(0xF107))

	if got := l.sessionFor(addr); got != sess {
		t.Fatal("ISN 相同的 SYN 是重传，绝不能关掉已建立的会话")
	}
	if sess.closed.Load() {
		t.Fatal("重传 SYN 不应关闭会话")
	}
}

// TestMaintainLoopHonorsIdleTimeout 钉住空闲超时真的被用上。
//
// rev.8 重组 Listener 字面量时把 idleTimeout 丢了，字段停在 0。
// maintainLoop 里 `idleFor() > 0` 对任何刚收到包的会话都成立，
// 下一秒会话就被关掉，客户端还显示隧道在。
func TestMaintainLoopHonorsIdleTimeout(t *testing.T) {
	l := newTestListener()
	l.idleTimeout = time.Hour
	addr := netip.MustParseAddrPort("203.0.113.7:44300")
	sess := newTestSession(addr, 1)
	sess.lastSeenAt.Store(time.Now().UnixNano())
	l.byAddr[addr] = sess

	l.mu.Lock()
	expired := sess.idleFor() > l.idleTimeout
	l.mu.Unlock()
	if expired {
		t.Fatal("空闲时间远小于配置的超时，不能回收")
	}
	// 0 是漏赋值的形态：比较必须显式要求超时已配置。
	l.idleTimeout = 0
	if l.idleTimeout > 0 && sess.idleFor() > l.idleTimeout {
		t.Fatal("超时未配置时不能回收")
	}
}

// TestMarkOfIgnoresLowByte 钉住识别只用 IP ID 高字节。
//
// 配置可以写成 0xF107（低字节非 0）。若按整值做按位与，
// IP ID 低字节一旦不是 0x07 就匹配失败，伪包被当成普通流量丢掉。
func TestMarkOfIgnoresLowByte(t *testing.T) {
	l := newTestListener() // marks 里放的是 0xF107 的高字节 0xF100
	l.marks = []uint16{0xF107}
	hit := ParsedPacket{IPID: 0xF100}
	if got := l.markOf(hit); got != 0xF100 {
		t.Fatalf("低字节为 0 的包应命中 0xF100，得到 %#x", got)
	}
	wrapped := ParsedPacket{IPID: 0xF1AB}
	if got := l.markOf(wrapped); got != 0xF100 {
		t.Fatalf("低字节回绕后仍应命中，得到 %#x", got)
	}
	other := ParsedPacket{IPID: 0x1E07}
	if got := l.markOf(other); got != 0 {
		t.Fatalf("高字节不同不能命中，得到 %#x", got)
	}
}

// TestMultiCredentialFirstPacket 钉住「多条密码各自可用」这条主线。
//
// 同一台机器既是客户端又是服务端时四元组会退化（源 IP == 目的 IP），
// 跑不出真实端到端结论；而多凭据是否真的成立只取决于两件事：
//   - 每条密码都能在凭据表里查到自己的密钥并解开首包；
//   - 表里没有的密码查不到 authID，必须被静默丢弃。
//
// 这两件事在编解码层就能完整验证，不需要 raw socket / root。
func TestMultiCredentialFirstPacket(t *testing.T) {
	tbl, err := newUserTable([]string{"pw-default", "pw-phone"})
	if err != nil {
		t.Fatalf("构造凭据表失败: %v", err)
	}
	for _, password := range []string{"pw-default", "pw-phone"} {
		client, cerr := NewClientCodec(password)
		if cerr != nil {
			t.Fatal(cerr)
		}
		payload := []byte("hello-" + password)
		opened := false
		for _, rec := range ParseRecords(client.Seal(payload)) {
			if rec.Type != RecAppData {
				continue
			}
			ver, authID, ok := ParseFirstHeader(rec.Payload)
			if !ok || ver != ProtocolVersion {
				continue
			}
			entry, found := tbl.lookup(authID)
			if !found {
				continue
			}
			out, ok := entry.codec.OpenFirst(rec.Payload)
			if !ok {
				continue
			}
			if string(out) != string(payload) {
				t.Fatalf("凭据 %s 解出的明文不一致", password)
			}
			opened = true
		}
		if !opened {
			t.Fatalf("凭据 %s 无法完成首包鉴权", password)
		}
	}

	// 表里没有的密码：必须查不到 authID（服务端据此静默丢弃）。
	unknown, err := NewClientCodec("pw-not-configured")
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range ParseRecords(unknown.Seal([]byte("x"))) {
		if rec.Type != RecAppData {
			continue
		}
		if _, authID, ok := ParseFirstHeader(rec.Payload); ok {
			if _, found := tbl.lookup(authID); found {
				t.Fatal("未配置的密码不应能查到凭据")
			}
		}
	}
}

// TestCredentialSources 钉住服务端凭据的三种来源及其互斥关系。
//
// 曾经的做法是「users 非空则以 users 为准，静默忽略 password」。
// 那是个很难发现的陷阱：
//   - 顶层 password 既不能登录，
//   - 也不参与 ip_id_mark 派生，
//   - 但配置文件里它明明白白写着，运维会以为它是兜底凭据。
//
// 而 mark 不一致的症状是「隧道完全不通」，排查成本极高。
// 所以现在直接拒绝同时配置，并且把判断收在 NormalizePasswords 里，
// 让 option 层（sing-box check）与传输层（真正启动）共用同一套规则。
func TestCredentialSources(t *testing.T) {
	listen := netip.MustParseAddrPort("0.0.0.0:8443")

	both := &ServerConfig{
		Listen:    listen,
		Password:  "top-level-pw",
		Passwords: []string{"other-pw"},
	}
	if err := both.Validate(); err == nil {
		t.Fatal("同时填 password 与 passwords 必须报错（静默忽略会让人以为有兜底凭据）")
	}

	// 只有 passwords：正常，每条各派生一个 mark
	multi := &ServerConfig{
		Listen:    listen,
		Passwords: []string{"pa", "pb"},
	}
	if err := multi.Validate(); err != nil {
		t.Fatalf("只配 passwords 应通过: %v", err)
	}
	if got := len(multi.Marks()); got != 2 {
		t.Fatalf("两条凭据应有 2 个 mark，得到 %d", got)
	}

	// 只有 password：正常，mark 从它派生
	onlyPw := &ServerConfig{Listen: listen, Password: "pw1"}
	if err := onlyPw.Validate(); err != nil {
		t.Fatalf("只配 password 应通过: %v", err)
	}
	if m := onlyPw.Marks(); len(m) != 1 || m[0] != DeriveIPIDMark("pw1") {
		t.Fatalf("单密码 mark 应从 password 派生，得到 %v", m)
	}
}

// TestDuplicatePasswordRejected 钉住「重复密码直接报错」。
//
// 重复的密码会派生出同一个 authID，而凭据表以 authID 为 key ——
// 静默覆盖的症状是「配了 3 条、启动日志说只有 2 条」，且不告诉少的是哪条。
// 这是「沿用一条默认密码」这一用法最容易踩的坑（用户会把同一条密码
// 复制多行，以为复制几行就能支持几台设备）。
func TestDuplicatePasswordRejected(t *testing.T) {
	_, err := NormalizePasswords("", []string{"same", "other", "same"}, nil)
	if err == nil {
		t.Fatal("重复 password 必须报错")
	}
	t.Logf("报错信息（供人工确认可读性）: %v", err)

	if _, err := NormalizePasswords("", []string{"ok", ""}, nil); err == nil {
		t.Fatal("空 password 必须报错")
	}
	// 单密码天然支持多客户端，所以一条密码是合法且推荐的写法。
	if got, err := NormalizePasswords("only-one", nil, nil); err != nil || len(got) != 1 {
		t.Fatalf("单密码应通过并得到 1 条凭据，得到 %v / %v", got, err)
	}
}

// TestCredentialIDStable 钉住日志短标识的两个性质：稳定、不泄漏密码。
//
// 去掉用户名之后，日志里区分凭据只能靠派生 ID：
//   - 必须跨进程稳定（重启后同一条密码还是同一个 uXXXXXXXX，日志能对上）；
//   - 必须与 authID 一致（它标识的是凭据，共用密码的客户端天然同名）。
func TestCredentialIDStable(t *testing.T) {
	tbl, err := newUserTable([]string{"password-a", "password-b"})
	if err != nil {
		t.Fatalf("构造凭据表失败: %v", err)
	}
	if tbl.len() != 2 {
		t.Fatalf("两条凭据应得到 2 项，得到 %d", tbl.len())
	}

	codecA, err := NewServerCodec("password-a")
	if err != nil {
		t.Fatal(err)
	}
	wantID := credentialID(codecA.AuthID())
	entry, ok := tbl.lookup(codecA.AuthID())
	if !ok {
		t.Fatal("按 authID 查不到 password-a 对应的凭据")
	}
	if entry.id != wantID {
		t.Fatalf("派生 ID 不稳定: %q != %q", entry.id, wantID)
	}
	if len(entry.id) != 9 || entry.id[0] != 'u' {
		t.Fatalf("派生 ID 形状应为 u + 8 位十六进制，得到 %q", entry.id)
	}
	// 两条凭据的 ID 必须不同，否则日志无法区分。
	codecB, err := NewServerCodec("password-b")
	if err != nil {
		t.Fatal(err)
	}
	entryB, _ := tbl.lookup(codecB.AuthID())
	if entryB.id == entry.id {
		t.Fatalf("两条不同凭据派生出同一个日志 ID %q", entry.id)
	}
}
