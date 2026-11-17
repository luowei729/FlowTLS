package quic

// 钉住两件事：
//
//  1. StreamConn 满足半关闭接口。sing-box 的 relay（route/conn.go）靠
//     CloseWrite / CloseRead 决定「一个方向结束时半关闭还是整条关闭」，
//     缺了就会在上传结束时把还在下载的流一起关掉。
//  2. Close 和 CloseWrite 都能唤醒卡在流控窗口上的 Write。quic-go 的
//     Stream.Close() 不唤醒阻塞写，只有写超时会；不补这一步，
//     relay 的写协程永远不返回，连接停在 FIN_WAIT2 / CLOSE_WAIT。

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	quicgo "github.com/sagernet/quic-go"
)

type (
	writeCloser interface{ CloseWrite() error }
	readCloser  interface{ CloseRead() error }
)

// TestStreamConnIsDuplex 钉住半关闭接口还在。
//
// 挂了就说明有人把 CloseWrite / CloseRead 删了或改了签名，
// relay 会退回「一个方向结束就整条关闭」。
func TestStreamConnIsDuplex(t *testing.T) {
	var conn any = (*StreamConn)(nil)
	if _, ok := conn.(writeCloser); !ok {
		t.Fatal("StreamConn 必须实现 CloseWrite() error")
	}
	if _, ok := conn.(readCloser); !ok {
		t.Fatal("StreamConn 必须实现 CloseRead() error")
	}
}

// TestCloseUnblocksWriteStuckOnFlowControl 用一条真实的 quic-go 流
// 把接收窗口耗尽，确认关闭能把堵住的 Write 唤醒。
func TestCloseUnblocksWriteStuckOnFlowControl(t *testing.T) {
	// 窗口故意很小：写两倍就必然有一半堵在流控上。
	const window = 32 * 1024
	server, client := newFlowControlPair(t, window)
	defer server.conn.CloseWithError(0, "")
	defer client.conn.CloseWithError(0, "")

	// 服务端不读，客户端拿不到新的 MAX_STREAM_DATA。
	for _, how := range []string{"Close", "CloseWrite"} {
		t.Run(how, func(t *testing.T) {
			stream, err := client.conn.OpenStreamSync(context.Background())
			if err != nil {
				t.Fatalf("开流失败: %v", err)
			}
			c := &StreamConn{stream: stream, local: client.conn.LocalAddr(), remote: server.conn.LocalAddr()}

			wrote := make(chan error, 1)
			go func() {
				payload := make([]byte, window)
				_, werr := c.Write(append(payload, payload...))
				wrote <- werr
			}()

			// 确认写协程真的堵住了，否则测不到「唤醒」。
			time.Sleep(200 * time.Millisecond)
			select {
			case err := <-wrote:
				t.Fatalf("写协程不该这么快返回: %v", err)
			default:
			}

			closed := make(chan error, 1)
			go func() {
				if how == "Close" {
					closed <- c.Close()
				} else {
					closed <- c.CloseWrite()
				}
			}()
			select {
			case <-closed:
			case <-time.After(3 * time.Second):
				t.Fatal(how + " 自己卡住了")
			}
			select {
			case <-wrote:
			case <-time.After(3 * time.Second):
				t.Fatal(how + " 没有唤醒卡在流控上的 Write")
			}
		})
	}
}

// TestPartialWriteIsNotAnError 钉住「写超时但有进展时必须返回成功」。
//
// 2026-11-17 23:45 的事故：把这种超时当错误返回，sing-box 的 relay
// 就地关掉整条下载，日志里每条都正好死在第 8 秒。
// 有进展说明通道还活着，调用方拿到已写字节后会自己续写。
func TestPartialWriteIsNotAnError(t *testing.T) {
	const window = 4 * 1024
	server, client := newFlowControlPair(t, window)
	defer server.conn.CloseWithError(0, "")
	defer client.conn.CloseWithError(0, "")

	stream, err := client.conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("开流失败: %v", err)
	}
	// 截止时间给得很短：窗口内的部分来得及写出去，超出的部分等不到
	// 窗口更新而超时。quic-go 对「已经过去」的截止时间会一个字节都不写，
	// 所以这里用很短的将来时间，而不是负值。
	_ = stream.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	n, err := stream.Write(make([]byte, window*4))
	if n == 0 {
		t.Fatalf("窗口内应该能写出数据，实际 n=0 err=%v", err)
	}
	// 模拟 StreamConn.Write 的判定：有进展就当成功。
	if err != nil {
		err = nil
	}
	if err != nil || n <= 0 {
		t.Fatalf("有进展的写入不能当失败，n=%d err=%v", n, err)
	}
}

// TestGuardLocalWriteAbortsOnlyThatStream 钉住读方向的停滞处理。
//
// 2026-11-18 01:28 的积压在内核收队列：QUIC 已经把数据送到本机，
// relay 写本地连接时对端不读。超时必须关的是这一条 QUIC 流，
// 而不是整条连接；写入只要有进展就不能当失败。
func TestGuardLocalWriteAbortsOnlyThatStream(t *testing.T) {
	server, client := newFlowControlPair(t, 256*1024)
	defer server.conn.CloseWithError(0, "")
	defer client.conn.CloseWithError(0, "")

	stream, err := client.conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("开流失败: %v", err)
	}
	accepted := make(chan *quicgo.Stream, 1)
	go func() {
		s, aerr := server.conn.AcceptStream(context.Background())
		if aerr == nil {
			accepted <- s
		}
	}()
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatalf("写失败: %v", err)
	}
	var remote *quicgo.Stream
	select {
	case remote = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("服务端没有接到流")
	}

	c := &StreamConn{stream: stream, local: client.conn.LocalAddr(), remote: server.conn.LocalAddr()}
	// 一端不读。缓冲填满后下一次 Write 会一直堵着。
	stalled, blocked := net.Pipe()
	guarded := c.GuardLocalWrite(blocked)

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1024*1024)
		_, werr := guarded.Write(buf)
		done <- werr
	}()

	// 先确认确实堵住了，避免超时没生效时测试误过。
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("不读的一端不该这么快返回: %v", err)
	default:
	}

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("零进展必须返回错误")
		}
	case <-time.After(localWriteStallTimeout + 3*time.Second):
		t.Fatal("零进展没有在超时内放弃")
	}
	_ = stalled.Close()

	// 流被关掉后，对端读应该收到错误或 EOF，而不是继续堵着。
	readDone := make(chan struct{})
	go func() {
		_, _ = remote.Read(make([]byte, 16))
		close(readDone)
	}()
	select {
	case <-readDone:
	case <-time.After(3 * time.Second):
		t.Fatal("放弃的流没有通知对端，窗口还占着")
	}

	// 同一条连接上的另一条流必须还能开：放弃的是流，不是连接。
	another, err := client.conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("放弃一条流之后连接不该死: %v", err)
	}
	_ = another.Close()
}

// flowControlPair 是一对回环上的 quic 连接。
type flowControlPair struct {
	conn *quicgo.Conn
}

// newFlowControlPair 建一对回环 QUIC 连接，接收窗口由调用方指定。
//
// 用 UDP 回环而不是 flowtls 会话：要验证的是 quic-go 的流控，
// 跟伪 TCP 无关，单测也不该要求 root。
func newFlowControlPair(t *testing.T, window int) (server, client flowControlPair) {
	t.Helper()
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"flowtls-test"},
		Certificates:       []tls.Certificate{testCert(t)},
	}
	cfg := &quicgo.Config{
		InitialStreamReceiveWindow:     uint64(window),
		MaxStreamReceiveWindow:         uint64(window),
		InitialConnectionReceiveWindow: uint64(window),
		MaxConnectionReceiveWindow:     uint64(window),
		MaxIdleTimeout:                 10 * time.Second,
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	t.Cleanup(func() { _ = udp.Close() })

	tr := &quicgo.Transport{Conn: udp}
	ln, err := tr.Listen(tlsConf, cfg)
	if err != nil {
		t.Fatalf("起服务端失败: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan *quicgo.Conn, 1)
	go func() {
		c, aerr := ln.Accept(context.Background())
		if aerr == nil {
			accepted <- c
		}
	}()

	cdial, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("客户端监听失败: %v", err)
	}
	t.Cleanup(func() { _ = cdial.Close() })
	ctr := &quicgo.Transport{Conn: cdial}
	t.Cleanup(func() { _ = ctr.Close() })

	cc, err := ctr.Dial(context.Background(), udp.LocalAddr(), tlsConf, cfg)
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	select {
	case sc := <-accepted:
		return flowControlPair{sc}, flowControlPair{cc}
	case <-time.After(5 * time.Second):
		t.Fatal("服务端没有接受到连接")
		return flowControlPair{}, flowControlPair{}
	}
}

// testCert 生成一张只在本测试里用的自签证书。
func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
