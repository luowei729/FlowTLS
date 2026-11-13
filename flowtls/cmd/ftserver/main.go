// Command ftserver 是 flowtls 的 Go 服务端联调工具。
//
// 它的职责与 ftdial/ftudp 相同：**跨语言互通的执行器**。
// 跑通它就等于证明 Go 服务端能被 Rust 客户端使用（而不仅自洽）。
//
//	ftserver -listen 0.0.0.0:8443 -password xxx -local-ip 1.2.3.4
//
// 需要 root 或 CAP_NET_RAW。
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	quicgo "github.com/sagernet/quic-go"

	"github.com/luowei729/flowtls"
	ftquic "github.com/luowei729/flowtls/quic"
)

func main() {
	var (
		listen   = flag.String("listen", "", "监听地址 host:port")
		password = flag.String("password", "", "单用户密码")
		users    = flag.String("users", "", "多用户，格式 name:password,name:password")
		localIP  = flag.String("local-ip", "", "对外源 IP（NAT 后必须指定）")
		ipidMark = flag.Uint("ip-id-mark", 0xF107, "IP ID 分流标记")
		idle     = flag.Duration("idle-timeout", 120*time.Second, "会话空闲回收")
		iptables = flag.String("iptables", "none", "iptables 模式：none / print / auto")
	)
	flag.Parse()

	if *listen == "" {
		flag.Usage()
		os.Exit(2)
	}
	iptMode, err := flowtls.ParseIPTablesMode(*iptables)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(2)
	}
	addr, err := parseListen(*listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "解析 listen 失败: %v\n", err)
		os.Exit(1)
	}
	userList, err := parseUsers(*users, *password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "解析用户失败: %v\n", err)
		os.Exit(1)
	}
	if len(userList) == 0 {
		fmt.Fprintln(os.Stderr, "必须提供 -password 或 -users")
		os.Exit(2)
	}

	var local netip.Addr
	if *localIP != "" {
		local, err = netip.ParseAddr(*localIP)
		if err != nil {
			fmt.Fprintf(os.Stderr, "local-ip 非法: %v\n", err)
			os.Exit(1)
		}
	}

	tlsConf, err := selfSignedTLS()
	if err != nil {
		fmt.Fprintf(os.Stderr, "生成内层 TLS 证书失败: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("→ 启动 flowtls 服务端 %s（%d 个用户）\n", addr, len(userList))
	srv, err := ftquic.NewServer(ftquic.ServerOptions{
		FlowTLS: flowtls.ServerConfig{
			Listen:   addr,
			Users:    userList,
			LocalIP:  local,
			IPIDMark: uint16(*ipidMark),
		},
		Listener: flowtls.ListenerOptions{IdleTimeout: *idle, IPTablesMode: iptMode},
		TLS:      tlsConf,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "启动失败: %v\n", err)
		os.Exit(1)
	}
	defer srv.Close()
	fmt.Printf("✓ 已就绪 local=%s users=%d\n", srv.Addr(), len(userList))
	if report := srv.ListenerRules(); !report.Empty() {
		for _, line := range strings.Split(report.Text(), "\n") {
			fmt.Println(line)
		}
	}
	fmt.Println("  提示：同端口的真证书网站需要另起一个程序监听（本工具只做协议联调）")

	// 统计协程
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				st := srv.ListenerStats()
				fmt.Printf("  统计: sessions=%d pending=%d accepted=%d dropped=%d\n",
					st.Sessions, st.Pending, st.Accepted, st.Dropped)
			}
		}
	}()

	for {
		conn, err := srv.Accept(ctx)
		if err != nil {
			fmt.Println("服务端退出")
			return
		}
		go handleConn(ctx, conn)
	}
}

// handleConn 处理一条进来的 QUIC 连接。
//
// 这是联调用的极简实现——没有路由规则、没有 DNS 策略，
// 只验证「Go 服务端能正确解出目标地址并转发」。
// 正式实现（sing-box 的 inbound 适配层）会把流交给 router 处理。
func handleConn(ctx context.Context, conn *quicgo.Conn) {
	logf := func(format string, args ...any) {
		fmt.Printf("  [%s] %s\n", conn.RemoteAddr(), fmt.Sprintf(format, args...))
	}
	// UDP：DATAGRAM 通路单独一个协程
	go handleDatagrams(ctx, conn, logf)

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go handleStream(stream, logf)
	}
}

// handleStream 读首帧目标地址，然后双向转发。
func handleStream(stream *quicgo.Stream, logf func(string, ...any)) {
	// 首帧：[总长 u16][ATYP][ADDR][PORT]
	var lenBuf [2]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		_ = stream.Close()
		return
	}
	frameLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if frameLen == 0 || frameLen > 300 {
		_ = stream.Close()
		return
	}
	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(stream, frame); err != nil {
		_ = stream.Close()
		return
	}
	host, port, err := flowtls.DecodeAddress(frame)
	if err != nil {
		logf("目标地址解析失败: %v", err)
		_ = stream.Close()
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	logf("新流 → %s", target)

	out, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		logf("连接 %s 失败: %v", target, err)
		_ = stream.Close()
		return
	}
	defer out.Close()

	// 双向拷贝。用两个协程而不是 select，因为两个方向都要能独立结束。
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(out, stream)
		// 上游 EOF：半关闭写方向，让目标知道没有更多数据（不要直接 Close）
		if tc, ok := out.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(stream, out)
		_ = stream.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
}

// handleDatagrams 处理 UDP DATAGRAM：按 session 建立/复用出站 socket。
func handleDatagrams(ctx context.Context, conn *quicgo.Conn, logf func(string, ...any)) {
	type udpSess struct {
		sock *net.UDPConn
	}
	var (
		mu    sync.Mutex
		table = make(map[uint32]*udpSess)
	)
	defer func() {
		mu.Lock()
		for _, s := range table {
			_ = s.sock.Close()
		}
		mu.Unlock()
	}()

	for {
		data, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			logf("DATAGRAM 接收结束: %v", err)
			return
		}
		session, targetFrame, payload, ok := flowtls.ParseClientDatagram(data)
		if !ok {
			logf("DATAGRAM 解析失败 len=%d", len(data))
			continue
		}

		mu.Lock()
		s, exists := table[session]
		if !exists {
			host, port, derr := flowtls.DecodeAddress(targetFrame)
			if derr != nil {
				mu.Unlock()
				continue
			}
			// 解析目标并 connect：connect 后内核只把该目标的包交给我们，
			// 天然防住任意源地址注入。
			raddr, rerr := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(int(port))))
			if rerr != nil {
				mu.Unlock()
				continue
			}
			c, derr2 := net.DialUDP("udp", nil, raddr)
			if derr2 != nil {
				mu.Unlock()
				continue
			}
			s = &udpSess{sock: c}
			table[session] = s
			logf("UDP 会话 %d → %s", session, raddr)
			// 回程协程：目标 → DATAGRAM
			go func(id uint32, sock *net.UDPConn) {
				buf := make([]byte, 65535)
				out := make([]byte, 0, 2048)
				for {
					n, rerr := sock.Read(buf)
					if rerr != nil {
						return
					}
					out = flowtls.EncodeServerDatagram(out[:0], id, buf[:n])
					// 超 MTU 直接丢（UDP 语义，不分片）
					_ = conn.SendDatagram(out)
				}
			}(session, s.sock)
		}
		sock := s.sock
		mu.Unlock()

		// UDP 的 send 在正常情况下不会阻塞；失败即丢包（不重传）。
		if _, werr := sock.Write(payload); werr != nil {
			logf("UDP session %d 发送失败: %v", session, werr)
		}
	}
}

// parseListen 把 ":8443" / "0.0.0.0:8443" 解析成 AddrPort。
func parseListen(s string) (netip.AddrPort, error) {
	if strings.HasPrefix(s, ":") {
		s = "0.0.0.0" + s
	}
	return netip.ParseAddrPort(s)
}

// parseUsers 解析 "name:pass,name:pass" 或单密码。
func parseUsers(spec, single string) ([]flowtls.User, error) {
	if spec == "" {
		if single == "" {
			return nil, nil
		}
		return []flowtls.User{{Name: "default", Password: single}}, nil
	}
	var out []flowtls.User
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, pass, ok := strings.Cut(item, ":")
		if !ok || name == "" || pass == "" {
			return nil, fmt.Errorf("条目格式应为 name:password，得到 %q", item)
		}
		out = append(out, flowtls.User{Name: name, Password: pass})
	}
	return out, nil
}

// selfSignedTLS 生成内层 QUIC 用的自签证书。
//
// 内层 TLS 只满足 QUIC 的协议要求，安全由外层 AEAD 保证，
// 所以每次启动现生成即可，不需要持久化。
func selfSignedTLS() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"flowtls"}, // 必须与客户端 ALPN 一致
		MinVersion:   tls.VersionTLS13,
	}, nil
}
