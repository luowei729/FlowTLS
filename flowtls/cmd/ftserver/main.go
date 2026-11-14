// Command ftserver 是 flowtls 的联调服务端：真正转发出站 TCP/UDP。
//
// 它存在的意义不是「给用户用的服务端」，而是**跨语言互通的执行器**：
//
//	ftserver -listen 0.0.0.0:8443 -password xxx
//
// 跑通它 + ftdial 就等于证明传输层能在真实链路上工作（而不仅是单测自洽）。
// 需要 root 或 CAP_NET_RAW（raw socket）。
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	quicgo "github.com/sagernet/quic-go"

	"github.com/luowei729/flowtls"
	ftquic "github.com/luowei729/flowtls/quic"
)

func main() {
	var (
		listen   = flag.String("listen", "0.0.0.0:8443", "监听地址")
		password = flag.String("password", "", "密码")
		localIP  = flag.String("local-ip", "", "回包源 IP（NAT 云主机填内网地址；留空按路由探测）")
		ipidMark = flag.Uint("ip-id-mark", 0xF107, "IP ID 分流标记")
		iptables = flag.String("iptables", "none", "iptables 模式：none / auto")
		maxCwnd  = flag.Uint64("max-cwnd", 8388608, "QUIC 拥塞窗口上限（字节）")
		verbose  = flag.Bool("v", false, "打印每 2 秒的路径统计")
	)
	flag.Parse()

	if *password == "" {
		flag.Usage()
		os.Exit(2)
	}
	mode, err := flowtls.ParseMode(*iptables)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(2)
	}
	addr, err := netip.ParseAddrPort(*listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "解析 listen 失败: %v\n", err)
		os.Exit(2)
	}
	cfg := flowtls.ServerConfig{
		Listen:    addr,
		Password:  *password,
		IPIDMark:  uint16(*ipidMark),
		NetMode:   mode,
		LocalIP:   parseLocalIP(*localIP),
		UDPTimeoutSecs: 120,
		UDPMaxSessions: 256,
	}

	var onStats func(ftquic.PathStats)
	if *verbose {
		onStats = func(s ftquic.PathStats) { ftquic.LogStats(s) }
	}
	srv, err := ftquic.NewServer(ftquic.ServerOptions{
		FlowTLS:  cfg,
		MaxCwnd:  *maxCwnd,
		OnStats:  onStats,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "启动失败: %v\n", err)
		os.Exit(1)
	}
	defer srv.Close()
	fmt.Printf("✓ flowtls 服务端已就绪 %s（用户 %d 个）\n", srv.Addr(), srv.Users())
	fmt.Printf("  发送路径: %s\n", srv.SendMode())

	for {
		conn, err := srv.Accept(context.Background())
		if err != nil {
			fmt.Fprintf(os.Stderr, "accept 结束: %v\n", err)
			return
		}
		fmt.Printf("✓ 新连接 %s\n", conn.RemoteAddr())
		go serveConn(conn, *verbose)
	}
}

// serveConn 在一条 QUIC 连接上同时处理 TCP 流与 UDP 数据报。
//
// 两条通路必须并行：TCP 走双向流，UDP 走 RFC 9221 DATAGRAM，
// 在 QUIC 层它们是不同机制，串行会互相阻塞。
func serveConn(conn *quicgo.Conn, verbose bool) {
	defer func() { _ = conn.CloseWithError(0, "") }()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		serveStreams(conn, verbose)
	}()
	go func() {
		defer wg.Done()
		serveDatagrams(conn)
	}()
	wg.Wait()
}

// serveStreams 接受流并把每条流交给拨号+转发逻辑。
func serveStreams(conn *quicgo.Conn, verbose bool) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go handleStream(stream, verbose)
	}
}

// handleStream 解析目标地址帧，然后建立出站 TCP 并双向拷贝。
//
// 每条流的首帧是目标地址：[len u16][ATYP][ADDR][PORT]。
// **必须由本层读掉这一帧才能路由**——这是本协议与 vless/trojan 的关键差别：
// 那里目标地址在协议握手头里，这里它在流内的第一帧。
func handleStream(stream *quicgo.Stream, verbose bool) {
	// 首帧长度是 u16，正常只有几十字节。
	// 给 8 秒上限：连地址帧都读不出来，说明对端不是本协议或链路已断。
	_ = stream.SetReadDeadline(time.Now().Add(8 * time.Second))
	host, port, err := readAddressFrame(stream)
	_ = stream.SetReadDeadline(time.Time{})
	if err != nil {
		// **只关这条流，绝不关整条连接**：一条 QUIC 连接上同时有几十条流
		// （浏览器并发请求），关连接会把其他正在传输的流一起杀掉。
		stream.CancelRead(0)
		_ = stream.Close()
		return
	}

	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	out, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		if verbose {
			fmt.Printf("  出站连接失败 %s: %v\n", target, err)
		}
		stream.CancelRead(0)
		_ = stream.Close()
		return
	}
	defer out.Close()

	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = out.Close()
			stream.CancelRead(0)
			_ = stream.Close()
		})
	}
	go func() {
		_, _ = io.Copy(out, stream)
		// 上行结束：半关闭出站写方向，让对端知道 EOF
		if c, ok := out.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
	}()
	_, _ = io.Copy(stream, out)
	closeBoth()
}

// readAddressFrame 从流里读一帧目标地址。
func readAddressFrame(r io.Reader) (string, uint16, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", 0, err
	}
	frameLen := int(uint16(lenBuf[0])<<8 | uint16(lenBuf[1]))
	if frameLen == 0 || frameLen > 300 {
		return "", 0, fmt.Errorf("非法地址帧长度 %d", frameLen)
	}
	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(r, frame); err != nil {
		return "", 0, err
	}
	return flowtls.DecodeAddressFrame(frame)
}

// serveDatagrams 接收 UDP 数据报并按 session 分发到出站 UDP socket。
//
// quic-go 的 ReceiveDatagram 是**单消费者**语义：多个协程同时读会互相抢包，
// 所以这里只有一个循环。
//
// 会话必须有回收，否则会拖垮整机：每个会话占一个出站 UDP socket，
// 而 Linux 临时端口只有约 28k 个。Rust 的回收在 udp_outbound 任务里
// 靠「主循环 remove + sender drop」自然退出，这里用空闲时间判断。
func serveDatagrams(conn *quicgo.Conn) {
	type session struct {
		pc       *net.UDPConn
		lastUsed time.Time
	}
	sessions := make(map[uint32]*session)
	var mu sync.Mutex

	// 回收协程：与 Rust `udp.timeout_secs` 同语义。
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
			mu.Lock()
			for id, s := range sessions {
				if time.Since(s.lastUsed) > 120*time.Second {
					_ = s.pc.Close()
					delete(sessions, id)
				}
			}
			mu.Unlock()
		}
	}()

	for {
		data, err := conn.ReceiveDatagram(context.Background())
		if err != nil {
			mu.Lock()
			for id, s := range sessions {
				_ = s.pc.Close()
				delete(sessions, id)
			}
			mu.Unlock()
			return
		}
		id, targetFrame, payload, ok := flowtls.ParseClientDatagram(data)
		if !ok {
			continue
		}
		host, port, err := flowtls.DecodeAddressFrame(targetFrame)
		if err != nil {
			continue
		}
		raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		if err != nil {
			continue
		}

		mu.Lock()
		s, exists := sessions[id]
		if !exists {
			// 服务端完全无状态：每个上行包都带目标地址，第一个包即可建会话。
			pc, derr := net.DialUDP("udp", nil, raddr)
			if derr != nil {
				mu.Unlock()
				continue
			}
			s = &session{pc: pc}
			sessions[id] = s
			// 下行：从出站 socket 读，编码成服务端帧回客户端。
			go func(id uint32, pc *net.UDPConn) {
				buf := make([]byte, 2048)
				for {
					n, rerr := pc.Read(buf)
					if rerr != nil {
						return
					}
					out := flowtls.EncodeServerDatagram(nil, id, buf[:n])
					// 超 MTU / 连接已断：按 UDP 语义直接丢，不关闭会话。
					_ = conn.SendDatagram(out)
				}
			}(id, pc)
		}
		s.lastUsed = time.Now()
		mu.Unlock()

		_, _ = s.pc.Write(payload)
	}
}

// parseLocalIP 解析配置里的源 IP；空串返回无效地址（由 NewListener 探测）。
func parseLocalIP(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "local-ip 不是合法 IPv4: %s\n", s)
		os.Exit(2)
	}
	return a
}
