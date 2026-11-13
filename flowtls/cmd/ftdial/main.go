// Command ftdial 是 flowtls 的联调工具：用 Go 传输层打通服务端并做一次真实请求。
//
// 它存在的意义不是「给用户用的客户端」，而是**跨语言互通的执行器**：
//
//	ftdial -server 127.0.0.1:8443 -password xxx -target example.com:443
//
// 跑通这条命令就等于证明了 Go 传输层能在真实链路上工作（而不仅是单测自洽）。
// 需要 root 或 CAP_NET_RAW（raw socket）。
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/luowei729/flowtls"
	ftquic "github.com/luowei729/flowtls/quic"
)

func main() {
	var (
		server   = flag.String("server", "", "服务端地址 host:port")
		password = flag.String("password", "", "密码")
		target   = flag.String("target", "example.com:443", "目标 host:port")
		sni      = flag.String("sni", "", "伪装 SNI（默认取 target 的域名）")
		srcPort  = flag.Uint("source-port", 44300, "客户端源端口")
		ipidMark = flag.Uint("ip-id-mark", 0xF107, "IP ID 分流标记")
		timeout  = flag.Duration("timeout", 30*time.Second, "总超时")
		doTLS    = flag.Bool("tls", true, "在流上再做一次 TLS（访问 https 站点）")
		insecure = flag.Bool("insecure", true, "跳过目标证书校验（自签站点测试用）")
		request  = flag.String("request", "", "直接发送的原始请求（为空则用默认 HTTP GET）")
		streams  = flag.Int("streams", 1, "在同一 QUIC 连接上并发打开的流数")
		verbose  = flag.Bool("v", false, "打印 QUIC 统计")
	)
	flag.Parse()

	if *server == "" || *password == "" {
		flag.Usage()
		os.Exit(2)
	}
	serverAddr, err := netip.ParseAddrPort(*server)
	if err != nil {
		if ap, err2 := netip.ParseAddr(*server); err2 == nil {
			serverAddr = netip.AddrPortFrom(ap, 8443)
		} else {
			fmt.Fprintf(os.Stderr, "解析 server 失败: %v\n", err)
			os.Exit(1)
		}
	}
	targetHost, targetPort := splitHostPort(*target)
	if *sni == "" {
		*sni = targetHost
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	fmt.Printf("→ 建立 flowtls 通道 %s（源端口 %d）\n", serverAddr, *srcPort)
	start := time.Now()
	client, err := ftquic.NewClient(ctx, ftquic.ClientOptions{
		FlowTLS: flowtls.ClientConfig{
			Server:     serverAddr,
			Password:   *password,
			SNI:        *sni,
			SourcePort: uint16(*srcPort),
			IPIDMark:   uint16(*ipidMark),
			Handshake:  true,
		},
		DialTimeout: *timeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "建连失败: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()
	fmt.Printf("✓ 通道已建立（%v）\n", time.Since(start).Round(time.Millisecond))

	// 多流并发：sing-box 的 outbound 就是这样用——**一条 QUIC 连接上
	// 为每个本地连接开一条流**，而不是每次重新握手。
	// 这个模式必须单独验证：它和「多连接」暴露的问题完全不同
	// （共享连接级流控窗口、共享拥塞控制）。
	nStreams := *streams
	if nStreams < 1 {
		nStreams = 1
	}
	if nStreams > 1 {
		fmt.Printf("→ 在同一连接上并发打开 %d 条流\n", nStreams)
	}

	req := *request
	if req == "" {
		req = fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: flowtls-ftdial\r\nConnection: close\r\n\r\n", targetHost)
	}

	type streamResult struct {
		idx   int
		total int64
		first string
		err   error
	}
	results := make(chan streamResult, nStreams)
	runStart := time.Now()
	for i := 0; i < nStreams; i++ {
		go func(idx int) {
			total, first, err := runOneStream(ctx, client, targetHost, targetPort,
				*sni, *doTLS, *insecure, req, nStreams == 1)
			results <- streamResult{idx: idx, total: total, first: first, err: err}
		}(i)
	}

	var failed int
	var sum int64
	for i := 0; i < nStreams; i++ {
		r := <-results
		if r.err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "  流 %d 失败: %v\n", r.idx, r.err)
			continue
		}
		sum += r.total
		if nStreams == 1 {
			fmt.Printf("✓ 收到 %d 字节（%v）\n", r.total, time.Since(runStart).Round(time.Millisecond))
			if r.first != "" {
				fmt.Printf("  响应首行: %s\n", r.first)
			}
		} else {
			fmt.Printf("  流 %d: %d 字节\n", r.idx, r.total)
		}
	}
	if nStreams > 1 {
		elapsed := time.Since(runStart)
		fmt.Printf("✓ %d 条流共 %d 字节（%v, %.2f MB/s）\n",
			nStreams-failed, sum, elapsed.Round(time.Millisecond),
			float64(sum)/elapsed.Seconds()/1024/1024)
	}

	if *verbose {
		s := client.Stats()
		fmt.Printf("  QUIC: rtt=%v sent=%dB/%dpkt recv=%dB lost=%dpkt\n",
			s.SmoothedRTT.Round(time.Microsecond), s.BytesSent, s.PacketsSent,
			s.BytesRecv, s.PacketsLost)
	}
	if failed > 0 {
		fmt.Printf("FAIL: %d/%d 条流失败\n", failed, nStreams)
		os.Exit(1)
	}
	fmt.Println("PASS")
}

// runOneStream 在既有连接上开一条流、完成一次请求并读满响应。
func runOneStream(
	ctx context.Context,
	client *ftquic.Client,
	host string,
	port uint16,
	sni string,
	doTLS, insecure bool,
	req string,
	verbose bool,
) (int64, string, error) {
	conn, err := client.DialConn(ctx, host, port)
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()

	var rw io.ReadWriter = conn
	if doTLS {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: insecure,
			MinVersion:         tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return 0, "", err
		}
		if verbose {
			fmt.Printf("✓ TLS 已就绪（%s）\n",
				tls.VersionName(tlsConn.ConnectionState().Version))
		}
		rw = tlsConn
	}

	if _, err := io.WriteString(rw, req); err != nil {
		return 0, "", err
	}

	// 边读边打进度：整块 ReadAll 在大流量下卡住时完全看不出停在哪一步，
	// 而「读到的字节是否还在增长」是区分「链路慢」和「真的卡死」的最快依据。
	var total int64
	var firstLine string
	var lastReport = time.Now()
	buf := make([]byte, 32*1024)
	for {
		n, rerr := rw.Read(buf)
		if n > 0 {
			if total == 0 {
				if line, _, ok := cutLine(buf[:n]); ok {
					firstLine = line
				}
			}
			total += int64(n)
			if verbose && time.Since(lastReport) >= 2*time.Second {
				lastReport = time.Now()
				fmt.Printf("  ... %d 字节\n", total)
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return total, firstLine, nil
			}
			// 非 EOF 但已有数据：按成功处理（与 Rust 行为对照，
			// 尾部被 reset 时数据往往已经完整）
			if total > 0 {
				return total, firstLine, nil
			}
			return 0, "", rerr
		}
	}
}

// splitHostPort 拆 host:port，缺端口时按 443 处理。
func splitHostPort(s string) (string, uint16) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			var p int
			fmt.Sscanf(s[i+1:], "%d", &p)
			if p > 0 && p < 65536 {
				return s[:i], uint16(p)
			}
			break
		}
	}
	return s, 443
}

// cutLine 取第一行（去掉 \r）。
func cutLine(b []byte) (string, []byte, bool) {
	for i, c := range b {
		if c == '\n' {
			line := b[:i]
			if n := len(line); n > 0 && line[n-1] == '\r' {
				line = line[:n-1]
			}
			return string(line), b[i+1:], true
		}
	}
	return "", nil, false
}
