// Command ftudp 是 flowtls 的 UDP 联调工具：验证 QUIC DATAGRAM 通路。
//
// 它的职责和 ftdial 一样，是**跨语言互通的执行器**而不是最终产品：
//
//	ftudp -server 127.0.0.1:8443 -password xxx -target 8.8.8.8:53
//
// 默认发一个 DNS A 查询并校验回程。需要 root 或 CAP_NET_RAW。
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
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
		target   = flag.String("target", "8.8.8.8:53", "UDP 目标 host:port")
		srcPort  = flag.Uint("source-port", 44300, "客户端源端口")
		ipidMark = flag.Uint("ip-id-mark", 0xF107, "IP ID 分流标记")
		timeout  = flag.Duration("timeout", 20*time.Second, "总超时")
		rounds   = flag.Int("rounds", 5, "连续发送轮数（验证 session 复用）")
		sessions = flag.Int("sessions", 1, "并发 UDP 会话数")
	)
	flag.Parse()

	if *server == "" || *password == "" {
		flag.Usage()
		os.Exit(2)
	}
	serverAddr, err := netip.ParseAddrPort(*server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "解析 server 失败: %v\n", err)
		os.Exit(1)
	}
	targetHost, targetPort := splitHostPort(*target)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	fmt.Printf("→ 建立 flowtls 通道 %s\n", serverAddr)
	client, err := ftquic.NewClient(ctx, ftquic.ClientOptions{
		FlowTLS: flowtls.ClientConfig{
			Server:     serverAddr,
			Password:   *password,
			SNI:        targetHost,
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
	fmt.Printf("✓ 通道已建立\n")

	failed := 0
	done := make(chan error, *sessions)
	start := time.Now()
	for i := 0; i < *sessions; i++ {
		go func(idx int) {
			done <- runSession(ctx, client, targetHost, targetPort, *rounds, *sessions > 1, idx)
		}(i)
	}
	for i := 0; i < *sessions; i++ {
		if err := <-done; err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "  会话失败: %v\n", err)
		}
	}
	elapsed := time.Since(start)

	if failed > 0 {
		fmt.Printf("FAIL: %d/%d 个会话失败\n", failed, *sessions)
		os.Exit(1)
	}
	fmt.Printf("✓ %d 个会话 × %d 轮全部收到回程（%v）\n",
		*sessions, *rounds, elapsed.Round(time.Millisecond))
	fmt.Println("PASS")
}

// runSession 建立一条 UDP 会话并连续发起 rounds 次 DNS 查询。
//
// 连续多轮的意义：验证 session 复用。如果每轮都新建会话，
// 服务端的 session 表会不断膨胀，而真实应用（DNS、游戏）都是复用同一条。
func runSession(
	ctx context.Context,
	client *ftquic.Client,
	host string,
	port uint16,
	rounds int,
	verbose bool,
	idx int,
) error {
	pc, err := client.ListenPacket(ctx, host, port)
	if err != nil {
		return fmt.Errorf("ListenPacket: %w", err)
	}
	defer pc.Close()

	// 轮询式读取：把回程投到 channel，主循环用 select 带超时
	recvCh := make(chan int, 4)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, rerr := pc.ReadFrom(buf)
			if rerr != nil {
				close(recvCh)
				return
			}
			recvCh <- n
		}
	}()

	for i := 0; i < rounds; i++ {
		query := buildDNSQuery(uint16(0x1000 + i))
		if _, err := pc.WriteTo(query, nil); err != nil {
			return fmt.Errorf("第 %d 轮写入: %w", i+1, err)
		}
		select {
		case n, ok := <-recvCh:
			if !ok {
				return fmt.Errorf("第 %d 轮会话已关闭", i+1)
			}
			if verbose {
				fmt.Printf("  会话 %d 第 %d 轮: 回程 %d 字节\n", idx, i+1, n)
			} else if i == 0 {
				fmt.Printf("  第 1 轮回程 %d 字节\n", n)
			}
		case <-time.After(6 * time.Second):
			return fmt.Errorf("第 %d 轮超时（UDP 不重传，丢包也算失败）", i+1)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// buildDNSQuery 构造一个最小的 DNS A 查询（example.com）。
func buildDNSQuery(id uint16) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint16(b, id)
	b = binary.BigEndian.AppendUint16(b, 0x0100) // 标准查询，RD=1
	b = binary.BigEndian.AppendUint16(b, 1)      // QDCOUNT
	b = binary.BigEndian.AppendUint16(b, 0)      // ANCOUNT
	b = binary.BigEndian.AppendUint16(b, 0)      // NSCOUNT
	b = binary.BigEndian.AppendUint16(b, 0)      // ARCOUNT
	// QNAME: example.com
	for _, label := range []string{"example", "com"} {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)                        // 根
	b = binary.BigEndian.AppendUint16(b, 1) // QTYPE = A
	b = binary.BigEndian.AppendUint16(b, 1) // QCLASS = IN
	return b
}

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
	return s, 53
}
