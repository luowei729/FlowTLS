package flowtls

// 同端口真网站（`masquerade`）。
//
// 对应 `legacy-rust:src/site/mod.rs`，行为逐条对齐：
//
//	TLS 1.3，ALPN 只宣告 http/1.1（真实世界大量站点如此，不成为指纹特征）
//	TLS 握手 10s 超时，连接总时长 30s 超时
//	单次请求头上限 16KB（防止被恶意超长请求拖垮）
//	GET/HEAD      → 静态文件 → 目录 index.html → 内置占位页
//	/robots.txt   → Allow: /
//	/favicon.ico  → 204（比 404 更像正常站点）
//	其它方法      → 405
//	keep-alive 由 Connection 头决定
//	响应头固定 Server: nginx + Cache-Control: public, max-age=300
//
// 为什么伪装站要和隧道同端口：443/8443 的主动探测必须看到一个真实的
// HTTPS 站点。伪包在 raw 表被 iptables DROP，剩下的包才落到内核 TCP。
//
// **没有反代（proxy_url）**：Rust 不做，Go v1/v2 加过，已删除。
// 静态站点的目录结构、响应头、404 页都是可枚举的，确实不如反代隐蔽；
// 但「原样移植」优先——要反代请用 nginx 监听别的端口再 detour。

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	// 与 Rust 常量一致
	masqueradeTLSTimeout    = 10 * time.Second
	masqueradeConnTimeout   = 30 * time.Second
	masqueradeMaxHeaderSize = 16 * 1024
	masqueradeReadChunk     = 4096

	robotsTXT = "User-agent: *\nAllow: /\n"

	// 内置占位页：编译期常量，保证离线也能响应。
	// **生产环境必须用 site_dir 换成真实内容**——占位页本身就是指纹。
	builtinIndexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Welcome</title>
<style>
  body { margin:0; font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
         background:#0f172a; color:#e2e8f0; display:flex; align-items:center;
         justify-content:center; min-height:100vh; }
  .card { max-width:32rem; padding:2.5rem 3rem; text-align:center;
          background:#1e293b; border-radius:.75rem;
          box-shadow:0 10px 30px rgba(0,0,0,.35); }
  h1 { font-size:1.5rem; margin:0 0 .75rem; font-weight:600; }
  p  { margin:.5rem 0; line-height:1.6; color:#94a3b8; }
</style>
</head>
<body>
  <div class="card">
    <h1>It works</h1>
    <p>This site is up and running.</p>
    <p>Content is being prepared.</p>
  </div>
</body>
</html>
`
)

// masquerade 是同端口伪装站点。
type masquerade struct {
	listener net.Listener
	logger   log.ContextLogger
	siteDir  string
	certs    []tls.Certificate

	closeOnce sync.Once
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
}

// newMasquerade 加载证书并 bind 内核 TCP 端口。
//
// **这是 flowtls 唯一 bind 内核 TCP 的地方**，且只在配了 masquerade 时发生。
// 不配时端口留给 nginx/caddy，入站只做隧道。
func newMasquerade(host string, port uint16, opts *option.FlowTLSMasqueradeOptions, logger log.ContextLogger) (*masquerade, error) {
	cert, err := tls.LoadX509KeyPair(opts.CertificatePath, opts.KeyPath)
	if err != nil {
		return nil, E.Cause(err, "flowtls: 加载伪装站证书失败")
	}
	if host == "" || host == "::" {
		host = "0.0.0.0"
	}
	listenAddr := net.JoinHostPort(host, fmt.Sprint(port))
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, E.Cause(err, "flowtls: 伪装站监听失败 ", listenAddr)
	}
	logger.Info("flowtls 伪装网站已启动 ", listenAddr,
		" (TLS 1.3, ALPN http/1.1, 站点目录: ", displayDir(opts.SiteDir), ")")

	return &masquerade{
		listener: ln,
		logger:   logger,
		siteDir:  opts.SiteDir,
		certs:    []tls.Certificate{cert},
		conns:    make(map[net.Conn]struct{}),
	}, nil
}

func displayDir(dir string) string {
	if dir == "" {
		return "内置占位页"
	}
	return dir
}

// serve 接受连接。
func (m *masquerade) serve() {
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			// 已关闭：正常退出。
			if m.isClosed() {
				return
			}
			m.logger.Debug("flowtls: 伪装站 accept: ", err)
			continue
		}
		go m.handle(conn)
	}
}

func (m *masquerade) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.conns == nil
}

func (m *masquerade) track(conn net.Conn) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.conns == nil {
		return false
	}
	m.conns[conn] = struct{}{}
	return true
}

func (m *masquerade) untrack(conn net.Conn) {
	m.mu.Lock()
	if m.conns != nil {
		delete(m.conns, conn)
	}
	m.mu.Unlock()
}

// handle 完成 TLS 握手并处理 HTTP/1.1 请求。
func (m *masquerade) handle(raw net.Conn) {
	defer raw.Close()
	if !m.track(raw) {
		return
	}
	defer m.untrack(raw)

	// TLS 握手失败通常说明对方不是浏览器（或指纹异常），直接断开即可。
	// 不记录 Info 级日志：扫描器会刷满日志。
	_ = raw.SetDeadline(time.Now().Add(masqueradeConnTimeout))
	tlsConn := tls.Server(raw, m.tlsConfigFor())
	_ = tlsConn.SetDeadline(time.Now().Add(masqueradeTLSTimeout))
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	_ = tlsConn.SetDeadline(time.Now().Add(masqueradeConnTimeout))
	m.serveHTTP(tlsConn)
	m.logger.Debug("flowtls: 伪装站连接结束 ", raw.RemoteAddr())
}

// tlsConfigFor 构造 TLS 配置。
//
// 单独提出成函数是为了让每次握手拿到的 *tls.Config 互不共享可变状态
// （Go 的 tls.Server 会在内部写 handshake 状态）。
func (m *masquerade) tlsConfigFor() *tls.Config {
	return &tls.Config{
		Certificates: m.certs,
		MinVersion:   tls.VersionTLS13,
		// 只宣告 http/1.1：实现简单，且真实世界大量站点如此，不会成为指纹。
		NextProtos: []string{"http/1.1"},
	}
}

// serveHTTP 处理一条 TLS 连接上的 HTTP/1.1 请求，支持 keep-alive。
func (m *masquerade) serveHTTP(conn *tls.Conn) {
	buf := make([]byte, 0, masqueradeReadChunk)
	chunk := make([]byte, masqueradeReadChunk)

	for {
		// 每次请求最多读 16KB 头部，防止被恶意超长请求拖垮。
		var headerEnd int
		for {
			n, err := conn.Read(chunk)
			if n > 0 {
				buf = append(buf, chunk[:n]...)
				if pos := findHeadersEnd(buf); pos >= 0 {
					headerEnd = pos
					break
				}
				if len(buf) > masqueradeMaxHeaderSize {
					return
				}
			}
			if err != nil {
				return
			}
		}

		head := string(buf[:headerEnd])
		requestLine := head
		if idx := strings.IndexAny(head, "\r\n"); idx >= 0 {
			requestLine = head[:idx]
		}
		parts := strings.Fields(requestLine)
		method, path := "GET", "/"
		if len(parts) > 0 {
			method = parts[0]
		}
		if len(parts) > 1 {
			path = parts[1]
		}
		// 绝对 URI 形式（GET http://host/path HTTP/1.1）只取 path 部分。
		if idx := strings.Index(path, "://"); idx >= 0 {
			if slash := strings.Index(path[idx+3:], "/"); slash >= 0 {
				path = path[idx+3+slash:]
			} else {
				path = "/"
			}
		}

		status, body, ctype := m.route(method, path)

		// 保持连接，除非客户端明确要求关闭。
		keepAlive := !strings.Contains(strings.ToLower(head), "connection: close")
		connState := "keep-alive"
		if !keepAlive {
			connState = "close"
		}
		resp := fmt.Sprintf(
			"HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: %s\r\nServer: nginx\r\nCache-Control: public, max-age=300\r\n\r\n",
			status, ctype, len(body), connState)
		payload := append([]byte(resp), body...)
		if method == "HEAD" {
			payload = []byte(resp)
		}
		if _, err := conn.Write(payload); err != nil {
			return
		}

		// 丢掉已处理的请求，保留可能粘在后面的下一请求。
		buf = append(buf[:0], buf[headerEnd:]...)
		if !keepAlive {
			return
		}
	}
}

// route 决定响应。返回 status / body / content-type。
func (m *masquerade) route(method, path string) (string, []byte, string) {
	if method != "GET" && method != "HEAD" {
		// 只允许常规只读方法，异常方法返回 405，
		// 避免看起来像可写的业务系统。
		return "405 Method Not Allowed", []byte("Method Not Allowed"), "text/plain; charset=utf-8"
	}
	switch path {
	case "/robots.txt":
		return "200 OK", []byte(robotsTXT), "text/plain; charset=utf-8"
	case "/favicon.ico":
		// 返回 204 比返回 404 更像正常站点。
		return "204 No Content", nil, "image/x-icon"
	}

	// 静态文件优先：也用于带宽对比测试。
	rel := strings.TrimPrefix(path, "/")
	if m.siteDir != "" && rel != "" && !strings.Contains(rel, "..") {
		fp := filepath.Join(m.siteDir, rel)
		if data, err := os.ReadFile(fp); err == nil {
			return "200 OK", data, contentTypeOf(rel)
		}
	}

	// 目录首页。
	if m.siteDir != "" {
		if data, err := os.ReadFile(filepath.Join(m.siteDir, "index.html")); err == nil {
			return "200 OK", data, "text/html; charset=utf-8"
		}
	}
	return "200 OK", []byte(builtinIndexHTML), "text/html; charset=utf-8"
}

// contentTypeOf 按扩展名给出 Content-Type，与 Rust 一致。
func contentTypeOf(rel string) string {
	switch {
	case strings.HasSuffix(rel, ".bin"):
		return "application/octet-stream"
	case strings.HasSuffix(rel, ".png"):
		return "image/png"
	case strings.HasSuffix(rel, ".jpg"), strings.HasSuffix(rel, ".jpeg"):
		return "image/jpeg"
	case strings.HasSuffix(rel, ".css"):
		return "text/css"
	case strings.HasSuffix(rel, ".js"):
		return "application/javascript"
	case strings.HasSuffix(rel, ".html"):
		return "text/html; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

// findHeadersEnd 找到 HTTP 头结束位置（\r\n\r\n），返回结束后的偏移。
func findHeadersEnd(buf []byte) int {
	for i := 0; i+3 < len(buf); i++ {
		if buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n' {
			return i + 4
		}
	}
	return -1
}

// close 停止监听并断开所有连接。
func (m *masquerade) close() {
	m.closeOnce.Do(func() {
		_ = m.listener.Close()
		m.mu.Lock()
		conns := make([]net.Conn, 0, len(m.conns))
		for c := range m.conns {
			conns = append(conns, c)
		}
		m.conns = nil
		m.mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
}
