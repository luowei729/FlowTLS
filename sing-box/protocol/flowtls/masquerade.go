package flowtls

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// MasqueradeOptions 是同端口真证书网站的配置。
//
// 为什么需要它：flowtls 的包特征再像 TLS，主动探测者仍然会**真的去连**
// 那个端口。如果那里什么都没有（或只有自签证书），一个 RST / 一个证书告警
// 就足以判定「这不是网站」。所以同一端口必须跑一个真实可访问的 HTTPS 站点。
//
// 与 Rust 版的关系：Rust 把站点做在协议进程内；Go 版也做在 inbound 内，
// 但用配置显式开启，不开启时 inbound 只做隧道（行为与之前一致）。
//
// **注意**：这会真正 bind 内核 TCP 端口。协议本身不 bind，
// 只有这个伪装站 bind。两者不冲突——内核只处理「没被 DROP 掉的包」。
type MasqueradeOptions struct {
	// SiteDir 是静态站点根目录。
	//
	// 留空时返回一个极简占位页。**生产环境务必填真实内容**：
	// 占位页本身就是指纹，一个只有 "It works" 的站点比没有站点更可疑。
	SiteDir string
	// CertificatePath / KeyPath 是**真证书**（Let's Encrypt、CloudFlare
	// Origin CA 等）。探测者能看到证书链，自签证书等于自报家门。
	CertificatePath string
	KeyPath         string
	// ProxyURL 非空时开启反向代理模式，优先于 SiteDir。
	//
	// 为什么反代比静态文件更难识破：静态站点的目录结构、响应头顺序、
	// 404 页、ETag 格式都是可枚举的；而反代拿到的是一个真实在跑的站点，
	// 探测者看到的一切都与直接访问那个站点完全一致。
	ProxyURL string
	// RewriteHost 决定反向代理转发时 Host 头用哪个（语义同 hysteria2）。
	RewriteHost bool
	// ServerName 仅用于日志，可为空。
	ServerName string
}

// Masquerade 是同端口伪装站点。
//
// 它监听内核 TCP（flowtls 的伪造包不经过这里），
// 只有在配置里开启时才存在。
type Masquerade struct {
	opts     MasqueradeOptions
	listener net.Listener
	server   *http.Server

	mu     sync.Mutex
	closed bool
}

// newMasquerade 校验配置并绑定端口。
//
// 任何一项不满足都直接报错而不是降级：
// 一个「以为开了但没开」的伪装站，比明确报错危险得多——
// 运维会以为端口探测已经处理好了。
func newMasquerade(ctx context.Context, addr net.Addr, opts MasqueradeOptions) (*Masquerade, error) {
	if opts.CertificatePath == "" || opts.KeyPath == "" {
		return nil, E.New("flowtls: masquerade 必须提供 certificate_path 与 key_path（真证书，不能用自签）")
	}
	for _, p := range []string{opts.CertificatePath, opts.KeyPath} {
		if _, err := os.Stat(p); err != nil {
			return nil, E.Cause(err, "flowtls: 读取证书文件 ", p)
		}
	}
	if opts.SiteDir != "" {
		info, err := os.Stat(opts.SiteDir)
		if err != nil {
			return nil, E.Cause(err, "flowtls: 站点目录 ", opts.SiteDir)
		}
		if !info.IsDir() {
			return nil, E.New("flowtls: site_dir 不是目录: ", opts.SiteDir)
		}
	}
	// 两种模式互斥：静默二选一会让运维以为自己配的那个生效了。
	// （优先级写在注释里不够，报错才能真检到。）
	if opts.ProxyURL != "" && opts.SiteDir != "" {
		return nil, E.New("flowtls: masquerade 的 proxy_url 与 site_dir 只能填一个")
	}
	if opts.ProxyURL != "" {
		u, err := url.Parse(opts.ProxyURL)
		if err != nil {
			return nil, E.Cause(err, "flowtls: 解析 proxy_url")
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, E.New("flowtls: proxy_url 必须带 http:// 或 https:// 前缀: ", opts.ProxyURL)
		}
		if u.Host == "" {
			return nil, E.New("flowtls: proxy_url 缺少主机名: ", opts.ProxyURL)
		}
	}

	cert, err := tls.LoadX509KeyPair(opts.CertificatePath, opts.KeyPath)
	if err != nil {
		return nil, E.Cause(err, "flowtls: 加载证书失败（fullchain 必须是「站点证书 + 中间证书」）")
	}

	// 只启用 TLS 1.2+ 与 HTTP/1.1、HTTP/2：
	// 真实网站不会拒绝这些版本，也不会提供 ALPN 之外的协议。
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	ln, err := net.Listen("tcp", addr.String())
	if err != nil {
		return nil, E.Cause(err, "flowtls: masquerade 监听 ", addr)
	}

	m := &Masquerade{opts: opts}
	m.server = &http.Server{
		Handler: m.handler(),
		// 与真实站点一致的超时，避免「没有超时」成为特征
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// 必须显式给一个丢弃型 logger。
		//
		// ErrorLog 为 nil 不等于「不打印」——Go 的语义是「用标准 logger」，
		// 也就是全部写到 stderr。对这个站点来说那是灾难：
		// 主动探测者会故意发畸形 TLS，每次握手失败都会打一行
		// "http: TLS handshake error from <IP>: ..."，
		// 把 sing-box 自己的日志冲掉，还会把探测者的 IP 留在盘上。
		ErrorLog: log.New(io.Discard, "", 0),
	}
	// TLS 握手在 listener 层完成，http.Server 只处理明文 HTTP。
	m.listener = tls.NewListener(ln, tlsConf)

	go func() {
		err := m.server.Serve(m.listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
			// 服务端异常退出不应该让整个 inbound 跟着挂掉：
			// 隧道才是主功能，站点只是伪装。
			_ = err
		}
	}()
	return m, nil
}

// handler 返回静态文件处理器。
//
// 直接用 http.FileServer，不自己做路径重写：
// 它已经处理了「/ → index.html」和「/about → /about/ → index.html」
// 这两种情况。手写重写会把 "/" 改写成 "/index.html"，
// 反而触发 FileServer 的 301 回跳，探测者看到一次多余的跳转。
func (m *Masquerade) handler() http.Handler {
	// 反代优先：它比静态文件更难识破，见 ProxyURL 字段注释。
	if m.opts.ProxyURL != "" {
		target, err := url.Parse(m.opts.ProxyURL)
		if err != nil {
			// newMasquerade 已经校验过一次，这里只是防御。
			return http.NotFoundHandler()
		}
		proxy := &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(target)
				if !m.opts.RewriteHost {
					// 沿用客户端的 Host：目标站点按自己的虚拟主机规则处理，
					// 响应看起来与他直接访问完全一样。
					r.Out.Host = r.In.Host
				}
			},
			// 用独立的 Transport 而不是 http.DefaultTransport：
			// 后者不带超时，一次卡住的回源会永久占住一个连接。
			Transport: &http.Transport{
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        32,
				MaxIdleConnsPerHost: 8,
				IdleConnTimeout:     90 * time.Second,
				// 回源超时：探测者会故意连一个慢路径，
				// 咔住的连接比错误响应更可疑。
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 20 * time.Second,
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				// 回源失败时不要泄露“这是个反代”：
				// 真实站点不可用时也是 502，这里保持一致。
				w.WriteHeader(http.StatusBadGateway)
			},
		}
		return proxy
	}

	if m.opts.SiteDir == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(placeholderPage))
		})
	}
	return m.staticHandler()
}

// staticHandler 处理静态站点请求，行为**逐项对齐 Rust `site/mod.rs`**。
//
// 为什么不能用 http.FileServer：
//
//	FileServer 在目录没有 index.html 时返回**目录列表**。实测服务器上
//	site_dir 只放了 100m.bin，访问 / 得到的是一个 113 字节的目录索引页——
//	一个只有一行下载链接的「网站」比 404 更像靶子。
//	Rust 版的做法是：找不到文件就退回内置首页，永远不会露出目录。
//
// Rust 的完整规则（site/mod.rs 的 serve 函数）：
//
//	GET/HEAD + /robots.txt   → 固定 robots 文本
//	GET/HEAD + /favicon.ico  → 204 空响应（比 404 更像正常站点）
//	GET/HEAD + 实体文件      → 该文件（按扩展名给 Content-Type）
//	GET/HEAD + 其它          → site_dir/index.html，**失败则退回内置首页**
//	其它方法                 → 405
//	响应头带 Server: nginx 与 Cache-Control: public, max-age=300
func (m *Masquerade) staticHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 与 Rust 一致：只允许只读方法。异常方法返回 405 而不是 200，
		// 避免看起来像可写的业务系统。
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusMethodNotAllowed)
			if r.Method != http.MethodHead {
				_, _ = w.Write([]byte("Method Not Allowed"))
			}
			return
		}

		path := r.URL.Path
		switch path {
		case "/robots.txt":
			m.writeResponse(w, r, http.StatusOK, "text/plain; charset=utf-8",
				[]byte("User-agent: *\nAllow: /\n"))
			return
		case "/favicon.ico":
			// 204 比 404 更像正常站点（真实站点几乎都有 favicon）
			m.writeResponse(w, r, http.StatusNoContent, "image/x-icon", nil)
			return
		}

		// 静态文件优先：既用于带宽测试，也给运维放置真实资源的入口。
		rel := strings.TrimPrefix(path, "/")
		if rel != "" && !strings.Contains(rel, "..") {
			fp := filepath.Join(m.opts.SiteDir, rel)
			if data, err := os.ReadFile(fp); err == nil {
				m.writeResponse(w, r, http.StatusOK, contentTypeOf(rel), data)
				return
			}
		}

		// 兜底：site_dir/index.html，读不到就用**编译期内置**的首页。
		//
		// 内置首页是 Rust 版的关键设计（`include_str!("../../web/index.html")`）：
		// 即使 site_dir 为空、被清空、或运维忘了放文件，
		// 访问根路径也是一个完整站点而不是目录列表。
		page, err := os.ReadFile(filepath.Join(m.opts.SiteDir, "index.html"))
		if err != nil {
			page = embeddedIndexHTML
		}
		m.writeResponse(w, r, http.StatusOK, "text/html; charset=utf-8", page)
	})
}

// writeResponse 写一个与 Rust 版响应头一致的响应。
//
// 响应头刻意模仿 nginx：Server 字段、Cache-Control 都与 Rust 版逐字一致。
// 少了这几个头（或写成 Go 默认的空值）本身就是可枚举的指纹。
func (m *Masquerade) writeResponse(w http.ResponseWriter, r *http.Request,
	status int, contentType string, body []byte) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("Server", "nginx")
	h.Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(status)
	// HEAD 不能带 body（但必须带 Content-Length，上面已设）
	if r.Method != http.MethodHead && len(body) > 0 {
		_, _ = w.Write(body)
	}
}

// contentTypeOf 按扩展名返回 Content-Type，取值与 Rust 版一致。
func contentTypeOf(name string) string {
	switch {
	case strings.HasSuffix(name, ".bin"):
		return "application/octet-stream"
	case strings.HasSuffix(name, ".png"):
		return "image/png"
	case strings.HasSuffix(name, ".jpg"), strings.HasSuffix(name, ".jpeg"):
		return "image/jpeg"
	case strings.HasSuffix(name, ".css"):
		return "text/css"
	case strings.HasSuffix(name, ".js"):
		return "application/javascript"
	case strings.HasSuffix(name, ".html"):
		return "text/html; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

// Addr 返回实际监听地址。
func (m *Masquerade) Addr() net.Addr { return m.listener.Addr() }

// Close 停止站点。
func (m *Masquerade) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.mu.Unlock()

	if m.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = m.server.Shutdown(ctx)
	}
	if m.listener != nil {
		return m.listener.Close()
	}
	return nil
}

// placeholderPage 是没配 site_dir 时的占位页。
//
// 它刻意做得**明显是占位页**，避免运维误以为「伪装已经做好了」。
// 真实部署应该指向一个有内容的站点（或直接反向代理到别处）。
const placeholderPage = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>503 Service Unavailable</title></head>
<body style="font-family:system-ui;margin:3rem">
<h1>503 Service Unavailable</h1>
<p>This virtual host is configured but has no content yet.</p>
<hr><address>flowtls masquerade &mdash; set <code>masquerade.site_dir</code></address>
</body>
</html>
`

// netipAddr 把 netip.AddrPort 转成 net.Addr。
//
// net.Listen("tcp", ...) 要字符串，但 netip.AddrPort.String() 对
// IPv4 会输出 "0.0.0.0:8443"——listener 用 net.TCPAddr 更直接。
func netipAddr(addr netip.AddrPort) net.Addr {
	return net.TCPAddrFromAddrPort(addr)
}

// orDefault 返回 s，为空时返回 def。仅用于日志。
func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// masqueradeMode 返回伪装站模式的简短描述，仅用于启动日志。
//
// 把「实际用的是哪种模式」写进日志很重要：proxy_url 与 site_dir
// 都填了会报错，但只填一个时运维仍可能记错自己配的是哪个。
func masqueradeMode(opts *option.FlowTLSMasqueradeOptions) string {
	switch {
	case opts == nil:
		return "disabled"
	case opts.ProxyURL != "":
		if opts.RewriteHost {
			return "proxy → " + opts.ProxyURL + " (rewrite_host)"
		}
		return "proxy → " + opts.ProxyURL
	case opts.SiteDir != "":
		return "site_dir=" + opts.SiteDir
	default:
		return "内置占位页"
	}
}

// validateMasqueradeOptions 做**纯配置**校验，不碰文件系统。
//
// 放在这里而不是 newMasquerade，是因为 `sing-box check` 会走构造函数
// 但不会走 Start：只有放在这里，配置错误才能在启动前被 check 抓到。
// 读证书、建 listener 这类动作仍然留在 Start（见 inbound.go 的注释）。
func validateMasqueradeOptions(opts *option.FlowTLSMasqueradeOptions) error {
	if opts.CertificatePath == "" || opts.KeyPath == "" {
		return E.New("flowtls: masquerade 必须提供 certificate_path 与 key_path（真证书，不能用自签）")
	}
	// 两种模式互斥：静默二选一会让运维以为自己配的那个生效了。
	if opts.ProxyURL != "" && opts.SiteDir != "" {
		return E.New("flowtls: masquerade 的 proxy_url 与 site_dir 只能填一个")
	}
	if opts.ProxyURL != "" {
		u, err := url.Parse(opts.ProxyURL)
		if err != nil {
			return E.Cause(err, "flowtls: 解析 proxy_url")
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return E.New("flowtls: proxy_url 必须带 http:// 或 https:// 前缀: ", opts.ProxyURL)
		}
		if u.Host == "" {
			return E.New("flowtls: proxy_url 缺少主机名: ", opts.ProxyURL)
		}
	}
	return nil
}
