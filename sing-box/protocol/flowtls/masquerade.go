package flowtls

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

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
	// ServerName 用于日志与 SNI 提示，可为空。
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
		// 不打印任何东西：这个站点的日志对我们没用，
		// 而默认 logger 会把每条请求写进 sing-box 日志，噪声很大。
		ErrorLog: nil,
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
	if m.opts.SiteDir == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(placeholderPage))
		})
	}
	return http.FileServer(http.Dir(m.opts.SiteDir))
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
