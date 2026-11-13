package flowtls

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// validateMasqueradeOptions 必须抓到所有「纯配置」错误。
//
// 这一层存在的唯一理由就是让 `sing-box check`（只走构造函数）
// 能在启动前报错。所以每条规则都要有用例钉住——
// 曾经这些检查全部躺在 Start 里，check 静默通过。
func TestValidateMasqueradeOptions(t *testing.T) {
	base := option.FlowTLSMasqueradeOptions{
		CertificatePath: "/tmp/fullchain.pem",
		KeyPath:         "/tmp/privkey.pem",
	}

	// 复制一份再改字段，避免用例之间互相污染
	with := func(mutate func(*option.FlowTLSMasqueradeOptions)) *option.FlowTLSMasqueradeOptions {
		o := base
		mutate(&o)
		return &o
	}

	// 合法：只配证书（走内置占位页）
	if err := validateMasqueradeOptions(&base); err != nil {
		t.Fatalf("基础配置不应报错：%v", err)
	}
	// 合法：证书 + 静态目录
	if err := validateMasqueradeOptions(with(func(o *option.FlowTLSMasqueradeOptions) {
		o.SiteDir = "/var/www/site"
	})); err != nil {
		t.Fatalf("site_dir 模式不应报错：%v", err)
	}
	// 合法：证书 + 反代
	if err := validateMasqueradeOptions(with(func(o *option.FlowTLSMasqueradeOptions) {
		o.ProxyURL = "https://example.com"
	})); err != nil {
		t.Fatalf("proxy_url 模式不应报错：%v", err)
	}

	cases := []struct {
		name   string
		opts   *option.FlowTLSMasqueradeOptions
		expect string
	}{
		{
			name:   "缺证书路径",
			opts:   with(func(o *option.FlowTLSMasqueradeOptions) { o.CertificatePath = "" }),
			expect: "certificate_path",
		},
		{
			name:   "缺私钥路径",
			opts:   with(func(o *option.FlowTLSMasqueradeOptions) { o.KeyPath = "" }),
			expect: "certificate_path",
		},
		{
			// 静默二选一会让运维以为自己配的那个生效了
			name: "两种模式互斥",
			opts: with(func(o *option.FlowTLSMasqueradeOptions) {
				o.SiteDir = "/var/www/site"
				o.ProxyURL = "https://example.com"
			}),
			expect: "只能填一个",
		},
		{
			name: "proxy_url 缺 scheme",
			opts: with(func(o *option.FlowTLSMasqueradeOptions) {
				o.ProxyURL = "example.com"
			}),
			expect: "http://",
		},
		{
			name: "proxy_url 用了别的 scheme",
			opts: with(func(o *option.FlowTLSMasqueradeOptions) {
				o.ProxyURL = "ftp://example.com"
			}),
			expect: "http://",
		},
		{
			name: "proxy_url 缺主机名",
			opts: with(func(o *option.FlowTLSMasqueradeOptions) {
				o.ProxyURL = "https://"
			}),
			expect: "主机名",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMasqueradeOptions(tc.opts)
			if err == nil {
				t.Fatal("应当报错但通过了")
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Fatalf("错误信息应包含 %q，实际：%v", tc.expect, err)
			}
		})
	}
}

// masqueradeMode 只用于日志，但它的价值在于让运维确认「实际生效的是哪种模式」。
// proxy_url 与 site_dir 互斥，可只填一个时人仍会记错自己配的是哪个。
func TestMasqueradeMode(t *testing.T) {
	cases := []struct {
		opts *option.FlowTLSMasqueradeOptions
		want string
	}{
		{nil, "disabled"},
		{&option.FlowTLSMasqueradeOptions{}, "内置占位页"},
		{&option.FlowTLSMasqueradeOptions{SiteDir: "/var/www"}, "site_dir=/var/www"},
		{&option.FlowTLSMasqueradeOptions{ProxyURL: "https://a.example"}, "proxy → https://a.example"},
		{&option.FlowTLSMasqueradeOptions{ProxyURL: "https://a.example", RewriteHost: true}, "rewrite_host"},
	}
	for _, tc := range cases {
		got := masqueradeMode(tc.opts)
		if !strings.Contains(got, tc.want) {
			t.Fatalf("masqueradeMode=%q，期望包含 %q", got, tc.want)
		}
	}
}

// 占位页必须能被一眼认出是占位页。
//
// 如果它长得像正经网站，运维会误以为「伪装已经做好了」——
// 而一个只有几行字的站点比没有站点更容易被识破。
func TestPlaceholderPageIsObvious(t *testing.T) {
	m := &Masquerade{opts: MasqueradeOptions{}}
	rec := httptest.NewRecorder()
	m.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("占位页应返回 200，实际 %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "503") && !strings.Contains(body, "Service Unavailable") {
		t.Fatalf("占位页应明确表示不可用，实际内容：%s", body)
	}
	// 必须提到该改哪个配置项，否则运维不知道下一步做什么
	if !strings.Contains(body, "site_dir") {
		t.Fatalf("占位页应提示 site_dir 配置项，实际内容：%s", body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type 应为 text/html，实际 %q", ct)
	}
}

// 反代模式必须在两件事上做对：
//   - rewrite_host=false 时沿用客户端 Host；
//   - rewrite_host=true 时改用目标站点的 Host。
//
// 这条区分是有实战代价的：回源第三方站点时用错会直接 403。
func TestReverseProxyHostRewrite(t *testing.T) {
	var gotHost string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("origin"))
	}))
	defer origin.Close()

	run := func(rewriteHost bool) string {
		m := &Masquerade{opts: MasqueradeOptions{
			ProxyURL:    origin.URL,
			RewriteHost: rewriteHost,
		}}
		req := httptest.NewRequest(http.MethodGet, "https://front.example/", nil)
		req.Host = "front.example"
		rec := httptest.NewRecorder()
		m.handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("反代应返回 200，实际 %d", rec.Code)
		}
		if rec.Body.String() != "origin" {
			t.Fatalf("响应体应透传，实际 %q", rec.Body.String())
		}
		return gotHost
	}

	if host := run(false); host != "front.example" {
		t.Fatalf("rewrite_host=false 应沿用客户端 Host，实际 %q", host)
	}
	if host := run(true); host == "front.example" {
		t.Fatalf("rewrite_host=true 应改用目标站点 Host，实际仍是 %q", host)
	}
}
