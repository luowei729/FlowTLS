package flowtls

// 本文件对应 legacy-rust:src/rules.rs 的 #[cfg(test)] 模块。

import (
	"strings"
	"testing"
)

// TestU32ExprHasHexPrefix 钉住 u32 右值必须带 `0x` 前缀。
//
// 内核解析器用 `simple_strtoul(..., base=0)`：只有带 0x 才按十六进制，
// 否则 "f1004000" 会被按十进制解析失败并返回 0，规则永不命中。
// 后果很隐蔽——`iptables -C` 报告规则存在，但内核照旧回 RST 把连接打断。
func TestU32ExprHasHexPrefix(t *testing.T) {
	rules := serverRules(8443, 0xF107)
	if len(rules) != 1 {
		t.Fatalf("服务端只需 1 条规则（与 Rust 一致），得到 %d", len(rules))
	}
	joined := strings.Join(rules[0].spec, " ")
	if !strings.Contains(joined, "--u32") {
		t.Fatal("服务端规则必须用 u32 匹配 IP ID")
	}
	// 取 --u32 后面紧跟的那个值，不硬编码下标
	pos := -1
	for i, a := range rules[0].spec {
		if a == "--u32" {
			pos = i
			break
		}
	}
	if pos < 0 {
		t.Fatal("规则里应有 --u32")
	}
	expr := rules[0].spec[pos+1]
	if !strings.HasPrefix(expr, "0x4&0xff00ffff=0x") {
		t.Fatalf("u32 右值必须带 0x 前缀，实际是 %q", expr)
	}
}

// TestServerRuleFollowsMagic 验证标记值来自配置，不写死。
func TestServerRuleFollowsMagic(t *testing.T) {
	a := strings.Join(serverRules(8443, 0xF107)[0].spec, " ")
	b := strings.Join(serverRules(8443, 0x1E07)[0].spec, " ")
	if a == b {
		t.Fatal("不同 magic 必须生成不同规则")
	}
	if !strings.Contains(b, "0x1e004000") {
		t.Fatalf("标记高字节应来自 magic: %s", b)
	}
}

// TestU32IgnoresIPIDLowByte 验证低字节被掩掉（FastPath 递增不参与匹配）。
func TestU32IgnoresIPIDLowByte(t *testing.T) {
	a := strings.Join(serverRules(8443, 0xF100)[0].spec, " ")
	b := strings.Join(serverRules(8443, 0xF1FF)[0].spec, " ")
	if a != b {
		t.Fatal("IP ID 低字节不应影响表达式")
	}
}

// TestServerRuleShape 验证服务端规则的表、链、端口与动作。
func TestServerRuleShape(t *testing.T) {
	r := serverRules(8443, 0xF107)[0]
	if r.table != "raw" {
		t.Fatalf("服务端规则必须在 raw 表，实际 %q", r.table)
	}
	add := strings.Join(r.command("-A"), " ")
	if !strings.Contains(add, "PREROUTING") {
		t.Fatalf("服务端规则必须在 PREROUTING：%s", add)
	}
	if !strings.HasSuffix(add, "-j DROP") {
		t.Fatalf("规则应以 -j DROP 结束：%s", add)
	}
	if !strings.Contains(add, "--dport 8443") {
		t.Fatalf("规则应匹配目标端口：%s", add)
	}
	// -A 与 -D 必须只差动作词，否则卸载会失败
	del := strings.Join(r.command("-D"), " ")
	if strings.Replace(add, "-A ", "-D ", 1) != del {
		t.Fatalf("增删命令除动作外必须一致：\nadd=%s\ndel=%s", add, del)
	}
}

// TestClientRuleShape 验证客户端两条规则：OUTPUT 拦 RST、INPUT 丢回程包。
func TestClientRuleShape(t *testing.T) {
	rules := clientRules(44300, 8443, 0xF107)
	if len(rules) != 2 {
		t.Fatalf("客户端需要 2 条规则（与 Rust 一致），得到 %d", len(rules))
	}
	out := strings.Join(rules[0].spec, " ")
	if !strings.Contains(out, "OUTPUT") ||
		!strings.Contains(out, "--sport 44300") ||
		!strings.Contains(out, "--tcp-flags RST RST") {
		t.Fatalf("OUTPUT 规则应精确匹配源端口 + RST：%s", out)
	}
	in := strings.Join(rules[1].spec, " ")
	if !strings.Contains(in, "INPUT") ||
		!strings.Contains(in, "--sport 8443") ||
		// 0xF107 → 标记高字节 0xF1，右值必须是 0xf1004000
		!strings.Contains(in, "0xf1004000") {
		t.Fatalf("INPUT 规则应按服务端口 + IP ID 标记匹配：%s", in)
	}
	// 客户端规则都在 filter 表
	for _, r := range rules {
		if r.table != "" {
			t.Fatalf("客户端规则应在 filter 表，实际 %q", r.table)
		}
	}
}

// TestParseMode 验证 net.mode 只接受 auto / none（与 Rust 一致）。
func TestParseMode(t *testing.T) {
	for _, in := range []string{"", "auto", "none"} {
		if _, err := ParseMode(in); err != nil {
			t.Fatalf("ParseMode(%q) 不应报错: %v", in, err)
		}
	}
	// Rust 没有 print / raw / 其它取值，拼错必须报错而不是静默放过
	for _, in := range []string{"print", "Auto", "AUTO", "raw"} {
		if _, err := ParseMode(in); err == nil {
			t.Fatalf("ParseMode(%q) 应报错（Rust 只接受 auto/none）", in)
		}
	}
}

// TestNoDuplicatedAction 钉住「动作词只能出现一次」。
//
// 曾经 spec 里写了 `-A PREROUTING`，而 command 又无条件插入动作词，
// 于是真机上发出去的是 `iptables -t raw -A -A PREROUTING ...`，
// 服务端启动直接 FATAL。旧单测只 Join(spec) 判断内容，看不出来，
// 所以这里必须检查**完整参数列表**里动作词的出现次数。
func TestNoDuplicatedAction(t *testing.T) {
	all := append(serverRules(8443, 0xF107), clientRules(44300, 8443, 0xF107)...)
	for i, r := range all {
		for _, op := range []string{"-A", "-C", "-D"} {
			args := r.command(op)
			n := 0
			for _, a := range args {
				switch a {
				case "-A", "-C", "-D":
					n++
					if a != op {
						t.Fatalf("规则 %d：动作词应为 %s，出现 %s", i, op, a)
					}
				}
			}
			if n != 1 {
				t.Fatalf("规则 %d：动作词应恰好出现 1 次，实际 %d 次：%v", i, n, args)
			}
		}
	}
}
