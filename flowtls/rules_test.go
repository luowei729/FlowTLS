package flowtls

import (
	"strings"
	"testing"
)

// u32 的右值必须带 0x 前缀。
//
// 内核解析器用 simple_strtoul(..., base=0)：只有带 0x 才按十六进制，
// 否则 "f1004000" 会被按十进制解析失败并返回 0，规则永不命中。
// 后果很隐蔽——iptables -C 报告规则存在，但内核照旧回 RST 把连接打断，
// 日志里一点异常都没有。这条单测就是为了钉住它。
func TestU32ExprHasHexPrefix(t *testing.T) {
	expr := U32IPIDExpr(0xF107)
	if !strings.HasPrefix(expr, "0x4&0xff00ffff=0x") {
		t.Fatalf("u32 右值必须带 0x 前缀，实际是 %q", expr)
	}
	if expr != "0x4&0xff00ffff=0xf1004000" {
		t.Fatalf("表达式与预期不符：%q", expr)
	}
}

// 标记必须来自配置，不能写死：
// 写死意味着 DPI 只要一条通用规则就能命中所有部署。
//
// 注意规则现在有两条（wscale 主特征 + IP ID 辅助），magic 只影响后者，
// 所以这里比较整组规则而不是第一条。
func TestRulesFollowMagic(t *testing.T) {
	a := serverRuleStrings(8443, 0xF107)
	b := serverRuleStrings(8443, 0x1E07)
	if a == b {
		t.Fatal("不同 magic 必须生成不同规则")
	}
	if !strings.Contains(b, "0x1e004000") {
		t.Fatalf("标记高字节应来自 magic，实际：%s", b)
	}
}

// serverRuleStrings 把整组服务端规则拼成一个便于比较的字符串。
func serverRuleStrings(port, magic uint16) string {
	var b strings.Builder
	for _, r := range ServerRules(port, magic) {
		b.WriteString(r.String())
		b.WriteByte('\n')
	}
	return b.String()
}

// wscale 规则必须真实存在且位置正确（偏移 56 的 NOP+wscale）。
//
// 这条是分流的核心：IP ID 匹配有 1/16 误命中率，且会被部分链路改写，
// 只有 TCP 选项是端到端稳定字段。
func TestServerRuleUsesWScale(t *testing.T) {
	rules := ServerRules(8443, 0xF107)
	var found bool
	for _, r := range rules {
		joined := strings.Join(r.Spec, " ")
		if strings.Contains(joined, U32WScaleExpr()) {
			found = true
			if !strings.Contains(joined, "--tcp-flags SYN,ACK SYN") {
				t.Fatalf("wscale 规则必须只匹配纯 SYN：%s", joined)
			}
		}
	}
	if !found {
		t.Fatalf("服务端必须有按 wscale 匹配的规则，实际：%v", rules)
	}
	// 偏移 56 起 4 字节 = NOP + kind3 + len3 + value12
	if got, want := U32WScaleExpr(), "0x38&0xffffffff=0x0103030c"; got != want {
		t.Fatalf("wscale 表达式不符：got %q want %q", got, want)
	}
}

// 低字节必须被掩掉：它随每个包递增（NextIPID），
// 若参与匹配则规则只会命中 1/256 的包。
func TestU32IgnoresIPIDLowByte(t *testing.T) {
	if U32IPIDExpr(0xF100) != U32IPIDExpr(0xF1FF) {
		t.Fatal("IP ID 低字节不应影响表达式")
	}
	if U32IPIDExpr(0xF1AA) != U32IPIDExpr(0xF107) {
		t.Fatal("同一高字节的不同 magic 必须产生同一表达式")
	}
}

// 服务端规则的关键要素：raw 表、PREROUTING、目标端口、u32、DROP。
func TestServerRuleShape(t *testing.T) {
	rules := ServerRules(8443, 0xF107)
	if len(rules) != 2 {
		t.Fatalf("服务端需要 2 条规则（wscale + IP ID），得到 %d", len(rules))
	}
	for _, r := range rules {
		assertServerRuleShape(t, r)
	}
}

func assertServerRuleShape(t *testing.T, r Rule) {
	t.Helper()
	if r.Table != "raw" {
		t.Fatalf("服务端规则必须在 raw 表，实际 %q", r.Table)
	}
	if r.Chain != "PREROUTING" {
		t.Fatalf("服务端规则必须在 PREROUTING，实际 %q", r.Chain)
	}
	// -A 与 -D 必须只差一个动作词，否则卸载会失败
	add := strings.Join(r.Command("-A"), " ")
	del := strings.Join(r.Command("-D"), " ")
	if add == del {
		t.Fatal("-A 与 -D 不能相同")
	}
	if strings.Replace(add, " -A ", " -D ", 1) != del {
		t.Fatalf("增删命令除动作外必须完全一致：\nadd=%s\ndel=%s", add, del)
	}
	if !strings.HasSuffix(add, "-j DROP") {
		t.Fatalf("规则应以 -j DROP 结束：%s", add)
	}
	if !strings.Contains(add, "--dport 8443") {
		t.Fatalf("规则应匹配目标端口：%s", add)
	}
}

// 客户端两条规则：OUTPUT 拦 RST、INPUT 丢回程包。
func TestClientRuleShape(t *testing.T) {
	rules := ClientRules(44300, 8443, 0xF107)
	if len(rules) != 2 {
		t.Fatalf("客户端需要 2 条规则，得到 %d", len(rules))
	}

	out := rules[0]
	if out.Table != "" || out.Chain != "OUTPUT" {
		t.Fatalf("第一条应是 filter 表的 OUTPUT，实际 table=%q chain=%q", out.Table, out.Chain)
	}
	outCmd := out.String()
	if !strings.Contains(outCmd, "--sport 44300") || !strings.Contains(outCmd, "--tcp-flags RST RST") {
		t.Fatalf("OUTPUT 规则应精确匹配源端口 + RST：%s", outCmd)
	}

	in := rules[1]
	if in.Table != "" || in.Chain != "INPUT" {
		t.Fatalf("第二条应是 filter 表的 INPUT，实际 table=%q chain=%q", in.Table, in.Chain)
	}
	inCmd := in.String()
	if !strings.Contains(inCmd, "--sport 8443") || !strings.Contains(inCmd, "0x4&0xff00ffff=0xf1004000") {
		t.Fatalf("INPUT 规则应匹配服务端端口 + 标记：%s", inCmd)
	}
	// filter 表不写 -t，与手工执行的命令逐字一致
	if strings.Contains(inCmd, "-t ") {
		t.Fatalf("filter 表不应显式写 -t：%s", inCmd)
	}
}

// ParseIPTablesMode：空串按 print（安全默认），未知值必须报错。
func TestParseIPTablesMode(t *testing.T) {
	cases := map[string]IPTablesMode{
		"":       IPTablesPrint,
		"print":  IPTablesPrint,
		"PRINT":  IPTablesPrint,
		" none ": IPTablesNone,
		"auto":   IPTablesAuto,
	}
	for in, want := range cases {
		got, err := ParseIPTablesMode(in)
		if err != nil {
			t.Fatalf("%q 不应报错：%v", in, err)
		}
		if got != want {
			t.Fatalf("%q 解析成 %v，预期 %v", in, got, want)
		}
	}
	if _, err := ParseIPTablesMode("atuo"); err == nil {
		t.Fatal("拼错的模式必须报错，不能静默降级")
	}
}

// print / none 模式不得访问系统：它们必须能在任意权限、任意平台下通过。
func TestApplyRulesPassiveModes(t *testing.T) {
	rules := ServerRules(8443, 0xF107)

	for _, mode := range []IPTablesMode{IPTablesNone, IPTablesPrint} {
		report, err := ApplyRules(mode, rules)
		if err != nil {
			t.Fatalf("mode=%v 不应报错：%v", mode, err)
		}
		if report.Added != 0 || report.Existing != 0 {
			t.Fatalf("mode=%v 不应统计落地条数", mode)
		}
	}

	// print 模式的文本必须包含安装与卸载两种命令，否则运维得自己反推
	report, _ := ApplyRules(IPTablesPrint, rules)
	text := report.Text()
	if !strings.Contains(text, "iptables -t raw -A PREROUTING") {
		t.Fatalf("print 文本缺少安装命令：\n%s", text)
	}
	if !strings.Contains(text, "-D PREROUTING") {
		t.Fatalf("print 文本缺少卸载命令：\n%s", text)
	}
}

// none 模式的文本要明确「需自行维护」，避免被当成「已经装好了」。
func TestRuleReportNoneText(t *testing.T) {
	report, _ := ApplyRules(IPTablesNone, ServerRules(8443, 0xF107))
	if !strings.Contains(report.Text(), "需自行维护") {
		t.Fatalf("none 模式必须提示需自行维护：%s", report.Text())
	}
}
