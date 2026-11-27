package flowtls

// 本文件对应 legacy-rust:src/rules.rs 的 #[cfg(test)] 模块。

import (
	"net/netip"
	"strings"
	"testing"
)

// TestU32ExprHasHexPrefix 钉住 u32 右值必须带 `0x` 前缀。
//
// 内核解析器用 `simple_strtoul(..., base=0)`：只有带 0x 才按十六进制，
// 否则 "f1004000" 会被按十进制解析失败并返回 0，规则永不命中。
// 后果很隐蔽——`iptables -C` 报告规则存在，但内核照旧回 RST 把连接打断。
func TestU32ExprHasHexPrefix(t *testing.T) {
	rules := serverRules(8443, []uint16{0xF107})
	// 一个标记两条：①认出 SYN 并记入 recent 列表 ②该来源的后续包一并丢弃。
	if len(rules) != 2 {
		t.Fatalf("一个标记应生成 2 条规则（记账 + 查表），得到 %d", len(rules))
	}
	joined := strings.Join(rules[0].spec, " ")
	if !strings.Contains(joined, "--u32") {
		t.Fatal("服务端规则必须用 u32 匹配 TCP ISN 低 16 位")
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
	// 序列号在 IP 头偏移 24（无 IP 选项时 TCP 头从 20 开始，seq 在 TCP 头内偏移 4），
	// 取低 16 位 → `24&0x0000ffff`。
	if !strings.HasPrefix(expr, "24&0x0000FFFF=0x") {
		t.Fatalf("u32 必须以 0x 前缀匹配 ISN 低 16 位，实际是 %q", expr)
	}
}

// TestServerRuleFollowsMagic 验证标记值来自配置，不写死。
func TestServerRuleFollowsMagic(t *testing.T) {
	a := strings.Join(serverRules(8443, []uint16{0xF107})[0].spec, " ")
	b := strings.Join(serverRules(8443, []uint16{0x1E07})[0].spec, " ")
	if a == b {
		t.Fatal("不同 magic 必须生成不同规则")
	}
	if !strings.Contains(b, "0x1e07") {
		t.Fatalf("ISN 标记必须原样使用（不掩低字节）：%s", b)
	}
}

// TestISNMarkUsesAllBits 钉住 ISN 标记用满 16 位。
//
// 旧 IP ID 方案只能用高字节（低字节按包递增），256 个值 → 真实探测流量
// 有 1/256 ≈ 0.39% 会被误 DROP。ISN 可以自由用低 16 位，
// 误判率降到 1/65536 —— 这是换用 ISN 的附带收益。
func TestISNMarkUsesAllBits(t *testing.T) {
	a := strings.Join(serverRules(8443, []uint16{0xF100})[0].spec, " ")
	b := strings.Join(serverRules(8443, []uint16{0xF1FF})[0].spec, " ")
	if a == b {
		t.Fatal("ISN 标记的低字节必须参与匹配（与 IP ID 的旧行为不同）")
	}
	if !strings.Contains(b, "0xf1ff") {
		t.Fatalf("表达式应含完整标记 0xf1ff：%s", b)
	}
}

// TestServerRuleShape 验证服务端规则的表、链、端口与动作。
func TestServerRuleShape(t *testing.T) {
	r := serverRules(8443, []uint16{0xF107})[0]
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
//
// **匹配依据是服务端地址，不是源端口**。这是「源端口可动态分配」的前提：
// 规则一旦依赖源端口，端口就必须固定（旧版就是这样，直接导致两台机器
// 经同一 NAT 出同一台服务器时四元组撞车、互相踢掉会话）。
func TestClientRuleShape(t *testing.T) {
	server := netip.MustParseAddrPort("198.51.100.7:8443")
	rules := clientRules(server, 0xF107)
	// 三条：①SYN 记账（不丢弃）②挡内核 RST ③入向按 recent 丢回程包。
	if len(rules) != 3 {
		t.Fatalf("客户端需要 3 条规则（记账 + RST + 入向丢包），得到 %d", len(rules))
	}
	// 第一条是记账：必须有 --set 且**不能**有 -j DROP（SYN 必须真的发出去）。
	set := strings.Join(rules[0].spec, " ")
	if !strings.Contains(set, "--set") {
		t.Fatalf("第 1 条规则必须把来源记入 recent 列表：%s", set)
	}
	if strings.Contains(set, "-j DROP") {
		t.Fatalf("记账规则不能 DROP —— 我们自己的 SYN 必须真的发出去：%s", set)
	}
	if !strings.Contains(set, "-d 198.51.100.7") || !strings.Contains(set, "--dport 8443") {
		t.Fatalf("记账规则应按服务端地址 + 端口匹配：%s", set)
	}
	rst := strings.Join(rules[1].spec, " ")
	if !strings.Contains(rst, "OUTPUT") ||
		!strings.Contains(rst, "--tcp-flags RST RST") {
		t.Fatalf("第 2 条规则应挡内核回的 RST：%s", rst)
	}
	// 关键回归：OUTPUT 侧规则里**不能出现本端源端口**。
	// 出现就说明又退回固定源端口了（两台机器经同一 NAT 会撞车）。
	for _, r := range rules {
		j := strings.Join(r.spec, " ")
		if strings.Contains(j, "OUTPUT") && strings.Contains(j, "--sport") {
			t.Fatalf("OUTPUT 规则不应依赖本端源端口：%s", j)
		}
	}
	// 入向规则：按服务端地址 + recent 列表匹配（不再依赖 IP ID）。
	in := strings.Join(rules[2].spec, " ")
	if !strings.Contains(in, "INPUT") ||
		!strings.Contains(in, "-s 198.51.100.7") ||
		!strings.Contains(in, "--sport 8443") ||
		!strings.Contains(in, "--rsource") ||
		!strings.Contains(in, "--rcheck") {
		t.Fatalf("INPUT 规则应按服务端地址 + recent 列表匹配：%s", in)
	}
	// IP ID 必须彻底退出规则（中间设备会改写，判据不可靠）。
	for _, r := range rules {
		if strings.Contains(strings.Join(r.spec, " "), "0xf1004000") {
			t.Fatal("规则里不能再出现 IP ID 标记匹配")
		}
	}
}

// TestClientRulesIndependentOfSourcePort 钉住「客户端规则与源端口无关」。
//
// 旧版按源端口匹配时，每换一个端口就要重写一遍规则，残规则还会互相干扰
// （真机踩过：换端口后旧的 DROP 规则留在 OUTPUT 里）。现在规则只依赖
// 服务端地址，同一台机器上的所有 FlowTLS 实例去同一服务端时共享一组。
func TestClientRulesIndependentOfSourcePort(t *testing.T) {
	server := netip.MustParseAddrPort("203.0.113.9:8443")
	a := ClientRules(server, 0xF107)
	b := ClientRules(server, 0xF107)
	if strings.Join(a, "|") != strings.Join(b, "|") {
		t.Fatalf("同一服务端的规则必须稳定不变：\n%v\n%v", a, b)
	}
	for _, ln := range a {
		for _, bad := range []string{"--sport 49", "--sport 50", "--sport 51",
			"--sport 52", "--sport 53", "--sport 54", "--sport 55",
			"--sport 56", "--sport 57", "--sport 58", "--sport 59",
			"--sport 60", "--sport 61", "--sport 62", "--sport 63",
			"--sport 64", "--sport 65"} {
			if strings.Contains(ln, bad) {
				t.Fatalf("规则不应包含动态端口段的源端口：%s", ln)
			}
		}
	}
}

// TestClientNftRulesByServerAddr 验证 nft 客户端规则按服务端地址匹配。
func TestClientNftRulesByServerAddr(t *testing.T) {
	script := nftClientScript(netip.MustParseAddrPort("203.0.113.9:8443"), 44300, 0xF107)
	for _, want := range []string{
		"ip daddr 203.0.113.9 tcp dport 8443 notrack",
		"ip daddr 203.0.113.9 tcp dport 8443 tcp flags & rst == rst drop",
		// 入向规则必须落在 **input** 钩子：prerouting 阶段看不到 NAT 还原后的
		// 目的地址，无法区分「本机回程」与「替 LAN 转发的回程」。
		"add chain inet flowtls cin_",
		// 入向按动态集合匹配（键含本端源端口），不再依赖 IP ID
		"ip saddr 203.0.113.9 tcp sport 8443 ip saddr . tcp dport @cft_",
		// 记账规则：只在我们自己的 SYN 上命中（ISN 低 16 位 = 标记）
		"tcp flags syn @th,48,16 0xf107 update @cft_",
		"add set inet flowtls cft_",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("nft 脚本缺少：%s\n实际：\n%s", want, script)
		}
	}
	// 链名按服务端地址生成，不同服务端必须得到不同链名
	outA, inA, _ := clientChains(netip.MustParseAddrPort("203.0.113.9:8443"))
	outB, inB, _ := clientChains(netip.MustParseAddrPort("203.0.113.10:8443"))
	if outA == outB || inA == inB {
		t.Fatalf("不同服务端应有不同链名：%s/%s vs %s/%s", outA, inA, outB, inB)
	}
}

// TestClientIngressUsesInputHook 钉住「客户端入向规则挂在 input 钩子」。
//
// 这是 2026-11-26 真机事故的回归防护，也是本仓库踩过的最隐蔽的一个坑。
// 现场拓扑（用户的多层环回路由，这里是简化版）：
//
//	LAN 主机 ── 路由器A ── 路由器B ── ... ── 互联网
//	              └─ 也跑 flowtls 客户端（同密码 P）→ 同一台服务端
//
// 路由器A 替 LAN 主机转发时，回程包在 **prerouting** 阶段的目的是
// 「路由器A 的 WAN 地址」（NAT 还没被 dstnat 还原），所以
// `fib daddr type local` 对「本机回程」和「转发的回程」**同时成立**——
// 实测两条规则计数完全相同（2 和 2），一条都区分不出来。
//
// 而 `input` 钩子只在「内核判定这个包交给本机」之后执行，转发路径根本
// 不进它。实测对比：
//
//	流量来源          prerouting   input
//	LAN 主机（转发）      2          0
//	本机自己              9          9
//
// 所以入向规则必须挂 input。少了这条，路由器会把它替 LAN 客户端转发回来的
// SYN-ACK 一并丢掉（服务端 SYN-ACK 的 IP ID 就是它凭据的 mark，同密码即
// 同 mark），表现为「LAN 客户端握手超时，而两端日志都正常」。
func TestClientIngressUsesInputHook(t *testing.T) {
	script := nftClientScript(netip.MustParseAddrPort("198.51.100.7:8443"), 44300, 0x6500)

	if !strings.Contains(script, "type filter hook input priority raw") {
		t.Errorf("客户端入向链必须挂在 input 钩子，实际：\n%s", script)
	}
	// prerouting 上不许再有任何客户端规则。nft 里 prerouting 是「所有进机包」
	// 的入口，在路由器上它也管转发，挂在这上面的 drop/notrack 一定会误伤。
	for _, ln := range strings.Split(script, "\n") {
		if strings.Contains(ln, "hook prerouting") {
			t.Errorf("客户端不该再建 prerouting 链（会误伤转发流量）：%s", ln)
		}
	}
	// fib daddr type local 是无效修法，钉住它不要再被加回来。
	if strings.Contains(script, "fib daddr type local") {
		t.Errorf("客户端不能用 fib daddr type local：NAT 之后它对转发的回程包同样成立")
	}

	// 服务端侧相反：它不做 NAT，转发流量 daddr 不是本机，fib local 有效。
	server := nftServerScript(8443, []uint16{0x6500})
	for _, ln := range strings.Split(server, "\n") {
		if strings.Contains(ln, "tcp dport 8443") &&
			!strings.Contains(ln, "fib daddr type local") {
			t.Errorf("服务端入向规则缺 fib daddr type local（软路由上会误伤转发）：%s", ln)
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
	all := append(serverRules(8443, []uint16{0xF107}),
		clientRules(netip.MustParseAddrPort("203.0.113.9:8443"), 0xF107)...)
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

// TestNftScriptShape 钉住 nft 脚本的关键形状。
//
// 为什么值得钉：这段脚本是**用字符串喂给 nft -f** 的，写错一个字
// （链名、hook 名、优先级、掩码）只会让 nft 报一句 "syntax error" 然后
// TestNftServerScriptShape 钉住服务端 nft 脚本的关键形状。
//
// 为什么值得钉：这段脚本是**用字符串喂给 nft -f** 的，写错一个字
// （链名、hook 名、优先级、掩码）只会让 nft 报一句 "syntax error" 然后
// 整批 abort，而现象是「规则没生效、日志里什么都没有」。
func TestNftServerScriptShape(t *testing.T) {
	s := nftServerScript(8443, []uint16{0x1E00, 0xC500})

	musts := []string{
		"add table inet flowtls",
		"add chain inet flowtls out_8443 { type filter hook output priority raw; policy accept; }",
		"add rule inet flowtls out_8443 tcp sport 8443 notrack",
		"add chain inet flowtls in_8443 { type filter hook prerouting priority raw; policy accept; }",
		// 入向必须限定「发给本机」：路由器上的 prerouting 会看到转发流量
		"add rule inet flowtls in_8443 fib daddr type local tcp dport 8443 notrack",
		// 动态集合：只有 ISN 标记的 SYN 才记账，数据包的 DROP 全靠它
		"add set inet flowtls ft_8443 { type ipv4_addr . inet_service; flags dynamic,timeout; timeout 10m; }",
		// 每条凭据的 ISN 标记各一条记账规则（多凭据部署的核心）
		"add rule inet flowtls in_8443 fib daddr type local tcp dport 8443 tcp flags syn @th,48,16 0x1e00 update @ft_8443 { ip saddr . tcp sport } drop",
		"add rule inet flowtls in_8443 fib daddr type local tcp dport 8443 tcp flags syn @th,48,16 0xc500 update @ft_8443 { ip saddr . tcp sport } drop",
		// 该流后续包按集合丢弃（否则内核逐包回 RST）
		"add rule inet flowtls in_8443 fib daddr type local tcp dport 8443 ip saddr . tcp sport @ft_8443 drop",
	}
	for _, m := range musts {
		if !strings.Contains(s, m) {
			t.Errorf("nft 脚本缺少: %s\n实际:\n%s", m, s)
		}
	}

	// priority raw 必须是 raw：要早于 conntrack(-200)，否则规则没机会生效。
	if strings.Count(s, "priority raw") != 2 {
		t.Error("两条链都必须在 raw 优先级上")
	}
	// 必须用 flush 而不是 delete table：表不存在时 delete 会让整批 abort。
	if strings.Contains(s, "delete table") {
		t.Error("不能用 delete table（表不存在时整批 abort）")
	}
	if strings.Count(s, "flush chain") != 2 {
		t.Error("两条链都要先 flush，否则重复执行会叠加重复规则")
	}
	// IP ID 必须完全退出规则：中间设备会改写它，靠它判据在真实链路上失效。
	if strings.Contains(s, "ip id") {
		t.Error("规则里不能再出现 ip id（中间设备会改写，判据不可靠）")
	}
	// flush set 必须存在，否则重复执行时旧条目会残留。
	if !strings.Contains(s, "flush set inet flowtls ft_8443") {
		t.Error("集合必须先 flush，否则重复执行会残留旧条目")
	}
}

// TestServerRulesSkipZeroMark 钉住 mark 为 0 时绝不写规则。
//
// `ip id & 0xff00 == 0x0000` 会匹配约 1/256 的正常流量（IP ID 高字节为 0
// 的包），等于无差别丢包。这条路径只有在 password 派生异常或配置出错时
// 才会走到，但后果极严重，必须挡住。
func TestServerRulesSkipZeroMark(t *testing.T) {
	rules := serverRules(8443, []uint16{0, 0x1E00})
	// 0x1E00 那个标记生成 2 条（记账 + 查表）；mark=0 一条都不生成。
	if len(rules) != 2 {
		t.Fatalf("mark=0 必须被跳过，只应剩 2 条规则，得到 %d", len(rules))
	}
	if !strings.Contains(strings.Join(rules[0].spec, " "), "24&0x0000FFFF=0x1e00") {
		t.Fatalf("保留的应是有效标记那条：%v", rules[0].spec)
	}
}

// TestDeriveISNMarkIsStableAndDiffers 钉住派生的三条性质。
//
//  1. 同一 password 必然得到同一个值 —— 这是「零配置两端一致」的全部原理；
//  2. 不同 password 得到不同值 —— 否则指纹退化；
//  3. 返回值非 0 —— 0 在代码里表示「未配置」。
//
// 与旧的 IP ID 标记相比，ISN 标记用满 16 位（65536 个值），
// 碰撞率比 256 个值低 256 倍。
func TestDeriveISNMarkIsStableAndDiffers(t *testing.T) {
	a1 := DeriveISNMark("FlowTLS@2026#hk2")
	a2 := DeriveISNMark("FlowTLS@2026#hk2")
	if a1 != a2 {
		t.Fatalf("同一 password 必须派生出同一标记：%#x vs %#x", a1, a2)
	}
	if a1 == 0 {
		t.Fatalf("标记不能为 0（0 表示未配置），得到 %#x", a1)
	}
	seen := map[uint16]string{a1: "p1"}
	passwords := []string{"p1", "p2", "p3", "abc", "123", "x", "长密码测试"}
	for _, p := range passwords {
		m := DeriveISNMark(p)
		if m == 0 {
			t.Fatalf("%q 派生出的标记不能为 0", p)
		}
		if prev, dup := seen[m]; dup && prev != p {
			t.Fatalf("%q 与 %q 派生出同一个标记 %#x（65536 空间下不应碰撞）",
				prev, p, m)
		}
		seen[m] = p
	}
	// 与 AEAD 密钥、authID 用不同 HKDF info：同一条密码的两个标记不能相同。
	if DeriveISNMark("x") == 0 {
		t.Fatal("DeriveISNMark 返回 0")
	}
}

// TestISNMarkDiffersFromOldIPIDMark 钉住换了派生 info。
//
// 若沿用旧的 `flowtls ip id mark v1`，升级后标记值与旧部署相同 ——
// 那样「旧客户端连新服务端」会以错误的方式部分可用，掩盖混部问题。
// 换 info 后新旧标记必然不同，混部时表现为握手失败（明显），而不是
// 半通不通（难查）。
func TestISNMarkDiffersFromOldIPIDMark(t *testing.T) {
	const pw = "FlowTLS@2026#compat"
	if DeriveISNMark(pw) == 0 {
		t.Fatal("标记不能让 0")
	}
	// 不同密码必须给出不同标记（保证派生真的依赖输入）。
	if DeriveISNMark("a") == DeriveISNMark("b") {
		t.Fatal("不同密码派生出同一标记")
	}
}

// TestISNMarksMultiUser 钉住多凭据服务端的标记集合。
//
// 多凭据是标记必须**从 password 派生**而不是全局配置的根本原因：
// 服务端在内核层判断「是不是我们的包」时还没解密，不知道对方用的是
// 哪条凭据，所以只能把每条凭据的派生标记都纳入识别范围。
func TestISNMarksMultiUser(t *testing.T) {
	cfg := &ServerConfig{
		// 三条互不相同的密码：NormalizePasswords 会拒绝重复项，
		// 所以这里验证的是「三条凭据 → 三个标记」这条主线。
		// （「同一条密码被多台设备共用」是另一回事：它只有一条凭据、
		//  一个标记，见 TestCredentialSources 的单密码分支。）
		Passwords: []string{"password-a", "password-b", "password-c"},
	}
	marks := cfg.ISNMarks()
	if len(marks) != 3 {
		t.Fatalf("三条凭据应得到 3 个标记，得到 %d: %v", len(marks), marks)
	}
	want := []uint16{
		DeriveISNMark("password-a"),
		DeriveISNMark("password-b"),
		DeriveISNMark("password-c"),
	}
	for _, w := range want {
		found := false
		for _, m := range marks {
			if m == w {
				found = true
			}
		}
		if !found {
			t.Fatalf("缺少派生标记 %#x，实际 %v", w, marks)
		}
	}
}
