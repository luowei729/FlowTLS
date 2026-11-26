package flowtls

// 本文件是 legacy-rust:src/rules.rs 的逐函数翻译。
//
// 对应关系：
//
//	iptables(args)                     → runIPTables
//	server_rules(port, magic)          → ServerRules
//	ensure_server(port, magic)         → EnsureServer
//	ensure_client(sp, dp, magic)       → EnsureClient
//	check_server / check_client        → CheckServer / CheckClient
//
// 规则的作用不是协议需要，而是阻止内核协议栈处理我们的伪造包：
//   - 服务端：把带魔数 IP ID 的 SYN 和无 conntrack 的包在 raw 表丢弃，
//     内核看不到就不会回 SYN-ACK / RST，NAT 映射不会被拆掉，
//     同端口的真网站也不受干扰。
//   - 客户端：屏蔽内核对伪造连接回包（SYN-ACK）产生的 RST。
//
// **不做 Rust 没有的事**：没有 print 模式、没有 conntrack 扩展规则、
// 没有 BPF 过滤器。net.mode 只有 auto / none 两个取值，与 Rust 一致。

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// rule 是一条 iptables 规则：表名 + 匹配条件与动作。
//
// Rust 用 `Vec<String>` 并把 `-A` 放在固定下标上做 `-C` 替换
// （服务端下标 2、客户端下标 0）。那样容易错位，这里把动作单独拿出来，
// 由 Command 统一拼装——语义完全相同，但不是新增机制。
type rule struct {
	// table 为空表示 filter 表（iptables 默认），raw 表必须显式指定。
	table string
	// spec 是「链名 + 匹配条件 + 动作」，**不含 -t / -A / -C / -D**。
	//
	// 动作词（-A/-C/-D）由 command 统一插入到链名之前，这样增删查三
	// 种命令除动作外完全一致——卸载时不会因为少一个字段而失败。
	spec []string
}

// command 返回带指定动作（-A / -C / -D）的完整参数列表。
//
// 参数以切片形式交给 exec，不经过 shell：u32 表达式里的 `&` 和 `=` 因此
// 不需要转义，也不会被 shell 拆开。
func (r rule) command(op string) []string {
	args := make([]string, 0, len(r.spec)+4)
	if r.table != "" {
		args = append(args, "-t", r.table)
	}
	args = append(args, op)
	return append(args, r.spec...)
}

// String 返回可直接粘到 shell 里的命令（用于日志）。
func (r rule) String() string {
	return "iptables " + strings.Join(r.command("-A"), " ")
}

// serverRules 构造服务端规则（对应 Rust `server_rules`）。
//
// 每个标记一条：把发往监听端口、且带该标记的伪包在内核 TCP 栈之前 DROP。
//
// 匹配依据是 IP ID 高字节。**不能写死常量**：写死一个固定值意味着任何
// DPI 只要加一条「IP ID 高字节 == 某值」的通用规则就能命中所有部署。
//
// marks 是一组值：服务端在内核层写规则时还不知道对端是哪个用户
// （解密发生在之后），所以每个用户的派生标记都要各自写一条
// （见 ServerConfig.Marks 的完整说明）。
//
// offset 4 读的是「IP ID(2) + Flags/Frag(2)」四字节：
// Frag 固定 0x4000（DF），掩掉 IP ID 低字节与 MF/offset。
func serverRules(port uint16, marks []uint16) []rule {
	portStr := strconv.Itoa(int(port))
	out := make([]rule, 0, len(marks))
	for _, magic := range marks {
		mark := magic & 0xFF00
		if mark == 0 {
			// 防御：mark 为 0 时 `0x4&0xff00ffff=0x00004000` 会匹配
			// 所有 IP ID 高字节为 0 的包（约占流量的 1/256），
			// 等于无差别丢包。绝不能写进规则。
			continue
		}
		out = append(out, rule{
			table: "raw",
			spec: []string{
				"PREROUTING",
				"-p", "tcp",
				"--dport", portStr,
				"-m", "u32",
				"--u32", fmt.Sprintf("0x4&0xff00ffff=0x%04x4000", mark),
				"-j", "DROP",
			},
		})
	}
	return out
}

// clientRules 构造客户端规则（对应 Rust `ensure_client` 的两条）。
//
//	OUTPUT：屏蔽内核对伪连接回的 RST
//	  Session 走 raw socket，内核里没有对应 socket。收到服务端的
//	  SYN-ACK 或数据时内核会回 RST，RST 是协议合法的「终止」信号，
//	  中间设备会立刻拆掉 NAT 映射，连接就断了。
//
//	INPUT：丢弃服务端回程包
//	  AF_PACKET 在 netfilter 之前收包，DROP 不影响我们拿到数据；
//	  但内核不再为每个包回一个 RST（否则每个回程包都会引出一个
//	  额外的出向包，既浪费带宽也让流量特征更显眼）。
//
// **匹配依据是服务端地址，不是源端口**。这一条改动的理由很硬：
//
//	内核回的 RST 是 `src=<伪源端口> dst=<服务端>:<服务端端口>`，
//	所以「按服务端地址丢 RST」比「按源端口丢 RST」更精确地描述了
//	我们想丢的东西，而且**与源端口无关**——源端口因此可以动态分配。
//
// 为什么必须允许动态源端口：固定源端口意味着一条隧道占一个端口，
// 同机多个实例 / 多台机器经同一个 NAT 出同一台服务器时，四元组会撞车，
// 服务端只能看到一个会话，新 SYN 会把旧会话踢掉（真机踩过：
// haproxy 里 FlowTLS 后端被反复标 DOWN）。
//
// 代价：本机发往 `服务端:服务端端口` 的 RST 会被一并丢弃。
// 该端口是 FlowTLS 专用（伪装站同端口时只有主动访问才会遇到），可接受。
func clientRules(server netip.AddrPort, magic uint16) []rule {
	mark := magic & 0xFF00
	dst := []string{"-p", "tcp", "-d", server.Addr().String(),
		"--dport", strconv.Itoa(int(server.Port()))}
	src := []string{"-p", "tcp", "-s", server.Addr().String(),
		"--sport", strconv.Itoa(int(server.Port()))}
	return []rule{
		{
			spec: append(append([]string{"OUTPUT"}, dst...),
				"--tcp-flags", "RST", "RST", "-j", "DROP"),
		},
		{
			spec: append(append([]string{"INPUT"}, src...),
				"-m", "u32",
				"--u32", fmt.Sprintf("0x4&0xff00ffff=0x%04x4000", mark),
				"-j", "DROP"),
		},
	}
}

// ServerRules 返回服务端规则的文本形式（供日志展示）。
//
// Rust 版没有独立的展示接口——它在 ensure_* 失败时把规则拼进报错信息。
// Go 侧的 sing-box 适配层需要在启动日志里说明「实际生效了什么」，
// 因此保留一个只读的文本出口。
func ServerRules(port uint16, marks []uint16) []string {
	rules := serverRules(port, marks)
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.String())
	}
	return out
}

// ClientRules 返回客户端规则的文本形式（供日志展示）。
func ClientRules(server netip.AddrPort, magic uint16) []string {
	rules := clientRules(server, magic)
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.String())
	}
	return out
}

// rulesBackendEnabled 决定 Ensure*/Check* 是否真的操作 iptables。
//
// 为什么需要这个开关：本文件是平台中性的（`sing-box check` 要在所有平台
// 都能编译），但 iptables 只在 Linux 上存在。Windows 用 WinDivert 的
// **扣留**语义天然屏蔽了内核对伪包的处理，完全不需要任何防火墙规则
// （详见 rules_windows.go 文件头）。
//
// 默认 true（Linux 行为）；rules_windows.go 在 init 里改成 false。
// 这样调用点不必按平台分叉，避免移植走样。
var rulesBackendEnabled = true

// runIPTables 执行一条 iptables 命令，返回是否成功（对应 Rust `iptables`）。
//
// 规则已存在时 `-A` 会报错，这里视为成功，保证幂等。
func runIPTables(args []string) (bool, error) {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err == nil {
		return true, nil
	}
	// 规则已存在 / 不存在：幂等路径，不算错误
	if strings.Contains(string(out), "already exists") {
		return true, nil
	}
	return false, nil
}

// EnsureServer 幂等写入服务端规则（对应 Rust `ensure_server`）。
//
// **nft 优先**：本机有 nft 就用 nft 写全套规则（notrack + RST 抑制 +
// IP ID 标记丢弃），成功即返回，完全不碰 iptables。
// 只有 nft 不存在或写入失败时才回退到 iptables（老固件 fw3）。
//
// 为什么这个顺序很重要：OpenWrt 22.03+ 默认只装 `iptables-nft`，
// 而 nftables 没有 u32 扩展 —— 走 iptables 分支会直接失败，隧道起不来，
// 用户被迫去装三个包。改用 nft 之后这条路不再需要（DEVTIPS 165）。
func EnsureServer(port uint16, marks []uint16) error {
	if !rulesBackendEnabled {
		return nil // Windows：WinDivert 已扣留伪包，内核看不到（见 rules_windows.go）
	}
	if ensureNftServer(port, marks) {
		return nil
	}
	return ensureIPTables(serverRules(port, marks), "服务端")
}

// EnsureClient 幂等写入客户端规则（对应 Rust `ensure_client`）。
//
// 与 EnsureServer 同样 nft 优先；客户端额外多一条「挡住内核为此伪连接
// 回的 RST」，因为 SYN-ACK 一到内核就找不到对应 socket。
//
// 参数是**服务端地址**而不是源端口：源端口允许动态分配，规则不能依赖它。
func EnsureClient(server netip.AddrPort, magic uint16) error {
	if !rulesBackendEnabled {
		return nil // Windows：同 EnsureServer
	}
	if ensureNftClient(server, magic) {
		return nil
	}
	return ensureIPTables(clientRules(server, magic), "客户端")
}

// ensureIPTables 逐条幂等写入规则（回退路径，nft 不可用时走这里）。
//
// why 只用于报错文案（“服务端”/“客户端”），让用户一眼知道是哪一端失败。
func ensureIPTables(rules []rule, why string) error {
	for _, r := range rules {
		ok, err := runIPTables(r.command("-C"))
		if err != nil {
			return iptablesUnavailable(why, err)
		}
		if ok {
			continue
		}
		ok, err = runIPTables(r.command("-A"))
		if err != nil {
			return iptablesUnavailable(why, err)
		}
		if !ok {
			return fmt.Errorf("flowtls: %s写入 iptables 规则失败: %s", why, r.String())
		}
	}
	return nil
}

// iptablesUnavailable 把底层错误转成可执行的提示。
//
// 这条路径只在本机既没有可用的 nft、又执行不动 iptables 时走到 ——
// 典型原因是缺少 root/CAP_NET_ADMIN，或者固件真的一套防火墙工具都没装。
// 报错必须说清楚两件事：现在不通的原因，以及怎么修。
func iptablesUnavailable(why string, err error) error {
	return fmt.Errorf("flowtls: %s无法写入防火墙规则（nft 与 iptables 都不可用）: %w；"+
		"\n  这两条规则不是可选优化，而是协议能工作的前提："+
		"\n  1. notrack —— 否则 fw4 把伪包判成 ct invalid 丢掉（表现为 sendto 返回 EPERM）"+
		"\n  2. RST 抑制 —— 否则第一个 SYN-ACK 就把 NAT 映射拆掉"+
		"\n  请确认以 root 运行，且系统存在 nft（OpenWrt 22.03+ / fw4）或 iptables（旧固件）。",
		why, err)
}

// CheckServer 只检查规则是否存在，不修改（对应 Rust `check_server`）。
//
// 顺序与 EnsureServer 一致：先看 nft 链，不在才回退查 iptables。
func CheckServer(port uint16, marks []uint16) bool {
	if !rulesBackendEnabled {
		return true // Windows：无需规则，状态恒为「就绪」
	}
	if nftAvailable() {
		return checkNftServer(port, marks)
	}
	for _, r := range serverRules(port, marks) {
		ok, _ := runIPTables(r.command("-C"))
		if !ok {
			return false
		}
	}
	return true
}

// CheckClient 只检查客户端规则是否存在（对应 Rust `check_client`）。
//
// Rust 只检查 OUTPUT 那条（`check_client` 只看 RST 规则），这里保持一致。
func CheckClient(server netip.AddrPort) bool {
	if !rulesBackendEnabled {
		return true // Windows：同 CheckServer
	}
	if nftAvailable() {
		return checkNftClient(server)
	}
	r := clientRules(server, 0)
	ok, _ := runIPTables(r[0].command("-C"))
	return ok
}

// ---------------------------------------------------------------- notrack

// 这一节解决的是**用 nftables 的发行版（OpenWrt fw4、新版 Debian 等）上
// 隧道第二个包起就发不出去**的问题。Rust 版同样有这个缺陷，只是当年
// 的测试环境用 iptables 且没有那条规则，所以没暴露。
//
// ## 现象
//
// 日志里反复出现：
//
//	发送失败（累计 1 次）: sendmmsg: operation not permitted
//	flowtls 握手失败: context deadline exceeded
//
// 且抓包只能看到 SYN 与 SYN-ACK，之后我们自己的数据包**全部消失**。
//
// ## 原因
//
// fw4（OpenWrt 默认防火墙）在 `accept_to_wan` 链里有一条：
//
//	meta nfproto ipv4 oifname "wan" ct state invalid ... drop
//	  comment "!fw4: Prevent NAT leakage"
//
// 我们的伪 TCP 包是自己手写 IP/TCP 头的，序号/确认号与内核 conntrack
// 记录的三次握手状态对不上，于是被判定成 `ct state invalid` 直接 DROP。
// 而 **netfilter 的 DROP 会把错误翻译成 -EPERM 返回给 sendto/sendmmsg**
// （`nf_hook_slow()` 里 `case NF_DROP: ret = -EPERM`），
// 所以表现为「permission denied」而不是「被防火墙拦了」——这条错误信息
// 具有极强的误导性，会让人去查 CAP_NET_RAW / SELinux。
//
// 为什么第一个包（SYN）能出去：那时 conntrack 还没有这个四元组的记录，
// 内核会把 SYN 判成 NEW 并建档；从第二个包起才因为序号对不上变 INVALID。
//
// ## 修法
//
// 在 raw 优先级（-300，早于 conntrack）给这条流打 `notrack`：
// 报文不再进 conntrack，也就没有「invalid」这个状态可判。
// 只按端口匹配，是我们专用的端口，不会误伤业务流量。
//
// **iptables 的 `-j NOTRACK` 在这里不可用**：OpenWrt 的
// `xtables-legacy-multi` 没有编译 xt_NOTRACK 目标，执行会报
// `Couldn't load target 'NOTRACK'`。所以改用 nft 原生语句。
//
// 注意：**出向与入向都要打**。只打出向时，回程包仍会以 invalid 状态
// 进 conntrack，把下一次握手也污染掉——实测「第一次失败、之后成功」
// 的诡异现象就是这么来的。

// notrackTable 是 FlowTLS 专用的 nft 表名。
//
// 用独立表而不是往 fw4 的表里插规则：fw4 每次 reload 都会重建自己的表，
// 插进去的规则会消失；独立表不受它管理，重启服务时我们自己重建。
const notrackTable = "flowtls"

// notrackChains 返回本端口对应的两条链名。
//
// 链名带端口，多个 FlowTLS 实例（例如客户端 + 服务端在同一台机器上）
// 各自维护自己的链，谁都不会清掉别人的规则。
func notrackChains(port uint16) (outChain, inChain string) {
	return "out_" + strconv.Itoa(int(port)), "in_" + strconv.Itoa(int(port))
}

// clientChains 返回客户端两条链名，按**服务端地址**命名。
//
// 为什么不再按源端口命名：源端口现在允许自动分配（每个实例、每次重连
// 都可能不同），按它命名会让链越积越多、也永远清不干净；而规则本身
// 也不该依赖源端口（见 clientRules 的说明）。
// 服务端地址在一台机器上是稳定的，不同服务端天然得到不同链名，互不干扰。
//
// 名字里用 IP 的四字节十六进制 + 端口，保证是合法的 nft 标识符
// （不能直接塞点号，虽然 nft 允许但引号/转义容易出错）。
func clientChains(server netip.AddrPort) (outChain, inChain string) {
	a := server.Addr().As4()
	base := fmt.Sprintf("%x_%d", a, server.Port())
	return "cout_" + base, "cin_" + base
}

// nftClientScript 生成客户端 nft 批处理脚本，按服务端地址匹配。
//
//	方向        规则                                          作用
//	output      daddr=<server> dport=<port> notrack            伪包不进 conntrack
//	output      daddr=<server> dport=<port> rst drop           挡内核回的 RST
//	prerouting  saddr=<server> sport=<port> notrack            回程包不进 conntrack
//	prerouting  saddr=<server> sport=<port> ip id mark drop    挡内核处理回程包
//
// 与旧版的区别只在匹配字段：以前是 `tcp sport <源端口>`，现在是
// `ip daddr/saddr <服务端>`。语义上更窄（只影响这一个服务端），
// 同时因为是「按目的地址」而不是「按源端口」，源端口才能动态分配。
//
// **prerouting 两条必须加 `fib daddr type local`**（见 srcLocal 的注释）。
func nftClientScript(server netip.AddrPort, magic uint16) string {
	outChain, inChain := clientChains(server)
	ip := server.Addr().String()
	portStr := strconv.Itoa(int(server.Port()))
	dst := " ip daddr " + ip + " tcp dport " + portStr
	src := " ip saddr " + ip + " tcp sport " + portStr
	// **只对「发给本机」的回程包生效**。
	//
	// 这两条规则的目的是「让内核不要碰我们的伪连接」：AF_PACKET 在
	// netfilter 之前就能拿到包，所以在这里 DROP/notrack 不影响我们收数据。
	// 而回程包的目的地址就是本机的伪源端口，所以判据天然是「dst 是本机」。
	//
	// 缺了这个条件，路由器上会连**它替 LAN 客户端转发**的回程包一起处理：
	//   - drop 用的是凭据派生出的 mark，而服务端发的 SYN-ACK 的 IP ID 正是
	//     它自己凭据的 mark（listener.go 的 `IPID: RandomIPID(mark)`），
	//     于是 LAN 客户端**永远收不到 SYN-ACK**，表现为「握手超时」；
	//   - notrack 让转发流量绕过 conntrack，fw4 匹配不到 established，
	//     按默认策略丢掉。
	//
	// 典型场景：OpenWrt 路由器自己开一个客户端，它下面的 PC 用**同一个密码**
	// 连**同一台服务端**——同密码同 mark，PC 的 SYN-ACK 被路由器当面丢掉。
	srcLocal := src + " fib daddr type local"
	markExpr := " ip id & 0xff00 == 0x" +
		strconv.FormatUint(uint64(magic&0xFF00), 16)

	lines := []string{
		"add table inet " + notrackTable,
		"add chain inet " + notrackTable + " " + outChain +
			" { type filter hook output priority raw; policy accept; }",
		"flush chain inet " + notrackTable + " " + outChain,
		"add rule inet " + notrackTable + " " + outChain + dst + " notrack",
		"add rule inet " + notrackTable + " " + outChain + dst +
			" tcp flags & rst == rst drop",
		"add chain inet " + notrackTable + " " + inChain +
			" { type filter hook prerouting priority raw; policy accept; }",
		"flush chain inet " + notrackTable + " " + inChain,
		"add rule inet " + notrackTable + " " + inChain + srcLocal + " notrack",
		"add rule inet " + notrackTable + " " + inChain + srcLocal + markExpr + " drop",
	}
	return strings.Join(append(lines, ""), "\n")
}

// ClientNftRules 返回客户端实际写进 nft 的规则（供启动日志展示）。
func ClientNftRules(server netip.AddrPort, magic uint16) []string {
	if !nftAvailable() {
		return nil
	}
	return nftRuleLines(nftClientScript(server, magic))
}

// ensureNftClient 写入客户端 nft 规则，返回是否真的成功。
func ensureNftClient(server netip.AddrPort, magic uint16) bool {
	return runNftScript(nftClientScript(server, magic))
}

// checkNftClient 报告客户端规则是否已就位。
func checkNftClient(server netip.AddrPort) bool {
	if !rulesBackendEnabled {
		return true
	}
	if !nftAvailable() {
		return false
	}
	outChain, inChain := clientChains(server)
	return chainHasRules(outChain) && chainHasRules(inChain)
}

// nftRuleLines 从批处理脚本里挑出 add rule 行并加 nft 前缀（日志用）。
func nftRuleLines(script string) []string {
	var out []string
	for _, ln := range strings.Split(script, "\n") {
		if strings.HasPrefix(ln, "add rule ") {
			out = append(out, "nft "+ln)
		}
	}
	return out
}

// nftServerScript 生成服务端 nft 批处理脚本。
//
//	方向        规则                                          作用
//	prerouting  dport=<端口> notrack                          伪包不进 conntrack
//	prerouting  dport=<端口> ip id == <mark> drop            挡内核处理伪包
//
// marks 是一组值（每个用户一个），每个标记各写一条 drop。
//
// 用 `add table` / `add chain` + `flush chain` 而不是 `delete table`：
// 前者在表已存在时幂等，后者在表不存在时会让整批 abort。
// 先 flush 再 add rule 保证重复执行不叠加重复规则。
//
// **服务端只需要入向规则**：它不发伪包，回程包就是正常的出向数据，
// 内核不会对它们回 RST（服务端是收 SYN-ACK 的一方……不，服务端是回复
// SYN-ACK 的一方，它自己发出去的包都有真实 socket 之外的上下文，
// 但内核并不知道这些 socket，所以仍需 notrack 出向）。见下方 output 链。
func nftServerScript(port uint16, marks []uint16) string {
	outChain, inChain := notrackChains(port)
	portStr := strconv.Itoa(int(port))
	// **入向规则要限定「发给本机」**（`fib daddr type local`）。
	//
	// 服务端通常不转发，但一旦跑在软路由上，prerouting 会同时看到
	// 「替 LAN 主机转发出去」的包：
	//   - `tcp dport <端口> notrack` 会让 dport 恰好是该端口的转发流量
	//     绕过 conntrack，fw4 匹配不到 established 就按默认策略丢掉；
	//   - `ip id & 0xff00 == <mark> drop` 会丢掉 LAN 主机发往别处、
	//     而 IP ID 高字节恰好撞上标记的包。
	// 伪包的目的地址永远是本机（客户端发往的就是这个监听端口），
	// 所以限定 local 不削弱任何防护。
	inLocal := " tcp dport " + portStr + " fib daddr type local"
	lines := []string{
		"add table inet " + notrackTable,
		"add chain inet " + notrackTable + " " + outChain +
			" { type filter hook output priority raw; policy accept; }",
		"flush chain inet " + notrackTable + " " + outChain,
		"add rule inet " + notrackTable + " " + outChain +
			" tcp sport " + portStr + " notrack",
		"add chain inet " + notrackTable + " " + inChain +
			" { type filter hook prerouting priority raw; policy accept; }",
		"flush chain inet " + notrackTable + " " + inChain,
		"add rule inet " + notrackTable + " " + inChain + inLocal + " notrack",
	}
	for _, magic := range marks {
		m := magic & 0xFF00
		if m == 0 {
			continue
		}
		lines = append(lines, "add rule inet "+notrackTable+" "+inChain+
			inLocal+" ip id & 0xff00 == 0x"+
			strconv.FormatUint(uint64(m), 16)+" drop")
	}
	return strings.Join(append(lines, ""), "\n")
}

// NftRules 返回服务端实际写进 nft 的规则（供启动日志展示）。
//
// 返回空切片表示本机没有 nft（老系统），此时走 iptables 分支。
func NftRules(port uint16, marks []uint16) []string {
	if !nftAvailable() {
		return nil
	}
	return nftRuleLines(nftServerScript(port, marks))
}

// nftPath 缓存 nft 可执行文件路径（空串表示没有）。
//
// 只查一次：EnsureClient/EnsureServer 在每次建连都会走到，
// 每次都 exec.LookPath 是没必要的系统调用开销。
var nftPath = func() string {
	p, err := exec.LookPath("nft")
	if err != nil {
		return ""
	}
	return p
}()

// nftAvailable 报告本机有没有 nft。
func nftAvailable() bool { return nftPath != "" }

// ensureNftServer 写入服务端 nft 规则，返回是否真的成功。
//
// **返回值必须被检查**：如果本机有 nft 但写入失败（缺 CAP_NET_ADMIN、
// 内核没编 nf_tables），不能假装成功 —— 调用方要回退到 iptables 或报错。
func ensureNftServer(port uint16, marks []uint16) bool {
	return runNftScript(nftServerScript(port, marks))
}

// runNftScript 执行一段 nft 批处理脚本，返回是否成功。
func runNftScript(script string) bool {
	if !rulesBackendEnabled || !nftAvailable() {
		return false
	}
	cmd := exec.Command(nftPath, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	// nft 的语法错误只体现在 stderr，退出码可能是 0（批量输入时）
	return !strings.Contains(string(out), "Error:")
}

// chainHasRules 报告链存在且同时含 notrack 与 drop 两条规则。
func chainHasRules(name string) bool {
	out, err := exec.Command(nftPath, "list", "chain", "inet",
		notrackTable, name).CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "notrack") &&
		strings.Contains(string(out), "drop")
}

// checkNftServer 报告服务端规则是否已就位。
func checkNftServer(port uint16, marks []uint16) bool {
	if !rulesBackendEnabled {
		return true // Windows：WinDivert 扣留语义，不需要
	}
	if !nftAvailable() {
		return false // 交给调用方走 iptables
	}
	outChain, inChain := notrackChains(port)
	if !chainHasRules(outChain) || !chainHasRules(inChain) {
		return false
	}
	// 标记条数也要核对：PassWall/用户改了 ips 时规则必须跟着变。
	out, err := exec.Command(nftPath, "list", "chain", "inet",
		notrackTable, inChain).CombinedOutput()
	if err != nil {
		return false
	}
	want := 0
	for _, m := range marks {
		if m&0xFF00 != 0 {
			want++
		}
	}
	return strings.Count(string(out), "ip id") >= want
}
