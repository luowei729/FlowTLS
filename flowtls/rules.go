package flowtls

// 本文件是内核分流规则的构造与执行（对应 Rust `src/rules.rs`）。
//
// # 规则要解决的唯一问题
//
// 伪 TCP 走 raw socket 自己收发，但**内核并不知道这些连接存在**。
// 于是同一个包会被两方同时处理：
//
//	方向            内核会做什么                          必须怎么拦
//	服务端收到 SYN   没有监听 socket → 回 RST；有伪装站则抢答   在 raw 优先级 DROP
//	服务端收到数据   没有 socket → 每个包回一个 RST            在 raw 优先级 DROP
//	客户端收到回程   没有 socket → 每个包回一个 RST            在 input 优先级 DROP
//	客户端发出伪包   fw4 判 ct invalid → DROP（sendto 报 EPERM） 出向 notrack
//
// # 识别依据是 TCP ISN，不是 IP ID
//
// 早期实现把标记放在 **IP ID 高字节**，靠 `ip id & 0xff00 == <mark>` 匹配。
// 这在真实网络里不可靠：中间设备会随机化 IP ID（RFC 6528 的防侧信道要求）。
// 2026-11-28 三角测量实测（同一客户端二进制，只换目标服务器）：
//
//	家宽 198.51.100.7 → tk3:8443     IP ID 保留      隧道正常
//	hk1 203.0.113.10  → sg1:8443     IP ID 保留      隧道正常
//	hk1 203.0.113.10  → tk3:8443     IP ID 被随机化  握手超时
//
// 被改写后这条规则永远不命中 → 伪包进内核 → 内核抢答/回 RST → 隧道死，
// 而两端日志毫无线索。**TCP 序列号没有任何设备会改写**（改了 TCP 就废了），
// 是唯一可靠且内核能静态匹配的载体。完整字段对比表见 packet.go 的
// `---- TCP ISN 分流标记 ----`。
//
// # 为什么需要「动态集合」才能只靠 SYN 上的标记
//
// ISN 标记只写在 **SYN 一个包**上；后续数据包的序列号从 ISN+1 正常递增，
// 低位早已打散，无法静态匹配。但数据包同样必须被 DROP（否则内核逐包回
// RST，既暴露特征又拆 NAT 映射）。
//
// 解法：在对 SYN 下 DROP 的同时，把它的**四元组**记进一个带超时的动态
// 集合；随后所有同四元组的包按集合匹配 DROP。真实浏览器（同端口的伪装站）
// 不命中任何一条，落到最后的 notrack 兜底规则上，行为与改造前一致。

import (
	"errors"
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
// 由 command 统一拼装——语义完全相同，但不是新增机制。
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
// 参数以切片形式交给 exec，不经过 shell：u32 表达式里的 `&` 和 `=`
// 因此不需要转义，也不会被 shell 拆开。
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

// iptablesISNExpr 是 TCP 序列号低 16 位的 `-m u32` 匹配表达式。
//
// iptables 的 u32 用**字节偏移**（不是 nft 的位偏移）：无 IP 选项时
// TCP 头从偏移 20 开始，序列号在 TCP 头内偏移 4，所以序列号是偏移
// 24..27。取低 16 位 → `24&0x0000FFFF`。
//
// 只用于 **iptables 回落路径**（老固件没有 nft）。主路径用 nft 的
// `@th,48,16`，语义相同。
func iptablesISNExpr(mark uint16) string {
	return fmt.Sprintf("24&0x0000FFFF=0x%04x", mark)
}

// serverRules 构造服务端 iptables 回落规则。
//
// 每个标记两条：
//
//	raw PREROUTING -p tcp --dport <port> --syn -m u32 --u32 <ISN 低16位> \
//	               -m recent --name flowtls_<port> --set -j DROP
//	raw PREROUTING -p tcp --dport <port> -m recent --name flowtls_<port> \
//	               --rcheck -j DROP
//
// 第一条负责「认出我们的 SYN 并记住来源」，第二条负责「同来源的后续包
// 一并丢弃」。recent 列表只按 **源 IP** 索引（模块不支持端口），
// 所以粒度比 nft 的动态集合粗 —— 同一台客户端访问该端口的其它流量也会
// 被短时丢弃。这是回落路径的已知代价，nft 可用时不会走到这里。
//
// marks 是一组值：服务端在内核层写规则时还不知道对端是哪个用户
// （解密发生在之后），所以每个用户的派生标记都要各自写一条。
func serverRules(port uint16, marks []uint16) []rule {
	portStr := strconv.Itoa(int(port))
	list := recentListName(port)
	out := make([]rule, 0, 2*len(marks))
	for _, m := range marks {
		if m == 0 {
			// 防御：标记为 0 时 u32 表达式会匹配大量无关流量，等于无差别丢包。
			// Validate 已挡住，这里再兜一层。
			continue
		}
		out = append(out,
			rule{
				table: "raw",
				spec: []string{
					"PREROUTING",
					"-p", "tcp",
					"--dport", portStr,
					"--syn",
					"-m", "u32",
					"--u32", iptablesISNExpr(m),
					"-m", "recent",
					"--name", list,
					"--set",
					"-j", "DROP",
				},
			},
			rule{
				table: "raw",
				spec: []string{
					"PREROUTING",
					"-p", "tcp",
					"--dport", portStr,
					"-m", "recent",
					"--name", list,
					"--rcheck",
					"-j", "DROP",
				},
			},
		)
	}
	return out
}

// clientRules 构造客户端 iptables 回落规则。
//
//	raw OUTPUT   -p tcp -d <server> --dport <port> --syn -m u32 --u32 <ISN> \
//	             -m recent --name <list> --rdest --set
//	raw OUTPUT   -p tcp -d <server> --dport <port> --tcp-flags RST RST -j DROP
//	filter INPUT -p tcp -s <server> --sport <port> -m recent --name <list> \
//	             --rsource --rcheck -j DROP
//
// 第一条**只记录不丢弃**（我们自己发的 SYN 必须真的发出去）；
// 用 `--rdest` 把**服务端地址**记进列表，INPUT 侧再用 `--rsource`
// 按源地址查回来。
//
// **入向规则挂 `input` 钩子，不能挂 `prerouting`**：prerouting 阶段
// （raw 优先级，早于 dstnat）看到的回程包目的地址都还是本机 WAN 地址，
// `fib daddr type local` 对「本机回程」和「转发的回程」同时成立，一条都
// 区分不出来（实测两条规则计数完全相同）。`input` 钩子只在内核判定
// 「这个包要交给本机」之后才执行，转发路径根本不会进它（实测
// prerouting=2 / input=0）。少了这一条，路由器会把它替 LAN 客户端转发
// 回来的 SYN-ACK 一并 drop（DEVTIPS 第 167 条）。
//
// **规则按服务端地址匹配，不按源端口**：源端口允许动态分配，按它命名会
// 让规则越积越多且永远清不干净。
func clientRules(server netip.AddrPort, magic uint16) []rule {
	dst := []string{"-p", "tcp", "-d", server.Addr().String(),
		"--dport", strconv.Itoa(int(server.Port()))}
	src := []string{"-p", "tcp", "-s", server.Addr().String(),
		"--sport", strconv.Itoa(int(server.Port()))}
	list := recentListName(server.Port())

	setRule := append(append([]string{"OUTPUT"}, dst...),
		"--syn",
		"-m", "u32", "--u32", iptablesISNExpr(magic),
		"-m", "recent", "--name", list, "--rdest", "--set")

	return []rule{
		// 记录来源（不丢弃：SYN 必须真的发出去）。
		{table: "raw", spec: setRule},
		// 挡内核对伪连接回的 RST。
		{
			table: "raw",
			spec: append(append([]string{"OUTPUT"}, dst...),
				"--tcp-flags", "RST", "RST", "-j", "DROP"),
		},
		// 挡内核处理回程包。
		{
			spec: append(append([]string{"INPUT"}, src...),
				"-m", "recent", "--name", list, "--rsource", "--rcheck",
				"-j", "DROP"),
		},
	}
}

// recentListName 返回 iptables recent 模块的列表名。
//
// 名字带端口，多个 FlowTLS 实例各自维护自己的列表，互不干扰。
func recentListName(port uint16) string {
	return "flowtls_" + strconv.Itoa(int(port))
}

// ServerRules 返回服务端规则的文本形式（供日志展示）。
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

// rulesBackendEnabled 决定 Ensure*/Check* 是否真的操作防火墙。
//
// 为什么需要这个开关：本文件是平台中性的（`sing-box check` 要在所有平台
// 都能编译），但 iptables/nft 只在 Linux 上存在。Windows 用 WinDivert 的
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
// **nft 优先**：本机有 nft 就用 nft 写全套规则（notrack + SYN 识别 +
// 动态集合 DROP），成功即返回，完全不碰 iptables。
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
// sourcePort 只用于日志与集合键的说明（nft 读的是实际发出的包）。
func EnsureClient(server netip.AddrPort, sourcePort uint16, magic uint16) error {
	if !rulesBackendEnabled {
		return nil // Windows：同 EnsureServer
	}
	if ensureNftClient(server, sourcePort, magic) {
		return nil
	}
	return ensureIPTables(clientRules(server, magic), "客户端")
}

// ensureIPTables 逐条幂等写入规则（回退路径，nft 不可用时走这里）。
//
// why 只用于报错文案（"服务端"/"客户端"），让用户一眼知道是哪一端失败。
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
	return errors.New("flowtls: " + why +
		"缺少可用的防火墙后端（nft 与 iptables 都不可用）: " + err.Error() +
		"；需要 root/CAP_NET_ADMIN，或安装 nftables")
}

// ---- nftables ----

// notrackTable 是 FlowTLS 专用的 nft 表名。
//
// 用独立表而不是往 fw4 的表里插规则：fw4 每次 reload 都会重建自己的表，
// 插进去的规则会消失；独立表不受它管理，重启服务时我们自己重建。
const notrackTable = "flowtls"

// notrackChains 返回本端口对应的两条链名 + 动态集合名。
//
// 名字都带端口，多个 FlowTLS 实例（客户端 + 服务端在同一台机器上）
// 各自维护自己的链与集合，谁都不会清掉别人的规则。
func notrackChains(port uint16) (outChain, inChain, set string) {
	p := strconv.Itoa(int(port))
	return "out_" + p, "in_" + p, "ft_" + p
}

// clientChains 返回客户端两条链名 + 动态集合名，按**服务端地址**命名。
//
// 为什么不按源端口命名：源端口现在允许自动分配（每次重连都可能不同），
// 按它命名会让链越积越多、也永远清不干净。
// 服务端地址在一台机器上是稳定的，不同服务端天然得到不同链名，互不干扰。
//
// 名字里用 IP 的四字节十六进制 + 端口，保证是合法的 nft 标识符
// （不能直接塞点号，虽然 nft 允许但引号/转义容易出错）。
func clientChains(server netip.AddrPort) (outChain, inChain, set string) {
	a := server.Addr().As4()
	base := fmt.Sprintf("%x_%d", a, server.Port())
	return "cout_" + base, "cin_" + base, "cft_" + base
}

// nftISNMatch 返回「TCP 序列号低 16 位 == 标记」的 nft 匹配片段。
//
// `@th,48,16` 读的是 TCP 头第 48 位起的 16 位 —— TCP 头布局：
//
//	偏移(位)  0..15   16..31   32..47     48..63
//	字段      源端口   目的端口  序列号高16  序列号低16
//
// **单位是 bit 不是 byte**。写成 `@th,32,16` 会读到序列号的**高** 16 位，
// 规则永不命中（实测：nft 还把它优化显示成 `tcp sequence 1694498816/16`，
// 那个数字是 0x65000000，一眼能看出错位）。
func nftISNMatch(mark uint16) string {
	return " @th,48,16 0x" + strconv.FormatUint(uint64(mark), 16)
}

// nftServerScript 生成服务端 nft 批处理脚本。
//
// 链（prerouting, priority raw —— 早于 conntrack，也早于内核 TCP 栈）：
//
//	# 1. 我们的纯 SYN：记下四元组，然后 DROP（内核看不见 → 不会抢答）
//	fib daddr type local tcp dport <port> tcp flags syn @th,48,16 <mark> \
//	    update @<set> { ip saddr . tcp sport } drop
//	# 2. 该流后续的数据包：按集合 DROP（否则内核逐包回 RST）
//	fib daddr type local tcp dport <port> ip saddr . tcp sport @<set> drop
//	# 3. 其它（真实浏览器）：notrack 交给内核 → 伪装站正常工作
//	fib daddr type local tcp dport <port> notrack
//
// 另有 output 侧的 `tcp sport <port> notrack`：服务端回的 SYN-ACK 与数据
// 走 raw socket，若被 fw4 判成 ct invalid 会 DROP（sendto 报 EPERM）。
//
// **入向规则限定 `fib daddr type local`**：服务端通常不转发，但一旦跑在
// 软路由上，prerouting 会同时看到「替 LAN 主机转发出去」的包。
// 伪包的目的地址永远是本机（客户端发往的就是这个监听端口），
// 所以限定 local 不削弱任何防护，却避免误伤转发流量。
//
// marks 是一组值（每个用户一个），每个标记各写一条「集合记账」规则，
// 全部写进同一个集合 —— 集合的键是四元组，与标记无关。
//
// 用 `add table` / `add chain` + `flush chain` 而不是 `delete table`：
// 前者在表已存在时幂等，后者在表不存在时会让整批 abort。
// 先 flush 再 add rule 保证重复执行不叠加重复规则。
func nftServerScript(port uint16, marks []uint16) string {
	outChain, inChain, set := notrackChains(port)
	portStr := strconv.Itoa(int(port))
	inLocal := " fib daddr type local tcp dport " + portStr

	lines := []string{
		"add table inet " + notrackTable,
		// 动态集合：键是「客户端 IP . 客户端源端口」，条目带超时自动回收。
		//
		// 超时必须 ≥ 会话空闲回收时间（默认 120s）：QUIC 连接在低流量时
		// 可能几十秒没有数据包，集合提前过期会让内核重新看到数据包并回 RST。
		// 这里取 10 分钟。
		//
		// **超时是「多久没刷新」而不是「创建后多久」**：下面的记账规则（SYN）
		// 与查表规则（后续数据包）**都带 update**，所以只要这条流还在跑，
		// 条目就会被每个包推到 10 分钟之后。
		// 只在 SYN 上 update 是不够的 —— QUIC 长连接不会再有 SYN，条目必然在
		// 「建连 + 10 分钟」过期，然后伪包落到内核 TCP 栈、内核开始逐包回 RST，
		// 表现为隧道每 10 分钟断一次、重连后恢复正常（DEVTIPS 第 205 条）。
		"add set inet " + notrackTable + " " + set +
			" { type ipv4_addr . inet_service; flags dynamic,timeout; timeout 10m; }",
		"flush set inet " + notrackTable + " " + set,

		"add chain inet " + notrackTable + " " + outChain +
			" { type filter hook output priority raw; policy accept; }",
		"flush chain inet " + notrackTable + " " + outChain,
		"add rule inet " + notrackTable + " " + outChain +
			" tcp sport " + portStr + " notrack",

		"add chain inet " + notrackTable + " " + inChain +
			" { type filter hook prerouting priority raw; policy accept; }",
		"flush chain inet " + notrackTable + " " + inChain,
	}
	for _, m := range marks {
		if m == 0 {
			// 防御：标记为 0 时匹配片段是 `@th,48,16 0x0`，会命中所有
			// ISN 低 16 位为 0 的流量。Validate 已挡住，这里再兜一层。
			continue
		}
		lines = append(lines, "add rule inet "+notrackTable+" "+inChain+inLocal+
			" tcp flags syn"+nftISNMatch(m)+
			" update @"+set+" { ip saddr . tcp sport } drop")
	}
	lines = append(lines,
		// 查表规则同时**刷新**条目：每次命中都把过期时间推到 10 分钟后。
		// 不带 update 时条目只在 SYN 时记账，长连接必然在 10 分钟后过期
		// （2026-11-28 真机：每条 QUIC 连接恰好活 10.7 分钟）。
		"add rule inet "+notrackTable+" "+inChain+inLocal+
			" ip saddr . tcp sport @"+set+
			" update @"+set+" { ip saddr . tcp sport } drop",
		"add rule inet "+notrackTable+" "+inChain+inLocal+" notrack",
	)
	return strings.Join(append(lines, ""), "\n")
}

// nftClientScript 生成客户端 nft 批处理脚本，按服务端地址匹配。
//
//	链       规则                                                作用
//	output   daddr=<server> dport=<port> notrack                 伪包不进 conntrack
//	output   daddr=<server> dport=<port> rst drop                挡内核回的 RST
//	output   daddr=<server> dport=<port> syn @th,48,16 <mark> \
//	             update @<set> { ip daddr . tcp sport }           记下本次流的源端口
//	input    saddr=<server> sport=<port> ip saddr . tcp dport \
//	             @<set> update @<set> { ip saddr . tcp dport } drop  挡内核处理回程包，
//	                                                            同时刷新条目
//
// 入向规则用**集合**而不是 IP ID 标记，原因有二：
//  1. IP ID 会被中间设备随机化（服务端回包的 IP ID 同理），不可靠；
//  2. 集合的键含**本端源端口**，因此只影响我们自己那条流 ——
//     同一台机器上主动访问服务端伪装站的真实连接照常工作。
//
// **入向规则必须挂在 `input` 钩子，不能挂 `prerouting`**。
// 这一条是 2026-11-26 真机事故的结论：prerouting 阶段（raw 优先级，
// 早于 dstnat）看到的回程包目的地址都还是本机 WAN 地址，
// `fib daddr type local` 对「本机回程」和「转发的回程」同时成立，
// 一条都区分不出来（实测两条规则计数完全相同）。而 `input` 钩子只在
// 内核判定「这个包要交给本机」之后才执行，转发路径根本不会进它
// （实测 prerouting=2 / input=0）。少了这一条，路由器会把它替 LAN 客户端
// 转发回来的 SYN-ACK 一并 drop，表现为「LAN 客户端握手超时，两端日志都正常」。
//
// sourcePort 参数只用于注释与日志：记账规则读的是**实际发出的包**的
// `tcp sport`，所以源端口由内核动态分配时规则同样正确。
func nftClientScript(server netip.AddrPort, sourcePort, magic uint16) string {
	outChain, inChain, set := clientChains(server)
	ip := server.Addr().String()
	portStr := strconv.Itoa(int(server.Port()))
	dst := " ip daddr " + ip + " tcp dport " + portStr
	inSrc := " ip saddr " + ip + " tcp sport " + portStr
	_ = sourcePort

	lines := []string{
		"add table inet " + notrackTable,
		"add set inet " + notrackTable + " " + set +
			" { type ipv4_addr . inet_service; flags dynamic,timeout; timeout 10m; }",
		"flush set inet " + notrackTable + " " + set,

		"add chain inet " + notrackTable + " " + outChain +
			" { type filter hook output priority raw; policy accept; }",
		"flush chain inet " + notrackTable + " " + outChain,
	}
	// 记账规则只在我们自己的 SYN 上命中（ISN 带标记）。
	if magic != 0 {
		lines = append(lines, "add rule inet "+notrackTable+" "+outChain+dst+
			" tcp flags syn"+nftISNMatch(magic)+
			" update @"+set+" { ip daddr . tcp sport }")
	}
	lines = append(lines,
		"add rule inet "+notrackTable+" "+outChain+dst+
			" tcp flags & rst == rst drop",
		"add rule inet "+notrackTable+" "+outChain+dst+" notrack",

		"add chain inet "+notrackTable+" "+inChain+
			" { type filter hook input priority raw; policy accept; }",
		"flush chain inet "+notrackTable+" "+inChain,
		// 入向规则同时刷新条目。回程包是长连接最主要的流量来源
		// （服务端 → 客户端方向），只靠出向 SYN 记账的话，客户端这边
		// 同样会在「建连 + 10 分钟」丢掉保护，内核回 RST 打断隧道。
		"add rule inet "+notrackTable+" "+inChain+inSrc+
			" ip saddr . tcp dport @"+set+
			" update @"+set+" { ip saddr . tcp dport } drop",
	)
	return strings.Join(append(lines, ""), "\n")
}

// ClientNftRules 返回客户端实际写进 nft 的规则（供启动日志展示）。
func ClientNftRules(server netip.AddrPort, sourcePort, magic uint16) []string {
	if !nftAvailable() {
		return nil
	}
	return nftRuleLines(nftClientScript(server, sourcePort, magic))
}

// ensureNftClient 写入客户端 nft 规则，返回是否真的成功。
func ensureNftClient(server netip.AddrPort, sourcePort, magic uint16) bool {
	return runNftScript(nftClientScript(server, sourcePort, magic))
}

// checkNftClient 报告客户端规则是否已就位。
func checkNftClient(server netip.AddrPort) bool {
	if !rulesBackendEnabled {
		return true
	}
	if !nftAvailable() {
		return false
	}
	outChain, inChain, _ := clientChains(server)
	// out 链有 notrack + RST drop + 集合记账；**入向链只有 drop**
	// （回程包不在 input 钩子做 notrack —— 那里已经晚于 conntrack，做了也没用）。
	return chainHasRules(outChain, "notrack", "drop") &&
		chainHasRules(inChain, "drop")
}

// nftRuleLines 从批处理脚本里挑出 add rule / add set 行并加 nft 前缀（日志用）。
func nftRuleLines(script string) []string {
	var out []string
	for _, ln := range strings.Split(script, "\n") {
		if strings.HasPrefix(ln, "add rule ") || strings.HasPrefix(ln, "add set ") {
			out = append(out, "nft "+ln)
		}
	}
	return out
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

// chainHasRules 报告链存在，且包含 must 里的全部子串。
//
// 用可变参数而不是写死「notrack + drop」：客户端入向链只要 drop
// （回程包的 notrack 已随 prerouting 钩子一起去掉——在 input 钩子做
// notrack 已经晚于 conntrack，没有意义），服务端两条链才都要 notrack。
func chainHasRules(name string, must ...string) bool {
	out, err := exec.Command(nftPath, "list", "chain", "inet",
		notrackTable, name).CombinedOutput()
	if err != nil {
		return false
	}
	chain := string(out)
	for _, m := range must {
		if !strings.Contains(chain, m) {
			return false
		}
	}
	return true
}

// checkNftServer 报告服务端规则是否已就位。
func checkNftServer(port uint16, marks []uint16) bool {
	if !rulesBackendEnabled {
		return true // Windows：WinDivert 扣留语义，不需要
	}
	if !nftAvailable() {
		return false // 交给调用方走 iptables
	}
	outChain, inChain, set := notrackChains(port)
	if !chainHasRules(outChain, "notrack") ||
		!chainHasRules(inChain, "notrack", "drop") {
		return false
	}
	// 集合必须存在：只有 ISN 标记的 SYN 才会记账，数据包的 DROP 完全
	// 依赖它。集合缺失时现象是「握手成功但传输一卡一卡」（内核逐包回 RST）。
	if _, err := exec.Command(nftPath, "list", "set", "inet",
		notrackTable, set).CombinedOutput(); err != nil {
		return false
	}
	// 标记条数也要核对：改了密码（标记跟着变）时规则必须跟着变。
	out, err := exec.Command(nftPath, "list", "chain", "inet",
		notrackTable, inChain).CombinedOutput()
	if err != nil {
		return false
	}
	want := 0
	for _, m := range marks {
		if m != 0 {
			want++
		}
	}
	return strings.Count(string(out), "update @") >= want
}
