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
	"os/exec"
	"strconv"
	"strings"
)

// 防火墙规则模式。取值与 Rust `net.mode` 完全一致。
const (
	// ModeAuto 在启动时自动写入 iptables（Rust 的默认值）。
	ModeAuto = "auto"
	// ModeNone 不写规则，由部署方自行维护。
	ModeNone = "none"
)

// ParseMode 校验 net.mode 取值。
//
// Rust check.rs:505 只接受 `auto` / `none`；空串按默认值 auto 处理
// （与 Rust 的 serde default 一致）。
func ParseMode(mode string) (string, error) {
	switch strings.TrimSpace(mode) {
	case "":
		return ModeAuto, nil
	case ModeNone:
		return ModeNone, nil
	case ModeAuto:
		return ModeAuto, nil
	default:
		return "", fmt.Errorf("flowtls: 未知 net.mode %q（可选 auto / none）", mode)
	}
}

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
// 只有一条：把发往监听端口的伪包在内核 TCP 栈之前 DROP。
//
// 匹配依据是 IP ID 高字节，取值来自配置的 `ip_id_mark`。
// **不能写死常量**：写死一个固定值意味着任何 DPI 只要加一条
// 「IP ID 高字节 == 某值」的通用规则就能命中所有部署。
//
// offset 4 读的是「IP ID(2) + Flags/Frag(2)」四字节：
// Frag 固定 0x4000（DF），掩掉 IP ID 低字节与 MF/offset。
func serverRules(port, magic uint16) []rule {
	portStr := strconv.Itoa(int(port))
	// 与 packet.go 的 IPIDMarkOf / BuildPacketInto 保持一致：只保留高字节
	mark := magic & 0xFF00
	magicExpr := fmt.Sprintf("0x4&0xff00ffff=0x%04x4000", mark)
	return []rule{{
		table: "raw",
		spec: []string{
			"PREROUTING",
			"-p", "tcp",
			"--dport", portStr,
			"-m", "u32",
			"--u32", magicExpr,
			"-j", "DROP",
		},
	}}
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
func clientRules(sourcePort, serverPort, magic uint16) []rule {
	mark := magic & 0xFF00
	return []rule{
		{
			spec: []string{
				"OUTPUT",
				"-p", "tcp",
				"--sport", strconv.Itoa(int(sourcePort)),
				"--tcp-flags", "RST", "RST",
				"-j", "DROP",
			},
		},
		{
			spec: []string{
				"INPUT",
				"-p", "tcp",
				"--sport", strconv.Itoa(int(serverPort)),
				"-m", "u32",
				"--u32", fmt.Sprintf("0x4&0xff00ffff=0x%04x4000", mark),
				"-j", "DROP",
			},
		},
	}
}

// ServerRules 返回服务端规则的文本形式（供日志展示）。
//
// Rust 版没有独立的展示接口——它在 ensure_* 失败时把规则拼进报错信息。
// Go 侧的 sing-box 适配层需要在启动日志里说明「实际生效了什么」，
// 因此保留一个只读的文本出口。
func ServerRules(port, magic uint16) []string {
	rules := serverRules(port, magic)
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.String())
	}
	return out
}

// ClientRules 返回客户端规则的文本形式（供日志展示）。
func ClientRules(sourcePort, serverPort, magic uint16) []string {
	rules := clientRules(sourcePort, serverPort, magic)
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
func EnsureServer(port, magic uint16) error {
	if !rulesBackendEnabled {
		return nil // Windows：WinDivert 已扣留伪包，内核看不到（见 rules_windows.go）
	}
	if ensureNft(kindServer, port, 0, magic) {
		return nil
	}
	for _, r := range serverRules(port, magic) {
		ok, err := runIPTables(r.command("-C"))
		if err != nil {
			return fmt.Errorf("无法执行 iptables，请确认已安装并具备 root 权限: %w", err)
		}
		if ok {
			continue
		}
		ok, err = runIPTables(r.command("-A"))
		if err != nil {
			return fmt.Errorf("无法执行 iptables，请确认已安装并具备 root 权限: %w", err)
		}
		if !ok {
			return fmt.Errorf("写入 iptables 规则失败: %s", r.String())
		}
	}
	return nil
}

// EnsureClient 幂等写入客户端规则（对应 Rust `ensure_client`）。
//
// 与 EnsureServer 同样 nft 优先；客户端额外多一条「挡住内核为此伪连接
// 回的 RST」，因为 SYN-ACK 一到内核就找不到对应 socket。
func EnsureClient(sourcePort, serverPort, magic uint16) error {
	if !rulesBackendEnabled {
		return nil // Windows：同 EnsureServer
	}
	if ensureNft(kindClient, sourcePort, serverPort, magic) {
		return nil
	}
	for _, r := range clientRules(sourcePort, serverPort, magic) {
		ok, err := runIPTables(r.command("-C"))
		if err != nil {
			return fmt.Errorf("无法执行 iptables，请确认已安装并具备 root 权限: %w", err)
		}
		if ok {
			continue
		}
		ok, err = runIPTables(r.command("-A"))
		if err != nil {
			return fmt.Errorf("无法执行 iptables，请确认已安装并具备 root 权限: %w", err)
		}
		if !ok {
			return fmt.Errorf("写入 iptables 规则失败: %s", r.String())
		}
	}
	return nil
}

// CheckServer 只检查规则是否存在，不修改（对应 Rust `check_server`）。
//
// 顺序与 EnsureServer 一致：先看 nft 链，不在才回退查 iptables。
func CheckServer(port, magic uint16) bool {
	if !rulesBackendEnabled {
		return true // Windows：无需规则，状态恒为「就绪」
	}
	if nftAvailable() {
		return checkNft(kindServer, port)
	}
	for _, r := range serverRules(port, magic) {
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
func CheckClient(sourcePort uint16) bool {
	if !rulesBackendEnabled {
		return true // Windows：同 CheckServer
	}
	if nftAvailable() {
		return checkNft(kindClient, sourcePort)
	}
	ok, _ := runIPTables([]string{
		"-C", "OUTPUT",
		"-p", "tcp",
		"--sport", strconv.Itoa(int(sourcePort)),
		"--tcp-flags", "RST", "RST",
		"-j", "DROP",
	})
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

// firewallKind 区分客户端与服务端要写的规则集。
type firewallKind int

const (
	kindClient firewallKind = iota
	kindServer
)

// nftScript 生成完整 nft 批处理脚本。
//
// **这就是 iptables 那套规则的 nft 等价实现**，两者做同一件事：
//
//	方向        规则                                        作用
//	output      sport=<本地端口> notrack                    伪包不进 conntrack
//	output      sport=<本地端口> tcp flags & rst == rst drop 挡内核回的 RST
//	prerouting  dport=<本地端口> notrack                    回程包不进 conntrack
//	prerouting  <对端方向> ip id & 0xff00 == <mark> drop     挡内核处理回程包
//
// 为什么用 nft 而不是 iptables（实测依据见 DEVTIPS 165）：
//
//  1. **u32 在 nftables 里没有对应扩展**，OpenWrt 22.03+ 默认只装
//     `iptables-nft`，`-m u32` 直接不支持 —— 于是插件必须让用户手工装
//     `iptables-zz-legacy` + `iptables-mod-u32` + `kmod-ipt-raw` 三个包，
//     否则隧道起不来。而 nft 用 `ip id & 0xff00 == 0x1e00` 一条就够，
//     完全等价于 u32 的 `0x4&0xff00ffff=0x1e004000`（已验证）。
//  2. `notrack` 只在 nft 里有；iptables 的 `-j NOTRACK` 在 OpenWrt 的
//     xtables-legacy 上没编译，执行会报 `Couldn't load target 'NOTRACK'`。
//  3. 少一套规则：不用再担心 iptables 与 nft 两处的规则互相打架。
//
// 用 `add table` / `add chain` + `flush chain` 而不是 `delete table`：
// 前者在表已存在时幂等，后者在表不存在时会让整批 abort。
// 先 flush 再 add rule 保证重复执行不叠加重复规则。
func nftScript(kind firewallKind, localPort, peerPort, magic uint16) string {
	outChain, inChain := notrackChains(localPort)
	portStr := strconv.Itoa(int(localPort))
	m := magic & 0xFF00
	lines := []string{
		"add table inet " + notrackTable,
		"add chain inet " + notrackTable + " " + outChain +
			" { type filter hook output priority raw; policy accept; }",
		"flush chain inet " + notrackTable + " " + outChain,
		"add rule inet " + notrackTable + " " + outChain +
			" tcp sport " + portStr + " notrack",
		"add rule inet " + notrackTable + " " + outChain +
			" tcp sport " + portStr + " tcp flags & rst == rst drop",
		"add chain inet " + notrackTable + " " + inChain +
			" { type filter hook prerouting priority raw; policy accept; }",
		"flush chain inet " + notrackTable + " " + inChain,
		"add rule inet " + notrackTable + " " + inChain +
			" tcp dport " + portStr + " notrack",
	}

	// 回程方向的 drop 两条分支的匹配字段不同，必须分开写：
	//   客户端：回程包来自服务端端口（sport）且带对方的 IP ID 标记；
	//   服务端：入站伪包发往监听端口（dport）且带客户端的 IP ID 标记。
	markExpr := " ip id & 0xff00 == 0x" + strconv.FormatUint(uint64(m), 16)
	if kind == kindClient {
		lines = append(lines, "add rule inet "+notrackTable+" "+inChain+
			" tcp sport "+strconv.Itoa(int(peerPort))+markExpr+" drop")
	} else {
		lines = append(lines, "add rule inet "+notrackTable+" "+inChain+
			" tcp dport "+portStr+markExpr+" drop")
	}
	return strings.Join(append(lines, ""), "\n")
}

// NftRules 返回实际写进 nft 的规则（供启动日志展示）。
//
// 返回空切片表示本机没有 nft（老系统），此时走 iptables 分支。
func NftRules(kind firewallKind, localPort, peerPort, magic uint16) []string {
	if !nftAvailable() {
		return nil
	}
	var out []string
	for _, ln := range strings.Split(nftScript(kind, localPort, peerPort, magic), "\n") {
		if strings.HasPrefix(ln, "add rule ") {
			out = append(out, "nft "+ln)
		}
	}
	return out
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

// ensureNft 写入 nft 规则，返回是否真的成功。
//
// **返回值必须被检查**：如果本机有 nft 但写入失败（缺 CAP_NET_ADMIN、
// 内核没编 nf_tables），不能假装成功 —— 调用方要回退到 iptables 或报错。
func ensureNft(kind firewallKind, localPort, peerPort, magic uint16) bool {
	if !rulesBackendEnabled || !nftAvailable() {
		return false
	}
	cmd := exec.Command(nftPath, "-f", "-")
	cmd.Stdin = strings.NewReader(nftScript(kind, localPort, peerPort, magic))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	// nft 的语法错误只体现在 stderr，退出码可能是 0（批量输入时）
	return !strings.Contains(string(out), "Error:")
}

// checkNft 报告规则是否已就位（链存在且含 notrack 与 drop 两条）。
func checkNft(kind firewallKind, localPort uint16) bool {
	if !rulesBackendEnabled {
		return true // Windows：WinDivert 扣留语义，不需要
	}
	if !nftAvailable() {
		return false // 交给调用方走 iptables
	}
	outChain, inChain := notrackChains(localPort)
	for _, ch := range []string{outChain, inChain} {
		out, err := exec.Command(nftPath, "list", "chain", "inet",
			notrackTable, ch).CombinedOutput()
		if err != nil {
			return false
		}
		if !strings.Contains(string(out), "notrack") ||
			!strings.Contains(string(out), "drop") {
			return false
		}
	}
	return true
}
