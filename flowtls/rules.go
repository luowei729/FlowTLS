package flowtls

import (
	"fmt"
	"strconv"
	"strings"
)

// IPTablesMode 决定 raw 表规则的落地方式。
//
// 规则不是协议运行所必需，作用是**保护内核协议栈不被自己的伪造包干扰**：
//
//	服务端：把带标记的伪包在内核 TCP 栈之前 DROP。内核看不到就不会回
//	        SYN-ACK / RST，NAT 映射不会被打断，同端口的真网站也不受干扰。
//	客户端：屏蔽内核对伪连接回 RST，并丢弃服务端回程包，
//	        避免每个包都引来一次 RST。
type IPTablesMode uint8

const (
	// IPTablesNone 不生成也不执行规则，由部署方自行维护。
	IPTablesNone IPTablesMode = iota
	// IPTablesPrint 只把规则文本交出来（默认）。
	//
	// 这是安全默认：不碰系统状态，但让运维一眼看到缺了什么、
	// 以及卸载时该删哪几条。
	IPTablesPrint
	// IPTablesAuto 幂等写入规则。
	IPTablesAuto
)

// ParseIPTablesMode 解析配置里的字符串。
//
// 空串按 print 处理：默认既不静默改防火墙，也不静默放过。
// 未知值直接报错，避免「拼错一个字母就静默不装规则」。
func ParseIPTablesMode(s string) (IPTablesMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "print":
		return IPTablesPrint, nil
	case "none":
		return IPTablesNone, nil
	case "auto":
		return IPTablesAuto, nil
	default:
		return IPTablesNone, fmt.Errorf("flowtls: 未知 iptables_mode %q（可选 none / print / auto）", s)
	}
}

// String 返回配置名，便于日志里原样回显。
func (m IPTablesMode) String() string {
	switch m {
	case IPTablesNone:
		return "none"
	case IPTablesAuto:
		return "auto"
	default:
		return "print"
	}
}

// Rule 是一条 iptables 规则。
//
// 用结构化表示而不是拼好的字符串，是因为同一条规则要三种形态：
// -A（添加）、-C（检查）、-D（删除）。
// Rust 版靠下标替换（rule[2] = "-C"）容易错位，结构化后只剩一处需要换。
type Rule struct {
	// Table 为空表示 filter 表（iptables 默认），raw 表必须显式写。
	Table string
	// Chain 是链名，如 PREROUTING / INPUT / OUTPUT。
	Chain string
	// Spec 是从匹配条件开始到动作结束的参数，不含 -t / -A / -C / -D。
	Spec []string
}

// Command 返回带指定动作（-A / -C / -D）的完整参数列表。
//
// 参数以切片形式交给 exec，不经过 shell：u32 表达式里的 `&` 和 `=`
// 因此不需要转义，也不会被 shell 拆开。
func (r Rule) Command(op string) []string {
	args := make([]string, 0, len(r.Spec)+5)
	if r.Table != "" {
		args = append(args, "-t", r.Table)
	}
	args = append(args, op, r.Chain)
	return append(args, r.Spec...)
}

// String 返回可直接粘到 shell 里的「安装」命令。
func (r Rule) String() string {
	return "iptables " + strings.Join(r.Command("-A"), " ")
}

// Uninstall 返回可直接粘到 shell 里的「卸载」命令。
//
// print 模式会把它一起打出来：运维手工装完规则后，
// 卸载时不用再回头翻文档反推参数。
func (r Rule) Uninstall() string {
	return "iptables " + strings.Join(r.Command("-D"), " ")
}

// U32IPIDExpr 生成按 IP ID 高字节匹配的 u32 表达式。
//
// iptables 没有单独的 IP ID 匹配模块，u32 是标准做法。
// offset 4 取到的是「IP ID(2B) + Flags/FragOff(2B)」四字节：
//
//	0x4&0xff00ffff  → 只保留 IP ID 高字节，Flags/Frag 全 16 位
//	=0x<HH>004000   → 高字节等于标记，且 Flags/Frag 必须是 0x4000
//
// **右值必须带 0x` 前缀**：内核解析器用 simple_strtoul(..., base=0)，
// 不带前缀会把 "f1004000" 按十进制解析失败并返回 0，规则永不命中——
// 现象是「内核照旧回 RST 把连接打断」，而 iptables -C 还报告规则存在，
// 从日志完全看不出异常。这是 Rust 版踩过的坑，单测钉住了它。
//
// **注意这条规则的可靠性有限**，只作为辅助特征保留（见 U32WScaleExpr）。
func U32IPIDExpr(magic uint16) string {
	return fmt.Sprintf("0x4&0xff00ffff=0x%04x4000", magic&0xFF00)
}

// U32WScaleExpr 生成按 TCP 窗口缩放因子匹配的 u32 表达式（分流主特征）。
//
// SYN 的选项布局固定为（见 SynOptions，共 20 字节）：
//
//	偏移 40: 02 04 05 b4       MSS 1460
//	偏移 44: 04 02             SACK permitted
//	偏移 46: 08 0a ts ts ts ts ecr ecr ecr ecr  时间戳
//	偏移 56: 01                NOP
//	偏移 57: 03 03 0c          wscale=12
//
// 因此「偏移 56 起的 4 字节 == 0x0103030c」即命中 wscale=12 的 SYN。
//
// 为什么它比 IP ID 可靠：TCP 选项是端到端字段，运营商 NAT / 云网关
// **不会改写**（实测同一路径上 MSS 会被 clamp 成 1400，但 wscale 原样保留）。
// 这一点已用双端抓包确认。
//
// 前提是 IHL=5（无 IP 选项），本实现构造的报文始终如此，真实客户端也一致。
func U32WScaleExpr() string {
	return fmt.Sprintf("0x%02x&0xffffffff=0x010303%02x", 56, WScale)
}

// ServerRules 返回服务端需要的规则。
//
// 四条规则，各解决一个具体问题（顺序即优先级）：
//
//  1. raw/PREROUTING：伪 **SYN** 在内核建 socket 之前丢弃。
//     匹配依据是 wscale=12 —— 唯一不会被 NAT 改写的分流特征。
//     （IP ID 会被客户端 NAT 改写，实测该规则的命中计数恒为 0。）
//
//  2. filter/INPUT：伪 **数据包** 丢弃。
//     数据包没有稳定静态特征（TCP 选项、窗口、TTL 都与真实浏览器重合），
//     但它们有一个**状态机特征**：真实浏览器完成过三次握手，
//     conntrack 里是 ESTABLISHED；伪连接的 SYN 已在第 1 步被丢弃，
//     所以数据包到达时 conntrack 视其为 NEW。
//     因此 `! --syn + ctstate NEW` 精确命中伪数据包，且不影响真实流量。
//
//  3. filter/OUTPUT：内核为伪数据包回的 RST **不出网卡**。
//     即使前两条有漏网，RST 也会被这条拦住——每个下行包引出一个 RST
//     等于把包量翻倍，还会让云网关的反 DDoS 把小包限速。
//
//  4. raw/PREROUTING：按 IP ID 高字节匹配（辅助，仅当链路不改写 IP ID 时有效）。
//
// **不要删除第 2、3 条**：它们不依赖任何可被中间设备改写的字段，
// 是「分流在真实链路上成立」的最后保证。
func ServerRules(port, magic uint16) []Rule {
	portStr := strconv.Itoa(int(port))
	return []Rule{
		{
			Table: "raw",
			Chain: "PREROUTING",
			Spec: []string{
				"-p", "tcp",
				"--dport", portStr,
				"--tcp-flags", "SYN,ACK", "SYN",
				"-m", "u32",
				"--u32", U32WScaleExpr(),
				"-j", "DROP",
			},
		},
		{
			Chain: "INPUT",
			Spec: []string{
				"-p", "tcp",
				"--dport", portStr,
				"!", "--syn",
				"-m", "conntrack",
				"--ctstate", "NEW",
				"-j", "DROP",
			},
		},
		{
			Chain: "OUTPUT",
			Spec: []string{
				"-p", "tcp",
				"--sport", portStr,
				"--tcp-flags", "RST", "RST",
				"-j", "DROP",
			},
		},
		{
			Table: "raw",
			Chain: "PREROUTING",
			Spec: []string{
				"-p", "tcp",
				"--dport", portStr,
				"-m", "u32",
				"--u32", U32IPIDExpr(magic),
				"-j", "DROP",
			},
		},
	}
}

// ClientRules 返回客户端需要的两条规则。
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
func ClientRules(sourcePort, serverPort, magic uint16) []Rule {
	return []Rule{
		{
			Chain: "OUTPUT",
			Spec: []string{
				"-p", "tcp",
				"--sport", strconv.Itoa(int(sourcePort)),
				"--tcp-flags", "RST", "RST",
				"-j", "DROP",
			},
		},
		{
			Chain: "INPUT",
			Spec: []string{
				"-p", "tcp",
				"--sport", strconv.Itoa(int(serverPort)),
				"-m", "u32",
				"--u32", U32IPIDExpr(magic),
				"-j", "DROP",
			},
		},
	}
}

// RuleReport 是一次规则落地的结果，用来让上层记日志。
type RuleReport struct {
	Mode     IPTablesMode
	Rules    []Rule
	Added    int
	Existing int
}

// Text 返回多行可读文本：本次处理的每条规则 + 卸载方式。
func (r RuleReport) Text() string {
	if len(r.Rules) == 0 {
		return ""
	}
	var b strings.Builder
	switch r.Mode {
	case IPTablesNone:
		b.WriteString("iptables_mode=none：未处理规则，需自行维护：")
	case IPTablesAuto:
		fmt.Fprintf(&b, "iptables_mode=auto：新增 %d 条，已存在 %d 条", r.Added, r.Existing)
	default:
		b.WriteString("iptables_mode=print：请手工安装以下规则（或改用 auto）：")
	}
	for _, rule := range r.Rules {
		b.WriteString("\n  ")
		b.WriteString(rule.String())
	}
	if r.Mode != IPTablesAuto {
		b.WriteString("\n卸载命令：")
		for _, rule := range r.Rules {
			b.WriteString("\n  ")
			b.WriteString(rule.Uninstall())
		}
	}
	return b.String()
}

// Empty 表示没有需要处理的规则。
func (r RuleReport) Empty() bool { return len(r.Rules) == 0 }

// ApplyRules 按 mode 落地一组规则。
//
// 幂等：先 -C 检查再 -A，重复调用只会报告「已存在」。
// 刻意**不做删除**（与 Rust 版一致）：
//
//   - 规则是部署级静态属性，每次启动都一样；
//   - 进程重启期间规则必须继续生效，否则那段时间内核会回 RST
//     打断正在重建的隧道；
//   - 崩溃/被 kill -9 时不会留下「规则已删」的半状态。
//
// 卸载由 RuleReport.Uninstall() 给出的命令手工完成。
func ApplyRules(mode IPTablesMode, rules []Rule) (RuleReport, error) {
	report := RuleReport{Mode: mode, Rules: rules}
	if mode == IPTablesNone || len(rules) == 0 {
		return report, nil
	}
	if mode == IPTablesPrint {
		// print 不碰系统状态，直接用当前平台的 iptables 探测无意义，
		// 所以只报告文本，不统计 Added/Existing。
		return report, nil
	}

	for _, rule := range rules {
		exists, err := ruleExists(rule)
		if err != nil {
			return report, err
		}
		if exists {
			report.Existing++
			continue
		}
		if err := addRule(rule); err != nil {
			return report, err
		}
		report.Added++
	}
	return report, nil
}
