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
func EnsureServer(port, magic uint16) error {
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
func EnsureClient(sourcePort, serverPort, magic uint16) error {
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
func CheckServer(port, magic uint16) bool {
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
	ok, _ := runIPTables([]string{
		"-C", "OUTPUT",
		"-p", "tcp",
		"--sport", strconv.Itoa(int(sourcePort)),
		"--tcp-flags", "RST", "RST",
		"-j", "DROP",
	})
	return ok
}
