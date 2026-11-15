//go:build windows && (amd64 || 386)

package flowtls

// 本文件负责**入站代理端口**的防火墙放行，与 rules_windows.go 讲的是两件事。
//
// # 两个容易混淆的层次
//
// 1. **伪包分流**（rules_windows.go）：WinDivert 在 WFP 的入站 IP 包层扣留匹配
//    的报文，子层权重最高，位于防火墙过滤之前。所以伪 SYN / SYN-ACK 的收发
//    **完全不需要防火墙规则**，这也是 Windows 不需要 iptables 的原因。
//
// 2. **代理端口监听**（本文件）：inbound 是真正的内核 TCP socket
//    （`0.0.0.0:1080`）。Windows 防火墙对它一视同仁——从局域网连进来会被拦，
//    而这恰恰是用户最常见的用法（手机、电视、另一台电脑共享代理）。
//
// 第 2 点在本项目最初的设计里被漏掉了：`rules_windows.go` 写着「Windows 不需要
// 任何防火墙规则」，那句话对伪包成立，对代理端口不成立。
//
// # 为什么可以自动放行
//
// 加载 WinDivert 驱动本来就要求管理员权限（`ERROR_ACCESS_DENIED`），
// 也就是说本程序一定以管理员身份在运行，有权限直接写防火墙规则。
// 只要规则在任何 `listen()` 之前就存在，Windows 连那个「是否允许此应用访问
// 网络」的弹窗都不会再弹——用户什么都不用点。
//
// # 为什么按「程序」而不是按「端口」放行
//
//   - 不用预先知道每个 inbound 的监听端口（mixed / socks / http 各不同）；
//   - 用户改端口不需要重建规则；
//   - 与用户手动点「允许」产生的规则形状完全一致。

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// 防火墙规则名。固定值，便于「先删后加」保持幂等，也便于用户自查/手工删除。
const fwRuleName = "FlowTLS"

// fwTimeout 是单次 netsh 调用的超时。
//
// netsh 正常在几十毫秒内返回；给 10 秒是为了防「防火墙服务异常」时卡住启动。
const fwTimeout = 10 * time.Second

// EnsureInboundFirewallRule 确保本程序的入站流量被 Windows 防火墙放行。
//
// 覆盖全部三种网络类型（域 / 专用 / 公用）。覆盖「公用」是刻意的取舍：
// 用户换到酒店、咖啡馆这类被判为公用网络的 Wi-Fi 时，局域网共享仍然可用，
// 不需要重新配置。代价是代理端口在不信任网络上也可达——防线是 inbound 的
// `users` 口令，**部署时不要留默认口令**。
//
// 幂等：每次启动先删同名规则再添加，因此可执行文件换目录后规则也会指向新路径。
// 失败不致命——调用方只告警，隧道本体（WinDivert 伪包路径）不依赖它。
func EnsureInboundFirewallRule(logger Logger) error {
	logger = loggerOr(logger)
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// 先删：规则不存在时 netsh 返回非 0，属正常情况，忽略。
	// 必须删而不是「存在就跳过」，否则换目录后旧规则仍指向旧路径，
	// 新路径继续被拦，现象与「没配规则」完全一样。
	_, _ = runNetsh(append(fwSubcommand, "delete", "rule", "name="+fwRuleName)...)
	// profile=any 就是域+专用+公用；protocol 不写等于 any（TCP+UDP 全覆盖）。
	//
	// program= 后面**不能加引号**：exec 把每个参数作为独立 argv 交给 netsh，
	// 不经过 shell 分词，路径里的空格本来就是安全的。加上引号反而会让 netsh
	// 把引号当成路径的一部分，报 exit status 1（真机上踩过）。
	out, err := runNetsh(append(fwSubcommand,
		"add", "rule",
		"name="+fwRuleName,
		"dir=in",
		"action=allow",
		"program="+exe,
		"enable=yes",
		"profile=any",
	)...)
	if err != nil {
		// 带上 netsh 自己的输出：只看 exit status 1 无法区分「权限不足」
		// 与「参数拼错」，而真机上这类错误往往只能靠这句话定位。
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	logger.Info("Windows 防火墙已放行本程序入站（域/专用/公用）: ", exe)
	return nil
}

// runNetsh 执行一次 netsh 并返回输出。
//
// **参数必须带完整的上下文前缀**：写规则要用 `advfirewall firewall add rule`，
// 漏掉 `advfirewall firewall` 时 netsh 只回一句「未找到命令」并返回 1，
// 而错误文本在中文系统上还会乱码——真机上就是被这一句骗了：
// 当时看到 exit status 1 以为是权限或引号问题，实际是子命令路径写错了。
//
// **不解析输出**：netsh 的提示文本随系统语言变化，按文本判断必然在非英文系统上
// 失效。这里只看退出码，输出只用于报错时附上。
func runNetsh(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), fwTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "netsh", args...)
	// 隐藏控制台窗口：不设的话每次启动都会闪一个黑框。
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.CombinedOutput()
}

// fwSubcommand 是写防火墙规则的固定前缀。
//
// 单独抽成常量是为了让上面的 runNetsh 注释与调用点对得上：
// netsh 的子命令是**两级**的，`netsh add rule` 不存在。
var fwSubcommand = []string{"advfirewall", "firewall"}
