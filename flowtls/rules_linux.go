//go:build linux

package flowtls

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// iptablesBin 是调用的可执行文件。
//
// 允许通过环境变量覆盖（例如 openwrt 上叫 iptables-nft，或它装在
// /usr/sbin 而服务的 PATH 里没有）。不写成配置项是因为它属于平台细节，
// 不该污染协议配置。
func iptablesBin() string {
	if v := strings.TrimSpace(os.Getenv("FLOWTLS_IPTABLES")); v != "" {
		return v
	}
	return "iptables"
}

// runIPTables 执行一条 iptables 命令，返回 stderr 文本。
func runIPTables(args []string) (string, error) {
	cmd := exec.Command(iptablesBin(), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stderr.String(), err
}

// isPermissionError 判断 stderr 是否是权限问题。
//
// iptables 在无权限时退出码也是 1（和「规则不存在」一样），
// 所以必须靠 stderr 区分，否则会把权限不足误报成「规则已存在」，
// 后续 -A 再失败一次才暴露，报错信息还指错方向。
func isPermissionError(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "permission denied") ||
		strings.Contains(s, "must be root") ||
		strings.Contains(s, "operation not permitted")
}

// ruleExists 用 -C 判断规则是否已存在。
func ruleExists(r Rule) (bool, error) {
	stderr, err := runIPTables(r.Command("-C"))
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if isPermissionError(stderr) {
			return false, fmt.Errorf("flowtls: iptables 权限不足（需要 root 或 CAP_NET_ADMIN）: %s", strings.TrimSpace(stderr))
		}
		if exitErr.ExitCode() == 1 {
			// -C 的约定：规则不存在时退出码 1
			return false, nil
		}
		return false, fmt.Errorf("flowtls: iptables -C 失败（退出码 %d）: %s", exitErr.ExitCode(), strings.TrimSpace(stderr))
	}
	// 二进制不存在或不可执行
	return false, fmt.Errorf("flowtls: 无法执行 %s（请确认已安装，或用 FLOWTLS_IPTABLES 指定路径）: %w", iptablesBin(), err)
}

// addRule 添加一条规则。
func addRule(r Rule) error {
	stderr, err := runIPTables(r.Command("-A"))
	if err == nil {
		return nil
	}
	// 并发启动两个进程时可能出现「刚 -C 判不存在，-A 时已被对方加上」，
	// 这种情况视为成功，保证幂等。
	if strings.Contains(stderr, "already exists") {
		return nil
	}
	if isPermissionError(stderr) {
		return fmt.Errorf("flowtls: iptables 权限不足（需要 root 或 CAP_NET_ADMIN）: %s", strings.TrimSpace(stderr))
	}
	return fmt.Errorf("flowtls: 写入规则失败 %q: %s", r.String(), strings.TrimSpace(stderr))
}
