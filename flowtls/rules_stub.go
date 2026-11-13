//go:build !linux

package flowtls

import "fmt"

// 非 Linux 平台上 iptables 不存在。
//
// 这条分支的存在意义不是「支持」，而是让 `print` 模式仍然能工作：
// 规则文本是纯字符串拼装，和平台无关。只有 auto 落到这里才报错。
//
// 交叉编译能过（CI 里有 windows/darwin 构建）也靠它。

var errIPTablesUnsupported = fmt.Errorf(
	"flowtls: iptables_mode=auto 仅支持 Linux；当前平台请用 iptables_mode=print 取规则后手工配置")

func ruleExists(Rule) (bool, error) { return false, errIPTablesUnsupported }

func addRule(Rule) error { return errIPTablesUnsupported }
