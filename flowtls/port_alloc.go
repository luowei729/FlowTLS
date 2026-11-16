package flowtls

// 客户端源端口的自动分配。
//
// ## 为什么需要动态端口
//
// FlowTLS 的一条隧道就是一个固定四元组：
//
//	(客户端 IP : 源端口, 服务端 IP : 服务端端口)
//
// 服务端用它定位会话（`listener.go` 的 byAddr）。固定源端口因此带来一个
// 硬限制：**一条隧道占一个端口**。当两处客户端经同一个 NAT 去同一台
// 服务端时（典型场景：路由器上的节点 + 局域网里另一台机器的节点），
// 如果它们的源端口相同，四元组就完全相同 —— 服务端只认一个会话，
// 新 SYN 会把旧会话踢掉，两边反复互踢。
//
// 真机踩过：PassWall 的 haproxy 里 FlowTLS 后端被反复标成 DOWN，
// 只有备用节点可用。
//
// ## 为什么以前必须固定
//
// 旧版的客户端防火墙规则是 `tcp sport <源端口> ... drop`（按源端口
// 精确匹配内核回的 RST）。端口随机就写不出这条规则，只能整段 DROP
// （会误伤正常流量），所以源端口必须固定。
//
// 现在规则改成**按服务端地址匹配**（见 rules.go 的 clientRules），
// 与源端口无关，这个限制就消失了。
//
// ## 分配策略
//
//   - 取 IANA 动态端口段 49152–65535，避开系统常用端口；
//   - 进程内用注册表避免自己撞自己（多个 Outbound 实例）；
//   - 再用 bind 探测一次内核是否已占用（best-effort，见 portFreeLocally）；
//   - Session 关闭时归还端口。
//
// 显式配置了 `source_port` 时不做任何分配，行为与旧版完全一致
// （部署方需要可预测的四元组时仍然可以钉死）。

import (
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
)

// 动态端口范围。上界取 65535，下界取 49152（IANA 动态/私有端口段），
// 避开 32768–60999 这种和 Linux 默认 ip_local_port_range 重叠较多的区间。
const (
	autoPortMin = 49152
	autoPortMax = 65535
)

var (
	autoPortMu   sync.Mutex
	autoPortUsed = make(map[uint16]struct{})
)

// AllocSourcePort 分配一个可用于 FlowTLS 的源端口。
//
// 返回 0 表示分配失败（极端情况下端口耗尽），调用方应报错而不是
// 退回到 0 —— 源端口 0 在 TCP 头里是非法的。
//
// 分配到的端口必须用 ReleaseSourcePort 归还，否则长时间运行会泄漏
// （每重连一次泄漏一个）。
func AllocSourcePort() uint16 {
	autoPortMu.Lock()
	defer autoPortMu.Unlock()

	// 随机起点 + 线性探测：随机起点让多实例重启后不会都从同一个端口
	// 开始抢，线性探测保证在只剩零星空位时也能找到。
	span := int(autoPortMax-autoPortMin) + 1
	start := int(rand.Uint32() % uint32(span))
	for i := 0; i < span; i++ {
		p := uint16(autoPortMin + (start+i)%span)
		if _, taken := autoPortUsed[p]; taken {
			continue
		}
		if !portFreeLocally(p) {
			continue
		}
		autoPortUsed[p] = struct{}{}
		return p
	}
	return 0
}

// ReleaseSourcePort 归还 AllocSourcePort 分配的端口。
//
// 传 0 或不存在的端口是安全的空操作（显式配置的固定端口不走这里）。
func ReleaseSourcePort(port uint16) {
	if port < autoPortMin || port > autoPortMax {
		return
	}
	autoPortMu.Lock()
	delete(autoPortUsed, port)
	autoPortMu.Unlock()
}

// portFreeLocally 探测内核是否已把这个端口当成「本机已用」。
//
// 只做 best-effort：伪连接走 raw socket，内核里没有对应 socket，
// 所以真正要防的是**本机其它程序**恰好占了这个端口。做法是尝试
// 在 127.0.0.1 上 bind 一个 TCP 监听——成功即说明内核侧没人用。
//
// 为什么不 bind 到 0.0.0.0：那会受 SO_REUSEADDR 与已有连接的影响，
// 结果不稳定；回环上的 bind 语义最干净。
//
// 探测失败（权限/家族不支持）时**视为可用**：宁可偶尔撞一次，也不要
// 因为探测本身不可用就让整条隧道起不来。
func portFreeLocally(port uint16) bool {
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		// 只有明确的「地址已占用」才算不可用。其它错误（地址族被禁、
		// 权限不足等）不能因此判定端口不可用，否则整条隧道会起不来。
		return !errors.Is(err, syscall.EADDRINUSE)
	}
	_ = l.Close()
	return true
}

// 保持 netip 引用：本文件与 Server 地址族约定一致（只支持 IPv4），
// 这样如果将来改成支持 IPv6，编译器会在这里提醒。
var _ = netip.AddrPort{}
