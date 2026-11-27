#!/usr/bin/env bash
#
# relay.sh —— FlowTLS 三层转发跳板机一键脚本（在**跳板机**上跑，不在客户端/服务端跑）
#
# 用途：让客户端连「跳板机A:本地端口」，跳板机把它原样转发到「服务端B:8443」。
#       只改 IP 头（DNAT + SNAT），不终止连接，伪造 TCP 报文原样穿过。
#
# 为什么必须三层转发、不能用 socat/nginx stream/haproxy/gost -L tcp：
#   那些工具会先用内核 TCP 把连接接住，再另起一条真 TCP 连过去。
#   服务端只认「带 ip_id 标记的伪 SYN」，内核发的普通 SYN 在 raw 表就被 DROP 了。
#   表现是「connect 成功但没数据」。详见 DEVTIPS.md 第 168 条。
#
# 设计上的三条硬约束（改脚本前必读）：
#
#   1. **规则写在独立的 nft 表里**（默认 table ip flowtls_relay），
#      绝不写进 `ip nat` 表的 PREROUTING/POSTROUTING。
#      原因：1Panel 的 dnat.service（/usr/local/bin/dnat.sh）循环里会
#      `iptables -t nat -F PREROUTING` + `-F POSTROUTING` 后重写全部规则。
#      它**不是**每 60 秒都 flush（只在服务重启、首轮、或它自己的
#      /etc/dnat/conf 变化时），但每次触发都会把别人写在那两个链里的规则
#      一并抹掉。独立表不受 iptables 兼容层 flush 影响。
#
#   2. **不给转发端口加 notrack**（服务端自己可以加，这里不行）。
#      没有 conntrack 条目时 nf_nat_inet_fn() 直接 NF_ACCEPT，
#      DNAT 和 SNAT 会一起失效。跳板机要的是 be_liberal=1，不是 notrack。
#
#   3. **DNAT 与 SNAT 必须成对**。只做 DNAT 时服务端回程包直接发给客户端，
#      源地址变成服务端地址，而客户端 matchPeer 只认配置里的对端地址/端口，
#      整包丢弃 → 客户端只会反复重发纯 SYN。
#
# 常用命令：
#   ./relay.sh add 9443 203.0.113.10 8443     # 加一条转发（立刻生效，**默认自动持久化**）
#   ./relay.sh del 9443                       # 删一条
#   ./relay.sh list                           # 看配置 + 实时规则 + 计数
#   ./relay.sh status                         # 体检（含冲突检测、SNAT 源地址推导）
#   ./relay.sh install                        # 只重新安装持久化（修复/手动同步）
#   ./relay.sh uninstall [--purge]            # 撤销持久化（默认保留 conf）
#
# **默认持久化**：add 会自动把脚本装到 /usr/local/sbin/flowtls-relay、
# 写 /etc/sysctl.d/99-flowtls-relay.conf、写并启用 systemd unit，重启后自动
# 重建规则表。文件内容没变就不重写（不磨损 flash，也不白跑 daemon-reload）。
# 临时试一下、不想留任何持久化痕迹时加 --no-persist（或 RELAY_NO_PERSIST=1）。
#
# 环境变量（测试/多实例时用，一般不用设）：
#   RELAY_CONF    配置文件     默认 /etc/flowtls-relay/conf
#   RELAY_TABLE   nft 表名     默认 flowtls_relay
#   RELAY_SYSCTL  sysctl 文件  默认 /etc/sysctl.d/99-flowtls-relay.conf
#   RELAY_UNIT    unit 文件    默认 /etc/systemd/system/flowtls-relay.service
#   RELAY_SELF    安装路径     默认 /usr/local/sbin/flowtls-relay
#   RELAY_SNAT    强制指定 SNAT 源地址（默认用 ip route get <目标> 自动推导）
#   RELAY_NO_FIB=1     不生成 fib daddr type local（老内核/nft 缺 fib 支持时用）
#   RELAY_NO_PERSIST=1 等同 --no-persist
#
set -uo pipefail

CONF="${RELAY_CONF:-/etc/flowtls-relay/conf}"
TABLE="${RELAY_TABLE:-flowtls_relay}"
SYSCTL_FILE="${RELAY_SYSCTL:-/etc/sysctl.d/99-flowtls-relay.conf}"
UNIT_FILE="${RELAY_UNIT:-/etc/systemd/system/flowtls-relay.service}"
SELF_PATH="${RELAY_SELF:-/usr/local/sbin/flowtls-relay}"
UNIT_NAME=$(basename "$UNIT_FILE" .service)

# PERSIST=1 表示「持久化是默认行为」。入口处解析 --no-persist 将其置 0。
PERSIST=1
[ "${RELAY_NO_PERSIST:-0}" = "1" ] && PERSIST=0

# 只在「包的目的地就是本机」时才 DNAT。
# 少了它，任何经过本机、目的端口恰好相同的**转发**流量也会被劫走。
# 注意：这条与 DEVTIPS 167 里客户端那条 `fib daddr type local` 用途相反——
# 那里是想**排除**转发流量（挂 prerouting 时 daddr 还没被 DNAT 还原，判不出来，
# 所以那条改挂 input 钩子）；这里是在 nat 的 prerouting 阶段判「目的地是不是本机」，
# 语义正确且早于 DNAT 改地址。
FIB_MATCH='fib daddr type local '
[ "${RELAY_NO_FIB:-0}" = "1" ] && FIB_MATCH=''

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
die()  { red "错误: $*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

need_root() {
	[ "$(id -u)" = "0" ] || die "必须以 root 运行（改 nft 规则与 sysctl）"
}
need_nft() {
	command -v nft >/dev/null 2>&1 || die "找不到 nft。FlowTLS 转发要求 nftables（Debian 10+ / Ubuntu 18.04+ 自带）"
}

valid_port() {
	case "$1" in ''|*[!0-9]*) return 1 ;; esac
	[ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

valid_ipv4() {
	# 只要点分十进制四段，且每段 0~255。不做域名解析以外的事。
	local ip=$1 IFS=. o
	case "$ip" in *[!0-9.]*|.*|*.|*..*) return 1 ;; esac
	set -- $ip
	[ $# -eq 4 ] || return 1
	for o in "$@"; do [ "$o" -le 255 ] || return 1; done
	return 0
}

# 把主机名解析成 IPv4（add 时解析一次并写死，避免开机时 DNS 还没好）
resolve_ipv4() {
	local h=$1 ip
	if valid_ipv4 "$h"; then printf '%s' "$h"; return 0; fi
	ip=$(getent ahostsv4 "$h" 2>/dev/null | awk 'NR==1{print $1}')
	[ -n "$ip" ] || return 1
	printf '%s' "$ip"
}

# 到目标地址的出向源 IP，就是 SNAT 要写的地址。
# 用 `ip route get` 而不是枚举网卡：多网卡 / 云主机内网地址 / VLAN 都自动正确。
# 1Panel 的 dnat.sh 用「排除私有段」的启发式，在 NAT 云主机上是错的（会挑不到地址）。
snat_ip_for() {
	local target=$1 src
	if [ -n "${RELAY_SNAT:-}" ]; then printf '%s' "$RELAY_SNAT"; return 0; fi
	src=$(ip -o -4 route get "$target" 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
	[ -n "$src" ] || return 1
	printf '%s' "$src"
}

# ------------------------------------------------------------------ conf 读写
#
# conf 每行一条：<本地端口> <目标IP> <目标端口>
# 允许 # 注释与空行。**只存 IP**，不存域名——开机时 DNS 未必可用。

conf_init() {
	mkdir -p "$(dirname "$CONF")"
	[ -f "$CONF" ] || { : >"$CONF"; chmod 600 "$CONF"; }
}

conf_mappings() {
	[ -f "$CONF" ] || return 0
	awk '/^[[:space:]]*(#|$)/{next} NF>=3{print $1, $2, $3}' "$CONF"
}

conf_has_port() {
	local port=$1
	conf_mappings | awk -v p="$port" '$1==p{f=1} END{exit !f}'
}

# ------------------------------------------------------------------ 规则生成

# render_nft 把全部映射渲染成一个 nft 脚本（stdout）。
# 用「add table → delete table → table {...}」三段：add 对已存在的表是幂等的，
# delete 因此必定成功；整个文件在 nft -f 里是一个原子事务，
# 不会出现「旧规则删了、新规则还没加」的空窗。
render_nft() {
	local lp tip tp snat

	# 没有映射时不留空表：空 base chain 本身无害，但会让 status / nft list
	# 看起来像「有配置却不出规则」。add + delete 在同一个 nft -f 事务里
	# 必定成功，跑完内核里干干净净。
	if [ -z "$(conf_mappings)" ]; then
		printf 'add table ip %s\ndelete table ip %s\n' "$TABLE" "$TABLE"
		return 0
	fi

	printf 'add table ip %s\n' "$TABLE"
	printf 'delete table ip %s\n' "$TABLE"
	printf 'table ip %s {\n' "$TABLE"
	printf '  chain prerouting {\n'
	printf '    type nat hook prerouting priority dstnat; policy accept;\n'
	while read -r lp tip tp; do
		[ -n "${lp:-}" ] || continue
		# counter 是给 status 看的：DNAT 计数 ≈ SNAT 计数 才说明回程也走通了
		printf '    iifname != "lo" %smeta l4proto tcp tcp dport %s counter dnat to %s:%s\n' \
			"$FIB_MATCH" "$lp" "$tip" "$tp"
		printf '    iifname != "lo" %smeta l4proto udp udp dport %s counter dnat to %s:%s\n' \
			"$FIB_MATCH" "$lp" "$tip" "$tp"
	done < <(conf_mappings)
	printf '  }\n'
	printf '  chain postrouting {\n'
	printf '    type nat hook postrouting priority srcnat; policy accept;\n'
	while read -r lp tip tp; do
		[ -n "${lp:-}" ] || continue
		snat=$(snat_ip_for "$tip") || {
			ylw "警告: 无法推导到 $tip 的源地址，跳过它的 SNAT（这条转发会不通）" >&2
			continue
		}
		printf '    meta l4proto tcp ip daddr %s tcp dport %s counter snat to %s\n' "$tip" "$tp" "$snat"
		printf '    meta l4proto udp ip daddr %s udp dport %s counter snat to %s\n' "$tip" "$tp" "$snat"
	done < <(conf_mappings)
	printf '  }\n'
	printf '}\n'
}

# apply_runtime 重建规则表（幂等，随时可重复执行）。
apply_runtime() {
	need_root
	need_nft
	local tmp st
	tmp=$(mktemp)
	render_nft >"$tmp"

	# 先 `nft -c` 只做语法/依赖检查，不落规则——避免把半截规则写进内核
	if ! st=$(nft -c -f "$tmp" 2>&1); then
		rm -f "$tmp"
		die "nft 语法检查失败，未做任何改动: $st"
	fi
	if ! st=$(nft -f "$tmp" 2>&1); then
		rm -f "$tmp"
		die "nft 应用失败: $st"
	fi
	rm -f "$tmp"

	# 注意：这里不能用 `conf_mappings | grep -q .`：grep -q 命中即退出会让上游
	# awk 收到 SIGPIPE，在 pipefail 下整条管道返回 141，被误判成「没有条目」。
	if [ -z "$(conf_mappings)" ]; then
		ylw "conf 里没有任何转发条目（$CONF），已清空规则表"
	fi
}

# ------------------------------------------------------------------ 子命令

cmd_add() {
	local lp=${1:-} host=${2:-} rp=${3:-} tip conflict
	[ -n "$lp" ] && [ -n "$host" ] && [ -n "$rp" ] || die "用法: $0 add <本地端口> <目标IP或域名> <目标端口>"
	need_root
	need_nft
	valid_port "$lp" || die "本地端口非法: $lp"
	valid_port "$rp" || die "目标端口非法: $rp"
	conf_init

	tip=$(resolve_ipv4 "$host") || die "无法把 $host 解析成 IPv4（本协议只支持 IPv4）"

	conf_has_port "$lp" && die "本地端口 $lp 已经在 conf 里了，先 del $lp（不允许同端口双目标）"

	# 冲突检测：如果其它表（含 iptables 兼容层 / 1Panel dnat.service）里已经有
	# 同端口的 DNAT，两条规则谁先生效取决于表/链的匹配顺序，结果不可预测。
	conflict=$(find_conflict "$lp")
	if [ -n "$conflict" ]; then
		ylw "注意: 系统里已有对端口 $lp 的 DNAT（可能来自 1Panel dnat.service）："
		printf '  %s\n' "$conflict"
		ylw "两条同时存在时以先匹配者为准，建议先清掉旧的那条。"
	fi

	printf '%s %s %s\n' "$lp" "$tip" "$rp" >>"$CONF"
	apply_runtime
	grn "已添加: 本机 ${lp} -> ${tip}:${rp}（SNAT 源地址 $(snat_ip_for "$tip")）"

	# **默认持久化**：装脚本、写 sysctl、启用 systemd，重启后自动重建。
	# 失败不阻断（本次转发已经生效），只警告。
	[ "$PERSIST" = "1" ] && install_persist

	cat <<EOF

客户端这样配（其余字段不变，password / sni / 带宽都不用改）：
  "server": "<跳板机公网地址>",
  "server_port": $lp

注意：
  * **不要从跳板机本机测** ${lp}：DNAT 挂在 prerouting，本机产生的流量走 output，
    永远不经过它，本机 curl/telnet 必然超时（这不是故障）。要从别的机器测。
  * 测的时候带 -k：回程是服务端的 masquerade 证书，域名对不上会报证书错。
  * 只能三层转发。别在前面再套 socat / nginx stream / haproxy / gost -L tcp。
EOF
}

cmd_del() {
	local lp=${1:-}
	[ -n "$lp" ] || die "用法: $0 del <本地端口>"
	conf_init
	conf_has_port "$lp" || die "conf 里没有端口 $lp"
	# 原地过滤（写临时文件再 mv，避免 tr 截断文件）
	local tmp
	tmp=$(mktemp)
	awk -v p="$lp" '/^[[:space:]]*(#|$)/{print;next} !($1==p)' "$CONF" >"$tmp"
	mv "$tmp" "$CONF"
	apply_runtime
	grn "已删除端口 $lp 的转发"
}

cmd_list() {
	conf_init
	info "== 配置文件 $CONF =="
	if [ -n "$(conf_mappings)" ]; then
		printf '%-8s %-16s %-8s %s\n' 本地端口 目标IP 目标端口 SNAT源
		while read -r lp tip tp; do
			printf '%-8s %-16s %-8s %s\n' "$lp" "$tip" "$tp" "$(snat_ip_for "$tip" || echo '?')"
		done < <(conf_mappings)
	else
		ylw "  （空）"
	fi
	info ""
	info "== 内核里的实时规则 table ip $TABLE =="
	if nft list table ip "$TABLE" >/dev/null 2>&1; then
		nft -a list table ip "$TABLE"
	else
		ylw "  表不存在（还没 apply 过，或已被清掉）"
	fi
}

# find_conflict 找「不在我们自己表里」的同端口 DNAT 规则。
# 只做只读查询，不修改任何东西。
find_conflict() {
	local lp=$1 out
	# 我们自己表里的不算冲突
	out=$(nft list ruleset 2>/dev/null | awk -v t="table ip $TABLE" '
		$0 ~ t {skip=1} skip && /^}/ {skip=0; next} !skip {print}' |
		grep -E "dnat to .*" | grep -E "dport $lp( |$)" || true)
	[ -n "$out" ] && printf '%s\n' "$out"
	return 0
}

cmd_status() {
	need_root
	info "== 1. 转发开关 =="
	local fwd
	fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo '?')
	[ "$fwd" = "1" ] && grn "  net.ipv4.ip_forward = 1 ✓" || red "  net.ipv4.ip_forward = $fwd ✗（必须是 1）"

	info ""
	info "== 2. conntrack 参数（伪 TCP 的关键两条）=="
	local bl mx cn
	bl=$(cat /proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal 2>/dev/null || echo '?')
	mx=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo '?')
	cn=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo '?')
	[ "$bl" = "1" ] && grn "  nf_conntrack_tcp_be_liberal = 1 ✓" ||
		red "  nf_conntrack_tcp_be_liberal = $bl ✗（伪 TCP 会被判 INVALID，表现为时通时不通；$0 install 会写）"
	info "  nf_conntrack_max  = $mx（当前用量 $cn）"
	if [ "$mx" != "?" ] && [ "$mx" -lt 32768 ] 2>/dev/null; then
		ylw "  上限偏小：每条隧道占 1 条 conntrack，多设备容易打满（建议 65536）"
	fi

	info ""
	info "== 3. 规则与计数 =="
	if nft list table ip "$TABLE" >/dev/null 2>&1; then
		nft -a list table ip "$TABLE"
		info ""
		info "  判读方法：同一映射的 DNAT 与 SNAT 计数应当**同量级**。"
		info "  SNAT 计数远低于 DNAT = 回程没走通（检查 SNAT 源地址是不是本机出口 IP）。"
		info "  DNAT 在涨但字节数 ≈ 包数 × 60 = 全是无载荷 SYN，说明服务端回程到不了客户端。"
	else
		ylw "  表不存在（$0 add 之后才有）"
	fi

	info ""
	info "== 4. 与本机其它转发工具的冲突 =="
	local found=0 lp
	while read -r lp _; do
		local c
		c=$(find_conflict "$lp")
		if [ -n "$c" ]; then
			found=1
			ylw "  端口 $lp 有其它表/工具的 DNAT："
			printf '    %s\n' "$c"
		fi
	done < <(conf_mappings)
	[ "$found" = "0" ] && grn "  无冲突 ✓"

	info ""
	info "== 5. 持久化状态（add 默认自动装）=="
	[ -f "$SYSCTL_FILE" ] && grn "  sysctl: $SYSCTL_FILE ✓" || ylw "  sysctl: 未安装（跑 $0 install）"
	[ -f "$UNIT_FILE" ] && grn "  unit:   $UNIT_FILE ✓" || ylw "  unit:   未安装（跑 $0 install）"
	systemctl is-enabled "$UNIT_NAME" >/dev/null 2>&1 &&
		grn "  开机自启: 已启用 ✓" || ylw "  开机自启: 未启用"
	systemctl is-active "$UNIT_NAME" >/dev/null 2>&1 &&
		grn "  服务状态: active ✓（systemctl reload $UNIT_NAME 可用）" ||
		ylw "  服务状态: inactive（$0 install 会启动它）"
}

# sync_file 内容不同才落盘。返回 0 = 有改动，1 = 内容一致（什么都没做）。
#
# 为什么必须比较：cron / 反复 add 会频繁调用，无脑覆盖会磨损 flash，
# 还会让 systemctl daemon-reload 白跑（这台机器上 1Panel 已经在每 60 秒
# 重写 iptables，再加一份无谓写入没有好处）。
sync_file() {
	local path=$1 tmp=$2
	if [ -f "$path" ] && cmp -s "$tmp" "$path"; then
		return 1
	fi
	mkdir -p "$(dirname "$path")"
	install -m 644 "$tmp" "$path"
	return 0
}

# install_persist 幂等地把「重启后仍然生效」需要的东西全部装好。
#
# 这是 add 的默认行为（PERSIST=1），所以它必须：
#   - 完全幂等，重复调用零副作用（内容没变就不写盘）；
#   - 失败时只警告不退出（持久化装不上不该妨碍本次转发已经生效）。
install_persist() {
	local changed=() tmp

	# 1) 脚本自身装到固定路径：unit 里必须引用一个不随 /tmp 消失的路径。
	if [ ! -f "$SELF_PATH" ] || ! cmp -s "$0" "$SELF_PATH"; then
		install -Dm755 "$0" "$SELF_PATH" || { ylw "警告: 无法安装脚本到 $SELF_PATH"; return 1; }
		changed+=("脚本 $SELF_PATH")
	fi

	# 2) sysctl：三条都必须持久化。
	#    ip_forward 是转发前提（1Panel 的 dnat.sh 也写 /etc/sysctl.conf，重复无害）；
	#    be_liberal 修「时通时不通」；max 防止多设备打满。
	tmp=$(mktemp)
	cat >"$tmp" <<-'EOF'
	# FlowTLS 三层转发跳板机（由 relay.sh 自动生成，add 时自维护）
	#
	# ip_forward：不做转发就什么都不通。
	net.ipv4.ip_forward = 1
	#
	# be_liberal：伪 TCP 的序号/窗口由协议自己造，不保证符合内核 conntrack
	# 的窗口跟踪。默认 0 时超出窗口的段会被判 INVALID 丢弃，症状是
	# 「隧道时通时不通，换个源端口重连又好」。放宽窗口校验不影响 NAT 决策。
	#
	# 注意：**不要**给它加 notrack——没有 conntrack 条目时
	# nf_nat_inet_fn() 直接放行，DNAT/SNAT 会一起失效。
	net.netfilter.nf_conntrack_tcp_be_liberal = 1
	#
	# 每条隧道占 1 条 conntrack 条目，默认 8192 对多设备偏小。
	net.netfilter.nf_conntrack_max = 65536
	EOF
	if sync_file "$SYSCTL_FILE" "$tmp"; then
		sysctl -q -p "$SYSCTL_FILE" >/dev/null 2>&1
		changed+=("sysctl $SYSCTL_FILE")
	fi
	rm -f "$tmp"

	# 3) systemd unit：开机重建规则表。
	#    ExecStop 故意是 /bin/true —— 规则**写后不清理**（与服务端一致）：
	#    服务重启/停止期间规则必须继续生效，否则内核会回 RST 打断重建中的隧道。
	#    要真正撤销请用 `relay.sh uninstall`。
	if command -v systemctl >/dev/null 2>&1; then
		tmp=$(mktemp)
		cat >"$tmp" <<-EOF
		[Unit]
		Description=FlowTLS L3 relay (DNAT+SNAT) for fake-TCP tunnels
		Documentation=file://$SELF_PATH
		After=network-online.target nftables.service
		Wants=network-online.target

		[Service]
		Type=oneshot
		RemainAfterExit=yes
		ExecStart=$SELF_PATH apply
		ExecReload=$SELF_PATH apply
		ExecStop=/bin/true

		[Install]
		WantedBy=multi-user.target
		EOF
		if sync_file "$UNIT_FILE" "$tmp"; then
			systemctl daemon-reload >/dev/null 2>&1
			changed+=("unit $UNIT_FILE")
		fi
		rm -f "$tmp"
		if ! systemctl is-enabled "$UNIT_NAME" >/dev/null 2>&1; then
			systemctl enable "$UNIT_NAME" >/dev/null 2>&1 &&
				changed+=("开机自启 $UNIT_NAME")
		fi
		# oneshot + RemainAfterExit 的 unit 必须先 start 一次才进入 active，
		# 否则 `systemctl reload` 会报 "is not active, cannot reload"。
		# 只在用默认路径时启动：测试用 RELAY_* 覆盖路径时，unit 指向的是
		# 真实服务，不应被测试顺手拉起。
		if [ "$CONF" = "/etc/flowtls-relay/conf" ] &&
			[ "$UNIT_FILE" = "/etc/systemd/system/flowtls-relay.service" ] &&
			! systemctl is-active "$UNIT_NAME" >/dev/null 2>&1; then
			systemctl start "$UNIT_NAME" >/dev/null 2>&1 &&
				changed+=("已启动 $UNIT_NAME")
		fi
	fi

	# 4) 运行中的取值兜底：有人手工 sysctl -w 改回去了也自动补回。
	[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ] ||
		sysctl -qw net.ipv4.ip_forward=1 >/dev/null 2>&1
	[ "$(cat /proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal 2>/dev/null)" = "1" ] ||
		sysctl -qw net.netfilter.nf_conntrack_tcp_be_liberal=1 >/dev/null 2>&1

	if [ ${#changed[@]} -gt 0 ]; then
		grn "已持久化: ${changed[*]}"
	else
		info "持久化已是最新（无改动）"
	fi
	return 0
}

cmd_install() {
	need_root
	need_nft
	conf_init

	if [ "$PERSIST" = "0" ]; then
		ylw "install 就是用来装持久化的，--no-persist 在这里无意义，已忽略"
	fi
	PERSIST=1
	install_persist

	apply_runtime
	grn "持久化完成。重启后会自动重建规则表。"
	info "改动 conf 后执行: $SELF_PATH apply（或 systemctl reload $UNIT_NAME）"
}

cmd_uninstall() {
	need_root
	local purge=0
	[ "${1:-}" = "--purge" ] && purge=1

	systemctl disable "$(basename "$UNIT_FILE" .service)" >/dev/null 2>&1
	rm -f "$UNIT_FILE"
	systemctl daemon-reload
	nft delete table ip "$TABLE" 2>/dev/null
	info "已删除 unit 与规则表（sysctl 保留：be_liberal/max 对其它转发也有益）"

	if [ "$purge" = "1" ]; then
		rm -f "$SYSCTL_FILE" "$CONF" "$SELF_PATH"
		sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1
		ylw "已彻底清理（conf / sysctl / 脚本自身）。ip_forward 已关，若还有别的转发请自行改回 1。"
	else
		info "conf 与 sysctl 保留；加 --purge 可彻底删除"
	fi
}

usage() {
	# 取脚本头部注释作为帮助：从第 2 行到 "set -uo pipefail" 之前，
	# 用标记截取而不是写死行号（行号会随注释增长而漂移）。
	awk 'NR>1 && /^set -uo pipefail/{exit} NR>1{sub(/^# ?/,""); print}' "$0"
}

# ------------------------------------------------------------------ 入口

# 先解析全局开关：--no-persist 对 add 有效（install 自己会强制打开）。
_args=()
for _a in "$@"; do
	case "$_a" in
	--no-persist) PERSIST=0 ;;
	*) _args+=("$_a") ;;
	esac
done
set -- ${_args[@]+"${_args[@]}"}

case "${1:-help}" in
	add)       shift; cmd_add "$@" ;;
	del|rm)    shift; cmd_del "$@" ;;
	list|ls)   cmd_list ;;
	status|st) cmd_status ;;
	apply)     apply_runtime; info "规则已重建（$(conf_mappings | awk 'END{print NR}') 条）" ;;
	install)   cmd_install ;;
	uninstall) shift; cmd_uninstall "$@" ;;
	help|-h|--help) usage ;;
	*) usage; exit 1 ;;
esac
