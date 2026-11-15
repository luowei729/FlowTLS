#!/usr/bin/env bash
# 内核态优化 A/B：**ABAB 交替**，每档只改环境变量，端口/配置/二进制全不变。
#
# # 为什么必须 ABAB 而不是 AAA BBB
#
# 本轮的教训（见 DEVTIPS 129）：先跑 6 轮 off、再跑 6 轮 on、再跑 6 轮 off，
# 结果是 off=0.0414 / on=0.0371 / off2=0.0379 —— 后两组几乎一样，
# 说明**存在时间漂移**（链路状态变化或服务端预热），
# 「on 比 off 快 10%」完全是漂移，不是收益。
#
# ABAB 交替把漂移均摊到两组上，差值才可信。
#
# # 判据
#
# 首选「服务端 CPU秒/MB」：它与链路速度无关（CPU 花在每字节上多少），
# 受漂移影响最小。吞吐只作参考。
#
# 用法：bash docs/ab_kernel.sh [每档轮数] [循环次数]

set -uo pipefail

ROUNDS="${1:-3}"
CYCLES="${2:-2}"
SRC="http://127.0.0.1:18090/100MB.bin"
AUTH="admin:abcd1234"
# ---- 服务端连接方式：**从环境变量取，绝不写死在仓库里** ----
#
# 真实 IP 属于部署指纹（AGENTS.md 约束 18 / DEVTIPS 119）：
# FakeTCP 的抗探测能力依赖「IP + ip_id_mark + SNI 都不公开」。
# 本脚本早先版本直接写死了跳板与服务端 IP，被 CI 的 docs/leak_check.sh 抓到，
# 已改为参数化——这也是它存在的意义：门禁真的会拦。
#
#   FLOWTLS_SERVER    必填，ssh 目标，形如 root@203.0.113.10
#   FLOWTLS_SSH_OPTS  可选，额外 ssh 参数，例如 "-J root@198.51.100.11"
#
# 示例：
#   FLOWTLS_SERVER=root@203.0.113.10 \
#   FLOWTLS_SSH_OPTS="-J root@198.51.100.11" \
#   bash docs/ab_kernel.sh 3 3
: "${FLOWTLS_SERVER:?请设置 FLOWTLS_SERVER（例如 root@203.0.113.10）；真实地址不要写进仓库}"
SSH="ssh ${FLOWTLS_SSH_OPTS:-} -o ConnectTimeout=15 ${FLOWTLS_SERVER}"

# 档位组合。TX_RING 已在实测中被否掉（见 DEVTIPS 131），
# 所以默认只对比 base / recvmmsg；要看 txring 把那两行取消注释。
# 用 | 分隔（早期用 : 导致 base 档的 env 变成 ":"，
# `env :` 会尝试执行名为 ":" 的程序 → 那一档全部失败）。
declare -a CASES=(
	"base|"
	"recvmmsg|FLOWTLS_RECVMMSG=1"
	#"txring|FLOWTLS_TXRING=1"
	#"both|FLOWTLS_RECVMMSG=1 FLOWTLS_TXRING=1"
)

switch_server() {
	local env="$1"
	timeout 40 $SSH "
		cd /root/flowtls
		for p in \$(pgrep -x sing-box-ab; pgrep -x sing-box-v3r; pgrep -x sing-box-v3c); do kill \$p; done
		# 等 5 秒：server.json 带 masquerade，它会 bind 内核 TCP 8443。
		# 上一个进程刚退出时端口可能仍被占（TIME_WAIT / backlog），
		# 新进程 bind 失败会直接 FATAL 退出——这会让该档全部测得 0，
		# 看起来像「代码跑不动」。
		sleep 5
		if [ -n "$env" ]; then
			env $env setsid nohup ./sing-box-ab run -c /root/flowtls/server.json \\
				> /root/flowtls/abk.log 2>&1 </dev/null & disown
		else
			setsid nohup ./sing-box-ab run -c /root/flowtls/server.json \\
				> /root/flowtls/abk.log 2>&1 </dev/null & disown
		fi
		sleep 4
		pgrep -x sing-box-ab >/dev/null || echo 'SERVER_FAILED' >> /root/flowtls/abk.log
		exit 0" >/dev/null 2>&1
}

switch_client() {
	local env="$1" i
	pkill -f 'client-v3-1080.json' 2>/dev/null
	# 等 1080 端口真的释放：sing-box 退出后监听 socket 可能还在
	# TIME_WAIT/CLOSE_WAIT，新实例 bind 失败会直接退出，
	# 那一档就会全部测成 0 MB/s（看起来像「代码跑不动」）。
	for i in $(seq 1 20); do
		ss -tln 2>/dev/null | grep -q ':1080 ' || break
		sleep 0.5
	done
	env $env nohup /root/FlowTLS/dist/sing-box-1.14.4-rev.2-linux-amd64 \
		run -c /tmp/live/client-v3-1080.json > /tmp/live/abk-client.log 2>&1 </dev/null &
	# 确认监听真的起来了，最多等 15 秒
	for i in $(seq 1 30); do
		ss -tln 2>/dev/null | grep -q ':1080 ' && return 0
		sleep 0.5
	done
	echo "  [警告] 客户端 1080 未监听，本档数据不可信"
}

# 输出「MB/s  CPU秒/MB」
measure() {
	local c0 c1 bytes secs
	c0=$($SSH "awk '{print \$14+\$15}' /proc/\$(pgrep -x sing-box-ab)/stat" 2>/dev/null)
	if [ -z "$c0" ]; then
		echo "0 SERVFAIL"
		return
	fi
	read -r bytes secs < <(curl -s -o /dev/null -w '%{size_download} %{time_total}\n' \
		-x "http://${AUTH}@127.0.0.1:1080" --max-time 180 "$SRC")
	c1=$($SSH "awk '{print \$14+\$15}' /proc/\$(pgrep -x sing-box-ab)/stat" 2>/dev/null)
	awk -v a="$c0" -v b="$c1" -v by="$bytes" -v t="$secs" 'BEGIN {
		if (by <= 0 || t <= 0) { print "0 0"; exit }
		mb = by/1048576
		printf "%.2f %.4f\n", mb/t, (b-a)*0.01/mb
	}'
}

echo "=== 内核态优化 ABAB 交替（每档 ${ROUNDS} 轮 × ${CYCLES} 循环）==="
for cyc in $(seq 1 "$CYCLES"); do
	for c in "${CASES[@]}"; do
		name="${c%%|*}"
		env="${c#*|}"
		switch_server "$env"
		sleep 3
		switch_client "$env"
		sleep 9
		# 预热
		curl -s -o /dev/null -x "http://${AUTH}@127.0.0.1:1080" --max-time 60 "$SRC"
		for i in $(seq 1 "$ROUNDS"); do
			read -r mb cpu <<< "$(measure)"
			printf '  循环%d %-10s 轮%d  %6s MB/s  %8s CPU秒/MB\n' "$cyc" "$name" "$i" "$mb" "$cpu"
		done
	done
done

echo
echo "=== 各档汇总（CPU秒/MB，越小越好）==="
