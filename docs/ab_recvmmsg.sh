#!/usr/bin/env bash
# recvmmsg 同端口可信 A/B（DEVTIPS 125 的方法论）
#
# 为什么必须同端口交替重启：这条跨境链路的 RTT/吞吐会在两态之间切换
# （77ms ↔ 220ms），跨端口并行测到的差值里混着链路状态，无法归因到代码。
# 所以这里**两端一起重启、只用环境变量切换**，端口、源端口、5 元组全不变。
#
# 用法：bash docs/ab_recvmmsg.sh [每档轮数]
#
# 判据（按可信度排序）：
#   1. 服务端 CPU秒/MB —— 与链路状态无关，最能说明 syscall 开销差异
#   2. 吞吐区间        —— 受链路影响，但同档内多轮取中位可比
#   3. QUIC srtt       —— 确认没有引入延迟回归

set -uo pipefail

ROUNDS="${1:-4}"
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

# 服务端切换：只改环境变量，端口/配置/hash 全不变
switch_server() {
	local mode="$1" env=""
	[ "$mode" = "on" ] && env="FLOWTLS_RECVMMSG=1"
	timeout 40 $SSH "
		cd /root/flowtls
		for p in \$(pgrep -x sing-box-v3r; pgrep -x sing-box-v3c; pgrep -x sing-box-rev1); do kill \$p; done
		sleep 2
		$env setsid nohup ./sing-box-v3r run -c /root/flowtls/server.json \
			> /root/flowtls/abm.log 2>&1 </dev/null & disown
		exit 0" >/dev/null 2>&1
}

# 客户端切换：同样只改环境变量
switch_client() {
	local mode="$1" env=""
	[ "$mode" = "on" ] && env="FLOWTLS_RECVMMSG=1"
	pkill -f 'client-v3-1080.json' 2>/dev/null
	sleep 2
	env $env nohup /root/FlowTLS/dist/sing-box-1.14.4-rev.2-linux-amd64 \
		run -c /tmp/live/client-v3-1080.json > /tmp/live/abm-client.log 2>&1 </dev/null &
}

# 一次下载：输出「MB/s  CPU秒/MB」
# CPU 用服务端进程的 utime+stime 差值，除以传输量 → 与链路速度无关的指标
measure() {
	local srv_cpu mb_per_s
	srv_cpu=$($SSH "awk '{print \$14+\$15}' /proc/\$(pgrep -x sing-box-v3r)/stat" 2>/dev/null)
	[ -z "$srv_cpu" ] && { echo "ERR"; return; }
	local bytes secs
	read -r bytes secs < <(curl -s -o /dev/null \
		-w '%{size_download} %{time_total}\n' \
		-x "http://${AUTH}@127.0.0.1:1080" --max-time 180 "$SRC")
	local srv_cpu2
	srv_cpu2=$($SSH "awk '{print \$14+\$15}' /proc/\$(pgrep -x sing-box-v3r)/stat" 2>/dev/null)
	awk -v a="$srv_cpu" -v b="$srv_cpu2" -v by="$bytes" -v t="$secs" 'BEGIN {
		if (by <= 0) { print "0 0"; exit }
		mb = by/1048576
		/* tick = 10ms（HZ=100） */
		cpu = (b-a)*0.01
		printf "%.2f %.4f\n", mb/t, cpu/mb
	}'
}

run_mode() {
	local mode="$1" label="$2"
	switch_server "$mode"
	sleep 3
	switch_client "$mode"
	sleep 9
	# 预热：建连 + 让 BBR 起速
	curl -s -o /dev/null -x "http://${AUTH}@127.0.0.1:1080" --max-time 60 "$SRC"
	local i mb cpu
	for i in $(seq 1 "$ROUNDS"); do
		read -r mb cpu <<< "$(measure)"
		printf '  %-6s 轮%d  %6s MB/s  %6s CPU秒/MB\n' "$label" "$i" "$mb" "$cpu"
	done
	# 顺带记录 srtt，确认没有延迟回归
	local srtt
	srtt=$($SSH "grep 'QUIC 路径统计' /root/flowtls/abm.log | tail -1 | grep -o 'srtt=[0-9]*ms'" 2>/dev/null)
	printf '  %-6s 服务端 %s\n' "$label" "${srtt:-srtt=NA}"
}

echo "=== recvmmsg 同端口 A/B（服务端 1 核 ARM，客户端同机）==="
echo "--- 逐帧 recvfrom（基准）---"
run_mode off "off"
echo "--- recvmmsg 批量（8 槽位）---"
run_mode on "on"
echo "--- 回到逐帧（确认无漂移）---"
run_mode off "off2"
