#!/usr/bin/env bash
# 三点分解：ChaCha+raw / AES+raw / AES+af_packet 各跑一遍
#
# 目的是把「换算法」与「换发送路径」两个改动的贡献分开，
# 而不是只看合起来的数字。
#
# 用法：bash docs/ab_bench3.sh [轮数] [并发路数]

set -uo pipefail

ROUNDS="${1:-4}"
CONC="${2:-4}"
SRC="http://127.0.0.1:18090/100MB.bin"
USER_AUTH="admin:abcd1234"

# 三组对照：标签 → 端口
declare -a CHANNELS=(
	"ChaCha+raw:1080"
	"AES+raw:1083"
	"AES+afpkt:1081"
)

# 读某进程的 utime/stime（clock ticks）
cpu_ticks() {
	local pid="$1"
	awk '{print $14, $15}' "/proc/${pid}/stat" 2>/dev/null || echo "0 0"
}

port_pid() {
	ss -tlnp 2>/dev/null | grep ":$1 " | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1
}

fetch() {
	local port="$1"
	curl -s -o /dev/null \
		-w '%{speed_download}\n' \
		-x "http://${USER_AUTH}@127.0.0.1:${port}" \
		--max-time 180 "$SRC"
}

fetch_conc() {
	local port="$1" n="$2" tmp
	tmp=$(mktemp -d)
	for i in $(seq 1 "$n"); do
		(
			curl -s -o /dev/null -w '%{speed_download}\n' \
				-x "http://${USER_AUTH}@127.0.0.1:${port}" \
				--max-time 180 "$SRC" > "$tmp/$i"
		) &
	done
	wait
	awk '{s+=$1} END {printf "%.0f\n", s}' "$tmp"/*
	rm -rf "$tmp"
}

echo "=== 单流 100MB × ${ROUNDS} 轮（三通道交替）==="
printf '%-4s %-14s %-10s %-10s\n' 轮次 通道 MB/s CPU占比
for i in $(seq 1 "$ROUNDS"); do
	for ch in "${CHANNELS[@]}"; do
		label="${ch%%:*}"
		port="${ch##*:}"
		pid=$(port_pid "$port")
		read -r u0 s0 <<< "$(cpu_ticks "$pid")"
		speed=$(fetch "$port")
		read -r u1 s1 <<< "$(cpu_ticks "$pid")"
		mbps=$(awk -v s="$speed" 'BEGIN {printf "%.2f", s/1048576}')
		# CPU 占比：本次下载消耗的 tick / 100（HZ=100 时 tick 即 10ms）
		cpu=$(awk -v a="$u0" -v b="$s0" -v c="$u1" -v d="$s1" \
			'BEGIN {t=(c-a)+(d-b); printf "%.1f%%", t*10/1000*100/100}')
		printf '%-4s %-14s %-10s %-10s\n' "$i" "$label" "$mbps" "$cpu"
	done
done

echo
echo "=== ${CONC} 路并发 100MB（三通道交替）==="
printf '%-4s %-14s %-10s\n' 轮次 通道 合计MB/s
for i in 1 2 3; do
	for ch in "${CHANNELS[@]}"; do
		label="${ch%%:*}"
		port="${ch##*:}"
		total=$(fetch_conc "$port" "$CONC")
		mbps=$(awk -v s="$total" 'BEGIN {printf "%.2f", s/1048576}')
		printf '%-4s %-14s %-10s\n' "$i" "$label" "$mbps"
	done
done
