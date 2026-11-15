#!/usr/bin/env bash
# 新旧通道吞吐对照（本地文件 100MB，单流 + 并发，交替测量）
#
# 为什么交替：跨境链路自身在 5~15 MB/s 之间漂移，隔几分钟的两次数据
# 没有可比性（DEVTIPS 109）。同一时间窗内轮流跑，才能把实现差异从链路漂移里分离。
#
# 用法：bash docs/ab_bench.sh [单流轮数] [并发路数]

set -uo pipefail

SINGLE="${1:-5}"
CONC="${2:-4}"
SRC="http://127.0.0.1:18090/100MB.bin"
USER_AUTH="admin:abcd1234"
OLD=1080
NEW=1081

# 一次下载：输出「字节数 秒数 字节/秒」
fetch() {
	local port="$1"
	curl -s -o /dev/null \
		-w '%{size_download} %{time_total} %{speed_download}\n' \
		-x "http://${USER_AUTH}@127.0.0.1:${port}" \
		--max-time 180 "$SRC"
}

# 并发下载：n 路同时开始，输出每路 speed_download，最后求和
fetch_conc() {
	local port="$1" n="$2"
	local tmp
	tmp=$(mktemp -d)
	for i in $(seq 1 "$n"); do
		(
			curl -s -o /dev/null \
				-w '%{speed_download}\n' \
				-x "http://${USER_AUTH}@127.0.0.1:${port}" \
				--max-time 180 "$SRC" > "$tmp/$i"
		) &
	done
	wait
	awk '{s+=$1} END {printf "%.0f\n", s}' "$tmp"/*
	rm -rf "$tmp"
}

echo "=== 单流 100MB × ${SINGLE} 轮（交替，同一时间窗）==="
printf '%-4s %-10s %-8s %-12s\n' 轮次 通道 秒 MB/s
for i in $(seq 1 "$SINGLE"); do
	for label_port in "旧:$OLD" "新:$NEW"; do
		label="${label_port%%:*}"
		port="${label_port##*:}"
		read -r bytes secs speed <<< "$(fetch "$port")"
		mbps=$(awk -v s="$speed" 'BEGIN {printf "%.2f", s/1048576}')
		printf '%-4s %-10s %-8s %-12s\n' "$i" "$label($port)" "$secs" "$mbps"
	done
done

echo
echo "=== ${CONC} 路并发 100MB（交替）==="
printf '%-4s %-10s %-12s\n' 轮次 通道 合计MB/s
for i in 1 2 3; do
	for label_port in "旧:$OLD" "新:$NEW"; do
		label="${label_port%%:*}"
		port="${label_port##*:}"
		total=$(fetch_conc "$port" "$CONC")
		mbps=$(awk -v s="$total" 'BEGIN {printf "%.2f", s/1048576}')
		printf '%-4s %-10s %-12s\n' "$i" "$label($port)" "$mbps"
	done
done
