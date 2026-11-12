#!/bin/bash
# 延迟体检：分三层测量，避免把「物理下限」误判成「性能退化」。
#
# 为什么分三层：
#   1. 纯隧道  = 目标在服务端本机，无 DNS、无 TLS。这一层等于隧道的真实成本，
#                理论值就是 1 个链路 RTT（ICMP RTT）。
#   2. 204 HTTPS = TLS(1 RTT) + HTTP(1 RTT) = 2 RTT 是**物理下限**，
#                任何代理都无法做到 1 RTT。看到 200ms 不等于有问题。
#   3. 丢包尾巴 = 跨境晚高峰 5%~20% 丢包，每丢一个包多等 1 RTT，
#                这是链路属性，不是代理实现问题。
#
# 用法：
#   bash docs/bench.sh              # 默认 20 次
#   bash docs/bench.sh 50           # 自定义次数
#   bash docs/bench.sh 20 11080     # 指定 SOCKS5 端口
set -u
N=${1:-20}
PORT=${2:-1080}
AUTH="admin:abcd1234"
API="http://127.0.0.1:${PORT}"
TUNNEL="http://203.0.113.10:8081/"

stat() { sort -n | awk '{a[NR]=$1} END {if(NR==0){print "  无数据";exit}
  printf "  min=%.0f  p50=%.0f  p90=%.0f  max=%.0f  (n=%d)\n",
    a[1]*1000, a[int((NR+1)/2)]*1000, a[int(NR*0.9)]*1000, a[NR]*1000, NR}'; }

# 链路基线：ICMP 直接打服务器，绕过所有代理
echo "[0] 链路基线（ICMP，绕过代理）"
ping -c 20 -i 0.3 -W 2 203.0.113.10 2>/dev/null | tail -2 | sed 's/^/  /'

echo
echo "[1] 纯隧道（目标=服务端本机，理论值 = 1 个 RTT）"
for _ in $(seq 1 "$N"); do
  curl -s -o /dev/null -w "%{time_total}\n" --max-time 12 \
    --socks5-hostname "$API" --proxy-user "$AUTH" "$TUNNEL"
done | stat

echo
echo "[2] 204 HTTPS（理论下限 = 2 个 RTT：TLS 1 + HTTP 1）"
for _ in $(seq 1 "$N"); do
  curl -s -o /dev/null -w "%{time_total}\n" --max-time 15 \
    --socks5-hostname "$API" --proxy-user "$AUTH" \
    https://www.gstatic.com/generate_204
done | stat

echo
echo "[3] 判定参考"
echo "  纯隧道 p50 ≈ ICMP RTT        → 隧道无额外开销（最优）"
echo "  纯隧道 p50 > ICMP RTT + 20ms → 实现有问题，需要排查"
echo "  204 p50  ≈ 纯隧道 × 2        → 正常"
echo "  两者的 p90 明显高于 p50      → 链路丢包（晚高峰常见），非代理问题"
