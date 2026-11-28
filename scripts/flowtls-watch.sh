#!/bin/sh
# passwall-flowtls-watch —— FlowTLS 链路外部探针（诊断用，非生产必需）
#
# 为什么需要它：面板（haproxy :1188）只告诉你「UP/DOWN」，不告诉你是哪一段出的问题。
# 而 sing-box 自身的日志对「卡住 100 秒」这种事件是**完全静默**的
# （它只在出错时打日志，卡住不出错），所以开 sing-box 的 debug 日志也没用。
# 唯一可靠的办法是从外面按固定间隔主动探测，并同时采一组「控制变量」，
# 事后按时间戳对齐就能判断故障落在哪一段：
#
#   直连探测失败  → 家宽/WAN 的问题，和 FlowTLS 无关
#   直连通、隧道不通 → FlowTLS（客户端卡 / 隧道丢包 / 服务端卡）
#   隧道通但很慢   → 拥塞或调度延迟，往往是下一次「卡住」的前兆
#
# 输出：/tmp/flowtls-watch.log（放在 /tmp 是内存盘，不磨损 flash）
#   每次运行写一行；成功且延迟正常时只写紧凑行，失败/慢时附详细快照。
#
# 用法：
#   /usr/bin/passwall-flowtls-watch            # 跑一轮
#   /usr/bin/passwall-flowtls-watch status     # 看统计摘要
#   /usr/bin/passwall-flowtls-watch tail [N]   # 看最近 N 行
#
# 安装由 deploy 脚本完成；卸载：删本文件 + 删 /etc/crontabs/root 里那行。

PROBE_URL="https://www.google.com/generate_204"
PORTS="2001 2002"
LOG=/tmp/flowtls-watch.log
LOG_MAX=4000          # 行数上限，超过就砍掉前半，防止内存盘被吃满
SLOW_MS=2000          # 超过这个耗时算「慢」，额外记录（毫秒）
CTL_TIMEOUT=5

# ---------- 一行探测：输出 "http_code duration_sec exit_code" ----------
# 用 --noproxy "" 是必须的：busybox 的 curl 会读环境变量里的代理设置，
# 不显式清掉会绕过 -x 指定的 socks（PassWall 就踩过这个坑，
# 所以它自己的 haproxy_check.sh 也带这个参数）。
probe_tunnel() {
    _port=$1
    _out=$(/usr/bin/curl -q -I -o /dev/null -sk -A 'Mozilla/5.0' --noproxy "" \
        -x "socks5h://127.0.0.1:$_port" \
        --connect-timeout 3 --max-time 8 \
        -w '%{http_code} %{time_total}' "$PROBE_URL" 2>/dev/null)
    _rc=$?
    # curl 失败时 -w 仍会输出 "000 0.000"，所以两者都要看
    set -- $_out
    echo "${1:-000} ${2:-0} $_rc"
}

# ---------- 控制变量：不经过任何代理，从路由器直接出网 ----------
probe_direct() {
    _out=$(/usr/bin/curl -q -I -o /dev/null -sk --noproxy '*' \
        --connect-timeout $CTL_TIMEOUT --max-time $CTL_TIMEOUT \
        -w '%{http_code} %{time_total}' "$PROBE_URL" 2>/dev/null)
    _rc=$?
    set -- $_out
    echo "${1:-000} ${2:-0} $_rc"
}

# ---------- 失败/慢的时候，把判断所需的现场一次性记下来 ----------
# 只记**不随时间变化或变化很慢**的量，避免日志爆炸。
snapshot() {
    # 集合条目：过期/为空说明 nft 侧掉了保护（这就是每 10 分钟断线的老 bug）
    _sets=$(nft list table inet flowtls 2>/dev/null |
        awk '/set cft_/{n=$2} /elements =/{print n": "$0}' | head -4)
    [ -n "$_sets" ] && echo "    nft: $_sets"
    # conntrack 接近上限会让新连接被丢，且现象和「隧道卡住」一模一样
    _ct=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)
    _ctm=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)
    [ -n "$_ct" ] && echo "    conntrack: $_ct/$_ctm"
    # 单核路由器被抢占时也会卡，先看负载
    echo "    loadavg: $(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)"
    # sing-box 进程还在不在（掉进程和卡住的表现不同）
    _pids=$(pgrep -f 'haproxy_.*json' 2>/dev/null | tr '\n' ' ')
    echo "    sing-box pid: ${_pids:-NONE}"
    cpu_stamp
    echo "    client log: $(wc -l < /tmp/etc/passwall/flowtls-client.log 2>/dev/null || echo 0) 行"
}

# ---------- CPU 时间戳：区分「进程卡住」与「网络丢包」 ----------
# 判据：间隔 2 秒两次读 /proc/PID/stat 的 utime+stime。
#   增量 ≈ 0 且探测一直失败 → 进程没事干，问题在网络上（或它等的对象没回包）
#   增量很大且探测失败     → 进程在忙（自旋/GC/重传风暴），是 CPU 侧瓶颈
# 这一条比看日志有用得多：卡住的事件根本不产生日志行。
cpu_stamp() {
    _line="    cpu(ticks, Δ2s):"
    for _pid in $(pgrep -f 'haproxy_.*json' 2>/dev/null); do
        _a=$(awk '{print $14+$15}' /proc/$_pid/stat 2>/dev/null)
        [ -z "$_a" ] && continue
        echo "$_pid $_a" >> /tmp/.ftw-cpu
        _line="$_line pid$_pid=$_a"
    done
    echo "$_line"
}

cpu_delta() {
    # 与上一轮的记录相减，得出 2 秒内的 CPU 增量
    [ -f /tmp/.ftw-cpu ] || return 0
    _out="    cpu Δ(自上次采样):"
    while read -r _pid _old; do
        _new=$(awk '{print $14+$15}' /proc/$_pid/stat 2>/dev/null)
        [ -z "$_new" ] && continue
        _out="$_out pid$_pid=$((_new - _old))t"
    done < /tmp/.ftw-cpu
    echo "$_out"
    rm -f /tmp/.ftw-cpu
}

rotate() {
    [ -f "$LOG" ] || return 0
    _n=$(wc -l < "$LOG" 2>/dev/null)
    [ "${_n:-0}" -gt "$LOG_MAX" ] || return 0
    # 保留后半段（最近的事件才是排查要用的）
    _keep=$((LOG_MAX / 2))
    tail -n "$_keep" "$LOG" > "$LOG.tmp" && mv -f "$LOG.tmp" "$LOG"
    echo "$(date '+%F %T') [watch] 日志超过 ${LOG_MAX} 行，已裁剪到最近 ${_keep} 行" >> "$LOG"
}

# 客户端 sing-box 的 warn 级日志也要限长：它在 /tmp（内存盘），
# 一旦某天真出了高频错误，不设上限会把路由器的 RAM 吃光。
# 超过 512KB 就把旧内容挪到 .1（只留一份），保留最近的现场。
rotate_client_log() {
    _cl=/tmp/etc/passwall/flowtls-client.log
    [ -f "$_cl" ] || return 0
    _sz=$(wc -c < "$_cl" 2>/dev/null)
    [ "${_sz:-0}" -gt 524288 ] || return 0
    tail -c 131072 "$_cl" > "$_cl.tmp" 2>/dev/null && mv -f "$_cl.tmp" "$_cl"
}

run_once() {
    _ts=$(date '+%F %T')
    # 控制变量先测：它决定了后面失败该怎么解释
    set -- $(probe_direct)
    _dc=$1; _dt=$2; _dr=$3
    if [ "$_dc" != "200" ] && [ "$_dc" != "204" ]; then
        # 直连都不通，说明是 WAN/家宽的问题，隧道结论不可用
        echo "$_ts DIRECT-FAIL code=$_dc t=${_dt}s rc=$_dr" >> "$LOG"
        snapshot >> "$LOG"
        return
    fi

    for _p in $PORTS; do
        set -- $(probe_tunnel "$_p")
        _c=$1; _t=$2; _r=$3
        _ms=$(awk -v t="$_t" 'BEGIN{printf "%d", t*1000}')
        if [ "$_c" = "200" ] || [ "$_c" = "204" ]; then
            if [ "$_ms" -gt "$SLOW_MS" ]; then
                # 慢但成功：往往是「卡住」的前兆，值得单独记
                echo "$_ts port=$_p SLOW code=$_c ${_ms}ms direct=${_dt}s" >> "$LOG"
                snapshot >> "$LOG"
            else
                echo "$_ts port=$_p ok $_c ${_ms}ms" >> "$LOG"
            fi
        else
            echo "$_ts port=$_p FAIL code=$_c ${_ms}ms rc=$_r direct_ok=${_dt}s" >> "$LOG"
            snapshot >> "$LOG"
        fi
    done
}

show_status() {
    [ -f "$LOG" ] || { echo "还没有日志：$LOG"; return; }
    echo "=== 日志范围 ==="
    head -1 "$LOG"
    tail -1 "$LOG"
    echo "=== 探针总数 ==="
    printf '  成功: %s\n' "$(grep -c ' ok ' "$LOG" 2>/dev/null)"
    printf '  慢  : %s\n' "$(grep -c ' SLOW ' "$LOG" 2>/dev/null)"
    printf '  失败: %s\n' "$(grep -c ' FAIL ' "$LOG" 2>/dev/null)"
    printf '  直连失败(控制变量): %s\n' "$(grep -c 'DIRECT-FAIL' "$LOG" 2>/dev/null)"
    echo "=== 最近的失败/慢 ==="
    grep -E ' FAIL | SLOW |DIRECT-FAIL' "$LOG" 2>/dev/null | tail -20
    echo "=== 客户端 sing-box 日志（warn 级，最近 20 行）==="
    tail -20 /tmp/etc/passwall/flowtls-client.log 2>/dev/null || echo "  （空——warn 级只在出错时写，空是好消息）"
}

case "$1" in
    status) show_status ;;
    tail)   tail -n "${2:-40}" "$LOG" 2>/dev/null ;;
    *)      rotate; rotate_client_log; run_once ;;
esac
