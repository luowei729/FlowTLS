#!/usr/bin/env bash
# 端到端互通矩阵（真 raw socket，需要 root 或 CAP_NET_RAW）。
#
# 与 docs/interop_check.sh 的分工：
#   interop_check.sh  —— 冻结向量，验证「字节层面」没漂移，不需要特权；
#   本脚本            —— 真链路，验证「握手 + 流 + 数据报」全链路可用。
#
# 矩阵（4 格）：
#   Go   客户端 → Go   服务端（sing-box 1.14.4-rev.1）   ← 始终执行
#   Go   客户端 → Rust 服务端                            ← 提供 RUST_FLOWTLS 时执行
#   Rust 客户端 → Go   服务端                            ← 提供 RUST_FLOWTLS 时执行
#   Rust 客户端 → Rust 服务端                            ← 提供 RUST_FLOWTLS 时执行
#
# Rust 参考实现已冻结，源码在 `legacy-rust` 分支（见 docs/EVOLUTION.md）。
# 想跑含 Rust 的单元格时，从该分支构建一次二进制即可：
#
#   git worktree add /tmp/flowtls-rust legacy-rust
#   cd /tmp/flowtls-rust && cargo build
#   RUST_FLOWTLS=/tmp/flowtls-rust/target/debug/flowtls bash docs/e2e_matrix.sh
#
# 用法：
#   bash docs/e2e_matrix.sh                     # 自动探测本机网卡 IP
#   LOCAL_IP=1.2.3.4 bash docs/e2e_matrix.sh
#
# 本脚本的 iptables_mode 固定为 none：矩阵验证的是协议互通，不是防火墙。
# auto 会往宿主机写入持久规则（设计如此，见 flowtls.ApplyRules 的注释），
# 由测试脚本静默改动系统状态不合适。想验证 auto 请看 DEVTIPS 第 74 条。
#
# 注意：LOCAL_IP 必须是**本机真实网卡地址**，不能是 127.0.0.1。
# 原因见 DEVTIPS 第 71 条：Go 客户端按默认路由选网卡，
# 发往 127.0.0.1 的裸包会被送到物理网卡，loopback 收不到。

set -uo pipefail

cd "$(dirname "$0")/.."

GO="${GO:-go}"
PASSWORD=test-password-123
PORT=8443
SOCKS_PORT_GO=11081
SOCKS_PORT_RUST=11080
IPID_MARK=61703 # 0xF107
SRC_PORT=44300
TMP=/tmp/ft-e2e
mkdir -p "$TMP"

# 环境探测要在写死默认值之前：本机 Go 装在 /usr/local/go，
# 而 CI 的 runner 上 Go 已经在 PATH 里、GOPATH 也不是 /root/go。
# 写死会让脚本在别的机器上直接失败（且报错信息指向权限，很难定位）。
if [ -d /usr/local/go/bin ] && ! command -v go >/dev/null 2>&1; then
	export PATH=/usr/local/go/bin:$PATH
fi
if [ -z "${GOPATH:-}" ]; then
	export GOPATH="$(go env GOPATH 2>/dev/null || echo "$HOME/go")"
fi
# GOTOOLCHAIN=local：禁止 go 自动下载新工具链。
# 依赖版本必须与 sing-box 的 go.mod 逐字节一致（AGENTS.md 第 9 条），
# 让 go 自作主张升版本会破坏这一点。
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"

RUST_FLOWTLS="${RUST_FLOWTLS:-}"

PASS=0
FAIL=0
SKIP=0

log() { printf '%s\n' "$*"; }
ok() {
	PASS=$((PASS + 1))
	log "  ✓ $*"
}
bad() {
	FAIL=$((FAIL + 1))
	log "  ✗ $*"
}
skip() {
	SKIP=$((SKIP + 1))
	log "  ‒ $*"
}

# ---------- 本机地址探测 ----------
if [[ -z "${LOCAL_IP:-}" ]]; then
	LOCAL_IP=$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
fi
if [[ -z "$LOCAL_IP" ]]; then
	log "无法探测本机地址，请显式设置 LOCAL_IP"
	exit 1
fi
log "本机地址：$LOCAL_IP"

if [[ $(id -u) -ne 0 ]] && ! capsh --print 2>/dev/null | grep -q cap_net_raw; then
	log "需要 root 或 CAP_NET_RAW"
	exit 1
fi

if [[ -n "$RUST_FLOWTLS" ]]; then
	[[ -x "$RUST_FLOWTLS" ]] || {
		log "RUST_FLOWTLS=$RUST_FLOWTLS 不可执行"
		exit 1
	}
	log "Rust 参考实现：$RUST_FLOWTLS"
else
	log "未设置 RUST_FLOWTLS，只跑 Go↔Go（含 Rust 的 3 格跳过）"
fi

# ---------- 构建 ----------
log ""
log "==> 构建"
# 只构建 sing-box 本体：矩阵两端都用真实发行版，而不是 Go 侧的联调小工具。
# （v1 时代这里还会构建 cmd/ftdial 与 cmd/ftudp，但脚本从未调用它们，
#   Rust 参考实现里也没有对应 bin，属于白白的失败源，已删除。）
make build >/dev/null 2>&1 || {
	log "sing-box 构建失败"
	exit 1
}
SB=dist/sing-box-1.14.4-rev.1-linux-amd64
[[ -x "$SB" ]] || {
	log "找不到 $SB"
	exit 1
}
ok "sing-box 构建"

# ---------- 清理与退出处理 ----------
PIDS=()
cleanup() {
	for pid in "${PIDS[@]:-}"; do
		[[ -n "$pid" ]] && kill "$pid" 2>/dev/null
	done
	wait 2>/dev/null
}
trap cleanup EXIT

# ---------- 配置文件 ----------
cat >"$TMP/rust-server.yaml" <<EOF
listen: "0.0.0.0:$PORT"
password: "$PASSWORD"
tls:
  cert: "$PWD/ssl/fullchain.pem"
  key: "$PWD/ssl/privkey.pem"
site:
  dir: ""
faketcp:
  ip_id_magic: $IPID_MARK
  handshake: symbolic
net:
  mode: "none"
udp:
  enabled: true
  max_sessions: 64
  timeout_secs: 30
EOF

cat >"$TMP/rust-client.yaml" <<EOF
server: "$LOCAL_IP:$PORT"
password: "$PASSWORD"
sni: "example.com"
faketcp:
  source_port: $SRC_PORT
  handshake: symbolic
  ip_id_magic: $IPID_MARK
socks5:
  listen: "127.0.0.1:$SOCKS_PORT_RUST"
  username: "admin"
  password: "abcd1234"
https:
  listen: "127.0.0.1:18443"
  self_signed: true
net:
  mode: "none"
EOF

cat >"$TMP/go-server.json" <<EOF
{
  "log": { "level": "warn" },
  "inbounds": [
    { "type": "flowtls", "tag": "ft-in", "listen": "0.0.0.0", "listen_port": $PORT,
      "password": "$PASSWORD", "local_ip": "$LOCAL_IP", "ip_id_mark": $IPID_MARK,
      "iptables_mode": "none" }
  ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ]
}
EOF

cat >"$TMP/go-client.json" <<EOF
{
  "log": { "level": "warn" },
  "inbounds": [
    { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": $SOCKS_PORT_GO,
      "users": [ { "username": "admin", "password": "abcd1234" } ] }
  ],
  "outbounds": [
    { "type": "flowtls", "tag": "ft-out", "server": "$LOCAL_IP", "server_port": $PORT,
      "password": "$PASSWORD", "source_port": $SRC_PORT, "ip_id_mark": $IPID_MARK,
      "sni": "example.com", "iptables_mode": "none" }
  ]
}
EOF

"$SB" check -c "$TMP/go-server.json" >/dev/null 2>&1 &&
	ok "sing-box check（非 root 前置校验）" ||
	bad "sing-box check 失败"

# ---------- 断言工具 ----------
# 通过 SOCKS5 访问 https://example.com，断言 HTTP 200。
check_tcp() {
	local port=$1 name=$2 code
	code=$(curl -s --max-time 25 --socks5-hostname "127.0.0.1:$port" \
		--proxy-user admin:abcd1234 -o /dev/null -w '%{http_code}' https://example.com/ 2>/dev/null)
	if [[ "$code" == "200" ]]; then ok "$name TCP 200"; else bad "$name TCP 得到 $code"; fi
}

# UDP：SOCKS5 UDP ASSOCIATE + 真实 DNS 查询发给 8.8.8.8:53，断言 rcode=0。
check_udp() {
	local port=$1 name=$2
	if python3 - "$port" <<'PY'
import socket, struct, sys
port = int(sys.argv[1])
def dnsq(name=b'example.com'):
    q = b''.join(bytes([len(p)]) + p for p in name.split(b'.')) + b'\x00'
    return b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + q + b'\x00\x01\x00\x01'
s = socket.create_connection(('127.0.0.1', port), timeout=10)
s.sendall(b'\x05\x01\x02'); s.recv(2)
s.sendall(b'\x01' + bytes([5]) + b'admin' + bytes([8]) + b'abcd1234'); s.recv(2)
s.sendall(b'\x05\x03\x00\x01' + socket.inet_aton('0.0.0.0') + struct.pack('>H', 0))
r = s.recv(10)
relay = (socket.inet_ntoa(r[4:8]), struct.unpack('>H', r[8:10])[0])
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(6)
msg = b'\x00\x00\x00\x01' + socket.inet_aton('8.8.8.8') + struct.pack('>H', 53) + dnsq()
u.sendto(msg, relay)
d, _ = u.recvfrom(4096)
sys.exit(0 if (d[3] == 1 and len(d) > 20 and (d[13] & 0x0f) == 0) else 1)
PY
	then ok "$name UDP DNS 应答"; else bad "$name UDP 超时/异常"; fi
}

# ---------- 单元格 4：Go → Go（始终执行）----------
log ""
log "==> Go 客户端（sing-box） → Go 服务端（sing-box）"
"$SB" run -c "$TMP/go-server.json" >"$TMP/go-server.log" 2>&1 &
PIDS+=($!)
sleep 2
"$SB" run -c "$TMP/go-client.json" >"$TMP/go-client.log" 2>&1 &
PIDS+=($!)
sleep 3
check_tcp "$SOCKS_PORT_GO" "Go→Go"
check_udp "$SOCKS_PORT_GO" "Go→Go"
pkill -f "$SB run -c $TMP/go-client.json" 2>/dev/null
pkill -f "$SB run -c $TMP/go-server.json" 2>/dev/null
sleep 1

if [[ -z "$RUST_FLOWTLS" ]]; then
	log ""
	log "==> 含 Rust 的 3 格"
	skip "Rust→Rust（未设置 RUST_FLOWTLS）"
	skip "Rust→Go（未设置 RUST_FLOWTLS）"
	skip "Go→Rust（未设置 RUST_FLOWTLS）"
else
	# Rust 服务端需要真证书（它自己监听内核 TCP 跑伪装网站）。
	# 主分支已不再携带 ssl/，这里缺了就现生成一张自签的，仅供联调。
	RUST_CERT="$PWD/ssl/fullchain.pem"
	RUST_KEY="$PWD/ssl/privkey.pem"
	if [[ ! -f "$RUST_CERT" || ! -f "$RUST_KEY" ]]; then
		mkdir -p "$PWD/ssl"
		openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
			-nodes -days 2 -subj "/CN=example.com" \
			-keyout "$RUST_KEY" -out "$RUST_CERT" >/dev/null 2>&1 ||
			{
				log "生成联调证书失败"
				exit 1
			}
		log "已生成联调自签证书：$RUST_CERT"
	fi

	# ---------- 单元格 1：Rust → Rust ----------
	log ""
	log "==> Rust 客户端 → Rust 服务端"
	"$RUST_FLOWTLS" server -c "$TMP/rust-server.yaml" >"$TMP/rust-server.log" 2>&1 &
	PIDS+=($!)
	sleep 2
	"$RUST_FLOWTLS" client -c "$TMP/rust-client.yaml" >"$TMP/rust-client1.log" 2>&1 &
	PIDS+=($!)
	sleep 3
	check_tcp "$SOCKS_PORT_RUST" "Rust→Rust"
	check_udp "$SOCKS_PORT_RUST" "Rust→Rust"
	pkill -f "flowtls client -c $TMP/rust-client.yaml" 2>/dev/null
	pkill -f "flowtls server -c $TMP/rust-server.yaml" 2>/dev/null
	sleep 1

	# ---------- 单元格 2：Rust → Go ----------
	log ""
	log "==> Rust 客户端 → Go 服务端（sing-box）"
	"$SB" run -c "$TMP/go-server.json" >"$TMP/go-server2.log" 2>&1 &
	PIDS+=($!)
	sleep 2
	"$RUST_FLOWTLS" client -c "$TMP/rust-client.yaml" >"$TMP/rust-client2.log" 2>&1 &
	PIDS+=($!)
	sleep 3
	check_tcp "$SOCKS_PORT_RUST" "Rust→Go"
	check_udp "$SOCKS_PORT_RUST" "Rust→Go"
	pkill -f "flowtls client -c $TMP/rust-client.yaml" 2>/dev/null
	pkill -f "$SB run -c $TMP/go-server.json" 2>/dev/null
	sleep 1

	# ---------- 单元格 3：Go → Rust ----------
	log ""
	log "==> Go 客户端（sing-box） → Rust 服务端"
	"$RUST_FLOWTLS" server -c "$TMP/rust-server.yaml" >"$TMP/rust-server3.log" 2>&1 &
	PIDS+=($!)
	sleep 2
	"$SB" run -c "$TMP/go-client.json" >"$TMP/go-client3.log" 2>&1 &
	PIDS+=($!)
	sleep 3
	check_tcp "$SOCKS_PORT_GO" "Go→Rust"
	check_udp "$SOCKS_PORT_GO" "Go→Rust"
	pkill -f "$SB run -c $TMP/go-client.json" 2>/dev/null
	pkill -f "flowtls server -c $TMP/rust-server.yaml" 2>/dev/null
fi

# ---------- 汇总 ----------
log ""
log "=== 汇总：$PASS 通过 / $FAIL 失败 / $SKIP 跳过 ==="
log "日志目录：$TMP"
if [[ $FAIL -ne 0 ]]; then
	log "FAIL"
	exit 1
fi
log "PASS"
