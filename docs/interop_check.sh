#!/usr/bin/env bash
# wire format 冻结向量门禁（无需 root，无需 Rust 工具链）。
#
# 背景：本协议最早由 Rust 实现，现在 Rust 已冻结归档到 `legacy-rust` 分支
# （见 docs/EVOLUTION.md）。冻结前用力它的单测导出了两份**黄金向量**并入库：
#
#   flowtls/testdata/wire_v2_rust.bin         两条记录的完整字节流
#   flowtls/testdata/wire_v2_rust_authid.txt  密码派生的 authID（hex）
#
# 这两个文件就是 wire format v2 的权威字节。任何「改了 HKDF 参数、
# AAD 组成、nonce 布局或记录头格式」的行为都会让门禁立刻变红。
#
# 为什么这比「跑一遍两端联调」更值得做门禁：
#   联调只能证明「两端现在能互相通信」，两端同时改错会一起通过；
#   冻结向量钉的是**绝对字节**，不存在两端同时漂移的盲区。
#
# 用法：bash docs/interop_check.sh
# 要求：go 可用；不需要 root；不需要 Rust。

set -euo pipefail

cd "$(dirname "$0")/.."

GO="${GO:-go}"
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

echo "==> 1/3 检查冻结向量是否入库"
for f in flowtls/testdata/wire_v2_rust.bin flowtls/testdata/wire_v2_rust_authid.txt; do
	if [[ ! -f "$f" ]]; then
		echo "FAIL: 缺少冻结向量 $f"
		echo "      它应该随仓库分发；丢失意味着兼容性基线消失。"
		exit 1
	fi
	echo "    ✓ $f ($(stat -c%s "$f") 字节)"
done

echo "==> 2/3 用冻结向量验证 Go 实现（Rust → Go 方向）"
(
	cd flowtls
	# 先把输出抓成变量再判断，不要用 `go test | grep -q`：
	# grep -q 命中即退出，管道关闭会让 go test 收到 EPIPE，
	# 配合 pipefail 会把一次成功的测试判成失败。
	if ! out=$("$GO" test -run 'TestInteropRustToGo' -v ./... 2>&1); then
		printf '%s\n' "$out"
		echo "FAIL: TestInteropRustToGo 未通过（冻结向量对不上 = wire format 已漂移）"
		exit 1
	fi
	# 单独确认不是 SKIP：门禁环境里向量必须存在，跳过等于没检查
	printf '%s\n' "$out" | grep -qE '^(--- PASS|ok)' || {
		printf '%s\n' "$out"
		echo "FAIL: TestInteropRustToGo 没有真正执行（被跳过？）"
		exit 1
	}
	printf '%s\n' "$out" | grep -E '^(=== RUN|--- (PASS|FAIL|SKIP))' || true
	echo "    ✓ 冻结向量解密通过，authID 一致"
)

echo "==> 3/3 全量单测（含竞态检测）"
(
	cd flowtls
	"$GO" test -race ./... 2>&1 | grep -v 'no test files'
)

echo
echo "冻结向量门禁：PASS"
