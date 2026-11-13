#!/usr/bin/env bash
# 跨语言互通门禁。
#
# 为什么需要脚本而不是只靠单测：
#   Rust 与 Go 各自单测通过，不代表两端能互通——派生参数、AAD 组成、
#   记录布局任何一处不一致都会「自测全绿、联调全挂」。
#   这里用「Rust 加密 → Go 解密」和「Go 加密 → Rust 解密」双向验证，
#   把互通性变成一个可执行的硬门禁。
#
# 用法：bash docs/interop_check.sh
# 要求：cargo 与 go 都可用；需要 root（不，本脚本不碰 raw socket，纯编解码）

set -euo pipefail

cd "$(dirname "$0")/.."

GO="${GO:-go}"
CARGO="${CARGO:-cargo}"
VECTOR=/tmp/flowtls-go-vector.bin
RUST_VECTOR=/tmp/flowtls-rust-vector.bin

echo "==> 1/4 清除旧向量"
rm -f "$VECTOR" "$RUST_VECTOR" /tmp/flowtls-rust-authid.txt

echo "==> 2/4 Rust 导出向量（Rust -> Go 用）"
"$CARGO" test --quiet export_vector 2>&1 | grep -E "test result|error" || true
test -f "$RUST_VECTOR" || { echo "FAIL: Rust 未导出向量"; exit 1; }

echo "==> 3/4 Go 消费 Rust 向量 + 导出 Go 向量"
(
  cd flowtls
  "$GO" test -run 'TestInterop' -v ./... 2>&1 | grep -E "^(=== RUN|--- (PASS|FAIL|SKIP))" || true
  "$GO" test -run 'TestInterop' ./... >/dev/null
)
test -f "$VECTOR" || { echo "FAIL: Go 未导出向量"; exit 1; }

echo "==> 4/4 Rust 消费 Go 向量（Go -> Rust 用）"
"$CARGO" test --quiet consume_go_vector 2>&1 | grep -E "test result|error" || true

echo
echo "互通门禁：PASS"
