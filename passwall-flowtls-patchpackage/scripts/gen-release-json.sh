#!/bin/sh
# 生成 PassWall「组件更新」要读取的元数据 JSON。
#
# 为什么需要它：
#   PassWall 检查 Sing-Box 更新时，会先去一个固定地址取 JSON，
#   里面要有 tag_name / assets[{name,browser_download_url,size,digest}]。
#   官方那份在 Openwrt-Passwall/openwrt-passwall-packages 的 api-cache 里，
#   我们改不了，所以每次发布时自己生成一份，随 Release 一起上传。
#
# 为什么用 releases/latest/download/ 这个地址：
#   - api.github.com 在国内经常不可达；
#   - github.com/.../releases/latest/download/<asset> 永远指向最新正式版，
#     地址稳定不变，而且能被 PassWall 自带的「GitHub 代理」加速；
#   - 每个 Release 自带一份描述自己的 JSON，发布新版本时自动切换。
#
# **tag_name 刻意不写字母 v**：
#   PassWall 的比较代码是
#       compare_versions(local:match("[^v]+"), "<", remote:match("[^v]+"))
#   "[^v]+" 在第一个 v 处截断，所以 "1.14.4-rev.5" → "1.14.4-re"，
#   rev.5 和 rev.6 会塌缩成同一个字符串，永远检测不到更新。
#   这里直接写成 OpenWrt 风格的 1.14.4-r5，两端都不含 v，比较才正确。
#
# 用法：
#   ./gen-release-json.sh --tag v1.14.4-rev.5 [--repo luowei729/FlowTLS] [--out FILE]
# 依赖 gh（已登录）与 jq。

set -eu

REPO='luowei729/FlowTLS'
TAG=''
OUT=''

while [ $# -gt 0 ]; do
	case "$1" in
		--repo) REPO=$2; shift 2 ;;
		--tag)  TAG=$2;  shift 2 ;;
		--out)  OUT=$2;  shift 2 ;;
		-h|--help) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*) echo "未知参数: $1" >&2; exit 1 ;;
	esac
done
[ -n "$TAG" ] || { echo '缺少 --tag' >&2; exit 1; }
[ -n "$OUT" ] || OUT='sing-box-release-api.json'

# v1.14.4-rev.5 → 1.14.4-r5
PWVER=$(printf '%s' "$TAG" | sed -E 's/^v?([0-9]+(\.[0-9]+)*)-rev\.([0-9]+)$/\1-r\3/')
case "$PWVER" in
	*v*) echo "tag 不符合 v<上游版本>-rev.N: $TAG" >&2; exit 1 ;;
esac

mkdir -p "$(dirname "$OUT")"

# gh api 直接给到 assets[].digest（形如 sha256:abcd…），
# PassWall 的 to_download 会拿它做完整性校验，缺了会直接拒绝下载。
gh api "repos/$REPO/releases/tags/$TAG" > /tmp/pw-release-$$.json || {
	echo "取 Release 失败：$TAG" >&2
	rm -f /tmp/pw-release-$$.json
	exit 1
}

jq --arg pwver "$PWVER" '{
	tag_name: $pwver,
	name: .name,
	flowtls_tag: .tag_name,
	html_url: .html_url,
	published_at: .published_at,
	assets: [ .assets[]
		| select(.name | test("\\.(tar\\.gz|zip)$"))
		| { name: .name, size: .size, digest: .digest, browser_download_url: .browser_download_url } ]
}' /tmp/pw-release-$$.json > "$OUT"
rm -f /tmp/pw-release-$$.json

# 硬断言：缺 digest 的资产在设备上一定下载失败（PassWall 先验签再解包）。
_missing=$(jq '[.assets[] | select(.digest == null or (.digest | startswith("sha256:")) | not)] | length' "$OUT")
if [ "$_missing" != "0" ]; then
	echo "生成的元数据里有 $_missing 个资产缺少 sha256 digest —— GitHub 只对较新的上传提供它" >&2
	exit 1
fi

_count=$(jq '.assets | length' "$OUT")
[ "$_count" -gt 0 ] || { echo '元数据里没有任何资产' >&2; exit 1; }

echo "已生成 $OUT（tag_name=$PWVER，资产 $_count 个）"
jq -r '.assets[] | "  \(.name)"' "$OUT"
