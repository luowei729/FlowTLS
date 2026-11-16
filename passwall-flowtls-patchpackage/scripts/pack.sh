#!/bin/sh
# 把 FlowTLS × PassWall 补丁包打成 .ipk 与 .apk（架构无关，单包）。
#
# 为什么是「架构无关」的单包：
#   本包里**没有任何二进制**——只有 Lua 脚本和 shell 脚本。
#   FlowTLS 内核由 PassWall 的「组件更新」在线下载（见 flowtls_com.lua），
#   所以一个包就能装到所有架构上。这也避免了「装错架构」的那类事故。
#
# 用法：
#   ./scripts/pack.sh                          # 版本号取自仓库根的 VERSION
#   ./scripts/pack.sh --version 1.14.4-r5 --out out
#   ./scripts/pack.sh --apk-tool /path/to/apk --sign-key ../deploy/apk-signing.key
#
#   --apk-tool   apk 可执行文件；省略则跳过 .apk（只出 .ipk）
#   --sign-key   apk 签名私钥（PEM RSA）；省略则出未签名包
#
# 关于签名（装不上时先查这一条）：
#   apk 在解包之前验签，未签名的包只能 `apk add --allow-untrusted`。
#   而 LuCI 的「上传安装包」入口不传这个参数，所以未签名包在网页上 100% 失败
#   （ERROR: ... UNTRUSTED signature，退出码 99）。

set -eu

PKGNAME='passwall-flowtls'
APP_DIR=$(cd "$(dirname "$0")/.." && pwd)
REPO_DIR=$(cd "$APP_DIR/.." && pwd)

VERSION=''
OUT=''
APK_TOOL=''
SIGN_KEY=''
ARCH='all'

usage() {
	sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
	exit "${1:-1}"
}

while [ $# -gt 0 ]; do
	case "$1" in
		--version)  VERSION=$2; shift 2 ;;
		--out)      OUT=$2; shift 2 ;;
		--apk-tool) APK_TOOL=$2; shift 2 ;;
		--sign-key) SIGN_KEY=$2; shift 2 ;;
		-h|--help)  usage 0 ;;
		*) echo "未知参数: $1" >&2; usage 1 ;;
	esac
done

# 版本号唯一真源是仓库根的 VERSION（AGENTS 约束：Makefile + VERSION）。
[ -n "$VERSION" ] || VERSION=$(cat "$REPO_DIR/VERSION" 2>/dev/null || true)
[ -n "$VERSION" ] || { echo '缺少 --version 且读不到 VERSION' >&2; exit 1; }
[ -n "$OUT" ] || OUT="$APP_DIR/dist"

# 绝对路径化：下面会 cd 进临时目录，相对路径在那里指向别处
OUT=$(cd "$OUT" 2>/dev/null && pwd || { mkdir -p "$OUT" && cd "$OUT" && pwd; })
[ -n "$APK_TOOL" ] && [ -x "$APK_TOOL" ] && APK_TOOL=$(cd "$(dirname "$APK_TOOL")" && pwd)/$(basename "$APK_TOOL")
[ -n "$SIGN_KEY" ] && {
	# 相对路径按「当前目录」找不到时，再按「仓库根」找一次。
	# make passwall 会先 cd 进本包目录，此时用户写的 deploy/xxx.key
	# 实际在上一级；不兜这一下就是莫名其妙的「私钥不存在」。
	[ -f "$SIGN_KEY" ] || [ ! -f "$REPO_DIR/$SIGN_KEY" ] || SIGN_KEY="$REPO_DIR/$SIGN_KEY"
	[ -f "$SIGN_KEY" ] || { echo "签名私钥不存在: $SIGN_KEY" >&2; exit 1; }
	SIGN_KEY=$(cd "$(dirname "$SIGN_KEY")" && pwd)/$(basename "$SIGN_KEY")
}

# 1.14.4-rev.5 → 1.14.4-r5。
# apk 的版本号语法不接受 "rev."，而 -rN 正是 OpenWrt 表达
# 「同一上游版本的第 N 次打包」的原生写法，语义与我们的 -rev.N 完全一致。
PKGVER=$(printf '%s' "$VERSION" | sed -E 's/^([0-9]+(\.[0-9]+)*)-rev\.([0-9]+)$/\1-r\3/')
case "$PKGVER" in
	*rev*) echo "版本号不符合 <上游版本>-rev.N: $VERSION" >&2; exit 1 ;;
esac

WORK=$(mktemp -d "${TMPDIR:-/tmp}/$PKGNAME.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM

# apk3 认的「任意架构」是 noarch，不是 all（写 all 会 uninstallable）。
case "$ARCH" in
	all|'') APK_ARCH='noarch' ;;
	*)      APK_ARCH=$ARCH ;;
esac

# ---------------------------------------------------------------- 文件树
mkdir -p "$WORK/root"
cp -R "$APP_DIR/root/." "$WORK/root/"

# 权限统一：目录 755、文件 644，脚本再单独 755。
# cp -R 会带上开发机的 umask，而 OpenWrt 上 644 的脚本等于装了个跑不起来的工具。
find "$WORK/root" -type d -exec chmod 755 {} +
find "$WORK/root" -type f -exec chmod 644 {} +
chmod 755 "$WORK/root/usr/bin/passwall-flowtls"
chmod 755 "$WORK/root/etc/uci-defaults/95-passwall-flowtls"
chmod 755 "$WORK/root/etc/hotplug.d/iface/99-passwall-flowtls"

SIZE_KB=$(du -sk "$WORK/root" | awk '{ print $1 }')
mkdir -p "$OUT"

# 产物完整性断言：每一条都是「缺了功能就不可用」的文件。
# 这类错误不会让打包失败，只会在用户点开网页时才暴露，只能用断言兜住。
for must in \
	usr/bin/passwall-flowtls \
	usr/lib/lua/luci/passwall/flowtls_com.lua \
	usr/lib/lua/luci/passwall/flowtls_outbound.lua \
	usr/lib/lua/luci/passwall/flowtls_fields.lua \
	etc/uci-defaults/95-passwall-flowtls \
	etc/hotplug.d/iface/99-passwall-flowtls
do
	[ -f "$WORK/root/$must" ] || { echo "打包失败：缺少 $must" >&2; exit 1; }
done

# 断言「包里没有内核」：本包的定位就是不含内核，一旦误加了二进制，
# 架构无关的前提就不成立，而包本身仍然能装 —— 只能在这里拦住。
if find "$WORK/root" -type f -size +1M | grep -q .; then
	echo '打包失败：包里出现了大于 1MB 的文件（本包不应该含任何二进制）' >&2
	find "$WORK/root" -type f -size +1M >&2
	exit 1
fi

# ---------------------------------------------------------------- 安装脚本
mkdir -p "$WORK/scripts"

# 装完立刻打补丁。PassWall 不存在时 apply 会自己跳过，不会报错。
cat > "$WORK/scripts/post-install" <<'EOF'
#!/bin/sh
# 升级安装时 IPKG_INSTROOT 指向临时根目录，此刻不能动宿主机
[ -n "${IPKG_INSTROOT:-}" ] && exit 0

/usr/bin/passwall-flowtls apply --quiet 2>/dev/null

# 清 LuCI 缓存：node_config 的类型文件列表是每次请求现扫目录，
# 但已被 require 过的 Lua 模块会缓存在 /tmp，清掉更保险。
rm -f /tmp/luci-indexcache* 2>/dev/null
rm -rf /tmp/luci-modulecache/* 2>/dev/null
exit 0
EOF

# 卸载前先把 PassWall 的文件还原。
# 必须在删除本包文件**之前**跑，否则 flowtls_*.lua 已经没了，
# 注入点却还留在 PassWall 里（每次开节点页都会 dofile 失败，静默但脏）。
cat > "$WORK/scripts/pre-deinstall" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
[ -x /usr/bin/passwall-flowtls ] && /usr/bin/passwall-flowtls uninstall --quiet 2>/dev/null
exit 0
EOF

chmod 755 "$WORK/scripts/post-install" "$WORK/scripts/pre-deinstall"

# ---------------------------------------------------------------- ipk
mkdir -p "$WORK/ipk"
cat > "$WORK/ipk/control" <<EOF
Package: $PKGNAME
Version: $PKGVER
Depends: libc, luci-base, luci-app-passwall
Source: https://github.com/luowei729/FlowTLS
SourceName: $PKGNAME
License: GPL-3.0-only
Section: luci
Section-Priority: 40
Architecture: $ARCH
Installed-Size: $SIZE_KB
Maintainer: luowei729 <1084605775@qq.com>
Description: FlowTLS patch for PassWall (core update source + FlowTLS node protocol)
EOF
cp "$WORK/scripts/post-install" "$WORK/ipk/postinst"
cp "$WORK/scripts/pre-deinstall" "$WORK/ipk/prerm"
chmod 755 "$WORK/ipk/postinst" "$WORK/ipk/prerm"

IPK="$OUT/${PKGNAME}_${PKGVER}_all.ipk"
tar -C "$WORK/ipk" -cf - ./control ./postinst ./prerm | gzip -9n > "$WORK/control.tar.gz"
tar -C "$WORK/root" -cf - . | gzip -9n > "$WORK/data.tar.gz"
printf '2.0\n' > "$WORK/debian-binary"
( cd "$WORK" && ar rc "$IPK" debian-binary control.tar.gz data.tar.gz )
echo "ipk: $IPK"

# ---------------------------------------------------------------- apk
if [ -z "$APK_TOOL" ]; then
	echo "apk: 跳过（没有 --apk-tool；OpenWrt SDK 里在 staging_dir/host/bin/apk）"
	exit 0
fi

APK="$OUT/${PKGNAME}_${PKGVER}_all.apk"
_SIGN_ARGS=''
if [ -n "$SIGN_KEY" ]; then
	_SIGN_ARGS='--sign-key'
else
	echo '警告：未签名 —— 命令行需要 apk add --allow-untrusted，LuCI 上传安装会失败' >&2
fi

# shellcheck disable=SC2086
"$APK_TOOL" mkpkg \
	--info "name:$PKGNAME" \
	--info "version:$PKGVER" \
	--info "arch:$APK_ARCH" \
	--info 'description:FlowTLS patch for PassWall (core update source + FlowTLS node protocol)' \
	--info 'license:GPL-3.0-only' \
	--info 'maintainer:luowei729 <1084605775@qq.com>' \
	--info 'url:https://github.com/luowei729/FlowTLS' \
	--info "origin:$PKGNAME" \
	--info 'depends:luci-base luci-app-passwall' \
	--files "$WORK/root" \
	--script "post-install:$WORK/scripts/post-install" \
	--script "pre-deinstall:$WORK/scripts/pre-deinstall" \
	$_SIGN_ARGS "$SIGN_KEY" \
	--output "$APK"
echo "apk: $APK"

# 公钥随产物发布：用户装公钥的那条命令可以直接指向 Release 附件。
if [ -n "$SIGN_KEY" ] && [ -f "$APP_DIR/keys/flowtls.pem" ]; then
	cp "$APP_DIR/keys/flowtls.pem" "$OUT/flowtls.pem"
	# 自检：用刚打的包 + 公钥验一次 —— 比「打成功了」值钱得多。
	# --keys-dir 必须绝对路径，相对路径会静默失效。
	if "$APK_TOOL" verify --keys-dir "$APP_DIR/keys" "$APK" >/dev/null 2>&1; then
		echo "apk: 签名验证通过（公钥随包发布：flowtls.pem）"
	else
		echo '打包失败：apk 签名验证未通过' >&2
		exit 1
	fi
fi

# 硬断言：arch 必须是 apk3 认识的值。
# 「包没坏但装不上」最贵的一次就是 arch: all → error: uninstallable。
_got_arch=$("$APK_TOOL" adbdump "$APK" 2>/dev/null | sed -n 's/^  arch: //p' | head -n 1)
if [ "$_got_arch" != "$APK_ARCH" ]; then
	echo "打包失败：apk 的 arch 是 '$_got_arch'，应为 '$APK_ARCH'" >&2
	exit 1
fi
echo "apk: arch=$APK_ARCH"
