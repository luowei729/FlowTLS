#!/usr/bin/env bash
# 防泄露门禁：确保被跟踪文件里没有真实公网 IP、证书私钥或部署凭据。
#
# 背景（DEVTIPS 第 119 条）：2026-11-15 发现三台服务器的公网 IP、内网地址、
# ip_id_mark、客户端源端口和伪装域名被明文写进 CHANGELOG / DEVTIPS / bench.sh
# 等文档，而仓库是 public。已用 git-filter-repo 全历史脱敏，本脚本负责「不再犯」。
#
# 用法：
#   bash docs/leak_check.sh
#   LEAK_DENYLIST="10.1.2.3 my.domain" bash docs/leak_check.sh   # 追加黑名单
#
# 设计原则：
#   - **不在本文件里硬编码任何真实地址**（那等于换个地方泄露）。需要额外
#     拉黑时用环境变量或 CI secret 传入。
#   - 用白名单而不是黑名单：除私有网段、RFC 5737 文档段、公共 DNS 和文档
#     占位地址之外，任何公网 IPv4 都算可疑——因为「没想到的那个 IP」才是
#     真正的漏网之鱼。
#   - 只看我们自己的文件：`sing-box/` 是上游子树，里面本来就有测试夹具
#     （example.org 私钥、chrome.pem 等）和大堆测试 IP。
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

fail=0
hit() { printf '  ✗ %s\n' "$*"; fail=1; }

echo "== 1/4 高危文件名 =="
# 部署配置与证书永远不该入库。.gitignore 只是第一道防线，
# 因为 `git add -f`、rename、或者换一台机器 clone 都可能绕过它。
bad=$(git ls-files | grep -vE '^sing-box/' | grep -iE \
  '(^|/)deploy/|(^|/)DEPLOY_CREDENTIALS\.md$|\.(pem|key|p12|pfx|jks|keystore)$|(^|/)\.env($|\.)|(^|/)id_(rsa|ed25519|ecdsa)$' || true)
if [ -n "$bad" ]; then
  while IFS= read -r f; do hit "敏感文件被跟踪: $f"; done <<< "$bad"
else
  echo "  ✓ 无"
fi

echo "== 2/4 私钥/证书内容 =="
# 注意：`git grep -I` 会把二进制文件当「无匹配」直接跳过，
# 用 `grep -a` 之类的组合扫描时才不会漏（DEVTIPS 第 119 条踩过这个坑）。
if git grep -lIE -- '-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----' -- . ':!sing-box' 2>/dev/null; then
  hit "包含私钥内容（见上）"
else
  echo "  ✓ 无"
fi

echo "== 3/4 公网 IPv4 =="
# 允许：回环 / 私网 / CGNAT / 链路本地 / 组播保留 / RFC 5737 文档段 /
#       RFC 2544 测试段 / 公共 DNS / 文档占位地址。
git grep -hoIE '([0-9]{1,3}\.){3}[0-9]{1,3}' -- . ':!sing-box' 2>/dev/null \
  | sort -u \
  | awk '
    BEGIN {
      # 公共 DNS 与文档占位：允许明文出现
      allow["1.1.1.1"]=1;   allow["1.0.0.1"]=1
      allow["8.8.8.8"]=1;   allow["8.8.4.4"]=1
      allow["9.9.9.9"]=1;   allow["4.4.4.4"]=1
      allow["223.5.5.5"]=1; allow["119.29.29.29"]=1
      allow["114.114.114.114"]=1
      allow["1.2.3.4"]=1;   allow["2.2.2.2"]=1
    }
    {
      ip=$0
      if (ip in allow) next
      split(ip, o, "."); a=o[1]; b=o[2]; c=o[3]; d=o[4]
      # 先剔掉非法写法，避免 999.1.1.1 之类被当成公网地址
      if (a>255 || b>255 || c>255 || d>255) next
      if (a==0 || a==10 || a==127) next          # 本机 / 私网
      if (a==100 && b>=64 && b<=127) next        # CGNAT
      if (a==169 && b==254) next                 # 链路本地
      if (a==172 && b>=16 && b<=31) next         # 私网
      if (a==192 && b==168) next                 # 私网
      if (a==192 && b==0 && c==2) next           # TEST-NET-1
      if (a==198 && b==51 && c==100) next        # TEST-NET-2
      if (a==203 && b==0 && c==113) next         # TEST-NET-3
      if (a==198 && (b==18 || b==19)) next       # RFC 2544
      if (a>=224) next                           # 组播 / 保留
      print ip
    }' > /tmp/leak_ips.$$
if [ -s /tmp/leak_ips.$$ ]; then
  while IFS= read -r ip; do hit "可疑公网 IPv4: $ip"; done < /tmp/leak_ips.$$
else
  echo "  ✓ 无"
fi
rm -f /tmp/leak_ips.$$

echo "== 4/4 额外黑名单（LEAK_DENYLIST） =="
# 真实的 IP / 域名放在 CI secret 里，不落进仓库。
if [ -n "${LEAK_DENYLIST:-}" ]; then
  found=0
  for pat in $LEAK_DENYLIST; do
    if git grep -qIF -- "$pat" -- . ':!sing-box' 2>/dev/null; then
      hit "命中黑名单: $pat"
      found=1
    fi
  done
  [ "$found" -eq 0 ] && echo "  ✓ 无"
else
  echo "  - 未设置（可在 CI 用 secret 传入真实 IP/域名）"
fi

echo
if [ "$fail" -ne 0 ]; then
  echo "✗ 泄露检查未通过：请把真实地址/凭据换成占位值"
  echo "  文档统一用 203.0.113.x / 198.51.100.x / 192.0.2.x 与 example.com"
  exit 1
fi
echo "✓ 泄露检查通过"
