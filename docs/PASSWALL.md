# PassWall × FlowTLS 补丁包

装上这个包之后，**PassWall 的网页里就能直接做两件事**：

1. 「组件更新 → Sing-Box 版本 → 检查更新」会从**本项目的 Release** 下载内核，
   装完就是带 `with_flowtls` 的 `sing-box 1.14.4-rev.N`；
2. 「节点列表 → 添加节点」的协议下拉框里多一个 `FlowTLS`，
   选中后会显示源端口 / IP ID 标记 / SNI / 握手方式等 FlowTLS 专有字段。

包里**没有任何二进制**（纯 Lua + shell），所以是架构无关的单包，
内核由 PassWall 在线更新获取。这与「让 FlowTLS 内核随 PassWall 自动更新」
是同一件事的两个方向：内核来源换成我们的 Release，协议字段由本包补上。

## 为什么是「补丁包」而不是一个新插件

PassWall 已经有完整的节点管理、路由规则、DNS 分流、ACL、订阅等一整套能力。
自己再写一个 LuCI 插件，等于把那些全部重做一遍，而且用户要同时维护两个代理面板。

补丁包的定位是：**只补 PassWall 缺的那两块**，其余一律复用 PassWall。

## 安装

先导入公钥（apk 在解包**之前**验签，未签名的包在 LuCI 上传入口装不上）：

```sh
wget -O /etc/apk/keys/flowtls.pem \
  https://github.com/luowei729/FlowTLS/releases/latest/download/flowtls.pem
```

也可以在 LuCI 里导入：系统 → 管理权 →「软件包仓库公钥」
（`/cgi-bin/luci/admin/system/admin/repokeys`），粘贴 `flowtls.pem` 的内容。

然后安装：

```sh
# apk 系统（OpenWrt 24.10+ / ImmortalWrt 25.x）
apk add ./passwall-flowtls_<版本>_all.apk

# opkg 系统（22.03 / 23.05）
opkg install ./passwall-flowtls_<版本>_all.ipk
```

安装完成会自动打补丁，无需重启。

## 使用

**换成我们的内核**：PassWall → 组件更新 → `Sing-Box 版本` → 检查更新。
检测到更新后点一下，它会下载、解包、替换到 `/usr/bin/sing-box` 并重启 PassWall。

**添加 FlowTLS 节点**：节点列表 → 添加节点 → 类型 `Sing-Box` → 协议 `FlowTLS`，
然后填：

| 字段 | 说明 |
|---|---|
| 地址 / 端口 | 服务端的公网地址与 FlowTLS 监听端口（不要用 443，见 AGENTS） |
| 密码 | 与服务端 `password` 一致（外层 AEAD 的密钥来源） |
| 源端口 | **每个节点必须不同**。客户端防火墙靠它精确拦截内核回的 RST |
| IP ID 标记 | 与服务端 `ip_id_mark` 一致（十进制），每个部署应不同 |
| SNI | 只影响伪 ClientHello 外观，不参与校验 |
| 握手方式 | `symbolic`（默认，标准三次握手）/ `none` |
| 防火墙模式 | `auto`（推荐，自动写 nftables/iptables）/ `none` |
| 最大拥塞窗口 | 字节，默认 8 MB；跨境小带宽建议 1 MB，应与服务端一致 |
| UDP | 留空＝跟随核心默认（开启）；可显式开 / 关 |

## 命令

```sh
passwall-flowtls status      # 补丁是否完整（含自愈状态）
passwall-flowtls apply       # 重新打补丁（升级 PassWall 之后）
passwall-flowtls verify      # 只看结果，返回码 0/1，适合脚本
passwall-flowtls uninstall   # 还原 PassWall 官方行为
```

## PassWall 升级后会不会失效

**会自动恢复**，但理解原理有助于排障。

做法是把逻辑全部放在本包自己的文件里：

```
/usr/lib/lua/luci/passwall/flowtls_com.lua        ← 改「组件更新」的数据源
/usr/lib/lua/luci/passwall/flowtls_outbound.lua   ← 补 flowtls 出站字段
/usr/lib/lua/luci/passwall/flowtls_fields.lua     ← 补节点配置界面
```

PassWall 的三个文件里只插入 5 行调用（带 `FLOWTLS-PATCH` 标记），
它们**只负责调上面那三个文件**。PassWall 升级会覆盖自己的文件、
把调用点冲掉，于是：

- 每 5 分钟一次 cron 自愈（`/etc/crontabs/root` 里带 `# passwall-flowtls` 标记）；
- 每次 WAN 上线（hotplug `ifup`）也会检查一次；
- 也可以随时手动 `passwall-flowtls apply`。

补丁内容没变化时**一个字节都不写盘**（先 `awk` 生成到临时文件再 `cmp`），
所以 cron 一年下来也不会磨损 flash。

PassWall 如果改了我们的锚点，`apply` 会**明确报出哪个文件找不到锚点**并跳过，
而不是静默写坏文件——那种情况下逻辑会停用，但 PassWall 本身仍然正常工作。

## 卸载

```sh
apk del passwall-flowtls     # 或 opkg remove passwall-flowtls
```

`pre-deinstall` 会先把三个文件还原成上游原文（按字节，`uninstall` 后与官方包
完全一致），再删本包文件、清 cron。

## 已知限制

- **不要用 443 端口**：国内出口设备对 443 的伪造 TCP 检查更严，建议 8443 / 9443。
- 只支持 IPv4。
- 同一台机器上多个 FlowTLS 节点必须用**不同的 `源端口`**，否则第二条隧道
  会抢第一条的防火墙规则。
- `防火墙模式 = none` 时内核不会写 any 规则。如果设备上同时有其它代理
  （PassWall 自己的节点、OpenClash 等），它们的 NAT 劫持会接管我们的伪 TCP
  流量——**那会导致两次跨境回环**。除非你确知自己在做什么，请保持 `auto`。
- 组件更新的「检查更新」读的是 `releases/latest`，所以只能升到最新正式版，
  无法回退到旧版；要回退就手动 `to_move` 那套路径（或用 `--allow-untrusted`
  装一个自带内核的旧包）。
