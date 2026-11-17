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
| **认证方式** | 见下方「单用户 vs 多用户」——选错会导致隧道完全建不起来 |
| 密码 | 单用户：服务端的全局 `password`；多用户：**你自己那个用户**的 password |
| 用户名 | 仅多用户时出现，**纯备注**，不会发送给服务端 |
| SNI | 只影响伪 ClientHello 外观，不参与校验 |
| 握手方式 | `symbolic`（默认，标准三次握手）/ `none` |
| 最大拥塞窗口 | 字节，默认 8 MB；跨境小带宽建议 1 MB，应与服务端一致 |
| UDP | 留空＝跟随核心默认（开启）；可显式开 / 关 |

### 单用户 vs 多用户（这是最容易配错的一项）

服务端有两种**互斥**的凭据形态（同时配置会直接报错）：

```jsonc
// 单用户
"password": "全局密码"

// 多用户（此时顶层 password 必须删掉）
"users": [
  { "name": "alice", "password": "alice-专属密码" },
  { "name": "bob",   "password": "bob-专属密码" }
]
```

客户端只需要填**一个密码**，但填哪个取决于服务端是哪种形态：

| 服务端形态 | 节点里的「认证方式」 | 密码填什么 |
|---|---|---|
| 单用户（只有 `password`） | 单用户（默认） | 那个全局 `password` |
| 多用户（只有 `users`） | 多用户 | `users[]` 里**你自己那条**的 `password` |

**多用户服务器上填全局密码是无效的**——服务端根本不登记它（没有对应的
authID），所以连不上，而且日志里不会有明显线索。这就是为什么界面要显式问
一次「你这台服务器是哪种」，而不是让一个「密码」框含糊地覆盖两种情况。

顺带说明：`ip_id_mark` 也从密码派生，所以两端密码必须完全一致，
只差一个字符就会让 IP ID 标记对不上，症状同样是「隧道完全不通」。

**多用户服务器怎么建节点**：一个节点对应一个用户。三个用户就建三个节点，
它们的地址/端口/SNI 完全相同，只有「密码」不同、可各自填「用户名」做区分。
这样在节点列表和分流规则里能一眼看出每条隧道属于谁。

## 命令

```sh
passwall-flowtls status      # 补丁是否完整（含自愈状态、节点命名状态）
passwall-flowtls apply       # 重新打补丁（升级 PassWall 之后），含节点修复
passwall-flowtls repair      # 只修 FlowTLS 节点的 section 名与 haproxy 引用
passwall-flowtls verify      # 只看结果，返回码 0/1，适合脚本
passwall-flowtls uninstall   # 还原 PassWall 官方行为
```

## 在节点列表里上下排序后会连不上（已修）

**现象**：在「节点列表」里调整顺序或者保存后，haproxy 控制台
（`http://路由器:1188/`）里 FlowTLS 那一栏的名字变成 `M1-cfgXXXXXX:`
（后半截是 section 名，带个空端口），后端一直 DOWN，通过 1181/1182
的流量全部失败。

**原因**：haproxy 的配置（`haproxy_config.lbss`）是按 **section 名**
记住「这个入口用哪个节点」的。而网页新建的节点在 `/etc/config/passwall`
里是**匿名** section（`config nodes` 后面没有名字），uci 给的
`cfgXXXXXX` 只是个临时名，**每次重写配置（排序、保存、改字段）都可能换一个**。
于是 `lbss` 存的那个名字变成死引用：haproxy 取不到节点，就把 section 名
当成服务器地址，端口变空 → 域名解析失败 → 后端永远 DOWN。

**修法**：`apply`（以及每 5 分钟的 cron 自愈）会把匿名 FlowTLS 节点改成
**固定名字**（例如 `flowtls_sg1`，取自备注，没备注就用地址），写进配置后
uci 不再重写它，之后无论怎么排序都不影响；同时把已经失效的 `lbss`
指回这个节点。

`status` 里的 `[节点] 已用固定 section 名` 就是这个修复已生效的标志。
若看到「有 N 个匿名节点」，执行一次 `passwall-flowtls apply` 即可。

> 只改 FlowTLS 自己的节点：其他协议的匿名节点不动，避免误伤用户
> 规则里对它们的引用。

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
- 源端口、IP ID 标记、防火墙规则**全部自动**，不需要也不应该手填。
  源端口每次建连由内核从动态端口段挑一个未在用的；IP ID 标记由密码派生，
  所以**改密码会同时换掉标记**（两端要一起改）。
- 组件更新的「检查更新」读的是 `releases/latest`，所以只能升到最新正式版，
  无法回退到旧版；要回退就手动 `to_move` 那套路径（或用 `--allow-untrusted`
  装一个自带内核的旧包）。
