-- FlowTLS × PassWall —— 组件更新源改写
--
-- 本文件由 /usr/bin/passwall-flowtls apply 注入到 com.lua 的调用点执行：
--     local _ok, _f = pcall(dofile, "<本文件>")
--     if _ok and type(_f) == "function" then _f(_M) end
--
-- 设计原则（这是整个补丁包的核心约束）：
--   **逻辑全部住在本文件里，PassWall 的源码里只留 5 行调用。**
--   PassWall 升级会覆盖 com.lua / util_sing-box.lua / 1_sing-box.lua，
--   但永远不会动本文件（那是我们自己包的路径），
--   所以升级后只要重跑一次 apply 就能恢复，且恢复的是最新逻辑。
--
-- 为什么必须改 com.lua 而不是别处：
--   PassWall「组件更新」的远程地址来自 com[k]:get_url()，
--   它写死了 Openwrt-Passwall/openwrt-passwall-packages 的 api-cache，
--   没有任何 uci 配置能改它。要换成我们的 Release 只能覆盖这张表。

-- 我们自己的 Release 元数据（由 CI 在发布时上传到同一个 Release 里）。
--
-- 为什么不用 api.github.com：
--   国内直连 api.github.com 经常不可达，而 releases/latest/download/ 走的是
--   github.com 的下载域名，可以被 PassWall 自带的「GitHub 代理」加速。
--   releases/latest 永远指向最新的正式版，所以这个 URL 是稳定不变的。
local META_URL = "https://github.com/luowei729/FlowTLS/releases/latest/download/sing-box-release-api.json"

-- 架构名 → 我们 Release 资产名里的平台片段
--
-- 我们的资产名形如：
--   sing-box-1.14.4-rev.5-linux-amd64.tar.gz
--   sing-box-1.14.4-rev.5-linux-mipsle-softfloat.tar.gz
-- 而 PassWall 用 match_fmt_str 把它和架构拼成正则去匹配资产名，
-- 所以 match_fmt_str 固定为 "linux%%-%s"，这里只填 %s 那一段。
--
-- **键必须覆盖 PassWall 的 auto_get_arch() 全部返回值**：
-- 漏掉的键会回落到 PassWall 自带的 default_file_tree（amd64/386/mipsel…），
-- 拼出来的正则匹配不到我们的资产，界面就报
-- 「New version found, but failed to get new version download url.」
local FILE_TREE = {
	x86_64   = "amd64",
	x86      = "386",
	aarch64  = "arm64",
	rockchip = "arm64",
	armv8    = "arm64",
	armv7    = "armv7",
	armv6    = "armv6",
	armv5    = "armv5",
	-- mips 家族：我们同时出 hardfloat / softfloat 两个变体，
	-- 统一选 softfloat —— 它能在硬浮点机器上跑，反之不行。
	mips     = "mips%-softfloat",
	mips64   = "mips64%-softfloat",
	mipsel   = "mipsle%-softfloat",
	mips64el = "mips64le%-softfloat",
	riscv64  = "riscv64",
	-- 上游 PassWall 没列这两个键；补上只是让它别报「无法判断架构」，
	-- 真机请以实际资产为准。
	loongarch64 = "loong64",
	ppc64le     = "ppc64le",
	s390x       = "s390x",
}

-- 版本号改写：让 PassWall 的版本比较能正确处理我们的 -rev.N
--
-- PassWall 的比较表达式是
--     compare_versions(local_version:match("[^v]+"), "<", remote_version:match("[^v]+"))
-- 注意那个 "[^v]+"：它在第一个字母 v 处截断。
-- 我们的版本号是 1.14.4-rev.5，截断后变成 "1.14.4-re"，rev.5 和 rev.6
-- 都塌缩成同一个字符串，于是**永远检测不到更新**。
-- 所以两边都要去 v 化：
--   本机二进制 → "version | sed 's/-rev\./-r/'" 得到 1.14.4-r5
--   远程元数据 → tag_name 直接写成 1.14.4-r6（见 CI 的 gen-release-json.sh）
local CMD_VERSION = 'version | sed "s/-rev\\./-r/"'

return function(_M)
	if type(_M) ~= "table" then
		return
	end
	local sb = _M["sing-box"]
	if type(sb) ~= "table" then
		-- PassWall 换了内部结构（或这是更老的版本）：什么都不改，
		-- 让它保持官方行为，比改坏强。verify 子命令会报这一条。
		return
	end

	-- 更新源换成我们的 Release 元数据
	sb.get_url = function()
		return META_URL
	end

	-- 让本机版本号进入 "-rN" 形式，配合上面的 tag_name 一起去掉字母 v。
	-- 这个字段原本是 "version"（直接跑 sing-box version），
	-- 追加一个 sed 不改变它打印版本号的能力，只是把 -rev. 换成 -r。
	sb.cmd_version = CMD_VERSION

	-- 资产名匹配：从 "linux-<musl 变体>" 改成 "linux-<平台>"
	sb.match_fmt_str = "linux%%-%s"
	sb.file_tree = FILE_TREE

	-- 保留官方其余字段（name / repo / zipped / zipped_suffix / default_path），
	-- 它们描述的是「解包后怎么搬到目标路径」，我们完全沿用：
	--   zipped_suffix = "tar.gz"，解包后是 <目录>/sing-box，
	--   PassWall 会把它 mv 到 /usr/bin/sing-box。
end
