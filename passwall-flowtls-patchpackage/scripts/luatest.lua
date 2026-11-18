-- 本地逻辑单测：不依赖 OpenWrt，只验补丁自身的语义。
-- 用法：lua scripts/luatest.lua <包根目录>
-- 覆盖三件事：
--   1) com.lua 补丁把更新源/版本命令/资产匹配改对了
--   2) gen_outbound 包装只对 flowtls 生效，其它协议零改动
--   3) 版本号在 PassWall 的 "[^v]+" 截断下仍能正确比较出「有更新」
local root = arg[1] or "."
local function load_mod(rel)
	local f, err = loadfile(root .. "/root/usr/lib/lua/luci/passwall/" .. rel)
	assert(f, err)
	local mod = f()
	assert(type(mod) == "function", rel .. " 应返回 function")
	return mod
end

local fails = 0
local function ok(cond, msg)
	if cond then
		print("  [通过] " .. msg)
	else
		fails = fails + 1
		print("  [失败] " .. msg)
	end
end

-- ---------------------------------------------------------------- 1) com 补丁
print("== com.lua 补丁 ==")
local patch_com = load_mod("flowtls_com.lua")

-- 复刻上游 com.lua 的最小结构
local _M = {
	order = { "geoview", "xray", "sing-box" },
	["sing-box"] = {
		name = "Sing-Box",
		repo = "SagerNet/sing-box",
		zipped = true,
		zipped_suffix = "tar.gz",
		default_path = "/usr/bin/sing-box",
		cmd_version = "version",
		match_fmt_str = "linux%%-%s",
		file_tree = { x86_64 = "amd64%-musl" },
		get_url = function(self)
			return "https://github.com/Openwrt-Passwall/openwrt-passwall-packages/"
		end,
	},
}

patch_com(_M)
local sb = _M["sing-box"]
ok(type(sb.get_url) == "function", "get_url 仍是函数（PassWall 用 : 调用）")
ok(tostring(sb.get_url(sb)):find("luowei729/FlowTLS", 1, true) ~= nil,
	"更新源已指向 FlowTLS Release")
ok(tostring(sb.get_url(sb)):find("releases/latest/download", 1, true) ~= nil,
	"用的是 releases/latest/download（地址稳定且能被 GitHub 代理加速）")
ok(sb.cmd_version:find("sed", 1, true) ~= nil, "cmd_version 已加去 v 处理")
ok(sb.file_tree.x86_64 == "amd64", "x86_64 映射为 amd64")
ok(sb.name == "Sing-Box" and sb.zipped == true and sb.zipped_suffix == "tar.gz",
	"其余官方字段未被破坏（解包/搬运路径仍沿用）")

-- 架构覆盖：PassWall 的 auto_get_arch 可能返回的键必须都在表里，
-- 否则会回落到官方 default_file_tree，正则匹配不到我们的资产。
local need = { "x86_64", "x86", "aarch64", "rockchip", "armv8", "armv7", "armv6",
	"armv5", "mips", "mips64", "mipsel", "mips64el", "riscv64" }
local missing = {}
for _, k in ipairs(need) do
	if sb.file_tree[k] == nil then missing[#missing + 1] = k end
end
ok(#missing == 0, "架构映射覆盖完整" .. (#missing > 0 and ("（缺 " .. table.concat(missing, ",") .. "）") or ""))

-- 资产名匹配：用真实发布过的文件名验证格式串
local assets = {
	"sing-box-1.14.4-rev.5-linux-amd64.tar.gz",
	"sing-box-1.14.4-rev.5-linux-arm64.tar.gz",
	"sing-box-1.14.4-rev.5-linux-386-softfloat.tar.gz",
	"sing-box-1.14.4-rev.5-linux-armv5.tar.gz",
	"sing-box-1.14.4-rev.5-linux-armv6.tar.gz",
	"sing-box-1.14.4-rev.5-linux-armv7.tar.gz",
	"sing-box-1.14.4-rev.5-linux-mips-softfloat.tar.gz",
	"sing-box-1.14.4-rev.5-linux-mipsle-softfloat.tar.gz",
	"sing-box-1.14.4-rev.5-linux-mips64-softfloat.tar.gz",
	"sing-box-1.14.4-rev.5-linux-mips64le-softfloat.tar.gz",
	"sing-box-1.14.4-rev.5-linux-riscv64.tar.gz",
}
for arch, frag in pairs(sb.file_tree) do
	local pat = string.format(sb.match_fmt_str, frag)
	local hit = nil
	for _, name in ipairs(assets) do
		if name:match(pat) then hit = name break end
	end
	if arch ~= "loongarch64" and arch ~= "ppc64le" and arch ~= "s390x" then
		ok(hit ~= nil, string.format("arch %-10s → 匹配到 %s", arch, tostring(hit)))
	end
end

-- ------------------------------------------------- 2) 版本比较（最关键的一条）
print("== 版本比较（PassWall 的 [^v]+ 截断）==")
-- 复刻 api.lua:compare_versions
local function compare_versions(ver1, comp, ver2)
	local function split(s)
		local t = {}
		for w in s:gmatch("[^%.%-]+") do t[#t + 1] = w end
		return t
	end
	local function part(v)
		local n = tonumber(v)
		if n then return n end
		local r = type(v) == "string" and v:match("^[rR](%d+)$")
		return tonumber(r) or 0
	end
	local av1, av2 = split(ver1), split(ver2)
	local max = math.max(#av1, #av2)
	for i = 1, max do
		local s1, s2 = part(av1[i] or 0), part(av2[i] or 0)
		if comp == "<" and s1 < s2 then return true end
		if s1 ~= s2 then return false end
	end
	return not (comp == "<")
end

-- 本机版本由 cmd_version 产出：把 -rev. 换成 -r
local local_ver = ("1.14.4-rev.5"):gsub("%-rev%.", "-r")
ok(local_ver == "1.14.4-r5", "本机版本被改写成 1.14.4-r5（无字母 v）")

local function remote(tag)
	-- CI 生成的元数据里 tag_name 就是 1.14.4-rN（同样不含字母 v）
	return tag
end
local function has_update(remote_tag)
	-- 与 api.lua:to_check 完全一致的表达式
	return compare_versions(local_ver:match("[^v]+"), "<", remote(remote_tag):match("[^v]+"))
end

ok(has_update("1.14.4-r5") == false, "同版本 → 无更新（不会误报）")
ok(has_update("1.14.4-r6") == true, "rev.5 → r6 → 检测到更新")
ok(has_update("1.14.5-r1") == true, "跨上游版本 → 检测到更新")
-- 反证：如果沿用官方那套 "v1.14.4-rev.6" 的 tag，截断后必然失效
local broken = compare_versions(("1.14.4-rev.5"):match("[^v]+"), "<", ("v1.14.4-rev.6"):match("[^v]+"))
ok(broken == false, "反证：官方 tag 形式在 [^v]+ 下确实检测不到更新（所以必须改写）")

-- ---------------------------------------------------------------- 3) UI 扩展
print("== 节点界面扩展 ==")
-- 用假的 CBI 环境跑 flowtls_fields.lua。
-- 重点回归的是「共享字段必须登记 flowtls」这一条：
-- 1_sing-box.lua 末尾用 protocol.keylist 逐个协议给 address/port/
-- domain_resolver/domain_strategy 挂 depends，那段循环在我们追加 flowtls
-- 之前就执行完了。漏登记的直接后果是「选了 FlowTLS 没有服务器地址可填」。
local made = {}
local function mkopt(map, section, option, title, desc)
	return {
		map = map, section = section, config_option = option,
		option = (section.option_prefix or "") .. option,
		title = title, desc = desc, depsset = {}, values = {},
		depends = function(self, d) self.depsset[#self.depsset + 1] = d end,
		value = function(self, v, label) self.values[#self.values + 1] = v end,
	}
end
_G.Value = function(...) local o = mkopt(...); made[#made + 1] = o; return o end
_G.ListValue = _G.Value

local function mksection()
	local sec = { fields = {}, children = {}, option_prefix = "singbox_" }
	function sec:option(class, name, title, desc)
		local o = mkopt(self.map, self, name, title, desc)
		made[#made + 1] = o
		self.fields[name] = o
		return o
	end
	return sec
end

local sec = mksection()
sec.map = {}
-- 复刻 1_sing-box.lua 里已存在的共享字段（已带各自协议的 depends）
local shared = { "address", "port", "domain_resolver", "domain_strategy", "password" }
for _, n in ipairs(shared) do
	local o = mkopt(sec.map, sec, n, n, "")
	o.depsset[1] = { protocol = "socks" }
	sec.fields[n] = o
end
-- protocol 下拉框
sec.fields["protocol"] = {
	keylist = { "socks", "http", "shadowsocks" },
	value = function(self, v) self.keylist[#self.keylist + 1] = v end,
}

local mod = loadfile(root .. "/root/usr/lib/lua/luci/passwall/flowtls_fields.lua")()
local ran, err = pcall(mod, sec.map, sec, sec)
ok(ran, "阶段调用不抛异常" .. (ran and "" or ("：" .. tostring(err))))

local function has_flowtls_dep(o)
	for _, d in ipairs(o.depsset or {}) do
		if d.protocol == "flowtls" then return true end
	end
	return false
end
for _, n in ipairs(shared) do
	ok(has_flowtls_dep(sec.fields[n]),
		string.format("共享字段 %s 已登记 flowtls 依赖（缺了就不渲染）", n))
end

local found = false
for _, v in ipairs(sec.fields["protocol"].keylist or {}) do
	if v == "flowtls" then found = true end
end
ok(found, "协议下拉框里已加入 FlowTLS")

-- 自定义字段里已经没有 source_port / ip_id_mark / iptables_mode
-- （三者都改为核心自动处理），剩下的字段都要挂 flowtls 依赖，
-- 否则选其它协议时会全部露出
local mine = { "sni", "handshake", "up_mbps", "down_mbps", "udp_enabled" }
for _, n in ipairs(mine) do
	local o = sec.fields[n]
	ok(o ~= nil and o.option == "singbox_" .. n,
		string.format("字段 %s 已创建且带 singbox_ 前缀", n))
	ok(o ~= nil and has_flowtls_dep(o),
		string.format("字段 %s 已挂 flowtls 依赖", n))
end

-- ------------------------------------------------- 认证方式（单用户 / 多用户）
print("== 认证方式 ==")
local mode = sec.fields["auth_mode"]
ok(mode ~= nil, "认证方式字段已创建")
if mode then
	-- 默认必须是单用户：多用户是少数情况，默认值要覆盖大多数部署
	ok(mode.default == "single",
		"认证方式默认 single（单用户，填全局密码），实际 " .. tostring(mode.default))
	local hasSingle, hasMulti = false, false
	for _, v in ipairs(mode.values or {}) do
		if v == "single" then hasSingle = true end
		if v == "multi" then hasMulti = true end
	end
	ok(hasSingle and hasMulti, "认证方式同时提供 single 与 multi 两个取值")
	ok(has_flowtls_dep(mode), "认证方式挂了 flowtls 依赖")
end

-- 用户名只在多用户模式下出现。
--
-- 这里要盯的是 **AND 条件必须并进同一个 depends 表**：
-- LuCI 的 depends 每条之间是 OR，写成两次 depends() 会变成
-- 「protocol=flowtls 或 auth_mode=multi」，于是选任何协议 + 多用户时
-- 这个字段都会跑出来。所以断言「只有一条依赖，且同时含两个键」。
local user = sec.fields["auth_user"]
ok(user ~= nil, "用户名字段已创建")
if user then
	local deps = user.depsset or {}
	ok(#deps == 1,
		string.format("user 应只有 1 条 depends（多条是 OR，会误显示），实际 %d 条", #deps))
	local d = deps[1] or {}
	ok(d.protocol == "flowtls" and d.auth_mode == "multi",
		"用户名依赖应为 {protocol=flowtls, auth_mode=multi}（同一表内 AND），实际 "
			.. tostring(d.protocol) .. "/" .. tostring(d.auth_mode))
end

-- ---------------------------------------------------------------- 4) 出站包装
print("== gen_outbound 包装 ==")
local wrap = load_mod("flowtls_outbound.lua")

-- 假的原始 gen_outbound：复刻 PassWall 行为（type = node.protocol）
local function fake_gen(flag, node, tag)
	if node.protocol == "hysteria2" then
		return { type = "hysteria2", tag = tag, server = node.address,
			server_port = tonumber(node.port), tls = { enabled = true } }
	end
	return { type = node.protocol, tag = tag, server = node.address,
		server_port = tonumber(node.port), tls = { enabled = true },
		multiplex = { enabled = true }, _id = "x", _flag = flag }
end
local gen = wrap(fake_gen)
ok(type(gen) == "function", "包装后仍是函数")

local flow = gen(nil, {
	protocol = "flowtls", address = "203.0.113.10", port = "8443",
	password = "pw", source_port = "44313", ip_id_mark = "61703",
	sni = "example.com", handshake = "symbolic", iptables_mode = "none",
	up_mbps = "200", down_mbps = "1000", udp_enabled = "",
}, "n1")
ok(flow.type == "flowtls", "type 保持 flowtls")
ok(flow.password == "pw", "password 已带出")
-- 源端口必须是自动分配：补丁不得再输出 source_port 字段。
-- 一旦 output 里又有它，两台机器经同一 NAT 去同一台服务端时就会四元组
-- 撞车、互相踢会话（真机踩过：haproxy 反复把 FlowTLS 后端标 DOWN）。
ok(flow.source_port == nil, "source_port 不再输出（交给内核自动分配）")
ok(flow.ip_id_mark == nil, "ip_id_mark 不再输出（从 password 派生）")
ok(flow.sni == "example.com" and flow.handshake == "symbolic", "sni/handshake 已带出")
ok(flow.iptables_mode == nil, "iptables_mode 不再输出（核心已强制写入规则）")
ok(flow.up_mbps == 200 and flow.down_mbps == 1000, "带宽已转成数字")
ok(flow.max_cwnd == nil, "max_cwnd 不再输出（Brutal 不读它）")
ok(flow.udp_enabled == nil, "udp_enabled 留空 → 不出字段（跟随核心默认）")
ok(flow.tls == nil and flow.multiplex == nil, "已清掉 tls/multiplex（flowtls 不认）")

local flow2 = gen(nil, { protocol = "flowtls", address = "192.0.2.1", port = "8443",
	password = "pw", udp_enabled = "0" }, "n2")
ok(flow2.udp_enabled == false, "udp_enabled=0 → 显式关闭")
local flow3 = gen(nil, { protocol = "flowtls", address = "192.0.2.1", port = "8443",
	password = "pw", udp_enabled = "1",
	-- 旧配置里可能还留着 source_port，包装器必须把它丢掉
	source_port = "44312", up_mbps = "" }, "n3")
ok(flow3.udp_enabled == true, "udp_enabled=1 → 显式开启")
ok(flow3.source_port == nil, "旧配置里的 source_port 已被清除")
ok(flow3.up_mbps == nil, "空串不产生 0 值字段")

-- 非 flowtls 必须逐字节等价
local other = gen(nil, { protocol = "hysteria2", address = "198.51.100.1", port = "443" }, "n4")
ok(other.type == "hysteria2" and other.tls ~= nil, "非 flowtls 节点原样返回")

print("")
if fails == 0 then
	print("全部通过")
	os.exit(0)
else
	print(string.format("失败 %d 项", fails))
	os.exit(1)
end
