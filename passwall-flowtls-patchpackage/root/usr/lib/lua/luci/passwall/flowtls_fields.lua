-- FlowTLS × PassWall —— 节点配置界面扩展
--
-- 本文件由 passwall-flowtls apply 注入到
--   /usr/lib/lua/luci/model/cbi/passwall/client/type/1_sing-box.lua
-- 调用点用 loadfile + setfenv(getfenv(1)) 加载，所以本文件里的全局名
-- （translate / Value / ListValue …）继承的是 PassWall 自己的环境。
-- **不能用 dofile**：dofile 恒定用 _G，而 translate 不在 _G 里，
-- 症状是「协议能选 FlowTLS，但下面的端口/SNI 等字段一个都不出现」。
--     local _ok, _f = pcall(dofile, "<本文件>")
--     if _ok and type(_f) == "function" then _f(m, s, s1) end
--
-- 为什么必须插在 type_cbi_section 之前：
--   那个函数把临时 section s 里的控件搬到真正的 section s1，
--   之后再 s:option(...) 加进来的控件会挂在已经搬空的临时 section 上，
--   页面上根本不会出现（症状是「填了保存不了，刷新就没了」）。
--
-- 为什么新增协议而不是新增一个独立 type：
--   FlowTLS 就是一个 sing-box 出站，走 PassWall 的 sing-box 主实例最省资源
--   （不额外起进程、不额外占端口）。独立 type 会被 PassWall 当成
--   「另一个客户端程序」，要走 app.sh 的 run_socks 分支，成本高得多。
--
-- 失败必须留痕：
--   注入点的 pcall 会吞掉所有异常，而「界面少几个字段」本身不报错，
--   只会表现为「协议选 FlowTLS 后没有端口/口令可填」。所以这里自己再包
--   一层 xpcall，把错误连同调用栈写进 /tmp 与 syslog。
--   同时保证**无论如何都不影响其它协议的正常使用**。

local ERR_FILE = "/tmp/passwall-flowtls-ui.err"

local function report(err)
	local msg = "FlowTLS 节点界面扩展失败：" .. tostring(err)
	pcall(function()
		local f = io.open(ERR_FILE, "w")
		if f then
			f:write(msg, "\n")
			f:close()
		end
	end)
	pcall(function()
		local sys = require "luci.sys"
		sys.call("logger -t passwall-flowtls " .. string.format("%q", msg))
	end)
end

local function build(m, s, s1)
	if type(s) ~= "table" or type(s.fields) ~= "table" then
		return
	end

	-- translate 的兜底兼容：正常路径下它来自 PassWall 的环境，
	-- 万一将来环境变了也不会整个扩展挂掉（只丢翻译，不丢字段）。
	local tr = _G.translate
	if type(tr) ~= "function" then
		local ok, i18n = pcall(require, "luci.i18n")
		tr = (ok and type(i18n.translate) == "function") and i18n.translate
			or function(text) return text end
	end

	-- protocol 列表由 1_sing-box.lua 创建，我们只是追加一个取值。
	local proto = s.fields["protocol"]
	if not proto then
		return
	end
	proto:value("flowtls", "FlowTLS")

	-- 共享字段必须手动登记 flowtls，否则页面上就不存在「地址」和「端口」。
	--
	-- 原因：1_sing-box.lua 末尾有一段循环，拿 protocol 的 keylist 逐个
	-- 给 address / port / domain_resolver / domain_strategy 挂
	-- depends({protocol=v})：
	--     local protocols = s.fields["protocol"].keylist
	--     for _, v in ipairs(protocols) do ... s.fields["address"]:depends(...) end
	-- 那段循环在我们追加 flowtls **之前**就跑完了，所以流着 flowtls 时
	-- 这四个字段一个 depends 都不命中，被判定成一整行不渲染。
	-- 现象就是「选了 FlowTLS 后没有服务器地址/端口可填」，而密码能填
	-- （密码有单独一行 depends，我们已经补过）。
	--
	-- 同样给 password 补一条（其余协议都靠各自 type 文件里逐行 depends）。
	for _, name in ipairs({ "address", "port", "domain_resolver",
		"domain_strategy", "password" }) do
		local f = s.fields[name]
		if f and type(f.depends) == "function" then
			f:depends({ protocol = "flowtls" })
		end
	end

	-- 统一构造：默认挂 depends({protocol="flowtls"})，选别的协议时自动隐藏。
	--
	-- extra 是**额外条件**，会并进**同一个** depends 表（因此是 AND）。
	-- 千万不要在 opt() 之后再调一次 o:depends(...)——LuCI 的 depends
	-- 每条是 OR 关系，那样写会变成「protocol=flowtls **或** 其它条件」，
	-- 结果是选别的协议时该字段也冒出来。
	local function opt(class, name, title, desc, extra)
		local o = s:option(class, name, title, desc)
		if o then
			local cond = { protocol = "flowtls" }
			if type(extra) == "table" then
				for k, v in pairs(extra) do
					cond[k] = v
				end
			end
			o:depends(cond)
		end
		return o
	end

	-- 认证方式 --------------------------------------------------------------
	-- 这一项**不改变生成的配置**（客户端永远只需要一个 password），
	-- 解决的是「多用户服务器的第一条隧道连不上」这个高频误配：
	--
	-- 服务端有两种互斥的凭据形态（同填会直接报错）：
	--   单用户：顶层 password
	--   多用户：users[] 里每个用户各自的 password
	--
	-- 而客户端只填一个「密码」。如果服务端开了多用户，填顶层那个
	-- 全局密码是**无效的**（服务端根本不登记它）——但界面上的
	-- 「密码」字段说明写的是「与服务端 password 一致」，于是必然踩坑。
	-- 症状是隧道完全建不起来，且没有任何明显的错误提示。
	--
	-- 所以这里把「你这台服务器是哪种」显式问出来，让下面的密码说明
	-- 跟着变。默认单用户（最常见）。
	local o = opt(ListValue, "auth_mode", tr("认证方式"),
		tr("单用户服务器：密码填服务端的全局 password。"
			.. "多用户服务器：密码填 users[] 里**你自己那个用户**的 password"
			.. "（服务端的全局 password 在多用户模式下不生效）。"))
	if o then
		o.default = "single"
		o:value("single", tr("单用户（全局密码）"))
		o:value("multi", tr("多用户（用户密码）"))
	end

	-- 用户名（仅多用户时出现）----------------------------------------------
	-- **纯备注**，不参与任何生成逻辑：线上只传 password 派生出的 authID，
	-- 用户名从不发送（服务端的 name 也只用于它自己的日志）。
	-- 加它是因为多用户服务器上通常有好几个节点（一人一个），
	-- 没有用户名就很难在节点列表里认出「这条隧道是谁的」。
	o = opt(Value, "auth_user", tr("用户名"),
		tr("仅用于区分/备注，不会发送给服务端。真正的凭据是上面的密码。"),
		{ auth_mode = "multi" })

	-- 这里**只有 SNI 一个必填项**。源端口、IP ID 标记、防火墙模式全部
	-- 由核心自动处理，不再让用户填：
	--
	--   源端口      → 每次建连自动从动态端口段挑一个未在用的
	--                 （固定它会撞四元组，两台机器经同一 NAT 去同一服务端
	--                  就会互相踢会话）
	--   IP ID 标记  → 从 password 派生（HKDF-SHA256，两端算出同一个值）。
	--                 多用户时服务端为每个用户各派生一个，全部纳入识别范围。
	--                 所以它天然「部署间不同」，不需要也不应该手填。
	--   防火墙模式  → 强制写入（notrack + RST 抑制是协议能工作的前提）
	--
	-- 用户要填的就是：地址、端口、密码、SNI。四项。

	-- SNI ------------------------------------------------------------------
	o = opt(Value, "sni", tr("SNI"),
		tr("只影响伪 ClientHello 的外观，不参与任何校验。填一个真实的、与你服务器同域名的站点。"))

	-- 握手方式 --------------------------------------------------------------
	o = opt(ListValue, "handshake", tr("握手方式"),
		tr("symbolic 是标准三次握手（默认）。none 只在链路无状态检查时可用，会导致严格 NAT 丢包。"))
	if o then
		o.default = "symbolic"
		o:value("symbolic", "Symbolic")
		o:value("none", "None")
	end


	-- 带宽 ---------------------------------------------------------------
	-- 与 hysteria2 的 up / down 同一含义，单位 Mbps。
	-- 留空用核心默认（1000，千兆）。
	-- 建连时和服务端取较小值：上传 = min(这里的 up, 服务端的 down)，
	-- 下载 = min(服务端的 up, 这里的 down)。不必和另一端填同一个数。
	o = opt(Value, "up_mbps", tr("上传带宽"),
		tr("Mbps。本端上传上限。留空＝1000（千兆）。实际速率还要和服务端的下载上限取较小值。"))
	if o then
		o.datatype = "uinteger"
		o.default = ""
	end
	o = opt(Value, "down_mbps", tr("下载带宽"),
		tr("Mbps。本端下载上限。留空＝1000（千兆）。实际速率还要和服务端的上传上限取较小值。"))
	if o then
		o.datatype = "uinteger"
		o.default = ""
	end

	-- UDP 三态 --------------------------------------------------------------
	-- 留空＝跟随核心默认（开启）。刻意不写成 Flag：
	-- Flag 的「关」会写 0，而「没配过」是空——两者语义不同，
	-- 混在一起会让默认值的变化被静默继承。
	o = opt(ListValue, "udp_enabled", tr("UDP"),
		tr("留空＝跟随核心默认（开启）。关闭后 QUIC/UDP 流量无法通过隧道。"))
	if o then
		o.default = ""
		o:value("", tr("跟随核心默认（开启）"))
		o:value("1", tr("开启"))
		o:value("0", tr("关闭"))
	end
end

return function(m, s, s1)
	-- xpcall + traceback：出错时把调用栈一起记下来，
	-- 否则只有一句 "attempt to call a nil value"，无从定位。
	local ok, err = xpcall(function()
		build(m, s, s1)
	end, function(e)
		return tostring(e) .. "\n" .. debug.traceback()
	end)
	if not ok then
		report(err)
	end
end
